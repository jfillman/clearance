package argosrc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/gobwas/glob"
	"go.yaml.in/yaml/v3"
)

const skipRenderingMarker = "+argocd:skip-file-rendering"

var manifestFileRx = regexp.MustCompile(`^.*\.(yaml|yml|json|jsonnet)$`)

// directory renders a plain directory the way findManifests does (reposerver/repository): the *.yaml, *.yml and
// *.json files of the directory (and below it with directory.recurse), those matching directory.include and not
// directory.exclude (gobwas globs on the path relative to the source's path, `*` crossing `/`), in lexical order,
// skipping a file that carries the skip-rendering marker; a symlink must stay inside the repository and name a
// regular file. A YAML file that does not parse is ignored unless it looks like a manifest, as Argo CD does.
//
// A selected *.jsonnet file is refused: it would be evaluated by Argo CD's own jsonnet.
func (st *state) directory(pos int, s Source, root, appPath string) ([]byte, error) {
	d := s.Directory
	if d == nil {
		d = &Directory{}
	}
	var out bytes.Buffer
	err := filepath.Walk(appPath, func(p string, f os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if f.IsDir() {
			if p != appPath && !d.Recurse {
				return filepath.SkipDir
			}
			return nil
		}
		if !manifestFileRx.MatchString(f.Name()) {
			return nil
		}
		rel, err := filepath.Rel(appPath, p)
		if err != nil {
			return err
		}
		real := f
		realPath := p
		if f.Mode()&os.ModeSymlink != 0 {
			rp, err := filepath.EvalSymlinks(p)
			if err != nil {
				if os.IsNotExist(err) {
					return nil
				}
				return fmt.Errorf("failed to evaluate symlink at %q: %w", rel, err)
			}
			rootReal, _ := filepath.EvalSymlinks(root)
			if rp != rootReal && !strings.HasPrefix(rp, rootReal+string(os.PathSeparator)) {
				return fmt.Errorf("illegal filepath in symlink at %q", rel)
			}
			real, err = os.Stat(rp)
			if err != nil {
				return nil
			}
			realPath = rp
		}
		if !real.Mode().IsRegular() {
			return nil
		}
		if d.Exclude != "" && globMatch(d.Exclude, rel) {
			return nil
		}
		if d.Include != "" && !globMatch(d.Include, rel) {
			return nil
		}
		b, err := os.ReadFile(realPath)
		if err != nil {
			return fmt.Errorf("failed to read %q: %w", rel, err)
		}
		if bytes.Contains(b, []byte(skipRenderingMarker)) {
			return nil
		}
		if strings.HasSuffix(f.Name(), ".jsonnet") {
			return unsupported(pos, "jsonnet", fmt.Sprintf("%s would be evaluated by Argo CD's jsonnet", rel))
		}
		doc, err := manifestDocs(f.Name(), b)
		if err != nil {
			return fmt.Errorf("source %d: %w", pos, err)
		}
		if len(doc) > 0 {
			out.Write(doc)
			out.WriteString("\n---\n")
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("source %d: failed to get potentially valid manifests: %w", pos, err)
	}
	return out.Bytes(), nil
}

// globMatch is glob.Match in argo-cd's util/glob: no separators, and a pattern that does not compile matches nothing.
func globMatch(pattern, text string) bool {
	g, err := glob.Compile(pattern)
	if err != nil {
		return false
	}
	return g.Match(text)
}

// manifestDocs is getObjsFromYAMLOrJSON for one file: it returns the file's bytes when they hold objects, nothing
// when an unrelated YAML file is to be ignored, an error when Argo CD would raise one.
func manifestDocs(name string, b []byte) ([]byte, error) {
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	if strings.HasSuffix(name, ".json") {
		dec := json.NewDecoder(bytes.NewReader(b))
		var obj map[string]any
		if err := dec.Decode(&obj); err != nil {
			return nil, fmt.Errorf("Failed to unmarshal %q: %w", name, err)
		}
		if k, _ := obj["kind"].(string); k == "" {
			return nil, fmt.Errorf("Failed to unmarshal %q: Object 'Kind' is missing", name)
		}
		if dec.More() {
			return nil, fmt.Errorf("Found multiple objects in %q. Only single objects are allowed in JSON files.", name)
		}
		return b, nil
	}
	// Decoded into nodes, not maps: Argo CD's reader (YAML 1.1, last duplicate key wins) accepts a mapping that
	// repeats a key, and this validation must not refuse what Argo CD renders. The plugin's own stamping reader does
	// refuse it later (internal Canonicalize), which is the fail-closed answer for a document with two readings.
	dec := yaml.NewDecoder(bytes.NewReader(b))
	n := 0
	var perr error
	for {
		var doc yaml.Node
		if err := dec.Decode(&doc); err != nil {
			if !errors.Is(err, io.EOF) {
				perr = err
			}
			break
		}
		node := &doc
		if node.Kind == yaml.DocumentNode && len(node.Content) == 1 {
			node = node.Content[0]
		}
		if node.Kind == yaml.ScalarNode && node.Tag == "!!null" {
			continue
		}
		if node.Kind != yaml.MappingNode {
			perr = errors.New("failed to unmarshal manifest: not an object")
			break
		}
		kind := ""
		for i := 0; i+1 < len(node.Content); i += 2 {
			if node.Content[i].Value == "kind" && node.Content[i+1].Kind == yaml.ScalarNode {
				kind = node.Content[i+1].Value
			}
		}
		if kind == "" {
			perr = errors.New("failed to unmarshal manifest: Object 'Kind' is missing")
			break
		}
		n++
	}
	if perr != nil {
		if n > 0 {
			return nil, fmt.Errorf("Failed to unmarshal %q: %v", name, perr)
		}
		if bytes.Contains(b, []byte("apiVersion:")) && bytes.Contains(b, []byte("kind:")) && bytes.Contains(b, []byte("metadata:")) {
			return nil, fmt.Errorf("Failed to unmarshal %q: %v", name, perr)
		}
		return nil, nil
	}
	return bytes.TrimSpace(b), nil
}
