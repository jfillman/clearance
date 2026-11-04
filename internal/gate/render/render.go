// Package render is `clearance register`'s manifest work (register.py): the Kubernetes objects of two directories
// of rendered manifests, their difference as the gate's objects (added, changed with the JSON pointers of every leaf
// that differs, removed), the images each runs, and the digests.
package render

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/jfillman/clearance/internal/pycompat"
)

// MaxObjects and MaxFields are the gate's (gate.MAX_OBJECTS, gate.MAX_FIELDS).
const (
	MaxObjects = 2000
	MaxFields  = 400
)

// Key is (apiVersion, kind, namespace, name).
type Key [4]string

func (k Key) less(o Key) bool {
	for i := range k {
		if k[i] != o[i] {
			return k[i] < o[i]
		}
	}
	return false
}

// Doc is one object: its value (maps, lists, scalars) and its ordered form (for the images walk).
type Doc struct {
	Value   any
	ordered any
}

// Set is the objects of one directory.
type Set map[Key]Doc

// canonical is register.canonical: json.dumps(doc, sort_keys=True, separators=(",", ":"), default=str) - ASCII.
func canonical(v any) string {
	b, err := pycompat.Dumps(v, pycompat.Options{ASCII: true})
	if err != nil {
		return pycompat.Str(v)
	}
	return string(b)
}

// LoadDir is register.load_dir: every object with a kind, an apiVersion and a name in the directory's *.yaml,
// *.yml and *.json files (a *List's items too). A missing directory is an empty set.
func LoadDir(dir string) (Set, error) {
	out := Set{}
	if dir == "" {
		return out, nil
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return out, nil
	}
	var files []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		switch filepath.Ext(p) {
		case ".yaml", ".yml", ".json":
		default:
			return nil
		}
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		if err := Add(out, data); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
	}
	return out, nil
}

// Add reads one file's documents into s.
func Add(s Set, data []byte) error {
	docs, err := loadAll(data)
	if err != nil {
		return err
	}
	for _, raw := range docs {
		doc, ok := raw.(*pycompat.Map)
		if !ok || !pycompat.Truthy(get(doc, "kind")) || !pycompat.Truthy(get(doc, "apiVersion")) {
			continue
		}
		items := []*pycompat.Map{doc}
		if kind, _ := get(doc, "kind").(string); strings.HasSuffix(kind, "List") {
			if list, ok := get(doc, "items").([]any); ok {
				items = nil
				for _, it := range list {
					if m, ok := it.(*pycompat.Map); ok {
						items = append(items, m)
					}
				}
			}
		}
		for _, d := range items {
			meta := get(d, "metadata")
			field := func(k string) string {
				if !pycompat.Truthy(get(meta, k)) {
					return ""
				}
				return pycompat.Str(plain(get(meta, k)))
			}
			key := Key{pycompat.Str(plain(get(d, "apiVersion"))), pycompat.Str(plain(get(d, "kind"))), field("namespace"), field("name")}
			if key[3] != "" {
				out := Doc{Value: plain(d), ordered: d}
				s[key] = out
			}
		}
	}
	return nil
}

func escape(k string) string { return strings.ReplaceAll(strings.ReplaceAll(k, "~", "~0"), "/", "~1") }

// DiffPointers is register.diff_pointers: the JSON pointers of every leaf that differs (a whole subtree when its
// type changed).
func DiffPointers(a, b any, path string) []string {
	am, aok := a.(map[string]any)
	bm, bok := b.(map[string]any)
	if aok && bok {
		keys := map[string]bool{}
		for k := range am {
			keys[k] = true
		}
		for k := range bm {
			keys[k] = true
		}
		sorted := make([]string, 0, len(keys))
		for k := range keys {
			sorted = append(sorted, k)
		}
		sort.Strings(sorted)
		var out []string
		for _, k := range sorted {
			av, ina := am[k]
			bv, inb := bm[k]
			if !ina || !inb {
				out = append(out, path+"/"+escape(k))
			} else {
				out = append(out, DiffPointers(av, bv, path+"/"+escape(k))...)
			}
		}
		return out
	}
	al, aok := a.([]any)
	bl, bok := b.([]any)
	if aok && bok {
		var out []string
		for i := 0; i < max(len(al), len(bl)); i++ {
			p := path + "/" + strconv.Itoa(i)
			if i >= len(al) || i >= len(bl) {
				out = append(out, p)
			} else {
				out = append(out, DiffPointers(al[i], bl[i], p)...)
			}
		}
		return out
	}
	if pycompat.Equal(a, b) {
		return nil
	}
	if path == "" {
		path = "/"
	}
	return []string{path}
}

// Images is register.images: every string under an `image` key, in document order, first occurrence kept.
func Images(d Doc) []string {
	var found []string
	var walk func(any)
	walk = func(x any) {
		switch v := x.(type) {
		case *pycompat.Map:
			for i := range v.Len() {
				k, e := v.At(i)
				if s, ok := e.(string); ok && k == "image" {
					found = append(found, s)
				} else {
					walk(e)
				}
			}
		case []any:
			for _, e := range v {
				walk(e)
			}
		}
	}
	walk(d.ordered)
	seen := map[string]bool{}
	out := []string{}
	for _, s := range found {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// Object is one entry of the change's objects, in the gate's field order.
type Object struct {
	APIVersion string   `json:"apiVersion"`
	Kind       string   `json:"kind"`
	Namespace  string   `json:"namespace"`
	Name       string   `json:"name"`
	Op         string   `json:"op"`
	Fields     []string `json:"fields"`
	Images     []string `json:"images"`
	Digest     string   `json:"digest"`
}

// TooMany is register's UsageError for a change of more than MaxObjects objects.
type TooMany struct{ N int }

func (e *TooMany) Error() string {
	return fmt.Sprintf("%d objects changed; Clearance takes at most %d in one change", e.N, MaxObjects)
}

func sortedKeys(sets ...Set) []Key {
	all := map[Key]bool{}
	for _, s := range sets {
		for k := range s {
			all[k] = true
		}
	}
	keys := make([]Key, 0, len(all))
	for k := range all {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].less(keys[j]) })
	return keys
}

// Objects is register.objects: the difference of two sets.
func Objects(before, after Set) ([]Object, error) {
	out := []Object{}
	for _, key := range sortedKeys(before, after) {
		old, hasOld := before[key]
		nw, hasNew := after[key]
		if hasOld && hasNew && canonical(old.Value) == canonical(nw.Value) {
			continue
		}
		op := "changed"
		switch {
		case !hasOld:
			op = "added"
		case !hasNew:
			op = "removed"
		}
		fields := []string{}
		if op == "changed" {
			fields = append(fields, DiffPointers(old.Value, nw.Value, "")...)
			if len(fields) > MaxFields {
				fields = fields[:MaxFields]
			}
		}
		doc := nw
		if !hasNew {
			doc = old
		}
		images := []string{}
		if hasNew {
			images = Images(nw)
		}
		out = append(out, Object{key[0], key[1], key[2], key[3], op, fields, images, ObjectDigest(doc)})
	}
	if len(out) > MaxObjects {
		return nil, &TooMany{len(out)}
	}
	return out, nil
}

// ObjectDigest is one rendered object's hash: the lowercase hex sha256 of its canonical JSON (canonical: keys
// sorted, separators "," and ":", every character outside space..~ escaped as \uXXXX). It is Objects' digest.
func ObjectDigest(d Doc) string {
	sum := sha256.Sum256([]byte(canonical(d.Value)))
	return hex.EncodeToString(sum[:])
}

// TreeDigest is the manifest-tree digest of a rendered directory (docs/gate.md, "The manifest-tree digest"): one
// line per object, "apiVersion/kind/namespace/name:" and its ObjectDigest (namespace empty when the object has
// none), the lines sorted byte-wise and joined with "\n" (no trailing newline), and the lowercase hex sha256 of that.
// It is what Glidepath's clearance-gate check computes for the same render, and what the Argo CD plugin stamps.
func TreeDigest(after Set) string {
	lines := make([]string, 0, len(after))
	for k, d := range after {
		lines = append(lines, strings.Join(k[:], "/")+":"+ObjectDigest(d))
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])
}

// ChangedFiles is register.changed_files: the files that differ between the two directories, by relative path.
func ChangedFiles(beforeDir, afterDir string) ([]string, error) {
	files := func(d string) (map[string][]byte, error) {
		out := map[string][]byte{}
		if d == "" {
			return out, nil
		}
		if st, err := os.Stat(d); err != nil || !st.IsDir() {
			return out, nil
		}
		err := filepath.WalkDir(d, func(p string, e fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if e.IsDir() {
				return nil
			}
			if st, err := os.Stat(p); err != nil || !st.Mode().IsRegular() {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(d, p)
			out[filepath.ToSlash(rel)] = b
			return nil
		})
		return out, err
	}
	a, err := files(beforeDir)
	if err != nil {
		return nil, err
	}
	b, err := files(afterDir)
	if err != nil {
		return nil, err
	}
	var out []string
	seen := map[string]bool{}
	for _, m := range []map[string][]byte{a, b} {
		for p := range m {
			if seen[p] {
				continue
			}
			seen[p] = true
			x, inA := a[p]
			y, inB := b[p]
			if inA != inB || string(x) != string(y) {
				out = append(out, p)
			}
		}
	}
	sort.Strings(out)
	if out == nil {
		out = []string{}
	}
	return out, nil
}
