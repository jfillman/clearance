package decide

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/jfillman/clearance/internal/docscope"
)

// BundleAPIVersion is the policy bundle format this engine loads.
const BundleAPIVersion = "clearance.policy/v1"

// PolicyBundle is a deployment's policy bundle as a file: the tools its rules govern, the rules (CEL), and the data
// and context the rules read. The core loads bundles from configuration (CLEARANCE_BUNDLES) and names every one,
// with its version, in each decision; nothing about a bundle is compiled into Clearance. docs/core.md, "Policy
// bundles", is the reference.
type PolicyBundle struct {
	APIVersion  string `json:"apiVersion"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description,omitempty"`
	// Tools are the tools the bundle's rules govern (the gateway's registry names the same ones).
	Tools []ToolSpec `json:"tools,omitempty"`
	// PRTools are tools whose receipt is a pull request (provenance looks them up by PR).
	PRTools []string `json:"pr_tools,omitempty"`
	// ProfileSections are definition profile sections whose `apps` list scopes an agent (a definition review
	// reads them as the agent's scope).
	ProfileSections []string `json:"profile_sections,omitempty"`
	// Sources are documents fetched at load time (a system's published contract) that Documents read.
	Sources []SourceSpec `json:"sources,omitempty"`
	// Vars are ctx.<name> variables, each a CEL expression over the call (CallVars), in order; a later one may
	// read an earlier one.
	Vars []VarSpec `json:"vars,omitempty"`
	// ArgChecks are argument checks: every check that is true for a call counts one bad argument (ctx.missing_args,
	// R008), for the calls whose `when` is true.
	ArgChecks []ArgCheck `json:"arg_checks,omitempty"`
	// Documents are field-scope checks over the files a file-writing tool carries (internal/docscope); each sets
	// ctx.<name> to its problem count, and a rule naming it in `problems` decides with its findings.
	Documents []DocumentSpec `json:"documents,omitempty"`
	// App is a CEL string expression: the application a call acts on, recorded as `app` ("" for none).
	App string `json:"app,omitempty"`
	// Rules are deny-if rules placed among the core's by order.
	Rules []Rule `json:"rules,omitempty"`
}

// SourceSpec is a document the loader fetches for a bundle (from the URL or file the deployment configures for
// the source's name), with a compatibility check on its version field.
type SourceSpec struct {
	Name string `json:"name"`
	// VersionPointer is the JSON pointer to the document's version (an integer), e.g. /contractVersion.
	VersionPointer string `json:"version_pointer"`
	// Compatible are the versions this bundle was written against; any other fails the load.
	Compatible []int64 `json:"compatible"`
}

// VarSpec is one context variable: ctx.<Name>, of Type bool or int, computed by Expr.
type VarSpec struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Expr string `json:"expr"`
}

// ArgCheck is a group of argument checks for the calls When selects.
type ArgCheck struct {
	When   string   `json:"when"`
	Checks []string `json:"checks"`
}

// DataRef is data a document reads: inline, or a pointer into a fetched source.
type DataRef struct {
	Source  string          `json:"source,omitempty"`
	Pointer string          `json:"pointer,omitempty"`
	Inline  json.RawMessage `json:"inline,omitempty"`
}

// DocumentSpec is one document field-scope check (docscope.Config as data).
type DocumentSpec struct {
	Name      string             `json:"name"`
	File      string             `json:"file"`
	Rules     DataRef            `json:"rules"`
	WholeFile docscope.Finding   `json:"whole_file"`
	Human     docscope.Finding   `json:"human"`
	Loosened  docscope.Finding   `json:"loosened"`
	Keyed     []docscope.Keyed   `json:"keyed,omitempty"`
	Counted   []docscope.Counted `json:"counted,omitempty"`
}

// Bundle is a loaded policy bundle: the file, its sources' documents, and its digest. Build it with LoadBundle.
type Bundle struct {
	Spec    PolicyBundle
	Sources []LoadedSource
	Digest  string // sha256 of the bundle file and every source document, hex
	docs    []*docscope.Config
}

// LoadedSource is one fetched source document.
type LoadedSource struct {
	Name     string `json:"name"`
	Location string `json:"location"`
	Version  int64  `json:"version"`
	Digest   string `json:"digest"`
	doc      any
}

// Fetch reads a source's document for a bundle; the deployment's configuration says where (internal/bundles).
type Fetch func(bundle string, src SourceSpec) (data []byte, location string, err error)

var nameRx = regexp.MustCompile(`\A[a-z0-9][a-z0-9-]{0,62}\z`)

// ParsePolicyBundle strictly decodes a bundle file and checks its shape (not its CEL: New compiles that).
func ParsePolicyBundle(data []byte) (PolicyBundle, error) {
	var b PolicyBundle
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return b, fmt.Errorf("decide: policy bundle: %w", err)
	}
	if dec.More() {
		return b, errors.New("decide: policy bundle: trailing data")
	}
	if b.APIVersion != BundleAPIVersion {
		return b, fmt.Errorf("decide: policy bundle: apiVersion %q, want %q", b.APIVersion, BundleAPIVersion)
	}
	if !nameRx.MatchString(b.Name) || b.Name == "clearance-core" {
		return b, fmt.Errorf("decide: policy bundle: bad name %q", b.Name)
	}
	if b.Version == "" {
		return b, fmt.Errorf("decide: policy bundle %s: version is required", b.Name)
	}
	seen := map[string]bool{}
	for _, s := range b.Sources {
		if !nameRx.MatchString(s.Name) || seen[s.Name] {
			return b, fmt.Errorf("decide: policy bundle %s: bad or repeated source name %q", b.Name, s.Name)
		}
		seen[s.Name] = true
		if !strings.HasPrefix(s.VersionPointer, "/") || len(s.Compatible) == 0 {
			return b, fmt.Errorf("decide: policy bundle %s: source %s needs a version_pointer and compatible versions",
				b.Name, s.Name)
		}
	}
	for _, d := range b.Documents {
		if d.Rules.Source != "" && !seen[d.Rules.Source] {
			return b, fmt.Errorf("decide: policy bundle %s: document %s reads unknown source %q", b.Name, d.Name, d.Rules.Source)
		}
		if (d.Rules.Source == "") == (len(d.Rules.Inline) == 0) {
			return b, fmt.Errorf("decide: policy bundle %s: document %s: rules are inline or from a source, not both or neither",
				b.Name, d.Name)
		}
	}
	return b, nil
}

// LoadBundle parses a bundle file and fetches its sources. A source that cannot be fetched, does not parse, or
// whose version is not one the bundle names as compatible fails the load: the core does not decide on a bundle it
// could not load.
func LoadBundle(data []byte, fetch Fetch) (*Bundle, error) {
	spec, err := ParsePolicyBundle(data)
	if err != nil {
		return nil, err
	}
	sum := sha256.New()
	sum.Write(data)
	out := &Bundle{Spec: spec}
	for _, s := range spec.Sources {
		if fetch == nil {
			return nil, fmt.Errorf("decide: policy bundle %s: source %s: no source is configured", spec.Name, s.Name)
		}
		raw, loc, err := fetch(spec.Name, s)
		if err != nil {
			return nil, fmt.Errorf("decide: policy bundle %s: source %s: %w", spec.Name, s.Name, err)
		}
		var doc any
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&doc); err != nil {
			return nil, fmt.Errorf("decide: policy bundle %s: source %s (%s): %w", spec.Name, s.Name, loc, err)
		}
		v, ok := pointer(doc, s.VersionPointer)
		n, isNum := v.(json.Number)
		ver, err := n.Int64()
		if !ok || !isNum || err != nil {
			return nil, fmt.Errorf("decide: policy bundle %s: source %s (%s): no integer version at %s",
				spec.Name, s.Name, loc, s.VersionPointer)
		}
		compatible := false
		for _, c := range s.Compatible {
			compatible = compatible || c == ver
		}
		if !compatible {
			return nil, fmt.Errorf("decide: policy bundle %s: source %s (%s) is version %d; this bundle is written for %v",
				spec.Name, s.Name, loc, ver, s.Compatible)
		}
		d := sha256.Sum256(raw)
		sum.Write(d[:])
		out.Sources = append(out.Sources, LoadedSource{Name: s.Name, Location: loc, Version: ver,
			Digest: hex.EncodeToString(d[:]), doc: doc})
	}
	for i := range spec.Documents {
		d := &spec.Documents[i]
		rules := []byte(d.Rules.Inline)
		if d.Rules.Source != "" {
			var src *LoadedSource
			for j := range out.Sources {
				if out.Sources[j].Name == d.Rules.Source {
					src = &out.Sources[j]
				}
			}
			v, ok := pointer(src.doc, d.Rules.Pointer)
			if !ok {
				return nil, fmt.Errorf("decide: policy bundle %s: document %s: source %s has nothing at %q",
					spec.Name, d.Name, d.Rules.Source, d.Rules.Pointer)
			}
			if rules, err = json.Marshal(v); err != nil {
				return nil, err
			}
		}
		pr, err := docscope.ParseRules(rules)
		if err != nil {
			return nil, fmt.Errorf("decide: policy bundle %s: document %s: %w", spec.Name, d.Name, err)
		}
		cfg := &docscope.Config{File: d.File, Rules: pr, WholeFile: d.WholeFile, Human: d.Human, Loosened: d.Loosened,
			Keyed: d.Keyed, Counted: d.Counted}
		if err := cfg.Prepare(); err != nil {
			return nil, fmt.Errorf("decide: policy bundle %s: document %s: %w", spec.Name, d.Name, err)
		}
		out.docs = append(out.docs, cfg)
	}
	out.Digest = hex.EncodeToString(sum.Sum(nil))
	return out, nil
}

// pointer resolves a JSON pointer (RFC 6901) in a decoded document.
func pointer(doc any, p string) (any, bool) {
	if p == "" {
		return doc, true
	}
	if !strings.HasPrefix(p, "/") {
		return nil, false
	}
	v := doc
	for _, seg := range strings.Split(p[1:], "/") {
		seg = strings.ReplaceAll(strings.ReplaceAll(seg, "~1", "/"), "~0", "~")
		switch x := v.(type) {
		case map[string]any:
			var ok bool
			if v, ok = x[seg]; !ok {
				return nil, false
			}
		case []any:
			var i int
			if _, err := fmt.Sscanf(seg, "%d", &i); err != nil || i < 0 || i >= len(x) || fmt.Sprint(i) != seg {
				return nil, false
			}
			v = x[i]
		default:
			return nil, false
		}
	}
	return v, true
}

// BundleRef names one loaded bundle in a decision: its declared version, the digest of what was loaded, and the
// version of each source document it read.
type BundleRef struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Digest  string      `json:"digest"`
	Sources []SourceRef `json:"sources,omitempty"`
}

// SourceRef is a source document a bundle read at load.
type SourceRef struct {
	Name    string `json:"name"`
	Version int64  `json:"version"`
	Digest  string `json:"digest"`
}

func (b *Bundle) ref() BundleRef {
	r := BundleRef{Name: b.Spec.Name, Version: b.Spec.Version, Digest: b.Digest}
	for _, s := range b.Sources {
		r.Sources = append(r.Sources, SourceRef{Name: s.Name, Version: s.Version, Digest: s.Digest})
	}
	return r
}
