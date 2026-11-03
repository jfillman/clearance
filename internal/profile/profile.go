// Package profile is agent definitions: durable, schema-validated, loaded from git-managed YAML. Ported from
// profile.py and schemas/agent-definition.schema.json (embedded here byte for byte; a drift test compares it with
// the Python copy).
//
// Clearance needs the parser to tier a definition change (review, the gate's definition releases) and to check a
// PR's provenance scope; after R-3 the definitions and their schema are Autopilot's.
package profile

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/jfillman/clearance/internal/definitions"
	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/pyyaml"
)

//go:embed agent-definition.schema.json
var schemaJSON []byte

// SchemaJSON is the embedded agent-definition schema, byte-identical to src/clearance/schemas.
func SchemaJSON() []byte { return bytes.Clone(schemaJSON) }

const schemaURL = "https://clearance.local/agent-definition.schema.json"

var compiled = sync.OnceValues(func() (*jsonschema.Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaJSON))
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(schemaURL, doc); err != nil {
		return nil, err
	}
	return c.Compile(schemaURL)
})

// placeholderDigest is PLACEHOLDER_DIGEST.
var placeholderDigest = regexp.MustCompile(`@sha256:0{64}\n?$`)

// BaselineDenyPaths are always denied, for every agent, in addition to whatever a definition adds. A definition can
// extend this list but cannot shrink it: an agent must never be able to edit the controls that constrain it.
// cicd.yaml is not here (2026-10-25): an agent may change it field by field under Glidepath's scope rules (the
// Hangar pack's R021). The generated pipeline (.tekton/) stays denied whole. Release files (D9/AF-5) are
// machine-owned.
var BaselineDenyPaths = []string{
	".tekton/**", "**/.tekton/**",
	"CODEOWNERS", "**/CODEOWNERS", ".github/**",
	"**/appproject*.yaml", "**/AppProject*.yaml",
	"release.yaml", "**/release.yaml", "*.release.yaml", "**/*.release.yaml",
}

// BaselineDenyFields (AF-9a) are the field-level equivalent: these JSON pointers, and anything under them, can never
// be the field an agent's diff touches, even if a definition's own fieldDeny omits them.
var BaselineDenyFields = []string{
	"/extraManifests", "/networkPolicy", "/httpRoute",
	"/release", "/releaseTracking", "/rollout/image",
}

// DefinitionError is a definition that does not parse: "<name>: <path>: <message>".
type DefinitionError struct{ Msg string }

func (e *DefinitionError) Error() string { return e.Msg }

// Network modes, ordered by reach (limits.Network).
type Network int

const (
	NetworkNone Network = iota
	NetworkClearance
	NetworkClearanceModel
	NetworkAllowlist
)

var networkNames = []string{"none", "clearance", "clearance+model", "allowlist"}

// ParseNetwork is Network.parse: case-insensitive, "+" and "-" as "_".
func ParseNetwork(s string) (Network, error) {
	n := strings.NewReplacer("+", "_", "-", "_").Replace(strings.ToLower(s))
	for i, name := range networkNames {
		if strings.ReplaceAll(name, "+", "_") == n {
			return Network(i), nil
		}
	}
	return 0, fmt.Errorf("unknown network mode %s", pycompat.Repr(s))
}

// Label is Network.label.
func (n Network) Label() string { return networkNames[n] }

// ComputeClass is limits.ComputeClass.
type ComputeClass int

const (
	ComputeSmall ComputeClass = iota
	ComputeMedium
	ComputeLarge
	ComputeGPU
)

var computeNames = []string{"small", "medium", "large", "gpu"}

// ParseComputeClass is ComputeClass.parse.
func ParseComputeClass(s string) (ComputeClass, error) {
	for i, name := range computeNames {
		if strings.ToLower(s) == name {
			return ComputeClass(i), nil
		}
	}
	return 0, fmt.Errorf("unknown compute class %s", pycompat.Repr(s))
}

// String is the class's name, lower-case.
func (c ComputeClass) String() string { return computeNames[c] }

// Limits is limits.Limits as a definition sets them.
type Limits struct {
	TierCeiling int // 0..3, T0..T3
	TTLMinutes  int64
	ToolCalls   int64
	GithubCalls int64
	OpenPRs     int64
	ModelTokens int64
	Children    int64
	Tools       []string // sorted, unique; human.request brings human.request.get
	Models      []string // sorted, unique
	Network     Network
	Compute     ComputeClass
}

// AgentDefinition is profile.AgentDefinition.
type AgentDefinition struct {
	Name, Kind, IdentityType string
	ServiceAccount           string // "" when the identity names none
	Limits                   Limits
	ReposAllow               []string
	APIAllow                 []string
	DenyPaths                []string // the baseline, then the definition's own, de-duplicated
	FieldAllow               []string
	FieldDeny                []string // the baseline, then the definition's own, de-duplicated
	Image                    string   // "" when the definition names no runtime image
	Framework, Sandbox       string
	Sidecars                 []map[string]any
	Triggers                 []map[string]any
	// Instructions is what a run starts with (runtime.instructions); HasInstructions says whether it is set.
	Instructions    string
	HasInstructions bool
	// Owner is the owning team (a Backstage group ref); HasOwner says whether the document names one.
	Owner    string
	HasOwner bool
	// RawProfile is the profile as written: a pack reads its own sections from it (profile.glidepath.apps).
	RawProfile  map[string]any
	Description string
	// Raw is the whole document.
	Raw map[string]any
}

// RunsIn is where the agent's loop runs: "cluster" when the definition names a runtime image (an AgentRun runs
// it), else "client" (a person's own MCP client is the loop and Clearance enforces this envelope on every call).
func (d AgentDefinition) RunsIn() string {
	if d.Image != "" {
		return "cluster"
	}
	return "client"
}

// Definition is the part of d that internal/definitions, review, gate and provenance read.
func (d AgentDefinition) Definition() definitions.Definition {
	return definitions.Definition{
		Name: d.Name, Description: d.Description, Kind: d.Kind, Owner: d.Owner, HasOwner: d.HasOwner,
		IdentityType: d.IdentityType, ServiceAccount: d.ServiceAccount, TierCeiling: d.Limits.TierCeiling,
		Tools: d.Limits.Tools, Models: d.Limits.Models, ReposAllow: d.ReposAllow, DenyPaths: d.DenyPaths,
		Image: d.Image, Raw: d.Raw,
	}
}

// Parser is Parse as a definitions.Parser.
func Parser() definitions.Parser {
	return func(doc map[string]any) (definitions.Definition, error) {
		d, err := Parse(doc)
		if err != nil {
			return definitions.Definition{}, err
		}
		return d.Definition(), nil
	}
}

// Parse is profile.parse: validate doc against the agent-definition schema, refuse a placeholder runtime digest,
// and read the typed fields. doc's numbers may be json.Number (pycompat.Decode) or Go numbers (YAML).
func Parse(doc map[string]any) (AgentDefinition, error) {
	sch, err := compiled()
	if err != nil {
		return AgentDefinition{}, fmt.Errorf("agent-definition schema: %w", err)
	}
	name := "?"
	if n, ok := doc["name"]; ok {
		name = pycompat.Str(n)
	}
	if err := sch.Validate(doc); err != nil {
		path, msg := explain(err, doc)
		return AgentDefinition{}, &DefinitionError{fmt.Sprintf("%s: %s: %s", name, path, msg)}
	}
	// The schema has checked every shape read below.
	p := doc["profile"].(map[string]any)
	lim := p["limits"].(map[string]any)
	tools := strs(p["tools"])
	if slices.Contains(tools, "human.request") {
		tools = append(tools, "human.request.get") // an agent that may ask may read its own answers
	}
	limits := Limits{
		TierCeiling: int(p["tierCeiling"].(string)[1] - '0'),
		TTLMinutes:  integer(lim["ttlMinutes"]), ToolCalls: integer(lim["toolCalls"]),
		GithubCalls: integer(lim["githubCalls"]), OpenPRs: integer(lim["openPrs"]),
		ModelTokens: integer(lim["modelTokens"]), Children: integer(lim["children"]),
		Tools: sortedUnique(tools), Models: sortedUnique(strs(p["models"])),
	}
	if limits.Network, err = ParseNetwork(strOr(p["network"], "clearance")); err != nil {
		return AgentDefinition{}, &DefinitionError{err.Error()}
	}
	if limits.Compute, err = ParseComputeClass(strOr(p["compute"], "small")); err != nil {
		return AgentDefinition{}, &DefinitionError{err.Error()}
	}
	repos, _ := p["repos"].(map[string]any)
	rt, _ := doc["runtime"].(map[string]any)
	image, _ := rt["image"].(string)
	if placeholderDigest.MatchString(image) {
		return AgentDefinition{}, &DefinitionError{fmt.Sprintf("%s: runtime/image: %s is a placeholder digest (all zeros); "+
			"name a real runtime image, or leave runtime.image out for an agent that runs in a person's client", pycompat.Str(doc["name"]), image)}
	}
	id := doc["identity"].(map[string]any)
	d := AgentDefinition{
		Name: doc["name"].(string), Kind: doc["kind"].(string), IdentityType: id["type"].(string),
		Limits:     limits,
		ReposAllow: strs(repos["allow"]), APIAllow: strs(mapOf(p["apis"])["allow"]),
		DenyPaths:  dedupe(append(append([]string(nil), BaselineDenyPaths...), strs(repos["denyPaths"])...)),
		FieldAllow: strs(repos["fieldAllow"]),
		FieldDeny:  dedupe(append(append([]string(nil), BaselineDenyFields...), strs(repos["fieldDeny"])...)),
		Image:      image, Framework: strOr(rt["framework"], "generic"), Sandbox: strOr(rt["sandbox"], "standard"),
		RawProfile: p, Description: doc["description"].(string), Raw: doc,
	}
	d.ServiceAccount, _ = id["serviceAccount"].(string)
	if s, ok := rt["instructions"].(string); ok {
		d.Instructions, d.HasInstructions = s, true
	}
	if o, ok := doc["owner"].(string); ok {
		d.Owner, d.HasOwner = o, true
	}
	for _, s := range list(rt["sidecars"]) {
		d.Sidecars = append(d.Sidecars, s.(map[string]any))
	}
	if trig, ok := doc["triggers"]; ok {
		for _, t := range list(trig) {
			d.Triggers = append(d.Triggers, t.(map[string]any))
		}
	} else {
		d.Triggers = []map[string]any{{"type": "manual"}}
	}
	return d, nil
}

// LoadDir is profile.load_dir: every *.yaml in dir, in name order; a file's name must be its agent's name, and no
// two files name the same agent.
func LoadDir(dir string) (map[string]AgentDefinition, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	out := map[string]AgentDefinition{}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		doc, err := DecodeYAML(raw)
		if err != nil {
			return nil, &DefinitionError{fmt.Sprintf("%s: %v", filepath.Base(f), err)}
		}
		d, err := Parse(doc)
		if err != nil {
			return nil, err
		}
		base := filepath.Base(f)
		if _, dup := out[d.Name]; dup {
			return nil, &DefinitionError{fmt.Sprintf("duplicate agent name %s (%s)", pycompat.Repr(d.Name), base)}
		}
		if strings.TrimSuffix(base, ".yaml") != d.Name {
			return nil, &DefinitionError{fmt.Sprintf("%s: file name must match agent name %s", base, pycompat.Repr(d.Name))}
		}
		out[d.Name] = d
	}
	return out, nil
}

// DecodeYAML reads one YAML document as JSON values: yaml.safe_load (internal/pyyaml, PyYAML's YAML 1.1 rules:
// `yes` is True, a key set twice keeps its last value), then the JSON data model (string keys, numbers as
// json.Number). A document that is not a mapping, or holds a value JSON has no form for (a non-string key, a date,
// NaN or an infinity), is refused.
func DecodeYAML(raw []byte) (map[string]any, error) {
	v, err := pyyaml.SafeLoad(string(raw))
	if err != nil {
		return nil, err
	}
	j, err := jsonValue(v)
	if err != nil {
		return nil, fmt.Errorf("not JSON-shaped: %w", err)
	}
	m, ok := j.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("the document is not a mapping")
	}
	return m, nil
}

// jsonValue is a safe_load value in the JSON data model, or an error for one JSON cannot hold.
func jsonValue(v any) (any, error) {
	switch x := v.(type) {
	case nil, bool, string:
		return x, nil
	case int64:
		return json.Number(strconv.FormatInt(x, 10)), nil
	case *big.Int:
		return json.Number(x.String()), nil
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return nil, fmt.Errorf("%s has no JSON form", pycompat.FloatRepr(x))
		}
		return json.Number(pycompat.FloatRepr(x)), nil
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			j, err := jsonValue(e)
			if err != nil {
				return nil, err
			}
			out[i] = j
		}
		return out, nil
	case *pycompat.Map:
		out := make(map[string]any, x.Len())
		for i := range x.Len() {
			k, e := x.At(i)
			ks, ok := k.(string)
			if !ok {
				return nil, fmt.Errorf("the key %s is not a string", pycompat.Repr(k))
			}
			j, err := jsonValue(e)
			if err != nil {
				return nil, err
			}
			out[ks] = j
		}
		return out, nil
	}
	return nil, fmt.Errorf("a %s has no JSON form", pycompat.TypeName(v))
}

func list(v any) []any { l, _ := v.([]any); return l }

func mapOf(v any) map[string]any { m, _ := v.(map[string]any); return m }

func strs(v any) []string {
	var out []string
	for _, x := range list(v) {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func strOr(v any, def string) string {
	if s, ok := v.(string); ok {
		return s
	}
	return def
}

// integer reads a schema-checked integer (json.Number, a Go integer, or an integral float).
func integer(v any) int64 {
	switch x := v.(type) {
	case json.Number:
		if i, err := strconv.ParseInt(string(x), 10, 64); err == nil {
			return i
		}
		f, _ := x.Float64()
		return int64(f)
	case int:
		return int64(x)
	case int64:
		return x
	case float64:
		return int64(x)
	}
	i, _ := pycompat.AsInt(v)
	return i
}

func dedupe(xs []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func sortedUnique(xs []string) []string {
	out := dedupe(xs)
	sort.Strings(out)
	return out
}
