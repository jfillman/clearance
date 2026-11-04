package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/decide"
	"github.com/jfillman/clearance/internal/gate"
)

//go:generate go run ../../tools/contract -api -o ../../contract/clearance-api.json

// ContractPath is the committed contract, relative to the module root.
const ContractPath = "contract/clearance-api.json"

// APIVersion is the contract's version: /v1 changes are additive only, a breaking change is /v2.
const APIVersion = "v1"

// ContractNotes is the contract's note on where writes go.
const ContractNotes = "GET only. clearance-api reads what the Clearance core committed. Writes go to the core " +
	"(POST /v1/clearances/{id}/clear and /deny, /v1/provenance, /v1/records); the runtime's reads and writes " +
	"(sessions, tasks, agents and their holds, the human inbox, events, results, runtimes) are the AI " +
	"gateway's."

// Operation is one entry of the contract's operations, in api.py's shape (a portal's backend vendors it and forwards
// only the operations it lists, by method, path and roles).
type Operation struct {
	OperationID string   `json:"operationId"`
	Method      string   `json:"method"`
	Path        string   `json:"path"`
	Roles       []string `json:"roles"`
	Params      []string `json:"params"`
	Summary     string   `json:"summary"`
}

// Contract is contract/clearance-api.json: api.py's document (api, version, notes, operations), plus the answers'
// JSON schemas generated from the Go types (responses by operationId and status, schemas by name). GET /v1/contract
// adds gateway and core, where writes go, when the deployment names them.
type Contract struct {
	API        string                               `json:"api"`
	Version    string                               `json:"version"`
	Notes      string                               `json:"notes"`
	Operations []Operation                          `json:"operations"`
	Responses  map[string]map[string]map[string]any `json:"responses"`
	Schemas    map[string]any                       `json:"schemas"`
	Gateway    string                               `json:"gateway,omitempty"`
	Core       string                               `json:"core,omitempty"`
}

// ContractDoc is the contract as a value.
func ContractDoc() (*Contract, error) {
	g := &schemaGen{defs: map[string]any{}}
	doc := &Contract{API: "clearance-api", Version: APIVersion, Notes: ContractNotes, Operations: []Operation{},
		Responses: map[string]map[string]map[string]any{}}
	for _, rt := range Routes() {
		params := rt.Params
		if params == nil {
			params = []string{}
		}
		doc.Operations = append(doc.Operations, Operation{OperationID: rt.OperationID, Method: rt.Method,
			Path: rt.Path, Roles: rt.Roles, Params: params, Summary: rt.Summary})
		resp := map[string]map[string]any{"200": g.schema(reflect.TypeOf(rt.Response))}
		for _, c := range rt.Errors {
			resp[strconv.Itoa(c)] = g.schema(reflect.TypeOf(ErrorBody{}))
		}
		doc.Responses[rt.OperationID] = resp
	}
	if g.err != nil {
		return nil, g.err
	}
	doc.Schemas = g.defs
	return doc, nil
}

// ContractJSON is the committed file's bytes: two-space indent, HTML characters unescaped, a trailing newline.
func ContractJSON() ([]byte, error) {
	doc, err := ContractDoc()
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// schemaGen is internal/server's reflection generator, for this package's answer types: a struct's JSON fields
// (embedded structs flattened), required = the fields without omitempty.
type schemaGen struct {
	defs map[string]any
	err  error
}

var (
	tTime    = reflect.TypeOf(time.Time{})
	tPyTime  = reflect.TypeOf(gate.PyTime{})
	tInt     = reflect.TypeOf(decide.Int{})
	tNumber  = reflect.TypeOf(json.Number(""))
	tRaw     = reflect.TypeOf(json.RawMessage(nil))
	tRecord  = reflect.TypeOf(Record{})
	tAny     = reflect.TypeOf((*any)(nil)).Elem()
	tChanges = reflect.TypeOf(ChangePage{})
	tMarshal = reflect.TypeOf((*json.Marshaler)(nil)).Elem()
)

func (g *schemaGen) special(t reflect.Type) (map[string]any, bool) {
	switch t {
	case tTime:
		return map[string]any{"type": "string", "format": "date-time"}, true
	case tPyTime:
		return map[string]any{"type": "string", "description": "Python datetime.isoformat() of an aware time"}, true
	case tInt:
		return map[string]any{"type": "integer"}, true
	case tNumber:
		return map[string]any{"type": "number"}, true
	case tRaw, tAny:
		return map[string]any{}, true
	case tRecord:
		g.defs["EvidenceRecord"] = map[string]any{"type": "object", "additionalProperties": map[string]any{},
			"description": "A stored evidence record (schemas/evidence.schema.json, clearance.evidence/v1 or a " +
				"v0-draft row projected into it) with assurance beside it and projected naming the fields the api " +
				"added (docs/evidence.md)",
			"required": []any{"seq", "ts", "tool", "hash", "prev_hash", "schema", "provider", "subject", "assurance", "projected"}}
		return map[string]any{"$ref": "#/schemas/EvidenceRecord"}, true
	case tChanges:
		// The items are the gate's stored records, served as stored.
		return g.schema(reflect.TypeOf(struct {
			Items []ListedChange `json:"items"`
			Next  *string        `json:"next"`
		}{})), true
	}
	return nil, false
}

func defName(t reflect.Type) string {
	pkg := t.PkgPath()
	if i := strings.LastIndex(pkg, "/"); i >= 0 {
		pkg = pkg[i+1:]
	}
	if pkg == "api" {
		return t.Name()
	}
	return strings.ToUpper(pkg[:1]) + pkg[1:] + t.Name()
}

func (g *schemaGen) schema(t reflect.Type) map[string]any {
	if s, ok := g.special(t); ok {
		return s
	}
	switch t.Kind() {
	case reflect.Pointer:
		inner := g.schema(t.Elem())
		if typ, ok := inner["type"].(string); ok && len(inner) == 1 {
			return map[string]any{"type": []any{typ, "null"}}
		}
		return map[string]any{"oneOf": []any{inner, map[string]any{"type": "null"}}}
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer"}
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}
	case reflect.Interface:
		return map[string]any{}
	case reflect.Slice, reflect.Array:
		return map[string]any{"type": "array", "items": g.schema(t.Elem())}
	case reflect.Map:
		return map[string]any{"type": "object", "additionalProperties": g.schema(t.Elem())}
	case reflect.Struct:
		if t.Name() == "" {
			return g.object(t)
		}
		name := defName(t)
		ref := map[string]any{"$ref": "#/schemas/" + name}
		if _, done := g.defs[name]; done {
			return ref
		}
		if t.Implements(tMarshal) || reflect.PointerTo(t).Implements(tMarshal) {
			g.fail(fmt.Errorf("contract: %s has its own MarshalJSON: describe it in schemaGen.special", t))
			return ref
		}
		g.defs[name] = map[string]any{} // a placeholder for recursion
		g.defs[name] = g.object(t)
		return ref
	}
	g.fail(fmt.Errorf("contract: no schema for %s", t))
	return map[string]any{}
}

func (g *schemaGen) object(t reflect.Type) map[string]any {
	props := map[string]any{}
	var required []string
	g.fields(t, props, &required)
	def := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		sort.Strings(required)
		def["required"] = required
	}
	return def
}

func (g *schemaGen) fields(t reflect.Type, props map[string]any, required *[]string) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, opts, _ := strings.Cut(tag, ",")
		if f.Anonymous && name == "" {
			et := f.Type
			if et.Kind() == reflect.Pointer {
				et = et.Elem()
			}
			g.fields(et, props, required)
			continue
		}
		if name == "" {
			g.fail(fmt.Errorf("contract: %s.%s has no json tag", t, f.Name))
			continue
		}
		props[name] = g.schema(f.Type)
		if !strings.Contains(opts, "omitempty") {
			*required = append(*required, name)
		}
	}
}

func (g *schemaGen) fail(err error) {
	if g.err == nil {
		g.err = err
	}
}
