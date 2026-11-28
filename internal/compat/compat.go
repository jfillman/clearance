// Package compat is the compatibility table (N-6c): for each release, the schema it ships, whether it can be rolled back
// from, and the provider versions its core accepts. It is data, embedded in the binary from compat.json, published with
// the release (a release asset) and served at GET /v1/version, so `clearance upgrade check`, doctor and the core's own
// provider check read one table.
//
// Versions are X.Y.Z (a leading v and a -pre or +build suffix are ignored). A version that does not parse is "unknown":
// Parse reports ok=false and nothing is refused on it.
package compat

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// CodeProviderVersion is the named refusal of a provider whose version is outside the range its core accepts.
const CodeProviderVersion = "provider_version_unsupported"

// ProviderHeader is the request header a provider sends: "<program>/<version>", for example "argocd-agent/0.58.0".
const ProviderHeader = "Clearance-Provider"

// Range is the provider versions a core accepts: Min inclusive, Max exclusive; "" is no bound.
type Range struct {
	Min string `json:"min,omitempty"`
	Max string `json:"max,omitempty"`
}

// Release is one row of the table.
type Release struct {
	// Core is the release (X.Y.Z). A core accepts what the newest row at or below its own version says, so a patch
	// release needs a row only when something changes.
	Core string `json:"core"`
	// SchemaVersion is the newest migration this release ships (0: unversioned, the idempotent DDL before N-6).
	SchemaVersion int `json:"schema_version"`
	// MinCore is the oldest core that runs on the schema after this release's migrations (N-6b).
	MinCore string `json:"min_core"`
	// NoRollback marks a release that carries a contract migration: the previous core refuses its schema, and the only
	// way back is a restore of the pre-upgrade backup (N-6e).
	NoRollback bool `json:"no_rollback"`
	// Providers is the accepted version range per provider program (the name before the slash in ProviderHeader). A
	// program not listed is not checked.
	Providers map[string]Range `json:"providers,omitempty"`
}

// Table is the whole table, oldest release first.
type Table struct {
	Format   int       `json:"format"`
	Releases []Release `json:"releases"`
}

//go:embed compat.json
var embedded []byte

// Embedded is the table this binary was built with.
func Embedded() Table {
	t, err := Parse(embedded)
	if err != nil {
		panic("compat: embedded compat.json: " + err.Error()) // a build-time fault, caught by the package's tests
	}
	return t
}

// Parse reads and validates a table: strict JSON, valid versions, rows in strictly increasing order.
func Parse(b []byte) (Table, error) {
	var t Table
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&t); err != nil {
		return Table{}, err
	}
	if t.Format != 1 {
		return Table{}, fmt.Errorf("format %d is not 1", t.Format)
	}
	var prev [3]int
	for i, r := range t.Releases {
		v, ok := Parse3(r.Core)
		if !ok {
			return Table{}, fmt.Errorf("releases[%d]: core %q is not X.Y.Z", i, r.Core)
		}
		if i > 0 && !less(prev, v) {
			return Table{}, fmt.Errorf("releases[%d]: %s is not after %s", i, r.Core, t.Releases[i-1].Core)
		}
		prev = v
		if _, ok := Parse3(r.MinCore); !ok {
			return Table{}, fmt.Errorf("releases[%d] %s: min_core %q is not X.Y.Z", i, r.Core, r.MinCore)
		}
		for name, rg := range r.Providers {
			for _, b := range []string{rg.Min, rg.Max} {
				if _, ok := Parse3(b); b != "" && !ok {
					return Table{}, fmt.Errorf("releases[%d] %s: provider %s: %q is not X.Y.Z", i, r.Core, name, b)
				}
			}
		}
	}
	return t, nil
}

// Parse3 reads X.Y.Z.
func Parse3(s string) ([3]int, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	var v [3]int
	if len(parts) != 3 {
		return v, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || p == "" || (len(p) > 1 && p[0] == '0') {
			return v, false
		}
		v[i] = n
	}
	return v, true
}

func less(a, b [3]int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// Less reports a < b. ok is false when either does not parse.
func Less(a, b string) (less_, ok bool) {
	x, ok1 := Parse3(a)
	y, ok2 := Parse3(b)
	if !ok1 || !ok2 {
		return false, false
	}
	return less(x, y), true
}

// Row is the row a core of this version follows: the newest at or below it. ok is false for a version that does not parse
// or is older than every row.
func (t Table) Row(core string) (Release, bool) {
	v, ok := Parse3(core)
	if !ok {
		return Release{}, false
	}
	best := -1
	for i, r := range t.Releases {
		rv, _ := Parse3(r.Core)
		if !less(v, rv) {
			best = i
		}
	}
	if best < 0 {
		return Release{}, false
	}
	return t.Releases[best], true
}

// Exact is the row for exactly this release.
func (t Table) Exact(core string) (Release, bool) {
	v, ok := Parse3(core)
	if !ok {
		return Release{}, false
	}
	for _, r := range t.Releases {
		if rv, _ := Parse3(r.Core); rv == v {
			return r, true
		}
	}
	return Release{}, false
}

// Previous is the newest release strictly below core.
func (t Table) Previous(core string) (Release, bool) {
	v, ok := Parse3(core)
	if !ok {
		return Release{}, false
	}
	var out Release
	found := false
	for _, r := range t.Releases {
		if rv, _ := Parse3(r.Core); less(rv, v) {
			out, found = r, true
		}
	}
	return out, found
}

// Accepts says whether a core of version core accepts a provider of this program and version. A refusal is a non-empty
// reason. Nothing is refused when the core has no row, the program has no range, or either version is unknown.
func (t Table) Accepts(core, program, version string) (ok bool, reason string) {
	row, found := t.Row(core)
	if !found {
		return true, ""
	}
	rg, found := row.Providers[program]
	if !found {
		return true, ""
	}
	pv, valid := Parse3(version)
	if !valid {
		return true, ""
	}
	if rg.Min != "" {
		if lo, _ := Parse3(rg.Min); less(pv, lo) {
			return false, fmt.Sprintf("%s %s is older than %s, the oldest this core (%s) accepts", program, version, rg.Min, core)
		}
	}
	if rg.Max != "" {
		if hi, _ := Parse3(rg.Max); !less(pv, hi) {
			return false, fmt.Sprintf("%s %s is not older than %s, the bound this core (%s) accepts below", program, version, rg.Max, core)
		}
	}
	return true, ""
}

// ParseHeader splits a ProviderHeader value into program and version.
func ParseHeader(v string) (program, version string, ok bool) {
	program, version, ok = strings.Cut(strings.TrimSpace(v), "/")
	if !ok || program == "" || version == "" || len(v) > 200 || strings.ContainsAny(v, " \t\r\n") {
		return "", "", false
	}
	return program, version, true
}

// Programs is the provider programs any row mentions, sorted.
func (t Table) Programs() []string {
	set := map[string]bool{}
	for _, r := range t.Releases {
		for p := range r.Providers {
			set[p] = true
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
