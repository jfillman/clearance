package packet

import (
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Mappings are data, not code: one file per framework and version, each keyed by control, naming for every assertion
// the evaluator that tests it against the packet. Adding a framework is adding a file here.
//
//go:embed mappings/*.json
var mappingFS embed.FS

// Mapping is one framework version's controls.
type Mapping struct {
	Framework string `json:"framework"`
	Version   string `json:"version"`
	Title     string `json:"title"`
	// Revision is the date the mapping was last changed; it, not the clock, dates the published OSCAL document.
	Revision string       `json:"revision"`
	Controls []MapControl `json:"controls"`
}

// MapControl is a control and the assertions that evidence it.
type MapControl struct {
	ID         string         `json:"id"`
	Title      string         `json:"title"`
	Assertions []MapAssertion `json:"assertions"`
}

// MapAssertion names one tested statement and its evaluator.
type MapAssertion struct {
	ID        string `json:"id"`
	Statement string `json:"statement"`
	Evaluator string `json:"evaluator"`
}

// Key is "framework/version", the key a mapping is chosen by.
func (m Mapping) Key() string { return m.Framework + "/" + m.Version }

// order puts soc2/2017 first and soc2/2027-draft second, then the rest by key.
var firstMappings = []string{"soc2/2017", "soc2/2027-draft"}

// AllMappings are the mappings the build carries, validated against the evaluators.
func AllMappings() ([]Mapping, error) {
	ents, err := mappingFS.ReadDir("mappings")
	if err != nil {
		return nil, err
	}
	var out []Mapping
	for _, e := range ents {
		raw, err := mappingFS.ReadFile("mappings/" + e.Name())
		if err != nil {
			return nil, err
		}
		var m Mapping
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&m); err != nil {
			return nil, fmt.Errorf("packet: mapping %s: %w", e.Name(), err)
		}
		if m.Framework == "" || m.Version == "" || len(m.Controls) == 0 {
			return nil, fmt.Errorf("packet: mapping %s names no framework, version or control", e.Name())
		}
		for _, c := range m.Controls {
			for _, a := range c.Assertions {
				if _, ok := evaluators[a.Evaluator]; !ok {
					return nil, fmt.Errorf("packet: mapping %s, %s: no evaluator %q", m.Key(), a.ID, a.Evaluator)
				}
			}
		}
		out = append(out, m)
	}
	rank := func(k string) int {
		for i, f := range firstMappings {
			if f == k {
				return i
			}
		}
		return len(firstMappings)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := rank(out[i].Key()), rank(out[j].Key())
		if ri != rj {
			return ri < rj
		}
		return out[i].Key() < out[j].Key()
	})
	return out, nil
}

// SelectMappings are the mappings for keys ("soc2/2017"); none given is all of them.
func SelectMappings(keys []string) ([]Mapping, error) {
	all, err := AllMappings()
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return all, nil
	}
	var out []Mapping
	for _, k := range keys {
		found := false
		for _, m := range all {
			if m.Key() == k {
				out, found = append(out, m), true
			}
		}
		if !found {
			return nil, fmt.Errorf("%w: %q", ErrNoMapping, k)
		}
	}
	return out, nil
}
