package conformance

import (
	"fmt"
	"io"
	"time"
)

// Assertion is one checked property of the provider.
type Assertion struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Pass   bool   `json:"pass"`
	Detail string `json:"detail,omitempty"`
}

// Chain is the evidence chain's state at the end of the run.
type Chain struct {
	OK      bool   `json:"ok"`
	Records int64  `json:"records"`
	Head    string `json:"head"`
}

// ProviderRef is who was tested.
type ProviderRef struct {
	URL     string `json:"url"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

// Report is the run's result; --report writes it as JSON.
type Report struct {
	Suite      string      `json:"suite"`
	Role       string      `json:"role"`
	Provider   ProviderRef `json:"provider"`
	Started    time.Time   `json:"started"`
	Finished   time.Time   `json:"finished"`
	Pass       bool        `json:"pass"`
	Assertions []Assertion `json:"assertions"`
	Chain      *Chain      `json:"chain,omitempty"`
}

// Failed is the assertions that failed.
func (r *Report) Failed() []Assertion {
	var out []Assertion
	for _, a := range r.Assertions {
		if !a.Pass {
			out = append(out, a)
		}
	}
	return out
}

// Get is the assertion with this id, or nil.
func (r *Report) Get(id string) *Assertion {
	for i := range r.Assertions {
		if r.Assertions[i].ID == id {
			return &r.Assertions[i]
		}
	}
	return nil
}

func (r *Report) add(id, title string, pass bool, detail string) {
	r.Assertions = append(r.Assertions, Assertion{ID: id, Title: title, Pass: pass, Detail: detail})
}

// Print writes one PASS or FAIL line per assertion, then a summary line.
func (r *Report) Print(w io.Writer) {
	for _, a := range r.Assertions {
		word := "PASS"
		if !a.Pass {
			word = "FAIL"
		}
		line := fmt.Sprintf("%s %-36s %s", word, a.ID, a.Title)
		if a.Detail != "" {
			line += ": " + a.Detail
		}
		fmt.Fprintln(w, line)
	}
	verdict := "PASS"
	if !r.Pass {
		verdict = "FAIL"
	}
	fmt.Fprintf(w, "%s %s %s provider %s (%s %s): %d assertions, %d failed\n", verdict, r.Suite, r.Role,
		r.Provider.URL, r.Provider.Name, r.Provider.Version, len(r.Assertions), len(r.Failed()))
}
