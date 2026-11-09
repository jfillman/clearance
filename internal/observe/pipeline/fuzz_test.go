package pipeline

import (
	"encoding/json"
	"testing"

	"github.com/jfillman/clearance/internal/vocab"
)

// FuzzProcess: whatever a collector hands over, Process answers or refuses and never panics.
func FuzzProcess(f *testing.F) {
	rs, err := Default()
	if err != nil {
		f.Fatal(err)
	}
	for _, name := range []string{"kubernetes.jsonl", "aws.jsonl"} {
		for _, r := range corpus(f, name) {
			f.Add(r.Provider, string(r.Raw), string(r.Before))
		}
	}
	f.Add("kubernetes", `{"auditID":"x","verb":"patch","user":{"username":"u"},"objectRef":{"resource":"secrets"}}`, `[1]`)
	f.Fuzz(func(t *testing.T, provider, raw, before string) {
		if !json.Valid([]byte(raw)) {
			return
		}
		p := New(rs, nil, vocab.Default())
		r := RawEvent{Provider: provider, Scope: "prod-eu-1", Raw: json.RawMessage(raw)}
		if before != "" && json.Valid([]byte(before)) {
			r.Before = json.RawMessage(before)
		}
		_, _, _, _ = p.Process(r)
		p.Flush()
	})
}
