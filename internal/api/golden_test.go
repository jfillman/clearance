package api

// The golden check against Python api.py: tools/api-golden/golden_py.py (at v0.29.0, with the Python package; see
// docs/clearance-api.md "Verifying against api.py") loads a chain dump into a scratch database, records api.py's answers to a list of
// requests, and writes them with the database's DSN. This test serves the same database through the Go API and
// compares every answer. It runs only with CLEARANCE_API_GOLDEN set to that file.

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/jfillman/clearance/internal/decide/decidetest"
	"github.com/jfillman/clearance/internal/vocab/vocabtest"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"

	"github.com/jfillman/clearance/internal/authn"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/store/pg"
)

type goldenAnswer struct {
	Path   string  `json:"path"`
	Token  string  `json:"token"`
	Who    *string `json:"who"`
	Status int     `json:"status"`
	Body   any     `json:"body"`
}

func TestGoldenAgainstPythonAPI(t *testing.T) {
	file := os.Getenv("CLEARANCE_API_GOLDEN")
	if file == "" {
		t.Skip("CLEARANCE_API_GOLDEN not set (docs/clearance-api.md, Verifying against api.py)")
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var g struct {
		DSN     string         `json:"dsn"`
		Answers []goldenAnswer `json:"answers"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&g); err != nil {
		t.Fatal(err)
	}
	rd, err := pg.OpenReader(bg, g.DSN, pg.Options{MaxConns: 2, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	st := &PG{R: rd}
	defs := NewDefinitions(loadAgents(t))
	eng := decidetest.Engine(t)
	gp := gate.DefaultPolicy().View()
	auth := authn.AuthenticatorFunc(func(_ context.Context, token string) (authn.Principal, error) {
		p, ok := map[string]authn.Principal{"audit": {ID: "user:auditor", Kind: authn.KindPerson},
			"jf": {ID: "user:jfillman", Kind: authn.KindPerson}, "bob": {ID: "user:bob", Kind: authn.KindPerson},
			"tower": {ID: tower, Kind: authn.KindForeignWorkload}}[token]
		if !ok {
			return p, os.ErrPermission
		}
		return p, nil
	})
	srv, err := New(Options{Store: st, Auth: auth, Log: quiet, Engine: eng, GatePolicy: &gp,
		Definitions: defs, Access: &Access{Delegates: []string{tower}, Notifiers: []string{tower},
			Auditors: []string{"user:auditor"}, Directory: groups{"user:bob": {platform}},
			Ownership: owns{"user:jfillman": {"gate-api"}}, Owners: defs.Owners}})
	if err != nil {
		t.Fatal(err)
	}
	same, differ := 0, 0
	for _, a := range g.Answers {
		req := httptest.NewRequest("GET", a.Path, nil)
		req.Header.Set("Authorization", "Bearer "+a.Token)
		if a.Who != nil {
			req.Header.Set(vocabtest.Lab().OnBehalfOfHeader, *a.Who)
		}
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		var got any
		d := json.NewDecoder(rec.Body)
		d.UseNumber()
		if err := d.Decode(&got); err != nil {
			t.Fatalf("%s: %v", a.Path, err)
		}
		// The one field the Go API adds: which records evidence counts counted.
		if m, ok := got.(map[string]any); ok {
			delete(m, "outcomes")
		}
		if rec.Code != a.Status || !reflect.DeepEqual(got, a.Body) {
			differ++
			gb, _ := json.Marshal(got)
			wb, _ := json.Marshal(a.Body)
			if differ <= 10 {
				t.Errorf("%s as %s (%v): Go %d %.400s\n  Python %d %.400s", a.Path, a.Token, a.Who, rec.Code, gb, a.Status, wb)
			}
			continue
		}
		same++
	}
	if same == 0 {
		t.Fatal("no answer compared equal: the comparison is vacuous")
	}
	t.Logf("%d answers identical to api.py's, %d differ", same, differ)
}
