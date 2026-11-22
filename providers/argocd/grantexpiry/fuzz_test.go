package grantexpiry

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// The handler parses what the API server sends: any body must give a 4xx or a well-formed review, never a panic, and in
// enforce an allowed answer only for a request out of scope or a live listed grant entry.
func FuzzServeHTTP(f *testing.F) {
	ok, _ := json.Marshal(map[string]any{"apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview", "request": reqFor(cmDoc("app-cm", h1), nil)})
	f.Add(ok)
	f.Add([]byte(`{"request":{"uid":"u","operation":"CREATE","namespace":"prot","userInfo":{"username":"` + argo + `"},"object":{"metadata":{"annotations":null}}}}`))
	f.Add([]byte(`{"request":{"object":"x"}}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		h, err := NewHandler(Config{Mode: Enforce, ArgoCDUser: argo, Now: func() time.Time { return now }}, expiredOnly, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body)))
		if rec.Code != http.StatusOK {
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status %d", rec.Code)
			}
			return
		}
		var out struct {
			Response *response `json:"response"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Response == nil {
			t.Fatalf("a 200 that is not a review: %s", rec.Body)
		}
		// The only grant in the fixture is expired: nothing in scope may be allowed.
		var in review
		_ = json.Unmarshal(body, &in)
		if out.Response.Allowed && in.Request != nil && h.inScope(in.Request) {
			t.Fatalf("allowed in scope under an expired grant: %s", body)
		}
	})
}
