// Package grctest is the fakes P-4 is built against: a Vanta that behaves as its public documentation describes
// (docs/grc-push.md), and a clearance-api that lists changes. Test code only.
package grctest

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jfillman/clearance/internal/gate"
)

// Vanta is a fake Vanta API: POST /oauth/token (JSON, client_credentials) and PUT /v1/resources/custom_resource (a
// full-state replace of one resource, keyed by uniqueId). Script failures with Fail.
type Vanta struct {
	*httptest.Server
	ClientID, ClientSecret string
	// Token is what a mint returns; a second mint invalidates the first (one token per application).
	mu        sync.Mutex
	minted    int
	current   string
	Sets      map[string]map[string]map[string]any // resourceId -> uniqueId -> resource
	Bodies    [][]byte                             // every PUT body, as received
	Puts      int
	Tokens    int
	Fail      []Failure // consumed one per PUT, in order, before normal service
	TokenFail int       // status for the next token mints (0 = ok), decremented per mint
	// Huge, when set, makes a PUT answer with this many bytes of junk.
	Huge int
	// Headers captured from the last PUT.
	LastAuth, LastCT string
	TokenBodies      [][]byte
}

// Failure is one scripted answer.
type Failure struct {
	Status     int
	RetryAfter string
}

// NewVanta starts a fake with these credentials.
func NewVanta(id, secret string) *Vanta {
	v := &Vanta{ClientID: id, ClientSecret: secret, Sets: map[string]map[string]map[string]any{}}
	v.Server = httptest.NewServer(http.HandlerFunc(v.serve))
	return v
}

func (v *Vanta) serve(w http.ResponseWriter, r *http.Request) {
	v.mu.Lock()
	defer v.mu.Unlock()
	body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<20))
	switch {
	case r.Method == "POST" && r.URL.Path == "/oauth/token":
		v.Tokens++
		v.TokenBodies = append(v.TokenBodies, body)
		if r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, `{"error":"invalid_request"}`, 400)
			return
		}
		var in map[string]string
		if json.Unmarshal(body, &in) != nil || in["grant_type"] != "client_credentials" || in["client_id"] != v.ClientID ||
			in["client_secret"] != v.ClientSecret || in["scope"] == "" {
			http.Error(w, `{"error":"invalid_client","echo":"`+in["client_secret"]+`"}`, 401)
			return
		}
		v.minted++
		v.current = "tok-" + strconv.Itoa(v.minted) + "-secret-access-token"
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": v.current, "expires_in": 3600, "token_type": "Bearer"})
	case r.Method == "PUT" && r.URL.Path == "/v1/resources/custom_resource":
		v.Puts++
		v.Bodies = append(v.Bodies, body)
		v.LastAuth, v.LastCT = r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		if len(v.Fail) > 0 {
			f := v.Fail[0]
			v.Fail = v.Fail[1:]
			if f.RetryAfter != "" {
				w.Header().Set("Retry-After", f.RetryAfter)
			}
			http.Error(w, `{"error":"scripted","echo":"`+strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")+`"}`, f.Status)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+v.current || v.current == "" {
			http.Error(w, `{"error":"unauthorized"}`, 401)
			return
		}
		var in struct {
			ResourceID string `json:"resourceId"`
			Resources  []struct {
				DisplayName      string         `json:"displayName"`
				UniqueID         string         `json:"uniqueId"`
				ExternalURL      string         `json:"externalUrl"`
				CustomProperties map[string]any `json:"customProperties"`
			} `json:"resources"`
		}
		if json.Unmarshal(body, &in) != nil || in.ResourceID == "" {
			http.Error(w, `{"error":"bad body"}`, 400)
			return
		}
		set := map[string]map[string]any{}
		for _, res := range in.Resources {
			if res.UniqueID == "" || res.DisplayName == "" || !strings.HasPrefix(res.ExternalURL, "https://") {
				http.Error(w, `{"error":"resource needs displayName, uniqueId and an https externalUrl"}`, 400)
				return
			}
			set[res.UniqueID] = map[string]any{"displayName": res.DisplayName, "externalUrl": res.ExternalURL, "customProperties": res.CustomProperties}
		}
		v.Sets[in.ResourceID] = set // the state of the world: what is missing is gone
		if v.Huge > 0 {
			w.Write([]byte(`{"success":true,"pad":"`))
			w.Write([]byte(strings.Repeat("x", v.Huge)))
			w.Write([]byte(`"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
	default:
		http.NotFound(w, r)
	}
}

// Items is how many resources the hub holds for resourceID.
func (v *Vanta) Items(resourceID string) int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.Sets[resourceID])
}

// Item returns one held resource.
func (v *Vanta) Item(resourceID, uniqueID string) (map[string]any, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	m, ok := v.Sets[resourceID][uniqueID]
	return m, ok
}

// AllBodies joins every request body the fake received (tokens and puts): what left the tenant.
func (v *Vanta) AllBodies() []byte {
	v.mu.Lock()
	defer v.mu.Unlock()
	var out []byte
	for _, b := range v.Bodies {
		out = append(out, b...)
	}
	return out
}

// API is a fake clearance-api: GET /v1/clearances, filtered by state, env and since.
type API struct {
	*httptest.Server
	mu      sync.Mutex
	Changes []gate.Change
	// PageSize forces pagination (0: one page).
	PageSize int
	// Override, when set, is served as-is with a 200 (an answer that is not a page); Extra are raw items appended to
	// every page's items (records that will not parse); Gets counts the list calls; Query is the last one's query.
	Override string
	Extra    []json.RawMessage
	Gets     int
	Query    string
}

// NewAPI starts one.
func NewAPI() *API {
	a := &API{}
	a.Server = httptest.NewServer(http.HandlerFunc(a.serve))
	return a
}

// Set replaces the changes served.
func (a *API) Set(cs ...gate.Change) { a.mu.Lock(); a.Changes = cs; a.mu.Unlock() }

func (a *API) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/v1/clearances" || r.Header.Get("Authorization") == "" {
		http.Error(w, `{"error":"no"}`, 401)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Gets++
	a.Query = r.URL.RawQuery
	if a.Override != "" {
		w.Write([]byte(a.Override))
		return
	}
	q := r.URL.Query()
	items := []json.RawMessage{}
	for _, c := range a.Changes {
		if (q.Get("state") != "" && c.State != q.Get("state")) || (q.Get("env") != "" && c.Env != q.Get("env")) {
			continue
		}
		if s := q.Get("since"); s != "" {
			if t, err := time.Parse("2006-01-02T15:04:05Z", s); err != nil || c.UpdatedAt.Time.Before(t) {
				continue
			}
		}
		b, _ := json.Marshal(c)
		items = append(items, b)
	}
	items = append(items, a.Extra...)
	var next *string
	if a.PageSize > 0 {
		start, _ := strconv.Atoi(q.Get("after"))
		end := start + a.PageSize
		if end < len(items) {
			s := strconv.Itoa(end)
			next = &s
		} else {
			end = len(items)
		}
		if start > len(items) {
			start = len(items)
		}
		items = items[start:end]
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"items": items, "next": next})
}
