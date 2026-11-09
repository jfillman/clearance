package backstage

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// fake is a Backstage catalog: by-name answers keyed by the path after /by-name/, and every request's path and
// Authorization header.
type fake struct {
	mu      sync.Mutex
	answers map[string]any // "user/default/x" -> the JSON object
	paths   []string
	auths   []string
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.paths = append(f.paths, r.URL.EscapedPath())
	f.auths = append(f.auths, r.Header.Get("Authorization"))
	a, ok := f.answers[strings.TrimPrefix(r.URL.Path, "/api/catalog/entities/by-name/")]
	f.mu.Unlock()
	if !ok {
		w.WriteHeader(404)
		_, _ = w.Write([]byte("{}"))
		return
	}
	_ = json.NewEncoder(w).Encode(a)
}

func (f *fake) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.paths...)
}

func tokenFile(t *testing.T, v string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "t")
	if err := os.WriteFile(p, []byte(v), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// test_gate_wiring.py test_app_owners_from_the_catalog.
func TestAppOwnersFromTheCatalog(t *testing.T) {
	f := &fake{answers: map[string]any{
		"component/default/gate-api": map[string]any{"spec": map[string]any{"owner": "group:default/team-gate"}},
		"component/default/bare":     map[string]any{"spec": map[string]any{"owner": "skyport"}},
		"component/default/person":   map[string]any{"spec": map[string]any{"owner": "user:default/dana"}},
	}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	o := NewOwners(NewCatalog(srv.URL, tokenFile(t, "x"), 0, quiet), 0, nil)
	ctx := context.Background()
	if got := o.OwnerOf(ctx, "gate-api"); got != "group:default/team-gate" {
		t.Fatal(got)
	}
	if got := o.OwnerOf(ctx, "bare"); got != "group:default/skyport" {
		t.Fatal(got)
	}
	for _, app := range []string{"person", "missing", "Bad Name!"} {
		if got := o.OwnerOf(ctx, app); got != "" {
			t.Fatalf("%s: %q", app, got)
		}
	}
	o.OwnerOf(ctx, "gate-api")
	n := 0
	for _, p := range f.calls() {
		if strings.HasSuffix(p, "/gate-api") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("gate-api asked %d times, want 1 (cached)", n)
	}
	if len(f.calls()) != 4 { // "Bad Name!" is refused before any request
		t.Fatal(f.calls())
	}
}

// test_reads.py test_directory_reads_memberof_and_caches_and_fails_closed.
func TestDirectoryReadsMemberOfAndCachesAndFailsClosed(t *testing.T) {
	f := &fake{answers: map[string]any{"user/default/jfillman": map[string]any{"relations": []any{
		map[string]any{"type": "memberOf", "targetRef": "group:default/team-platform"},
		map[string]any{"type": "ownerOf", "targetRef": "component:default/x"},
	}}}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	c := &clock{t: time.Unix(0, 0)}
	d := NewDirectory(NewCatalog(srv.URL, tokenFile(t, "tok"), 0, quiet), 60*time.Second, c.now)
	ctx := context.Background()
	want := []string{"group:default/team-platform"}
	if got := d.Groups(ctx, "user:jfillman"); !reflect.DeepEqual(got, want) {
		t.Fatal(got)
	}
	if got := d.Groups(ctx, "user:jfillman"); !reflect.DeepEqual(got, want) || len(f.calls()) != 1 {
		t.Fatal("not cached", got, f.calls())
	}
	c.add(61 * time.Second)
	d.Groups(ctx, "user:jfillman")
	if len(f.calls()) != 2 {
		t.Fatal(f.calls())
	}
	for _, p := range []string{"user:nobody", "ns/sa", "user:../x"} {
		if got := d.Groups(ctx, p); len(got) != 0 {
			t.Fatalf("%s: %v", p, got)
		}
	}
	calls := f.calls()
	if calls[0] != "/api/catalog/entities/by-name/user/default/jfillman" {
		t.Fatal(calls[0])
	}
	if len(calls) != 3 { // nobody is asked (404); ns/sa and ../x never are
		t.Fatal(calls)
	}
	if f.auths[0] != "Bearer tok" {
		t.Fatal("token not sent")
	}
}

// Every failure is no groups and no owner, cached for the TTL like an answer: fail closed for clearing.
func TestFailuresAreNoGroupsAndNoOwner(t *testing.T) {
	member := map[string]any{"relations": []any{map[string]any{"type": "memberOf", "targetRef": "group:default/web"}}}
	owned := map[string]any{"spec": map[string]any{"owner": "web"}}
	cases := map[string]http.HandlerFunc{
		"500": func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) },
		"403": func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(403) },
		"not json": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("<html>"))
		},
		"a list": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`[1]`)) },
		"relations not a list": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"relations": {"memberOf": "group:default/web"}, "spec": "web"}`))
		},
		"too large": func(w http.ResponseWriter, _ *http.Request) {
			b, _ := json.Marshal(member)
			_, _ = w.Write(append(b[:len(b)-1], []byte(`,"pad":"`+strings.Repeat("x", MaxBody)+`"}`)...))
		},
		"redirect": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		},
		"hangs": func(w http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		},
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			n := 0
			var mu sync.Mutex
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				n++
				mu.Unlock()
				if r.URL.Path == "/elsewhere" {
					t.Error("followed a redirect")
				}
				h(w, r)
			}))
			defer srv.Close()
			cat := NewCatalog(srv.URL, tokenFile(t, "x"), 200*time.Millisecond, quiet)
			d, o := NewDirectory(cat, 0, nil), NewOwners(cat, 0, nil)
			ctx := context.Background()
			for range 2 {
				if g := d.Groups(ctx, "user:alice"); len(g) != 0 {
					t.Fatal(g)
				}
				if v := o.OwnerOf(ctx, "web"); v != "" {
					t.Fatal(v)
				}
			}
			mu.Lock()
			defer mu.Unlock()
			if n != 2 {
				t.Fatalf("%d requests, want 2 (the failure is cached)", n)
			}
		})
	}
	t.Run("unreachable", func(t *testing.T) {
		srv := httptest.NewServer(http.NotFoundHandler())
		u := srv.URL
		srv.Close()
		cat := NewCatalog(u, tokenFile(t, "x"), 0, quiet)
		if g := NewDirectory(cat, 0, nil).Groups(context.Background(), "user:alice"); len(g) != 0 {
			t.Fatal(g)
		}
		if v := NewOwners(cat, 0, nil).OwnerOf(context.Background(), "web"); v != "" {
			t.Fatal(v)
		}
	})
	t.Run("no token file", func(t *testing.T) {
		f := &fake{answers: map[string]any{"user/default/alice": member, "component/default/web": owned}}
		srv := httptest.NewServer(f)
		defer srv.Close()
		cat := NewCatalog(srv.URL, filepath.Join(t.TempDir(), "missing"), 0, quiet)
		if g := NewDirectory(cat, 0, nil).Groups(context.Background(), "user:alice"); len(g) != 0 {
			t.Fatal(g)
		}
		if v := NewOwners(cat, 0, nil).OwnerOf(context.Background(), "web"); v != "" {
			t.Fatal(v)
		}
		if len(f.calls()) != 0 {
			t.Fatal("asked without a token")
		}
	})
}

// The token file is re-read on every call (the kubelet rotates the projected token), trimmed.
func TestTokenIsReadOnEveryCall(t *testing.T) {
	f := &fake{answers: map[string]any{}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	tok := tokenFile(t, "one\n")
	d := NewDirectory(NewCatalog(srv.URL+"/", tok, 0, quiet), 0, nil)
	d.Groups(context.Background(), "user:a")
	if err := os.WriteFile(tok, []byte("  two "), 0o600); err != nil {
		t.Fatal(err)
	}
	d.Groups(context.Background(), "user:b")
	if !reflect.DeepEqual(f.auths, []string{"Bearer one", "Bearer two"}) {
		t.Fatal(f.auths)
	}
	if f.paths[0] != "/api/catalog/entities/by-name/user/default/a" {
		t.Fatal("base's trailing slash kept", f.paths[0])
	}
}

func TestOwnersCacheExpires(t *testing.T) {
	f := &fake{answers: map[string]any{"component/default/web": map[string]any{"spec": map[string]any{"owner": "a"}}}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	c := &clock{t: time.Unix(0, 0)}
	o := NewOwners(NewCatalog(srv.URL, tokenFile(t, "x"), 0, quiet), 0, c.now)
	ctx := context.Background()
	if o.OwnerOf(ctx, "web") != "group:default/a" {
		t.Fatal()
	}
	f.mu.Lock()
	f.answers["component/default/web"] = map[string]any{"spec": map[string]any{"owner": "group:default/b"}}
	f.mu.Unlock()
	c.add(OwnersTTL - time.Second)
	if o.OwnerOf(ctx, "web") != "group:default/a" {
		t.Fatal("expired early")
	}
	c.add(time.Second)
	if o.OwnerOf(ctx, "web") != "group:default/b" {
		t.Fatal("did not expire at the TTL")
	}
}

func TestNormalizeOwner(t *testing.T) {
	for raw, want := range map[string]string{
		"":                       "",
		"skyport":                "group:default/skyport",
		"group:default/team":     "group:default/team",
		"group:team":             "group:default/team",
		"group:other/team":       "group:other/team",
		"user:default/dana":      "",
		"user:dana":              "",
		"group:":                 "group:default/",
		"team/sub":               "group:team/sub",
		"default/admins":         "group:default/admins",
		"{'kind': 'Group'}":      "",
		"5":                      "group:default/5",
		"group:default/a:b":      "group:default/a:b",
		"component:default/x/y":  "",
		"True":                   "group:default/True",
		"group:x:y":              "group:default/x:y",
		"Group:default/Platform": "",
	} {
		if got := NormalizeOwner(raw); got != want {
			t.Errorf("%q: %q, want %q", raw, got, want)
		}
	}
}

// spec.owner is str()'d when truthy: an int's digits; false, 0, "" and null are no owner.
func TestOwnerOfNonStringOwners(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:] {
		case "int":
			_, _ = w.Write([]byte(`{"spec":{"owner":5}}`))
		case "zero":
			_, _ = w.Write([]byte(`{"spec":{"owner":0}}`))
		case "false":
			_, _ = w.Write([]byte(`{"spec":{"owner":false}}`))
		case "dict":
			_, _ = w.Write([]byte(`{"spec":{"owner":{"kind":"Group"}}}`))
		default:
			_, _ = w.Write([]byte(`{"spec":null}`))
		}
	}))
	defer srv.Close()
	o := NewOwners(NewCatalog(srv.URL, tokenFile(t, "x"), 0, quiet), 0, nil)
	for app, want := range map[string]string{"int": "group:default/5", "zero": "", "false": "", "dict": "", "nul": ""} {
		if got := o.OwnerOf(context.Background(), app); got != want {
			t.Errorf("%s: %q, want %q", app, got, want)
		}
	}
}

func TestValidIsPythonsNameMatch(t *testing.T) {
	for s, want := range map[string]bool{
		"jfillman": true, "JFillman": true, "a": true, "a.b-c": true, "x\n": true, // Python's $ before a final \n
		"": false, "-a": false, "a-": false, "../x": false, "a b": false, "a/b": false, "x\n\n": false,
		"İ": false, strings.Repeat("a", 253): true, strings.Repeat("a", 254): false, "K": true, // Kelvin: lower() is k
	} {
		if got := valid(s); got != want {
			t.Errorf("%q: %v", s, got)
		}
	}
}

func TestCacheIsBounded(t *testing.T) {
	c := &clock{t: time.Unix(0, 0)}
	k := newCache[string](time.Minute, c.now)
	for i := range MaxCached {
		k.put(strings.Repeat("k", 1)+string(rune('a'+i%26))+strings.Repeat("x", i/26), "v")
	}
	if len(k.m) != MaxCached {
		t.Fatal(len(k.m))
	}
	k.put("one-more", "v")
	if len(k.m) != 1 {
		t.Fatalf("a full cache with nothing expired is emptied: %d", len(k.m))
	}
	k.put("old", "v")
	c.add(2 * time.Minute)
	for i := range MaxCached - 2 {
		k.put(string(rune('A'+i%26))+strings.Repeat("y", i/26), "v")
	}
	k.put("new", "v")
	if _, ok := k.get("new"); !ok || len(k.m) != MaxCached-1 {
		t.Fatalf("the expired entries make room: %d", len(k.m))
	}
}

// Many people at once: the caches are safe for concurrent use (go test -race).
func TestConcurrentLookups(t *testing.T) {
	f := &fake{answers: map[string]any{"user/default/a": map[string]any{"relations": []any{
		map[string]any{"type": "memberOf", "targetRef": "group:default/web"}}}}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	cat := NewCatalog(srv.URL, tokenFile(t, "x"), 0, quiet)
	d, o := NewDirectory(cat, 0, nil), NewOwners(cat, 0, nil)
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if g := d.Groups(context.Background(), "user:a"); len(g) != 1 {
				t.Error(g)
			}
			o.OwnerOf(context.Background(), "web")
		}()
	}
	wg.Wait()
}
