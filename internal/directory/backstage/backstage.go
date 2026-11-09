// Package backstage is the deployment gate's group directory and app-owner lookup on Tower's Backstage catalog:
// gate.Directory (a person's groups are their User entity's memberOf relations) and gate.Owners (an app's owner group
// is its Component's spec.owner). Ported from autopilot reads.py BackstageDirectory and BackstageAppOwners, with the
// BackstageCatalog transport they share: the same catalog paths, the same group-ref forms, the same TTLs, and the same
// failure behaviour, which fails closed for clearing: any failure, or an unknown person or app, is no groups and no
// owner, never an error, and that answer is cached for the TTL like any other.
//
// Every call reads the token file (a projected service-account token for the `backstage` audience, rotated by the
// kubelet) afresh, has its own deadline, refuses redirects (the token never leaves for another URL), and reads at most
// MaxBody bytes of the answer. The token is never logged.
package backstage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jfillman/clearance/internal/pycompat"
)

const (
	// DefaultTimeout is each catalog call's deadline. The Python transport's was 30 s; the Go gate asks the directory
	// inside its lock and the operation's open transaction, so a hung Backstage is cut off sooner.
	DefaultTimeout = 10 * time.Second
	// MaxBody caps an answer read from the catalog; a longer one is a failure (no groups, no owner).
	MaxBody = 1 << 20
	// DirectoryTTL is how long a person's groups are kept (BackstageDirectory ttl=60).
	DirectoryTTL = 60 * time.Second
	// OwnersTTL is how long an app's owner is kept (BackstageAppOwners ttl=300).
	OwnersTTL = 300 * time.Second
	// MaxCached bounds each cache; when full, expired entries are dropped, and if none were, the cache is emptied.
	MaxCached = 4096
	// DefaultTokenFile is serve.py's BACKSTAGE_TOKEN_FILE default.
	DefaultTokenFile = "/var/run/clearance/backstage-token"
)

// name is reads.py _NAME, the shape of a catalog entity name. Python's `$` also matches before one final newline;
// valid reproduces that.
var name = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)

// valid is `_NAME.match(s.lower())`. U+0130 is the one character whose Python lower() (full case mapping, two runes)
// differs from Go's (simple mapping, "i"); Python's never matches.
func valid(s string) bool {
	if strings.ContainsRune(s, 'İ') {
		return false
	}
	return name.MatchString(strings.TrimSuffix(strings.ToLower(s), "\n"))
}

// Catalog is the catalog transport (reads.py BackstageCatalog): the base URL and the token file.
type Catalog struct {
	base      string
	tokenFile string
	timeout   time.Duration
	client    *http.Client
	log       *slog.Logger
}

// NewCatalog is a transport to the Backstage at base (its trailing slashes dropped) with the bearer token read from
// tokenFile on every call. timeout <= 0 is DefaultTimeout; log nil is slog.Default().
func NewCatalog(base, tokenFile string, timeout time.Duration, log *slog.Logger) *Catalog {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if log == nil {
		log = slog.Default()
	}
	return &Catalog{base: strings.TrimRight(base, "/"), tokenFile: tokenFile, timeout: timeout, log: log,
		client: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

var errTooLarge = errors.New("answer larger than the cap")

// get is one GET of the catalog: the status and body, or an error when it could not be asked or read (the token
// file, the connection, the deadline, the cap).
func (c *Catalog) get(ctx context.Context, path string) (int, []byte, error) {
	raw, err := os.ReadFile(c.tokenFile)
	if err != nil {
		return 0, nil, fmt.Errorf("reading the token file: %w", errors.Unwrap(err))
	}
	token := strings.TrimSpace(string(raw))
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // the URL is configuration, not news; keep the cause
		}
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody+1))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	if len(body) > MaxBody {
		return resp.StatusCode, nil, errTooLarge
	}
	return resp.StatusCode, body, nil
}

// entity GETs /api/catalog/entities/by-name/<kind>/default/<name> and decodes the object; ok false on any failure,
// a status other than 200, or an answer that is not a JSON object.
func (c *Catalog) entity(ctx context.Context, kind, n string) (map[string]any, bool) {
	status, body, err := c.get(ctx, "/api/catalog/entities/by-name/"+kind+"/default/"+url.PathEscape(n))
	if err != nil {
		c.log.WarnContext(ctx, "backstage: catalog read failed", "kind", kind, "name", n, "error", err.Error())
		return nil, false
	}
	if status != http.StatusOK {
		if status != http.StatusNotFound {
			c.log.WarnContext(ctx, "backstage: catalog read refused", "kind", kind, "name", n, "status", status)
		}
		return nil, false
	}
	var doc map[string]any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber() // an int stays an int for str() (pycompat.Str)
	if err := dec.Decode(&doc); err != nil || doc == nil || dec.More() {
		c.log.WarnContext(ctx, "backstage: catalog answer is not a JSON object", "kind", kind, "name", n)
		return nil, false
	}
	return doc, true
}

// cache is a TTL map, safe for concurrent use. Two misses for one key may both fetch; the later answer stays.
type cache[V any] struct {
	mu    sync.Mutex
	ttl   time.Duration
	clock func() time.Time
	m     map[string]entry[V]
}

type entry[V any] struct {
	at time.Time
	v  V
}

func newCache[V any](ttl time.Duration, clock func() time.Time) *cache[V] {
	if clock == nil {
		clock = time.Now
	}
	return &cache[V]{ttl: ttl, clock: clock, m: map[string]entry[V]{}}
}

func (c *cache[V]) get(k string) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[k]
	if ok && c.clock().Sub(e.at) < c.ttl {
		return e.v, true
	}
	var zero V
	return zero, false
}

func (c *cache[V]) put(k string, v V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.clock()
	if _, ok := c.m[k]; !ok && len(c.m) >= MaxCached {
		for key, e := range c.m {
			if now.Sub(e.at) >= c.ttl {
				delete(c.m, key)
			}
		}
		if len(c.m) >= MaxCached {
			clear(c.m)
		}
	}
	c.m[k] = entry[V]{now, v}
}

// Directory is gate.Directory on the catalog (reads.py BackstageDirectory). A Clearance person `user:<login>` is the
// catalog's `user:default/<login>` (Tower signs people in by GitHub login, usernameMatchingUserEntityName).
type Directory struct {
	catalog *Catalog
	cache   *cache[[]string]
}

// NewDirectory caches each person's groups for ttl (<= 0: DirectoryTTL); clock nil is time.Now.
func NewDirectory(c *Catalog, ttl time.Duration, clock func() time.Time) *Directory {
	if ttl <= 0 {
		ttl = DirectoryTTL
	}
	return &Directory{catalog: c, cache: newCache[[]string](ttl, clock)}
}

// Groups is the person's memberOf group refs (`group:...`), sorted. Not a person, a name that is not an entity
// name, an unknown person or any failure: none.
func (d *Directory) Groups(ctx context.Context, person string) []string {
	n, ok := strings.CutPrefix(person, "user:")
	if !ok || n == "" || !valid(n) {
		return nil
	}
	if g, ok := d.cache.get(n); ok {
		return append([]string(nil), g...)
	}
	g := d.fetch(ctx, n)
	d.cache.put(n, g)
	return append([]string(nil), g...)
}

func (d *Directory) fetch(ctx context.Context, n string) []string {
	doc, ok := d.catalog.entity(ctx, "user", n)
	if !ok {
		return nil
	}
	rels, _ := doc["relations"].([]any)
	set := map[string]bool{}
	for _, r := range rels {
		rel, _ := r.(map[string]any)
		if rel == nil || rel["type"] != "memberOf" {
			continue
		}
		if ref, ok := rel["targetRef"].(string); ok && strings.HasPrefix(ref, "group:") {
			set[ref] = true
		}
	}
	out := make([]string, 0, len(set))
	for g := range set {
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}

// Owners is gate.Owners on the catalog (reads.py BackstageAppOwners): an app's owner group is its Component's
// spec.owner (`component:default/<app>`).
type Owners struct {
	catalog *Catalog
	cache   *cache[string]
}

// NewOwners caches each app's owner for ttl (<= 0: OwnersTTL); clock nil is time.Now.
func NewOwners(c *Catalog, ttl time.Duration, clock func() time.Time) *Owners {
	if ttl <= 0 {
		ttl = OwnersTTL
	}
	return &Owners{catalog: c, cache: newCache[string](ttl, clock)}
}

// OwnerOf is the app's owner group ref (NormalizeOwner), and an owner of another kind (a user), an unknown app or any failure is "" (the gate then lets the
// outside group stand in as owner).
func (o *Owners) OwnerOf(ctx context.Context, app string) string {
	if !valid(app) {
		return ""
	}
	if v, ok := o.cache.get(app); ok {
		return v
	}
	v := o.fetch(ctx, app)
	o.cache.put(app, v)
	return v
}

func (o *Owners) fetch(ctx context.Context, app string) string {
	doc, ok := o.catalog.entity(ctx, "component", app)
	if !ok {
		return ""
	}
	spec, _ := doc["spec"].(map[string]any)
	raw := ""
	if spec != nil && truthy(spec["owner"]) {
		raw = pycompat.Str(spec["owner"])
	}
	return NormalizeOwner(raw)
}

// NormalizeOwner is the group ref of a spec.owner, which Backstage writes as [group:][namespace/]name: "" stays "", a
// ref with no namespace gains default/, a ref with no kind gains group:, and a ref of another kind is "".
func NormalizeOwner(raw string) string {
	if raw == "" {
		return ""
	}
	owner := raw
	if !strings.HasPrefix(raw, "group:") {
		if strings.Contains(raw, ":") {
			return ""
		}
		owner = "group:" + raw
	}
	if !strings.Contains(owner, "/") {
		owner = strings.Replace(owner, "group:", "group:default/", 1)
	}
	return owner
}

// truthy is Python's bool() of a decoded JSON value.
func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case json.Number:
		f, err := x.Float64()
		return err != nil || f != 0
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}
