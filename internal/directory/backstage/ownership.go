package backstage

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// OwnershipTTL is how long a person's apps are kept (reads.py BackstageOwnership ttl=60).
const OwnershipTTL = 60 * time.Second

// Ownership is clearance-api's api.Ownership on the catalog (reads.py BackstageOwnership): the apps a person owns
// are the Components whose spec.owner is the person (user:default/<login>) or one of their groups (Directory). On
// Hangar a Component's name is its app's. Cached for the TTL; a failure is no apps, never an error.
type Ownership struct {
	catalog   *Catalog
	directory *Directory
	cache     *cache[[]string]
}

// NewOwnership caches each person's apps for ttl (<= 0: OwnershipTTL); clock nil is time.Now.
func NewOwnership(c *Catalog, d *Directory, ttl time.Duration, clock func() time.Time) *Ownership {
	if ttl <= 0 {
		ttl = OwnershipTTL
	}
	return &Ownership{catalog: c, directory: d, cache: newCache[[]string](ttl, clock)}
}

// Apps is the names of the Components the person or one of their groups owns, lower-cased and sorted.
func (o *Ownership) Apps(ctx context.Context, person string) []string {
	n, ok := strings.CutPrefix(person, "user:")
	if !ok || n == "" || !valid(n) {
		return nil
	}
	if a, ok := o.cache.get(n); ok {
		return append([]string(nil), a...)
	}
	a := o.fetch(ctx, person, n)
	o.cache.put(n, a)
	return append([]string(nil), a...)
}

func (o *Ownership) fetch(ctx context.Context, person, n string) []string {
	owners := map[string]bool{"user:default/" + n: true}
	if o.directory != nil {
		for _, g := range o.directory.Groups(ctx, person) {
			owners[g] = true
		}
	}
	sorted := make([]string, 0, len(owners))
	for k := range owners {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	q := url.Values{}
	for _, ow := range sorted {
		q.Add("filter", "kind=component,spec.owner="+ow)
	}
	q.Set("fields", "metadata.name")
	q.Set("limit", "500")
	status, body, err := o.catalog.get(ctx, "/api/catalog/entities/by-query?"+q.Encode())
	if err != nil {
		o.catalog.log.WarnContext(ctx, "backstage: catalog query failed", "error", err.Error())
		return nil
	}
	if status != http.StatusOK {
		o.catalog.log.WarnContext(ctx, "backstage: catalog query refused", "status", status)
		return nil
	}
	var doc struct {
		Items []struct {
			Metadata *struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&doc); err != nil {
		o.catalog.log.WarnContext(ctx, "backstage: catalog answer is not a query result")
		return nil
	}
	set := map[string]bool{}
	for _, it := range doc.Items {
		if it.Metadata != nil && it.Metadata.Name != "" {
			set[strings.ToLower(it.Metadata.Name)] = true
		}
	}
	out := make([]string, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}
