package grantexpiry

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	agent "github.com/jfillman/clearance/providers/argocd/agent"
)

// Metrics is the webhook's Prometheus text exposition (no client library): its decisions, its mode, whether its cache
// is synced, and per active grant the times the alerts read. The webhook is the observer the agent's own health cannot
// be: a stalled agent stops refreshing status.checkedAt and leaves an expired grant valid, and both show here.
//
//	clearance_grant_expiry_decisions_total{mode,verdict,expired}  counter
//	clearance_grant_expiry_mode{mode}                             1
//	clearance_grant_expiry_cache_synced                           1 or 0
//	clearance_grant_status_checked_timestamp_seconds{grant_namespace,grant}  status.checkedAt (absent when unset)
//	clearance_grant_expires_timestamp_seconds{grant_namespace,grant}         spec.expiresAt (absent when unreadable)
//	clearance_grant_status_valid{grant_namespace,grant}                      1 when status.valid is true, else 0
//
// The grant's namespace is grant_namespace: a scrape's own namespace label is the pod's.
type Metrics struct {
	src  func() []agent.Grant
	mode Mode

	mu        sync.Mutex
	decisions map[[2]string]uint64 // verdict, expired
	synced    func() bool
}

// NewMetrics builds the metrics over the cache's grants (src may be nil).
func NewMetrics(src func() []agent.Grant, mode Mode) *Metrics {
	return &Metrics{src: src, mode: mode, decisions: map[[2]string]uint64{}}
}

// SetSynced names the cache's Synced.
func (m *Metrics) SetSynced(f func() bool) { m.synced = f }

func (m *Metrics) decided(v Verdict) {
	verdict := "allow"
	if !v.Allowed {
		verdict = "refuse"
	}
	m.mu.Lock()
	m.decisions[[2]string{verdict, fmt.Sprint(v.Expired)}]++
	m.mu.Unlock()
}

func esc(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

// ServeHTTP writes the exposition.
func (m *Metrics) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	var b strings.Builder
	b.WriteString("# HELP clearance_grant_expiry_decisions_total Writes the webhook decided, by verdict (refuse is would-refuse in audit) and whether the clock was the reason.\n")
	b.WriteString("# TYPE clearance_grant_expiry_decisions_total counter\n")
	m.mu.Lock()
	keys := make([][2]string, 0, len(m.decisions))
	for k := range m.decisions {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i][0]+keys[i][1] < keys[j][0]+keys[j][1] })
	for _, k := range keys {
		fmt.Fprintf(&b, "clearance_grant_expiry_decisions_total{mode=%q,verdict=%q,expired=%q} %d\n", m.mode, k[0], k[1], m.decisions[k])
	}
	m.mu.Unlock()
	b.WriteString("# HELP clearance_grant_expiry_mode The mode the webhook runs in.\n# TYPE clearance_grant_expiry_mode gauge\n")
	fmt.Fprintf(&b, "clearance_grant_expiry_mode{mode=%q} 1\n", m.mode)
	synced := 0
	if m.synced != nil && m.synced() {
		synced = 1
	}
	b.WriteString("# HELP clearance_grant_expiry_cache_synced 1 when the grant cache is synced with the API server.\n# TYPE clearance_grant_expiry_cache_synced gauge\n")
	fmt.Fprintf(&b, "clearance_grant_expiry_cache_synced %d\n", synced)
	var grants []agent.Grant
	if m.src != nil {
		grants = m.src()
	}
	b.WriteString("# HELP clearance_grant_status_checked_timestamp_seconds status.checkedAt of an active ClearanceGrant: the agent's last status write.\n# TYPE clearance_grant_status_checked_timestamp_seconds gauge\n")
	for _, g := range grants {
		if t, err := time.Parse(time.RFC3339, g.CheckedAt); err == nil {
			fmt.Fprintf(&b, "clearance_grant_status_checked_timestamp_seconds{grant_namespace=\"%s\",grant=\"%s\"} %d\n", esc(g.Namespace), esc(g.Name), t.Unix())
		}
	}
	b.WriteString("# HELP clearance_grant_expires_timestamp_seconds spec.expiresAt of an active ClearanceGrant.\n# TYPE clearance_grant_expires_timestamp_seconds gauge\n")
	for _, g := range grants {
		if t, err := time.Parse(time.RFC3339, g.Spec.ExpiresAt); err == nil {
			fmt.Fprintf(&b, "clearance_grant_expires_timestamp_seconds{grant_namespace=\"%s\",grant=\"%s\"} %d\n", esc(g.Namespace), esc(g.Name), t.Unix())
		}
	}
	b.WriteString("# HELP clearance_grant_status_valid 1 when an active ClearanceGrant's status.valid is true.\n# TYPE clearance_grant_status_valid gauge\n")
	for _, g := range grants {
		v := 0
		if g.Valid != nil && *g.Valid {
			v = 1
		}
		fmt.Fprintf(&b, "clearance_grant_status_valid{grant_namespace=\"%s\",grant=\"%s\"} %d\n", esc(g.Namespace), esc(g.Name), v)
	}
	_, _ = w.Write([]byte(b.String()))
}
