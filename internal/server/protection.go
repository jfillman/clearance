package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/store"
)

// Protected pairs a cluster's agent reports (G-ARGO-10c; docs/gate.md, "Annotation opt-in").
//
//	PUT /v1/protection/{cluster}   the cluster's whole set of protected app/environment pairs (an agent)
//	GET /v1/protection             what the core holds, and how stale each cluster's report is (any provider)
//
// The route is a provider route. Who may report for which cluster is the provider's `protection` list in
// CLEARANCE_PROVIDERS: "<principal glob>=<cluster>" entries, the cluster exact. A principal that matches no entry
// for the cluster in the path is refused, so an agent on cluster A cannot change what is protected on cluster B,
// and a provider with no `protection` list reports nothing. The cluster belongs to the first provider that lists
// it (as a targets source does).
//
// A report is the whole set, content-addressed, and replaces the cluster's earlier one. A changed set is one
// protection.report record (who, which pairs were added and removed, whether a removed pair is still protected by
// CLEARANCE_PROTECTED_ENVIRONMENTS); an unchanged one records nothing and only renews the report's time, which is how
// staleness is told. Nothing the core does depends on that time: an agent that stops reporting leaves its last set in
// force, and GET /v1/protection says how old it is.

var protectionClusterRx = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\z`)

// MaxProtectionBody is PUT /v1/protection/{cluster}'s body cap.
const MaxProtectionBody = 1 << 20

// MaxProtectionRecordsPerHour bounds how many protection.report records one cluster can write per hour, so that a
// compromised agent cannot flood the ledger with set changes. Over it, a changing report is refused with 429.
const MaxProtectionRecordsPerHour = 30

// MaxProtectionAddsPerHour bounds, per cluster, the records of reports that only ADD pairs: removals never spend it, so a
// legitimate addition is never refused because of removals, and a compromised agent cannot write 5000 additions one by one.
const MaxProtectionAddsPerHour = 300

// ProtectionStaleAfter is how old a cluster's last report may be before GET /v1/protection says stale (three missed
// reports of the agent's five minutes). Staleness is shown, never acted on.
const ProtectionStaleAfter = 15 * time.Minute

// ProtectionRequest is PUT /v1/protection/{cluster}'s body: every pair the cluster's agent reports as protected.
// reason is free text the agent gives for the report (an opt-out says which Application and why), recorded as claimed.
type ProtectionRequest struct {
	Pairs  []gate.ProtectedPair `json:"pairs" contract:"required"`
	Reason string               `json:"reason,omitempty"`
	// Seq numbers the report; it only goes up per cluster. A lower or equal number carrying another set is refused 409.
	Seq int64 `json:"seq,omitempty"`
	// Exempted are the pairs this report removes because a gate exemption released their Application (docs/gate.md,
	// "The gate rule and exemptions"). A pair whose environment CLEARANCE_PROTECTED_ENVIRONMENTS protects is refused
	// 409 ("refused: static"): no exemption lifts the list. Absent: no pair leaves for an exemption.
	Exempted []gate.ProtectedPair `json:"exempted,omitempty"`
}

// ProtectionResult is what a report did: the cluster, the digest of the set now held, how many pairs, whether it
// differs from what the core held, the record's seq (null when nothing changed), the pairs it added and removed, and
// which removed pairs CLEARANCE_PROTECTED_ENVIRONMENTS still protects (the removal does not unprotect those).
type ProtectionResult struct {
	Cluster       string               `json:"cluster"`
	Digest        string               `json:"digest"`
	Pairs         int                  `json:"pairs"`
	Changed       bool                 `json:"changed"`
	Seq           *int64               `json:"seq"`
	HeldSeq       int64                `json:"held_seq"`
	Added         []gate.ProtectedPair `json:"added"`
	Removed       []gate.ProtectedPair `json:"removed"`
	StaticRemoved []gate.ProtectedPair `json:"static_removed"`
}

// ProtectionCluster is one cluster's reported set in GET /v1/protection.
type ProtectionCluster struct {
	Cluster    string               `json:"cluster"`
	Digest     string               `json:"digest"`
	Seq        int64                `json:"seq"`
	Pairs      []gate.ProtectedPair `json:"pairs"`
	ReportedAt string               `json:"reported_at"`
	ChangedAt  string               `json:"changed_at"`
	AgeSeconds int64                `json:"age_seconds"`
	Stale      bool                 `json:"stale"`
}

// ProtectionState is GET /v1/protection's answer.
type ProtectionState struct {
	Static            []string            `json:"static"`
	StaleAfterSeconds int64               `json:"stale_after_seconds"`
	Clusters          []ProtectionCluster `json:"clusters"`
}

// protectionVerified: the core authenticated the caller, set ts, chose the kind and computed the digest and the diff.
var protectionVerified = targetsVerified

func init() {
	routeTable = append(routeTable,
		Route{
			Method: "PUT", Path: "/v1/protection/{cluster}", OperationID: "reportProtection", Auth: AuthProvider,
			MaxBody: MaxProtectionBody,
			Summary: "The app and environment pairs one cluster's agent reports as protected (an Application that opted " +
				"in). The set replaces the one the core holds for that cluster and adds to " +
				"CLEARANCE_PROTECTED_ENVIRONMENTS: the core protects a pair if the list or the report does. A changed set is one " +
				"protection.report record naming the pairs added and removed; an unchanged one records nothing and renews " +
				"the report's time. Only a provider whose `protection` list pairs the caller's principal with this cluster; " +
				"a missing report never removes a pair.",
			Request:   ProtectionRequest{},
			Responses: append([]Response{{200, "what was held, and whether it changed", ProtectionResult{}}}, errs(400, 401, 403, 404, 409, 413, 429, 503)...),
			serve:     func(s *Server) http.HandlerFunc { return s.reportProtection },
		},
		Route{
			Method: "GET", Path: "/v1/protection", OperationID: "getProtection", Auth: AuthProvider, MaxBody: DefaultMaxBody,
			Summary: "The pairs each cluster's agent reported as protected, how old each report is, and whether it is stale " +
				"(older than stale_after_seconds). Staleness is shown only: the core keeps acting on the last report.",
			Responses: append([]Response{{200, "the reported sets", ProtectionState{}}}, errs(401, 403, 404, 503)...),
			serve:     func(s *Server) http.HandlerFunc { return s.getProtection },
		})
}

// mayReportProtection says whether the principal may report for the cluster: an entry "<principal glob>=<cluster>".
func (p *Provider) mayReportProtection(principal, cluster string) bool {
	for _, e := range p.Protection {
		glob, c, ok := strings.Cut(e, "=")
		if ok && c == cluster && pycompat.Match(principal, glob) {
			return true
		}
	}
	return false
}

// listsProtection says whether the provider's protection list names the cluster at all.
func (p *Provider) listsProtection(cluster string) bool {
	for _, e := range p.Protection {
		if _, c, ok := strings.Cut(e, "="); ok && c == cluster {
			return true
		}
	}
	return false
}

// checkProtection holds a provider's protection list to its shape: "<principal glob>=<cluster>", the cluster a name.
func checkProtection(i int, p *Provider) error {
	for _, e := range p.Protection {
		glob, c, ok := strings.Cut(e, "=")
		if !ok || glob == "" || len(e) > 200 || !protectionClusterRx.MatchString(c) {
			return fmt.Errorf("CLEARANCE_PROVIDERS[%d]: protection entries are <principal glob>=<cluster>, the cluster a name, got %q", i, e)
		}
		if !pycompat.MatchAny(glob, p.Principals) {
			return fmt.Errorf("CLEARANCE_PROVIDERS[%d]: protection entry %q names a principal the provider's principals do not match", i, e)
		}
	}
	return nil
}

func (s *Server) reportProtection(w http.ResponseWriter, r *http.Request) {
	p, prov, ok := s.caller(w, r)
	if !ok {
		return
	}
	if s.opt.Gate == nil {
		writeError(w, http.StatusNotFound, "the deployment gate is off")
		return
	}
	cluster := r.PathValue("cluster")
	if !protectionClusterRx.MatchString(cluster) {
		writeError(w, http.StatusBadRequest, "cluster is a name")
		return
	}
	if !prov.mayReportProtection(p.ID, cluster) {
		writeError(w, http.StatusForbidden, fmt.Sprintf("%s may not report protection for cluster %q (provider %q)", p.ID, cluster, prov.Name))
		return
	}
	// A cluster belongs to the first provider that lists it: another provider's report for it is refused.
	for i := range s.opt.Providers {
		if o := &s.opt.Providers[i]; o.listsProtection(cluster) {
			if o.Name != prov.Name {
				writeError(w, http.StatusForbidden, fmt.Sprintf("cluster %q belongs to provider %q", cluster, o.Name))
				return
			}
			break
		}
	}
	var body ProtectionRequest
	if err := strictDecode(r.Body, &body); err != nil {
		bodyError(w, err)
		return
	}
	if len(body.Reason) > 500 || strings.ContainsRune(body.Reason, 0) {
		writeError(w, http.StatusBadRequest, "reason is at most 500 bytes")
		return
	}
	if body.Pairs == nil {
		writeError(w, http.StatusBadRequest, "pairs is required (an empty list withdraws every pair)")
		return
	}
	if body.Seq < 1 {
		writeError(w, http.StatusBadRequest, "seq is required (1 or more): a report carries a number that only goes up per cluster, so an old report cannot replace a newer one")
		return
	}
	pairs, err := gate.NormalizePairs(body.Pairs)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var exempted []gate.ProtectedPair
	if body.Exempted != nil {
		if exempted, err = gate.NormalizePairs(body.Exempted); err != nil {
			writeError(w, http.StatusBadRequest, "exempted: "+err.Error())
			return
		}
		for _, p := range exempted {
			if slices.Contains(pairs, p) {
				writeError(w, http.StatusBadRequest, fmt.Sprintf("exempted: %s/%s is still in pairs: an exempted pair is one the report removes", p.App, p.Env))
				return
			}
		}
		if err := s.opt.Gate.RefuseExemptedStatic(cluster, exempted); err != nil {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
	}
	doc, _ := json.Marshal(pairs)
	sum := sha256.Sum256(doc)
	digest := hex.EncodeToString(sum[:])
	out := ProtectionResult{Cluster: cluster, Digest: digest, Pairs: len(pairs), Added: []gate.ProtectedPair{},
		Removed: []gate.ProtectedPair{}, StaticRemoved: []gate.ProtectedPair{}}
	var status int // 0: accepted; 409: refused as older than the held report; 429: over the hourly bound
	var why string
	err = s.opt.Store.Atomic(r.Context(), func(tx store.Tx) error {
		held, err := tx.Protections(r.Context())
		if err != nil {
			return err
		}
		var cur store.ProtectionSet
		var was []gate.ProtectedPair
		for _, h := range held {
			if h.Cluster == cluster {
				cur = h
				if err := json.Unmarshal(h.Doc, &was); err != nil {
					return err
				}
			}
		}
		// The same number and set again (its number and its set are the ones held): the agent's heartbeat, or a retry after
		// a lost answer. Its exempted pairs are not checked against the held set (they were when it was first taken, and are
		// no longer held). A reason it carries is recorded, as for any unchanged report with one: the core does not keep the
		// last reason, so it cannot tell a retry's from a new explanation, and recording twice beats losing one.
		replay := cur.Digest != "" && cur.Digest == digest && body.Seq == cur.Seq
		reason := body.Reason
		now := s.opt.Clock()
		next := store.ProtectionSet{Cluster: cluster, Digest: digest, Doc: doc, Seq: cur.Seq, WindowStart: cur.WindowStart, WindowCount: cur.WindowCount, AddCount: cur.AddCount}
		if next.WindowStart.IsZero() || now.Sub(next.WindowStart) >= time.Hour || now.Before(next.WindowStart) {
			next.WindowStart, next.WindowCount, next.AddCount = now, 0, 0
		}
		out.HeldSeq = cur.Seq
		countIt := true
		record := func(tool, target, result string) error {
			rec, err := tx.Append(r.Context(), store.Event{"ts": evidence.ISO(now), "task_id": nil, "session": nil,
				"parent": nil, "principal": "provider:" + prov.Name, "agent": nil, "tool": tool, "tier": nil,
				"decision": "allow", "rule": nil, "target": target, "args_sha256": digest, "result": result,
				"caller": callerField(prov, p)}, s.coreWriter(protectionVerified))
			if err != nil {
				return err
			}
			if countIt {
				next.WindowCount++
			} else {
				next.AddCount++
			}
			seq, _ := gate.SeqInt(rec["seq"])
			out.Changed, out.Seq = true, &seq
			return nil
		}
		// An old or replayed report cannot replace a newer one: a number that is not above the held one, with a set that
		// is not the held one, is refused (and recorded, once, while the hourly bound allows).
		if body.Seq > 0 && cur.Digest != "" && body.Seq <= cur.Seq && digest != cur.Digest {
			status, why = http.StatusConflict, fmt.Sprintf("report %d is not above the held report %d and carries another set", body.Seq, cur.Seq)
			key := fmt.Sprint(cluster, "|", body.Seq, "|", digest)
			if !s.protectionRefused.has(key) && next.WindowCount < MaxProtectionRecordsPerHour {
				s.protectionRefused.add(key)
				if err := record("protection.refused", "protection:"+cluster, fmt.Sprintf("%s (principal %s); not applied", why, p.ID)); err != nil {
					return err
				}
				out.Changed, out.Seq = false, nil
				keep := cur // the held set stays; only the recording window moves
				keep.WindowStart, keep.WindowCount, keep.AddCount = next.WindowStart, next.WindowCount, next.AddCount
				return tx.PutProtection(r.Context(), keep)
			}
			return nil
		}
		// After the number check (an old or replayed number with another set is a 409, which tells the agent to read the
		// held report again): an exempted pair is one the report removes, so it must be held.
		for _, e := range exempted {
			if !replay && !slices.Contains(was, e) {
				status, why = http.StatusBadRequest, fmt.Sprintf("exempted: %s/%s is not in the held report: an exempted pair is one the report removes", e.App, e.Env)
				return nil
			}
		}
		changed := cur.Digest != digest
		// A report that only ADDS pairs is never refused by the hourly bound and is not counted against it: the bound is
		// there to stop a flood of removals and re-additions, and one tenant flipping its annotation must not keep another
		// team's pair out. Additions are bounded by the pair cap (MaxProtectedPairs).
		onlyAdds := changed
		for _, o := range was {
			if !slices.Contains(pairs, o) {
				onlyAdds = false
			}
		}
		if (changed && !onlyAdds) || (!changed && reason != "") { // removals, mixed reports and reasons are bounded
			if next.WindowCount >= MaxProtectionRecordsPerHour {
				status, why = http.StatusTooManyRequests, fmt.Sprintf("at most %d removals or explained reports are recorded per hour for a cluster", MaxProtectionRecordsPerHour)
				return nil
			}
		}
		if onlyAdds && next.AddCount >= MaxProtectionAddsPerHour {
			status, why = http.StatusTooManyRequests, fmt.Sprintf("at most %d additions are recorded per hour for a cluster", MaxProtectionAddsPerHour)
			return nil
		}
		countIt = !onlyAdds
		if body.Seq > next.Seq {
			next.Seq = body.Seq
		}
		out.HeldSeq = next.Seq
		if !changed && reason == "" {
			return tx.PutProtection(r.Context(), next)
		}
		for _, n := range pairs {
			if !slices.Contains(was, n) {
				out.Added = append(out.Added, n)
			}
		}
		for _, o := range was {
			if !slices.Contains(pairs, o) {
				out.Removed = append(out.Removed, o)
				if s.opt.Gate.StaticProtects(cluster, o.Env) {
					out.StaticRemoved = append(out.StaticRemoved, o)
				}
			}
		}
		result := fmt.Sprintf("%d pairs sha256:%s", len(pairs), digest)
		if cur.Digest != "" && changed {
			result += " (was sha256:" + cur.Digest + ")"
		} else if !changed {
			result += " (unchanged)"
		}
		result += list("; added ", out.Added, nil) + list("; removed ", out.Removed, out.StaticRemoved)
		result += list("; removed for a gate exemption ", exempted, nil)
		if reason != "" {
			result += "; reason (claimed): " + reason
		}
		if len(result) > MaxFieldText {
			result = result[:MaxFieldText-3] + "..."
		}
		if err := record("protection.report", "protection:"+cluster, result); err != nil {
			return err
		}
		if !changed { // only the reason was recorded: no set changed
			out.Changed = false
		}
		return tx.PutProtection(r.Context(), next)
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "protection: report failed", "cluster", cluster, "error", err.Error())
		writeError(w, http.StatusServiceUnavailable, "the report could not be recorded")
		return
	}
	if status != 0 {
		writeError(w, status, why)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// list renders up to 20 pairs as "app/env, ..."; a pair in static is marked "(still protected by the list)".
func list(prefix string, pairs, static []gate.ProtectedPair) string {
	if len(pairs) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(prefix)
	for i, p := range pairs {
		if i == 20 {
			fmt.Fprintf(&b, ", and %d more", len(pairs)-20)
			break
		}
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(p.App + "/" + p.Env)
		if slices.Contains(static, p) {
			b.WriteString(" (still protected by CLEARANCE_PROTECTED_ENVIRONMENTS)")
		}
	}
	return b.String()
}

// reportsFor says whether the principal is one a `protection` entry of the provider names.
func (p *Provider) reportsFor(principal string) bool {
	for _, e := range p.Protection {
		if glob, _, ok := strings.Cut(e, "="); ok && pycompat.Match(principal, glob) {
			return true
		}
	}
	return false
}

func (s *Server) getProtection(w http.ResponseWriter, r *http.Request) {
	p, prov, ok := s.caller(w, r)
	if !ok {
		return
	}
	// What is read: an admin reads everything; the agent that reports a cluster reads that cluster's set (it needs its last
	// sequence number) and the static list; any other provider needs none of it and gets 403. The static list is the
	// deployment's protected-environment globs, which is not for every provider principal.
	admin := s.opt.Gate != nil && pycompat.MatchAny(p.ID, s.opt.Gate.Config.Admins)
	if !admin && !prov.reportsFor(p.ID) {
		writeError(w, http.StatusForbidden, p.ID+" does not report protection and is not an admin: it may not read it")
		return
	}
	if s.opt.Gate == nil {
		writeError(w, http.StatusNotFound, "the deployment gate is off")
		return
	}
	sets, err := s.opt.Store.Protections(r.Context())
	if err != nil {
		s.log.ErrorContext(r.Context(), "protection: reading failed", "error", err.Error())
		writeError(w, http.StatusServiceUnavailable, "the protection could not be read")
		return
	}
	now := s.opt.Clock()
	out := ProtectionState{Static: append([]string{}, s.opt.Gate.Config.Protected...), StaleAfterSeconds: int64(ProtectionStaleAfter / time.Second),
		Clusters: []ProtectionCluster{}}
	for _, set := range sets {
		if !admin && !prov.mayReportProtection(p.ID, set.Cluster) {
			continue
		}
		c, err := protectionCluster(set, now)
		if err != nil {
			s.log.ErrorContext(r.Context(), "protection: a stored set is not a list of pairs", "cluster", set.Cluster)
			writeError(w, http.StatusServiceUnavailable, "the protection could not be read")
			return
		}
		out.Clusters = append(out.Clusters, c)
	}
	writeJSON(w, http.StatusOK, out)
}

// protectionCluster is one stored set as GET /v1/protection shows it at now: its age, and stale when the last report
// is older than ProtectionStaleAfter. Nothing else reads the age.
func protectionCluster(set store.ProtectionSet, now time.Time) (ProtectionCluster, error) {
	var pairs []gate.ProtectedPair
	if err := json.Unmarshal(set.Doc, &pairs); err != nil {
		return ProtectionCluster{}, err
	}
	age := now.Sub(set.ReportedAt)
	return ProtectionCluster{Cluster: set.Cluster, Digest: set.Digest, Seq: set.Seq, Pairs: pairs, ReportedAt: evidence.ISO(set.ReportedAt),
		ChangedAt: evidence.ISO(set.ChangedAt), AgeSeconds: int64(age / time.Second), Stale: age > ProtectionStaleAfter}, nil
}

// refusedSet remembers the refused reports already recorded (cluster, number, digest), so a replay is recorded once. It is
// bounded (the oldest is forgotten past maxRefusedKeys) and only a refusal that is recorded is added to it.
type refusedSet struct {
	mu    sync.Mutex
	m     map[string]bool
	order []string
}

const maxRefusedKeys = 1000

func (r *refusedSet) has(k string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.m[k]
}

func (r *refusedSet) add(k string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.m == nil {
		r.m = map[string]bool{}
	}
	if r.m[k] {
		return
	}
	r.m[k] = true
	r.order = append(r.order, k)
	for len(r.order) > maxRefusedKeys {
		delete(r.m, r.order[0])
		r.order = r.order[1:]
	}
}
