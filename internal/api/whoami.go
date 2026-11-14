package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/authn"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/pycompat"
)

// WhoAmI is GET /v1/whoami's answer: who the token says the caller is and what the api resolves that to. Nothing
// secret: no token, no subject claim, no key.
type WhoAmI struct {
	// Principal is the authenticated caller: user:<login> for a person, the service account's id for a machine.
	Principal string `json:"principal"`
	// Kind is the authenticator's kind: person, service-account, github-actions or foreign-workload.
	Kind string `json:"kind"`
	// Roles are every role the principal holds (person, delegate, auditor, feed, notifier, observer).
	Roles []string `json:"roles"`
	// Role is the one this read resolved to (the viewer's role).
	Role string `json:"role"`
	// Person is who the reads are as: the principal for a person, the person a delegate named.
	Person string `json:"person"`
	// Via is the delegate that asked on a person's behalf, else null.
	Via *string `json:"via"`
	// Admin is whether Person is one of CLEARANCE_ADMINS (may deny any held change and break glass).
	Admin bool `json:"admin"`
	// Auditor is whether the principal is an auditor (CLEARANCE_API_AUDITORS).
	Auditor bool `json:"auditor"`
	// Groups are the person's groups, Apps the apps they own (directly or through a group) and Agents the agent
	// definitions their groups own. Empty without a catalog (BACKSTAGE_URL).
	Groups []string `json:"groups"`
	Apps   []string `json:"apps"`
	Agents []string `json:"agents"`
	// Issuer is the token's issuer and ExpiresAt its exp (RFC 3339), when the token carried them.
	Issuer    string  `json:"issuer,omitempty"`
	ExpiresAt *string `json:"expires_at"`
}

// HeldRoles is every role p holds, in a stable order: person, delegate, auditor, feed, notifier, observer.
func (a *Access) HeldRoles(p authn.Principal) []string {
	out := []string{}
	if p.IsPerson() {
		out = append(out, RolePerson)
	}
	if pycompat.MatchAny(p.ID, a.Delegates) {
		out = append(out, RoleDelegate)
	}
	if pycompat.MatchAny(p.ID, a.Auditors) {
		out = append(out, RoleAuditor)
	}
	for _, f := range a.FeedReaders {
		if pycompat.MatchAny(p.ID, []string{f.Principal}) {
			out = append(out, RoleFeed)
			break
		}
	}
	if pycompat.MatchAny(p.ID, a.Notifiers) {
		out = append(out, RoleNotifier)
	}
	if !p.IsPerson() && pycompat.MatchAny(p.ID, a.ObservationReaders) {
		out = append(out, RoleObserver)
	}
	return out
}

// IsAdmin is whether person (user:<login>) is one of CLEARANCE_ADMINS, the core's own test.
func (a *Access) IsAdmin(person string) bool { return pycompat.MatchAny(person, a.Admins) }

func (s *Server) whoami(w http.ResponseWriter, r *http.Request, v *Viewer) {
	p, _ := authn.From(r.Context())
	out := WhoAmI{Principal: p.ID, Kind: p.Kind, Roles: s.opt.Access.HeldRoles(p), Role: v.Role, Person: v.Person,
		Groups: nz(v.Groups), Apps: nz(v.Apps), Agents: nz(v.Agents)}
	if v.Via != "" {
		// A delegate asked: the principal is the delegate, the reads are the person's.
		via := v.Via
		out.Via = &via
	}
	if strings.HasPrefix(v.Person, "user:") {
		out.Admin = s.opt.Access.IsAdmin(v.Person)
	}
	out.Auditor = in(out.Roles, RoleAuditor)
	out.Issuer, _ = p.Claims["iss"].(string)
	if exp, ok := claimUnix(p.Claims["exp"]); ok {
		t := pycompat.Isoformat(time.Unix(exp, 0).UTC())
		out.ExpiresAt = &t
	}
	writeJSON(w, 200, out)
}

func nz(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func claimUnix(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	}
	return 0, false
}

// listAwaiting is GET /v1/clearances?awaiting=me: the holding changes the caller may clear now. The qualification is
// the gate's own (gate.RoleFor: not the proposer, not already an approver, in the owner group or an outside group
// whose requirement is not yet filled), applied to the changes the viewer can already see; the api re-implements no
// policy. Admins are not listed unless they also qualify: an admin may deny any held change but clearing is the
// groups'.
func (s *Server) listAwaiting(w http.ResponseWriter, r *http.Request, v *Viewer, f ChangeFilter, limit int, after string) {
	if v.Role != RolePerson || !strings.HasPrefix(v.Person, "user:") {
		writeError(w, 400, "awaiting=me needs a person's token (or a delegate naming one)")
		return
	}
	if f.State != "" && f.State != "holding" {
		writeError(w, 400, "awaiting=me lists holding changes; state is holding or unset")
		return
	}
	f.State = "holding"
	groups := map[string]bool{}
	for _, g := range v.Groups {
		groups[g] = true
	}
	const maxScan = 2000 // changes read to fill one page; holding changes are few
	items := []json.RawMessage{}
	scanned := 0
	for len(items) < limit && scanned < maxScan {
		page, err := s.opt.Store.Changes(r.Context(), f, v, MaxLimit, after)
		if err != nil {
			s.readFailed(w, r, err)
			return
		}
		for _, raw := range page {
			var c gate.Change
			if json.Unmarshal(raw, &c) != nil {
				continue
			}
			if _, err := gate.RoleFor(v.Person, groups, &c); err == nil && len(items) < limit {
				items = append(items, raw)
			}
		}
		scanned += len(page)
		if len(page) < MaxLimit {
			break
		}
		c, ok := cursorAfter(page[len(page)-1])
		if !ok {
			break
		}
		after = c
	}
	out := ChangePage{Items: items}
	if len(items) == limit && limit > 0 {
		if c, ok := cursorAfter(items[len(items)-1]); ok {
			out.Next = &c
		}
	}
	writeJSON(w, 200, out)
}

// AnyCaller are the roles of whoami: any authenticated caller may ask who the api takes it for.
var AnyCaller = []string{RolePerson, RoleDelegate, RoleAuditor, RoleNotifier, RoleFeed, RoleObserver}
