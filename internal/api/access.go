package api

import (
	"context"
	"github.com/jfillman/clearance/internal/vocab"
	"sort"
	"strings"

	"github.com/jfillman/clearance/internal/authn"
	"github.com/jfillman/clearance/internal/pycompat"
)

// Roles, as api.py names them.
const (
	RoleAuditor  = "auditor"
	RolePerson   = "person"
	RoleDelegate = "delegate"
	RoleNotifier = "notifier"
	RoleAny      = "any" // no token asked (the contract)
)

// PersonRoles are the roles of every person read (api.py PERSON_ROLES). An auditor may call any route a person may.
var PersonRoles = []string{RolePerson, RoleDelegate, RoleAuditor}

// Viewer is who is reading and what they may see (api.py Viewer).
//
//	auditor   every read (CLEARANCE_API_AUDITORS)
//	person    records of their own runs (sessions whose task they opened), records with no session that name them,
//	          records of agents whose definition owner group they are in, records that act on an app they own;
//	          changes on apps they own and changes their groups may clear
//	delegate  everything the person named in the on-behalf-of header may (CLEARANCE_DELEGATES, e.g. a portal)
//	notifier  CLEARANCE_API_NOTIFIERS: kept so the role resolves as at api.py, but no Clearance read is a
//	          notifier's since the inbox feed moved to the gateway (R-3)
type Viewer struct {
	Role   string
	Person string // user:<login> for a person or a delegate's person; the auditor's own id
	Via    string // the delegate, when a delegate asked
	Agents []string
	Apps   []string
	Groups []string
}

// All is whether the viewer sees every record (an auditor).
func (v *Viewer) All() bool { return v.Role == RoleAuditor }

// role is the role the route table is checked against: a delegate's viewer is a person, but it called as a delegate.
func (v *Viewer) role() string {
	if v.Via != "" {
		return RoleDelegate
	}
	return v.Role
}

// Directory is a person's groups (backstage.Directory).
type Directory interface {
	Groups(ctx context.Context, person string) []string
}

// Ownership is the apps a person owns, directly or through a group (backstage.Ownership).
type Ownership interface {
	Apps(ctx context.Context, person string) []string
}

// Access resolves a caller to a Viewer (api.py Access).
type Access struct {
	Delegates, Notifiers, Auditors []string // principal globs (fnmatchcase)
	Directory                      Directory
	Ownership                      Ownership
	// Owners is each live agent definition's owner group, by agent name ("" when it names none).
	Owners func() map[string]string
}

// MaxOnBehalfOf is the longest person a delegate may name.
const MaxOnBehalfOf = 200

// Viewer is api.py Access.viewer for an authenticated principal and the on-behalf-of header (vocab).
func (a *Access) Viewer(ctx context.Context, p authn.Principal, onBehalfOf string) (*Viewer, *apiError) {
	if onBehalfOf != "" {
		if !pycompat.MatchAny(p.ID, a.Delegates) {
			return nil, errorf(403, "%s may not act for a person", p.ID)
		}
		if !strings.HasPrefix(onBehalfOf, "user:") || len(onBehalfOf) > MaxOnBehalfOf {
			return nil, errorf(400, "%s must name a person (user:<name>)", vocab.Get().OnBehalfOfHeader)
		}
		return a.person(ctx, onBehalfOf, p.ID), nil
	}
	if pycompat.MatchAny(p.ID, a.Auditors) {
		return &Viewer{Role: RoleAuditor, Person: p.ID}, nil
	}
	if pycompat.MatchAny(p.ID, a.Notifiers) {
		return &Viewer{Role: RoleNotifier}, nil
	}
	if p.IsPerson() {
		return a.person(ctx, p.ID, ""), nil
	}
	return nil, errorf(403, "%s is not a person, delegate, notifier or auditor", p.ID)
}

func (a *Access) person(ctx context.Context, person, via string) *Viewer {
	v := &Viewer{Role: RolePerson, Person: person, Via: via, Agents: []string{}, Apps: []string{}, Groups: []string{}}
	if a.Directory != nil {
		v.Groups = append(v.Groups, a.Directory.Groups(ctx, person)...)
	}
	in := map[string]bool{}
	for _, g := range v.Groups {
		in[g] = true
	}
	if a.Owners != nil {
		for name, owner := range a.Owners() {
			if owner != "" && in[owner] {
				v.Agents = append(v.Agents, name)
			}
		}
	}
	sort.Strings(v.Agents)
	if a.Ownership != nil {
		for _, app := range a.Ownership.Apps(ctx, person) {
			v.Apps = append(v.Apps, strings.ToLower(app))
		}
	}
	return v
}

// allowed is api.py viewer_for's check: the role is in the route's roles, or an auditor calls a person's route.
func allowed(role string, roles []string) bool {
	for _, r := range roles {
		if r == role || (role == RoleAuditor && r == RolePerson) {
			return true
		}
	}
	return false
}
