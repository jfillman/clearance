package api

import (
	"context"
	"fmt"
	"github.com/jfillman/clearance/internal/vocab"
	"slices"
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
	RoleFeed     = "feed"     // a grant-sync agent: the cleared changes and their tokens, for its clusters only
	RoleObserver = "observer" // CLEARANCE_API_OBSERVATION_READERS: a machine poller of the observation reads (O-5)
	RoleAny      = "any"      // no token asked (the contract, the keys)
)

// FeedRoles are the roles that may read the gate's changes and their tokens: people's, and a feed reader's.
var FeedRoles = []string{RolePerson, RoleDelegate, RoleAuditor, RoleFeed}

// FeedReader is one entry of CLEARANCE_API_FEED_READERS: principals (an fnmatch glob) that read the cleared
// changes of one cluster ("*": any) with their tokens. A grant-sync agent on a protected cluster is one.
type FeedReader struct {
	Principal, Cluster string
}

// ParseFeedReaders reads CLEARANCE_API_FEED_READERS: comma-separated <principal glob>=<cluster> pairs.
func ParseFeedReaders(v string) ([]FeedReader, error) {
	var out []FeedReader
	for _, pair := range strings.Split(v, ",") {
		if pair = strings.TrimSpace(pair); pair == "" {
			continue
		}
		glob, cluster, ok := strings.Cut(pair, "=")
		glob, cluster = strings.TrimSpace(glob), strings.TrimSpace(cluster)
		if !ok || glob == "" || cluster == "" || strings.ContainsAny(cluster, " \t,=") {
			return nil, fmt.Errorf("CLEARANCE_API_FEED_READERS entries are <principal glob>=<cluster>, not %q", pair)
		}
		out = append(out, FeedReader{glob, cluster})
	}
	return out, nil
}

// PersonRoles are the roles of every person read (api.py PERSON_ROLES). An auditor may call any route a person may.
var PersonRoles = []string{RolePerson, RoleDelegate, RoleAuditor}

// NotifierChangeRoles are the roles of the reads of the gate's changes a notifier also makes (the list, the counts, the
// stream): not the change by id, which carries its clearance token.
var NotifierChangeRoles = append(slices.Clone(FeedRoles), RoleNotifier)

// NotifierCountRoles are PersonRoles and the notifier (the change counts).
var NotifierCountRoles = append(slices.Clone(PersonRoles), RoleNotifier)

// ObservationRoles are the roles of the observation reads (O-5): every person, a delegate for one, an auditor, and a
// configured machine poller.
var ObservationRoles = []string{RolePerson, RoleDelegate, RoleAuditor, RoleObserver}

// Viewer is who is reading and what they may see (api.py Viewer).
//
//	auditor   every read (CLEARANCE_API_AUDITORS)
//	person    records of their own runs (sessions whose task they opened), records with no session that name them,
//	          records of agents whose definition owner group they are in, records that act on an app they own;
//	          changes on apps they own and changes their groups may clear
//	delegate  everything the person named in the on-behalf-of header may (CLEARANCE_DELEGATES, e.g. a portal)
//	notifier  CLEARANCE_API_NOTIFIERS: every change of the gate, as a list, the counts and the stream (clearance events
//	          only), redacted like a person's view but whole-scope, and no token (G5: a notification service reads who
//	          waits on whom without naming each person); no evidence record, no change by id, no clearance token
//	observer  CLEARANCE_API_OBSERVATION_READERS: coverage, observations, observation health and exceptions, whole scope; nothing else
//	feed      CLEARANCE_API_FEED_READERS: the changes on its clusters, with their tokens (the grant feed); nothing else
type Viewer struct {
	Role   string
	Person string // user:<login> for a person or a delegate's person; the auditor's own id
	Via    string // the delegate, when a delegate asked
	Agents []string
	Apps   []string
	Groups []string
	// Clusters are a feed reader's clusters ("*": any).
	Clusters []string
}

// FeedOf says whether a feed reader may read cluster's changes.
func (v *Viewer) FeedOf(cluster string) bool {
	return v.Role == RoleFeed && (in(v.Clusters, "*") || (cluster != "" && in(v.Clusters, cluster)))
}

// All is whether the viewer sees every record (an auditor).
func (v *Viewer) All() bool { return v.Role == RoleAuditor }

// AllChanges is whether the viewer sees every change of the gate: an auditor, and a notifier (G5), which reads the
// changes and their stream and nothing else.
func (v *Viewer) AllChanges() bool { return v.All() || v.Role == RoleNotifier }

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
	// ObservationReaders are principal globs that read the observation reads (coverage, observations, observation
	// health, exceptions) and nothing else.
	ObservationReaders []string
	// Admins are principal globs (user:<login>, CLEARANCE_ADMINS, the core's own list): reported by whoami.
	Admins      []string
	FeedReaders []FeedReader
	Directory   Directory
	Ownership   Ownership
	// Owners is each live agent definition's owner group, by agent name ("" when it names none).
	Owners func() map[string]string
}

// MaxOnBehalfOf is the longest person a delegate may name.
const MaxOnBehalfOf = 200

// Viewer is api.py Access.viewer for an authenticated principal and the on-behalf-of header (vocab).
func (a *Access) Viewer(ctx context.Context, p authn.Principal, onBehalfOf string) (*Viewer, *apiError) {
	return a.ViewerFor(ctx, p, onBehalfOf, nil)
}

// ViewerFor is Viewer for a route that admits roles. A machine principal may hold several machine roles (Tower's
// backend is a notifier and an observation reader): the first of them, in the order auditor, feed, notifier, observer,
// that the route admits is the viewer, else the first it holds (so the route refuses it by that role). A person and a
// delegate are unaffected. Empty roles is the first held.
func (a *Access) ViewerFor(ctx context.Context, p authn.Principal, onBehalfOf string, roles []string) (*Viewer, *apiError) {
	if onBehalfOf != "" {
		if !pycompat.MatchAny(p.ID, a.Delegates) {
			return nil, errorf(403, "%s may not act for a person", p.ID)
		}
		if !strings.HasPrefix(onBehalfOf, "user:") || len(onBehalfOf) > MaxOnBehalfOf {
			return nil, errorf(400, "%s must name a person (user:<name>)", vocab.Get().OnBehalfOfHeader)
		}
		return a.person(ctx, onBehalfOf, p.ID), nil
	}
	var held []*Viewer
	if pycompat.MatchAny(p.ID, a.Auditors) {
		held = append(held, &Viewer{Role: RoleAuditor, Person: p.ID})
	}
	var clusters []string
	for _, f := range a.FeedReaders {
		if pycompat.MatchAny(p.ID, []string{f.Principal}) && !in(clusters, f.Cluster) {
			clusters = append(clusters, f.Cluster)
		}
	}
	if len(clusters) > 0 {
		sort.Strings(clusters)
		held = append(held, &Viewer{Role: RoleFeed, Person: p.ID, Clusters: clusters})
	}
	if pycompat.MatchAny(p.ID, a.Notifiers) {
		held = append(held, &Viewer{Role: RoleNotifier, Person: p.ID})
	}
	if len(held) == 0 && p.IsPerson() {
		return a.person(ctx, p.ID, ""), nil
	}
	if !p.IsPerson() && pycompat.MatchAny(p.ID, a.ObservationReaders) {
		held = append(held, &Viewer{Role: RoleObserver, Person: p.ID})
	}
	if len(held) == 0 {
		return nil, errorf(403, "%s is not a person, delegate, notifier or auditor", p.ID)
	}
	for _, v := range held {
		if allowed(v.Role, roles) {
			return v, nil
		}
	}
	return held[0], nil
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
