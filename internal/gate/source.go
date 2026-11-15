package gate

import (
	"fmt"
	"sort"
	"strings"

	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/vocab"
)

// MaxSourcePeople bounds each of a change's source lists (authors, mergers).
const MaxSourcePeople = 64

// SourcePeople is the people behind a change, as the verifier resolved them from authenticated facts: the openers
// of the source pull requests a release bundles (Authors), the people who merged them (Mergers) and the person who
// promoted the release (Promoter). With the proposer they are the people who may not clear the change (RoleFor):
// one proposer field alone lets a developer arrange for someone else, or a bot, to be the proposer and then clear
// their own change. Each entry is a principal in the proposer's form. The set only grows (Change.absorb).
type SourcePeople struct {
	Authors  []string `json:"authors,omitempty"`
	Mergers  []string `json:"mergers,omitempty"`
	Promoter string   `json:"promoter,omitempty"`
}

var sourceKeys = setOf("authors", "mergers", "promoter")

// parseSource reads request.source; an empty set is no set (nil).
func parseSource(v any) (*SourcePeople, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, bad("source is an object {authors, mergers, promoter}")
	}
	if k := unknownKey(m, sourceKeys); k != "" {
		return nil, bad("source has an unknown field %s", pycompat.Repr(k))
	}
	out := &SourcePeople{}
	for _, f := range []struct {
		key string
		dst *[]string
	}{{"authors", &out.Authors}, {"mergers", &out.Mergers}} {
		xs, ok := listOfStrings(m, f.key, principalRx.MatchString)
		if !ok || len(xs) > MaxSourcePeople {
			return nil, bad("source.%s is a list of at most %d principals", f.key, MaxSourcePeople)
		}
		seen := map[string]bool{}
		for _, x := range xs {
			if seen[bareName(x)] {
				return nil, bad("source.%s names %s twice", f.key, pycompat.Repr(x))
			}
			seen[bareName(x)] = true
		}
		if len(xs) > 0 {
			*f.dst = xs
		}
	}
	if p, present := m["promoter"]; present && p != nil && p != "" {
		s, isStr := p.(string)
		if !isStr || !principalRx.MatchString(s) {
			return nil, bad("source.promoter is a principal")
		}
		out.Promoter = s
	}
	if out.empty() {
		return nil, nil
	}
	return out, nil
}

func (s *SourcePeople) empty() bool {
	return s == nil || (len(s.Authors) == 0 && len(s.Mergers) == 0 && s.Promoter == "")
}

// key is the set as a comparable string: each list sorted and normalised as the clearing rule compares names, so a
// re-run that spells the same people differently is the same set.
func (s *SourcePeople) key() string {
	if s.empty() {
		return ""
	}
	norm := func(xs []string) string {
		out := make([]string, 0, len(xs))
		for _, x := range xs {
			out = append(out, bareName(x))
		}
		sort.Strings(out)
		return strings.Join(out, "\x00")
	}
	return norm(s.Authors) + "\x01" + norm(s.Mergers) + "\x01" + bareName(s.Promoter)
}

func (s *SourcePeople) clone() *SourcePeople {
	if s.empty() {
		return nil
	}
	return &SourcePeople{Authors: append([]string(nil), s.Authors...), Mergers: append([]string(nil), s.Mergers...), Promoter: s.Promoter}
}

// Behind is a person added to a change's excluded set after its first registration: another proposer (two registrars,
// or a re-registration naming someone else) or another promoter (a /retest by a different person). Role is "proposer"
// or "promoter". The first proposer stays the displayed one.
type Behind struct {
	Role   string `json:"role"`
	Person string `json:"person"`
}

const (
	// MaxSourceStored bounds each list of a change's stored set, which grows by union across re-registrations and
	// same-tree changes; a registration that would pass it is refused (DG-SOURCE-LIMIT).
	MaxSourceStored = 512
	// MaxPeopleNotes bounds the people notes and refused-clear records written per change.
	MaxPeopleNotes = 32
	// maxPeopleListed is how many names a record lists (past it: the digest and the count only).
	maxPeopleListed = 64
)

// nameKeys are the names one person is known by: the bare name and its alias groups, as approverKeys resolves them.
func nameKeys(name string) []string {
	n := bareName(name)
	keys := []string{n}
	for gi, g := range vocab.Get().ApproverAliases {
		for _, a := range g {
			if bareName(a) == n {
				keys = append(keys, fmt.Sprintf("alias:%d", gi))
			}
		}
	}
	return keys
}

func sameName(a, b string) bool {
	have := map[string]bool{}
	for _, k := range nameKeys(a) {
		have[k] = true
	}
	for _, k := range nameKeys(b) {
		if have[k] {
			return true
		}
	}
	return false
}

func anyName(xs []string, who string) bool {
	for _, x := range xs {
		if sameName(who, x) {
			return true
		}
	}
	return false
}

// people is a set of names by role.
type people struct{ proposers, authors, mergers, promoters []string }

// peopleOf is every name behind c: the proposer and the ones added, the source lists, the promoters.
func (c *Change) peopleOf() people {
	p := people{proposers: []string{c.Proposer}}
	for _, b := range c.AlsoBehind {
		if b.Role == "proposer" {
			p.proposers = append(p.proposers, b.Person)
		} else {
			p.promoters = append(p.promoters, b.Person)
		}
	}
	if s := c.Source; s != nil {
		p.authors, p.mergers = append(p.authors, s.Authors...), append(p.mergers, s.Mergers...)
		if s.Promoter != "" {
			p.promoters = append([]string{s.Promoter}, p.promoters...)
		}
	}
	return p
}

func requestPeople(r ChangeRequest) people {
	p := people{proposers: []string{r.Proposer}}
	if s := r.Source; s != nil {
		p.authors, p.mergers = s.Authors, s.Mergers
		if s.Promoter != "" {
			p.promoters = []string{s.Promoter}
		}
	}
	return p
}

func (p people) union(o people) people {
	return people{append(append([]string(nil), p.proposers...), o.proposers...), append(append([]string(nil), p.authors...), o.authors...),
		append(append([]string(nil), p.mergers...), o.mergers...), append(append([]string(nil), p.promoters...), o.promoters...)}
}

func hasBare(xs []string, n string) bool {
	for _, x := range xs {
		if bareName(x) == bareName(n) {
			return true
		}
	}
	return false
}

// absorb adds the names of p that c does not have (grow-only: nothing is ever removed) and returns what it added,
// as "role name". A name over the stored bound is refused.
func (c *Change) absorb(p people) ([]string, error) {
	var added []string
	cur := c.peopleOf()
	for _, n := range p.proposers {
		if !hasBare(cur.proposers, n) {
			c.AlsoBehind = append(c.AlsoBehind, Behind{"proposer", n})
			cur.proposers = append(cur.proposers, n)
			added = append(added, "proposer "+n)
		}
	}
	for _, n := range p.promoters {
		if hasBare(cur.promoters, n) {
			continue
		}
		cur.promoters = append(cur.promoters, n)
		added = append(added, "promoter "+n)
		if c.Source == nil {
			c.Source = &SourcePeople{}
		}
		if c.Source.Promoter == "" {
			c.Source.Promoter = n
		} else {
			c.AlsoBehind = append(c.AlsoBehind, Behind{"promoter", n})
		}
	}
	for _, f := range []struct {
		role string
		have *[]string
		add  []string
		get  func(*SourcePeople) *[]string
	}{{"author", &cur.authors, p.authors, func(s *SourcePeople) *[]string { return &s.Authors }},
		{"merger", &cur.mergers, p.mergers, func(s *SourcePeople) *[]string { return &s.Mergers }}} {
		for _, n := range f.add {
			if hasBare(*f.have, n) {
				continue
			}
			if len(*f.have) >= MaxSourceStored {
				return added, gerr("DG-SOURCE-LIMIT", fmt.Sprintf("the people behind this change would pass %d %ss", MaxSourceStored, f.role),
					"A change's set only grows; register a new head.", 409)
			}
			*f.have = append(*f.have, n)
			added = append(added, f.role+" "+n)
			if c.Source == nil {
				c.Source = &SourcePeople{}
			}
			l := f.get(c.Source)
			*l = append(*l, n)
		}
	}
	return added, nil
}

// omitted is how many of c's people a registration's own do not name (a re-registration cannot remove them).
func (c *Change) omitted(r ChangeRequest) int {
	have, n := requestPeople(r), 0
	cur := c.peopleOf()
	for _, x := range []struct{ cur, req []string }{{cur.proposers, have.proposers}, {cur.authors, have.authors}, {cur.mergers, have.mergers}, {cur.promoters, have.promoters}} {
		for _, name := range x.cur {
			if !hasBare(x.req, name) {
				n++
			}
		}
	}
	return n
}

// rolesBehind is how person (any spelling of the principal, or an alias of it) is behind c: the proposer, a source
// author, a source merger, the promoter, or one added later. Names are compared as bareName does (case, a "user:"
// prefix) and through the approver aliases; nothing here treats a bot specially.
func rolesBehind(person string, c *Change) []string {
	var roles []string
	if sameName(person, c.Proposer) {
		roles = append(roles, "the proposer")
	}
	if s := c.Source; s != nil {
		if anyName(s.Authors, person) {
			roles = append(roles, "a source author")
		}
		if anyName(s.Mergers, person) {
			roles = append(roles, "a source merger")
		}
		if s.Promoter != "" && sameName(person, s.Promoter) {
			roles = append(roles, "the promoter")
		}
	}
	for _, b := range c.AlsoBehind {
		if sameName(person, b.Person) {
			roles = append(roles, "a further "+b.Role)
			break
		}
	}
	return roles
}

// peopleSummary is the excluded set as a record carries it: a digest of the sorted names by role, how many, and the
// names themselves when there are few enough. It is the set version a clear is checked against.
func (c *Change) peopleSummary() map[string]any {
	p := c.peopleOf()
	norm := func(xs []string) []string {
		seen, out := map[string]bool{}, []string{}
		for _, x := range xs {
			if n := bareName(x); !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
		sort.Strings(out)
		return out
	}
	set := map[string]any{"proposers": norm(p.proposers), "authors": norm(p.authors), "mergers": norm(p.mergers), "promoters": norm(p.promoters)}
	n := len(norm(p.proposers)) + len(norm(p.authors)) + len(norm(p.mergers)) + len(norm(p.promoters))
	out := map[string]any{"digest": pycompat.ArgsDigest(set), "count": n}
	if n <= maxPeopleListed {
		out["excluded"] = set
	}
	return out
}

// recordChange is the change object a deploy.request, deploy.clear or deploy.people record carries: the summary, and
// the excluded set when the change has any beyond its proposer (so a change without them records what it always did).
func (c *Change) recordChange() map[string]any {
	m := c.Summary()
	if c.Source != nil || len(c.AlsoBehind) > 0 {
		m["people"] = c.peopleSummary()
	}
	return m
}
