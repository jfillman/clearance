package gate

import (
	"sort"
	"strings"

	"github.com/jfillman/clearance/internal/pycompat"
)

// MaxSourcePeople bounds each of a change's source lists (authors, mergers).
const MaxSourcePeople = 64

// SourcePeople is the people behind a change, as the verifier resolved them from authenticated facts: the openers
// of the source pull requests a release bundles (Authors), the people who merged them (Mergers) and the person who
// promoted the release (Promoter). With the proposer they are the people who may not clear the change (RoleFor):
// one proposer field alone lets a developer arrange for someone else, or a bot, to be the proposer and then clear
// their own change. Each entry is a principal in the proposer's form. The set is fixed at registration.
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

// roles is how person (any spelling of the principal) is behind c: the proposer, a source author, a source merger,
// the promoter. Names are compared as bareName does (case, a "user:" prefix); nothing here treats a bot specially.
func rolesBehind(person string, c *Change) []string {
	who := bareName(person)
	var roles []string
	if who == bareName(c.Proposer) {
		roles = append(roles, "the proposer")
	}
	if s := c.Source; s != nil {
		for _, a := range s.Authors {
			if who == bareName(a) {
				roles = append(roles, "a source author")
				break
			}
		}
		for _, m := range s.Mergers {
			if who == bareName(m) {
				roles = append(roles, "a source merger")
				break
			}
		}
		if s.Promoter != "" && who == bareName(s.Promoter) {
			roles = append(roles, "the promoter")
		}
	}
	return roles
}

// sameSource is the immutability rule: nil error when the registration's proposer and set are the change's.
func sameSource(existing *Change, req ChangeRequest) error {
	if bareName(existing.Proposer) != bareName(req.Proposer) {
		return gerr("DG-IMMUTABLE", "the proposer of a registered change cannot be changed",
			"A change keeps the proposer it was registered with; a new head is a new change.", 409)
	}
	if existing.Source.key() != req.Source.key() {
		return gerr("DG-IMMUTABLE", "the source people (authors, mergers, promoter) of a registered change cannot be changed",
			"The set is fixed at registration; a new head is registered with its own.", 409)
	}
	return nil
}
