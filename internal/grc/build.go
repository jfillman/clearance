package grc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/packet"
)

// EvidenceFields are every property an evidence item carries to a hub, and (with the item's id, title and link) the
// whole of what a change sends. Nothing else of a change is read into an item: not the repository, the pull request,
// the paths, the proposer's or an approver's name, the checks or the reasons. docs/grc-push.md prints this table and
// a test holds the outbound payload to it.
var EvidenceFields = map[string]string{
	"origin":           "who made the change: person, agent or automation (the proposer's kind, never a name)",
	"tier":             "the clearance tier, 0 to 3",
	"state":            "the change's state (always cleared: only cleared changes are sent)",
	"app":              "the application's name",
	"env":              "the environment's name",
	"approver_kind":    "person when every approval was checked to be a person, mixed or none otherwise",
	"approver_count":   "how many approvals the change carries",
	"approvers_sha256": "SHA-256 of the sorted approver identities: it identifies them without naming them",
	"change_digest":    "the digest of what was cleared (the manifest tree or saved plan), SHA-256",
	"policy_version":   "the policy bundle version that decided the tier",
	"controls":         "the hub control identifiers this evidence is mapped to, framework/version:control",
	"cleared_at":       "when the change was cleared, RFC 3339 UTC",
}

// ReportFields are every property a coverage report item carries.
var ReportFields = map[string]string{
	"period":            "the UTC day the counts are for, YYYY-MM-DD",
	"env":               "the environment the counts are for",
	"changes_total":     "changes decided in the period in these states",
	"changes_cleared":   "of them, cleared",
	"changes_denied":    "of them, denied",
	"changes_exception": "of them, ended as an exception",
	"changes_degraded":  "of them, ended degraded",
	"cleared_tier0":     "cleared changes at tier 0",
	"cleared_tier1":     "cleared changes at tier 1",
	"cleared_tier2":     "cleared changes at tier 2",
	"cleared_tier3":     "cleared changes at tier 3",
	"cleared_by_people": "cleared changes whose every approval was checked to be a person",
	"controls":          "the hub control identifiers this report is mapped to",
}

var safeID = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

// Builder turns changes into hub items.
type Builder struct {
	// LinkBase is the configured https base of the Clearance UI; a change's link is LinkBase + "/changes/" + id. It is
	// never taken from a request, a change field or anything a caller can set.
	LinkBase string
	Controls string // "soc2/2017:CC8.1"
}

// ControlsFor reads the control identifiers of the named mappings ("soc2/2017") from the packet's mapping data.
func ControlsFor(keys []string) (string, error) {
	ms, err := packet.SelectMappings(keys)
	if err != nil {
		return "", err
	}
	var out []string
	for _, m := range ms {
		for _, c := range m.Controls {
			out = append(out, m.Key()+":"+c.ID)
		}
	}
	sort.Strings(out)
	return strings.Join(out, ","), nil
}

// Link is the link back to the change's record page. ok is false for an id that is not a plain identifier.
func (b Builder) Link(id string) (string, bool) {
	if !safeID.MatchString(id) {
		return "", false
	}
	return b.LinkBase + "/changes/" + url.PathEscape(id), true
}

// Evidence is the item for one cleared change; ok is false when it cannot be sent (an unusable id or no decision time).
func (b Builder) Evidence(c gate.Change) (Item, bool) {
	link, ok := b.Link(c.ID)
	if !ok || c.DecidedAt == nil || c.State != gate.StateCleared {
		return Item{}, false
	}
	ids := make([]string, 0, len(c.Approvals))
	people := 0
	for _, a := range c.Approvals {
		ids = append(ids, a.Person)
		if a.Kind == "person" {
			people++
		}
	}
	sort.Strings(ids)
	kind := "none"
	switch {
	case len(c.Approvals) == 0:
	case people == len(c.Approvals):
		kind = "person"
	default:
		kind = "mixed"
	}
	return Item{
		ID:    "clearance-change-" + c.ID,
		Title: fmt.Sprintf("%s/%s change %s (tier %d)", c.App, c.Env, short(c.ID), c.Tier),
		Link:  link,
		Props: map[string]any{
			"origin": orNone(c.ProposerKind), "tier": int64(c.Tier), "state": c.State, "app": c.App, "env": c.Env,
			"approver_kind": kind, "approver_count": int64(len(c.Approvals)),
			"approvers_sha256": sha(strings.Join(ids, "\n")), "change_digest": c.TreeDigest,
			"policy_version": c.PolicyVersion, "controls": b.Controls, "cleared_at": c.DecidedAt.Time.UTC(),
		},
	}, true
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func orNone(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func sha(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

// Digest is the SHA-256 of an item's content: what the ledger records of what was sent, and what makes a record's
// event id change when the item does.
func Digest(it Item) string {
	b, _ := json.Marshal(struct {
		ID, Title, Link string
		Props           map[string]any
	}{it.ID, it.Title, it.Link, it.Props})
	return sha(string(b))
}

// SetDigest is the digest of a whole set (order does not matter).
func SetDigest(items []Item) string {
	ds := make([]string, len(items))
	for i, it := range items {
		ds[i] = Digest(it)
	}
	sort.Strings(ds)
	return sha(strings.Join(ds, "\n"))
}

// Day is a change's UTC day for the report.
func Day(t time.Time) string { return t.UTC().Format("2006-01-02") }

// Reports builds one coverage report item per UTC day and environment from the changes decided in the window.
// Counts only: no change, person or path appears in one.
func (b Builder) Reports(changes []gate.Change) []Item {
	type key struct{ day, env string }
	type tally struct {
		total, cleared, denied, exception, degraded, people int64
		tiers                                               [4]int64
	}
	by := map[key]*tally{}
	for _, c := range changes {
		var when time.Time
		switch {
		case c.DecidedAt != nil:
			when = c.DecidedAt.Time
		default:
			when = c.UpdatedAt.Time
		}
		k := key{Day(when), c.Env}
		t := by[k]
		if t == nil {
			t = &tally{}
			by[k] = t
		}
		switch c.State {
		case gate.StateCleared:
			t.cleared++
			if c.Tier >= 0 && c.Tier <= 3 {
				t.tiers[c.Tier]++
			}
			all := len(c.Approvals) > 0
			for _, a := range c.Approvals {
				all = all && a.Kind == "person"
			}
			if all {
				t.people++
			}
		case gate.StateDenied:
			t.denied++
		case gate.StateException:
			t.exception++
		case gate.StateDegraded:
			t.degraded++
		default:
			continue
		}
		t.total++
	}
	var out []Item
	for k, t := range by {
		out = append(out, Item{
			ID: "clearance-coverage-" + k.env + "-" + k.day, Title: fmt.Sprintf("Change coverage, %s, %s", k.env, k.day), Link: b.LinkBase,
			Props: map[string]any{"period": k.day, "env": k.env, "changes_total": t.total, "changes_cleared": t.cleared,
				"changes_denied": t.denied, "changes_exception": t.exception, "changes_degraded": t.degraded,
				"cleared_tier0": t.tiers[0], "cleared_tier1": t.tiers[1], "cleared_tier2": t.tiers[2], "cleared_tier3": t.tiers[3],
				"cleared_by_people": t.people, "controls": b.Controls},
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
