package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"

	"github.com/jfillman/clearance/internal/pycompat"
)

// The gate rule (W-42; docs/gate.md, "The gate rule").
//
// A platform rule selects Applications to gate by properties every Application already has: its Argo CD project, its
// destination namespace and its labels. A selected Application is gated as if it carried the opt-in annotation, and
// removing the annotation does not release it. The rule lives in one YAML file (--gate-rule-file, rendered by the chart
// from its gateRule value into a ConfigMap mounted read-only), re-read every pass:
//
//	version: 1
//	select:                       # OR across entries
//	  - name: tenants-prod        # required, a DNS label; it appears in records and in the status
//	    projects: [tenants]       # globs on spec.project              }
//	    namespaces: ["app-*-prod"] # globs on spec.destination.namespace } AND across the keys present,
//	    labels: {tier: prod}      # exact key=value on the labels, all } OR across a key's values
//	exempt:
//	  - application: argocd/web-prod  # glob on <namespace>/<name>
//	    reason: "a migration to the new chart"   # 10 to 500 characters
//	    expires: 2026-12-19       # a date (00:00 UTC) or an RFC 3339 time; at most --gate-exempt-max away
//	    ref: PR-123               # optional
//
// An entry with none of projects, namespaces and labels is refused (it would match everything): gate every Application
// the agent can see with projects: ["*"], on purpose. A select entry that is invalid makes the whole file invalid (the
// last good rule stays); an invalid exempt entry is ignored on its own (its Application stays gated) and reported.

// RuleVersion is the one version of the rule file.
const RuleVersion = 1

// DefaultExemptMax is how far ahead an exemption's expiry may be (--gate-exempt-max).
const DefaultExemptMax = 90 * 24 * time.Hour

// Rule is a parsed rule file. The zero value (and nil) selects nothing.
type Rule struct {
	Version int          `yaml:"version"`
	Select  []RuleSelect `yaml:"select"`
	Exempt  []RuleExempt `yaml:"exempt"`
	// Digest is the sha256 of the file's bytes, which every record and release reason names.
	Digest string `yaml:"-"`
	// Raw is the file as read: the copy kept in the state ConfigMap.
	Raw string `yaml:"-"`
}

// RuleSelect is one select entry: the keys present are ANDed; inside a key the values are ORed, labels all match.
type RuleSelect struct {
	Name       string            `yaml:"name"`
	Projects   []string          `yaml:"projects"`
	Namespaces []string          `yaml:"namespaces"`
	Labels     map[string]string `yaml:"labels"`
}

// RuleExempt is one exempt entry. Invalid says why it is ignored ("" when it is valid); At is its expiry.
type RuleExempt struct {
	Application string `yaml:"application"`
	Reason      string `yaml:"reason"`
	Expires     string `yaml:"expires"`
	Ref         string `yaml:"ref"`

	At      time.Time `yaml:"-"`
	Invalid string    `yaml:"-"`
}

var ruleNameRx = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// MaxRuleBytes bounds the rule file.
const MaxRuleBytes = 256 << 10

// ParseRule reads a rule file. now and max bound the exemptions' expiries (an expiry further than max from now makes the
// entry invalid; an expiry already past makes it stale, not invalid). An error means the file as a whole is refused.
func ParseRule(raw []byte, now time.Time, max time.Duration) (*Rule, error) {
	if len(raw) > MaxRuleBytes {
		return nil, fmt.Errorf("the rule file is over %d bytes", MaxRuleBytes)
	}
	sum := sha256.Sum256(raw)
	r := &Rule{Digest: hex.EncodeToString(sum[:]), Raw: string(raw)}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(r); err != nil {
		if errors.Is(err, io.EOF) || strings.TrimSpace(string(raw)) == "" {
			return nil, errors.New("the rule file is empty: write version: 1 and an empty select for a rule that gates nothing")
		}
		return nil, fmt.Errorf("the rule file is not the rule's YAML: %w", err)
	}
	if r.Version != RuleVersion {
		return nil, fmt.Errorf("the rule file's version is %d, this agent reads version %d", r.Version, RuleVersion)
	}
	seen := map[string]bool{}
	for i, s := range r.Select {
		where := fmt.Sprintf("select[%d]", i)
		if !ruleNameRx.MatchString(s.Name) {
			return nil, fmt.Errorf("%s: name is required, a DNS label (it appears in records)", where)
		}
		where = fmt.Sprintf("select %q", s.Name)
		if seen[s.Name] {
			return nil, fmt.Errorf("%s is named twice", where)
		}
		seen[s.Name] = true
		if len(s.Projects) == 0 && len(s.Namespaces) == 0 && len(s.Labels) == 0 {
			return nil, fmt.Errorf("%s names none of projects, namespaces and labels: it would match everything (write projects: [\"*\"] to mean that)", where)
		}
		for _, l := range [][]string{s.Projects, s.Namespaces} {
			for _, g := range l {
				if strings.TrimSpace(g) == "" || len(g) > 253 {
					return nil, fmt.Errorf("%s has an empty or over-long glob", where)
				}
			}
		}
		for k, v := range s.Labels {
			if k == "" || len(k) > 317 || len(v) > 63 {
				return nil, fmt.Errorf("%s has a label that is not key: value", where)
			}
		}
	}
	for i := range r.Exempt {
		r.Exempt[i].check(now, max)
	}
	return r, nil
}

func (e *RuleExempt) check(now time.Time, max time.Duration) {
	n := utf8.RuneCountInString(e.Reason)
	switch {
	case strings.TrimSpace(e.Application) == "" || len(e.Application) > 253 || !strings.Contains(e.Application, "/"):
		e.Invalid = "application is a glob on <namespace>/<name>"
	case n < 10 || n > 500:
		e.Invalid = "reason is 10 to 500 characters"
	case e.Expires == "":
		e.Invalid = "expires is required (a date or an RFC 3339 time)"
	case len(e.Ref) > 200:
		e.Invalid = "ref is at most 200 characters"
	}
	if e.Invalid != "" {
		return
	}
	at, err := time.Parse(time.RFC3339, e.Expires)
	if err != nil {
		at, err = time.Parse("2006-01-02", e.Expires)
	}
	if err != nil {
		e.Invalid = "expires is a date (2006-01-02, 00:00 UTC) or an RFC 3339 time"
		return
	}
	e.At = at.UTC()
	if e.At.After(now.Add(max)) {
		e.Invalid = fmt.Sprintf("expires %s is more than %s away (--gate-exempt-max)", e.At.Format(time.RFC3339), max)
	}
}

// Expired says whether the exemption no longer applies at now (no grace).
func (e *RuleExempt) Expired(now time.Time) bool { return !now.Before(e.At) }

// Match is the first select entry the Application matches ("" and false: none).
func (r *Rule) Match(app Application) (string, bool) {
	if r == nil {
		return "", false
	}
	for _, s := range r.Select {
		if s.matches(app) {
			return s.Name, true
		}
	}
	return "", false
}

func (s RuleSelect) matches(app Application) bool {
	if len(s.Projects) > 0 && !pycompat.MatchAny(app.Project, s.Projects) {
		return false
	}
	if len(s.Namespaces) > 0 && (app.DestNS == "" || !pycompat.MatchAny(app.DestNS, s.Namespaces)) {
		return false
	}
	for k, v := range s.Labels {
		if got, ok := app.Labels[k]; !ok || got != v {
			return false
		}
	}
	return true
}

// ExemptFor is the first exempt entry whose glob matches the Application, valid or not (nil: none).
func (r *Rule) ExemptFor(app Application) *RuleExempt {
	if r == nil {
		return nil
	}
	for i := range r.Exempt {
		if pycompat.Match(app.Namespace+"/"+app.Name, r.Exempt[i].Application) {
			return &r.Exempt[i]
		}
	}
	return nil
}

// short is a digest's first twelve characters.
func shortDigest(d string) string {
	if len(d) > 12 {
		return d[:12]
	}
	return d
}
