// Package describe is the generic change description (SDK-1, schemas/change-description.schema.json): what any
// change is, said the same way whatever made it. A subject of some subject kind, the target it reaches, the items it
// creates, updates, deletes or replaces, where it came from and who described it.
//
//	{"subject": {"kind", "version", "rootFn", "root", "facts"},
//	 "target": {"scope", "environment", "app"},
//	 "items": [{"type", "id", "op", "fields", "attrs", "hash"}],
//	 "source": {"repo", "commit", "base", "pr"},
//	 "describedBy": {"provider", "version"}}
//
// The core derives every summary (Summarize) from the items and never takes one from a caller. A subject's root is
// computed by the root function its kind declares (root.go): merkle/1 for new kinds; tree/1 (manifest-tree) and
// plan/1 (terraform-plan) for the built-in kinds, whose roots are exactly what they were before the description
// existed. The kinds themselves are internal/kinds (clearance.kind/v1).
//
// Everything that hashes goes through internal/canon, the reference canonicalization; schemas/vectors holds the
// golden vectors another language's SDK reproduces byte for byte.
package describe

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode"

	"github.com/jfillman/clearance/internal/canon"
	"github.com/jfillman/clearance/internal/pycompat"
)

// The ops an item may have. Anything else is refused (DG-UNBOUND once a kind binds it, internal/kinds).
const (
	OpCreate  = "create"
	OpUpdate  = "update"
	OpDelete  = "delete"
	OpReplace = "replace"
)

// Ops are the four item ops, in summary order.
var Ops = []string{OpCreate, OpUpdate, OpDelete, OpReplace}

// Limits on a description. MaxItems is the gate's MaxObjects: a larger change pages its items (merkle/1 makes that
// possible; paging itself is not built yet).
const (
	MaxItems    = 2000
	MaxFields   = 400
	MaxAttrs    = 64
	MaxFacts    = 64
	MaxIDLen    = 1024
	MaxTypeLen  = 256
	MaxFieldLen = 1024
)

// CoreProvider is describedBy.provider when the core itself mapped a verifier's request of a built-in kind onto the
// description (internal/gate describe.go).
const CoreProvider = "clearance-core"

// Description is one change, described.
type Description struct {
	Subject     Subject     `json:"subject" contract:"required"`
	Target      Target      `json:"target" contract:"required"`
	Items       []Item      `json:"items" contract:"required"`
	Source      Source      `json:"source" contract:"required"`
	DescribedBy DescribedBy `json:"describedBy" contract:"required"`
}

// Subject is what the change binds to: its subject kind and that kind's version, the root function the kind declares
// and the root it gives, and the change-level facts the kind's subjectSchema declares (Terraform's workspace, its
// versions, whether -target was used).
type Subject struct {
	Kind    string         `json:"kind" contract:"required"`
	Version int            `json:"version" contract:"required"`
	RootFn  string         `json:"rootFn" contract:"required"`
	Root    string         `json:"root" contract:"required"`
	Facts   map[string]any `json:"facts,omitempty"`
}

// Target is where the change lands: a scope (a cluster, an account, a database; empty when the change has none, as a
// terraform-plan registered without a cluster), the environment, and the application it belongs to (whose owner
// group clears it), when there is one.
type Target struct {
	Scope       string `json:"scope"`
	Environment string `json:"environment" contract:"required"`
	App         string `json:"app,omitempty"`
}

// Item is one thing the change creates, updates, deletes or replaces: its type (as the kind's itemTypes name it), its
// id (unique per type in the change), the op, the JSON pointers of what an update changes (names only, never a
// value), the attributes the kind's schema declares for the type, and the item's content hash (bare lowercase hex
// sha256, empty when the gate has none).
type Item struct {
	Type   string         `json:"type" contract:"required"`
	ID     string         `json:"id" contract:"required"`
	Op     string         `json:"op" contract:"required"`
	Fields []string       `json:"fields,omitempty"`
	Attrs  map[string]any `json:"attrs,omitempty"`
	Hash   string         `json:"hash,omitempty"`
}

// Source is where the change came from: the repository, the commit, the base it is compared with, and the pull
// request (0 or absent: a pushed commit).
type Source struct {
	Repo   string `json:"repo" contract:"required"`
	Commit string `json:"commit" contract:"required"`
	Base   string `json:"base,omitempty"`
	PR     int64  `json:"pr,omitempty"`
}

// DescribedBy names what described the change: the provider (a registered gate, or CoreProvider) and its version.
type DescribedBy struct {
	Provider string `json:"provider" contract:"required"`
	Version  string `json:"version,omitempty"`
}

// Summary is what the items say, counted by the core: one count per op and the ids the change deletes (in item
// order). A caller never sends one.
type Summary struct {
	Create  int64    `json:"create"`
	Update  int64    `json:"update"`
	Delete  int64    `json:"delete"`
	Replace int64    `json:"replace"`
	Deleted []string `json:"deleted"`
}

// Summarize derives the summary from the items.
func (d *Description) Summarize() Summary {
	s := Summary{Deleted: []string{}}
	for _, it := range d.Items {
		switch it.Op {
		case OpCreate:
			s.Create++
		case OpUpdate:
			s.Update++
		case OpDelete:
			s.Delete++
			s.Deleted = append(s.Deleted, it.ID)
		case OpReplace:
			s.Replace++
		}
	}
	return s
}

// Error is a refused description: the field and what is wrong with it.
type Error struct{ Msg string }

func (e *Error) Error() string { return "describe: " + e.Msg }

func bad(format string, a ...any) error { return &Error{fmt.Sprintf(format, a...)} }

var (
	hexRx      = regexp.MustCompile(`^[0-9a-f]{64}\z`)
	rootFnRx   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}/[1-9][0-9]{0,3}\z`)
	kindNameRx = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)*\z`)
	providerRx = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}\z`)
	commitRx   = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?\z`)
	repoRx     = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\z`)
	envRx      = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\z`)
	attrKeyRx  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}\z`)
)

// IsSHA256 says whether s is a bare lowercase hex sha256, the form every root and hash in a description takes.
func IsSHA256(s string) bool { return hexRx.MatchString(s) }

// printable: 1 to max characters (code points), none a control character.
func printable(s string, max int) bool {
	if s == "" || pycompat.Len(s) > max {
		return false
	}
	return !strings.ContainsFunc(s, unicode.IsControl)
}

var (
	descriptionKeys = keys("subject", "target", "items", "source", "describedBy")
	subjectKeys     = keys("kind", "version", "rootFn", "root", "facts")
	targetKeys      = keys("scope", "environment", "app")
	itemKeys        = keys("type", "id", "op", "fields", "attrs", "hash")
	sourceKeys      = keys("repo", "commit", "base", "pr")
	describedByKeys = keys("provider", "version")
)

func keys(xs ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func object(v any, where string, allowed map[string]bool) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, bad("%s is an object", where)
	}
	var unknown []string
	for k := range m {
		if !allowed[k] {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return nil, bad("%s has an unknown field %s", where, pycompat.Repr(unknown[0]))
	}
	return m, nil
}

func str(m map[string]any, k string, required bool) (string, bool) {
	v, present := m[k]
	if !present || v == nil {
		return "", !required
	}
	s, ok := v.(string)
	return s, ok && (s != "" || !required)
}

// Parse decodes a description strictly, as a request body is decoded (numbers as json.Number; unknown fields
// refused), and validates it (Validate). It does not bind the description to a kind: that is internal/kinds.
func Parse(v any) (*Description, error) {
	top, err := object(v, "the description", descriptionKeys)
	if err != nil {
		return nil, err
	}
	d := &Description{}
	sub, err := object(top["subject"], "subject", subjectKeys)
	if err != nil {
		return nil, err
	}
	var ok bool
	if d.Subject.Kind, ok = str(sub, "kind", true); !ok {
		return nil, bad("subject.kind is a subject kind's name")
	}
	ver, isInt := pycompat.AsInt(sub["version"])
	if !isInt || ver < 1 || ver > 1<<20 {
		return nil, bad("subject.version is the kind's version, a positive integer")
	}
	d.Subject.Version = int(ver)
	if d.Subject.RootFn, ok = str(sub, "rootFn", true); !ok {
		return nil, bad("subject.rootFn names the kind's root function (merkle/1, tree/1, plan/1)")
	}
	if d.Subject.Root, ok = str(sub, "root", true); !ok {
		return nil, bad("subject.root is a sha256")
	}
	if f, present := sub["facts"]; present && f != nil {
		fm, isMap := f.(map[string]any)
		if !isMap {
			return nil, bad("subject.facts is an object")
		}
		d.Subject.Facts = fm
	}
	tg, err := object(top["target"], "target", targetKeys)
	if err != nil {
		return nil, err
	}
	scope, ok1 := str(tg, "scope", false)
	env, ok2 := str(tg, "environment", true)
	app, ok3 := str(tg, "app", false)
	if !ok1 || !ok2 || !ok3 {
		return nil, bad("target is {scope, environment, app}: strings, environment required")
	}
	d.Target = Target{scope, env, app}
	rawItems, isList := top["items"].([]any)
	if !isList {
		return nil, bad("items is a list (empty for a change that changes nothing)")
	}
	if len(rawItems) > MaxItems {
		return nil, bad("items is a list of at most %d", MaxItems)
	}
	d.Items = make([]Item, 0, len(rawItems))
	for i, raw := range rawItems {
		it, err := parseItem(raw, i)
		if err != nil {
			return nil, err
		}
		d.Items = append(d.Items, it)
	}
	src, err := object(top["source"], "source", sourceKeys)
	if err != nil {
		return nil, err
	}
	repo, ok1 := str(src, "repo", true)
	commit, ok2 := str(src, "commit", true)
	baseC, ok3 := str(src, "base", false)
	if !ok1 || !ok2 || !ok3 {
		return nil, bad("source is {repo, commit, base, pr}: repo and commit required")
	}
	d.Source = Source{Repo: repo, Commit: commit, Base: baseC}
	if p, present := src["pr"]; present && p != nil {
		n, isInt := pycompat.AsInt(p)
		if !isInt || n < 0 {
			return nil, bad("source.pr is a non-negative integer (0: a pushed commit)")
		}
		d.Source.PR = n
	}
	by, err := object(top["describedBy"], "describedBy", describedByKeys)
	if err != nil {
		return nil, err
	}
	prov, ok1 := str(by, "provider", true)
	pver, ok2 := str(by, "version", false)
	if !ok1 || !ok2 {
		return nil, bad("describedBy is {provider, version}: provider required")
	}
	d.DescribedBy = DescribedBy{prov, pver}
	if err := d.Validate(); err != nil {
		return nil, err
	}
	return d, nil
}

func parseItem(raw any, i int) (Item, error) {
	where := fmt.Sprintf("items[%d]", i)
	o, err := object(raw, where, itemKeys)
	if err != nil {
		return Item{}, err
	}
	var it Item
	var ok bool
	if it.Type, ok = str(o, "type", true); !ok {
		return it, bad("%s.type is required", where)
	}
	if it.ID, ok = str(o, "id", true); !ok {
		return it, bad("%s.id is required", where)
	}
	if it.Op, ok = str(o, "op", true); !ok {
		return it, bad("%s.op is required", where)
	}
	if it.Hash, ok = str(o, "hash", false); !ok {
		return it, bad("%s.hash is a sha256", where)
	}
	if f, present := o["fields"]; present && f != nil {
		l, isList := f.([]any)
		if !isList {
			return it, bad("%s.fields is a list of JSON pointers", where)
		}
		for _, x := range l {
			s, isStr := x.(string)
			if !isStr {
				return it, bad("%s.fields is a list of JSON pointers", where)
			}
			it.Fields = append(it.Fields, s)
		}
	}
	if a, present := o["attrs"]; present && a != nil {
		am, isMap := a.(map[string]any)
		if !isMap {
			return it, bad("%s.attrs is an object", where)
		}
		it.Attrs = am
	}
	return it, nil
}

// Validate checks what a description must be whatever its kind: names and formats, the ops, unique items, a root in
// the form its root function gives, and canonical facts and attrs. It is what Parse runs; the core's own mapping of a
// built-in kind (internal/gate) builds descriptions that pass it.
func (d *Description) Validate() error {
	s := d.Subject
	if !kindNameRx.MatchString(s.Kind) || len(s.Kind) > 253 {
		return bad("subject.kind %s is not a subject kind's name (reverse-DNS, such as io.acme.db-migration, or a built-in kind)", pycompat.Repr(s.Kind))
	}
	if s.Version < 1 {
		return bad("subject.version is a positive integer")
	}
	if !rootFnRx.MatchString(s.RootFn) {
		return bad("subject.rootFn %s is not a root function (name/version, such as merkle/1)", pycompat.Repr(s.RootFn))
	}
	if !IsSHA256(s.Root) {
		return bad("subject.root is a bare lowercase hex sha256")
	}
	if len(s.Facts) > MaxFacts {
		return bad("subject.facts has at most %d facts", MaxFacts)
	}
	if s.Facts != nil {
		if _, err := canon.Canonical(s.Facts); err != nil {
			return bad("subject.facts: %v", err)
		}
	}
	if d.Target.Scope != "" && !printable(d.Target.Scope, 253) {
		return bad("target.scope is at most 253 printable characters")
	}
	if !envRx.MatchString(d.Target.Environment) {
		return bad("target.environment is an environment name")
	}
	if d.Target.App != "" && !envRx.MatchString(d.Target.App) {
		return bad("target.app is an application name")
	}
	if len(d.Items) > MaxItems {
		return bad("items is a list of at most %d", MaxItems)
	}
	seen := map[[2]string]bool{}
	for i, it := range d.Items {
		where := fmt.Sprintf("items[%d]", i)
		if !printable(it.Type, MaxTypeLen) {
			return bad("%s.type is 1 to %d printable characters", where, MaxTypeLen)
		}
		if !printable(it.ID, MaxIDLen) {
			return bad("%s.id is 1 to %d printable characters", where, MaxIDLen)
		}
		if !slices.Contains(Ops, it.Op) {
			return bad("%s.op is create, update, delete or replace", where)
		}
		k := [2]string{it.Type, it.ID}
		if seen[k] {
			return bad("%s: %s %s is listed twice", where, it.Type, pycompat.Repr(it.ID))
		}
		seen[k] = true
		if len(it.Fields) > MaxFields {
			return bad("%s.fields is a list of at most %d JSON pointers", where, MaxFields)
		}
		for _, f := range it.Fields {
			if !strings.HasPrefix(f, "/") || !printable(f, MaxFieldLen) {
				return bad("%s.fields are JSON pointers (attribute names, never values)", where)
			}
		}
		if len(it.Attrs) > MaxAttrs {
			return bad("%s.attrs has at most %d attributes", where, MaxAttrs)
		}
		for k := range it.Attrs {
			if !attrKeyRx.MatchString(k) {
				return bad("%s.attrs: %s is not an attribute name", where, pycompat.Repr(k))
			}
		}
		if it.Attrs != nil {
			if _, err := canon.Canonical(it.Attrs); err != nil {
				return bad("%s.attrs: %v", where, err)
			}
		}
		if it.Hash != "" && !IsSHA256(it.Hash) {
			return bad("%s.hash is a bare lowercase hex sha256", where)
		}
	}
	if !repoRx.MatchString(d.Source.Repo) {
		return bad("source.repo is owner/name")
	}
	if !commitRx.MatchString(d.Source.Commit) {
		return bad("source.commit is a 40-hex (or 64-hex) commit")
	}
	if d.Source.Base != "" && !commitRx.MatchString(d.Source.Base) {
		return bad("source.base is a 40-hex (or 64-hex) commit")
	}
	if d.Source.PR < 0 {
		return bad("source.pr is a non-negative integer")
	}
	if !providerRx.MatchString(d.DescribedBy.Provider) {
		return bad("describedBy.provider names the provider that described the change")
	}
	if d.DescribedBy.Version != "" && !printable(d.DescribedBy.Version, 128) {
		return bad("describedBy.version is at most 128 printable characters")
	}
	return nil
}

// ErrRootMismatch is a description whose root is not what its root function gives over its items and facts.
var ErrRootMismatch = errors.New("describe: subject.root is not the root of the items and facts")

// MarshalCanonical is the description's canonical JSON (internal/canon).
func (d *Description) MarshalCanonical() ([]byte, error) {
	raw, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	v, err := canon.Parse(raw)
	if err != nil {
		return nil, err
	}
	return canon.Canonical(v)
}
