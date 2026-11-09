package gate

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/pycompat"
)

// PyTime is a datetime the way gate.py stores it: isoformat() ("2026-09-26T12:00:00+00:00", microseconds when
// non-zero), read back with fromisoformat.
type PyTime struct{ time.Time }

// MarshalJSON writes isoformat.
func (t PyTime) MarshalJSON() ([]byte, error) { return json.Marshal(pycompat.Isoformat(t.Time)) }

// UnmarshalJSON reads isoformat.
func (t *PyTime) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := pycompat.ParseIsoformat(s)
	if err != nil {
		return err
	}
	t.Time = v
	return nil
}

// Approval is one person's clearance: {person, via, role, at, sub, iss}. sub and iss name the person at their
// identity provider: the ID token's subject and issuer when the person signed in themselves; the person as the
// delegate named them and "delegate:<delegate>" when a delegate (a portal) acted for them. Approvals recorded
// before C-1 have neither.
type Approval struct {
	Person string  `json:"person"`
	Via    *string `json:"via"`
	Role   string  `json:"role"`
	At     string  `json:"at"`
	Sub    string  `json:"sub,omitempty"`
	Iss    string  `json:"iss,omitempty"`
	// Kind is "person" once the approval route checked the approver is a person (GATE-APPROVER-001); absent before.
	Kind string `json:"kind,omitempty"`
	// Session is a digest of the approver's session at their identity provider, when the ID token carried one (kept to
	// refuse a second approval from the same session; the session id itself is not kept, and is not in the token).
	Session string `json:"session,omitempty"`
}

// Deployment is a GitHub Actions deployment waiting on a change (github_app.py's deployment protection rule).
// Answer stays nil while the change holds; deliveries are retried until GitHub takes them.
type Deployment struct {
	RunID        int64   `json:"run_id"`
	Environment  string  `json:"environment"`
	Installation string  `json:"installation"`
	CallbackURL  string  `json:"callback_url"`
	RequestedAt  string  `json:"requested_at"`
	Answer       *string `json:"answer"`
	AnsweredAt   *string `json:"answered_at"`
	Delivered    bool    `json:"delivered"`
	DeliveredAt  *string `json:"delivered_at"`
}

// Change is the change on record (gate.Change). Its JSON is Change.view(): the dataclass fields in order (subject,
// what the change binds to, after tree_digest), then target, objects_count and paths_count; it is the row's jsonb
// record. A change stored before subjects were (v0.30.0 and earlier) is read with a manifest-tree subject.
type Change struct {
	ID               string            `json:"id"`
	App              string            `json:"app"`
	Env              string            `json:"env"`
	Cluster          string            `json:"cluster"`
	Repo             string            `json:"repo"`
	PR               int64             `json:"pr"`
	Head             string            `json:"head"`
	Base             string            `json:"base"`
	Proposer         string            `json:"proposer"`
	ProposerKind     string            `json:"proposer_kind"`
	Agent            *string           `json:"agent"`
	TaskID           *string           `json:"task_id"`
	Owner            string            `json:"owner"`
	Protected        bool              `json:"protected"`
	TreeDigest       string            `json:"tree_digest"`
	Subject          *Subject          `json:"subject"`
	Paths            []string          `json:"paths"`
	LinesChanged     int64             `json:"lines_changed"`
	Objects          []ObjectChange    `json:"objects"`
	Checks           map[string]string `json:"checks"`
	PolicyVersion    string            `json:"policy_version"`
	RepoPolicyDigest *string           `json:"repo_policy_digest"`
	PolicyRef        string            `json:"policy_ref,omitempty"`
	Admission        *Admission        `json:"admission,omitempty"`
	Tier             int               `json:"tier"`
	Reasons          []Reason          `json:"reasons"`
	Requirement      *Requirement      `json:"requirement"`
	State            string            `json:"state"`
	CreatedAt        PyTime            `json:"created_at"`
	UpdatedAt        PyTime            `json:"updated_at"`
	ExpiresAt        PyTime            `json:"expires_at"`
	RegisteredBy     string            `json:"registered_by"`
	Approvals        []Approval        `json:"approvals"`
	ClearedBy        *string           `json:"cleared_by"`
	DecidedAt        *PyTime           `json:"decided_at"`
	DenyReason       *string           `json:"deny_reason"`
	DeniedBy         *string           `json:"denied_by"`
	SupersededBy     *string           `json:"superseded_by"`
	Deployments      []Deployment      `json:"deployments"`
	Outcome          *Outcome          `json:"outcome,omitempty"` // the apply's outcome, once (G-TF-2)
	Target           string            `json:"target"`
	ObjectsCount     int               `json:"objects_count"`
	PathsCount       int               `json:"paths_count"`
	// Outage is what a provider does with this change while the core is unreachable: allow-and-record or hold
	// (its tier under its effective policy's outage block). Absent on changes registered before C-6.
	Outage string `json:"outage,omitempty"`
	// Ended is the record that moved the change to degraded or exception (C-6): its seq, its tool and, for an
	// exception, its kind.
	Ended *Ended `json:"ended,omitempty"`
	// EvidenceWait is set while a tier 3 change whose approvals are all in has not been cleared because its evidence
	// cannot be checkpointed (C-3, the evidence ledger's outage knob). It is removed when the change clears.
	EvidenceWait *EvidenceWait `json:"evidence_wait,omitempty"`
}

// AssuranceWaiting is EvidenceWait.Assurance: the change is waiting for evidence to be checkpointed.
const AssuranceWaiting = "waiting-for-checkpoint"

// EvidenceWait says why an approved tier 3 change is still holding.
type EvidenceWait struct {
	Since     string `json:"since"`     // when the last approval arrived and the ledger could not checkpoint
	Assurance string `json:"assurance"` // AssuranceWaiting
	Reason    string `json:"reason"`    // the ledger's state and why
}

// Ended names the provider record that took a change out of the main path.
type Ended struct {
	Seq  int64  `json:"seq"`
	Tool string `json:"tool"`
	Kind string `json:"kind,omitempty"`
}

// TargetOf is "repo#pr@short" (or "repo@short" for a pushed commit).
func (c *Change) TargetOf() string {
	if c.PR != 0 {
		return fmt.Sprintf("%s#%d@%s", c.Repo, c.PR, pycompat.Truncate(c.Head, 7))
	}
	return fmt.Sprintf("%s@%s", c.Repo, pycompat.Truncate(c.Head, 7))
}

// View fills the derived fields (target, objects_count, paths_count) and empty lists; it returns c for chaining.
func (c *Change) View() *Change {
	c.Target, c.ObjectsCount, c.PathsCount = c.TargetOf(), len(c.Objects), len(c.Paths)
	if c.Subject == nil {
		c.Subject = c.legacySubject()
	}
	if c.Paths == nil {
		c.Paths = []string{}
	}
	if c.Objects == nil {
		c.Objects = []ObjectChange{}
	}
	if c.Checks == nil {
		c.Checks = map[string]string{}
	}
	if c.Reasons == nil {
		c.Reasons = []Reason{}
	}
	if c.Approvals == nil {
		c.Approvals = []Approval{}
	}
	if c.Deployments == nil {
		c.Deployments = []Deployment{}
	}
	for i := range c.Objects {
		if c.Objects[i].Fields == nil {
			c.Objects[i].Fields = []string{}
		}
		if c.Objects[i].Images == nil {
			c.Objects[i].Images = []string{}
		}
	}
	return c
}

// Summary is what a record carries about the change (claimed: the verifier described it).
func (c *Change) Summary() map[string]any {
	return map[string]any{"id": c.ID, "app": c.App, "env": c.Env, "cluster": c.Cluster, "head": c.Head,
		"tree": c.TreeDigest, "tier": json.Number(fmt.Sprint(c.Tier)), "state": c.State,
		"objects": json.Number(fmt.Sprint(len(c.Objects)))}
}

// RequirementObj is the requirement, if any.
func (c *Change) RequirementObj() *Requirement { return c.Requirement }

// Open is Change.open: a new holding change from a request and its classification.
func Open(req ChangeRequest, cl Classification, now time.Time, registeredBy string) *Change {
	reasons := append([]Reason(nil), cl.Reasons...)
	c := &Change{ID: req.ID(), App: req.App, Env: req.Env, Cluster: req.Cluster, Repo: req.Repo, PR: req.PR,
		Head: req.Head, Base: req.Base, Proposer: req.Proposer, ProposerKind: req.ProposerKind, Agent: req.Agent, TaskID: req.TaskID,
		Owner: req.Owner, Protected: req.Protected, TreeDigest: req.TreeDigest, Subject: subjectFor(req), Paths: append([]string(nil), req.Paths...),
		LinesChanged: req.LinesChanged, Objects: append([]ObjectChange(nil), req.Objects...), Checks: copyChecks(req.Checks),
		PolicyVersion: cl.Policy.Version, RepoPolicyDigest: cl.Policy.RepoPolicyDigest, PolicyRef: policyRefOf(req),
		Admission: copyAdmission(req.Admission), Tier: cl.Tier, Reasons: reasons,
		Requirement: cl.Requirement, State: "holding", CreatedAt: PyTime{now}, UpdatedAt: PyTime{now},
		ExpiresAt: PyTime{now.AddDate(0, 0, cl.Policy.TTLDays)}, RegisteredBy: registeredBy,
		Outage: cl.Policy.OutageFor(cl.Tier)}
	return c.View()
}

func copyAdmission(a *Admission) *Admission {
	if a == nil {
		return nil
	}
	out := *a
	return &out
}

func copyChecks(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// FromRecord is Change.from_record: the row's jsonb back to a change.
func FromRecord(raw []byte) (*Change, error) {
	var c Change
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("gate: change record: %w", err)
	}
	return c.View(), nil
}

// DeploymentAnswer is what a waiting GitHub deployment is told for a change in state: approved once cleared,
// rejected once it can never be, nothing while it holds.
func DeploymentAnswer(state string) *string {
	switch state {
	case StateCleared:
		return strp("approved")
	case StateHolding:
		return nil
	}
	return strp("rejected")
}

// AnswerDeployments settles the deployments waiting on c from its state; returns how many were answered now.
// answered_at is isoformat here (gate.answer_deployments), audit.iso in DeploymentRequested, as in gate.py.
func AnswerDeployments(c *Change, now time.Time) int {
	answer := DeploymentAnswer(c.State)
	if answer == nil {
		return 0
	}
	n := 0
	for i := range c.Deployments {
		d := &c.Deployments[i]
		if d.Answer == nil {
			at := pycompat.Isoformat(now)
			d.Answer, d.AnsweredAt, d.Delivered = strp(*answer), &at, false
			n++
		}
	}
	return n
}

// CheckReason is gate.check_reason.
func CheckReason(reason any) (string, error) {
	s, ok := reason.(string)
	if !ok || strings.TrimSpace(s) == "" {
		return "", gerr("DG-REASON", "a reason is required", "Say why, in a sentence; it is recorded.", 400)
	}
	if pycompat.Len(s) > MaxReason {
		return "", gerr("DG-REASON", fmt.Sprintf("the reason is longer than %d characters", MaxReason), "", 400)
	}
	return strings.TrimSpace(s), nil
}

// RoleFor is gate.role_for: which requirement a person satisfies, owner first, else outside.
func RoleFor(person string, groups map[string]bool, c *Change) (string, error) {
	if c.State != StateHolding {
		return "", gerr("DG-STATE", "this change is "+c.State, "", 409)
	}
	if person == c.Proposer {
		return "", gerr("DG-PROPOSER", "the proposer of a change cannot clear it", "Someone else from the owner group must.", 403)
	}
	for _, a := range c.Approvals {
		if a.Person == person {
			return "", gerr("DG-TWICE", person+" already cleared this change", "A second person is needed.", 409)
		}
	}
	req := c.RequirementObj()
	if req == nil {
		return "", gerr("DG-STATE", "this change needs no person", "", 409)
	}
	owner, outside := 0, 0
	for _, a := range c.Approvals {
		switch a.Role {
		case "owner":
			owner++
		case "outside":
			outside++
		}
	}
	inOutside := false
	for _, g := range req.OutsideGroups {
		if groups[g] {
			inOutside = true
		}
	}
	if groups[req.OwnerGroup] && owner < req.Owner {
		return "owner", nil
	}
	if inOutside && outside < req.Outside {
		return "outside", nil
	}
	if groups[req.OwnerGroup] || inOutside {
		which := "outside"
		if groups[req.OwnerGroup] {
			which = "owner"
		}
		return "", gerr("DG-FILLED", fmt.Sprintf("the %s requirement is already met; this change still needs %s", which, req.Words()), "", 409)
	}
	return "", gerr("DG-FORBIDDEN", fmt.Sprintf("%s is in neither %s nor an outside group (%s)", person, req.OwnerGroup, strings.Join(req.OutsideGroups, ", ")),
		"Only the app's owner group and the outside group may clear.", 403)
}
