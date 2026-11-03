package gate

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/store"
)

// DeploymentResult is deployment_requested's answer.
type DeploymentResult struct {
	Answer   *string `json:"answer"`
	Rule     *string `json:"rule"`
	Comment  string  `json:"comment"`
	Change   *string `json:"change"`
	AuditSeq any     `json:"audit_seq"`
}

// DeploymentRequested is Gateway.deployment_requested: GitHub asks whether a GitHub Actions deployment of head
// from repo to environment may go. The answer is the change registered for that commit and environment (matched on
// repo, head and the environment's name lowercased): cleared approves; holding waits and is answered when people
// decide; denied, expired or superseded rejects; no change at all rejects (DG-UNREGISTERED). Each request is a
// deploy.request record by app:<installation>.
func (s *Service) DeploymentRequested(ctx context.Context, installation, repo, head, environment string, runID int64, callbackURL string) (DeploymentResult, error) {
	var out DeploymentResult
	repo, env := strings.ToLower(repo), strings.ToLower(environment)
	principal := "app:" + installation
	err := s.op(ctx, func(tx store.Tx, w *writer) error {
		var found []*Change
		if !s.Config.Off {
			all, err := loadAll(tx.ChangesForHead(ctx, repo, head))
			if err != nil {
				return err
			}
			for _, c := range all {
				if c.Env == env && c.State != "superseded" {
					found = append(found, c)
				}
			}
		}
		if len(found) == 0 {
			why := fmt.Sprintf("no change is registered for %s to %s; register it first (Glidepath's "+
				"clearance-gate check, or `clearance register` in this workflow before the deploy job)", pycompat.Truncate(head, 7), environment)
			rec := w.append(store.Event{
				"ts": pycompat.ISO(w.now), "task_id": nil, "session": nil, "parent": nil, "principal": principal,
				"agent": nil, "tool": "deploy.request", "tier": nil, "decision": "deny", "rule": "DG-UNREGISTERED",
				"target": repo + "@" + pycompat.Truncate(head, 7),
				"args_sha256": pycompat.ArgsDigest(map[string]any{"run": runID, "environment": environment}),
				"result":      fmt.Sprintf("deployment run %d to %s: rejected", runID, environment), "boundary": "deployment"})
			out = DeploymentResult{strp("rejected"), strp("DG-UNREGISTERED"), why, nil, recordSeq(rec)}
			return nil
		}
		c := found[len(found)-1]
		idx := -1
		for i, d := range c.Deployments {
			if d.RunID == runID && d.Environment == environment {
				idx = i
				break
			}
		}
		if idx < 0 {
			c.Deployments = append(c.Deployments, Deployment{RunID: runID, Environment: environment, Installation: installation,
				CallbackURL: callbackURL, RequestedAt: pycompat.ISO(w.now)})
			idx = len(c.Deployments) - 1
		}
		entry := &c.Deployments[idx]
		if answer := DeploymentAnswer(c.State); answer != nil && entry.Answer == nil {
			at := pycompat.ISO(w.now)
			entry.Answer, entry.AnsweredAt, entry.Delivered = answer, &at, false
		}
		c.UpdatedAt = PyTime{w.now}
		w.put(c)
		word := "waiting"
		if entry.Answer != nil {
			word = *entry.Answer
		}
		rec := w.record(principal, nil, "deploy.request", c, "allow", nil, fmt.Sprintf("deployment run %d to %s: %s", runID, environment, word),
			map[string]any{"run": runID, "environment": environment})
		id := c.ID
		out = DeploymentResult{entry.Answer, nil, s.deploymentComment(c, entry.Answer), &id, recordSeq(rec)}
		return nil
	})
	return out, err
}

func (s *Service) deploymentComment(c *Change, answer *string) string {
	if answer != nil && *answer == "approved" {
		by := "policy"
		if c.ClearedBy != nil && *c.ClearedBy != "" {
			by = *c.ClearedBy
		}
		return fmt.Sprintf("Cleared by %s (tier %d). Clearance change `%s`.", by, c.Tier, c.ID)
	}
	if answer != nil && *answer == "rejected" {
		var why string
		switch c.State {
		case "denied":
			why = fmt.Sprintf("denied by %s: %s", pycompat.Str(strOrNil(c.DeniedBy)), pycompat.Str(strOrNil(c.DenyReason)))
		case "expired":
			why = "it expired before it was cleared"
		case "superseded":
			sup := ""
			if c.SupersededBy != nil {
				sup = *c.SupersededBy
			}
			why = fmt.Sprintf("a newer commit (%s) replaced it", pycompat.Truncate(sup, 7))
		default:
			why = c.State
		}
		return fmt.Sprintf("Not cleared: %s. Clearance change `%s`.", why, c.ID)
	}
	words := "a person must clear it"
	if req := c.RequirementObj(); req != nil {
		words = req.Words()
	}
	return fmt.Sprintf("Held for people (tier %d): %s. Clearance change `%s`; this deployment goes as soon as it is cleared.", c.Tier, words, c.ID)
}

// Undelivered is one answered deployment GitHub has not taken yet: the entry plus its change, repo and comment.
type Undelivered struct {
	Deployment
	Change  string `json:"change"`
	Repo    string `json:"repo"`
	Comment string `json:"comment"`
}

// UndeliveredDeployments is Gateway.undelivered_deployments: answered but not yet taken, oldest first.
func (s *Service) UndeliveredDeployments(ctx context.Context) ([]Undelivered, error) {
	if s.Config.Off {
		return nil, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cs, err := loadAll(s.Store.ChangesUndelivered(ctx))
	if err != nil {
		return nil, fmt.Errorf("gate: %w", err)
	}
	var out []Undelivered
	for _, c := range cs {
		for _, d := range c.Deployments {
			if d.Answer != nil && *d.Answer != "" && !d.Delivered {
				out = append(out, Undelivered{d, c.ID, c.Repo, s.deploymentComment(c, d.Answer)})
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return deref(out[i].AnsweredAt) < deref(out[j].AnsweredAt) })
	return out, nil
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// DeploymentDelivered is Gateway.deployment_delivered: GitHub took the answer; the entry is delivered and the answer
// is a deploy.answer record by app:<installation>. nil when nothing matched.
func (s *Service) DeploymentDelivered(ctx context.Context, changeID string, runID int64, environment string) (store.Record, error) {
	if s.Config.Off {
		return nil, nil
	}
	var out store.Record
	err := s.op(ctx, func(tx store.Tx, w *writer) error {
		c, err := load(ctx, tx, changeID)
		if err != nil || c == nil {
			return err
		}
		for i := range c.Deployments {
			d := &c.Deployments[i]
			if d.RunID == runID && d.Environment == environment && !d.Delivered {
				at := pycompat.ISO(w.now)
				d.Delivered, d.DeliveredAt = true, &at
				c.UpdatedAt = PyTime{w.now}
				w.put(c)
				answer := deref(d.Answer)
				decision, rule := "allow", (*string)(nil)
				if answer != "approved" {
					decision, rule = "deny", strp("DG-NOT-CLEARED")
				}
				out = w.record("app:"+d.Installation, nil, "deploy.answer", c, decision, rule,
					fmt.Sprintf("deployment run %d to %s: %s", runID, environment, pycompat.Str(strOrNil(d.Answer))),
					map[string]any{"run": runID, "environment": environment, "answer": strOrNil(d.Answer)})
				return nil
			}
		}
		return nil
	})
	return out, err
}
