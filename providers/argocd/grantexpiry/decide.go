// Package grantexpiry is the clock the Argo CD gate's admission policy does not have (I-44). The policy
// clearance-protected-writes (providers/argocd/crd/admission.yaml) admits Argo CD's write to a protected namespace when
// the namespace's active ClearanceGrant is status.valid and lists the object at its stamped hash. CEL has no clock, so
// expiry reaches admission only through the agent flipping status.valid; an agent that stops leaves an expired grant
// admitting writes. This package is a ValidatingWebhook beside the policy that compares every matching grant entry's
// expiry with its own clock. It mirrors the policy's matching, it can only refuse, and the policy must pass as well.
package grantexpiry

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	agent "github.com/jfillman/clearance/providers/argocd/agent"
)

// Object is what Decide reads of the admitted object (the request's object: the new state on an UPDATE).
type Object struct {
	APIVersion  string
	Kind        string
	Name        string
	Labels      map[string]string
	Annotations map[string]string
	Spec        json.RawMessage // read only for the wait Job's exemption
}

// Key is the policy's key for the object: <group>/<kind>/<name>, an empty group for the core group (the policy's
// `key` variable: the part of apiVersion before '/', when there is one).
func (o Object) Key() string {
	group := ""
	if g, _, ok := strings.Cut(o.APIVersion, "/"); ok {
		group = g
	}
	return agent.GrantKey(group, o.Kind, o.Name)
}

// Pins are the gate's own PreSync wait Job, as the policy's exemption pins it: the wait image, the core URL (and for one
// release the previous one), the host alias and the CA ConfigMap. An empty Image exempts nothing.
type Pins struct {
	agent.WaitPin
	PreviousURL string
}

// exempt is the policy's `exempt` variable: the injected wait Job exactly as the CMP builds it (the same field allowlist
// the agent's exception scan uses), on the pinned URL or, for one release, the previous one, and with or without the
// optional CA volume (the policy admits a Job without it, the CMP before its CA is configured).
func (p Pins) exempt(o Object) bool {
	if p.Image == "" {
		return false
	}
	urls := []string{p.URL}
	if p.PreviousURL != "" {
		urls = append(urls, p.PreviousURL)
	}
	cas := []string{""}
	if p.CAConfigMap != "" {
		cas = append(cas, p.CAConfigMap)
	}
	for _, u := range urls {
		for _, ca := range cas {
			pin := p.WaitPin
			pin.URL, pin.CAConfigMap = u, ca
			if agent.IsWaitJob(o.APIVersion, o.Kind, o.Name, o.Labels, o.Annotations, o.Spec, pin) {
				return true
			}
		}
	}
	return false
}

// Verdict is Decide's answer.
type Verdict struct {
	Allowed bool
	// Expired: the refusal is the clock's. An entry lists the object at its hash, and every such entry has expired (or
	// its expiry is missing or unreadable). This is what the policy alone would have admitted while status.valid was
	// stale: the audit annotation clearance.hangar.io/expired-grant marks exactly these.
	Expired bool
	Grant   string // the grant whose entries decided (namespace-free name), when there was one
	Reason  string
}

// Decide is the webhook's decision for one write. active is every grant of the object's namespace labelled
// clearance.hangar.io/active=true, as the policy's paramRef selector sees them. Like the policy, each active grant must
// pass, and with none the write is refused. An entry counts only if it lists the object's key at exactly the stamped
// hash (the policy compares the stamp literally), and it counts as unexpired only while now is before its expiry plus
// skew:
//
//   - the grant's own objects[key]: spec.expiresAt, and objects[key].expiresAt when the entry has one (a merged grant's
//     per-object expiry);
//   - a carried[] entry whose objects[key] is at the hash: the entry's expiresAt, and the object's own expiresAt when set.
//
// An expired matching entry is never rescued by an unexpired entry that does not match. A missing or unreadable expiry
// is an expired one. Decide reads no status: status.valid stays the policy's check.
func Decide(o Object, active []agent.Grant, now time.Time, skew time.Duration, pins Pins) Verdict {
	if pins.exempt(o) {
		return Verdict{Allowed: true, Reason: "the gate's own PreSync wait Job (exempt, as in the admission policy)"}
	}
	rendered := o.Annotations[agent.AnnRendered]
	key := o.Key()
	if rendered == "" {
		return Verdict{Reason: "no " + agent.AnnRendered + " annotation on " + key + ": it did not come from the Clearance plugin"}
	}
	if len(active) == 0 {
		return Verdict{Reason: "no active ClearanceGrant in the namespace"}
	}
	var last Verdict
	for _, g := range active {
		v := decideOne(g, key, rendered, now, skew)
		if !v.Allowed {
			return v
		}
		last = v
	}
	return last
}

func decideOne(g agent.Grant, key, rendered string, now time.Time, skew time.Duration) Verdict {
	live := func(ts ...string) (bool, string) {
		for _, s := range ts {
			t, err := time.Parse(time.RFC3339, s)
			if err != nil {
				if s == "" {
					return false, "no expiresAt"
				}
				return false, fmt.Sprintf("expiresAt %q is not an RFC 3339 time", s)
			}
			if !now.Before(t.Add(skew)) {
				return false, "expired at " + t.UTC().Format(time.RFC3339)
			}
		}
		return true, ""
	}
	var why []string
	if e, ok := g.Spec.Objects[key]; ok && e.Rendered == rendered {
		ts := []string{g.Spec.ExpiresAt}
		if e.ExpiresAt != "" {
			ts = append(ts, e.ExpiresAt)
		}
		if ok, r := live(ts...); ok {
			return Verdict{Allowed: true, Grant: g.Name, Reason: "grant " + g.Name + " lists " + key + " at " + rendered + ", unexpired"}
		} else {
			why = append(why, "its own entry: "+r)
		}
	}
	for i, c := range g.Spec.Carried {
		e, ok := c.Objects[key]
		if !ok || e.Rendered != rendered {
			continue
		}
		ts := []string{c.ExpiresAt}
		if e.ExpiresAt != "" {
			ts = append(ts, e.ExpiresAt)
		}
		if ok, r := live(ts...); ok {
			return Verdict{Allowed: true, Grant: g.Name, Reason: fmt.Sprintf("grant %s carries %s at %s (carried[%d], change %s), unexpired", g.Name, key, rendered, i, c.Change)}
		} else {
			why = append(why, fmt.Sprintf("carried[%d] (change %s): %s", i, c.Change, r))
		}
	}
	if len(why) > 0 {
		return Verdict{Expired: true, Grant: g.Name, Reason: "grant " + g.Name + " lists " + key + " at " + rendered +
			" only in expired entries (" + strings.Join(why, "; ") + ")"}
	}
	return Verdict{Grant: g.Name, Reason: "grant " + g.Name + " does not list " + key + " at " + rendered}
}
