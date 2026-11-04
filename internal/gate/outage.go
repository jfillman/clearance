package gate

import (
	"fmt"
	"sort"
)

// The outage policy (C-6): what a deployment-gate provider does with a change when it cannot reach the core.
// The platform baseline lets tiers 0 and 1 through and records them (allow-and-record: the provider keeps what it
// did and posts it as deploy.degraded once the core answers, coverage coverage-unavailable), and holds tiers 2 and
// 3 until the core is back. A repo's clearance.yaml may only tighten it (outage: {"0": hold, "1": hold}); tier 3
// always holds. A provider that cannot tell a change's tier (it never reached the core) treats it as held: an
// unknown tier is never allowed.
const (
	OutageAllow = "allow-and-record"
	OutageHold  = "hold"
)

// OutageActions are the two actions, the looser first.
var OutageActions = []string{OutageAllow, OutageHold}

// DefaultOutage is the platform baseline, by tier.
var DefaultOutage = [4]string{OutageAllow, OutageAllow, OutageHold, OutageHold}

// OutageFor is the action for tier under the policy; a tier out of range (unknown) holds.
func (p Policy) OutageFor(tier int) string {
	if tier < 0 || tier > 3 {
		return OutageHold
	}
	if a := p.Outage[tier]; a != "" {
		return a
	}
	return DefaultOutage[tier]
}

// OutageView is the outage block as the policy view serves it: {"0": action, ..., "3": action}.
func (p Policy) OutageView() map[string]string {
	out := map[string]string{}
	for t := 0; t <= 3; t++ {
		out[fmt.Sprint(t)] = p.OutageFor(t)
	}
	return out
}

// tightenOutage applies clearance.yaml's outage block: {"<tier>": "hold" | "allow-and-record"}. A tier may move
// from allow-and-record to hold; anything that would let more through than the policy it tightens is DG-POLICY.
func (p Policy) tightenOutage(v any) ([4]string, error) {
	out := [4]string{}
	for t := 0; t <= 3; t++ {
		out[t] = p.OutageFor(t)
	}
	m, ok := v.(map[string]any)
	if !ok {
		return out, gerr("DG-POLICY", `clearance.yaml: outage is {"<tier 0-3>": hold | allow-and-record}`, "", 400)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if len(k) != 1 || k[0] < '0' || k[0] > '3' {
			return out, gerr("DG-POLICY", fmt.Sprintf("clearance.yaml: outage.%s is not a tier (0 to 3)", k), "", 400)
		}
		t := int(k[0] - '0')
		a, ok := m[k].(string)
		if !ok || (a != OutageAllow && a != OutageHold) {
			return out, gerr("DG-POLICY", fmt.Sprintf("clearance.yaml: outage.%s is hold or allow-and-record", k), "", 400)
		}
		if a == OutageAllow && out[t] == OutageHold {
			return out, gerr("DG-POLICY", fmt.Sprintf("clearance.yaml: outage.%s may only be tightened (the baseline holds tier %d while Clearance is unreachable)", k, t),
				"An outage block may change allow-and-record to hold, never the other way.", 400)
		}
		out[t] = a
	}
	return out, nil
}
