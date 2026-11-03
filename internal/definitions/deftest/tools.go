package deftest

import "github.com/jfillman/clearance/internal/review"

// Tools is the core registry (tiers.CORE_TOOLS) and the Hangar pack's tools the ported tests name.
func Tools() review.Registry {
	t := map[string]review.ToolSpec{
		"catalog.read": {Tier: 0}, "metrics.query": {Tier: 0}, "logs.query": {Tier: 0}, "argo.app.get": {Tier: 0},
		"app.api.get": {Tier: 0}, "chat.recv": {Tier: 0}, "chat.send": {Tier: 0},
		"repo.file.get": {Tier: 0, ReadsRepo: true},
		"repo.pr.open":  {Tier: 1, WritesFiles: true},
		"xr.request":    {Tier: 1}, "argo.sync.lower": {Tier: 1}, "artifact.put": {Tier: 1}, "artifact.get": {Tier: 0},
		"run.spawn": {Tier: 1}, "run.close": {Tier: 1}, "human.request": {Tier: 1}, "human.request.get": {Tier: 0},
		"repo.pr.open_upper": {Tier: 2, ProposeOnly: true, WritesFiles: true},
		// the Hangar pack's read tools
		"glidepath.runs.list": {Tier: 0}, "glidepath.run.get": {Tier: 0}, "glidepath.logs.get": {Tier: 0}, "glidepath.explain": {Tier: 0},
	}
	trip := map[string]bool{}
	for _, n := range []string{"k8s.exec", "k8s.apply", "k8s.delete", "secrets.read", "iam.grant", "argo.sync.upper",
		"argo.app.delete", "branch_protection.update"} {
		trip[n] = true
	}
	return review.Registry{Tools: t, Tripwires: trip}
}
