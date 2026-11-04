package gate_test

// G-TF-1: the terraform-plan subject. The tier table (docs/gate.md, The terraform-plan subject), its negatives (a
// destroy in a protected workspace never clears by policy; a looser clearance.yaml is DG-POLICY), registration by a
// verifier and by a GitHub Actions OIDC principal with DG-REPO enforced, the record's subject, and the schema.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/jfillman/clearance/internal/authn"
	"github.com/jfillman/clearance/internal/canon"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/store/memory"
	"github.com/jfillman/clearance/schemas"
)

var (
	planDigest = canon.SHA256Hex([]byte("the saved plan"))
	planJSON   = canon.SHA256Hex([]byte("the redacted plan JSON"))
	varSet     = canon.SHA256Hex([]byte("the variable set"))
)

// res is one resource change; fields are JSON pointers.
func res(address, typ string, actions []string, fields ...string) map[string]any {
	return map[string]any{"address": address, "type": typ, "actions": strs(actions), "fields": strs(fields)}
}

var (
	create  = []string{"create"}
	update  = []string{"update"}
	destroy = []string{"delete"}
	replace = []string{"delete", "create"}
	noop    = []string{"no-op"}
)

// plan is a terraform-plan subject over resources, its summary computed from them as a verifier would.
func plan(over map[string]any, resources ...map[string]any) map[string]any {
	sum := map[string]any{"create": 0, "update": 0, "replace": 0, "destroy": 0, "destroyedAddresses": []any{}}
	inc := func(k string) { sum[k] = sum[k].(int) + 1 }
	for _, r := range resources {
		switch a := r["actions"].([]any); {
		case len(a) == 2:
			inc("replace")
		case a[0] == "create":
			inc("create")
		case a[0] == "update":
			inc("update")
		case a[0] == "delete":
			inc("destroy")
			sum["destroyedAddresses"] = append(sum["destroyedAddresses"].([]any), r["address"])
		}
	}
	rs := []any{}
	for _, r := range resources {
		rs = append(rs, r)
	}
	s := map[string]any{"kind": "terraform-plan", "planDigest": "sha256:" + planDigest, "planJsonDigest": planJSON,
		"workspace": map[string]any{"backend": "s3", "key": "network/lab/terraform.tfstate", "name": "default"},
		"versions":  map[string]any{"terraform": "1.9.8", "providers": map[string]any{"registry.terraform.io/hashicorp/aws": "5.70.0"}},
		"summary":   sum, "targeted": false, "variableSetDigest": varSet, "resources": rs}
	for k, v := range over {
		s[k] = v
	}
	return s
}

// tfChange is a registration of a plan for jfillman/hangar-infra's network/lab workspace.
func tfChange(subject map[string]any, over map[string]any) map[string]any {
	b := map[string]any{"app": "network", "env": "lab", "repo": "jfillman/hangar-infra", "pr": 12, "head": head,
		"proposer": "user:dana", "owner": owner, "paths": strs([]string{"network/lab/main.tf"}),
		"checks": map[string]any{"ci": "pass", "provenance": "not-agent"}, "subject": subject}
	for k, v := range over {
		if v == nil {
			delete(b, k)
		} else {
			b[k] = v
		}
	}
	raw, _ := json.Marshal(b)
	v, _ := pycompat.Decode(strings.NewReader(string(raw)))
	return v.(map[string]any)
}

func reasonFor(c gate.Classification, subject string) (gate.Reason, bool) {
	for _, r := range c.Reasons {
		if r.Subject == subject {
			return r, true
		}
	}
	return gate.Reason{}, false
}

// The tier table, one row per case, each naming the address that set the tier.
func TestTheTerraformTierTable(t *testing.T) {
	unprotected := map[string]any{"protected": false}
	for _, tc := range []struct {
		name     string
		subject  map[string]any
		over     map[string]any
		tier     int
		decision string
		setBy    string // the reason subject at the tier
		rule     string
	}{
		{"destroy in a protected workspace", plan(nil, res("aws_instance.bastion", "aws_instance", destroy)), nil, 3, "hold", "aws_instance.bastion", "tf:destroy"},
		{"replace in a protected workspace", plan(nil, res("aws_instance.bastion", "aws_instance", replace)), nil, 3, "hold", "aws_instance.bastion", "tf:replace"},
		{"destroy in an unprotected workspace", plan(nil, res("aws_instance.bastion", "aws_instance", destroy)), unprotected, 2, "hold", "aws_instance.bastion", "tf:destroy"},
		{"create-before-destroy replace, unprotected", plan(nil, res("aws_instance.b", "aws_instance", []string{"create", "delete"})), unprotected, 2, "hold", "aws_instance.b", "tf:replace"},
		{"an IAM role", plan(nil, res("aws_iam_role.ci", "aws_iam_role", create)), unprotected, 3, "hold", "aws_iam_role.ci", "tf-type:iam"},
		{"a tag on an IAM role is still tier 3", plan(nil, res("aws_iam_role.ci", "aws_iam_role", update, "/tags/Owner")), nil, 3, "hold", "aws_iam_role.ci", "tf-type:iam"},
		{"a security group rule in a module", plan(nil, res(`module.net.aws_security_group_rule.web["443"]`, "aws_security_group_rule", update, "/cidr_blocks/0")), nil, 3, "hold", `module.net.aws_security_group_rule.web["443"]`, "tf-type:security-group"},
		{"a network ACL", plan(nil, res("aws_network_acl.private", "aws_network_acl", update, "/ingress")), nil, 3, "hold", "aws_network_acl.private", "tf-type:network-acl"},
		{"a KMS key", plan(nil, res("aws_kms_key.state", "aws_kms_key", create)), nil, 3, "hold", "aws_kms_key.state", "tf-type:kms"},
		{"a database", plan(nil, res("aws_db_instance.main", "aws_db_instance", update, "/instance_class")), nil, 3, "hold", "aws_db_instance.main", "tf-type:database"},
		{"a Google firewall", plan(nil, res("google_compute_firewall.ssh", "google_compute_firewall", update, "/source_ranges")), nil, 3, "hold", "google_compute_firewall.ssh", "tf-type:security-group"},
		{"tag-only", plan(nil, res("aws_vpc.lab", "aws_vpc", update, "/tags/Owner", "/tags_all/Owner")), nil, 1, "clear", "aws_vpc.lab", "tf:tag-only"},
		{"description-only", plan(nil, res("aws_ec2_managed_prefix_list.office", "aws_ec2_managed_prefix_list", update, "/description")), nil, 1, "clear", "aws_ec2_managed_prefix_list.office", "tf:tag-only"},
		{"an update beyond tags", plan(nil, res("aws_vpc.lab", "aws_vpc", update, "/tags/Owner", "/enable_dns_hostnames")), nil, 2, "hold", "aws_vpc.lab", "tf:update"},
		{"a create", plan(nil, res("aws_subnet.c", "aws_subnet", create)), nil, 2, "hold", "aws_subnet.c", "tf:create"},
		{"an update naming no fields", plan(nil, res("aws_vpc.lab", "aws_vpc", update)), nil, 2, "hold", "aws_vpc.lab", "tf:update"},
		{"a plan that changes nothing", plan(nil, res("aws_vpc.lab", "aws_vpc", noop)), nil, 1, "clear", "the plan", "tf:no-change"},
		{"-target lifts tag-only to the floor of 2", plan(map[string]any{"targeted": true}, res("aws_vpc.lab", "aws_vpc", update, "/tags/Owner")), nil, 2, "hold", "the plan", "tf:targeted"},
		{"-target lifts tier 2 to 3", plan(map[string]any{"targeted": true}, res("aws_subnet.c", "aws_subnet", create)), nil, 3, "hold", "the plan", "tf:targeted"},
		{"-target on a no-change plan", plan(map[string]any{"targeted": true}), nil, 2, "hold", "the plan", "tf:targeted"},
		{"-replace lifts an unprotected replace to 3", plan(nil, func() map[string]any {
			r := res("aws_instance.b", "aws_instance", replace)
			r["actionReason"] = "replace_by_request"
			return r
		}()), unprotected, 3, "hold", "aws_instance.b", "tf:replace-requested"},
		{"tag-only without green CI waits", plan(nil, res("aws_vpc.lab", "aws_vpc", update, "/tags/Owner")), map[string]any{"checks": map[string]any{"ci": "fail", "provenance": "not-agent"}}, 2, "hold", "the checks", "checks:ci"},
		{"a clearance.yaml change in the infra repo", plan(nil, res("aws_vpc.lab", "aws_vpc", update, "/tags/Owner")), map[string]any{"paths": strs([]string{"clearance.yaml"})}, 3, "hold", "clearance.yaml", "path:clearance.yaml"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := mustClassify(t, tfChange(tc.subject, tc.over), baseline)
			if c.Tier != tc.tier || c.Decision != tc.decision {
				t.Fatalf("tier %d %s, want %d %s: %+v", c.Tier, c.Decision, tc.tier, tc.decision, c.Reasons)
			}
			if !slices.ContainsFunc(c.Reasons, func(r gate.Reason) bool { return r.Subject == tc.setBy && r.Rule == tc.rule && r.Tier == tc.tier }) {
				t.Fatalf("%s: %+v, want %s at tier %d", tc.setBy, c.Reasons, tc.rule, tc.tier)
			}
			if !strings.Contains(c.Why, "set by "+tc.setBy) || !strings.Contains(c.Why, "s3:network/lab/terraform.tfstate#default") {
				t.Fatalf("why %q does not name %s and the workspace", c.Why, tc.setBy)
			}
			if tc.tier == 3 && (c.Requirement == nil || c.Requirement.Owner != 1 || c.Requirement.Outside != 1) {
				t.Fatalf("tier 3 needs an owner and an outsider: %+v", c.Requirement)
			}
		})
	}
}

// Negative: a destroy in a protected workspace is never cleared by policy, however the checks, the proposer or
// clearance.yaml look; and the summary cannot hide it.
func TestADestroyInAProtectedWorkspaceNeverClearsByPolicy(t *testing.T) {
	gone := plan(nil, res("aws_s3_bucket.state", "aws_s3_bucket", destroy))
	for name, over := range map[string]map[string]any{
		"green checks":              nil,
		"an agent's PR":             {"proposerKind": "agent", "checks": map[string]any{"ci": "pass", "provenance": "confirmed"}},
		"clearance.yaml tightening": {"policy": map[string]any{"approvers": map[string]any{"3": map[string]any{"owner": 2}}, "ttlDays": 1}},
		"protected by clearance.yaml though the verifier said not": {"protected": false,
			"policy": map[string]any{"workspaces": map[string]any{"protected": []any{"network/*"}}}},
	} {
		c := mustClassify(t, tfChange(gone, over), baseline)
		if c.Decision == "clear" || c.Tier != 3 {
			t.Errorf("%s: %s at tier %d", name, c.Decision, c.Tier)
		}
	}
	// The summary must say what the resources say: a destroy left out of either is refused, not tiered.
	hidden := plan(nil, res("aws_s3_bucket.state", "aws_s3_bucket", destroy))
	hidden["summary"] = map[string]any{"create": 0, "update": 0, "replace": 0, "destroy": 0, "destroyedAddresses": []any{}}
	missing := plan(nil)
	missing["summary"] = map[string]any{"create": 0, "update": 0, "replace": 0, "destroy": 1, "destroyedAddresses": []any{"aws_s3_bucket.state"}}
	for name, s := range map[string]map[string]any{"summary hides it": hidden, "resources hide it": missing} {
		var bc *gate.BadChange
		if _, err := gate.ParseRequest(tfChange(s, nil)); !errors.As(err, &bc) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Through the gate: held for two people, never cleared by the registration however often it is re-registered.
	f := newGate(t)
	for range 2 {
		out := f.register(t, "ci", tfChange(gone, nil))
		if out.State != "holding" || out.Tier != 3 || out.ClearedBy != nil {
			t.Fatalf("%s tier %d", out.State, out.Tier)
		}
	}
	if n := len(f.records(t, "deploy.clear")); n != 0 {
		t.Fatalf("%d deploy.clear records", n)
	}
}

// Negative: a clearance.yaml whose workspaces block loosens (or says something it may not) is DG-POLICY, and the
// registration is denied by policy.
func TestALooserWorkspacesBlockIsDGPolicy(t *testing.T) {
	gone := plan(nil, res("aws_instance.bastion", "aws_instance", destroy))
	for name, ws := range map[string]any{
		"unprotect":        map[string]any{"unprotected": []any{"network/lab/*"}},
		"tier 1 types":     map[string]any{"tiers": map[string]any{"1": map[string]any{"types": []any{"aws_iam_role"}}}},
		"tier 0 types":     map[string]any{"tiers": map[string]any{"0": map[string]any{"types": []any{"aws_instance"}}}},
		"protected: false": map[string]any{"protected": false},
		"a non-list":       map[string]any{"protected": "network/*"},
		"a non-string":     map[string]any{"tiers": map[string]any{"3": map[string]any{"types": []any{3}}}},
		"other keys":       map[string]any{"tiers": map[string]any{"3": map[string]any{"kinds": []any{"Secret"}}}},
		"not a mapping":    []any{"network/lab"},
	} {
		_, err := classify(t, tfChange(gone, map[string]any{"policy": map[string]any{"workspaces": ws}}), baseline)
		if r, s := ruleOf(err); r != "DG-POLICY" || s != 400 {
			t.Errorf("%s: %v", name, err)
		}
	}
	f := newGate(t)
	out := f.register(t, "ci", tfChange(gone, map[string]any{"policy": map[string]any{"workspaces": map[string]any{"unprotected": []any{"*"}}}}))
	if out.State != "denied" || out.DeniedBy == nil || *out.DeniedBy != "policy" || out.Subject.Kind != gate.KindTerraformPlan {
		t.Fatalf("%s %v", out.State, out.DeniedBy)
	}
	// What it may do: add tier-3 and tier-2 types and protect workspaces.
	tight := map[string]any{"workspaces": map[string]any{"protected": []any{"network/*"},
		"tiers": map[string]any{"3": map[string]any{"types": []any{"aws_route53_*"}}, "2": map[string]any{"types": []any{"aws_vpc"}}}}}
	c := mustClassify(t, tfChange(plan(nil, res("aws_route53_record.www", "aws_route53_record", update, "/ttl")), map[string]any{"policy": tight}), baseline)
	if r, _ := reasonFor(c, "aws_route53_record.www"); c.Tier != 3 || r.Rule != "tf-type:clearance.yaml" {
		t.Fatal(c.Reasons)
	}
	c = mustClassify(t, tfChange(plan(nil, res("aws_vpc.lab", "aws_vpc", update, "/tags/Owner")), map[string]any{"policy": tight}), baseline)
	if r, _ := reasonFor(c, "aws_vpc.lab"); c.Tier != 2 || r.Rule != "tf-type:tier2" {
		t.Fatal(c.Reasons)
	}
	c = mustClassify(t, tfChange(plan(nil, res("aws_instance.b", "aws_instance", destroy)), map[string]any{"protected": false, "policy": tight}), baseline)
	if c.Tier != 3 {
		t.Fatalf("protected by clearance.yaml: tier %d", c.Tier)
	}
	if v := c.Policy.View().Terraform; !slices.Contains(v.ProtectedWorkspaces, "network/*") || !slices.Contains(v.Tier3Types["clearance.yaml"], "aws_route53_*") ||
		!slices.Contains(v.Tier3Types["iam"], "aws_iam_*") {
		t.Fatalf("%+v", v)
	}
}

func TestAMalformedPlanIsRefused(t *testing.T) {
	ok := plan(nil, res("aws_vpc.lab", "aws_vpc", update, "/tags/Owner"))
	with := func(k string, v any) map[string]any {
		s := plan(nil, res("aws_vpc.lab", "aws_vpc", update, "/tags/Owner"))
		if v == nil {
			delete(s, k)
		} else {
			s[k] = v
		}
		return s
	}
	resWith := func(k string, v any) map[string]any {
		r := res("aws_vpc.lab", "aws_vpc", update, "/tags/Owner")
		r[k] = v
		return with("resources", []any{r})
	}
	for name, body := range map[string]map[string]any{
		"another kind":           tfChange(with("kind", "manifest-tree"), nil),
		"an unknown field":       tfChange(with("plan", "raw"), nil),
		"no plan digest":         tfChange(with("planDigest", nil), nil),
		"a short digest":         tfChange(with("planJsonDigest", "abc"), nil),
		"no variable set":        tfChange(with("variableSetDigest", nil), nil),
		"no workspace":           tfChange(with("workspace", nil), nil),
		"a workspace key":        tfChange(with("workspace", map[string]any{"backend": "s3", "key": "a\nb", "name": "default"}), nil),
		"no versions":            tfChange(with("versions", map[string]any{"providers": map[string]any{}}), nil),
		"no resources":           tfChange(with("resources", nil), nil),
		"targeted not a bool":    tfChange(with("targeted", "yes"), nil),
		"an invented action":     tfChange(resWith("actions", []any{"update", "delete"}), nil),
		"a type not its address": tfChange(resWith("type", "aws_iam_role"), nil),
		"a value in fields":      tfChange(resWith("fields", []any{"password=hunter2"}), nil),
		"a resource field":       tfChange(resWith("before", map[string]any{"password": "x"}), nil),
		"twice":                  tfChange(with("resources", []any{res("aws_vpc.lab", "aws_vpc", create), res("aws_vpc.lab", "aws_vpc", create)}), nil),
		"objects too":            tfChange(ok, map[string]any{"objects": replicas}),
		"another treeDigest":     tfChange(ok, map[string]any{"treeDigest": tree}),
		"a definition too":       tfChange(ok, map[string]any{"definition": map[string]any{"name": "x", "new": map[string]any{}}}),
	} {
		if _, err := gate.ParseRequest(body); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A placeholder digest is DG-UNBOUND, for every digest of a plan.
	for _, k := range []string{"planDigest", "planJsonDigest", "variableSetDigest"} {
		_, err := gate.ParseRequest(tfChange(with(k, strings.Repeat("0", 64)), nil))
		if r, s := ruleOf(err); r != "DG-UNBOUND" || s != 400 {
			t.Errorf("%s: %v", k, err)
		}
	}
	// No cluster and no treeDigest are needed; a treeDigest that is the plan's is accepted.
	req, err := gate.ParseRequest(tfChange(ok, map[string]any{"treeDigest": "sha256:" + planDigest, "cluster": ""}))
	if err != nil || req.TreeDigest != planDigest || req.Kind() != gate.KindTerraformPlan {
		t.Fatal(req.TreeDigest, err)
	}
}

// POST /v1/clearances takes a plan from a verifier (a pipeline's service account) and from a GitHub Actions
// workflow's OIDC token, for its own repository only (DG-REPO); the change and its records carry the subject.
func TestARegisteredPlanIsRecordedWithItsSubject(t *testing.T) {
	f := newGate(t)
	out := f.register(t, "ci", tfChange(plan(nil, res("aws_vpc.lab", "aws_vpc", update, "/tags/Owner")), nil))
	if out.State != "cleared" || out.Tier != 1 || out.TreeDigest != planDigest || out.Cluster != "" {
		t.Fatalf("%s tier %d tree %s", out.State, out.Tier, out.TreeDigest)
	}
	s := out.Subject
	if s == nil || s.Kind != gate.KindTerraformPlan || s.Workspace.Ref() != "s3:network/lab/terraform.tfstate#default" ||
		s.Digests["sha256"] != planDigest || s.Digests["planJson"] != planJSON || s.Digests["variableSet"] != varSet ||
		s.Digests["gitCommit"] != head || s.Versions.Terraform != "1.9.8" || *s.Targeted || len(s.Resources) != 1 {
		t.Fatalf("%+v", s)
	}
	stored := f.get(t, out.ID)
	if stored.Subject == nil || stored.Subject.PlanJSONDigest != planJSON || stored.Subject.Summary.Update != 1 {
		t.Fatalf("stored %+v", stored.Subject)
	}
	for _, rec := range f.records(t, "") {
		subj, _ := rec["subject"].(map[string]any)
		d, _ := subj["digests"].(map[string]any)
		if subj["kind"] != "terraform-plan" || subj["name"] != "network/lab" || d["sha256"] != planDigest ||
			d["planJson"] != planJSON || d["variableSet"] != varSet || d["gitCommit"] != head {
			t.Fatalf("%s: subject %v", rec["tool"], rec["subject"])
		}
		if pg, _ := rec["policy"].(map[string]any); pg["ref"] != "baseline" || pg["version"] != "baseline-2026-10-31" || pg["verdict"] != "not-evaluated" {
			t.Fatalf("%s: policy group %v", rec["tool"], rec["policy"])
		}
		if !inList(rec["claimed"], "subject") {
			t.Fatalf("the subject is the verifier's claim: %v", rec["claimed"])
		}
		raw, _ := json.Marshal(rec)
		if bytes.Contains(raw, []byte("password")) || bytes.Contains(raw, []byte("resources")) {
			t.Fatalf("the record carries more than digests: %s", raw)
		}
	}

	const repo = "jfillman/hangar-infra"
	svc := gate.NewService(gate.Config{Verifiers: []string{"github:repo:jfillman/*"}}, memory.New(), (&clock{T0}).now)
	wf := authn.Principal{ID: "github:repo:" + repo + ":environment:lab", Kind: authn.KindGitHubActions, Claims: map[string]any{"repository": repo}}
	body := tfChange(plan(nil, res("aws_iam_role.ci", "aws_iam_role", create)), map[string]any{"owner": "group:default/admins", "proposer": "user:jfillman"})
	got, err := svc.Register(context.Background(), wf, body)
	if err != nil || got.State != "holding" || got.Tier != 3 || got.RegisteredBy != wf.ID || got.Subject.Kind != gate.KindTerraformPlan {
		t.Fatal(got, err)
	}
	body["repo"] = "jfillman/gitops-gate-api"
	_, err = svc.Register(context.Background(), wf, body)
	if r, s := ruleOf(err); r != "DG-REPO" || s != 403 {
		t.Fatal(err)
	}
	// The same through the HTTP route.
	other := map[string]any{"planDigest": canon.SHA256Hex([]byte("another plan"))}
	code, ans := call(serve(f), "POST", "/v1/clearances", "ci", tfChange(plan(other, res("aws_db_instance.main", "aws_db_instance", update, "/tags/x")), map[string]any{"pr": 13}), nil)
	if code != 200 || fmt.Sprint(ans["tier"]) != "3" || ans["subject"].(map[string]any)["kind"] != "terraform-plan" {
		t.Fatal(code, ans)
	}
}

// A manifest-tree change records subject {kind: manifest-tree, digests}; a placeholder tree is flagged (bound to the
// commit only) or, where the deployment says refuse, refused DG-UNBOUND.
func TestTheManifestTreeSubjectAndAnUnboundTree(t *testing.T) {
	f := newGate(t)
	out := f.register(t, "ci", change(map[string]any{"objects": replicas}))
	if s := out.Subject; s.Kind != gate.KindManifestTree || s.Digests["sha256"] != tree || s.Digests["gitCommit"] != head || len(s.Flags) != 0 {
		t.Fatalf("%+v", s)
	}
	rec := f.records(t, "deploy.request")[0]
	if subj := rec["subject"].(map[string]any); subj["kind"] != "manifest-tree" || subj["name"] != "gate-api/prod" ||
		subj["digests"].(map[string]any)["sha256"] != tree {
		t.Fatal(rec["subject"])
	}
	for _, placeholder := range []string{strings.Repeat("0", 64), "sha256:" + strings.Repeat("1", 64),
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"} {
		f := newGate(t)
		out := f.register(t, "ci", change(map[string]any{"treeDigest": placeholder, "paths": strs([]string{"docs/x.md"})}))
		if out.State != "cleared" || !slices.Contains(out.Subject.Flags, gate.FlagUnboundTree) || out.Subject.Digests["sha256"] != "" {
			t.Fatalf("%s: %s %+v", placeholder, out.State, out.Subject)
		}
		if !slices.ContainsFunc(out.Reasons, func(r gate.Reason) bool { return r.Rule == "tree:unbound" && r.Tier == 0 }) {
			t.Fatalf("%s: %+v", placeholder, out.Reasons)
		}
		d := f.records(t, "deploy.request")[0]["subject"].(map[string]any)["digests"].(map[string]any)
		if len(d) != 1 || d["gitCommit"] != head {
			t.Fatalf("%s: the record binds to %v", placeholder, d)
		}
		f.svc.Config.UnboundTree = gate.UnboundRefuse
		_, err := f.svc.Register(f.ctx, principals["ci"], change(map[string]any{"head": strings.Repeat("9", 40), "treeDigest": placeholder}))
		if r, s := ruleOf(err); r != "DG-UNBOUND" || s != 400 {
			t.Fatalf("%s: %v", placeholder, err)
		}
	}
	// A change stored before subjects reads back with one.
	legacy := []byte(`{"id":"ch-1","app":"a","env":"e","repo":"r/s","pr":1,"head":"` + head + `","tree_digest":"` + tree + `"}`)
	c, err := gate.FromRecord(legacy)
	if err != nil || c.Subject == nil || c.Subject.Kind != gate.KindManifestTree || c.Subject.Digests["sha256"] != tree {
		t.Fatal(c.Subject, err)
	}
	// A definition release is subject kind definition, named for the agent.
	d := f.register(t, "ci", release(nil, defDoc(t), nil))
	if d.Subject.Kind != gate.KindDefinition || d.Subject.Name != "gate-triage" {
		t.Fatalf("%+v", d.Subject)
	}
}

// schemas/change-request.schema.json and ParseRequest agree: what one accepts the other does, over manifest, definition
// and plan bodies (the checks only the parser makes are listed in the schema's description and tested above).
func TestTheChangeRequestSchemaMatchesTheParser(t *testing.T) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemas.ChangeRequestV1))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	const url = "https://clearance.hangarplatform.dev/schemas/change-request/v1.json"
	if err := c.AddResource(url, doc); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile(url)
	if err != nil {
		t.Fatal(err)
	}
	ok := plan(nil, res("aws_vpc.lab", "aws_vpc", update, "/tags/Owner"))
	bodies := map[string]map[string]any{
		"manifest":                     change(map[string]any{"objects": imageBump}),
		"manifest, minimal":            change(map[string]any{"base": nil, "proposerKind": nil, "protected": nil, "linesChanged": nil, "objects": nil, "checks": nil, "owner": nil, "paths": nil}),
		"manifest without a tree":      change(map[string]any{"treeDigest": nil}),
		"manifest without a cluster":   change(map[string]any{"cluster": nil}),
		"manifest, bad head":           change(map[string]any{"head": "abc"}),
		"manifest, unknown field":      change(map[string]any{"extra": 1}),
		"manifest, null protected":     change(map[string]any{"protected": false, "pr": -1}),
		"definition":                   release(nil, map[string]any{"name": "gate-triage"}, nil),
		"definition, neither":          release(nil, nil, nil),
		"plan":                         tfChange(ok, nil),
		"plan with a tree and cluster": tfChange(ok, map[string]any{"treeDigest": planDigest, "cluster": "hangar-dev"}),
		"plan, no workspace":           tfChange(func() map[string]any { s := plan(nil); delete(s, "workspace"); return s }(), nil),
		"plan, a placeholder":          tfChange(func() map[string]any { s := plan(nil); s["planDigest"] = strings.Repeat("a", 64); return s }(), nil),
		"plan, bad action":             tfChange(plan(nil, res("aws_vpc.lab", "aws_vpc", []string{"move"})), nil),
		"plan, unknown field":          tfChange(func() map[string]any { s := plan(nil); s["raw"] = "x"; return s }(), nil),
		"manifest with C-1 and C-8 fields": change(map[string]any{"taskId": "task-1", "policy": map[string]any{"ttlDays": 1}, "policyCommit": head,
			"admission": map[string]any{"engine": "kyverno/1.19.0", "verdict": "pass", "bundle": "r//p@x", "deny": 0, "warn": 1}}),
		"manifest, bad admission":          change(map[string]any{"admission": map[string]any{"engine": "Kyverno", "verdict": "pass"}}),
		"manifest, bad taskId":             change(map[string]any{"taskId": "a b"}),
		"plan with a taskId and admission": tfChange(plan(nil), map[string]any{"taskId": "t", "admission": map[string]any{"engine": "kyverno/1.19.0", "verdict": "skipped"}}),
		"plan, null resources":             tfChange(func() map[string]any { s := plan(nil); s["resources"] = nil; return s }(), nil),
		"plan, objects":                    tfChange(ok, map[string]any{"objects": replicas}),
		"plan, a value in fields":          tfChange(plan(nil, res("aws_vpc.lab", "aws_vpc", update, "tags=x")), nil),
	}
	accepted := 0
	for name, body := range bodies {
		_, perr := gate.ParseRequest(body)
		verr := sch.Validate(any(body))
		if (perr == nil) != (verr == nil) {
			t.Errorf("%s: parser %v, schema %v", name, perr, verr)
		}
		if perr == nil {
			accepted++
		}
	}
	if accepted != 8 {
		t.Errorf("%d of %d bodies accepted, want 8 (the comparison would be vacuous)", accepted, len(bodies))
	}
}

// A cleared plan's clearance token names its subject kind and binds the plan's digest (plan_digest, no tree_root).
func TestAPlanTokenIsATerraformPlanSubject(t *testing.T) {
	f := newGate(t)
	c := f.register(t, "ci", tfChange(plan(nil, res("aws_vpc.lab", "aws_vpc", update, "/tags/Owner")), nil))
	cl := (&gate.Tokens{}).Claims(c, "n", T0, T0.Add(time.Minute))
	if cl.Policy != c.PolicyClaim() || cl.Policy.Version == "" {
		t.Fatalf("policy claim %+v", cl.Policy)
	}
	if cl.Subjects.Kind != gate.KindTerraformPlan || cl.Subjects.PlanDigest != planDigest || cl.Subjects.TreeRoot != "" {
		t.Fatalf("%+v", cl.Subjects)
	}
	m := f.register(t, "ci", change(map[string]any{"objects": imageBump}))
	if k := (&gate.Tokens{}).Claims(m, "n", T0, T0.Add(time.Minute)).Subjects.Kind; k != gate.KindManifestTree {
		t.Fatal(k)
	}
}
