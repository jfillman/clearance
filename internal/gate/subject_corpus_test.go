package gate_test

// SDK-1's golden subject corpus (testdata/golden/subjects.jsonl): manifest-tree and terraform-plan registrations, each
// with the tier, decision, reasons, why, requirement, change id, recorded subject and token subjects the core gave
// them before the generic change description existed (recorded at v0.57.3, 713f576). The replay runs every request
// through today's core, which tiers through the description (describe.go), and fails on any difference. The corpus
// is never re-recorded to make a change pass: `go test -run TestSubjectCorpus -record` exists to add cases, and a
// re-record that changes an existing line is a behaviour change to be named in the pull request.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/definitions/deftest"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/pycompat"
)

var recordCorpus = flag.Bool("record", false, "rewrite testdata/golden/subjects.jsonl from the corpus cases")

const corpusPath = "../../testdata/golden/subjects.jsonl"

// corpusBaselines are the deployment policies the corpus runs under: the lab's, and the lab's with release stamps,
// trusted registries and tier-2 Terraform types set.
func corpusBaseline(name string) gate.Policy {
	pol := baseline
	switch name {
	case "stamps":
		pol.ReleaseStamps = []string{"/metadata/labels/app.kubernetes.io~1version", "/spec/template/metadata/labels/app.kubernetes.io~1version",
			"/metadata/annotations/hangar.io~1release-id"}
	case "registries":
		pol.TrustedRegistries = []string{"ghcr.io/jfillman/flight/"}
	case "tf-tier2":
		pol.TFTier2Types = []string{"aws_route53_*"}
	}
	return pol
}

type corpusCase struct {
	Name     string         `json:"name"`
	Baseline string         `json:"baseline"`
	Request  map[string]any `json:"request"`
}

type corpusLine struct {
	corpusCase
	Expect json.RawMessage `json:"expect"`
}

func corpusCases() []corpusCase {
	const label, tmpl, img = "/metadata/labels/app.kubernetes.io~1version", "/spec/template/metadata/labels/app.kubernetes.io~1version", "/spec/template/spec/containers/0/image"
	const rid = "/metadata/annotations/hangar.io~1release-id"
	stamped := func(kind, name, api string, fields ...string) map[string]any {
		return obj(kind, name, "changed", fields, nil, api)
	}
	unprotected := map[string]any{"protected": false}
	replaceReq := res("aws_instance.b", "aws_instance", replace)
	replaceReq["actionReason"] = "replace_by_request"
	clusterScoped := map[string]any{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "name": "reader", "op": "added",
		"fields": []any{}, "images": []any{}, "digest": strings.Repeat("c", 64)}
	noDigest := map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "namespace": "app-gate-api-prod", "name": "cm", "op": "changed",
		"fields": strs([]string{"/data/x"})}
	m := func(name string, over map[string]any) corpusCase { return corpusCase{name, "lab", change(over)} }
	mb := func(name, base string, over map[string]any) corpusCase { return corpusCase{name, base, change(over)} }
	p := func(name string, subject, over map[string]any) corpusCase {
		return corpusCase{name, "lab", tfChange(subject, over)}
	}
	return []corpusCase{
		// manifest-tree
		m("docs only", map[string]any{"paths": strs([]string{"docs/runbook.md", "README.md"})}),
		m("image bump, green", map[string]any{"objects": imageBump}),
		m("image bump, ci pending", map[string]any{"objects": imageBump, "checks": map[string]any{"ci": "pending", "provenance": "not-agent", "render": "ok"}}),
		m("image bump, unattested", map[string]any{"objects": imageBump, "checks": map[string]any{"ci": "pass", "provenance": "unattested", "render": "ok", "admission": "pass"}}),
		mb("image from a trusted registry", "registries", map[string]any{"objects": imageBump}),
		mb("image from outside the trusted registries", "registries", map[string]any{"objects": objs(obj("Rollout", "gate-api", "changed",
			[]string{img}, []string{"docker.io/library/nginx:latest"}, "argoproj.io/v1alpha1"))}),
		m("a big diff", map[string]any{"objects": imageBump, "linesChanged": 401}),
		m("replicas", map[string]any{"objects": replicas}),
		m("a ConfigMap", map[string]any{"objects": objs(obj("ConfigMap", "gate-api-config", "changed", []string{"/data/LOG_LEVEL"}, nil, "v1"))}),
		m("an unknown kind added", map[string]any{"objects": objs(obj("Weird", "x", "added", nil, nil, "x.io/v1"))}),
		m("a Secret label", map[string]any{"objects": objs(obj("Secret", "s", "changed", []string{"/metadata/labels/x"}, nil, "v1"))}),
		m("a ServiceAccount added", map[string]any{"objects": objs(obj("ServiceAccount", "sa", "added", nil, nil, "v1"))}),
		m("a secretKeyRef", map[string]any{"objects": objs(obj("Rollout", "gate-api", "changed", []string{"/spec/template/spec/containers/0/env/3/valueFrom/secretKeyRef/key"}, nil, "argoproj.io/v1alpha1"))}),
		m("clearance.yaml in paths", map[string]any{"paths": strs([]string{"hangar-prod/prod/values.yaml", "clearance.yaml"}), "objects": imageBump}),
		m("metadata only", map[string]any{"objects": objs(obj("Rollout", "gate-api", "changed", []string{"/metadata/annotations/note"}, nil, "argoproj.io/v1alpha1"))}),
		m("a Secret removed", map[string]any{"objects": objs(obj("Secret", "db", "removed", nil, nil, "v1"))}),
		m("unchanged objects beside a bump", map[string]any{"objects": append(append([]any{}, imageBump...),
			obj("Secret", "db", "unchanged", nil, nil, "v1"), obj("Rollout", "other", "unchanged", nil, nil, "argoproj.io/v1alpha1"))}),
		m("a cluster-scoped object", map[string]any{"objects": objs(clusterScoped)}),
		m("an object without a digest", map[string]any{"objects": objs(noDigest)}),
		m("an agent's docs PR", map[string]any{"paths": strs([]string{"docs/x.md"}), "proposerKind": "agent", "proposer": "autopilot-runs/release-proposer", "agent": "release-proposer"}),
		m("an unknown proposer", map[string]any{"objects": imageBump, "proposerKind": "unknown"}),
		m("unvouched commits", map[string]any{"objects": imageBump, "proposerKind": "unknown", "provenanceReason": "unvouched-commits", "unvouchedCommits": strs([]string{base})}),
		m("a placeholder tree", map[string]any{"objects": imageBump, "treeDigest": strings.Repeat("0", 64)}),
		m("a tighter clearance.yaml", map[string]any{"objects": objs(obj("ConfigMap", "cm", "changed", []string{"/data/x"}, nil, "v1")),
			"policy": map[string]any{"tiers": map[string]any{"3": map[string]any{"kinds": strs([]string{"ConfigMap"})}}, "ttlDays": 2}}),
		m("a pushed commit", map[string]any{"objects": imageBump, "pr": 0}),
		mb("a release with stamps", "stamps", map[string]any{"objects": objs(stamped("Rollout", "a", "argoproj.io/v1alpha1", rid, label, tmpl, img),
			stamped("ServiceAccount", "a", "v1", label), stamped("Service", "a", "v1", label))}),
		mb("a stamp in a pod template alone", "stamps", map[string]any{"objects": objs(stamped("Rollout", "a", "argoproj.io/v1alpha1", tmpl))}),
		mb("a stamp on a ServiceAccount being added", "stamps", map[string]any{"objects": objs(obj("ServiceAccount", "a", "added", []string{label}, nil, "v1"))}),
		// terraform-plan
		p("destroy, protected", plan(nil, res("aws_instance.bastion", "aws_instance", destroy)), nil),
		p("replace, protected", plan(nil, res("aws_instance.bastion", "aws_instance", replace)), nil),
		p("destroy, unprotected", plan(nil, res("aws_instance.bastion", "aws_instance", destroy)), unprotected),
		p("create-before-destroy, unprotected", plan(nil, res("aws_instance.b", "aws_instance", []string{"create", "delete"})), unprotected),
		p("an IAM role", plan(nil, res("aws_iam_role.ci", "aws_iam_role", create)), unprotected),
		p("a tag on an IAM role", plan(nil, res("aws_iam_role.ci", "aws_iam_role", update, "/tags/Owner")), nil),
		p("a security group rule in a module", plan(nil, res(`module.net.aws_security_group_rule.web["443"]`, "aws_security_group_rule", update, "/cidr_blocks/0")), nil),
		p("a network ACL", plan(nil, res("aws_network_acl.private", "aws_network_acl", update, "/ingress")), nil),
		p("a KMS key", plan(nil, res("aws_kms_key.state", "aws_kms_key", create)), nil),
		p("a database", plan(nil, res("aws_db_instance.main", "aws_db_instance", update, "/instance_class")), nil),
		p("tag-only", plan(nil, res("aws_vpc.lab", "aws_vpc", update, "/tags/Owner", "/tags_all/Owner")), nil),
		p("description-only", plan(nil, res("aws_ec2_managed_prefix_list.office", "aws_ec2_managed_prefix_list", update, "/description")), nil),
		{"tag-only on a tier-2 type", "tf-tier2", tfChange(plan(nil, res("aws_route53_record.www", "aws_route53_record", update, "/tags/Owner")), nil)},
		p("an update beyond tags", plan(nil, res("aws_vpc.lab", "aws_vpc", update, "/tags/Owner", "/enable_dns_hostnames")), nil),
		p("a create", plan(nil, res("aws_subnet.c", "aws_subnet", create)), nil),
		p("an update naming no fields", plan(nil, res("aws_vpc.lab", "aws_vpc", update)), nil),
		p("a no-op plan", plan(nil, res("aws_vpc.lab", "aws_vpc", noop), res("data.aws_ami.x", "aws_ami", []string{"read"})), nil),
		p("an empty plan", plan(nil), nil),
		p("-target on tag-only", plan(map[string]any{"targeted": true}, res("aws_vpc.lab", "aws_vpc", update, "/tags/Owner")), nil),
		p("-target on a create", plan(map[string]any{"targeted": true}, res("aws_subnet.c", "aws_subnet", create)), nil),
		p("-target on an empty plan", plan(map[string]any{"targeted": true}), nil),
		p("-replace, unprotected", plan(nil, replaceReq), unprotected),
		p("tag-only, ci failing", plan(nil, res("aws_vpc.lab", "aws_vpc", update, "/tags/Owner")), map[string]any{"checks": map[string]any{"ci": "fail", "provenance": "not-agent"}}),
		p("clearance.yaml in an infra repo", plan(nil, res("aws_vpc.lab", "aws_vpc", update, "/tags/Owner")), map[string]any{"paths": strs([]string{"clearance.yaml"})}),
		p("a mixed plan", plan(nil, res("aws_vpc.lab", "aws_vpc", update, "/tags/Owner"), res("aws_subnet.c", "aws_subnet", create),
			res("aws_instance.old", "aws_instance", destroy), res("aws_instance.r", "aws_instance", replace), res("aws_vpc.same", "aws_vpc", noop)), unprotected),
		p("a protected workspace by clearance.yaml", plan(nil, res("aws_instance.bastion", "aws_instance", destroy)),
			map[string]any{"protected": false, "policy": map[string]any{"workspaces": map[string]any{"protected": strs([]string{"network/*"})}}}),
		p("a plan with a cluster", plan(nil, res("aws_vpc.lab", "aws_vpc", update, "/tags/Owner")), map[string]any{"cluster": "hangar-prod", "treeDigest": planDigest}),
		p("an unknown proposer's plan", plan(nil, res("aws_vpc.lab", "aws_vpc", update, "/tags/Owner")), map[string]any{"proposerKind": "unknown"}),
	}
}

// corpusExpect is what the core makes of a case: the classification, and the change Open records from it.
func corpusExpect(t *testing.T, cc corpusCase) json.RawMessage {
	t.Helper()
	req, err := gate.ParseRequest(cc.Request)
	if err != nil {
		t.Fatalf("%s: %v", cc.Name, err)
	}
	cl, err := gate.Classify(req, corpusBaseline(cc.Baseline), deftest.Tools(), nil)
	if err != nil {
		t.Fatalf("%s: %v", cc.Name, err)
	}
	ch := gate.Open(req, cl, T0, "app-gate-api-cicd/pipeline-runner")
	claims := (&gate.Tokens{}).Claims(ch, "n", T0, T0.Add(time.Minute))
	out := map[string]any{"tier": cl.Tier, "decision": cl.Decision, "rule": cl.Rule, "why": cl.Why, "reasons": cl.Reasons,
		"requirement": cl.Requirement, "id": ch.ID, "treeDigest": ch.TreeDigest, "subject": ch.Subject, "expiresAt": ch.ExpiresAt,
		"operationalClass": ch.OperationalClasses, "tokenSubjects": claims.Subjects}
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSubjectCorpus(t *testing.T) {
	if *recordCorpus {
		var buf bytes.Buffer
		for _, cc := range corpusCases() {
			line, err := json.Marshal(corpusLine{cc, corpusExpect(t, cc)})
			if err != nil {
				t.Fatal(err)
			}
			buf.Write(line)
			buf.WriteByte('\n')
		}
		if err := os.WriteFile(corpusPath, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	f, err := os.Open(corpusPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	n, kinds := 0, map[string]int{}
	for sc.Scan() {
		var line corpusLine
		v, err := pycompat.Decode(bytes.NewReader(sc.Bytes()))
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(v)
		if err := json.Unmarshal(raw, &line); err != nil {
			t.Fatal(err)
		}
		// The request as a decoded body is (numbers as json.Number), as Register sees it.
		line.Request = v.(map[string]any)["request"].(map[string]any)
		got := corpusExpect(t, line.corpusCase)
		if !jsonEqual(t, got, line.Expect) {
			t.Errorf("%s: the core now gives\n%s\nthe corpus recorded\n%s", line.Name, got, line.Expect)
		}
		req, _ := gate.ParseRequest(line.Request)
		kinds[req.Kind()]++
		n++
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if n != len(corpusCases()) || kinds[gate.KindManifestTree] < 20 || kinds[gate.KindTerraformPlan] < 20 {
		t.Fatalf("%d corpus lines (%v), %d cases: the replay would be vacuous or the corpus is stale", n, kinds, len(corpusCases()))
	}
}

func jsonEqual(t *testing.T, a, b []byte) bool {
	t.Helper()
	var x, y any
	if err := json.Unmarshal(a, &x); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &y); err != nil {
		t.Fatal(err)
	}
	xa, _ := json.Marshal(x)
	ya, _ := json.Marshal(y)
	return bytes.Equal(xa, ya)
}
