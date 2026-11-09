package gate_test

import (
	"slices"
	"testing"

	"github.com/jfillman/clearance/internal/gate"
)

func classesOf(t *testing.T, r map[string]any) []string {
	t.Helper()
	raw, ok := r["operational_class"].([]any)
	if !ok || len(raw) == 0 {
		t.Fatalf("%v carries no operational_class: %v", r["tool"], r["operational_class"])
	}
	var out []string
	for _, x := range raw {
		out = append(out, x.(string))
	}
	return out
}

// The Done-when cases: a seeded Secret rotation, an IAM policy change and a Deployment image bump, plus the shapes
// that carry no operational change, each on the lab shape (an unprotected environment too).
func TestOperationalClassOfTheSeededChanges(t *testing.T) {
	stamp := "/metadata/annotations/argocd.argoproj.io~1tracking-id"
	for _, tc := range []struct {
		name string
		body map[string]any
		want []string
		tier int
	}{
		{"a Secret rotation", change(map[string]any{"objects": objs(obj("Secret", "db-creds", "changed", []string{"/data/password"}, nil, "v1"))}),
			[]string{"credential-exposure"}, 3},
		{"a Deployment image bump", change(map[string]any{"objects": objs(obj("Deployment", "gate-api", "changed",
			[]string{"/spec/template/spec/containers/0/image"}, []string{"ghcr.io/x/y:2"}, "apps/v1"))}), []string{"availability"}, -1},
		{"an Argo Rollout image bump", change(map[string]any{"objects": imageBump}), []string{"availability"}, -1},
		{"a ClusterRoleBinding", change(map[string]any{"objects": objs(obj("ClusterRoleBinding", "admin", "added", nil, nil, "rbac.authorization.k8s.io/v1"))}),
			[]string{"privilege"}, 3},
		{"a StatefulSet with a new claim template", change(map[string]any{"objects": objs(obj("StatefulSet", "db", "changed",
			[]string{"/spec/volumeClaimTemplates/0"}, nil, "apps/v1"))}), []string{"availability", "data-integrity"}, -1},
		{"a NetworkPolicy", change(map[string]any{"objects": objs(obj("NetworkPolicy", "deny", "changed", []string{"/spec"}, nil, "networking.k8s.io/v1"))}),
			[]string{"security-boundary"}, -1},
		{"a Deployment that now reads a Secret", change(map[string]any{"objects": objs(obj("Deployment", "a", "changed",
			[]string{"/spec/template/spec/containers/0/envFrom"}, nil, "apps/v1"))}), []string{"availability", "credential-exposure"}, -1},
		{"an unmapped kind", change(map[string]any{"objects": objs(obj("Widget", "w", "changed", []string{"/spec/x"}, nil, "x.io/v1"))}),
			[]string{"availability"}, -1},
		{"release stamps only", change(map[string]any{"objects": objs(obj("Deployment", "gate-api", "changed", []string{stamp}, nil, "apps/v1"))}),
			[]string{"none"}, 0},
		{"nothing changed but a doc", change(map[string]any{"objects": objs(), "paths": strs([]string{"README.md"})}), []string{"none"}, -1},
		{"an unprotected lab environment", change(map[string]any{"cluster": "hangar-dev", "env": "dev", "objects": objs(obj("Secret", "s", "changed", []string{"/data/k"}, nil, "v1"))}),
			[]string{"credential-exposure"}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newGate(t)
			f.svc.Config.Protected = []string{"hangar-prod/*"}
			c := f.register(t, "ci", tc.body)
			if !slices.Equal(c.OperationalClasses, tc.want) || c.ClassMapping != gate.OperationalClassMapping() {
				t.Fatalf("classes %v mapping %q, want %v", c.OperationalClasses, c.ClassMapping, tc.want)
			}
			if tc.tier >= 0 && c.Tier != tc.tier {
				t.Fatalf("tier %d, want %d (the class never moves it)", c.Tier, tc.tier)
			}
			recs := f.records(t, "")
			if len(recs) == 0 {
				t.Fatal("no records")
			}
			for _, r := range recs {
				if got := classesOf(t, r); !slices.Equal(got, tc.want) || r["class_mapping"] != "opclass/1" {
					t.Fatalf("%v: %v %v", r["tool"], got, r["class_mapping"])
				}
				if !slices.Contains(r["verified"].([]any), any("operational_class")) {
					t.Fatalf("%v: operational_class is not verified: %v", r["tool"], r["verified"])
				}
			}
		})
	}
}

func TestEveryRecordOfAChangeCarriesAClassThroughItsLife(t *testing.T) {
	f := newGate(t)
	out := f.register(t, "ci", change(map[string]any{"objects": objs(obj("Secret", "s", "changed", []string{"/data/k"}, nil, "v1"))}))
	if _, err := f.svc.Clear(f.ctx, principals["erin"], out.ID, ""); err != nil {
		t.Fatal(err)
	}
	for _, r := range f.records(t, "") {
		if got := classesOf(t, r); !slices.Equal(got, []string{"credential-exposure"}) {
			t.Fatalf("%v: %v", r["tool"], got)
		}
	}
}

func TestOperationalClassOfATerraformPlan(t *testing.T) {
	for _, tc := range []struct {
		name    string
		subject map[string]any
		want    []string
	}{
		{"an IAM policy change", plan(nil, res("aws_iam_role_policy.ci", "aws_iam_role_policy", update, "/policy")), []string{"privilege"}},
		{"a security group rule", plan(nil, res("aws_security_group_rule.web", "aws_security_group_rule", update, "/cidr_blocks/0")), []string{"security-boundary"}},
		{"a database", plan(nil, res("aws_db_instance.main", "aws_db_instance", update, "/instance_class")), []string{"data-integrity"}},
		{"a KMS key", plan(nil, res("aws_kms_key.state", "aws_kms_key", create)), []string{"credential-exposure"}},
		{"an instance", plan(nil, res("aws_instance.b", "aws_instance", destroy)), []string{"availability"}},
		{"an unmapped type", plan(nil, res("aws_thing.x", "aws_thing", create)), []string{"availability"}},
		{"IAM and a database", plan(nil, res("aws_iam_role.r", "aws_iam_role", create), res("aws_db_instance.d", "aws_db_instance", create)),
			[]string{"data-integrity", "privilege"}},
		{"a tag on a vpc", plan(nil, res("aws_vpc.lab", "aws_vpc", update, "/tags/Owner")), []string{"none"}},
		{"a no-op", plan(nil, res("aws_vpc.lab", "aws_vpc", noop)), []string{"none"}},
		{"no resources", plan(nil), []string{"none"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newGate(t)
			c := f.register(t, "ci", tfChange(tc.subject, nil))
			if !slices.Equal(c.OperationalClasses, tc.want) {
				t.Fatalf("%v, want %v", c.OperationalClasses, tc.want)
			}
			for _, r := range f.records(t, "") {
				if got := classesOf(t, r); !slices.Equal(got, tc.want) {
					t.Fatalf("%v: %v", r["tool"], got)
				}
			}
		})
	}
}

func TestAnUnregisteredDeploymentHasNoClass(t *testing.T) {
	f := newGate(t)
	res, err := f.svc.DeploymentRequested(f.ctx, "inst", "jfillman/gitops-gate-api", head, "prod", 1, "")
	if err != nil || res.Rule == nil || *res.Rule != "DG-UNREGISTERED" {
		t.Fatalf("%v %+v", err, res)
	}
	recs := f.records(t, "deploy.request")
	if len(recs) != 1 {
		t.Fatal(len(recs))
	}
	if _, ok := recs[0]["operational_class"]; ok {
		t.Fatalf("a record with no change carries a class: %v", recs[0])
	}
}
