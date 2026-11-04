// Spike c, cost: the runtime CEL cost of the grant-match validation, measured with the Kubernetes API server's own
// admission CEL compiler and evaluator (k8s.io/apiserver v0.36.3, hangar-dev's minor), the code path a
// ValidatingAdmissionPolicy runs. Cost is the budget consumed: RuntimeCELCostBudget minus what ForInput returns.
//
//	go test -v ./...
//
// Cost units, not wall time, are the measure: the API server enforces the budget in these units.
package celcost

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/cel-go/cel"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"
	plugincel "k8s.io/apiserver/pkg/admission/plugin/cel"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/cel/environment"
)

type expr struct{ name, e string }

func (x expr) GetExpression() string    { return x.e }
func (x expr) ReturnTypes() []*cel.Type { return []*cel.Type{cel.BoolType} }
func (x expr) GetName() string          { return x.name }

type variable struct{ expr }

func (v variable) ReturnTypes() []*cel.Type { return []*cel.Type{cel.AnyType} }

// The policy's variables and validations, as in manifests/30-vap.yaml.
var variables = []plugincel.NamedExpressionAccessor{
	variable{expr{"ann", "has(object.metadata.annotations) ? object.metadata.annotations : {}"}},
	variable{expr{"rendered", "'clearance.hangar.io/rendered' in variables.ann ? variables.ann['clearance.hangar.io/rendered'] : ''"}},
	variable{expr{"key", "(has(object.apiVersion) && object.apiVersion.contains('/') ? object.apiVersion.split('/')[0] : '') + '/' + object.kind + '/' + object.metadata.name"}},
}

var shapes = map[string]string{
	"list-exists": "params.spec.objects.exists(o, (has(o.group) ? o.group : '') + '/' + o.kind + '/' + o.name == variables.key && o.rendered == variables.rendered)",
	"map-index":   "variables.key in params.spec.index && params.spec.index[variables.key] == variables.rendered",
}

const hash = "sha256:279546c87e365c1d0b0c1e7c6d3e2f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e"

func grant(n int, matchAt int) *unstructured.Unstructured {
	objs := []any{}
	index := map[string]any{}
	for i := 0; i < n; i++ {
		name, rendered := fmt.Sprintf("obj-%04d", i), fmt.Sprintf("sha256:%064d", i)
		if i == matchAt {
			name, rendered = "spike-web", hash
		}
		objs = append(objs, map[string]any{"group": "apps", "kind": "Deployment", "name": name, "rendered": rendered, "changed": i%7 == 0})
		index["apps/Deployment/"+name] = rendered
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "spike.clearance.hangar.io/v1", "kind": "ClearanceGrant",
		"metadata": map[string]any{"name": "g", "namespace": "clearance-spike-prot"},
		"spec": map[string]any{
			"subject": map[string]any{"commit": "25216f9", "tree": "sha256:8b19"}, "expiresAt": "2026-11-10T00:00:00Z",
			"objects": objs, "index": index,
		},
	}}
}

func deployment() *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": map[string]any{"name": "spike-web", "namespace": "clearance-spike-prot",
			"annotations": map[string]any{"clearance.hangar.io/rendered": hash, "clearance.hangar.io/grant": "g"}},
		"spec": map[string]any{"replicas": int64(0)},
	}}
}

func cost(t testing.TB, shape string, params *unstructured.Unstructured) (int64, bool) {
	t.Helper()
	compiler, err := plugincel.NewCompositedCompiler(environment.MustBaseEnvSet(environment.DefaultCompatibilityVersion()))
	if err != nil {
		t.Fatal(err)
	}
	opts := plugincel.OptionalVariableDeclarations{HasParams: true}
	compiler.CompileAndStoreVariables(variables, opts, environment.StoredExpressions)
	f := compiler.CompileCondition([]plugincel.ExpressionAccessor{expr{shape, shapes[shape]}}, opts, environment.StoredExpressions)
	obj := deployment()
	gvk := schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"}
	gvr := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	attr := admission.NewAttributesRecord(obj, nil, gvk, "clearance-spike-prot", "spike-web", gvr, "", admission.Create,
		&metav1.CreateOptions{}, false, &user.DefaultInfo{Name: "system:serviceaccount:argocd-apps:argocd-application-controller"})
	va := &admission.VersionedAttributes{Attributes: attr, VersionedObject: obj, VersionedKind: gvk}
	req := plugincel.CreateAdmissionRequest(attr, metav1.GroupVersionResource(gvr), metav1.GroupVersionKind(gvk))
	res, remaining, err := f.ForInput(context.Background(), va, req, plugincel.OptionalVariableBindings{VersionedParams: params}, nil, celconfig.RuntimeCELCostBudget)
	if err != nil {
		t.Fatal(err)
	}
	if res[0].Error != nil {
		t.Fatal(res[0].Error)
	}
	return celconfig.RuntimeCELCostBudget - remaining, res[0].EvalResult.Value() == true
}

func TestGrantMatchCost(t *testing.T) {
	for _, n := range []int{1, 200, 2000} {
		for _, shape := range []string{"list-exists", "map-index"} {
			last, ok := cost(t, shape, grant(n, n-1))
			if !ok {
				t.Fatalf("%s n=%d: the listed object was refused", shape, n)
			}
			miss, ok := cost(t, shape, grant(n, -1))
			if ok {
				t.Fatalf("%s n=%d: an unlisted object was admitted", shape, n)
			}
			t.Logf("grant of %4d objects, %-11s: cost %7d when the object is last, %7d when it is absent (budget %d per binding, %d per expression)",
				n, shape, last, miss, celconfig.RuntimeCELCostBudget, celconfig.PerCallLimit)
		}
	}
}
