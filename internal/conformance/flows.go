package conformance

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/gate/render"
	"github.com/jfillman/clearance/internal/pycompat"
)

// Flows a deployment provider can declare in Info.Flow. They differ in what the provider registers and what its
// subject digest is; the rules the suite asserts are the same.
const (
	// FlowRegister (the default, "") is a provider that registers the change it is given (ApplyRequest.Change, a
	// manifest-tree change whose treeDigest is the sha256 of Manifest) and applies Manifest.
	FlowRegister = ""
	// FlowTerraformPlan is a Terraform gate: Manifest stands for the saved plan file (the plan digest is its sha256),
	// and Change is the terraform-plan change `clearance hold` would register for it (subject.workspace names the
	// fake workspace; subject.resources says whether the plan changes anything). The change id is the plan's
	// (gate.ChangeRequest.ID), and the outcome goes through POST /v1/clearances/{id}/outcome.
	FlowTerraformPlan = "terraform-plan"
	// FlowPushedTree is an Argo CD gate: the provider renders Manifest, registers the pushed commit's tree itself
	// (pr 0 and the commit in Change.head, as the CMP does), and the tree's digest is render.TreeDigest of it. A tree
	// a pull request's check already cleared (Change.pr > 0, the CI's registration, which the harness makes) is
	// found by its tree rather than registered again. What the fake target receives is the rendered, stamped objects.
	FlowPushedTree = "pushed-tree"
)

// ValidFlow reports whether f is a flow the harness knows.
func ValidFlow(f string) bool {
	return f == FlowRegister || f == FlowTerraformPlan || f == FlowPushedTree
}

// PlanJSON is the fake workspace's `terraform show -json`: a plan that changes nothing (tier 1, cleared by policy when
// the checks pass) or one that updates an instance (tier 2, held for a person). The harness and a Terraform
// provider's adapter use the same function, so the change the harness registers is the one the provider computes.
func PlanJSON(changes bool) []byte {
	rc := []any{}
	if changes {
		rc = append(rc, map[string]any{"address": "aws_instance.web", "mode": "managed", "type": "aws_instance", "name": "web",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"change": map[string]any{"actions": []string{"update"},
				"before": map[string]any{"instance_type": "t3.small"},
				"after":  map[string]any{"instance_type": "t3.medium"}}})
	}
	raw, err := json.Marshal(map[string]any{"format_version": "1.2", "terraform_version": "1.9.8", "resource_changes": rc})
	if err != nil {
		panic(err)
	}
	return raw
}

// TreeDigestOf is the manifest-tree digest of a stream of objects with the provider's own annotations (Info.Stamps)
// removed first: they are added after the digest is taken, so they are not part of it. The fake target of a
// pushed-tree provider uses it to say what it received.
func TreeDigestOf(content string, stamps []string) (string, error) {
	set := render.Set{}
	if err := render.Add(set, []byte(content)); err != nil {
		return "", err
	}
	if len(set) == 0 {
		return "", errors.New("no objects")
	}
	for _, d := range set {
		m, _ := d.Value.(map[string]any)
		md, _ := m["metadata"].(map[string]any)
		ann, ok := md["annotations"].(map[string]any)
		if !ok {
			continue
		}
		for _, k := range stamps {
			delete(ann, k)
		}
		if len(ann) == 0 {
			delete(md, "annotations")
		}
	}
	return render.TreeDigest(set), nil
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// digestFor is the digest the target reports for content in a flow.
func digestFor(flow string, stamps []string) func(string) string {
	if flow != FlowPushedTree {
		return sha256hex
	}
	return func(content string) string {
		d, err := TreeDigestOf(content, stamps)
		if err != nil {
			return "unreadable:" + sha256hex(content)
		}
		return d
	}
}

// parseChange reads a change request body the way the core does (the id of a plan change is the gate's own).
func parseChange(raw []byte) (gate.ChangeRequest, error) {
	v, err := pycompat.Decode(bytes.NewReader(raw))
	if err != nil {
		return gate.ChangeRequest{}, fmt.Errorf("the change is not JSON: %w", err)
	}
	return gate.ParseRequest(v)
}
