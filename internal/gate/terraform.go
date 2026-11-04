package gate

import (
	"fmt"
	"slices"
	"strings"
)

// TypeRule is one category of Terraform resource types the baseline makes tier 3, by fnmatch glob.
type TypeRule struct {
	Category string   `json:"category"`
	Types    []string `json:"types"`
}

// DefaultTerraformTier3 is the baseline's tier-3 resource types (G-TF-1): identity and access, security groups and
// firewalls, network ACLs, keys, and databases, for the AWS, Google Cloud, Azure and Kubernetes providers. A change of
// any kind to one of these is tier 3, a tag included.
func DefaultTerraformTier3() []TypeRule {
	return []TypeRule{
		{"iam", []string{"aws_iam_*", "aws_ssoadmin_*", "aws_organizations_policy*", "aws_lambda_permission",
			"aws_s3_bucket_policy", "aws_sqs_queue_policy", "aws_sns_topic_policy", "aws_ecr_repository_policy",
			"aws_secretsmanager_secret_policy", "google_*_iam_*", "google_service_account*", "google_organization_policy",
			"azurerm_role_assignment", "azurerm_role_definition", "azurerm_user_assigned_identity", "azuread_*",
			"kubernetes_*role*", "kubernetes_service_account*"}},
		{"security-group", []string{"aws_security_group", "aws_security_group_rule", "aws_default_security_group",
			"aws_vpc_security_group_*", "google_compute_firewall*", "azurerm_network_security_group", "azurerm_network_security_rule"}},
		{"network-acl", []string{"aws_network_acl", "aws_network_acl_*", "aws_default_network_acl"}},
		{"kms", []string{"aws_kms_*", "google_kms_*", "azurerm_key_vault*"}},
		{"database", []string{"aws_db_*", "aws_rds_*", "aws_dynamodb_*", "aws_docdb_*", "aws_neptune_*", "aws_redshift_*",
			"aws_elasticache_*", "aws_memorydb_*", "aws_dax_*", "aws_keyspaces_*", "aws_timestreamwrite_*",
			"google_sql_*", "google_spanner_*", "google_bigtable_*", "google_firestore_*", "google_alloydb_*",
			"azurerm_*sql*", "azurerm_cosmosdb_*", "azurerm_redis_*"}},
	}
}

// DefaultTagFields are the attributes a tag-only or description-only update touches (tier 1): the JSON pointer is
// one of these or under one.
var DefaultTagFields = []string{"/tags", "/tags_all", "/labels", "/description"}

// replaceByRequest is Terraform's action_reason for a resource `-replace` named.
const replaceByRequest = "replace_by_request"

func (p Policy) tier3Category(typ string) string {
	for _, r := range p.TFTier3Types {
		if globs(typ, r.Types) {
			return r.Category
		}
	}
	return ""
}

// WorkspaceProtected is whether a workspace is protected: the verifier says so (the request's protected, true unless
// it says false), or clearance.yaml's workspaces.protected names its state key or its name.
func (p Policy) WorkspaceProtected(w Workspace, protected bool) bool {
	return protected || globs(w.Key, p.ProtectedWorkspaces) || globs(w.Name, p.ProtectedWorkspaces)
}

func tagOnly(fields, tags []string) bool {
	if len(fields) == 0 {
		return false
	}
	for _, f := range fields {
		if !slices.ContainsFunc(tags, func(t string) bool { return f == t || strings.HasPrefix(f, t+"/") }) {
			return false
		}
	}
	return true
}

// resourceTier is the Terraform tier table for one resource change (docs/gate.md, The terraform-plan subject):
// destroy or replace in a protected workspace is 3; a tier-3 type is 3 whatever the change; a tag-only or
// description-only update is 1; everything else is 2.
func resourceTier(r Resource, protected bool, pol Policy) Reason {
	act := r.action()
	if (act == "destroy" || act == "replace") && protected {
		return Reason{r.Address, "tf:" + act, 3}
	}
	if cat := pol.tier3Category(r.Type); cat != "" {
		return Reason{r.Address, "tf-type:" + cat, 3}
	}
	if act == "update" && tagOnly(r.Fields, pol.TFTagFields) {
		if globs(r.Type, pol.TFTier2Types) {
			return Reason{r.Address, "tf-type:tier2", 2}
		}
		return Reason{r.Address, "tf:tag-only", 1}
	}
	return Reason{r.Address, "tf:" + act, 2}
}

// setBy names what set the tier: the subjects of the reasons at it, at most five and how many more.
func setBy(reasons []Reason, tier int) string {
	var names []string
	for _, r := range reasons {
		if r.Tier == tier && !slices.Contains(names, r.Subject) {
			names = append(names, r.Subject)
		}
	}
	if len(names) > 5 {
		return strings.Join(names[:5], ", ") + fmt.Sprintf(" and %d more", len(names)-5)
	}
	return strings.Join(names, ", ")
}

// checksPlanOK is what each check must say for policy to clear a tier-1 plan: the clearance-gate checks without
// render (a plan is not rendered; its digest is the subject).
var checksPlanOK = checksOK[:2]

// classifyPlan is Classify for a terraform-plan subject: the path rules, each resource change's tier, a plan that
// changes nothing at tier 1, then -target or -replace one tier up with a floor of 2, then provenance and the checks.
func classifyPlan(req ChangeRequest, pol Policy, reasons []Reason) Classification {
	s := req.Subject
	protected := pol.WorkspaceProtected(*s.Workspace, req.Protected)
	changed := 0
	var replaced []string
	for _, r := range s.Resources {
		if !r.Changes() {
			continue
		}
		changed++
		reasons = append(reasons, resourceTier(r, protected, pol))
		if r.ActionReason == replaceByRequest {
			replaced = append(replaced, r.Address)
		}
	}
	tier := maxTier(reasons)
	if changed == 0 {
		reasons = append(reasons, Reason{"the plan", "tf:no-change", 1})
		tier = max(tier, 1)
	}
	if *s.Targeted || len(replaced) > 0 {
		up := min(3, max(2, tier+1))
		if *s.Targeted {
			reasons = append(reasons, Reason{"the plan", "tf:targeted", up})
		}
		for _, a := range replaced {
			reasons = append(reasons, Reason{a, "tf:replace-requested", up})
		}
		tier = up
	}
	if req.ProposerKind == "unknown" {
		reasons = append(reasons, Reason{"the PR", "provenance:unknown", 3})
		return Classification{max(tier, 2), reasons, "deny", strp("DG-PROVENANCE"),
			"the PR looks like an agent's but Clearance has no record of opening it", nil, pol}
	}
	if tier == 1 {
		var missing []string
		for _, c := range checksPlanOK {
			if v, ok := req.Checks[c.name]; !ok || !slices.Contains(c.ok, v) {
				missing = append(missing, c.name)
			}
		}
		if len(missing) > 0 {
			reasons = append(reasons, Reason{"the checks", "checks:" + strings.Join(missing, ","), 2})
			tier = 2
		}
	}
	where := s.Workspace.Ref()
	if protected {
		where += ", protected"
	}
	if tier <= 1 {
		return Classification{tier, reasons, "clear", nil,
			fmt.Sprintf("tier %d: cleared by policy (%s; set by %s)", tier, where, setBy(reasons, tier)), nil, pol}
	}
	c := holdFor(req, pol, tier, reasons)
	c.Why += fmt.Sprintf(" (%s; set by %s)", where, setBy(reasons, tier))
	return c
}
