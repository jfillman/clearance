package main

// Every sidecar setting the plugin reads, and what it does when unset (hardening F8). The rule: **no setting is
// required without a safe default, or a preflight refusal that names it.** 0.52.0 broke this: it added
// CLEARANCE_CHART_REPOS as required, so a sidecar upgraded without it refused every chart.
//
// settings_test.go enforces the rule from this table: every CLEARANCE_* name in the plugin's code is listed here and in
// the install guide's "Every setting" table; a RuleDefault setting set to its Default parses exactly as unset (so the
// documented default is the real one); a RuleOptional setting unset still parses; a RulePreflight setting unset makes
// `clearance-cmp doctor` report it by name. The set of RulePreflight settings is pinned by the test: a new one needs the
// test changed, on purpose, with the reason in the release notes.

// SettingRule is what a setting does when it is not set.
type SettingRule string

const (
	RuleDefault   SettingRule = "default"   // unset is Default, which is safe
	RuleOptional  SettingRule = "optional"  // unset turns its feature off, which is safe
	RulePreflight SettingRule = "preflight" // no safe default: doctor names it when unset, and so does the refusal that follows
)

// Setting is one sidecar setting.
type Setting struct {
	Name    string
	Rule    SettingRule
	Default string // RuleDefault: a value ParseConfig accepts that is the same as unset
	Doc     string // what the install guide's Default column says (Default when empty)
}

// Settings is every sidecar setting.
var Settings = []Setting{
	{Name: "CLEARANCE_URL", Rule: RulePreflight},
	{Name: "CLEARANCE_CHART_REPOS", Rule: RulePreflight},
	{Name: "CLEARANCE_WAIT_IMAGE", Rule: RulePreflight},
	{Name: "CLEARANCE_TOKEN_FILE", Rule: RuleDefault, Default: "/var/run/secrets/tokens/clearance"},
	{Name: "CLEARANCE_CA_FILE", Rule: RuleOptional},
	{Name: "CLEARANCE_WAIT_HOST_ALIAS", Rule: RuleOptional},
	{Name: "CLEARANCE_WAIT_CA_CONFIGMAP", Rule: RuleOptional},
	{Name: "CLEARANCE_WAIT_TIMEOUT", Rule: RuleDefault, Default: "24h"},
	{Name: "CLEARANCE_CMP_CACHE_DIR", Rule: RuleDefault, Default: "/tmp/clearance-cmp-cache"},
	{Name: "CLEARANCE_CMP_CACHE_TTL", Rule: RuleDefault, Default: "2m"},
	{Name: "CLEARANCE_CMP_RENDER_CACHE_TTL", Rule: RuleDefault, Default: "15m"},
	{Name: "CLEARANCE_CMP_CHART_CACHE_MAX_BYTES", Rule: RuleDefault, Default: "536870912", Doc: "536870912"},
	{Name: "CLEARANCE_CMP_CHART_CACHE_MAX_ENTRIES", Rule: RuleDefault, Default: "32"},
	{Name: "CLEARANCE_CMP_CALL_TIMEOUT", Rule: RuleDefault, Default: "20s"},
	{Name: NetnsEnv, Rule: RuleDefault, Default: "try"},
	{Name: LKGEnv, Rule: RuleDefault, Default: "off"},
	{Name: FSSandboxEnv, Rule: RuleDefault, Default: "try"},
	{Name: EnvRenderTimeout, Rule: RuleDefault, Default: "30s"},
	{Name: EnvMaxCPU, Rule: RuleDefault, Default: "30s"},
	{Name: EnvMaxMemory, Rule: RuleDefault, Default: "512Mi"},
	{Name: EnvMaxOutput, Rule: RuleDefault, Default: "32Mi"},
	{Name: EnvMaxTemp, Rule: RuleDefault, Default: "512Mi"},
	{Name: EnvMaxRenders, Rule: RuleDefault, Default: "4"},
	{Name: "CLEARANCE_CMP_LINK_BASE", Rule: RuleOptional},
	{Name: MetricsDirEnv, Rule: RuleOptional},
	{Name: MetricsAddrEnv, Rule: RuleOptional},
}
