package main

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The F8 rule (settings.go): no sidecar setting is required without a safe default, or a preflight refusal that names it.

// baseEnv is a valid run with every setting unset except the RulePreflight ones.
func baseEnv() map[string]string {
	return map[string]string{"ARGOCD_APP_NAME": "gate-api-prod", "ARGOCD_APP_NAMESPACE": "app-gate-api-prod", "ARGOCD_APP_REVISION": mergeSHA,
		"ARGOCD_APP_SOURCE_REPO_URL": "https://github.com/jfillman/gitops-gate-api.git", "PARAM_APP": "gate-api", "PARAM_ENV": "prod", "PARAM_CLUSTER": "hangar-prod",
		"PARAM_CHARTREPO": "https://github.com/jfillman/airframe.git", "PARAM_CHARTREVISION": "v0.3.168",
		"CLEARANCE_URL": "http://clearance.test", "CLEARANCE_CHART_REPOS": "https://github.com/jfillman/airframe.git",
		"CLEARANCE_WAIT_IMAGE": "registry.example.test/clearance-wait:v1"}
}

func getter(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func setting(name string) (Setting, bool) {
	for _, s := range Settings {
		if s.Name == name {
			return s, true
		}
	}
	return Setting{}, false
}

// Every CLEARANCE_* name in the plugin's code is a listed setting (or a name the plugin only mentions).
func TestEverySettingInTheCodeIsListed(t *testing.T) {
	notSettings := map[string]bool{
		"CLEARANCE_VERIFIERS":        true, // the core's setting, named in a doctor hint
		"CLEARANCE_CMP_STEP_ID":      true, // a render step's own token, which its descendants carry (proc_linux.go)
		"CLEARANCE_CMP_SANDBOX_SPEC": true, // the plugin's instructions to its own sandbox shim (fssandbox.go), never set by anyone
	}
	files, _ := filepath.Glob("*.go")
	rx := regexp.MustCompile(`"(CLEARANCE_[A-Z0-9_]+)"`)
	seen := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range rx.FindAllStringSubmatch(string(b), -1) {
			seen[m[1]] = true
			if _, ok := setting(m[1]); !ok && !notSettings[m[1]] {
				t.Errorf("%s (%s) is read but not in Settings: give it a safe default or a preflight refusal, and list it", m[1], f)
			}
		}
	}
	if len(seen) < 10 {
		t.Fatalf("found only %d names: the scan is broken", len(seen))
	}
	names := map[string]bool{}
	for _, s := range Settings {
		if names[s.Name] {
			t.Errorf("%s listed twice", s.Name)
		}
		names[s.Name] = true
	}
}

func TestEverySettingHasASafeDefaultOrAPreflightRefusal(t *testing.T) {
	base := baseEnv()
	unset, err := ParseConfig(getter(base))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range Settings {
		t.Run(s.Name, func(t *testing.T) {
			switch s.Rule {
			case RuleDefault:
				if s.Default == "" {
					t.Fatal("a default rule with no default")
				}
				m := baseEnv()
				m[s.Name] = s.Default
				set, err := ParseConfig(getter(m))
				if err != nil || !reflect.DeepEqual(set, unset) {
					t.Fatalf("%s=%s is not the same as unset (%v): the documented default is not the real one", s.Name, s.Default, err)
				}
			case RuleOptional:
				if s.Default != "" {
					t.Fatal("an optional setting has no default")
				}
				// Unset in baseEnv already; it parses.
			case RulePreflight:
				m := baseEnv()
				delete(m, s.Name)
				f := newDoctorFixture(t)
				delete(f.env, s.Name)
				checks, _, _ := f.run(t)
				named := false
				for _, c := range checks {
					if (c.Level == levelFail || c.Level == levelWarn) && strings.Contains(c.Msg+" "+c.Fix, s.Name) {
						named = true
					}
				}
				if !named {
					t.Fatalf("doctor does not name %s when it is unset", s.Name)
				}
			default:
				t.Fatalf("rule %q", s.Rule)
			}
		})
	}
}

// The settings with no safe default are pinned. Adding one breaks every sidecar upgraded without it (0.52.0): give it a
// default instead; if there truly is none, change this list on purpose and say so in the release's upgrade notes.
func TestNoNewRequiredSetting(t *testing.T) {
	var got []string
	for _, s := range Settings {
		if s.Rule == RulePreflight {
			got = append(got, s.Name)
		}
	}
	sort.Strings(got)
	want := []string{"CLEARANCE_CHART_REPOS", "CLEARANCE_URL", "CLEARANCE_WAIT_IMAGE"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("settings with no safe default %v, want %v", got, want)
	}
	// And the new hardening settings are safe when unset: last-known-good off, links to the core's record.
	if s, _ := setting(LKGEnv); s.Rule != RuleDefault || s.Default != "off" {
		t.Fatalf("%+v", s)
	}
}

// Every setting has a row in the install guide's "Every setting" table, with its default.
func TestEverySettingIsDocumented(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "install-argocd-plugin.md"))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	for _, s := range Settings {
		row := regexp.MustCompile("(?m)^\\| `" + regexp.QuoteMeta(s.Name) + "` \\|(.*)$").FindStringSubmatch(doc)
		if row == nil {
			t.Errorf("%s has no row in the guide's settings table", s.Name)
			continue
		}
		want := s.Doc
		if want == "" {
			want = s.Default
		}
		if want != "" && !strings.Contains(row[1], want) {
			t.Errorf("%s: the guide's row does not give the default %s", s.Name, want)
		}
	}
}
