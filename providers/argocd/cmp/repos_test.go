package main

import (
	"strings"
	"testing"
)

const allowedAirframe = "https://github.com/jfillman/airframe.git"

// Whatever the spelling, the same repository gets the same key; anything that is not a remote repository is an error.
func TestNormalizeRepo(t *testing.T) {
	same := []string{
		"https://github.com/jfillman/airframe.git", "https://github.com/jfillman/airframe", "https://github.com/jfillman/airframe/",
		"HTTPS://GitHub.com/jfillman/airframe.git", "https://github.com:443/jfillman/airframe.git", "https://user:pw@github.com/jfillman/airframe.git",
		"  https://github.com/jfillman/airframe.git\n",
	}
	want, err := NormalizeRepo(allowedAirframe, false)
	if err != nil || want != "https://github.com/jfillman/airframe" {
		t.Fatal(want, err)
	}
	for _, s := range same {
		if got, err := NormalizeRepo(s, false); err != nil || got != want {
			t.Errorf("%q: %q, %v", s, got, err)
		}
	}
	if a, _ := NormalizeRepo("git@github.com:jfillman/airframe.git", false); a != "ssh://github.com/jfillman/airframe" {
		t.Errorf("scp-like: %q", a)
	}
	if b, _ := NormalizeRepo("ssh://git@github.com:22/jfillman/airframe", false); b != "ssh://github.com/jfillman/airframe" {
		t.Errorf("ssh: %q", b)
	}
	if o, err := NormalizeRepo("GHCR.io/Org/charts/", true); err != nil || o != "oci://ghcr.io/Org/charts" {
		t.Errorf("oci: %q, %v", o, err)
	}
	// different repositories keep different keys: another scheme, port, owner, name or case in the path
	for _, s := range []string{"http://github.com/jfillman/airframe.git", "https://github.com:8443/jfillman/airframe.git", "https://github.com/evil/airframe.git",
		"https://github.com/jfillman/airframe-evil.git", "https://github.com/jfillman/Airframe.git", "https://github.com/jfillman/airframe.git.evil/x", "ssh://github.com/jfillman/airframe"} {
		if got, err := NormalizeRepo(s, false); err != nil || got == want {
			t.Errorf("%q must not equal the allowed repository: %q, %v", s, got, err)
		}
	}
	for _, s := range []string{"", "-oProxyCommand=x", "--upload-pack=x", "/etc", "../x", "file:///etc", "ext::sh -c id", "ftp://h/o/r", "https://github.com", "https://github.com/",
		"https://github.com/jfillman/../evil/airframe.git", "https://github.com/jfillman//airframe", "https://github.com/jfillman/./airframe", "https://github.com/o/r?x=1", "https://github.com/o/r#f",
		"ghcr.io/org/charts", "https://github.com/o/r\\x"} {
		if got, err := NormalizeRepo(s, false); err == nil {
			t.Errorf("%q accepted as %q", s, got)
		}
	}
	if _, err := NormalizeRepo("https://u:secret@github.com/o/..", false); err == nil || strings.Contains(err.Error(), "secret") {
		t.Errorf("a refusal does not print a credential: %v", err)
	}
}

func TestParseRepoList(t *testing.T) {
	got := ParseRepoList(" https://a.test/x.git,https://b.test/y.git\n\thttps://c.test/z ,, ")
	if len(got) != 3 || got[2] != "https://c.test/z" || len(ParseRepoList("")) != 0 || len(ParseRepoList(" , ")) != 0 {
		t.Fatalf("%q", got)
	}
}

func refuses(t *testing.T, cfg Config, want ...string) {
	t.Helper()
	err := cfg.CheckRepos()
	if err == nil {
		t.Fatal("accepted")
	}
	for _, w := range want {
		if !strings.Contains(err.Error(), w) {
			t.Fatalf("%q lacks %q", err, w)
		}
	}
}

func TestAllowedChartRepoIsAccepted(t *testing.T) {
	c := gateAPIConfig()
	for _, spelling := range []string{"https://github.com/jfillman/airframe", "https://GITHUB.com/jfillman/airframe.git/", "git@github.com:jfillman/airframe.git"} {
		c.ChartRepo = spelling
		c.AllowedRepos = []string{"https://github.com/jfillman/airframe.git", "git@github.com:jfillman/airframe.git"}
		if err := c.CheckRepos(); err != nil {
			t.Errorf("%s: %v", spelling, err)
		}
	}
	c.ChartRepo = "" // the chart is in the gitops repository: nothing is fetched, nothing is checked
	c.AllowedRepos = nil
	if err := c.CheckRepos(); err != nil {
		t.Fatal(err)
	}
}

func TestAChartRepoTheAppProjectWouldNotAllowIsRefused(t *testing.T) {
	for _, repo := range []string{"https://github.com/evil/airframe.git", "http://github.com/jfillman/airframe.git", "file:///etc", "/var/run/secrets", "ext::sh -c id",
		"https://github.com/jfillman/airframe.git/../../evil/x.git", "ghcr.io/jfillman/charts" /* an OCI registry: the plugin fetches git charts only */} {
		c := gateAPIConfig()
		c.ChartRepo = repo
		refuses(t, c, "refused:")
	}
	c := gateAPIConfig()
	c.ChartRepo = "https://github.com/evil/airframe.git"
	refuses(t, c, "chart repository https://github.com/evil/airframe.git is not one of the repositories this cluster's platform allows", "CLEARANCE_CHART_REPOS")
}

// An unset or empty list refuses every fetch: there is no wildcard and no default, because "any repository" is the gap.
func TestNoListFailsClosedAndThereIsNoWildcard(t *testing.T) {
	c := gateAPIConfig()
	c.AllowedRepos = nil
	refuses(t, c, "CLEARANCE_CHART_REPOS is not set on the plugin sidecar", "no chart repository may be fetched")
	c.AllowedRepos = ParseRepoList("  ")
	refuses(t, c, "CLEARANCE_CHART_REPOS is not set")
	c.AllowedRepos = ParseRepoList("*")
	c.ChartRepo = "https://github.com/evil/x.git"
	refuses(t, c, "CLEARANCE_CHART_REPOS entry")
	if _, err := ParseConfig(func(k string) string {
		return map[string]string{"ARGOCD_APP_NAME": "a-dev", "ARGOCD_APP_NAMESPACE": "ns", "PARAM_APP": "a", "PARAM_ENV": "dev", "PARAM_CLUSTER": "c", "CLEARANCE_URL": "http://clearance.test",
			"CLEARANCE_CHART_REPOS": "*"}[k]
	}); err == nil || !strings.Contains(err.Error(), "CLEARANCE_CHART_REPOS") {
		t.Fatalf("a wildcard entry is a configuration error: %v", err)
	}
}

// The refusal comes before any fetch: nothing is cloned, nothing is registered with the core.
func TestARefusedRepoIsNeverCloned(t *testing.T) {
	e := newEnv(t)
	e.cfg.ChartRepo = "https://github.com/evil/airframe.git"
	o, objs, err := e.generate(t)
	if err == nil || o != "" || len(objs) != 0 || len(e.exec.calls) != 0 || len(e.core.reqs) != 0 {
		t.Fatalf("%q %v %v: %d calls, %d registrations", o, objs, err, len(e.exec.calls), len(e.core.reqs))
	}
	if !strings.Contains(err.Error(), "not one of the repositories this cluster's platform allows") {
		t.Fatal(err)
	}
}

// The list is read from the sidecar's environment only: no PARAM_ value sets it.
func TestTheListCannotBeSetByAParameter(t *testing.T) {
	get := func(k string) string {
		return map[string]string{"ARGOCD_APP_NAME": "a-dev", "ARGOCD_APP_NAMESPACE": "ns", "PARAM_APP": "a", "PARAM_ENV": "dev", "PARAM_CLUSTER": "c", "CLEARANCE_URL": "http://clearance.test",
			"PARAM_CHARTREPO": "https://github.com/evil/x.git", "PARAM_CHARTREVISION": "v1", "PARAM_CHARTPATH": "c",
			"PARAM_CLEARANCE_CHART_REPOS": "https://github.com/evil/x.git", "PARAM_ALLOWEDREPOS": "https://github.com/evil/x.git", "PARAM_CHARTREPOS": "https://github.com/evil/x.git"}[k]
	}
	c, err := ParseConfig(get)
	if err != nil || len(c.AllowedRepos) != 0 {
		t.Fatal(c.AllowedRepos, err)
	}
	refuses(t, c, "CLEARANCE_CHART_REPOS is not set")
}

func TestChartPathMustStayInsideTheChartRepository(t *testing.T) {
	for _, p := range []string{"..", "../x", "charts/../../x", "charts/../x", "/etc", "/", "charts/..", "a\x00b"} {
		c := gateAPIConfig()
		c.ChartPath = p
		if err := c.validate(); err == nil || !strings.Contains(err.Error(), "must be relative and stay inside its repository") {
			t.Errorf("%q: %v", p, err)
		}
	}
	for _, p := range []string{"charts/airframe-application", "charts/a.b/c", "..charts/x", "."} {
		c := gateAPIConfig()
		c.ChartPath = p
		if err := c.validate(); err != nil && strings.Contains(err.Error(), "stay inside") {
			t.Errorf("%q: %v", p, err)
		}
	}
}

// The generic mode fetches the Application's original sources itself, so each one meets the same list: a git repository,
// a Helm repository and an OCI registry (written with no scheme in the source, oci:// in the list).
func TestGenericSourcesMeetTheSameList(t *testing.T) {
	c := genericConfig(t)
	if err := c.CheckRepos(); err != nil { // airframe from the list, the gitops repository because it is the Application's own source
		t.Fatal(err)
	}
	c.Sources = `[{"repoURL":"https://github.com/evil/x.git","path":"."}]`
	refuses(t, c, "source 1 repository https://github.com/evil/x.git is not one of the repositories")
	c.Sources = `[{"repoURL":"https://charts.example.test/stable","chart":"nginx","targetRevision":"1.2.3"}]`
	refuses(t, c, "not one of the repositories")
	c.AllowedRepos = append(c.AllowedRepos, "https://charts.example.test/stable/")
	if err := c.CheckRepos(); err != nil {
		t.Fatal(err)
	}
	c.Sources = `[{"repoURL":"ghcr.io/org/charts","chart":"app","targetRevision":"1.2.3"}]`
	refuses(t, c, "not one of the repositories")
	c.AllowedRepos = append(c.AllowedRepos, "oci://ghcr.io/org/charts")
	if err := c.CheckRepos(); err != nil {
		t.Fatal(err)
	}
	c.Sources = `[{"repoURL":"https://github.com/jfillman/airframe.git","path":"."},{"repoURL":"https://github.com/evil/x.git","ref":"x"}]`
	refuses(t, c, "source 2 repository")
	c.AllowedRepos = nil
	c.Sources = `[{"repoURL":"https://github.com/jfillman/airframe.git","path":"."}]`
	refuses(t, c, "CLEARANCE_CHART_REPOS is not set")
}
