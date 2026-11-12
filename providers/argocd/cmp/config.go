package main

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"
)

// Config is everything one `generate` run knows: what Argo CD says (ARGOCD_APP_*), the Application's plugin
// parameters (PARAM_*, set by the tenant-onboarding ApplicationSet) and the sidecar's own settings (CLEARANCE_*).
type Config struct {
	// From Argo CD.
	AppName     string   // ARGOCD_APP_NAME: the Helm release name (D26: the release name is the Application)
	Destination string   // ARGOCD_APP_NAMESPACE: the destination namespace, set on every namespaced object
	Revision    string   // ARGOCD_APP_REVISION: the commit Argo syncs (the merge commit, not a PR head)
	SourceRepo  string   // ARGOCD_APP_SOURCE_REPO_URL: the gitops repository (the plugin's own source)
	SourcePath  string   // ARGOCD_APP_SOURCE_PATH
	Project     string   // ARGOCD_APP_PROJECT_NAME
	KubeVersion string   // KUBE_VERSION: the destination cluster's Kubernetes version (set by Argo CD for a plugin)
	APIVersions []string // KUBE_API_VERSIONS: its API versions, comma separated in the environment

	// Plugin parameters.
	App          string   // the Hangar app (the change's `app`)
	Env          string   // the environment
	Cluster      string   // the cluster
	ChartRepo    string   // the chart's repository; empty = the chart is in the source directory itself
	ChartRev     string   // its tag
	ChartPath    string   // the chart's directory in that repository
	ValueFiles   []string // paths in the gitops repository, in order; a missing one is skipped
	ValuesJSON   string   // the platform's injected values (what the ApplicationSet gives a Helm source as valuesObject)
	KustomizeDir string   // an optional kustomize directory rendered beside the chart (the tenant's configmap/)
	ExtraCluster []string // more cluster-scoped kinds

	// Sources is the generic mode (G-ARGO-10b): the Application's original spec.sources as a JSON array, taken
	// unchanged (docs/gate.md, "Rendering any source"). Set, it replaces ChartRepo/ChartRev/ChartPath/ValueFiles/
	// ValuesJSON/KustomizeDir, none of which may then be set.
	Sources               string
	KustomizeBuildOptions string // argocd-cm's kustomize.buildOptions, when the cluster sets any

	// The sidecar.
	CoreURL      string
	TokenFile    string
	CacheDir     string
	CacheTTL     time.Duration
	WaitImage    string
	WaitHost     string // "ip=host1,host2": a hostAlias for the wait Job's pod
	WaitTimeout  time.Duration
	RegisterWait time.Duration // how long one call to the core may take
}

var (
	sha40   = regexp.MustCompile(`^[0-9a-f]{40}$`)
	nameRx  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	revRx   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/+-]{0,200}$`)
	hostRx  = regexp.MustCompile(`^[0-9a-fA-F:.]+=[A-Za-z0-9.,-]+$`)
	imageRx = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,300}$`)
)

// ParseConfig reads the environment (get returns "" for unset).
func ParseConfig(get func(string) string) (Config, error) {
	p := func(name string) string { return strings.TrimSpace(get("PARAM_" + strings.ToUpper(name))) }
	c := Config{
		AppName: get("ARGOCD_APP_NAME"), Destination: get("ARGOCD_APP_NAMESPACE"), Revision: get("ARGOCD_APP_REVISION"),
		SourceRepo: get("ARGOCD_APP_SOURCE_REPO_URL"), SourcePath: get("ARGOCD_APP_SOURCE_PATH"),
		Project: get("ARGOCD_APP_PROJECT_NAME"), KubeVersion: strings.TrimSpace(get("KUBE_VERSION")),
		Sources: strings.TrimSpace(get("PARAM_SOURCES")), KustomizeBuildOptions: p("kustomizeBuildOptions"),
		App: p("app"), Env: p("env"), Cluster: p("cluster"), ChartRepo: p("chartRepo"), ChartRev: p("chartRevision"),
		ChartPath: p("chartPath"), ValuesJSON: p("valuesJson"), KustomizeDir: p("kustomizeDir"),
		CoreURL: get("CLEARANCE_URL"), TokenFile: orDefault(get("CLEARANCE_TOKEN_FILE"), "/var/run/secrets/tokens/clearance"),
		CacheDir:  orDefault(get("CLEARANCE_CMP_CACHE_DIR"), "/tmp/clearance-cmp-cache"),
		WaitImage: get("CLEARANCE_WAIT_IMAGE"), WaitHost: get("CLEARANCE_WAIT_HOST_ALIAS"),
	}
	for _, f := range strings.Split(p("valueFiles"), ",") {
		if f = strings.TrimSpace(f); f != "" {
			c.ValueFiles = append(c.ValueFiles, f)
		}
	}
	for _, k := range strings.Split(p("clusterScopedKinds"), ",") {
		if k = strings.TrimSpace(k); k != "" {
			c.ExtraCluster = append(c.ExtraCluster, k)
		}
	}
	for _, v := range strings.Split(get("KUBE_API_VERSIONS"), ",") {
		if v = strings.TrimSpace(v); v != "" {
			c.APIVersions = append(c.APIVersions, v)
		}
	}
	var err error
	dur := func(name string, def time.Duration) time.Duration {
		v := get(name)
		if v == "" || err != nil {
			return def
		}
		d, e := time.ParseDuration(v)
		if e != nil || d <= 0 {
			err = fmt.Errorf("%s is a positive duration, got %q", name, v)
		}
		return d
	}
	c.CacheTTL = dur("CLEARANCE_CMP_CACHE_TTL", 2*time.Minute)
	c.WaitTimeout = dur("CLEARANCE_WAIT_TIMEOUT", 24*time.Hour)
	c.RegisterWait = dur("CLEARANCE_CMP_CALL_TIMEOUT", 20*time.Second)
	if err != nil {
		return c, err
	}
	return c, c.validate()
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

func (c Config) validate() error {
	var errs []error
	need := func(name, v string) {
		if v == "" {
			errs = append(errs, fmt.Errorf("%s is required", name))
		}
	}
	need("ARGOCD_APP_NAME", c.AppName)
	need("ARGOCD_APP_NAMESPACE", c.Destination)
	need("PARAM_APP", c.App)
	need("PARAM_ENV", c.Env)
	need("PARAM_CLUSTER", c.Cluster)
	need("CLEARANCE_URL", c.CoreURL)
	for k, v := range map[string]string{"PARAM_APP": c.App, "PARAM_ENV": c.Env, "PARAM_CLUSTER": c.Cluster} {
		if v != "" && !nameRx.MatchString(v) {
			errs = append(errs, fmt.Errorf("%s %q is not a DNS-1123 label", k, v))
		}
	}
	if c.Sources != "" {
		for k, v := range map[string]string{"PARAM_CHARTREPO": c.ChartRepo, "PARAM_CHARTREVISION": c.ChartRev, "PARAM_CHARTPATH": c.ChartPath,
			"PARAM_VALUEFILES": strings.Join(c.ValueFiles, ","), "PARAM_VALUESJSON": c.ValuesJSON, "PARAM_KUSTOMIZEDIR": c.KustomizeDir} {
			if v != "" {
				errs = append(errs, fmt.Errorf("%s is set with PARAM_SOURCES: the plugin renders either the Airframe chart parameters or the Application's original sources, not both", k))
			}
		}
	}
	if c.ChartRepo != "" {
		if c.ChartRev == "" {
			errs = append(errs, errors.New("PARAM_CHARTREVISION is required with PARAM_CHARTREPO: a chart is fetched at a pinned tag"))
		}
		if strings.HasPrefix(c.ChartRepo, "-") {
			errs = append(errs, errors.New("PARAM_CHARTREPO must not start with '-'"))
		}
		if c.ChartRev != "" && !revRx.MatchString(c.ChartRev) {
			errs = append(errs, fmt.Errorf("PARAM_CHARTREVISION %q is not a tag name", c.ChartRev))
		}
	}
	for _, f := range append([]string{c.ChartPath, c.KustomizeDir}, c.ValueFiles...) {
		if f != "" && !safeRel(f) {
			errs = append(errs, fmt.Errorf("path %q must be relative and stay inside its repository", f))
		}
	}
	if c.WaitHost != "" && !hostRx.MatchString(c.WaitHost) {
		errs = append(errs, fmt.Errorf("CLEARANCE_WAIT_HOST_ALIAS %q is ip=host[,host]", c.WaitHost))
	}
	if c.WaitImage != "" && !imageRx.MatchString(c.WaitImage) {
		errs = append(errs, fmt.Errorf("CLEARANCE_WAIT_IMAGE %q is not an image reference", c.WaitImage))
	}
	if c.CoreURL != "" {
		if u, err := url.Parse(c.CoreURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			errs = append(errs, fmt.Errorf("CLEARANCE_URL %q is not an http(s) URL", c.CoreURL))
		}
	}
	return errors.Join(errs...)
}

func safeRel(p string) bool {
	if path.IsAbs(p) || strings.ContainsRune(p, 0) {
		return false
	}
	clean := path.Clean(p)
	return clean != ".." && !strings.HasPrefix(clean, "../")
}

// RepoName is "owner/name" of the gitops repository, lowercased, from the Application's source URL
// (https://github.com/o/r.git, git@github.com:o/r.git, ssh://git@host/o/r).
func (c Config) RepoName() (string, error) {
	s := strings.TrimSuffix(strings.TrimSpace(c.SourceRepo), "/")
	s = strings.TrimSuffix(s, ".git")
	var p string
	if u, err := url.Parse(s); err == nil && u.Host != "" {
		p = strings.TrimPrefix(u.Path, "/")
	} else if _, after, ok := strings.Cut(s, ":"); ok {
		p = after
	}
	parts := strings.Split(p, "/")
	if len(parts) < 2 {
		return "", fmt.Errorf("ARGOCD_APP_SOURCE_REPO_URL %q has no owner/name", c.SourceRepo)
	}
	return strings.ToLower(parts[len(parts)-2] + "/" + parts[len(parts)-1]), nil
}
