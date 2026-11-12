package argosrc

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// Env is the build environment Argo CD gives a source (newEnv in reposerver/repository): ARGOCD_APP_* only. Values
// in value file paths, Helm parameters and Kustomize images, labels and annotations are expanded from it; an unknown
// variable expands to the empty string and `$$` is a literal `$` (v1alpha1.Env.Envsubst, which is os.Expand).
type Env map[string]string

// Subst is Env.Envsubst.
func (e Env) Subst(s string) string {
	return os.Expand(s, func(name string) string {
		if name == "$" {
			return "$"
		}
		return e[name]
	})
}

func shorten(rev string, n int) string {
	if len(rev) > n {
		return rev[:n]
	}
	return rev
}

// sourceEnv is the environment of one source: the Application's, plus that source's repository, path, target
// revision and the revision it resolved to.
func sourceEnv(req Request, s Source, revision string) Env {
	return Env{
		"ARGOCD_APP_NAME": req.AppName, "ARGOCD_APP_NAMESPACE": req.Namespace, "ARGOCD_APP_PROJECT_NAME": req.Project,
		"ARGOCD_APP_REVISION": revision, "ARGOCD_APP_REVISION_SHORT": shorten(revision, 7),
		"ARGOCD_APP_REVISION_SHORT_8": shorten(revision, 8), "ARGOCD_APP_SOURCE_REPO_URL": s.RepoURL,
		"ARGOCD_APP_SOURCE_PATH": s.Path, "ARGOCD_APP_SOURCE_TARGET_REVISION": s.TargetRevision,
	}
}

// ReleaseName is the Helm release name Argo CD uses: the Application's name without a namespace prefix
// ("namespace_name", argo.ParseInstanceName), unless helm.releaseName is set.
func ReleaseName(appName string, h *Helm) string {
	name := appName
	if parts := strings.Split(appName, "_"); len(parts) == 2 {
		name = parts[1]
	}
	if h != nil && h.ReleaseName != "" {
		name = h.ReleaseName
	}
	return name
}

var kubeVersionRx = regexp.MustCompile(`^\s*v?([0-9]+(?:\.[0-9]+)+)`)

// ParseKubeVersion is parseKubeVersion in the repo-server (k8s.io/apimachinery version.ParseGeneric(v).String()):
// the numeric components, without a leading "v" or any suffix ("v1.30.2+k3s1" is "1.30.2").
func ParseKubeVersion(v string) (string, error) {
	if v == "" {
		return "", nil
	}
	m := kubeVersionRx.FindStringSubmatch(v)
	if m == nil {
		return "", fmt.Errorf("could not parse kubernetes version %q", v)
	}
	for _, p := range strings.Split(m[1], ".") {
		if _, err := strconv.ParseUint(p, 10, 32); err != nil {
			return "", fmt.Errorf("could not parse kubernetes version %q", v)
		}
	}
	return m[1], nil
}
