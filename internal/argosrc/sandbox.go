package argosrc

import (
	"os"
	"path/filepath"
)

// The render step has no network. Our own code fetches only what the platform allows (the chart and the sources, by
// the allow list's own URL strings: cmp/repos.go); every later `helm template`, `helm dependency build` and
// `kustomize build` reads files already on disk. A Chart.yaml, Chart.lock or kustomization inside an allowed source
// can name any repository, base or registry, and Helm and Kustomize decide what that means with their own parsers, so
// the boundary is not a parser of ours but the environment they run in:
//   - GIT_ALLOW_PROTOCOL=none: git, and kustomize's exec of it, refuse every transport (https, ssh, git, file);
//   - HTTP(S)_PROXY and ALL_PROXY (both cases) set to a closed local port, NO_PROXY empty: Helm's repository, index,
//     package and OCI registry requests, and Kustomize's HTTP resources, all go through Go's or curl-style proxy
//     handling and fail to connect (checked with helm 3 against an HTTP repository and an OCI registry);
//   - HELM_REPOSITORY_CONFIG, HELM_REPOSITORY_CACHE and HELM_REGISTRY_CONFIG point at empty files in a scratch
//     directory, so no stored repository or credential is read.
// What is not covered: a fetch the plugin itself makes is as wide as the listed repository (a Helm index may name a
// package URL on another host; the platform trusts what it lists), and a process that ignores the proxy variables.

// NetworkOffEnv is that environment. scratch is a directory the files above are written in.
func NetworkOffEnv(scratch string) ([]string, error) {
	repos := filepath.Join(scratch, "no-repositories.yaml")
	reg := filepath.Join(scratch, "no-registry.json")
	if err := os.WriteFile(repos, []byte("apiVersion: \"\"\ngenerated: \"0001-01-01T00:00:00Z\"\nrepositories: []\n"), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(reg, []byte("{}\n"), 0o600); err != nil {
		return nil, err
	}
	const dead = "http://127.0.0.1:9" // the discard port: nothing listens, so a proxied request cannot connect
	return []string{
		"GIT_ALLOW_PROTOCOL=none",
		"HTTP_PROXY=" + dead, "HTTPS_PROXY=" + dead, "ALL_PROXY=" + dead,
		"http_proxy=" + dead, "https_proxy=" + dead, "all_proxy=" + dead,
		"NO_PROXY=", "no_proxy=",
		"HELM_REPOSITORY_CONFIG=" + repos,
		"HELM_REPOSITORY_CACHE=" + filepath.Join(scratch, "no-repo-cache"),
		"HELM_REGISTRY_CONFIG=" + reg,
	}, nil
}

// NetworkOffFor is whether a command runs with the network off: helm (except pull, a fetch of ours) and kustomize.
func NetworkOffFor(name string, args []string) bool {
	switch name {
	case "helm":
		return len(args) == 0 || args[0] != "pull"
	case "kustomize":
		return true
	}
	return false // git (our own fetches) and anything else
}

// renderEnv is the environment of a render command: Helm's directories (helm) plus the network-off settings.
func (st *state) renderEnv(helm bool) ([]string, error) {
	off, err := NetworkOffEnv(st.o.Work)
	if err != nil {
		return nil, err
	}
	if helm {
		return append(st.o.helmEnv(), off...), nil
	}
	return off, nil
}
