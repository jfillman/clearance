// Package argosrc renders an Argo CD Application's sources the way Argo CD's repo-server does (v3.5): Helm from a git
// path, an HTTP repository or an OCI registry, with value files (including multi-source `$ref/` ones), inline values,
// parameters, the release name and namespace; Kustomize; and a plain directory. It exists so the Clearance plugin
// (providers/argocd/cmp) can render, hash and clear what an Application already uses (G-ARGO-10b).
//
// It decides nothing and holds no credential. Anything it cannot reproduce exactly fails closed with an
// *UnsupportedError that names the gap; it never renders something different from Argo CD silently. The behaviour it
// copies is cited at the function that copies it (argo-cd v3.5.0: reposerver/repository, util/helm, util/kustomize).
package argosrc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Source is one entry of an Application's spec.sources (or its spec.source): Argo CD's ApplicationSource, as JSON.
// The plugin's `sources` parameter is a JSON array of exactly these, taken from the Application unchanged.
type Source struct {
	RepoURL        string     `json:"repoURL"`
	Path           string     `json:"path,omitempty"`
	TargetRevision string     `json:"targetRevision,omitempty"`
	Chart          string     `json:"chart,omitempty"`
	Ref            string     `json:"ref,omitempty"`
	Name           string     `json:"name,omitempty"`
	TagPrefix      string     `json:"tagPrefix,omitempty"`
	Helm           *Helm      `json:"helm,omitempty"`
	Kustomize      *Kustomize `json:"kustomize,omitempty"`
	Directory      *Directory `json:"directory,omitempty"`
	Plugin         *Plugin    `json:"plugin,omitempty"`
}

// Plugin is ApplicationSourcePlugin: a source another config management plugin renders. Only its presence matters
// here, because it is refused; its env and parameters are kept as they are.
type Plugin struct {
	Name       string          `json:"name,omitempty"`
	Env        json.RawMessage `json:"env,omitempty"`
	Parameters json.RawMessage `json:"parameters,omitempty"`
}

// Helm is ApplicationSourceHelm.
type Helm struct {
	ValueFiles              []string        `json:"valueFiles,omitempty"`
	Parameters              []HelmParameter `json:"parameters,omitempty"`
	ReleaseName             string          `json:"releaseName,omitempty"`
	Values                  string          `json:"values,omitempty"`
	ValuesObject            json.RawMessage `json:"valuesObject,omitempty"`
	FileParameters          []HelmFileParam `json:"fileParameters,omitempty"`
	Version                 string          `json:"version,omitempty"`
	PassCredentials         bool            `json:"passCredentials,omitempty"`
	IgnoreMissingValueFiles bool            `json:"ignoreMissingValueFiles,omitempty"`
	SkipCrds                bool            `json:"skipCrds,omitempty"`
	SkipTests               bool            `json:"skipTests,omitempty"`
	SkipSchemaValidation    bool            `json:"skipSchemaValidation,omitempty"`
	Namespace               string          `json:"namespace,omitempty"`
	KubeVersion             string          `json:"kubeVersion,omitempty"`
	APIVersions             []string        `json:"apiVersions,omitempty"`
}

// HelmParameter is one `--set` / `--set-string`.
type HelmParameter struct {
	Name        string `json:"name,omitempty"`
	Value       string `json:"value,omitempty"`
	ForceString bool   `json:"forceString,omitempty"`
}

// HelmFileParam is one `--set-file`.
type HelmFileParam struct {
	Name string `json:"name,omitempty"`
	Path string `json:"path,omitempty"`
}

// Kustomize is ApplicationSourceKustomize.
type Kustomize struct {
	NamePrefix                string            `json:"namePrefix,omitempty"`
	NameSuffix                string            `json:"nameSuffix,omitempty"`
	Images                    []string          `json:"images,omitempty"`
	CommonLabels              map[string]string `json:"commonLabels,omitempty"`
	CommonAnnotations         map[string]string `json:"commonAnnotations,omitempty"`
	Version                   string            `json:"version,omitempty"`
	ForceCommonLabels         bool              `json:"forceCommonLabels,omitempty"`
	ForceCommonAnnotations    bool              `json:"forceCommonAnnotations,omitempty"`
	Namespace                 string            `json:"namespace,omitempty"`
	CommonAnnotationsEnvsubst bool              `json:"commonAnnotationsEnvsubst,omitempty"`
	Replicas                  []KustomizeRep    `json:"replicas,omitempty"`
	Patches                   []json.RawMessage `json:"patches,omitempty"`
	Components                []string          `json:"components,omitempty"`
	IgnoreMissingComponents   bool              `json:"ignoreMissingComponents,omitempty"`
	LabelWithoutSelector      bool              `json:"labelWithoutSelector,omitempty"`
	LabelIncludeTemplates     bool              `json:"labelIncludeTemplates,omitempty"`
	KubeVersion               string            `json:"kubeVersion,omitempty"`
	APIVersions               []string          `json:"apiVersions,omitempty"`
}

// KustomizeRep is one replica override; Count is a number or a numeric string.
type KustomizeRep struct {
	Name  string          `json:"name"`
	Count json.RawMessage `json:"count"`
}

// Directory is ApplicationSourceDirectory.
type Directory struct {
	Recurse bool `json:"recurse,omitempty"`
	Jsonnet *struct {
		ExtVars []json.RawMessage `json:"extVars,omitempty"`
		TLAs    []json.RawMessage `json:"tlas,omitempty"`
		Libs    []string          `json:"libs,omitempty"`
	} `json:"jsonnet,omitempty"`
	Exclude string `json:"exclude,omitempty"`
	Include string `json:"include,omitempty"`
}

// UnsupportedError is a source feature the renderer does not reproduce. The plugin refuses the render with it: a
// tree the plugin cannot render exactly as Argo CD would is never cleared.
type UnsupportedError struct {
	Source  int    // 1-based position in the sources list (0: the list as a whole)
	Feature string // the gap, named
	Detail  string
}

func (e *UnsupportedError) Error() string {
	where := "sources"
	if e.Source > 0 {
		where = fmt.Sprintf("source %d", e.Source)
	}
	msg := fmt.Sprintf("unsupported by the Clearance plugin (%s): %s", where, e.Feature)
	if e.Detail != "" {
		msg += ": " + e.Detail
	}
	return msg + "; it is not rendered, because it could not be guaranteed to match Argo CD's own render"
}

func unsupported(i int, feature, detail string) error {
	return &UnsupportedError{Source: i, Feature: feature, Detail: detail}
}

// IsUnsupported is whether err (or one it wraps) is an *UnsupportedError.
func IsUnsupported(err error) bool {
	var u *UnsupportedError
	return errors.As(err, &u)
}

// ParseSources reads the `sources` parameter: a JSON array of Application sources. Unknown fields are an
// unsupported feature, not ignored: a field Argo CD acts on that this code does not know would render differently.
func ParseSources(raw string) ([]Source, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("the sources parameter is empty")
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	dec.DisallowUnknownFields()
	var out []Source
	if err := dec.Decode(&out); err != nil {
		if strings.Contains(err.Error(), "unknown field") {
			return nil, unsupported(0, "an Application source field the plugin does not know", err.Error())
		}
		return nil, fmt.Errorf("the sources parameter is not a JSON array of Application sources: %w", err)
	}
	if dec.More() {
		return nil, errors.New("the sources parameter holds more than one JSON document")
	}
	if len(out) == 0 {
		return nil, errors.New("the sources parameter lists no source")
	}
	return out, nil
}
