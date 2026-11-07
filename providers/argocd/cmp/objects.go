package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/jfillman/clearance/internal/gate/render"
)

// Annotations the plugin stamps on every object it emits (docs/gate.md, Phase 2 design pass, (b)).
const (
	AnnRendered = "clearance.hangar.io/rendered" // the object's hash in the manifest-tree digest (bare hex)
	AnnTree     = "clearance.hangar.io/tree"     // the tree root (bare hex)
	AnnGrant    = "clearance.hangar.io/grant"    // the clearance id; only on a cleared change's objects
)

// clusterScoped are the kinds that take no namespace. Argo CD asks the cluster's discovery; a plugin cannot, so
// the common kinds are listed, any other kind named Cluster* counts too, and the Application may add more
// (PARAM_CLUSTERSCOPEDKINDS).
var clusterScoped = setOf("Namespace", "Node", "PersistentVolume", "StorageClass", "PriorityClass", "IngressClass",
	"RuntimeClass", "CSIDriver", "CSINode", "VolumeAttachment", "APIService", "CustomResourceDefinition",
	"MutatingWebhookConfiguration", "ValidatingWebhookConfiguration", "ValidatingAdmissionPolicy",
	"ValidatingAdmissionPolicyBinding", "MutatingAdmissionPolicy", "MutatingAdmissionPolicyBinding",
	"CertificateSigningRequest", "GatewayClass", "VolumeSnapshotClass", "VolumeSnapshotContent", "ValidatingPolicy",
	"MutatingPolicy", "GeneratingPolicy", "PolicyException", "ResourceQuotaClass", "TokenReview",
	"SubjectAccessReview", "SelfSubjectAccessReview", "SelfSubjectRulesReview")

func setOf(xs ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func isClusterScoped(kind string, extra []string) bool {
	if clusterScoped[kind] || strings.HasPrefix(kind, "Cluster") {
		return true
	}
	for _, k := range extra {
		if k == kind {
			return true
		}
	}
	return false
}

// Tree is a rendered tree, canonicalised: every object with its namespace set, its hash, and the root.
type Tree struct {
	Root    string
	Set     render.Set
	Hashes  map[render.Key]string
	Emitted []map[string]any // the objects to emit, parsed as Kubernetes parses them, in key order
	Keys    []render.Key     // parallel to Emitted
}

// Canonicalize reads helm's (or kustomize's) output and returns the tree. Hashing follows docs/gate.md (the
// manifest-tree digest): the objects are read the way Glidepath's clearance-gate check reads them (PyYAML
// SafeLoader, internal/gate/render); each gets the destination namespace first, when it is namespaced and has none,
// because Argo CD adds that namespace on apply and the agent must be able to reproduce the stamp. What is emitted
// is a second parse by a YAML 1.2 reader (what Argo CD itself uses), matched to the hashed objects by identity.
func Canonicalize(rendered []byte, destination string, extraCluster []string) (*Tree, error) {
	set := render.Set{}
	if err := render.Add(set, rendered); err != nil {
		return nil, fmt.Errorf("the render is not YAML: %w", err)
	}
	if len(set) == 0 {
		return nil, errors.New("the render holds no objects: nothing to clear")
	}
	if len(set) > render.MaxObjects {
		return nil, fmt.Errorf("the render holds %d objects, more than the gate's %d", len(set), render.MaxObjects)
	}
	withNS := render.Set{}
	for k, d := range set {
		if k[2] == "" && !isClusterScoped(k[1], extraCluster) {
			k[2] = destination
			if md, ok := asMap(d.Value)["metadata"].(map[string]any); ok {
				md["namespace"] = destination
			}
		}
		withNS[k] = d
	}
	if len(withNS) != len(set) {
		return nil, errors.New("two objects of one identity once the destination namespace is set")
	}
	t := &Tree{Root: render.TreeDigest(withNS), Set: withNS, Hashes: map[render.Key]string{}}
	for k, d := range withNS {
		t.Hashes[k] = render.ObjectDigest(d)
	}
	emitted, err := parseEmit(rendered, destination, extraCluster)
	if err != nil {
		return nil, err
	}
	for _, o := range emitted {
		k := keyOf(o)
		if _, ok := t.Hashes[k]; !ok {
			return nil, fmt.Errorf("%s/%s %q reads differently as YAML 1.1 (the hash) and YAML 1.2 (Argo CD): refusing to stamp it", k[0], k[1], k[3])
		}
		t.Emitted, t.Keys = append(t.Emitted, o), append(t.Keys, k)
	}
	if len(t.Emitted) != len(t.Hashes) {
		return nil, fmt.Errorf("the two YAML readers disagree on the object count (%d to hash, %d to emit)", len(t.Hashes), len(t.Emitted))
	}
	return t, nil
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func keyOf(o map[string]any) render.Key {
	md := asMap(o["metadata"])
	s := func(v any) string { str, _ := v.(string); return str }
	return render.Key{s(o["apiVersion"]), s(o["kind"]), s(md["namespace"]), s(md["name"])}
}

// parseEmit reads the stream as Argo CD would, flattens a *List, drops what render.Add drops (no kind, apiVersion
// or name), sets the namespace and returns the objects sorted by identity (a later document of one identity
// replaces an earlier one, as render.Add does).
func parseEmit(data []byte, destination string, extraCluster []string) ([]map[string]any, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	byKey := map[render.Key]map[string]any{}
	add := func(m map[string]any) {
		md := asMap(m["metadata"])
		if m["kind"] == nil || m["apiVersion"] == nil || md == nil || md["name"] == nil || md["name"] == "" {
			return
		}
		if ns, _ := md["namespace"].(string); ns == "" {
			if kind, _ := m["kind"].(string); !isClusterScoped(kind, extraCluster) {
				md["namespace"] = destination
			}
		}
		byKey[keyOf(m)] = m
	}
	for {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("the render is not YAML: %w", err)
		}
		if len(m) == 0 {
			continue
		}
		if kind, _ := m["kind"].(string); strings.HasSuffix(kind, "List") {
			if items, ok := m["items"].([]any); ok {
				for _, it := range items {
					if im, ok := it.(map[string]any); ok {
						add(im)
					}
				}
				continue
			}
		}
		add(m)
	}
	keys := make([]render.Key, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		for x := range keys[i] {
			if keys[i][x] != keys[j][x] {
				return keys[i][x] < keys[j][x]
			}
		}
		return false
	})
	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, byKey[k])
	}
	return out, nil
}

// Stamp annotates every object: its hash and the tree root, and, for a cleared change, the clearance id.
func (t *Tree) Stamp(grant string) {
	for i, o := range t.Emitted {
		md := asMap(o["metadata"])
		ann, _ := md["annotations"].(map[string]any)
		if ann == nil {
			ann = map[string]any{}
			md["annotations"] = ann
		}
		ann[AnnRendered] = t.Hashes[t.Keys[i]]
		ann[AnnTree] = t.Root
		if grant != "" {
			ann[AnnGrant] = grant
		} else {
			delete(ann, AnnGrant)
		}
	}
}

// WriteStream writes objects as a stream of JSON documents (JSON is YAML; Argo CD splits it like any manifest stream).
func WriteStream(w io.Writer, objs []map[string]any) error {
	for _, o := range objs {
		b, err := json.Marshal(o)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "---\n%s\n", b); err != nil {
			return err
		}
	}
	return nil
}
