package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"time"
)

// ErrWatchGone is a watch whose resourceVersion the API server no longer holds (410).
var ErrWatchGone = errors.New("agent: watch resourceVersion is too old")

// Errors of the opt-in writes.
var (
	ErrConflict = errors.New("agent: the object changed since it was read")
	// ErrInvalid: the API server refused a write as invalid (a schema or validation error, not a stale read): retrying
	// the same patch cannot help, so it is reported and not treated as a conflict.
	ErrInvalid  = errors.New("agent: the API server refused the write as invalid")
	ErrNotFound = errors.New("agent: not found")
	// ErrNotOurs: the namespace's protected label was not put there by this agent (it has no marker), so the agent
	// does not remove it.
	ErrNotOurs = errors.New("agent: the namespace's protected label is not the agent's")
)

// The grant CRD's group, version and plural (G-ARGO-2). Configurable because the CRD's version is its.
type GrantAPI struct {
	Group, Version, Plural string
}

// DefaultGrantAPI is clearance.hangar.io/v1 clearancegrants.
var DefaultGrantAPI = GrantAPI{"clearance.hangar.io", "v1", "clearancegrants"}

// API is the REST implementation of Kube over the in-cluster service account.
type API struct {
	Base      string // https://kubernetes.default.svc
	TokenFile string // the service account token, read per request (it rotates)
	Client    *http.Client
	Grants    GrantAPI
	ArgoNS    string // where the Applications are
}

const (
	saDir     = "/var/run/secrets/kubernetes.io/serviceaccount"
	maxKubeBd = 64 << 20
)

// InCluster is an API for the pod's own cluster.
func InCluster(grants GrantAPI, argoNS string) (*API, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, errors.New("agent: not in a cluster (KUBERNETES_SERVICE_HOST is unset)")
	}
	ca, err := os.ReadFile(saDir + "/ca.crt")
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("agent: the service account CA is not PEM")
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	return &API{Base: "https://" + host + ":" + port, TokenFile: saDir + "/token",
		Client: &http.Client{Transport: tr}, Grants: grants, ArgoNS: argoNS}, nil
}

func (a *API) do(ctx context.Context, method, path, contentType string, body []byte, stream bool) (*http.Response, error) {
	tok, err := os.ReadFile(a.TokenFile)
	if err != nil {
		return nil, err
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.Base+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	c := a.Client
	if !stream {
		cc := *c
		cc.Timeout = 30 * time.Second
		c = &cc
	}
	return c.Do(req)
}

// call is one request whose answer is JSON into out (nil: ignored). A non-2xx is *StatusError.
type StatusError struct {
	Code int
	Body string
}

func (e *StatusError) Error() string { return fmt.Sprintf("kubernetes API: %d %s", e.Code, e.Body) }

func (a *API) call(ctx context.Context, method, path, ct string, body any, out any) error {
	var raw []byte
	if body != nil {
		raw = rawJSON(body)
	}
	resp, err := a.do(ctx, method, path, ct, raw, false)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxKubeBd))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return &StatusError{resp.StatusCode, truncate(string(b), 300)}
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

const merge = "application/merge-patch+json"

func (a *API) grantPath(ns, name string) string {
	p := fmt.Sprintf("/apis/%s/%s/", a.Grants.Group, a.Grants.Version)
	if ns == "" {
		return p + a.Grants.Plural
	}
	p += "namespaces/" + url.PathEscape(ns) + "/" + a.Grants.Plural
	if name != "" {
		p += "/" + url.PathEscape(name)
	}
	return p
}

// ProtectedNamespaces implements Kube.
func (a *API) ProtectedNamespaces(ctx context.Context) (map[string]map[string]string, error) {
	var l struct {
		Items []struct {
			Metadata struct {
				Name   string            `json:"name"`
				Labels map[string]string `json:"labels"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if err := a.call(ctx, "GET", "/api/v1/namespaces?labelSelector="+url.QueryEscape(LabelProtected+"=true"), "", nil, &l); err != nil {
		return nil, err
	}
	out := map[string]map[string]string{}
	for _, it := range l.Items {
		out[it.Metadata.Name] = it.Metadata.Labels
	}
	return out, nil
}

type grantWire struct {
	Metadata struct {
		Name      string            `json:"name"`
		Namespace string            `json:"namespace"`
		Labels    map[string]string `json:"labels"`
	} `json:"metadata"`
	Spec   GrantSpec `json:"spec"`
	Status struct {
		Valid     *bool  `json:"valid"`
		CheckedAt string `json:"checkedAt"`
	} `json:"status"`
}

func (w grantWire) grant() Grant {
	return Grant{Namespace: w.Metadata.Namespace, Name: w.Metadata.Name, Labels: w.Metadata.Labels, Spec: w.Spec,
		Valid: w.Status.Valid, CheckedAt: w.Status.CheckedAt}
}

// ListGrants implements Kube.
func (a *API) ListGrants(ctx context.Context) ([]Grant, error) {
	var l struct {
		Items []grantWire `json:"items"`
	}
	if err := a.call(ctx, "GET", a.grantPath("", "")+"?labelSelector="+url.QueryEscape(LabelManagedBy+"="+ManagedBy), "", nil, &l); err != nil {
		return nil, err
	}
	out := make([]Grant, 0, len(l.Items))
	for _, w := range l.Items {
		out = append(out, w.grant())
	}
	return out, nil
}

// CreateGrant implements Kube: a POST for a grant that is absent. On a conflict (something created it since the
// list) it reads the grant, and patches only if spec or labels differ.
func (a *API) CreateGrant(ctx context.Context, g Grant) error {
	meta := map[string]any{"name": g.Name, "namespace": g.Namespace, "labels": g.Labels}
	obj := map[string]any{"apiVersion": a.Grants.Group + "/" + a.Grants.Version, "kind": "ClearanceGrant",
		"metadata": meta, "spec": g.Spec}
	err := a.call(ctx, "POST", a.grantPath(g.Namespace, ""), "application/json", obj, nil)
	var se *StatusError
	if !errors.As(err, &se) || se.Code != http.StatusConflict {
		return err
	}
	var cur grantWire
	if err := a.call(ctx, "GET", a.grantPath(g.Namespace, g.Name), "", nil, &cur); err != nil {
		return err
	}
	have := Grant{Namespace: g.Namespace, Name: g.Name, Labels: cur.Metadata.Labels, Spec: cur.Spec}
	if reflect.DeepEqual(have.Spec, g.Spec) && sameLabels(have.Labels, g.Labels) {
		return nil
	}
	return a.UpdateGrant(ctx, g, have)
}

// UpdateGrant implements Kube: a merge patch of spec and labels. A removed active label must be sent as null, so the
// patch names every label the agent owns; spec.objects keys the new spec lacks are sent as null (a merge patch only
// adds and replaces keys), so the stored map ends up exactly the token's objects.
func (a *API) UpdateGrant(ctx context.Context, g, cur Grant) error {
	labels := map[string]any{LabelActive: nil}
	for k, v := range g.Labels {
		labels[k] = v
	}
	spec := map[string]any{}
	_ = json.Unmarshal(rawJSON(g.Spec), &spec)
	objs, _ := spec["objects"].(map[string]any)
	if objs == nil {
		objs = map[string]any{}
		spec["objects"] = objs
	}
	if len(g.Spec.Carried) == 0 {
		spec["carried"] = nil // a merge patch keeps a list it is not told to clear
	}
	for k := range cur.Spec.Objects {
		if _, ok := g.Spec.Objects[k]; !ok {
			objs[k] = nil
		}
	}
	return a.call(ctx, "PATCH", a.grantPath(g.Namespace, g.Name), merge,
		map[string]any{"metadata": map[string]any{"labels": labels}, "spec": spec}, nil)
}

// SetGrantValid implements Kube.
func (a *API) SetGrantValid(ctx context.Context, ns, name string, valid bool, reason string, at time.Time) error {
	return a.call(ctx, "PATCH", a.grantPath(ns, name)+"/status", merge, map[string]any{"status": map[string]any{
		"valid": valid, "reason": truncate(reason, 250), "checkedAt": at.UTC().Format(time.RFC3339)}}, nil)
}

// DeleteGrant implements Kube.
func (a *API) DeleteGrant(ctx context.Context, ns, name string) error {
	err := a.call(ctx, "DELETE", a.grantPath(ns, name), "", nil, nil)
	var se *StatusError
	if errors.As(err, &se) && se.Code == http.StatusNotFound {
		return nil
	}
	return err
}

type ignoreWire struct {
	Group             string   `json:"group"`
	Kind              string   `json:"kind"`
	Name              string   `json:"name"`
	Namespace         string   `json:"namespace"`
	JSONPointers      []string `json:"jsonPointers"`
	JQPathExpressions []string `json:"jqPathExpressions"`
}

func ignores(in []ignoreWire) []IgnoreDifference {
	var out []IgnoreDifference
	for _, i := range in {
		out = append(out, IgnoreDifference{Group: i.Group, Kind: i.Kind, Name: i.Name, Namespace: i.Namespace,
			JSONPointers: i.JSONPointers, JQPathExpressions: i.JQPathExpressions})
	}
	return out
}

type appWire struct {
	Metadata struct {
		Namespace       string            `json:"namespace"`
		Name            string            `json:"name"`
		Labels          map[string]string `json:"labels"`
		Annotations     map[string]string `json:"annotations"`
		UID             string            `json:"uid"`
		ResourceVersion string            `json:"resourceVersion"`
		OwnerReferences []struct {
			Kind string `json:"kind"`
			Name string `json:"name"`
		} `json:"ownerReferences"`
	} `json:"metadata"`
	Spec struct {
		Project     string `json:"project"`
		Destination struct {
			Namespace string `json:"namespace"`
			Server    string `json:"server"`
			Name      string `json:"name"`
		} `json:"destination"`
		Source            json.RawMessage   `json:"source"`
		Sources           []json.RawMessage `json:"sources"`
		IgnoreDifferences []ignoreWire      `json:"ignoreDifferences"`
		SyncPolicy        struct {
			SyncOptions []string `json:"syncOptions"`
		} `json:"syncPolicy"`
	} `json:"spec"`
	Status struct {
		Sync struct {
			Status    string   `json:"status"`
			Revision  string   `json:"revision"`
			Revisions []string `json:"revisions"`
		} `json:"sync"`
		Health struct {
			Status string `json:"status"`
		} `json:"health"`
		OperationState *struct {
			Phase      string `json:"phase"`
			Message    string `json:"message"`
			StartedAt  string `json:"startedAt"`
			FinishedAt string `json:"finishedAt"`
			SyncResult *struct {
				Revision  string   `json:"revision"`
				Revisions []string `json:"revisions"`
				Resources []struct {
					Group     string `json:"group"`
					Version   string `json:"version"`
					Kind      string `json:"kind"`
					Namespace string `json:"namespace"`
					Name      string `json:"name"`
					Status    string `json:"status"`
					Message   string `json:"message"`
				} `json:"resources"`
			} `json:"syncResult"`
		} `json:"operationState"`
	} `json:"status"`
}

func (w appWire) app() Application {
	a := Application{Namespace: w.Metadata.Namespace, Name: w.Metadata.Name, Labels: w.Metadata.Labels, UID: w.Metadata.UID, Project: w.Spec.Project,
		DestNS: w.Spec.Destination.Namespace, DestServer: w.Spec.Destination.Server, DestName: w.Spec.Destination.Name, SyncState: w.Status.Sync.Status, Health: w.Status.Health.Status,
		Revisions: w.Status.Sync.Revisions}
	if len(a.Revisions) == 0 && w.Status.Sync.Revision != "" {
		a.Revisions = []string{w.Status.Sync.Revision}
	}
	a.Annotations, a.ResourceVersion = w.Metadata.Annotations, w.Metadata.ResourceVersion
	if len(w.Spec.Source) > 0 && string(w.Spec.Source) != "null" {
		a.Source = w.Spec.Source
	}
	a.Sources = w.Spec.Sources
	for _, o := range w.Metadata.OwnerReferences {
		a.Owners = append(a.Owners, OwnerRef{o.Kind, o.Name})
	}
	a.IgnoreDifferences, a.SyncOptions = ignores(w.Spec.IgnoreDifferences), w.Spec.SyncPolicy.SyncOptions
	if s := w.Status.OperationState; s != nil {
		op := &Operation{Phase: s.Phase, Message: s.Message, StartedAt: s.StartedAt, FinishedAt: s.FinishedAt}
		if r := s.SyncResult; r != nil {
			op.Revisions = r.Revisions
			if len(op.Revisions) == 0 && r.Revision != "" {
				op.Revisions = []string{r.Revision}
			}
			for _, x := range r.Resources {
				op.Resources = append(op.Resources, SyncResource{x.Group, x.Version, x.Kind, x.Namespace, x.Name, x.Status, x.Message})
			}
		}
		a.Op = op
	}
	return a
}

func (a *API) appsPath() string {
	return "/apis/argoproj.io/v1alpha1/namespaces/" + url.PathEscape(a.ArgoNS) + "/applications"
}

// ListApplications implements Kube.
func (a *API) ListApplications(ctx context.Context) ([]Application, string, error) {
	var l struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
		Items []appWire `json:"items"`
	}
	if err := a.call(ctx, "GET", a.appsPath(), "", nil, &l); err != nil {
		return nil, "", err
	}
	out := make([]Application, 0, len(l.Items))
	for _, w := range l.Items {
		out = append(out, w.app())
	}
	return out, l.Metadata.ResourceVersion, nil
}

// WatchApplications implements Kube.
func (a *API) WatchApplications(ctx context.Context, rv string, fn func(Application)) error {
	q := "?watch=true&allowWatchBookmarks=true&timeoutSeconds=300&resourceVersion=" + url.QueryEscape(rv)
	resp, err := a.do(ctx, "GET", a.appsPath()+q, "", nil, true)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusGone {
		return ErrWatchGone
	}
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<12))
		return &StatusError{resp.StatusCode, truncate(string(b), 300)}
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		var ev struct {
			Type   string          `json:"type"`
			Object json.RawMessage `json:"object"`
		}
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			return err
		}
		switch ev.Type {
		case "ERROR":
			var st struct {
				Code int `json:"code"`
			}
			_ = json.Unmarshal(ev.Object, &st)
			if st.Code == http.StatusGone {
				return ErrWatchGone
			}
			return fmt.Errorf("agent: watch error %s", truncate(string(ev.Object), 200))
		case "ADDED", "MODIFIED":
			var w appWire
			if err := json.Unmarshal(ev.Object, &w); err != nil {
				return err
			}
			fn(w.app())
		}
	}
	if err := sc.Err(); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}

// ListObjects implements Kube.
func (a *API) ListObjects(ctx context.Context, res Resource, ns string) ([]ObjectDetail, error) {
	base := "/api/" + res.Version
	if res.Group != "" {
		base = "/apis/" + res.Group + "/" + res.Version
	}
	var l struct {
		Items []struct {
			APIVersion string `json:"apiVersion"`
			Kind       string `json:"kind"`
			Metadata   struct {
				Name            string            `json:"name"`
				Namespace       string            `json:"namespace"`
				UID             string            `json:"uid"`
				Labels          map[string]string `json:"labels"`
				Annotations     map[string]string `json:"annotations"`
				OwnerReferences []struct {
					Controller *bool `json:"controller"`
				} `json:"ownerReferences"`
				ManagedFields []struct {
					Manager string `json:"manager"`
					Time    string `json:"time"`
				} `json:"managedFields"`
			} `json:"metadata"`
			Spec json.RawMessage `json:"spec"`
		} `json:"items"`
		Kind string `json:"kind"`
	}
	if err := a.call(ctx, "GET", base+"/namespaces/"+url.PathEscape(ns)+"/"+res.Plural, "", nil, &l); err != nil {
		var se *StatusError
		if errors.As(err, &se) && se.Code == http.StatusNotFound {
			return nil, nil // the kind is not installed here
		}
		return nil, err
	}
	kind := strings.TrimSuffix(l.Kind, "List")
	out := make([]ObjectDetail, 0, len(l.Items))
	for _, it := range l.Items {
		m := it.Metadata
		o := Object{APIVersion: it.APIVersion, Kind: it.Kind, Namespace: ns, Name: m.Name, UID: m.UID, Labels: m.Labels,
			Annotations: m.Annotations}
		if o.APIVersion == "" { // a list's items may omit apiVersion and kind
			o.APIVersion = strings.TrimPrefix(base, "/api/")
			if res.Group != "" {
				o.APIVersion = res.Group + "/" + res.Version
			}
		}
		if o.Kind == "" {
			o.Kind = kind
		}
		for _, r := range m.OwnerReferences {
			if r.Controller != nil && *r.Controller {
				o.Owned = true
			}
		}
		var newest string
		for _, f := range m.ManagedFields {
			if f.Time >= newest {
				newest, o.Manager = f.Time, f.Manager
			}
		}
		d := ObjectDetail{Object: o, LastApplied: m.Annotations["kubectl.kubernetes.io/last-applied-configuration"]}
		if o.Kind == "Job" {
			d.Spec = it.Spec
		}
		out = append(out, d)
	}
	return out, nil
}

// GetData implements Kube: nil when the ConfigMap does not exist.
func (a *API) GetData(ctx context.Context, ns, name string) (map[string]string, error) {
	var cm struct {
		Data map[string]string `json:"data"`
	}
	err := a.call(ctx, "GET", "/api/v1/namespaces/"+url.PathEscape(ns)+"/configmaps/"+url.PathEscape(name), "", nil, &cm)
	var se *StatusError
	if errors.As(err, &se) && se.Code == http.StatusNotFound {
		return nil, nil
	}
	return cm.Data, err
}

// PutData implements Kube: patch the data of the ConfigMap that is there, and create it only when it is not (a 404),
// so the steady state never sends a create that the API server refuses.
func (a *API) PutData(ctx context.Context, ns, name string, data map[string]string) error {
	path := "/api/v1/namespaces/" + url.PathEscape(ns) + "/configmaps"
	patch := func() error {
		return a.call(ctx, "PATCH", path+"/"+url.PathEscape(name), merge, map[string]any{"data": data}, nil)
	}
	err := patch()
	var se *StatusError
	if !errors.As(err, &se) || se.Code != http.StatusNotFound {
		return err
	}
	err = a.call(ctx, "POST", path, "application/json", map[string]any{"apiVersion": "v1", "kind": "ConfigMap",
		"metadata": map[string]any{"name": name, "labels": map[string]string{LabelManagedBy: ManagedBy}}, "data": data}, nil)
	if errors.As(err, &se) && se.Code == http.StatusConflict { // created since the patch
		return patch()
	}
	return err
}

// UpdateApplicationSource implements Kube: one JSON patch, guarded by a test of the resource version the agent read
// (the API server applies the patch to the stored object, so a changed Application fails the test: 422, read here as
// ErrConflict). It writes spec.source, spec.sources and the switched annotation, and nothing else.
func (a *API) UpdateApplicationSource(ctx context.Context, app Application, e SourceEdit) error {
	esc := func(s string) string { return strings.NewReplacer("~", "~0", "/", "~1").Replace(s) }
	ops := []map[string]any{{"op": "test", "path": "/metadata/resourceVersion", "value": app.ResourceVersion}}
	field := func(path string, had bool, v any, set bool) {
		switch {
		case set:
			ops = append(ops, map[string]any{"op": "add", "path": path, "value": v}) // add replaces an existing member
		case had:
			ops = append(ops, map[string]any{"op": "remove", "path": path})
		}
	}
	field("/spec/source", len(app.Source) > 0, e.Source, len(e.Source) > 0)
	var srcs any = e.Sources
	field("/spec/sources", len(app.Sources) > 0, srcs, len(e.Sources) > 0)
	_, hadAnn := app.Annotations[AnnSwitched]
	if e.Switched != "" && app.Annotations == nil {
		ops = append(ops, map[string]any{"op": "add", "path": "/metadata/annotations", "value": map[string]string{}})
	}
	field("/metadata/annotations/"+esc(AnnSwitched), hadAnn, e.Switched, e.Switched != "")
	err := a.call(ctx, "PATCH", a.appsPath()+"/"+url.PathEscape(app.Name), "application/json-patch+json", ops, nil)
	var se *StatusError
	if errors.As(err, &se) && se.Code == http.StatusConflict {
		return fmt.Errorf("%w: %s", ErrConflict, se.Body)
	}
	if errors.As(err, &se) && se.Code == http.StatusUnprocessableEntity {
		if patchNotApplied(se.Body) {
			return fmt.Errorf("%w: %s", ErrConflict, se.Body)
		}
		return fmt.Errorf("%w: %s", ErrInvalid, se.Body)
	}
	if errors.As(err, &se) && se.Code == http.StatusNotFound {
		return ErrNotFound
	}
	return err
}

// patchNotApplied says whether a 422 is the API server's answer to a JSON patch that did not apply: a failed `test`
// (the object changed since it was read) or an op on a path that is no longer there. The server answers both the same
// way, and has no details: {"reason":"Invalid","message":"the server rejected our request due to an error in our request",
// "details":{},"code":422} (measured against kube-apiserver 1.36.2 with envtest, docs/gate.md). A validation error
// (a CRD schema or admission refusal) names its causes or says what is invalid, and is not this.
func patchNotApplied(body string) bool {
	var st struct {
		Reason  string `json:"reason"`
		Message string `json:"message"`
		Details struct {
			Causes []json.RawMessage `json:"causes"`
			Name   string            `json:"name"`
		} `json:"details"`
	}
	if json.Unmarshal([]byte(body), &st) != nil {
		return false // a body cut at 300 bytes still starts with the fields above; unparseable: not a stale read
	}
	return st.Reason == "Invalid" && len(st.Details.Causes) == 0 && st.Details.Name == "" &&
		st.Message == "the server rejected our request due to an error in our request"
}

// GetApplicationSet implements Kube.
func (a *API) GetApplicationSet(ctx context.Context, name string) (AppSet, error) {
	var w struct {
		Metadata struct {
			Namespace string `json:"namespace"`
			Name      string `json:"name"`
		} `json:"metadata"`
		Spec struct {
			Ignore    []ignoreWire `json:"ignoreApplicationDifferences"`
			Preserved struct {
				Annotations []string `json:"annotations"`
			} `json:"preservedFields"`
		} `json:"spec"`
	}
	err := a.call(ctx, "GET", "/apis/argoproj.io/v1alpha1/namespaces/"+url.PathEscape(a.ArgoNS)+"/applicationsets/"+url.PathEscape(name), "", nil, &w)
	var se *StatusError
	if errors.As(err, &se) && se.Code == http.StatusNotFound {
		return AppSet{}, ErrNotFound
	}
	if err != nil {
		return AppSet{}, err
	}
	return AppSet{Namespace: w.Metadata.Namespace, Name: w.Metadata.Name, IgnoreApplicationDifferences: ignores(w.Spec.Ignore),
		PreservedAnnotations: w.Spec.Preserved.Annotations}, nil
}

// SetNamespaceProtected implements Kube: a read, then one merge patch guarded by the version read. Adding leaves a
// namespace that is already labelled protected alone (an operator's label stays the operator's); removing needs the
// agent's marker.
func (a *API) SetNamespaceProtected(ctx context.Context, ns string, protected bool) error {
	path := "/api/v1/namespaces/" + url.PathEscape(ns)
	var cur struct {
		Metadata struct {
			Labels          map[string]string `json:"labels"`
			ResourceVersion string            `json:"resourceVersion"`
		} `json:"metadata"`
	}
	if err := a.call(ctx, "GET", path, "", nil, &cur); err != nil {
		var se *StatusError
		if errors.As(err, &se) && se.Code == http.StatusNotFound {
			return ErrNotFound
		}
		return err
	}
	l := cur.Metadata.Labels
	labels := map[string]any{}
	if protected {
		if l[LabelProtected] == "true" {
			return nil
		}
		labels[LabelProtected], labels[LabelProtectedBy] = "true", ProtectedByOptIn
	} else {
		if l[LabelProtected] != "true" && l[LabelProtectedBy] == "" {
			return nil
		}
		if l[LabelProtectedBy] != ProtectedByOptIn {
			return ErrNotOurs
		}
		labels[LabelProtected], labels[LabelProtectedBy] = nil, nil
	}
	err := a.call(ctx, "PATCH", path, merge, map[string]any{"metadata": map[string]any{
		"resourceVersion": cur.Metadata.ResourceVersion, "labels": labels}}, nil)
	var se *StatusError
	if errors.As(err, &se) && se.Code == http.StatusConflict {
		return fmt.Errorf("%w: %s", ErrConflict, se.Body)
	}
	return err
}

// GetNamespaceLabels implements Kube.
func (a *API) GetNamespaceLabels(ctx context.Context, ns string) (map[string]string, error) {
	var cur struct {
		Metadata struct {
			Labels map[string]string `json:"labels"`
		} `json:"metadata"`
	}
	if err := a.call(ctx, "GET", "/api/v1/namespaces/"+url.PathEscape(ns), "", nil, &cur); err != nil {
		var se *StatusError
		if errors.As(err, &se) && se.Code == http.StatusNotFound {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return cur.Metadata.Labels, nil
}

// ClusterScopes implements Kube: /api and /apis discovery, one request per group version.
func (a *API) ClusterScopes(ctx context.Context) (map[string]bool, error) {
	type resources struct {
		APIResources []struct {
			Name       string `json:"name"`
			Kind       string `json:"kind"`
			Namespaced bool   `json:"namespaced"`
		} `json:"resources"`
	}
	var paths []string
	var core struct {
		Versions []string `json:"versions"`
	}
	if err := a.call(ctx, "GET", "/api", "", nil, &core); err != nil {
		return nil, err
	}
	for _, v := range core.Versions {
		paths = append(paths, "/api/"+v)
	}
	var groups struct {
		Groups []struct {
			Versions []struct {
				GroupVersion string `json:"groupVersion"`
			} `json:"versions"`
		} `json:"groups"`
	}
	if err := a.call(ctx, "GET", "/apis", "", nil, &groups); err != nil {
		return nil, err
	}
	for _, g := range groups.Groups {
		for _, v := range g.Versions {
			paths = append(paths, "/apis/"+v.GroupVersion)
		}
	}
	scope := map[string]bool{}
	ambiguous := map[string]bool{}
	for _, p := range paths {
		var l resources
		if err := a.call(ctx, "GET", p, "", nil, &l); err != nil {
			var se *StatusError
			if errors.As(err, &se) && se.Code == http.StatusServiceUnavailable {
				return nil, fmt.Errorf("discovery of %s: %w", p, err) // an aggregated API that is down: the answer is incomplete
			}
			return nil, err
		}
		for _, r := range l.APIResources {
			if strings.Contains(r.Name, "/") {
				continue
			}
			if was, ok := scope[r.Kind]; ok && was != !r.Namespaced {
				ambiguous[r.Kind] = true
			}
			scope[r.Kind] = !r.Namespaced
		}
	}
	for k := range ambiguous {
		delete(scope, k)
	}
	return scope, nil
}

// GrantSchemaFields implements Kube: the CRD's schema for the version the agent uses.
func (a *API) GrantSchemaFields(ctx context.Context) (map[string]bool, error) {
	var crd struct {
		Spec struct {
			Versions []struct {
				Name   string `json:"name"`
				Schema struct {
					OpenAPIV3Schema struct {
						Properties struct {
							Spec struct {
								Properties struct {
									Objects struct {
										AdditionalProperties struct {
											Properties map[string]json.RawMessage `json:"properties"`
										} `json:"additionalProperties"`
									} `json:"objects"`
									Carried struct {
										Items struct {
											Properties struct {
												Objects struct {
													AdditionalProperties struct {
														Properties map[string]json.RawMessage `json:"properties"`
													} `json:"additionalProperties"`
												} `json:"objects"`
											} `json:"properties"`
										} `json:"items"`
									} `json:"carried"`
								} `json:"properties"`
							} `json:"spec"`
						} `json:"properties"`
					} `json:"openAPIV3Schema"`
				} `json:"schema"`
			} `json:"versions"`
		} `json:"spec"`
	}
	path := "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/" + url.PathEscape(a.Grants.Plural+"."+a.Grants.Group)
	if err := a.call(ctx, "GET", path, "", nil, &crd); err != nil {
		return nil, err
	}
	for _, v := range crd.Spec.Versions {
		if v.Name != a.Grants.Version {
			continue
		}
		sp := v.Schema.OpenAPIV3Schema.Properties.Spec.Properties
		out := map[string]bool{}
		for k := range sp.Objects.AdditionalProperties.Properties {
			out["objects."+k] = true
		}
		for k := range sp.Carried.Items.Properties.Objects.AdditionalProperties.Properties {
			out["carried."+k] = true
		}
		return out, nil
	}
	return nil, fmt.Errorf("the CRD has no version %s", a.Grants.Version)
}
