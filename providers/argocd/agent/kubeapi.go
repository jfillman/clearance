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
	"strings"
	"time"
)

// ErrWatchGone is a watch whose resourceVersion the API server no longer holds (410).
var ErrWatchGone = errors.New("agent: watch resourceVersion is too old")

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
		Valid *bool `json:"valid"`
	} `json:"status"`
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
		out = append(out, Grant{Namespace: w.Metadata.Namespace, Name: w.Metadata.Name, Labels: w.Metadata.Labels,
			Spec: w.Spec, Valid: w.Status.Valid})
	}
	return out, nil
}

// ApplyGrant implements Kube: create, and on a conflict replace spec and labels with a merge patch. A removed
// active label must be sent as null, so the patch names every label the agent owns.
func (a *API) ApplyGrant(ctx context.Context, g Grant) error {
	meta := map[string]any{"name": g.Name, "namespace": g.Namespace, "labels": g.Labels}
	obj := map[string]any{"apiVersion": a.Grants.Group + "/" + a.Grants.Version, "kind": "ClearanceGrant",
		"metadata": meta, "spec": g.Spec}
	err := a.call(ctx, "POST", a.grantPath(g.Namespace, ""), "application/json", obj, nil)
	var se *StatusError
	if !errors.As(err, &se) || se.Code != http.StatusConflict {
		return err
	}
	labels := map[string]any{}
	for _, k := range []string{LabelActive} {
		labels[k] = nil
	}
	for k, v := range g.Labels {
		labels[k] = v
	}
	// A merge patch only adds and replaces keys: spec.objects keys the new spec lacks are sent as null, so the stored
	// map ends up exactly the token's objects.
	var cur grantWire
	if err := a.call(ctx, "GET", a.grantPath(g.Namespace, g.Name), "", nil, &cur); err != nil {
		return err
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

type appWire struct {
	Metadata struct {
		Namespace       string            `json:"namespace"`
		Name            string            `json:"name"`
		Labels          map[string]string `json:"labels"`
		UID             string            `json:"uid"`
		ResourceVersion string            `json:"resourceVersion"`
	} `json:"metadata"`
	Spec struct {
		Project     string `json:"project"`
		Destination struct {
			Namespace string `json:"namespace"`
		} `json:"destination"`
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
		DestNS: w.Spec.Destination.Namespace, SyncState: w.Status.Sync.Status, Health: w.Status.Health.Status,
		Revisions: w.Status.Sync.Revisions}
	if len(a.Revisions) == 0 && w.Status.Sync.Revision != "" {
		a.Revisions = []string{w.Status.Sync.Revision}
	}
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

// PutData implements Kube: create, or replace the data.
func (a *API) PutData(ctx context.Context, ns, name string, data map[string]string) error {
	path := "/api/v1/namespaces/" + url.PathEscape(ns) + "/configmaps"
	err := a.call(ctx, "POST", path, "application/json", map[string]any{"apiVersion": "v1", "kind": "ConfigMap",
		"metadata": map[string]any{"name": name, "labels": map[string]string{LabelManagedBy: ManagedBy}}, "data": data}, nil)
	var se *StatusError
	if errors.As(err, &se) && se.Code == http.StatusConflict {
		return a.call(ctx, "PATCH", path+"/"+url.PathEscape(name), merge, map[string]any{"data": data}, nil)
	}
	return err
}
