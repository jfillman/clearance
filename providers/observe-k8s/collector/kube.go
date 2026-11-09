package collector

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

// ErrGone is a watch whose resourceVersion the API server no longer holds (410): list again.
var ErrGone = errors.New("collector: watch resourceVersion is too old")

// WatchSpec is a resource the collector watches, to keep the objects as they stood (the audit event carries only the
// new state) and to notice a change no audit event reported. Secrets are never listed here: the collector's service
// account has no get, list or watch on them.
type WatchSpec struct {
	Group, Version, Resource, Kind string
	Namespaced                     bool
}

func (w WatchSpec) path(ns string) string {
	base := "/api/" + w.Version
	if w.Group != "" {
		base = "/apis/" + w.Group + "/" + w.Version
	}
	if w.Namespaced && ns != "" {
		base += "/namespaces/" + url.PathEscape(ns)
	}
	return base + "/" + w.Resource
}

// ParseWatch reads "group/version/resource=Kind[,cluster]" ("" group: core): "apps/v1/deployments=Deployment",
// "v1/configmaps=ConfigMap", "rbac.authorization.k8s.io/v1/clusterroles=ClusterRole,cluster".
func ParseWatch(s string) (WatchSpec, error) {
	spec, flag, _ := strings.Cut(s, ",")
	path, kind, ok := strings.Cut(spec, "=")
	parts := strings.Split(path, "/")
	if !ok || kind == "" || (len(parts) != 2 && len(parts) != 3) || (flag != "" && flag != "cluster") {
		return WatchSpec{}, fmt.Errorf("watch %q: want group/version/resource=Kind[,cluster] (v1/configmaps=ConfigMap for the core group)", s)
	}
	w := WatchSpec{Kind: kind, Namespaced: flag != "cluster"}
	if len(parts) == 2 {
		w.Version, w.Resource = parts[0], parts[1]
	} else {
		w.Group, w.Version, w.Resource = parts[0], parts[1], parts[2]
	}
	if strings.EqualFold(w.Resource, "secrets") || strings.EqualFold(kind, "Secret") {
		return WatchSpec{}, errors.New("the collector never watches Secrets")
	}
	return w, nil
}

// Kube is the cluster API as the collector uses it: list, watch, merge-patch, and one ConfigMap read.
type Kube interface {
	List(ctx context.Context, path string) (items []map[string]any, rv string, err error)
	Watch(ctx context.Context, path, rv string, fn func(typ string, obj map[string]any)) error
	Patch(ctx context.Context, path string, body any) error
	Get(ctx context.Context, path string) (map[string]any, error)
}

// API is Kube over the pod's service account, with no client library.
type API struct {
	Base      string
	TokenFile string
	Client    *http.Client
}

const saDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// InCluster is the API of the pod's own cluster.
func InCluster() (*API, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, errors.New("collector: not in a cluster (KUBERNETES_SERVICE_HOST is unset)")
	}
	ca, err := os.ReadFile(saDir + "/ca.crt")
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("collector: the service account CA is not PEM")
	}
	return &API{Base: "https://" + host + ":" + port, TokenFile: saDir + "/token",
		Client: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}}, nil
}

// StatusError is a non-2xx answer.
type StatusError struct {
	Code int
	Body string
}

func (e *StatusError) Error() string { return fmt.Sprintf("kubernetes API: %d %s", e.Code, e.Body) }

func (a *API) do(ctx context.Context, method, path, ct string, body []byte, stream bool) (*http.Response, error) {
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
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	c := a.Client
	if !stream {
		cc := *c
		cc.Timeout = 30 * time.Second
		c = &cc
	}
	return c.Do(req)
}

func (a *API) json(ctx context.Context, method, path, ct string, body []byte, out any) error {
	resp, err := a.do(ctx, method, path, ct, body, false)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		if len(b) > 300 {
			b = b[:300]
		}
		return &StatusError{resp.StatusCode, string(b)}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(b, out)
}

// List reads a collection and its resourceVersion.
func (a *API) List(ctx context.Context, path string) ([]map[string]any, string, error) {
	var l struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
		Items []map[string]any `json:"items"`
	}
	if err := a.json(ctx, "GET", path, "", nil, &l); err != nil {
		return nil, "", err
	}
	return l.Items, l.Metadata.ResourceVersion, nil
}

// Get reads one object.
func (a *API) Get(ctx context.Context, path string) (map[string]any, error) {
	var o map[string]any
	return o, a.json(ctx, "GET", path, "", nil, &o)
}

// Patch merge-patches an object.
func (a *API) Patch(ctx context.Context, path string, body any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	return a.json(ctx, "PATCH", path, "application/merge-patch+json", b, nil)
}

// Watch streams changes after rv until ctx ends or the stream breaks.
func (a *API) Watch(ctx context.Context, path, rv string, fn func(string, map[string]any)) error {
	q := "?watch=true&allowWatchBookmarks=true&timeoutSeconds=300"
	if rv != "" {
		q += "&resourceVersion=" + url.QueryEscape(rv)
	}
	resp, err := a.do(ctx, "GET", path+q, "", nil, true)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusGone {
		return ErrGone
	}
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return &StatusError{resp.StatusCode, string(b)}
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		var ev struct {
			Type   string         `json:"type"`
			Object map[string]any `json:"object"`
		}
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			return err
		}
		switch ev.Type {
		case "ERROR":
			if code, _ := ev.Object["code"].(float64); code == 410 {
				return ErrGone
			}
			return fmt.Errorf("watch error: %v", ev.Object["message"])
		case "BOOKMARK":
			fn("BOOKMARK", ev.Object)
		default:
			fn(ev.Type, ev.Object)
		}
	}
	if err := sc.Err(); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}
