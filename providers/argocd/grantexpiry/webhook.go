package grantexpiry

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	agent "github.com/jfillman/clearance/providers/argocd/agent"
)

// Mode is how the webhook answers. In audit it always allows, and a write it would refuse gets a warning (and, when the
// clock is the reason, the audit annotation); in enforce it refuses. The chart renders the mode and the configuration's
// failurePolicy (Ignore in audit, Fail in enforce) from one value, grantExpiry.enforce.
type Mode string

const (
	Audit   Mode = "audit"
	Enforce Mode = "enforce"
)

// ParseMode reads --mode.
func ParseMode(s string) (Mode, error) {
	switch Mode(s) {
	case Audit, Enforce:
		return Mode(s), nil
	}
	return "", fmt.Errorf("grantexpiry: mode must be audit or enforce, not %q", s)
}

// AuditKey is the audit annotation's key in the response. The API server prefixes it with the webhook's name, and the
// chart names the webhook clearance.hangar.io, so the audit log carries clearance.hangar.io/expired-grant.
const AuditKey = "expired-grant"

// WebhookName is the name the chart gives the webhook (a name needs three dot-separated segments; this one is the
// prefix of the audit annotation).
const WebhookName = "clearance.hangar.io"

// Excluded are the resources the admission policy's matchConstraints.excludeResourceRules leave out (so the agent can
// bootstrap a grant and the control plane keeps writing): the configuration's matchConditions leave the same out, and
// the handler checks again.
var Excluded = []struct{ Group, Resource string }{
	{"clearance.hangar.io", "clearancegrants"},
	{"", "events"},
	{"", "endpoints"},
	{"events.k8s.io", "events"},
	{"discovery.k8s.io", "endpointslices"},
	{"coordination.k8s.io", "leases"},
}

// Lookup is the cache as the handler reads it.
type Lookup interface {
	Active(namespace string) ([]agent.Grant, bool)
}

// Config is the handler's settings.
type Config struct {
	Mode Mode
	// ArgoCDUser is the Argo CD application controller's username (the policy's matchConditions user).
	ArgoCDUser string
	Skew       time.Duration // an entry is live until its expiry plus Skew (default 0, never negative)
	Pins       Pins
	Now        func() time.Time
}

// Handler serves POST /validate (AdmissionReview admission.k8s.io/v1).
type Handler struct {
	cfg     Config
	lookup  Lookup
	log     *slog.Logger
	metrics *Metrics
}

// NewHandler checks cfg and builds the handler. metrics and log may be nil.
func NewHandler(cfg Config, lookup Lookup, metrics *Metrics, log *slog.Logger) (*Handler, error) {
	if _, err := ParseMode(string(cfg.Mode)); err != nil {
		return nil, err
	}
	if cfg.ArgoCDUser == "" {
		return nil, fmt.Errorf("grantexpiry: the Argo CD controller's username is required")
	}
	if cfg.Skew < 0 {
		return nil, fmt.Errorf("grantexpiry: the skew allowance cannot be negative")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if log == nil {
		log = slog.Default()
	}
	if metrics == nil {
		metrics = NewMetrics(nil, cfg.Mode)
	}
	return &Handler{cfg: cfg, lookup: lookup, log: log, metrics: metrics}, nil
}

// The admission.k8s.io/v1 wire types, as much as the webhook reads and writes.
type review struct {
	APIVersion string    `json:"apiVersion"`
	Kind       string    `json:"kind"`
	Request    *request  `json:"request,omitempty"`
	Response   *response `json:"response,omitempty"`
}

type request struct {
	UID         string `json:"uid"`
	Resource    *gvr   `json:"resource,omitempty"`
	SubResource string `json:"subResource,omitempty"`
	Name        string `json:"name,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
	Operation   string `json:"operation"`
	UserInfo    *struct {
		Username string `json:"username"`
	} `json:"userInfo,omitempty"`
	Object json.RawMessage `json:"object,omitempty"`
}

type gvr struct {
	Group    string `json:"group"`
	Version  string `json:"version"`
	Resource string `json:"resource"`
}

type response struct {
	UID              string            `json:"uid"`
	Allowed          bool              `json:"allowed"`
	Status           *status           `json:"status,omitempty"`
	Warnings         []string          `json:"warnings,omitempty"`
	AuditAnnotations map[string]string `json:"auditAnnotations,omitempty"`
}

type status struct {
	Code    int    `json:"code"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message"`
}

// inScope mirrors the configuration's matchConditions (and the policy's): Argo CD's controller, a main resource
// (no subresource), CREATE or UPDATE of a namespaced object, not an excluded resource. The API server calls the webhook
// only for these; a request outside them is allowed without a decision.
func (h *Handler) inScope(r *request) bool {
	if r.UserInfo == nil || r.UserInfo.Username != h.cfg.ArgoCDUser || r.SubResource != "" || r.Namespace == "" {
		return false
	}
	if r.Operation != "CREATE" && r.Operation != "UPDATE" {
		return false
	}
	if r.Resource != nil {
		for _, x := range Excluded {
			if r.Resource.Group == x.Group && r.Resource.Resource == x.Resource {
				return false
			}
		}
	}
	return true
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n-3] + "..."
	}
	return s
}

// Review answers one AdmissionReview request.
func (h *Handler) Review(r *request) *response {
	resp := &response{UID: r.UID, Allowed: true}
	if !h.inScope(r) {
		return resp
	}
	var v Verdict
	var obj struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Metadata   struct {
			Name        string            `json:"name"`
			Labels      map[string]string `json:"labels"`
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
		Spec json.RawMessage `json:"spec"`
	}
	if err := json.Unmarshal(r.Object, &obj); err != nil || len(r.Object) == 0 {
		v = Verdict{Reason: "the request carries no readable object"}
	} else if grants, ok := h.lookup.Active(r.Namespace); !ok {
		v = Verdict{Reason: "the grant cache is not synced with the API server"}
	} else {
		o := Object{APIVersion: obj.APIVersion, Kind: obj.Kind, Name: obj.Metadata.Name, Labels: obj.Metadata.Labels,
			Annotations: obj.Metadata.Annotations, Spec: obj.Spec}
		v = Decide(o, grants, h.cfg.Now(), h.cfg.Skew, h.cfg.Pins)
	}
	h.metrics.decided(v)
	if v.Allowed {
		return resp
	}
	where := r.Namespace
	if v.Grant != "" {
		where += "/" + v.Grant
	}
	msg := clip("clearance grant-expiry: "+v.Reason, 1000)
	if v.Expired {
		resp.AuditAnnotations = map[string]string{AuditKey: clip(where+": "+v.Reason, 1000)}
	}
	h.log.Info("refused", "mode", h.cfg.Mode, "namespace", r.Namespace, "name", r.Name, "operation", r.Operation,
		"expired", v.Expired, "reason", v.Reason)
	if h.cfg.Mode == Audit {
		resp.Warnings = []string{clip("clearance grant-expiry (audit, not enforced) would refuse: "+v.Reason, 250)}
		return resp
	}
	resp.Allowed = false
	resp.Status = &status{Code: http.StatusForbidden, Reason: "Forbidden", Message: msg}
	return resp
}

// ServeHTTP implements POST /validate.
func (h *Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "POST an AdmissionReview", http.StatusMethodNotAllowed)
		return
	}
	if ct := req.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/json") {
		http.Error(w, "the body must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, 8<<20))
	if err != nil {
		http.Error(w, "reading the body: "+err.Error(), http.StatusBadRequest)
		return
	}
	var in review
	if err := json.Unmarshal(body, &in); err != nil || in.Request == nil {
		// Not a review: the API server counts this as a failed call, and failurePolicy decides (Fail in enforce).
		http.Error(w, "not an AdmissionReview with a request", http.StatusBadRequest)
		return
	}
	out := review{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview", Response: h.Review(in.Request)}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// Ready serves GET /readyz: 200 when the cache is synced and, when the probe names one (?mode=enforce), the webhook runs
// in that mode. The chart's probe names the mode it rendered, so a pod still in audit is not Ready in an enforce
// rollout, and the configuration's later sync wave (failurePolicy Fail) waits for pods that enforce.
func Ready(mode Mode, synced func() bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		want := r.URL.Query().Get("mode")
		switch {
		case want != "" && Mode(want) != mode:
			http.Error(w, fmt.Sprintf("not ready: mode=%s, the rollout wants mode=%s", mode, want), http.StatusServiceUnavailable)
		case !synced():
			http.Error(w, fmt.Sprintf("not ready: mode=%s, the grant cache is not synced", mode), http.StatusServiceUnavailable)
		default:
			fmt.Fprintf(w, "ok mode=%s\n", mode)
		}
	}
}
