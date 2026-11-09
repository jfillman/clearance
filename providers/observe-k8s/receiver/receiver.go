// Package receiver is the webhook the kube-apiserver's audit backend posts batches to. It authenticates the API
// server (mutual TLS: a client certificate that chains to the configured CA and names an allowed identity), strips
// every Secret body from what it was sent before anything is written, appends the batch to the durable queue, and
// answers 200 only after the append has returned, which is after an fsync. Anything it cannot make durable is
// answered 503 so the API server retries; nothing is acknowledged and then lost.
//
// The receiver is the only thing in the collector that sees raw audit events before the pipeline, so it is where the
// Secret rule is enforced a second time: the audit policy already records Secrets at Metadata, and if the live policy
// does not (a node's policy was changed), the body is cut off here, the event is marked, and the collector's health
// says so (the secrets-metadata-only check).
package receiver

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jfillman/clearance/providers/observe-k8s/queue"
)

// Annotations the receiver puts on an event it changed.
const (
	AnnStripped  = "observe-k8s.clearance.hangar.io/body-stripped"
	AnnOversized = "observe-k8s.clearance.hangar.io/body-dropped-oversize"
)

// Limits.
const (
	MaxBody = 32 << 20 // one batch
	MaxItem = 4 << 20  // one event: past this its bodies are dropped
)

// Sink is where an accepted batch goes. Append returns only when the entries are durable (queue.Queue).
type Sink interface {
	Append(payloads ...[]byte) error
}

// Config configures a Receiver.
type Config struct {
	Sink Sink
	// AllowedClients are the certificate names (subject common name or a DNS SAN) the API server's client certificate
	// may carry. Required: an empty list would let any certificate under the CA post audit events.
	AllowedClients []string
	Log            *slog.Logger
	Now            func() time.Time
}

// Receiver is the http.Handler of POST /audit.
type Receiver struct {
	cfg Config

	batches, events, stripped atomic.Int64
	rejected                  atomic.Int64
	lastBatch                 atomic.Int64 // unix nanos of the last accepted batch
	lastClient                atomic.Value // string
}

// New builds a Receiver.
func New(cfg Config) (*Receiver, error) {
	if cfg.Sink == nil {
		return nil, errors.New("receiver: no sink")
	}
	if len(cfg.AllowedClients) == 0 {
		return nil, errors.New("receiver: at least one allowed client name is required (the API server's certificate)")
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Receiver{cfg: cfg}, nil
}

// Status is what the receiver has seen.
type Status struct {
	Batches, Events, Stripped, Rejected int64
	LastBatch                           time.Time // zero: none yet
	LastClient                          string
}

// Status snapshots the counters.
func (r *Receiver) Status() Status {
	s := Status{Batches: r.batches.Load(), Events: r.events.Load(), Stripped: r.stripped.Load(), Rejected: r.rejected.Load()}
	if n := r.lastBatch.Load(); n > 0 {
		s.LastBatch = time.Unix(0, n).UTC()
	}
	s.LastClient, _ = r.lastClient.Load().(string)
	return s
}

// ServeHTTP handles POST /audit; every other path and method is refused.
func (r *Receiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/audit" {
		http.NotFound(w, req)
		return
	}
	if req.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	name, status, why := r.authenticate(req)
	if status != 0 {
		r.rejected.Add(1)
		r.cfg.Log.Warn("audit batch refused", "reason", why, "remote", req.RemoteAddr)
		http.Error(w, why, status)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, req.Body, MaxBody))
	if err != nil {
		r.rejected.Add(1)
		http.Error(w, "the body is unreadable or over the limit", http.StatusRequestEntityTooLarge)
		return
	}
	items, stripped, err := Sanitize(body)
	if err != nil {
		r.rejected.Add(1)
		r.cfg.Log.Warn("audit batch is not an EventList", "err", err)
		http.Error(w, "not an audit.k8s.io EventList: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(items) > 0 {
		if err := r.cfg.Sink.Append(items...); err != nil {
			code := http.StatusServiceUnavailable
			r.cfg.Log.Error("audit batch not made durable: the API server will retry", "err", err, "events", len(items))
			w.Header().Set("Retry-After", "5")
			http.Error(w, "not durable", code)
			return
		}
	}
	// Durable: now, and only now, the API server is told.
	r.batches.Add(1)
	r.events.Add(int64(len(items)))
	r.stripped.Add(int64(stripped))
	r.lastBatch.Store(r.cfg.Now().UnixNano())
	r.lastClient.Store(name)
	if stripped > 0 {
		r.cfg.Log.Error("Secret bodies were in the audit batch and were dropped: the live audit policy records Secrets above Metadata", "events", stripped)
	}
	w.WriteHeader(http.StatusOK)
}

func (r *Receiver) authenticate(req *http.Request) (name string, status int, why string) {
	if req.TLS == nil || len(req.TLS.VerifiedChains) == 0 || len(req.TLS.PeerCertificates) == 0 {
		return "", http.StatusUnauthorized, "a verified client certificate is required"
	}
	c := req.TLS.PeerCertificates[0]
	names := append([]string{c.Subject.CommonName}, c.DNSNames...)
	for _, n := range names {
		if n != "" && slices.Contains(r.cfg.AllowedClients, n) {
			return n, 0, ""
		}
	}
	return "", http.StatusForbidden, "this client certificate is not the API server's"
}

// eventList is audit.k8s.io/v1 EventList, with each event kept raw.
type eventList struct {
	Kind       string            `json:"kind"`
	APIVersion string            `json:"apiVersion"`
	Items      []json.RawMessage `json:"items"`
}

// Sanitize decodes an EventList and returns each event as the bytes to queue, with every Secret body removed, and how
// many events had one. A body is removed when the event is about a Secret (or a service-account token), or when the
// body itself is one (a Secret, a SecretList, a TokenRequest). An event over MaxItem loses its bodies.
func Sanitize(body []byte) (items [][]byte, stripped int, err error) {
	var l eventList
	if err := json.Unmarshal(body, &l); err != nil {
		return nil, 0, err
	}
	if l.Kind != "EventList" || !strings.HasPrefix(l.APIVersion, "audit.k8s.io/") {
		return nil, 0, fmt.Errorf("kind %q apiVersion %q", l.Kind, l.APIVersion)
	}
	return SanitizeItems(l.Items)
}

// SanitizeItems is Sanitize for events that did not come in an EventList (the managed-cluster readers' events), with
// the same guarantees.
func SanitizeItems(raws []json.RawMessage) (items [][]byte, stripped int, err error) {
	for i, raw := range raws {
		var ev map[string]any
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&ev); err != nil {
			return nil, 0, fmt.Errorf("event %d: %w", i, err)
		}
		if id, _ := ev["auditID"].(string); id == "" {
			return nil, 0, fmt.Errorf("event %d has no auditID", i)
		}
		changed := false
		if aboutCredential(ev) {
			changed = dropBodies(ev, AnnStripped)
			if changed {
				stripped++
			}
		}
		out, err := json.Marshal(ev)
		if err != nil {
			return nil, 0, err
		}
		if len(out) > MaxItem {
			if dropBodies(ev, AnnOversized) {
				out, err = json.Marshal(ev)
				if err != nil {
					return nil, 0, err
				}
			}
			if len(out) > queue.MaxEntry {
				return nil, 0, fmt.Errorf("event %d is %d bytes after its bodies were dropped", i, len(out))
			}
		}
		items = append(items, out)
	}
	return items, stripped, nil
}

// aboutCredential: the event's object is a Secret or a token, or one of its bodies is one.
func aboutCredential(ev map[string]any) bool {
	if ref, ok := ev["objectRef"].(map[string]any); ok {
		res, _ := ref["resource"].(string)
		sub, _ := ref["subresource"].(string)
		if res == "secrets" || (res == "serviceaccounts" && sub == "token") {
			return true
		}
	}
	for _, k := range []string{"requestObject", "responseObject"} {
		if o, ok := ev[k].(map[string]any); ok {
			switch o["kind"] {
			case "Secret", "SecretList", "TokenRequest":
				return true
			}
		}
	}
	return false
}

// dropBodies removes requestObject and responseObject and marks the event; it says whether there was a body.
func dropBodies(ev map[string]any, mark string) bool {
	_, a := ev["requestObject"]
	_, b := ev["responseObject"]
	level, _ := ev["level"].(string)
	had := a || b || level == "Request" || level == "RequestResponse"
	delete(ev, "requestObject")
	delete(ev, "responseObject")
	if had {
		ann, _ := ev["annotations"].(map[string]any)
		if ann == nil {
			ann = map[string]any{}
		}
		ann[mark] = "true"
		ev["annotations"] = ann
	}
	return had
}

// ServerTLS is the receiver's TLS configuration: the server's certificate and key, and the CA that signed the API
// server's client certificate. TLS 1.2 or later; a client certificate is required and verified.
func ServerTLS(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	pem, err := os.ReadFile(clientCAFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("receiver: the client CA file holds no PEM certificate")
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12}, nil
}
