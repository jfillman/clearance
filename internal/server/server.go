// Package server is the Go core's HTTP API: one http.Server serving the runtime decision
// (POST /access/v1/evaluation), the call's outcome (POST /v1/decisions/{id}/outcome), a registered provider's own
// records (POST /v1/records), and the gate, review, provenance and GitHub App routes at their Python paths.
// Routes is the route table; the contract (contract/clearance-core.json, OpenAPI 3.1) is generated from it and the
// Go request and response types (Contract), and a test fails when the committed file drifts.
//
// Every request: a body cap per route (MaxBytesReader, and Content-Length checked first), strict JSON decoding on
// this package's own routes, JSON errors {"error": ...}, a structured access log line without bodies, headers or
// tokens, panics recovered to a bare 500. Every route but /healthz, /readyz and the GitHub webhook (authenticated by
// its HMAC signature) needs a bearer token the Authenticator accepts; the decision, outcome and record routes also
// need the caller to be a registered provider (CLEARANCE_PROVIDERS, Provider).
//
// # Decision ids
//
// A recorded decision's id is its evidence record's seq, as a decimal string: unique, stable, and found again in
// one indexed read (store.Reader.Records(seq, 1)). The decision record names its caller (`caller`: {provider,
// principal}, verified: the core authenticated it), so an outcome is accepted only from the provider that asked
// for the decision. Which decisions already have an outcome is an index the server builds from the chain at start
// (the outcome records' `outcome_of.seq`) and keeps while it is the one writer (store.LockKey), so a second outcome
// is refused without a scan. A decision with no record (a model call to a deployment without model routes) has
// decision_id null and takes no outcome.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/jfillman/clearance/internal/authn"
	"github.com/jfillman/clearance/internal/decide"
	"github.com/jfillman/clearance/internal/definitions"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/githubapp"
	"github.com/jfillman/clearance/internal/httpjson"
	"github.com/jfillman/clearance/internal/provenance"
	"github.com/jfillman/clearance/internal/review"
	"github.com/jfillman/clearance/internal/store"
)

// Server timeouts. Reads allow the largest body (a 25 MiB webhook) over a slow link; handlers are cut at
// HandlerTimeout so a stuck store call cannot hold a connection past WriteTimeout.
const (
	ReadHeaderTimeout = 5 * time.Second
	ReadTimeout       = 30 * time.Second
	WriteTimeout      = 30 * time.Second
	IdleTimeout       = 120 * time.Second
	HandlerTimeout    = 25 * time.Second
	ReadyTimeout      = 2 * time.Second
	// DefaultMaxClockSkew is how far an evaluation's context.now may be from the core's clock: the record's ts is
	// the decision's now and is verified, so a caller may not move it.
	DefaultMaxClockSkew = 5 * time.Minute
)

// Options are what the server serves. Store, Engine and Auth are required; a nil Gate, Review or Provenance is a
// core without those routes (they answer 404), a nil App answers the webhook 404 (githubapp.Handler).
type Options struct {
	Store     store.Store
	Engine    *decide.Engine
	Auth      authn.Authenticator
	Providers []Provider
	// Version is the core's build version: the provider version of the core's own records.
	Version string
	Clock   func() time.Time
	Log     *slog.Logger
	// MaxClockSkew bounds |context.now - Clock()| on an evaluation; 0 is DefaultMaxClockSkew, negative is off.
	MaxClockSkew time.Duration
	// DevRecords serves GET /v1/dev/records (DevRecordsPath): the chain, for another package's tests to read what
	// the core recorded. `clearance core --memory --insecure-dev-auth` only; not in the contract (clearance-api is
	// the reader of a kept chain).
	DevRecords bool

	// Definitions keeps the cluster-pinned definitions a provider publishes (PUT /v1/definitions), parsed with
	// ParseDefinition; nil answers the route 404.
	Definitions     *definitions.Service
	ParseDefinition definitions.Parser

	Gate       *gate.Service
	Review     *review.Handler
	Provenance *provenance.Service
	App        *githubapp.App
}

// Server is the HTTP API. Build it with New.
type Server struct {
	opt     Options
	log     *slog.Logger
	mux     *http.ServeMux
	handler http.Handler

	// outcomeMu serializes outcomes, so the has-an-outcome check and the record it guards are one step.
	outcomeMu sync.Mutex
	outcomes  map[int64]bool // decision seqs that have an outcome
}

// New builds the server and its outcome index (one pass over the chain).
func New(ctx context.Context, opt Options) (*Server, error) {
	if opt.Store == nil || opt.Engine == nil || opt.Auth == nil {
		return nil, errors.New("server: Store, Engine and Auth are required")
	}
	if opt.Clock == nil {
		opt.Clock = time.Now
	}
	if opt.Log == nil {
		opt.Log = slog.Default()
	}
	if opt.MaxClockSkew == 0 {
		opt.MaxClockSkew = DefaultMaxClockSkew
	}
	s := &Server{opt: opt, log: opt.Log, mux: http.NewServeMux()}
	idx, err := outcomeIndex(ctx, opt.Store)
	if err != nil {
		return nil, fmt.Errorf("server: reading the outcome index: %w", err)
	}
	s.outcomes = idx
	for _, rt := range Routes() {
		if rt.serve != nil {
			s.mux.HandleFunc(rt.Pattern(), rt.serve(s))
		}
	}
	s.mountServices()
	if opt.DevRecords {
		s.mux.HandleFunc("GET "+DevRecordsPath, s.devRecords)
	}
	s.handler = s.recoverer(s.accessLog(s.bodyCap(authn.Middleware(opt.Auth, unauthenticated)(notePrincipal(s.mux)))))
	return s, nil
}

// mountServices registers the R-1c handlers on the mux with their own Routes.
func (s *Server) mountServices() {
	if s.opt.Gate != nil {
		(&gate.Handler{Svc: s.opt.Gate, Log: s.log}).Routes(s.mux)
	}
	if s.opt.Review != nil {
		s.opt.Review.Routes(s.mux)
	}
	if s.opt.Provenance != nil {
		(&provenance.Handler{Svc: s.opt.Provenance, Log: s.log}).Routes(s.mux)
	}
	(&githubapp.Handler{App: s.opt.App}).Routes(s.mux)
}

// unauthenticated are the requests no bearer token is asked of.
func unauthenticated(r *http.Request) bool {
	switch {
	case r.Method == http.MethodGet && (r.URL.Path == "/healthz" || r.URL.Path == "/readyz" || r.URL.Path == "/v1/keys"):
		return true
	case r.Method == http.MethodPost && r.URL.Path == "/v1/github/webhook":
		return true // the payload's HMAC signature authenticates it (githubapp.App.Accept)
	}
	return false
}

// Handler is the whole API with its middleware.
func (s *Server) Handler() http.Handler { return s.handler }

// HTTPServer is an http.Server on addr with every timeout set.
func (s *Server) HTTPServer(addr string) *http.Server {
	return &http.Server{
		Addr: addr, Handler: s.handler,
		ReadHeaderTimeout: ReadHeaderTimeout, ReadTimeout: ReadTimeout, WriteTimeout: WriteTimeout,
		IdleTimeout: IdleTimeout, MaxHeaderBytes: 64 << 10,
		ErrorLog: slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
}

// outcomeIndex is every decision seq an outcome record names, from the whole chain.
func outcomeIndex(ctx context.Context, st store.Reader) (map[int64]bool, error) {
	idx := map[int64]bool{}
	const page = 5000
	for from := int64(0); ; {
		recs, err := st.Records(ctx, from, page)
		if err != nil {
			return nil, err
		}
		for _, r := range recs {
			if of, ok := r["outcome_of"].(map[string]any); ok {
				if seq, ok := gate.SeqInt(of["seq"]); ok {
					idx[seq] = true
				}
			}
		}
		if len(recs) < page {
			return idx, nil
		}
		last, _ := gate.SeqInt(recs[len(recs)-1]["seq"])
		from = last + 1
	}
}

// -- middleware ---------------------------------------------------------------------------------------------------

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				s.log.ErrorContext(r.Context(), "panic serving request", "method", r.Method, "path", r.URL.Path,
					"panic", fmt.Sprint(v))
				writeError(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

// principalBox lets the access log name the principal the auth middleware (inside it) found.
type principalBox struct{ id string }

type boxKey struct{}

// accessLog writes one line per request: method, path (never the query), status, bytes, duration and the
// principal. No body, no header, no token.
func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t0 := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		box := &principalBox{}
		ctx, cancel := context.WithTimeout(context.WithValue(r.Context(), boxKey{}, box), HandlerTimeout)
		defer cancel()
		next.ServeHTTP(sw, r.WithContext(ctx))
		if sw.status == 0 {
			sw.status = http.StatusOK
		}
		s.log.LogAttrs(r.Context(), slog.LevelInfo, "http",
			slog.String("method", r.Method), slog.String("path", r.URL.Path), slog.Int("status", sw.status),
			slog.Int64("bytes", sw.bytes), slog.Int64("ms", time.Since(t0).Milliseconds()),
			slog.String("principal", box.id))
	})
}

// notePrincipal records the authenticated principal (inside the auth middleware) for the access log (outside it).
func notePrincipal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if box, ok := r.Context().Value(boxKey{}).(*principalBox); ok {
			if p, ok := authn.From(r.Context()); ok {
				box.id = p.ID
			}
		}
		next.ServeHTTP(w, r)
	})
}

// bodyCap caps every request body at its route's limit: a declared Content-Length over it is 413 at once, and the
// body reader stops one byte past it (the R-1c handlers read cap+1 and answer 413 themselves; this package's
// handlers see *http.MaxBytesError).
func (s *Server) bodyCap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit, mounted := capFor(r)
		if r.ContentLength > limit {
			writeError(w, http.StatusRequestEntityTooLarge, "body too large")
			return
		}
		if mounted {
			limit++ // the handler reads cap+1 and answers 413 itself
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		next.ServeHTTP(w, r)
	})
}

// capFor is the body cap of the route r matches (DefaultMaxBody for anything else), and whether the route is a
// mounted R-1c handler.
func capFor(r *http.Request) (int64, bool) {
	for _, rt := range Routes() {
		if rt.Method == r.Method && rt.matches(r.URL.Path) {
			return rt.MaxBody, rt.serve == nil
		}
	}
	return DefaultMaxBody, false
}

// -- the operational routes ---------------------------------------------------------------------------------------

// DevRecordsPath is the dev-only chain read (Options.DevRecords): ?from=<seq>&limit=<n, at most 10000>, the
// records in seq order as stored.
const DevRecordsPath = "/v1/dev/records"

func (s *Server) devRecords(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	from, limit := int64(0), int64(1000)
	if v := q.Get("from"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			writeError(w, http.StatusBadRequest, "from is a seq")
			return
		}
		from = n
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 1 || n > 10000 {
			writeError(w, http.StatusBadRequest, "limit is 1 to 10000")
			return
		}
		limit = n
	}
	recs, err := s.opt.Store.Records(r.Context(), from, int(limit))
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "the store could not be read")
		return
	}
	if recs == nil {
		recs = []store.Record{}
	}
	writeJSON(w, http.StatusOK, recs)
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, Health{OK: true})
}

// readyz: the store answers (its head, under ReadyTimeout) and the policy is loaded.
func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), ReadyTimeout)
	defer cancel()
	seq, _, err := s.opt.Store.Head(ctx)
	pol := s.opt.Engine.Policy()
	if err != nil {
		s.log.WarnContext(r.Context(), "readyz: store unreachable", "error", err.Error())
		writeJSON(w, http.StatusServiceUnavailable, Ready{OK: false, Error: "store unreachable", Policy: pol})
		return
	}
	if pol.Bundle == "" {
		writeJSON(w, http.StatusServiceUnavailable, Ready{OK: false, Error: "no policy loaded", Policy: pol})
		return
	}
	// A degraded policy bundle does not make the core unready: the core is one replica that also serves the gate,
	// records and the GitHub App, and a 503 would take it out of its Service. The bundle's own calls are denied
	// (R000) instead; readyz names it.
	var degraded []string
	for _, b := range pol.Bundles {
		if b.Status == "unavailable" {
			degraded = append(degraded, b.Name)
		}
	}
	writeJSON(w, http.StatusOK, Ready{OK: true, Policy: pol, Head: seq, Degraded: degraded})
}

// Health is GET /healthz's answer.
type Health struct {
	OK bool `json:"ok"`
}

// Ready is GET /readyz's answer: the policy bundle and the chain's head seq (-1 empty).
type Ready struct {
	OK     bool             `json:"ok"`
	Error  string           `json:"error,omitempty"`
	Policy decide.PolicyRef `json:"policy"`
	Head   int64            `json:"head"`
	// Degraded names the policy bundles whose sources could not be read (still 200: see readyz).
	Degraded []string `json:"degraded,omitempty"`
}

// ErrorResponse is every refusal of this package's routes.
type ErrorResponse struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) { httpjson.Write(w, status, v) }

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, ErrorResponse{Error: msg})
}

// caller is the authenticated principal and the registered provider it is, or a written refusal (401, 403).
func (s *Server) caller(w http.ResponseWriter, r *http.Request) (authn.Principal, *Provider, bool) {
	p, ok := authn.From(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "a bearer token is required")
		return p, nil, false
	}
	prov := providerFor(s.opt.Providers, p.ID)
	if prov == nil {
		writeError(w, http.StatusForbidden, p.ID+" is not a registered provider")
		return p, nil, false
	}
	return p, prov, true
}

// bodyError maps a decode error to its answer: 413 for an oversized body, else 400.
func bodyError(w http.ResponseWriter, err error) {
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) || errors.Is(err, decide.ErrTooLarge) {
		writeError(w, http.StatusRequestEntityTooLarge, "body too large")
		return
	}
	writeError(w, http.StatusBadRequest, "bad request: "+err.Error())
}

func seqString(n int64) string { return strconv.FormatInt(n, 10) }
