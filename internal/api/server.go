// Package api is clearance-api: Clearance's read API (docs/clearance-api.md), `clearance api` of the one binary.
// A separate, read-only process: it reads what the core committed to Postgres (the evidence chain, the deployment
// gate's changes, the stored definitions) through pg.OpenReader with its own read-only role and DSN, never the
// writer's lock, so reads never queue behind decisions and the API runs as many replicas as it needs. It writes
// nothing.
//
// Ported from clearance api.py and the serving logic in autopilot's api_serve.py, for Clearance's own reads:
// evidence (filters, the seq cursor, the chain check, counts), receipts and provenance verdicts, the gate's
// changes and its policy, the decision policy as data and the dry-run explainer, and the definitions. The
// runtime's reads (sessions, runs, agents with their holds, the human inbox, trigger history, results, the runtime
// catalog) are the Autopilot gateway's own read API after R-3. Paths, query parameters, answers and status codes of
// every route kept are api.py's (docs/clearance-api.md lists the differences).
//
// Every request: GET only, no body read, every query parameter checked against the route's list (an unknown or a
// repeated one is 400), a bearer token for every route but /healthz, /readyz and /v1/contract, JSON errors
// {"error": ...}, one access-log line without the query, headers or tokens, panics recovered to a bare 500, and a
// deadline on the handler. Every record served goes through evidence.Project, with its assurance beside it.
package api

import (
	"context"
	"errors"
	"fmt"
	"github.com/jfillman/clearance/internal/vocab"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/authn"
	"github.com/jfillman/clearance/internal/decide"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/httpjson"
)

// Limits (api.py).
const (
	MaxLimit        = 200
	DefaultLimit    = 50
	MaxExplainArgs  = 16 << 10
	ReadyTimeout    = 2 * time.Second
	MaxHeaderBytes  = 64 << 10
	MaxRequestBody  = 0 // GET only: a body is never read
	HandlerTimeout  = 25 * time.Second
	ReadHeaderLimit = 5 * time.Second
	ReadTimeout     = 10 * time.Second
	WriteTimeout    = 30 * time.Second
	IdleTimeout     = 120 * time.Second
)

// Options are what the API serves. Store, Auth and Access are required; a nil Engine serves no policy (/v1/policy
// and the explainer answer 404), a nil GatePolicy no gate policy, a nil Definitions no definitions.
type Options struct {
	Store       Store
	Auth        authn.Authenticator
	Access      *Access
	Engine      *decide.Engine
	GatePolicy  *gate.PolicyView
	Definitions *Definitions
	// GatewayURL and CoreURL are where writes go, named in /v1/contract.
	GatewayURL, CoreURL string
	Clock               func() time.Time
	Log                 *slog.Logger
}

// Server is the read API. Build it with New.
type Server struct {
	opt     Options
	log     *slog.Logger
	handler http.Handler
}

// New builds the server.
func New(opt Options) (*Server, error) {
	if opt.Store == nil || opt.Auth == nil || opt.Access == nil {
		return nil, errors.New("api: Store, Auth and Access are required")
	}
	if opt.Clock == nil {
		opt.Clock = time.Now
	}
	if opt.Log == nil {
		opt.Log = slog.Default()
	}
	s := &Server{opt: opt, log: opt.Log}
	mux := http.NewServeMux()
	for _, rt := range Routes() {
		if rt.serve == nil {
			rt.serve = (*Server).getContract
		}
		mux.HandleFunc(rt.Method+" "+rt.Path, s.endpoint(rt))
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, Health{OK: true}) })
	mux.HandleFunc("GET /readyz", s.readyz)
	mux.HandleFunc("/", notFound)
	s.handler = s.recoverer(s.accessLog(noBody(mux)))
	return s, nil
}

// Handler is the whole API with its middleware.
func (s *Server) Handler() http.Handler { return s.handler }

// HTTPServer is an http.Server on addr with every timeout set.
func (s *Server) HTTPServer(addr string) *http.Server {
	return &http.Server{
		Addr: addr, Handler: s.handler,
		ReadHeaderTimeout: ReadHeaderLimit, ReadTimeout: ReadTimeout, WriteTimeout: WriteTimeout,
		IdleTimeout: IdleTimeout, MaxHeaderBytes: MaxHeaderBytes,
		ErrorLog: slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
}

// apiError is a refusal: a status and the message of its {"error": ...} body.
type apiError struct {
	status int
	msg    string
}

func errorf(status int, format string, a ...any) *apiError {
	return &apiError{status, fmt.Sprintf(format, a...)}
}

func writeJSON(w http.ResponseWriter, status int, v any) { httpjson.Write(w, status, v) }

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, ErrorBody{Error: msg})
}

func (e *apiError) write(w http.ResponseWriter) { writeError(w, e.status, e.msg) }

// readFailed is a store failure: 503, the cause logged and never sent (api.py: "read failed: <class>").
func (s *Server) readFailed(w http.ResponseWriter, r *http.Request, err error) {
	s.log.ErrorContext(r.Context(), "read failed", "path", r.URL.Path, "error", err.Error())
	writeError(w, http.StatusServiceUnavailable, "read failed")
}

// endpoint wraps a route: authenticate (but /v1/contract), resolve the viewer, check the role and the query.
func (s *Server) endpoint(rt Route) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var v *Viewer
		if !in(rt.Roles, RoleAny) {
			token := authn.Bearer(r)
			if token == "" {
				writeError(w, http.StatusUnauthorized, "a bearer token is required")
				return
			}
			p, err := s.opt.Auth.Authenticate(r.Context(), token)
			if err != nil {
				s.log.DebugContext(r.Context(), "token refused", "reason", err.Error(), "path", r.URL.Path)
				writeError(w, http.StatusUnauthorized, "token not accepted")
				return
			}
			notePrincipal(r, p.ID)
			var aerr *apiError
			if v, aerr = s.opt.Access.Viewer(r.Context(), p, r.Header.Get(vocab.Get().OnBehalfOfHeader)); aerr != nil {
				aerr.write(w)
				return
			}
			if role := v.role(); !allowed(role, rt.Roles) {
				writeError(w, http.StatusForbidden, fmt.Sprintf("a %s may not call %s", role, rt.OperationID))
				return
			}
		}
		if aerr := checkQuery(r.URL.RawQuery, rt.Params); aerr != nil {
			aerr.write(w)
			return
		}
		rt.serve(s, w, r, v)
	}
}

// checkQuery refuses a query that does not parse, names a parameter the route does not take, or repeats one.
func checkQuery(raw string, params []string) *apiError {
	vals, err := url.ParseQuery(raw)
	if err != nil {
		return errorf(400, "the query does not parse")
	}
	for k, vs := range vals {
		if !in(params, k) {
			return errorf(400, "unknown query parameter %q", k)
		}
		if len(vs) > 1 {
			return errorf(400, "%s is given more than once", k)
		}
	}
	return nil
}

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), ReadyTimeout)
	defer cancel()
	if err := s.opt.Store.Ping(ctx); err != nil {
		s.log.WarnContext(r.Context(), "readyz: store unreachable", "error", err.Error())
		writeJSON(w, http.StatusServiceUnavailable, Ready{OK: false, Error: "store unreachable"})
		return
	}
	// A degraded policy bundle leaves the api ready (200): only /v1/policy and the explainer read the policy, and
	// they show the bundle's state. readyz names it.
	var degraded []string
	if s.opt.Engine != nil {
		for _, b := range s.opt.Engine.Policy().Bundles {
			if b.Status == "unavailable" {
				degraded = append(degraded, b.Name)
			}
		}
	}
	writeJSON(w, http.StatusOK, Ready{OK: true, Degraded: degraded})
}

// notFound answers what no route matched: 405 for a known path asked with another method, else 404.
func notFound(w http.ResponseWriter, r *http.Request) {
	for _, p := range append([]string{"/healthz", "/readyz"}, paths()...) {
		if pathMatches(p, r.URL.Path) {
			w.Header().Set("Allow", "GET, HEAD")
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
	}
	writeError(w, http.StatusNotFound, "not found")
}

func paths() []string {
	out := make([]string, 0, len(routeTable))
	for _, rt := range routeTable {
		out = append(out, rt.Path)
	}
	return out
}

// pathMatches reports whether path fits pattern, a {name} segment matching any one non-empty segment.
func pathMatches(pattern, path string) bool {
	want, got := strings.Split(pattern, "/"), strings.Split(path, "/")
	if len(want) != len(got) {
		return false
	}
	for i := range want {
		if strings.HasPrefix(want[i], "{") {
			if got[i] == "" {
				return false
			}
		} else if want[i] != got[i] {
			return false
		}
	}
	return true
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

type principalBox struct{ id string }

type boxKey struct{}

func notePrincipal(r *http.Request, id string) {
	if box, ok := r.Context().Value(boxKey{}).(*principalBox); ok {
		box.id = id
	}
}

// accessLog writes one line per request: method, path (never the query: explain's args are in it), status,
// bytes, duration and the principal. No body, no header, no token. It also sets the handler's deadline.
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

// noBody refuses a request that declares a body (every route is a GET) and never reads one.
func noBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > MaxRequestBody {
			writeError(w, http.StatusRequestEntityTooLarge, "body too large")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBody)
		next.ServeHTTP(w, r)
	})
}
