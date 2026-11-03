package authn

import (
	"log/slog"
	"net/http"
	"strings"
)

// Bearer is the request's bearer token: an Authorization header that starts "Bearer " (any case) and has a
// non-blank token after it ("" otherwise), as server.py's _bearer.
func Bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) < 7 || !strings.EqualFold(h[:7], "bearer ") {
		return ""
	}
	return strings.TrimSpace(h[7:])
}

// Middleware authenticates every request skip does not exempt (the caller exempts /v1/github/webhook, which GitHub
// signs, and /healthz and /readyz) and puts the Principal on its context. No token is 401
// {"error":"a bearer token is required"}; a refused one is 401 {"error":"token not accepted"}, the two answers the
// Python routes gave. Why a token was refused goes to the log at debug, never the token.
func Middleware(a Authenticator, skip func(*http.Request) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if skip != nil && skip(r) {
				next.ServeHTTP(w, r)
				return
			}
			token := Bearer(r)
			if token == "" {
				unauthorized(w, `{"error":"a bearer token is required"}`)
				return
			}
			p, err := a.Authenticate(r.Context(), token)
			if err != nil {
				slog.DebugContext(r.Context(), "token refused", "reason", err.Error(), "path", r.URL.Path)
				unauthorized(w, `{"error":"token not accepted"}`)
				return
			}
			next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
		})
	}
}

func unauthorized(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(body))
}
