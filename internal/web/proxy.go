package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

// The forwarding: /api/read/* to clearance-api, /api/write/* to the core, /api/gateway/* to the agent gateway,
// each with the person's own ID token as the bearer. Nothing a browser sends is trusted to carry identity: the
// outbound request is built fresh from an allowlist of headers, so the inbound Authorization, Cookie and every other
// header are dropped.

// forwardHeaders are the only request headers that cross.
var forwardHeaders = []string{"Accept", "Accept-Language", "Content-Type", "Last-Event-ID", "Idempotency-Key"}

// reauthHeader tells the page the core wants a fresh login and where to send the person.
const reauthHeader = "X-Clearance-Reauth"

// freshRule is the rule the core answers with when a write needs a fresher login than the token shows.
const freshRule = "auth-not-fresh"

type ctxKey struct{}

type proxy struct {
	rp    *httputil.ReverseProxy
	write bool // every call carries X-Clearance-Via: web (the core's writes), else only non-safe methods do
}

type call struct {
	token   string
	ret     string // where to return after a fresh login
	freshMA time.Duration
}

// newProxy forwards to target. write marks the core (every call carries the via header).
func (s *Server) newProxy(target *url.URL, write bool) *proxy {
	tr := &http.Transport{
		Proxy:                 nil, // egress is to the three configured upstreams only; never an ambient HTTP(S)_PROXY
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: s.cfg.RequestTimeout,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
	}
	p := &proxy{write: write}
	p.rp = &httputil.ReverseProxy{
		Transport:     tr,
		FlushInterval: -1, // an event stream is passed through as it arrives
		Rewrite: func(pr *httputil.ProxyRequest) {
			c, _ := pr.In.Context().Value(ctxKey{}).(*call)
			up, _ := pr.In.Context().Value(pathKey{}).(string)
			out := pr.Out
			out.URL.Scheme, out.URL.Host = target.Scheme, target.Host
			out.URL.Path, out.URL.RawPath = strings.TrimRight(target.Path, "/")+up, ""
			out.URL.RawQuery = pr.In.URL.RawQuery
			out.Host = target.Host
			h := make(http.Header, 8)
			for _, k := range forwardHeaders {
				if v := pr.In.Header.Values(k); len(v) > 0 {
					h[k] = []string{v[0]}
				}
			}
			h.Set("Authorization", "Bearer "+c.token)
			h.Set("User-Agent", "clearance-web/"+s.version)
			switch pr.In.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions:
				if p.write {
					h.Set("X-Clearance-Via", "web")
				}
			default:
				h.Set("X-Clearance-Via", "web")
			}
			out.Header = h
		},
		ModifyResponse: func(resp *http.Response) error { return s.modifyResponse(resp) },
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			var mbe *http.MaxBytesError
			switch {
			case errors.As(err, &mbe):
				jsonError(w, http.StatusRequestEntityTooLarge, "too_large", "request body too large")
			case errors.Is(err, context.DeadlineExceeded):
				jsonError(w, http.StatusGatewayTimeout, "timeout", "upstream timed out")
			case errors.Is(err, context.Canceled):
				// the browser went away; nothing to say
			default:
				s.log.Warn("upstream call failed", "path", r.URL.Path, "err", err.Error())
				jsonError(w, http.StatusBadGateway, "upstream", "upstream unavailable")
			}
		},
	}
	return p
}

type pathKey struct{}

// forward is the handler of one prefix: session, CSRF, limits, then the proxy.
func (s *Server) forward(prefix string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		px := s.proxies[prefix]
		_, sess, ok := s.sessionFrom(r)
		if !ok {
			jsonError(w, http.StatusUnauthorized, "unauthenticated", "sign in")
			return
		}
		switch {
		case prefix == "/api/read/" && r.Method != http.MethodGet && r.Method != http.MethodHead:
			jsonError(w, http.StatusMethodNotAllowed, "method", "reads are GET")
			return
		case prefix == "/api/write/" && (r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions):
			jsonError(w, http.StatusMethodNotAllowed, "method", "writes are not GET")
			return
		}
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		default:
			jsonError(w, http.StatusMethodNotAllowed, "method", "method not allowed")
			return
		}
		if !s.checkCSRF(w, r, sess) {
			return
		}
		up, ok := upstreamPath(prefix, r.URL.Path, r.URL.EscapedPath())
		if !ok {
			jsonError(w, http.StatusBadRequest, "path", "bad path")
			return
		}
		if r.ContentLength > s.cfg.MaxBodyBytes {
			jsonError(w, http.StatusRequestEntityTooLarge, "too_large", "request body too large")
			return
		}
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
		}
		stream := strings.Contains(r.Header.Get("Accept"), "text/event-stream") || strings.HasSuffix(up, "/stream")
		var ctx context.Context
		var cancel context.CancelFunc
		if stream {
			// A stream has no overall timeout but ends when the session does.
			ctx, cancel = context.WithDeadline(r.Context(), sess.Expires)
		} else {
			ctx, cancel = context.WithTimeout(r.Context(), s.cfg.RequestTimeout)
		}
		defer cancel()
		ctx = context.WithValue(ctx, ctxKey{}, &call{token: sess.Token, freshMA: s.cfg.FreshMaxAge, ret: refererReturn(r, s.origin)})
		ctx = context.WithValue(ctx, pathKey{}, up)
		px.rp.ServeHTTP(w, r.WithContext(ctx))
	}
}

// refererReturn is the same-origin path of the page that made the call, for returning there after a fresh login.
func refererReturn(r *http.Request, origin string) string {
	ref := r.Header.Get("Referer")
	if !strings.HasPrefix(ref, origin+"/") {
		return "/"
	}
	return safeReturn(strings.TrimPrefix(ref, origin))
}

// upstreamPath is the path after the prefix, for the upstream. It refuses what could climb out of it or hide a
// separator: dot segments, empty segments, backslashes, control characters and encoded slashes or dots.
func upstreamPath(prefix, decoded, escaped string) (string, bool) {
	if !strings.HasPrefix(decoded, prefix) || !strings.HasPrefix(escaped, prefix) {
		return "", false
	}
	rest := "/" + strings.TrimPrefix(decoded, prefix)
	le := strings.ToLower(escaped)
	if strings.Contains(le, "%2f") || strings.Contains(le, "%5c") || strings.Contains(le, "%2e") || strings.Contains(le, "%00") {
		return "", false
	}
	for _, c := range rest {
		if c < 0x20 || c == 0x7f || c == '\\' {
			return "", false
		}
	}
	segs := strings.Split(strings.TrimPrefix(rest, "/"), "/")
	for i, sg := range segs {
		if sg == "." || sg == ".." || (sg == "" && i != len(segs)-1) {
			return "", false
		}
	}
	if rest == "/" {
		return "", false
	}
	return rest, true
}

// modifyResponse makes the upstream's answer safe to hand to the browser, and notices the core's freshness refusal.
func (s *Server) modifyResponse(resp *http.Response) error {
	h := resp.Header
	for k := range h {
		ck := http.CanonicalHeaderKey(k)
		if ck == "Set-Cookie" || ck == "Location" || ck == "Content-Location" || strings.HasPrefix(ck, "Access-Control-") {
			h.Del(k)
		}
	}
	h.Set("Cache-Control", "no-store") // no answer is cached anywhere
	if resp.StatusCode >= 300 && resp.StatusCode < 400 && resp.StatusCode != http.StatusNotModified {
		resp.Body.Close()
		return errors.New("upstream redirected")
	}
	if strings.HasPrefix(h.Get("Content-Type"), "text/event-stream") {
		return nil
	}
	if resp.ContentLength > s.cfg.MaxResponseBytes {
		resp.Body.Close()
		return errors.New("upstream answer too large")
	}
	resp.Body = &limitedBody{r: resp.Body, left: s.cfg.MaxResponseBytes}
	if resp.StatusCode >= 400 && resp.StatusCode < 500 && strings.Contains(h.Get("Content-Type"), "json") {
		c, _ := resp.Request.Context().Value(ctxKey{}).(*call)
		const peek = 64 << 10
		b, _ := io.ReadAll(io.LimitReader(resp.Body, peek+1))
		resp.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(b), resp.Body), resp.Body}
		if len(b) <= peek && c != nil {
			if ma, ok := freshRefusal(b); ok {
				if ma <= 0 || ma > time.Hour {
					ma = c.freshMA
				}
				h.Set(reauthHeader, fmt.Sprintf("/auth/login?reauth=1&max_age=%d&return=%s", int(ma.Seconds()), url.QueryEscape(c.ret)))
			}
		}
	}
	return nil
}

// freshRefusal reports whether body is the core's "the login is not fresh enough" refusal: rule "auth-not-fresh",
// at the top level or one object down (detail, error, context), with an optional max_age in seconds beside it.
func freshRefusal(body []byte) (time.Duration, bool) {
	var top map[string]any
	if json.Unmarshal(body, &top) != nil {
		return 0, false
	}
	var look func(m map[string]any, depth int) (time.Duration, bool)
	look = func(m map[string]any, depth int) (time.Duration, bool) {
		if r, _ := m["rule"].(string); r == freshRule {
			var d time.Duration
			if n, ok := m["max_age"].(float64); ok && n > 0 && n <= 3600 {
				d = time.Duration(n) * time.Second
			}
			return d, true
		}
		if depth == 0 {
			return 0, false
		}
		for _, k := range []string{"detail", "error", "context"} {
			if sub, ok := m[k].(map[string]any); ok {
				if d, ok := look(sub, depth-1); ok {
					return d, true
				}
			}
		}
		return 0, false
	}
	return look(top, 1)
}

// limitedBody errors once the answer is longer than the limit, so the connection is cut rather than truncated quietly.
type limitedBody struct {
	r    io.ReadCloser
	left int64
}

var errTooLarge = errors.New("upstream answer too large")

func (l *limitedBody) Read(p []byte) (int, error) {
	if l.left <= 0 {
		// Probe for one more byte: an answer of exactly the limit is fine.
		var one [1]byte
		if n, _ := l.r.Read(one[:]); n > 0 {
			return 0, errTooLarge
		}
		return 0, io.EOF
	}
	if int64(len(p)) > l.left {
		p = p[:l.left]
	}
	n, err := l.r.Read(p)
	l.left -= int64(n)
	return n, err
}

func (l *limitedBody) Close() error { return l.r.Close() }
