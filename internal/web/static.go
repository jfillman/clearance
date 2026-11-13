package web

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

// The UI bundle is whatever sits in internal/web/static when the binary is built. The committed placeholder says
// the bundle is not built in; the shell app's build output (WEB-3) replaces the directory's contents before
// `go build` (docs/web.md, "Building the bundle in"). Nothing else in this package knows what the bundle holds,
// beyond this: index.html is the entry, files under assets/ have content-hashed names.
//
//go:embed all:static
var embedded embed.FS

func bundle() (fs.FS, error) { return fs.Sub(embedded, "static") }

// serveStatic serves the bundle: hashed assets cached for a year, everything else revalidated (index.html above
// all), and an unknown path without a file extension falls back to index.html for the client-side router. The entry
// page needs a session, so a person without one is sent to sign in first; assets are public (they hold nothing
// secret) so they load while that redirect is in flight.
func (s *Server) serveStatic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if name == "" {
		name = "index.html"
	}
	b, err := fs.ReadFile(s.static, name)
	if err != nil {
		if path.Ext(name) != "" {
			http.NotFound(w, r)
			return
		}
		name = "index.html"
		if b, err = fs.ReadFile(s.static, name); err != nil {
			http.NotFound(w, r)
			return
		}
	}
	if name == "index.html" {
		if _, _, ok := s.sessionFrom(r); !ok {
			ret := r.URL.Path
			if r.URL.RawQuery != "" {
				ret += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, "/auth/login?return="+url.QueryEscape(safeReturn(ret)), http.StatusFound)
			return
		}
	}
	sum := sha256.Sum256(b)
	w.Header().Set("ETag", `"`+hex.EncodeToString(sum[:8])+`"`)
	if strings.HasPrefix(name, "assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(b))
}
