// Command cmpsmoke-stub is the fake Clearance core for tools/cmp-smoke.sh: it answers POST /v1/clearances as a
// cleared change and appends every request body, one JSON document per line, to the file given with -log. It exists
// so the smoke test can run the built clearance-cmp image against something that speaks the register call, with no
// database and no policy: the test is about the plugin image, not the core.
//
// The Argo CD conformance job (tools/cmp-conformance.sh) runs it in a kind cluster as the plugin's core and as the git
// host Argo CD and the plugin fetch from. Each flag it adds is off by default, so the smoke test's stub is unchanged:
//   - -deny APPS: a register call for one of these apps (comma-separated) answers a denied change;
//   - -garble APPS: one for these apps answers 200 with a body that is not a change (a plugin fault on the plugin's side);
//   - -token "": any non-empty bearer token is accepted (the in-cluster plugin sends a projected service-account token);
//   - -git-root DIR: the bare repositories under DIR are served read-only over git's smart HTTP protocol at /git/.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cgi"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// set is a comma-separated list of names, as a lookup.
func set(s string) map[string]bool {
	m := map[string]bool{}
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			m[v] = true
		}
	}
	return m
}

func main() {
	listen := flag.String("listen", "127.0.0.1:0", "address to listen on")
	logPath := flag.String("log", "", "file the register requests are appended to (one JSON document per line)")
	portFile := flag.String("port-file", "", "file the chosen port is written to once the stub is listening")
	token := flag.String("token", "smoke-token", `the bearer token the stub accepts; "" accepts any non-empty one`)
	denyApps := flag.String("deny", "", "apps (comma-separated) whose register call answers a denied change")
	garbleApps := flag.String("garble", "", "apps (comma-separated) whose register call answers 200 with a body that is not a change")
	gitRoot := flag.String("git-root", "", "a directory of bare git repositories to serve read-only over smart HTTP at /git/")
	flag.Parse()
	if *logPath == "" || *portFile == "" {
		fmt.Fprintln(os.Stderr, "cmpsmoke-stub: -log and -port-file are required")
		os.Exit(2)
	}
	l, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cmpsmoke-stub:", err)
		os.Exit(1)
	}
	authorized := func(r *http.Request) bool {
		h := r.Header.Get("Authorization")
		if *token == "" {
			return strings.HasPrefix(h, "Bearer ") && len(h) > len("Bearer ")
		}
		return h == "Bearer "+*token
	}
	deny, garble := set(*denyApps), set(*garbleApps)
	var mu sync.Mutex
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/clearances", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		var req map[string]any
		if err != nil || json.Unmarshal(body, &req) != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		req["_authorization"] = authorized(r) // that the fixture token was sent as a bearer, never its value
		line, _ := json.Marshal(req)
		mu.Lock()
		f, ferr := os.OpenFile(*logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if ferr == nil {
			f.Write(append(line, '\n'))
			f.Close()
		}
		mu.Unlock()
		app, _ := req["app"].(string)
		w.Header().Set("Content-Type", "application/json")
		if garble[app] {
			w.Write([]byte("this is not a change"))
			return
		}
		ch := map[string]any{
			"id": "chg-smoke", "app": req["app"], "env": req["env"], "cluster": req["cluster"], "repo": req["repo"],
			"head": req["head"], "tree_digest": req["tree_digest"], "state": "cleared", "tier": 1,
			"outage": "allow-and-record", "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano),
		}
		if deny[app] {
			ch["id"], ch["state"], ch["deny_reason"] = "chg-denied", "denied", "denied by the test double"
		}
		json.NewEncoder(w).Encode(ch)
	})
	// What `clearance-cmp doctor` reads: /healthz, and an authenticated read of a change that does not exist (the core
	// answers 401 without a bearer token and 404 with one).
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("GET /v1/clearances/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !authorized(r) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"a bearer token is required"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"no such change"}`))
	})
	if *gitRoot != "" {
		git, err := exec.LookPath("git")
		if err != nil {
			fmt.Fprintln(os.Stderr, "cmpsmoke-stub: -git-root needs git:", err)
			os.Exit(1)
		}
		// Fetch only: http-backend refuses a push unless http.receivepack is set, and it is not. safe.directory=* because
		// the repositories belong to whoever built the image, not to the uid serving them.
		mux.Handle("/git/", &cgi.Handler{Path: git, Args: []string{"http-backend"}, Root: "/git", Env: []string{
			"GIT_PROJECT_ROOT=" + *gitRoot, "GIT_HTTP_EXPORT_ALL=1", "HOME=/tmp",
			"GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=safe.directory", "GIT_CONFIG_VALUE_0=*",
		}})
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := os.WriteFile(*portFile, []byte(fmt.Sprint(port)), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "cmpsmoke-stub:", err)
		os.Exit(1)
	}
	if err := http.Serve(l, mux); err != nil {
		fmt.Fprintln(os.Stderr, "cmpsmoke-stub:", err)
		os.Exit(1)
	}
}
