// Command cmpsmoke-stub is the fake Clearance core for tools/cmp-smoke.sh: it answers POST /v1/clearances as a
// cleared change and appends every request body, one JSON document per line, to the file given with -log. It exists
// so the smoke test can run the built clearance-cmp image against something that speaks the register call, with no
// database and no policy: the test is about the plugin image, not the core.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:0", "address to listen on")
	logPath := flag.String("log", "", "file the register requests are appended to (one JSON document per line)")
	portFile := flag.String("port-file", "", "file the chosen port is written to once the stub is listening")
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
	var mu sync.Mutex
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/clearances", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		var req map[string]any
		if err != nil || json.Unmarshal(body, &req) != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		req["_authorization"] = r.Header.Get("Authorization") == "Bearer smoke-token" // that the fixture token was sent as a bearer, never its value
		line, _ := json.Marshal(req)
		mu.Lock()
		f, ferr := os.OpenFile(*logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if ferr == nil {
			f.Write(append(line, '\n'))
			f.Close()
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"id": "chg-smoke", "app": req["app"], "env": req["env"], "cluster": req["cluster"], "repo": req["repo"],
			"head": req["head"], "tree_digest": req["tree_digest"], "state": "cleared", "tier": 1,
			"outage": "allow-and-record", "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano),
		})
	})
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
