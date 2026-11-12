// Command observe-k8s is Clearance's Kubernetes audit collector (providers/observe-k8s, O-3).
//
//	observe-k8s run [flags]                       the collector: webhook receiver, queue, pipeline, heartbeat, watches, health
//	observe-k8s run --reader eks|gke|aks ...      the same engine reading a managed cluster's audit export from a file
//	observe-k8s policy render [--namespaces a,b]  the kube-apiserver audit policy, rendered and checked
//	observe-k8s policy check <file>               hold a policy to the rule that no Secret body is ever recorded
//	observe-k8s normalize --source eks|gke|aks <file>   a managed source's export as `clearance observe replay` input
//
// `run` holds no secret: its identity on the core is the pod's projected service-account token; its TLS key is the
// server certificate the API server's webhook connects to.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jfillman/clearance/client"
	"github.com/jfillman/clearance/internal/observe/pipeline"
	"github.com/jfillman/clearance/internal/vocab"
	agent "github.com/jfillman/clearance/providers/argocd/agent"
	"github.com/jfillman/clearance/providers/observe-k8s/auditpolicy"
	"github.com/jfillman/clearance/providers/observe-k8s/collector"
	"github.com/jfillman/clearance/providers/observe-k8s/queue"
	"github.com/jfillman/clearance/providers/observe-k8s/readers"
	"github.com/jfillman/clearance/providers/observe-k8s/receiver"
)

var version = "dev"

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func list(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func main() {
	args := os.Args[1:]
	cmd := "run"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "run":
		err = run(args)
	case "policy":
		err = policy(args, os.Stdout)
	case "normalize":
		err = normalize(args, os.Stdout)
	case "version":
		fmt.Println(collector.ProviderName + "/" + version)
	default:
		err = fmt.Errorf("unknown command %q (run, policy, normalize, version)", cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "observe-k8s:", err)
		os.Exit(1)
	}
}

// ---- policy -----------------------------------------------------------------------------------------------------

func policy(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("policy render [--namespaces a,b] | policy check <file>")
	}
	switch args[0] {
	case "render":
		fs := flag.NewFlagSet("policy render", flag.ContinueOnError)
		nss := fs.String("namespaces", "", "the protected namespaces whose desired-state writes are recorded with bodies, comma-separated")
		groups := fs.String("status-groups", "", "API groups whose status writes drop to Metadata (default: the groups the Hangar clusters run)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		b, err := auditpolicy.Render(auditpolicy.Params{ProtectedNamespaces: list(*nss), StatusGroups: list(*groups)})
		if err != nil {
			return err
		}
		_, err = out.Write(b)
		return err
	case "check":
		if len(args) != 2 {
			return errors.New("policy check <file>")
		}
		b, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		p, err := auditpolicy.Parse(b)
		if err != nil {
			return err
		}
		if vs := auditpolicy.Check(p); len(vs) > 0 {
			for _, v := range vs {
				fmt.Fprintln(out, "FAIL:", v)
			}
			return fmt.Errorf("%s records a Secret body", args[1])
		}
		fmt.Fprintf(out, "ok: %s never records a Secret body (%d rules)\n", args[1], len(p.Rules))
		return nil
	}
	return fmt.Errorf("policy %q", args[0])
}

// ---- normalize --------------------------------------------------------------------------------------------------

// normalize turns a managed source's export into the JSON lines `clearance observe replay` reads.
func normalize(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("normalize", flag.ContinueOnError)
	src := fs.String("source", "", "eks, gke or aks")
	scope := fs.String("scope", "managed-1", "the scope (cluster name) to put on each event")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, ok := readers.ByName(*src)
	if !ok || fs.NArg() != 1 {
		return errors.New("normalize --source eks|gke|aks [--scope name] <file>")
	}
	f, err := os.Open(fs.Arg(0))
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	enc := json.NewEncoder(out)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) == "" {
			continue
		}
		evs, err := s.Parse(sc.Bytes())
		if err != nil {
			return err
		}
		items, _, err := receiver.SanitizeItems(toRaw(evs))
		if err != nil {
			return err
		}
		for _, it := range items {
			if err := enc.Encode(pipeline.RawEvent{Provider: pipeline.Kubernetes, Scope: *scope, Raw: it}); err != nil {
				return err
			}
		}
	}
	return sc.Err()
}

func toRaw(b [][]byte) []json.RawMessage {
	out := make([]json.RawMessage, len(b))
	for i := range b {
		out[i] = b[i]
	}
	return out
}

// ---- run --------------------------------------------------------------------------------------------------------

func run(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	var (
		cluster   = fs.String("cluster", env("CLEARANCE_CLUSTER", ""), "the cluster's name: the scope of every record (the Argo CD agent's cluster name)")
		coreURL   = fs.String("core-url", env("CLEARANCE_CORE_URL", ""), "the core's URL (records, break-glass windows)")
		tokenFile = fs.String("token-file", env("CLEARANCE_TOKEN_FILE", "/var/run/secrets/tokens/clearance"), "the projected service-account token, audience clearance")
		rulesFile = fs.String("rules", env("OBSERVE_RULES", ""), "the observation rule set (clearance.observe-rules/v1): scopes, identities, noise, attribution")
		dataDir   = fs.String("data-dir", env("OBSERVE_DATA_DIR", "/var/lib/observe-k8s"), "the volume the durable queue lives on")
		maxBytes  = fs.Int64("queue-max-bytes", 1<<30, "refuse batches (503) when the unhandled queue would pass this")
		listen    = fs.String("listen", env("OBSERVE_LISTEN", ":8443"), "the audit webhook's TLS listener")
		health    = fs.String("health-listen", env("OBSERVE_HEALTH_LISTEN", ":8080"), "plain HTTP /healthz and /readyz for the kubelet (no audit data)")
		tlsCert   = fs.String("tls-cert", env("OBSERVE_TLS_CERT", "/etc/observe-k8s/tls/tls.crt"), "the webhook's server certificate")
		tlsKey    = fs.String("tls-key", env("OBSERVE_TLS_KEY", "/etc/observe-k8s/tls/tls.key"), "its key")
		clientCA  = fs.String("client-ca", env("OBSERVE_CLIENT_CA", "/etc/observe-k8s/tls/ca.crt"), "the CA that signed the API server's client certificate")
		allowed   = fs.String("allowed-client", env("OBSERVE_ALLOWED_CLIENT", ""), "the names (CN or DNS SAN) the API server's client certificate may carry, comma-separated (required)")
		source    = fs.String("source", env("OBSERVE_SOURCE", ""), "source.name (default k8s-audit-webhook; with --reader, the reader's)")
		reader    = fs.String("reader", env("OBSERVE_READER", ""), "read a managed cluster's export instead of serving the webhook: eks, gke or aks")
		readFile  = fs.String("reader-file", env("OBSERVE_READER_FILE", ""), "with --reader: the JSON-lines file the cloud's audit export is appended to")
		latency   = fs.Duration("latency", 0, "with --reader: how far behind the cluster the source is (default the reader's own)")
		pollEvery = fs.Duration("poll-interval", 15*time.Second, "with --reader: how often the export is read")
		namespace = fs.String("namespace", env("POD_NAMESPACE", ""), "the collector's own namespace")
		saName    = fs.String("service-account", env("POD_SERVICE_ACCOUNT", ""), "the collector's own service account name")
		hbCM      = fs.String("heartbeat-configmap", env("OBSERVE_HEARTBEAT_CONFIGMAP", "clearance-observe-heartbeat"), "the ConfigMap the collector patches to prove the audit path (empty: no heartbeat, only batch arrival is checked)")
		canary    = fs.String("canary-secret", env("OBSERVE_CANARY_SECRET", ""), "an empty Secret the collector patches to prove Secrets are recorded at Metadata (empty: none)")
		policyCM  = fs.String("policy-configmap", env("OBSERVE_POLICY_CONFIGMAP", ""), "namespace/name of a ConfigMap mirroring the live audit policy, to hold to the Secret rule (empty: none)")
		watches   = fs.String("watch", env("OBSERVE_WATCH", ""), "resources to watch, items separated by semicolons: group/version/resource=Kind, with a trailing ,cluster for a cluster-scoped resource (v1/configmaps=ConfigMap;rbac.authorization.k8s.io/v1/clusterroles=ClusterRole,cluster)")
		watchNS   = fs.String("watch-namespaces", env("OBSERVE_WATCH_NAMESPACES", ""), "the namespaces the namespaced watches cover, comma-separated")
		grantAPI  = fs.String("grant-api", env("CLEARANCE_GRANT_API", "clearance.hangar.io/v1"), "the ClearanceGrant CRD's group/version")
		grantsOn  = fs.Bool("grants-enabled", true, "the cluster has the gate, so the ClearanceGrant CRD exists and its grants are listed (false: no gate on this cluster, no grant is listed, only break-glass windows are read)")
		healthEv  = fs.Duration("health-interval", time.Minute, "the health record's interval")
		beatEv    = fs.Duration("heartbeat-interval", 30*time.Second, "how often the heartbeat is written")
		gapGrace  = fs.Duration("gap-grace", 3*time.Minute, "how long a watch change waits for its audit event before it is an audit gap")
		settle    = fs.Duration("grant-settle", 3*time.Minute, "how long a write that names a grant the collector does not know yet waits, and the grants are re-read, before it is decided (negative: decide at once)")
		argoIdx   = fs.Duration("argo-index-timeout", 5*time.Minute, "how long a platform Argo CD controller's write waits for the Application index to sync before it is decided as it stands (negative: never wait)")
		complete  = fs.Bool("completeness-claimed", true, "each observation claims its feed delivered everything (the core checks the claim against health)")
		showVer   = fs.Bool("version", false, "print the version")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVer {
		fmt.Println(collector.ProviderName + "/" + version)
		return nil
	}
	req := map[string]string{"cluster": *cluster, "core-url": *coreURL, "rules": *rulesFile, "namespace": *namespace}
	if *reader == "" {
		req["allowed-client"] = *allowed
	} else {
		req["reader-file"] = *readFile
	}
	for k, v := range req {
		if v == "" {
			return fmt.Errorf("--%s is required", k)
		}
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	rulesB, err := os.ReadFile(*rulesFile)
	if err != nil {
		return err
	}
	rs, err := pipeline.Load(rulesB)
	if err != nil {
		return fmt.Errorf("the rule set: %w", err)
	}
	grants := agent.DefaultGrantAPI
	g, v, ok := strings.Cut(*grantAPI, "/")
	if !ok {
		return errors.New("--grant-api is <group>/<version>")
	}
	grants.Group, grants.Version = g, v
	argoKube, err := agent.InCluster(grants, "argocd")
	if err != nil {
		return err
	}
	kube, err := collector.InCluster()
	if err != nil {
		return err
	}
	tok := client.FileToken(*tokenFile)
	cc, err := client.New(client.Options{BaseURL: *coreURL, Token: tok, Provider: collector.ProviderName, Timeout: 10 * time.Second,
		UserAgent: collector.ProviderName + "/" + version})
	if err != nil {
		return err
	}
	core := &agent.HTTPCore{Client: cc, Feeds: agent.HTTPFeeds{Base: *coreURL, Token: tok}}
	lookups := &collector.Lookups{Cluster: *cluster, BG: core}
	if *grantsOn {
		lookups.Grants = argoKube // a nil Grants is an explicit "no gate here"; a typed nil would not be
	}
	pipe := pipeline.New(rs, lookups, vocab.Default())

	cfg := collector.Config{Cluster: *cluster, Source: *source, Webhook: *reader == "", CompletenessClaimed: *complete,
		Namespace: *namespace, ServiceAccount: *saName, HeartbeatCM: *hbCM, CanarySecret: *canary, PolicyCM: *policyCM,
		HealthInterval: *healthEv, HeartbeatInterval: *beatEv, GapGrace: *gapGrace, GrantSettle: *settle, ArgoIndexTimeout: *argoIdx, WatchNS: list(*watchNS), Log: log}
	cfg.Watches, err = parseWatches(*watches)
	if err != nil {
		return err
	}

	dir := filepath.Join(*dataDir, "webhook")
	var src readers.Source
	if *reader != "" {
		var found bool
		if src, found = readers.ByName(*reader); !found {
			return fmt.Errorf("--reader is eks, gke or aks")
		}
		cfg.Source, cfg.Latency = src.Name, src.Latency
		if *latency > 0 {
			cfg.Latency = *latency
		}
		dir = filepath.Join(*dataDir, src.Name)
	} else if cfg.Source == "" {
		cfg.Source = "k8s-audit-webhook"
	}
	q, err := queue.Open(dir, queue.Options{MaxBytes: *maxBytes})
	if err != nil {
		return fmt.Errorf("the queue in %s: %w", dir, err)
	}
	defer q.Close()

	deps := collector.Deps{Queue: q, Pipeline: pipe, Core: core, Lookups: lookups, Kube: kube,
		Policy: func(raw []byte) ([]string, error) {
			p, err := auditpolicy.Parse(raw)
			if err != nil {
				return nil, err
			}
			return auditpolicy.Check(p), nil
		}}
	var rcv *receiver.Receiver
	if *reader == "" {
		if rcv, err = receiver.New(receiver.Config{Sink: q, AllowedClients: list(*allowed), Log: log}); err != nil {
			return err
		}
		deps.Delivery = func() time.Time { return rcv.Status().LastBatch }
	} else {
		deps.Kube = nil // a reader has no heartbeat, no policy mirror and no watches
		cfg.Watches = nil
	}
	c, err := collector.New(cfg, deps)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 3)
	if rcv != nil {
		tc, err := receiver.ServerTLS(*tlsCert, *tlsKey, *clientCA)
		if err != nil {
			return err
		}
		mux := http.NewServeMux()
		mux.Handle("/audit", rcv)
		srv := &http.Server{Addr: *listen, Handler: mux, TLSConfig: tc, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: time.Minute,
			WriteTimeout: time.Minute, MaxHeaderBytes: 1 << 16}
		go func() { errc <- srv.ListenAndServeTLS("", "") }()
		go func() {
			<-ctx.Done()
			sc, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = srv.Shutdown(sc)
		}()
	}
	hmux := http.NewServeMux()
	hmux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200); _, _ = w.Write([]byte("ok")) })
	hmux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200); _, _ = w.Write([]byte("ok")) })
	hsrv := &http.Server{Addr: *health, Handler: hmux, ReadHeaderTimeout: 5 * time.Second}
	go func() { errc <- hsrv.ListenAndServe() }()
	go func() { <-ctx.Done(); _ = hsrv.Close() }()

	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	go c.RunHealth(ctx)
	go c.RunFlush(ctx)
	if *reader == "" {
		go c.RunHeartbeat(ctx)
		go c.RunWatches(ctx)
	} else {
		go pollLoop(ctx, log, src, readers.FileFetcher{Path: *readFile}, q, readers.FileCursor{Path: filepath.Join(dir, "reader.cursor")}, *pollEvery)
	}
	log.Info("observe-k8s started", "cluster", *cluster, "source", cfg.Source, "version", version)
	select {
	case <-ctx.Done():
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			stop()
			<-done
			return err
		}
	}
	<-done
	return nil
}

func pollLoop(ctx context.Context, log *slog.Logger, src readers.Source, f readers.Fetcher, q *queue.Queue, cur readers.Cursors, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if n, err := readers.Poll(ctx, src, f, q, cur); err != nil {
			log.Error("reading the export", "source", src.Name, "err", err)
		} else if n > 0 {
			log.Info("read audit events", "source", src.Name, "events", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// parseWatches reads --watch: items separated by ";" -- group/version/resource=Kind, with ",cluster" for a
// cluster-scoped resource, e.g. "apps/v1/deployments=Deployment;rbac.authorization.k8s.io/v1/clusterroles=ClusterRole,cluster".
func parseWatches(s string) ([]collector.WatchSpec, error) {
	var out []collector.WatchSpec
	for _, item := range strings.Split(s, ";") {
		if item = strings.TrimSpace(item); item == "" {
			continue
		}
		w, err := collector.ParseWatch(item)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, nil
}
