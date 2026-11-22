// Command grant-expiry is the Argo CD gate's grant-expiry webhook (providers/argocd/grantexpiry, I-44): a
// ValidatingWebhook beside the admission policy that refuses an Argo CD write a ClearanceGrant lists only in expired
// entries, on its own clock. It reads the active grants (list and watch, nothing else), holds no Clearance credential
// and writes nothing to the cluster. Settings are flags, each defaulting to an environment variable.
package main

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jfillman/clearance/internal/tlsutil"
	agent "github.com/jfillman/clearance/providers/argocd/agent"
	"github.com/jfillman/clearance/providers/argocd/grantexpiry"
)

var version = "dev"

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// rootsOnly is a pool of exactly the certificates in caFile (an API server's own CA, not the system roots too).
func rootsOnly(caFile string) (*x509.CertPool, error) {
	b, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("%s holds no PEM certificate", caFile)
	}
	return pool, nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "grant-expiry:", err)
		os.Exit(1)
	}
}

func run() error {
	fs := flag.NewFlagSet("grant-expiry", flag.ContinueOnError)
	var (
		mode      = fs.String("mode", env("CLEARANCE_GRANT_EXPIRY_MODE", "audit"), "audit (always allow; warn and annotate what enforce would refuse) or enforce (refuse)")
		argoUser  = fs.String("argocd-user", env("CLEARANCE_ARGOCD_USER", "system:serviceaccount:argocd:argocd-application-controller"), "the Argo CD application controller's username, as the admission policy's matchConditions name it")
		skew      = fs.Duration("skew", 0, "a grant entry stays live this long past its expiresAt (clock-skew allowance; default 0, none)")
		grantGV   = fs.String("grant-api", env("CLEARANCE_GRANT_API", "clearance.hangar.io/v1"), "the ClearanceGrant CRD's group/version")
		listen    = fs.String("listen", env("CLEARANCE_GRANT_EXPIRY_LISTEN", ":8443"), "the https address the API server calls (POST /validate)")
		probe     = fs.String("probe-listen", env("CLEARANCE_GRANT_EXPIRY_PROBE_LISTEN", ":8080"), "plain http for the kubelet and Prometheus: /healthz, /readyz, /metrics (no admission)")
		certFile  = fs.String("tls-cert-file", env("CLEARANCE_TLS_CERT_FILE", "/etc/clearance/tls/tls.crt"), "the serving certificate (re-read when it changes)")
		keyFile   = fs.String("tls-key-file", env("CLEARANCE_TLS_KEY_FILE", "/etc/clearance/tls/tls.key"), "the serving key")
		maxAge    = fs.Duration("max-cache-age", 10*time.Minute, "the cache is not synced (not Ready; enforce refuses) when the API server has not been heard from for this long")
		waitImage = fs.String("wait-image", env("CLEARANCE_WAIT_IMAGE", ""), "the pinned image of the gate's PreSync wait Job, as the admission policy's exemption has it (empty: no exemption)")
		waitURL   = fs.String("wait-url", env("CLEARANCE_WAIT_URL", ""), "the core URL the wait Job polls, as the exemption pins it")
		waitPrev  = fs.String("wait-previous-url", env("CLEARANCE_WAIT_PREVIOUS_URL", ""), "the previous core URL the exemption admits for one release (empty: none)")
		waitAlias = fs.String("wait-host-alias", env("CLEARANCE_WAIT_HOST_ALIAS", ""), "the wait Job's host alias, ip=host[,host] (empty: none)")
		waitCA    = fs.String("wait-ca-configmap", env("CLEARANCE_WAIT_CA_CONFIGMAP", ""), "the ConfigMap the wait Job mounts as its CA (empty: none)")
		kubeAPI   = fs.String("kube-api", "", "out of a cluster only (tests): the API server's URL; empty: the pod's own cluster")
		kubeToken = fs.String("kube-token-file", "", "with --kube-api: a file holding the bearer token")
		kubeCA    = fs.String("kube-ca-file", "", "with --kube-api: the API server's CA (PEM)")
		drain     = fs.Duration("shutdown-delay", 5*time.Second, "on SIGTERM, keep answering this long (not Ready) while the API server drops the pod's endpoint, then stop")
		showVer   = fs.Bool("version", false, "print the version")
	)
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}
	if *showVer {
		fmt.Println("grant-expiry/" + version)
		return nil
	}
	m, err := grantexpiry.ParseMode(*mode)
	if err != nil {
		return err
	}
	if *maxAge <= grantexpiry.WatchDeadline {
		return fmt.Errorf("--max-cache-age must be longer than %s: a healthy watch can be silent that long", grantexpiry.WatchDeadline)
	}
	if *waitImage != "" && *waitURL == "" {
		return errors.New("--wait-url is required with --wait-image")
	}
	grants := agent.DefaultGrantAPI
	if g, v, ok := strings.Cut(*grantGV, "/"); ok {
		grants.Group, grants.Version = g, v
	} else {
		return fmt.Errorf("--grant-api is <group>/<version>")
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil)).With("component", "grant-expiry", "version", version)
	var kube *agent.API
	if *kubeAPI == "" {
		if kube, err = agent.InCluster(grants, ""); err != nil {
			return err
		}
	} else {
		if *kubeToken == "" || *kubeCA == "" {
			return errors.New("--kube-api needs --kube-token-file and --kube-ca-file")
		}
		tc, err := tlsutil.ClientConfig(*kubeCA)
		if err != nil {
			return err
		}
		tc.RootCAs, err = rootsOnly(*kubeCA)
		if err != nil {
			return err
		}
		kube = &agent.API{Base: *kubeAPI, TokenFile: *kubeToken, Client: &http.Client{Transport: &http.Transport{TLSClientConfig: tc}}, Grants: grants}
	}
	tlsSrv, err := tlsutil.NewServer(*certFile, *keyFile)
	if err != nil {
		return err
	}
	cache := grantexpiry.NewCache(kube, *maxAge, nil, log)
	metrics := grantexpiry.NewMetrics(cache.All, m)
	metrics.SetSynced(cache.Synced)
	h, err := grantexpiry.NewHandler(grantexpiry.Config{Mode: m, ArgoCDUser: *argoUser, Skew: *skew,
		Pins: grantexpiry.Pins{WaitPin: agent.WaitPin{Image: *waitImage, URL: *waitURL, HostAlias: *waitAlias, CAConfigMap: *waitCA},
			PreviousURL: *waitPrev}}, cache, metrics, log)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go cache.Run(ctx, 2*time.Second)

	admit := http.NewServeMux()
	admit.Handle("/validate", h)
	probes := http.NewServeMux()
	probes.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
	var stopping atomic.Bool
	probes.Handle("/readyz", grantexpiry.Ready(m, func() bool { return !stopping.Load() && cache.Synced() }))
	probes.Handle("/metrics", metrics)

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: admit, TLSConfig: tlsSrv.Config(), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}
	psrv := &http.Server{Addr: *probe, Handler: probes, ReadHeaderTimeout: 5 * time.Second}
	errc := make(chan error, 2)
	go func() { errc <- srv.ServeTLS(ln, "", "") }()
	go func() { errc <- psrv.ListenAndServe() }()
	log.Info("serving", "mode", m, "listen", *listen, "probe", *probe, "skew", skew.String())
	select {
	case <-ctx.Done():
		// Terminating: report not Ready and keep answering until the endpoint is gone, so a call in flight under
		// failurePolicy Fail is not refused for want of a server.
		stopping.Store(true)
		time.Sleep(*drain)
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(sctx)
	_ = psrv.Shutdown(sctx)
	return nil
}
