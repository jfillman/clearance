package api

import (
	"context"
	"errors"
	"fmt"
	"github.com/jfillman/clearance/internal/tlsutil"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/attest"
	"github.com/jfillman/clearance/internal/authn"
	"github.com/jfillman/clearance/internal/bundles"
	"github.com/jfillman/clearance/internal/directory/backstage"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/profile"
	"github.com/jfillman/clearance/internal/store/pg"
	"github.com/jfillman/clearance/internal/token"
	"github.com/jfillman/clearance/internal/vocab"
)

// Config is clearance-api's deployment, read by FromEnv:
//
//	CLEARANCE_API_DSN                   the read-only role's DSN (required)
//	CLEARANCE_API_AUDITORS              principal globs, comma-separated: every read, the chain check, full=1
//	CLEARANCE_API_NOTIFIERS             principal globs: the notifier role (every change of the gate: the list, the counts and
//	                                    the stream's clearance events; no token, no evidence)
//	CLEARANCE_API_OBSERVATION_READERS   principal globs: machine pollers that read coverage, observations, observation
//	                                    health and exceptions (whole scope, redacted like a person) and nothing else
//	CLEARANCE_DELEGATES                 principal globs that may name a person in the on-behalf-of header (a portal)
//	CLEARANCE_API_FEED_READERS          <principal glob>=<cluster> pairs, comma-separated: the grant-sync agents
//	                                    that read a cluster's grant feed (cleared changes and their tokens)
//	CLEARANCE_AGENTS_DIR                the bundled agent definitions (*.yaml); the cluster pins come from the
//	                                    core's store (clearance_definitions), refreshed every
//	CLEARANCE_API_DEFINITIONS_INTERVAL  seconds (default 30)
//	CLEARANCE_API_POOL                  Postgres connections per replica (default 5)
//	CLEARANCE_API_COVERAGE_CONCURRENCY  coverage computations in flight at once per replica, 1 to 20 (default 2); a read past
//	                                    it is answered 503 with Retry-After
//	CLEARANCE_API_METRICS_LISTEN        host:port for /metrics (Go runtime memory and the coverage gauges); unset: none (debug.go)
//	CLEARANCE_API_PPROF_LISTEN          a loopback IP literal host:port (127.0.0.1:6060) for the pprof profiles; unset: none; anything else is refused
//	CLEARANCE_API_COVERAGE_WAIT_SECONDS how long a coverage read waits for a slot before the 503, 0 to 10 (default 3; 0 refuses at once)
//	CLEARANCE_API_COVERAGE_CACHE_SECONDS  reuse a coverage answer this many seconds, 0 to 300 (default 0: no cache); a
//	                                    reused answer carries Age and its `to` is when it was computed
//	CLEARANCE_API_ATTEST_KEY            the attestation signing key's public half (PEM) or the core's JWKS: verifies
//	                                    static-key attestations (GET /v1/clearances/{id}/attestation/verify)
//	CLEARANCE_API_ATTEST_TRUST_ROOT     keyless: a Sigstore trusted-root.json, or Fulcio's root and intermediate PEM
//	CLEARANCE_API_ATTEST_IDENTITY, _ISSUER  keyless: the identity and OIDC issuer the certificate must name
//	CLEARANCE_API_ATTEST_REKOR_KEY      keyless with a PEM trust root: Rekor's public key (not with a trusted-root.json)
//	CLEARANCE_API_ATTEST_REKOR_URL      Rekor's public URL, for the portal's "open in Rekor" links
//	CLEARANCE_BUNDLES, CLEARANCE_BUNDLE_SOURCES, CLEARANCE_ENV_*  the policy the core runs (internal/bundles), for
//	                                    /v1/policy and the explainer
//	CLEARANCE_GATEWAY_URL               where the runtime's writes go, named in /v1/contract as gateway
//	CLEARANCE_CORE_URL                  where Clearance's writes go, named in /v1/contract as core
//	BACKSTAGE_URL, BACKSTAGE_TOKEN_FILE the portal's catalog: a person's groups and the apps they own (unset: none)
//	CLEARANCE_LISTEN                    the listen address (the core's name; default :$PORT, PORT default 8080)
//
// and the authenticator's (authn.EnvVars: CLEARANCE_AUDIENCE, CLEARANCE_OIDC_*, CLEARANCE_FOREIGN_*,
// CLEARANCE_GITHUB_OIDC_*) and the deployment's vocabulary (vocab.EnvVars).
// An empty variable is an unset one.
type Config struct {
	DSN                            string
	Listen                         string
	Auditors, Notifiers, Delegates []string
	ObservationReaders             []string
	Admins                         []string // CLEARANCE_ADMINS, for whoami
	FeedReaders                    []FeedReader
	AgentsDir                      string
	DefinitionsEvery               time.Duration
	Pool                           int32
	CoverageConcurrency            int
	CoverageCacheTTL               time.Duration
	CoverageWait                   time.Duration
	MetricsListen, PprofListen     string
	Policy                         bundles.Config
	Vocabulary                     *vocab.Vocabulary // nil: the vocabulary already in force (vocab.Get; tests)
	GatewayURL, CoreURL            string
	// TLS is the optional https listener beside Listen (CLEARANCE_TLS_LISTEN, _CERT_FILE, _KEY_FILE); Listen "off" drops plain http.
	TLS                tlsutil.Listener
	BackstageURL       string
	BackstageTokenFile string
	Auth               authn.Authenticator
	Attest             *AttestTrust // nil: nothing configured, so nothing is verified here
}

func list(v string) []string {
	out := []string{}
	for _, x := range strings.Split(v, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

// FromEnv reads Config from getenv, the authenticator included (authn.FromEnv).
func FromEnv(getenv func(string) string) (Config, error) {
	get := func(k, def string) string {
		if v := getenv(k); v != "" {
			return v
		}
		return def
	}
	cfg := Config{DSN: get("CLEARANCE_API_DSN", ""), AgentsDir: get("CLEARANCE_AGENTS_DIR", ""),
		Auditors: list(get("CLEARANCE_API_AUDITORS", "")), Notifiers: list(get("CLEARANCE_API_NOTIFIERS", "")),
		Delegates: list(get("CLEARANCE_DELEGATES", "")), Admins: list(get("CLEARANCE_ADMINS", "")), ObservationReaders: list(get("CLEARANCE_API_OBSERVATION_READERS", "")),
		GatewayURL: get("CLEARANCE_GATEWAY_URL", ""), CoreURL: get("CLEARANCE_CORE_URL", ""),
		BackstageURL: get("BACKSTAGE_URL", ""), BackstageTokenFile: get("BACKSTAGE_TOKEN_FILE", backstage.DefaultTokenFile)}
	if cfg.DSN == "" {
		return cfg, errors.New("CLEARANCE_API_DSN is required (the read-only role's DSN)")
	}
	var err error
	if cfg.FeedReaders, err = ParseFeedReaders(get("CLEARANCE_API_FEED_READERS", "")); err != nil {
		return cfg, err
	}
	cfg.Listen = get("CLEARANCE_LISTEN", "")
	if cfg.Listen == "" {
		port, err := strconv.Atoi(get("PORT", "8080"))
		if err != nil || port < 1 || port > 65535 {
			return cfg, errors.New("PORT is a port number")
		}
		cfg.Listen = ":" + strconv.Itoa(port)
	}
	if cfg.TLS, err = tlsutil.ListenerFromEnv(getenv, cfg.Listen); err != nil {
		return cfg, err
	}
	secs, err := strconv.ParseFloat(get("CLEARANCE_API_DEFINITIONS_INTERVAL", "30"), 64)
	if err != nil || secs < 1 || secs > 3600 {
		return cfg, errors.New("CLEARANCE_API_DEFINITIONS_INTERVAL is seconds, 1 to 3600")
	}
	cfg.DefinitionsEvery = time.Duration(secs * float64(time.Second))
	pool, err := strconv.Atoi(get("CLEARANCE_API_POOL", "5"))
	if err != nil || pool < 1 || pool > 50 {
		return cfg, errors.New("CLEARANCE_API_POOL is a number of connections, 1 to 50")
	}
	cfg.Pool = int32(pool)
	if cfg.CoverageConcurrency, err = strconv.Atoi(get("CLEARANCE_API_COVERAGE_CONCURRENCY", strconv.Itoa(DefaultCoverageConcurrency))); err != nil ||
		cfg.CoverageConcurrency < 1 || cfg.CoverageConcurrency > 20 {
		return cfg, errors.New("CLEARANCE_API_COVERAGE_CONCURRENCY is a number of computations, 1 to 20")
	}
	cfg.MetricsListen, cfg.PprofListen = get("CLEARANCE_API_METRICS_LISTEN", ""), get("CLEARANCE_API_PPROF_LISTEN", "")
	if cfg.PprofListen != "" {
		if err := LoopbackOnly(cfg.PprofListen); err != nil {
			return cfg, fmt.Errorf("CLEARANCE_API_PPROF_LISTEN: %w", err)
		}
	}
	wait, err := strconv.Atoi(get("CLEARANCE_API_COVERAGE_WAIT_SECONDS", "3"))
	if err != nil || wait < 0 || wait > 10 {
		return cfg, errors.New("CLEARANCE_API_COVERAGE_WAIT_SECONDS is seconds, 0 to 10")
	}
	cfg.CoverageWait = time.Duration(wait) * time.Second
	ttl, err := strconv.Atoi(get("CLEARANCE_API_COVERAGE_CACHE_SECONDS", "0"))
	if err != nil || ttl < 0 || ttl > 300 {
		return cfg, errors.New("CLEARANCE_API_COVERAGE_CACHE_SECONDS is seconds, 0 to 300")
	}
	cfg.CoverageCacheTTL = time.Duration(ttl) * time.Second
	if getenv("CLEARANCE_PACKS") != "" {
		return cfg, errors.New("CLEARANCE_PACKS is gone: name policy bundle files in CLEARANCE_BUNDLES (docs/core.md, Policy bundles)")
	}
	if cfg.Policy, err = bundles.FromEnv(getenv); err != nil {
		return cfg, err
	}
	v, err := vocab.FromEnv(getenv)
	if err != nil {
		return cfg, err
	}
	cfg.Vocabulary = &v
	for k, v := range map[string]string{"BACKSTAGE_URL": cfg.BackstageURL, "CLEARANCE_GATEWAY_URL": cfg.GatewayURL,
		"CLEARANCE_CORE_URL": cfg.CoreURL} {
		if v == "" {
			continue
		}
		u, err := url.Parse(v)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
			u.RawQuery != "" || u.Fragment != "" {
			return cfg, fmt.Errorf("%s must be an http(s) URL with a host and no credentials, query or fragment", k)
		}
	}
	if cfg.Auth, err = authn.FromEnv(getenv); err != nil {
		return cfg, err
	}
	if cfg.Attest, err = attestTrustFromEnv(getenv); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// attestTrustFromEnv reads the attestation trust: nil when no variable names any. The checks are the CLI's
// (`clearance attest verify`): a keyless trust root needs the identity and issuer, a PEM one Rekor's key, and a
// trusted-root.json carries Rekor's keys so refuses one.
func attestTrustFromEnv(getenv func(string) string) (*AttestTrust, error) {
	names := []string{"CLEARANCE_API_ATTEST_KEY", "CLEARANCE_API_ATTEST_TRUST_ROOT", "CLEARANCE_API_ATTEST_IDENTITY",
		"CLEARANCE_API_ATTEST_ISSUER", "CLEARANCE_API_ATTEST_REKOR_KEY", "CLEARANCE_API_ATTEST_REKOR_URL"}
	any := false
	for _, n := range names {
		any = any || getenv(n) != ""
	}
	if !any {
		return nil, nil
	}
	t := &AttestTrust{Identity: getenv("CLEARANCE_API_ATTEST_IDENTITY"), Issuer: getenv("CLEARANCE_API_ATTEST_ISSUER"),
		RekorURL: getenv("CLEARANCE_API_ATTEST_REKOR_URL")}
	read := func(name string) ([]byte, error) {
		path := getenv(name)
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		defer f.Close()
		b, err := io.ReadAll(io.LimitReader(f, token.MaxEnvelopeBytes+1))
		if err != nil || len(b) > token.MaxEnvelopeBytes {
			return nil, fmt.Errorf("%s: unreadable or over %d bytes", name, token.MaxEnvelopeBytes)
		}
		return b, nil
	}
	if t.RekorURL != "" {
		u, err := attest.CheckURL("CLEARANCE_API_ATTEST_REKOR_URL", t.RekorURL)
		if err != nil {
			return nil, err
		}
		t.RekorURL = u.String()
	}
	if getenv("CLEARANCE_API_ATTEST_KEY") != "" {
		b, err := read("CLEARANCE_API_ATTEST_KEY")
		if err != nil {
			return nil, err
		}
		if t.Keys, err = attest.ParseKeys(b); err != nil {
			return nil, fmt.Errorf("CLEARANCE_API_ATTEST_KEY: %w", err)
		}
	}
	if getenv("CLEARANCE_API_ATTEST_TRUST_ROOT") != "" {
		b, err := read("CLEARANCE_API_ATTEST_TRUST_ROOT")
		if err != nil {
			return nil, err
		}
		if t.Identity == "" || t.Issuer == "" {
			return nil, errors.New("CLEARANCE_API_ATTEST_TRUST_ROOT needs CLEARANCE_API_ATTEST_IDENTITY and CLEARANCE_API_ATTEST_ISSUER")
		}
		pemKey := getenv("CLEARANCE_API_ATTEST_REKOR_KEY")
		if strings.HasPrefix(strings.TrimSpace(string(b)), "{") {
			if pemKey != "" {
				return nil, errors.New("CLEARANCE_API_ATTEST_REKOR_KEY: not with a trusted-root.json, which carries Rekor's keys")
			}
			if t.Trust, err = attest.ParseTrustedRoot(b); err != nil {
				return nil, fmt.Errorf("CLEARANCE_API_ATTEST_TRUST_ROOT: %w", err)
			}
		} else {
			if pemKey == "" {
				return nil, errors.New("CLEARANCE_API_ATTEST_TRUST_ROOT as PEM needs CLEARANCE_API_ATTEST_REKOR_KEY")
			}
			if t.Roots, err = attest.ParseRoots(b); err != nil {
				return nil, fmt.Errorf("CLEARANCE_API_ATTEST_TRUST_ROOT: %w", err)
			}
			kb, err := read("CLEARANCE_API_ATTEST_REKOR_KEY")
			if err != nil {
				return nil, err
			}
			if t.RekorKey, err = attest.ParseRekorKey(kb); err != nil {
				return nil, fmt.Errorf("CLEARANCE_API_ATTEST_REKOR_KEY: %w", err)
			}
		}
	} else if t.Identity != "" || t.Issuer != "" || getenv("CLEARANCE_API_ATTEST_REKOR_KEY") != "" {
		return nil, errors.New("CLEARANCE_API_ATTEST_IDENTITY, _ISSUER and _REKOR_KEY are for a keyless trust root (CLEARANCE_API_ATTEST_TRUST_ROOT)")
	}
	return t, nil
}

// ShutdownTimeout is how long Run waits for requests in flight once its context ends.
const ShutdownTimeout = 20 * time.Second

// Run opens the read-only store, loads the policy and the definitions, and serves on cfg.Listen until ctx ends.
// ready, when set, gets the bound address once the listener is up.
func Run(ctx context.Context, cfg Config, log *slog.Logger, ready func(addr string)) error {
	if log == nil {
		log = slog.Default()
	}
	eng, err := bundles.Engine(ctx, cfg.Policy, log)
	if err != nil {
		return fmt.Errorf("api: loading the policy: %w", err)
	}
	voc := vocab.Get()
	if cfg.Vocabulary != nil {
		voc = *cfg.Vocabulary
	}
	vocab.Set(voc.WithPolicy(eng))
	bundled := map[string]profile.AgentDefinition{}
	if cfg.AgentsDir != "" {
		if bundled, err = profile.LoadDir(cfg.AgentsDir); err != nil {
			return fmt.Errorf("api: CLEARANCE_AGENTS_DIR: %w", err)
		}
	}
	rd, err := pg.OpenReader(ctx, cfg.DSN, pg.Options{MaxConns: cfg.Pool, Logger: log})
	if err != nil {
		return fmt.Errorf("api: opening the store: %w", err)
	}
	defer rd.Close()
	st := &PG{R: rd}
	defs := NewDefinitions(bundled)
	if _, err := defs.Refresh(ctx, st); err != nil {
		// The core may not have created its tables yet (a fresh install starts both at once): serve the bundled
		// set, retry every interval, and stay unready (/readyz) until the database answers.
		log.Warn("api: the stored definitions are not readable yet; retrying", "error", err.Error())
	}
	access := &Access{Delegates: cfg.Delegates, Notifiers: cfg.Notifiers, Auditors: cfg.Auditors,
		ObservationReaders: cfg.ObservationReaders, Admins: cfg.Admins, FeedReaders: cfg.FeedReaders, Owners: defs.Owners}
	if cfg.BackstageURL != "" {
		cat := backstage.NewCatalog(cfg.BackstageURL, cfg.BackstageTokenFile, 0, log)
		dir := backstage.NewDirectory(cat, 0, nil)
		access.Directory, access.Ownership = dir, backstage.NewOwnership(cat, dir, 0, nil)
	} else {
		log.Warn("api: no BACKSTAGE_URL, so no groups and no app owners: a person sees only their own records")
	}
	gp := gate.DefaultPolicy().View()
	srv, err := New(Options{Store: st, Auth: cfg.Auth, Access: access, Engine: eng, GatePolicy: &gp,
		Definitions: defs, GatewayURL: cfg.GatewayURL, CoreURL: cfg.CoreURL, Log: log, Attest: cfg.Attest,
		CoverageConcurrency: cfg.CoverageConcurrency, CoverageCacheTTL: cfg.CoverageCacheTTL, CoverageWait: cfg.CoverageWait})
	if err != nil {
		return err
	}
	tlsLn, err := cfg.TLS.Listen()
	if err != nil {
		return fmt.Errorf("api: %w", err)
	}
	var ln net.Listener
	if cfg.Listen != tlsutil.Off {
		if ln, err = net.Listen("tcp", cfg.Listen); err != nil {
			if tlsLn != nil {
				_ = tlsLn.Close()
			}
			return fmt.Errorf("api: listen %s: %w", cfg.Listen, err)
		}
	}
	first := ln
	if first == nil {
		first = tlsLn
	}
	for _, side := range []struct {
		name string
		srv  func() (*http.Server, error)
		addr string
	}{{"metrics", func() (*http.Server, error) { return srv.MetricsServer(cfg.MetricsListen), nil }, cfg.MetricsListen},
		{"pprof", func() (*http.Server, error) { return PprofServer(cfg.PprofListen) }, cfg.PprofListen}} {
		if side.addr == "" {
			continue
		}
		ss, err := side.srv()
		if err != nil {
			ln.Close()
			return fmt.Errorf("api: %s listener: %w", side.name, err)
		}
		sl, err := net.Listen("tcp", side.addr)
		if err != nil {
			ln.Close()
			return fmt.Errorf("api: %s listener %s: %w", side.name, side.addr, err)
		}
		log.Info("clearance api: opt-in listener", "kind", side.name, "addr", sl.Addr().String())
		go func(name string) {
			if err := ss.Serve(sl); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("clearance api: opt-in listener stopped", "kind", name, "error", err.Error())
			}
		}(side.name)
		defer ss.Close()
	}
	hs := srv.HTTPServer(cfg.Listen)
	bg, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defs.Run(bg, st, cfg.DefinitionsEvery, log); close(done) }()
	watched := make(chan struct{})
	go func() { bundles.Watch(bg, cfg.Policy, eng, log); close(watched) }()
	defer func() { <-watched }()
	serveErr := make(chan error, 2)
	if ln != nil {
		go func() { serveErr <- hs.Serve(ln) }()
	}
	var ts *http.Server
	if tlsLn != nil {
		ts = srv.HTTPServer(cfg.TLS.Addr)
		go func() { serveErr <- ts.Serve(tlsLn) }()
		log.Info("clearance api serving https", "addr", tlsLn.Addr().String())
	}
	log.Info("clearance api serving", "addr", first.Addr().String(), "agents", len(defs.Names()),
		"auditors", cfg.Auditors, "notifiers", cfg.Notifiers, "observation_readers", cfg.ObservationReaders, "delegates", cfg.Delegates, "feed_readers", len(cfg.FeedReaders),
		"catalog", cfg.BackstageURL != "", "policy", eng.Policy().Bundle)
	if ready != nil {
		ready(first.Addr().String())
	}
	var runErr error
	select {
	case <-ctx.Done():
	case err := <-serveErr:
		runErr = err
	}
	sctx, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
	defer cancel()
	if err := hs.Shutdown(sctx); err != nil && runErr == nil {
		runErr = err
	}
	if ts != nil {
		_ = ts.Shutdown(sctx)
	}
	stop()
	<-done
	if errors.Is(runErr, http.ErrServerClosed) {
		runErr = nil
	}
	log.Info("clearance api stopped")
	return runErr
}
