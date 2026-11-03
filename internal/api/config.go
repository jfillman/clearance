package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/authn"
	"github.com/jfillman/clearance/internal/bundles"
	"github.com/jfillman/clearance/internal/directory/backstage"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/profile"
	"github.com/jfillman/clearance/internal/store/pg"
	"github.com/jfillman/clearance/internal/vocab"
)

// Config is clearance-api's deployment, read by FromEnv:
//
//	CLEARANCE_API_DSN                   the read-only role's DSN (required)
//	CLEARANCE_API_AUDITORS              principal globs, comma-separated: every read, the chain check, full=1
//	CLEARANCE_API_NOTIFIERS             principal globs: the notifier role (no Clearance read is a notifier's)
//	CLEARANCE_DELEGATES                 principal globs that may name a person in the on-behalf-of header (a portal)
//	CLEARANCE_AGENTS_DIR                the bundled agent definitions (*.yaml); the cluster pins come from the
//	                                    core's store (clearance_definitions), refreshed every
//	CLEARANCE_API_DEFINITIONS_INTERVAL  seconds (default 30)
//	CLEARANCE_API_POOL                  Postgres connections per replica (default 5)
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
	AgentsDir                      string
	DefinitionsEvery               time.Duration
	Pool                           int32
	Policy                         bundles.Config
	Vocabulary                     *vocab.Vocabulary // nil: the vocabulary already in force (vocab.Get; tests)
	GatewayURL, CoreURL            string
	BackstageURL                   string
	BackstageTokenFile             string
	Auth                           authn.Authenticator
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
		Delegates:  list(get("CLEARANCE_DELEGATES", "")),
		GatewayURL: get("CLEARANCE_GATEWAY_URL", ""), CoreURL: get("CLEARANCE_CORE_URL", ""),
		BackstageURL: get("BACKSTAGE_URL", ""), BackstageTokenFile: get("BACKSTAGE_TOKEN_FILE", backstage.DefaultTokenFile)}
	if cfg.DSN == "" {
		return cfg, errors.New("CLEARANCE_API_DSN is required (the read-only role's DSN)")
	}
	cfg.Listen = get("CLEARANCE_LISTEN", "")
	if cfg.Listen == "" {
		port, err := strconv.Atoi(get("PORT", "8080"))
		if err != nil || port < 1 || port > 65535 {
			return cfg, errors.New("PORT is a port number")
		}
		cfg.Listen = ":" + strconv.Itoa(port)
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
	return cfg, nil
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
	access := &Access{Delegates: cfg.Delegates, Notifiers: cfg.Notifiers, Auditors: cfg.Auditors, Owners: defs.Owners}
	if cfg.BackstageURL != "" {
		cat := backstage.NewCatalog(cfg.BackstageURL, cfg.BackstageTokenFile, 0, log)
		dir := backstage.NewDirectory(cat, 0, nil)
		access.Directory, access.Ownership = dir, backstage.NewOwnership(cat, dir, 0, nil)
	} else {
		log.Warn("api: no BACKSTAGE_URL, so no groups and no app owners: a person sees only their own records")
	}
	gp := gate.DefaultPolicy().View()
	srv, err := New(Options{Store: st, Auth: cfg.Auth, Access: access, Engine: eng, GatePolicy: &gp,
		Definitions: defs, GatewayURL: cfg.GatewayURL, CoreURL: cfg.CoreURL, Log: log})
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("api: listen %s: %w", cfg.Listen, err)
	}
	hs := srv.HTTPServer(cfg.Listen)
	bg, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defs.Run(bg, st, cfg.DefinitionsEvery, log); close(done) }()
	serveErr := make(chan error, 1)
	go func() { serveErr <- hs.Serve(ln) }()
	log.Info("clearance api serving", "addr", ln.Addr().String(), "agents", len(defs.Names()),
		"auditors", cfg.Auditors, "notifiers", cfg.Notifiers, "delegates", cfg.Delegates,
		"catalog", cfg.BackstageURL != "", "policy", eng.Policy().Bundle)
	if ready != nil {
		ready(ln.Addr().String())
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
	stop()
	<-done
	if errors.Is(runErr, http.ErrServerClosed) {
		runErr = nil
	}
	log.Info("clearance api stopped")
	return runErr
}
