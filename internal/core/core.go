// Package core wires the Go core: the store, the decision engine and its policy bundles, the gate, review, provenance and
// GitHub App services, the authenticator and the HTTP server (internal/server), from the environment. Run serves
// until its context ends, then shuts the server down gracefully and stops the background loops.
//
// # Environment
//
//	CLEARANCE_DSN                 the Postgres DSN (required unless Memory)
//	CLEARANCE_LISTEN              listen address (default :8080)
//	CLEARANCE_PROVIDERS           the registered providers, JSON (server.Provider; required to serve decisions)
//	CLEARANCE_BUNDLES, CLEARANCE_BUNDLE_SOURCES, CLEARANCE_BUNDLE_SOURCE_WAIT, CLEARANCE_ENV_*
//	                              the policy bundles and environment naming (internal/bundles; default: the core
//	                              rules only). A bundle whose sources cannot be read fails the start.
//	CLEARANCE_VERIFIERS           principal globs that may register changes and ask for provenance
//	CLEARANCE_DELEGATES           principal globs that may act for a person they name (the on-behalf-of header)
//	CLEARANCE_ADMINS              principal globs (user:<login>) that may deny any held change
//	CLEARANCE_EXPIRE_SECONDS      how often holding changes past their TTL are expired (default 60)
//	CLEARANCE_MAX_CLOCK_SKEW      how far an evaluation's context.now may be from the core's clock, a Go duration
//	                              (default 5m, at most 24h); 0 turns the check off, which `clearance core` allows
//	                              only with --memory (ParseMaxClockSkew)
//	CLEARANCE_AGENTS_DIR          bundled agent definitions (*.yaml, profile.LoadDir); default none
//	AGENT_LOGINS                  GitHub logins agents open PRs as (default none: an agent PR is known by its
//	                              Clearance record or its trailers only)
//	MODEL_ROUTES                  alias=upstream,...: the model aliases a definition release may name (unset: not checked)
//	RUNTIME_IMAGES_EXTRA          globs a definition's runtime.image may match
//	CLEARANCE_TRUSTED_REGISTRIES  comma-separated image prefixes, each ending in "/", a tier-1 image bump may come from;
//	                              an image from anywhere else is tier 2 (image:not-trusted-registry). Unset: any registry
//	CLEARANCE_GATE_UNBOUND_TREE   flag (default) | refuse: a manifest-tree registration whose treeDigest is a placeholder
//	                              (64 copies of one digit, or sha256 of nothing) is flagged tree:unbound, or refused
//	                              DG-UNBOUND (docs/gate.md, The manifest-tree digest)
//	CLEARANCE_GITHUB_APP_ID, CLEARANCE_GITHUB_APP_KEY_FILE, CLEARANCE_GITHUB_APP_WEBHOOK_SECRET_FILE
//	                              the Clearance GitHub App: all three or none
//	CLEARANCE_GITHUB_APP_COMMENTS off | agent-failures
//	CLEARANCE_GITHUB_API          the GitHub API base (default https://api.github.com)
//	BACKSTAGE_URL                 the portal's Backstage (http/https): the gate's group directory (a person's memberOf
//	                              groups) and app owners (a Component's spec.owner). Unset: neither, so nobody is in
//	                              any group and no person can clear a tier-2/3 change
//	BACKSTAGE_TOKEN_FILE          the bearer token for Backstage, re-read on every call (default
//	                              /var/run/clearance/backstage-token: a projected token for the backstage audience)
//	CLEARANCE_SIGNING_KEY_FILE    the clearance token signing key: a PEM ECDSA P-256 private key (SEC 1 or PKCS #8),
//	                              read once at start. Unset: no tokens are issued (and none of a gate provider's
//	                              deploys can be admitted on one)
//	CLEARANCE_SIGNING_KMS         a KMS key reference for the signing key (KMS signing is not built: setting it
//	                              stops the start; docs/core.md, The clearance token)
//	CLEARANCE_TOKEN_TTL           each token's life, a Go duration (default 15m, 1m to 24h, at least four expiry
//	                              intervals); tokens are re-issued at half-life while their change stays cleared
//	CLEARANCE_TOKEN_ISSUER        the tokens' iss, which verifiers check (default clearance)
//
// and the authenticator's (authn.EnvVars: CLEARANCE_AUDIENCE, CLEARANCE_OIDC_*, CLEARANCE_FOREIGN_*,
// CLEARANCE_GITHUB_OIDC_*), and the deployment's vocabulary (vocab.EnvVars).
// An empty variable is an unset one.
package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jfillman/clearance/internal/authn"
	"github.com/jfillman/clearance/internal/bundles"
	"github.com/jfillman/clearance/internal/decide"
	"github.com/jfillman/clearance/internal/definitions"
	"github.com/jfillman/clearance/internal/directory/backstage"
	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/githubapp"
	"github.com/jfillman/clearance/internal/profile"
	"github.com/jfillman/clearance/internal/provenance"
	"github.com/jfillman/clearance/internal/review"
	"github.com/jfillman/clearance/internal/server"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/store/memory"
	"github.com/jfillman/clearance/internal/store/pg"
	"github.com/jfillman/clearance/internal/token"
	"github.com/jfillman/clearance/internal/vocab"
)

// ShutdownTimeout is how long Run waits for requests in flight once its context ends.
const ShutdownTimeout = 20 * time.Second

// Config is the core's deployment.
type Config struct {
	DSN    string
	Memory bool // store/memory instead of Postgres: tests and `clearance core --memory`
	Listen string
	// Version is the build version: the provider version of the core's own records.
	Version   string
	Providers []server.Provider
	Policy    bundles.Config
	// Vocabulary is the deployment's names (vocab); Build sets it process-wide.
	Vocabulary *vocab.Vocabulary // nil: the vocabulary already in force (vocab.Get; tests)
	Gate       gate.Config
	// AgentLogins are provenance's agent logins.
	AgentLogins []string
	AgentsDir   string
	ExpireEvery time.Duration
	GitHubApp   *githubapp.Config // nil: no App
	Auth        authn.Authenticator
	// MaxClockSkew is server.Options.MaxClockSkew: 0 the default, negative off (CheckMaxClockSkew: --memory only).
	MaxClockSkew time.Duration
	// DevRecords is server.Options.DevRecords (GET /v1/dev/records): `clearance core --memory --insecure-dev-auth`.
	// Build refuses it without Memory.
	DevRecords bool
	// BackstageURL is Tower's Backstage, the gate's Directory and Owners ("": neither).
	BackstageURL string
	// BackstageTokenFile is read on every Backstage call (default backstage.DefaultTokenFile).
	BackstageTokenFile string
	// BackstageTimeout is each Backstage call's deadline (<= 0: backstage.DefaultTimeout).
	BackstageTimeout time.Duration
	// Signer signs clearance tokens (nil: none are issued); TokenTTL and TokenIssuer are gate.Tokens'.
	Signer      token.Signer
	TokenTTL    time.Duration
	TokenIssuer string
}

// FromEnv reads Config from getenv, the authenticator included (authn.FromEnv).
func FromEnv(getenv func(string) string) (Config, error) {
	get := func(k, def string) string {
		if v := getenv(k); v != "" {
			return v
		}
		return def
	}
	cfg := Config{DSN: get("CLEARANCE_DSN", ""), Listen: get("CLEARANCE_LISTEN", ":8080"),
		AgentsDir: get("CLEARANCE_AGENTS_DIR", "")}
	var err error
	if cfg.Providers, err = server.ParseProviders(get("CLEARANCE_PROVIDERS", "")); err != nil {
		return cfg, err
	}
	if get("CLEARANCE_PACKS", "") != "" {
		return cfg, errors.New("CLEARANCE_PACKS is gone: name policy bundle files in CLEARANCE_BUNDLES (docs/core.md, Policy bundles)")
	}
	if get("CLEARANCE_FLIGHT_REGISTRIES", "") != "" {
		return cfg, errors.New("CLEARANCE_FLIGHT_REGISTRIES is now CLEARANCE_TRUSTED_REGISTRIES")
	}
	if cfg.Policy, err = bundles.FromEnv(getenv); err != nil {
		return cfg, err
	}
	v, err := vocab.FromEnv(getenv)
	if err != nil {
		return cfg, err
	}
	cfg.Vocabulary = &v
	cfg.Gate = gate.Config{Verifiers: list(get("CLEARANCE_VERIFIERS", "")),
		Delegates: list(get("CLEARANCE_DELEGATES", "")), Admins: list(get("CLEARANCE_ADMINS", "")),
		ImageAllow: list(get("RUNTIME_IMAGES_EXTRA", "")), TrustedRegistries: list(get("CLEARANCE_TRUSTED_REGISTRIES", ""))}
	switch cfg.Gate.UnboundTree = get("CLEARANCE_GATE_UNBOUND_TREE", gate.UnboundFlag); cfg.Gate.UnboundTree {
	case gate.UnboundFlag, gate.UnboundRefuse:
	default:
		return cfg, fmt.Errorf("CLEARANCE_GATE_UNBOUND_TREE is flag or refuse, not %q", cfg.Gate.UnboundTree)
	}
	for _, r := range cfg.Gate.TrustedRegistries {
		// The check is a plain prefix test, so a prefix without its trailing slash would also admit a look-alike
		// owner (ghcr.io/acme matches ghcr.io/acme-evil/...).
		if !strings.HasSuffix(r, "/") || strings.ContainsAny(r, " \t") {
			return cfg, fmt.Errorf("CLEARANCE_TRUSTED_REGISTRIES: %q is not a registry prefix ending in \"/\"", r)
		}
	}
	if routes := get("MODEL_ROUTES", ""); routes != "" {
		cfg.Gate.Models = []string{}
		for _, pair := range list(routes) {
			alias, upstream, ok := strings.Cut(pair, "=")
			if !ok || strings.TrimSpace(alias) == "" || strings.TrimSpace(upstream) == "" {
				return cfg, fmt.Errorf("MODEL_ROUTES entries are alias=upstream-model, not %q", pair)
			}
			cfg.Gate.Models = append(cfg.Gate.Models, strings.TrimSpace(alias))
		}
	}
	cfg.AgentLogins = list(get("AGENT_LOGINS", ""))
	secs, err := strconv.ParseFloat(get("CLEARANCE_EXPIRE_SECONDS", "60"), 64)
	if err != nil || secs <= 0 || secs > 86400 {
		return cfg, errors.New("CLEARANCE_EXPIRE_SECONDS must be a positive number of seconds (at most 86400)")
	}
	cfg.ExpireEvery = time.Duration(secs * float64(time.Second))
	if cfg.MaxClockSkew, err = ParseMaxClockSkew(get("CLEARANCE_MAX_CLOCK_SKEW", "")); err != nil {
		return cfg, fmt.Errorf("CLEARANCE_MAX_CLOCK_SKEW: %w", err)
	}
	parts := []string{get("CLEARANCE_GITHUB_APP_ID", ""), get("CLEARANCE_GITHUB_APP_KEY_FILE", ""),
		get("CLEARANCE_GITHUB_APP_WEBHOOK_SECRET_FILE", "")}
	set := 0
	for _, p := range parts {
		if p != "" {
			set++
		}
	}
	if set != 0 && set != 3 {
		return cfg, errors.New("CLEARANCE_GITHUB_APP_ID, _KEY_FILE and _WEBHOOK_SECRET_FILE are set together or not at all")
	}
	comments := get("CLEARANCE_GITHUB_APP_COMMENTS", "off")
	if comments != "off" && comments != "agent-failures" {
		return cfg, errors.New("CLEARANCE_GITHUB_APP_COMMENTS is off or agent-failures")
	}
	if set == 3 {
		if cfg.GitHubApp, err = githubapp.ReadConfig(parts[0], parts[1], parts[2], comments,
			get("CLEARANCE_GITHUB_API", githubapp.API)); err != nil {
			return cfg, err
		}
	}
	cfg.BackstageURL = get("BACKSTAGE_URL", "")
	cfg.BackstageTokenFile = get("BACKSTAGE_TOKEN_FILE", backstage.DefaultTokenFile)
	if cfg.BackstageURL != "" {
		u, err := url.Parse(cfg.BackstageURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
			u.RawQuery != "" || u.Fragment != "" {
			return cfg, errors.New("BACKSTAGE_URL must be an http(s) URL with a host and no credentials, query or fragment")
		}
	}
	if get("CLEARANCE_SIGNING_KMS", "") != "" {
		return cfg, errors.New("CLEARANCE_SIGNING_KMS: KMS signing is not built yet; sign with a key file " +
			"(CLEARANCE_SIGNING_KEY_FILE) until it is (docs/core.md, The clearance token)")
	}
	if path := get("CLEARANCE_SIGNING_KEY_FILE", ""); path != "" {
		if cfg.Signer, err = token.LoadKeyFile(path); err != nil {
			return cfg, fmt.Errorf("CLEARANCE_SIGNING_KEY_FILE: %w", err)
		}
	}
	if cfg.TokenTTL, err = ParseTokenTTL(get("CLEARANCE_TOKEN_TTL", ""), cfg.ExpireEvery); err != nil {
		return cfg, fmt.Errorf("CLEARANCE_TOKEN_TTL: %w", err)
	}
	cfg.TokenIssuer = get("CLEARANCE_TOKEN_ISSUER", gate.DefaultTokenIssuer)
	if len(cfg.TokenIssuer) > 200 || strings.ContainsAny(cfg.TokenIssuer, " \t\r\n") {
		return cfg, errors.New("CLEARANCE_TOKEN_ISSUER is at most 200 characters, without spaces")
	}
	if cfg.Auth, err = authn.FromEnv(getenv); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// MinTokenTTL is the shortest token life a deployment may set.
const MinTokenTTL = time.Minute

// ParseTokenTTL reads CLEARANCE_TOKEN_TTL: "" is gate.DefaultTokenTTL; else a Go duration from MinTokenTTL to
// gate.MaxTokenTTL and at least four times the refresh interval (the expiry loop's), so a token is always
// re-issued before it lapses.
func ParseTokenTTL(v string, every time.Duration) (time.Duration, error) {
	d := gate.DefaultTokenTTL
	if v != "" {
		var err error
		if d, err = time.ParseDuration(v); err != nil {
			return 0, fmt.Errorf("%q is not a Go duration (15m, 1h)", v)
		}
	}
	if d < MinTokenTTL || d > gate.MaxTokenTTL {
		return 0, fmt.Errorf("%s is not between %s and %s", d, MinTokenTTL, gate.MaxTokenTTL)
	}
	if every > 0 && d < 4*every {
		return 0, fmt.Errorf("%s is under four refresh intervals (CLEARANCE_EXPIRE_SECONDS: %s)", d, every)
	}
	return d, nil
}

// MaxClockSkewLimit is the largest clock-skew bound a deployment may set.
const MaxClockSkewLimit = 24 * time.Hour

// ErrSkewOffNeedsMemory refuses a core with the clock-skew check off on a durable store.
var ErrSkewOffNeedsMemory = errors.New("the clock-skew check may be off (0) only with --memory: a decision " +
	"record's ts is the evaluation's context.now, and it is verified")

// ParseMaxClockSkew reads CLEARANCE_MAX_CLOCK_SKEW or --max-clock-skew into Config.MaxClockSkew's terms: "" is the
// default (0, server.DefaultMaxClockSkew), "0" is off (-1), else a positive Go duration of at most
// MaxClockSkewLimit.
func ParseMaxClockSkew(v string) (time.Duration, error) {
	if v == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(v)
	switch {
	case err != nil:
		return 0, fmt.Errorf("%q is not a Go duration (5m, 30s; 0 is off)", v)
	case d == 0:
		return -1, nil
	case d < 0 || d > MaxClockSkewLimit:
		return 0, fmt.Errorf("%q is not between 0 and %s", v, MaxClockSkewLimit)
	}
	return d, nil
}

// CheckMaxClockSkew is the deployment rule for the clock-skew check: off only on an in-memory store. A test core
// on a fixed clock turns it off; a core whose records are kept may only widen or narrow it.
func (c Config) CheckMaxClockSkew() error {
	if c.MaxClockSkew < 0 && !c.Memory {
		return ErrSkewOffNeedsMemory
	}
	return nil
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

// Core is the wired core: what Run serves. Build it with Build; tests serve Server.Handler() themselves.
type Core struct {
	Config  Config
	Store   store.Store
	Engine  *decide.Engine
	Gate    *gate.Service
	Server  *server.Server
	App     *githubapp.App
	clock   func() time.Time
	log     *slog.Logger
	closeFn func()
	once    sync.Once
}

// Build opens the store (memory or Postgres, verified from genesis), loads the policy (a rule that does not compile
// fails here), the bundled and stored definitions, and wires every service and the server.
func Build(ctx context.Context, cfg Config, clock func() time.Time, log *slog.Logger) (*Core, error) {
	if clock == nil {
		clock = time.Now
	}
	if log == nil {
		log = slog.Default()
	}
	if cfg.Auth == nil {
		return nil, errors.New("core: no authenticator")
	}
	if cfg.DevRecords && !cfg.Memory {
		return nil, errors.New("core: the dev records read is for an in-memory core only")
	}
	eng, err := bundles.Engine(ctx, cfg.Policy, log)
	if err != nil {
		return nil, fmt.Errorf("core: loading the policy: %w", err)
	}
	voc := vocab.Get()
	if cfg.Vocabulary != nil {
		voc = *cfg.Vocabulary
	}
	vocab.Set(voc.WithPolicy(eng))
	var st store.Store
	switch {
	case cfg.Memory:
		st = memory.New()
	case cfg.DSN == "":
		return nil, errors.New("core: CLEARANCE_DSN is required (or --memory for an in-memory store, tests only)")
	default:
		p, err := pg.Open(ctx, cfg.DSN, pg.Options{Logger: log})
		if err != nil {
			return nil, fmt.Errorf("core: opening the store: %w", err)
		}
		st = p
	}
	c := &Core{Config: cfg, Store: st, Engine: eng, clock: clock, log: log, closeFn: st.Close}
	if err := c.wire(ctx); err != nil {
		st.Close()
		return nil, err
	}
	return c, nil
}

func (c *Core) wire(ctx context.Context) error {
	cfg := c.Config
	parse := profile.Parser()
	writer := evidence.Core(cfg.Version)

	bundled := map[string]definitions.Definition{}
	if cfg.AgentsDir != "" {
		defs, err := profile.LoadDir(cfg.AgentsDir)
		if err != nil {
			return fmt.Errorf("core: CLEARANCE_AGENTS_DIR: %w", err)
		}
		for name, d := range defs {
			bundled[name] = d.Definition()
		}
	}
	reg := definitions.NewRegistry(bundled)
	rows, err := c.Store.Definitions(ctx)
	if err != nil {
		return fmt.Errorf("core: reading the stored definitions: %w", err)
	}
	maps := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		var m map[string]any
		if err := json.Unmarshal(r.Record, &m); err != nil {
			return fmt.Errorf("core: stored definition %q: %w", r.Name, err)
		}
		maps = append(maps, m)
	}
	reg.ApplyRecords(maps, parse)

	tools := review.Registry{Tools: map[string]review.ToolSpec{}, Tripwires: map[string]bool{}}
	for _, t := range c.Engine.Tools() {
		tools.Tools[t.Name] = review.ToolSpec{Tier: t.Tier, ProposeOnly: t.ProposeOnly, WritesFiles: t.WritesFiles,
			ReadsRepo: t.ReadsRepo}
	}
	for _, n := range c.Engine.Tripwires() {
		tools.Tripwires[n] = true
	}

	g := gate.NewService(cfg.Gate, c.Store, c.clock)
	g.Writer, g.Tools, g.Parse = writer, tools, parse
	if cfg.Signer != nil {
		if err := c.useKey(ctx, cfg.Signer); err != nil {
			return err
		}
		g.Tokens = &gate.Tokens{Signer: cfg.Signer, Issuer: cfg.TokenIssuer, TTL: cfg.TokenTTL}
	} else if !cfg.Gate.Off {
		c.log.WarnContext(ctx, "gate: no CLEARANCE_SIGNING_KEY_FILE, so no clearance tokens: a gate provider that "+
			"admits on a token (the Argo CD grant sync) admits nothing")
	}
	if cfg.BackstageURL != "" {
		tokenFile := cfg.BackstageTokenFile
		if tokenFile == "" {
			tokenFile = backstage.DefaultTokenFile
		}
		cat := backstage.NewCatalog(cfg.BackstageURL, tokenFile, cfg.BackstageTimeout, c.log)
		g.Directory = backstage.NewDirectory(cat, 0, c.clock)
		g.Owners = backstage.NewOwners(cat, 0, c.clock)
	} else {
		c.log.WarnContext(ctx, "gate: no BACKSTAGE_URL, so no group directory and no app owners: "+
			"nobody is in any group and no person can clear a tier-2 or tier-3 change")
	}
	c.Gate = g
	prov := &provenance.Service{Config: provenance.Config{Verifiers: cfg.Gate.Verifiers, AgentLogins: cfg.AgentLogins},
		Store: c.Store, Clock: c.clock, Defs: reg, Writer: writer}
	rev := &review.Handler{Config: review.Config{Verifiers: cfg.Gate.Verifiers, Delegates: cfg.Gate.Delegates,
		Models: cfg.Gate.Models, ImageAllow: cfg.Gate.ImageAllow}, Registry: tools, Parse: parse}
	if cfg.GitHubApp != nil {
		app, err := githubapp.New(*cfg.GitHubApp, prov, g, c.clock, c.log)
		if err != nil {
			return fmt.Errorf("core: the GitHub App: %w", err)
		}
		c.App = app
		g.OnAnswered = append(g.OnAnswered, app.Poke)
	}
	srv, err := server.New(ctx, server.Options{Store: c.Store, Engine: c.Engine, Auth: cfg.Auth,
		Providers: cfg.Providers, Version: cfg.Version, Clock: c.clock, Log: c.log, MaxClockSkew: cfg.MaxClockSkew,
		DevRecords:      cfg.DevRecords,
		Definitions:     &definitions.Service{Registry: reg, Store: c.Store, Clock: c.clock, Writer: writer},
		ParseDefinition: parse, Gate: g, Review: rev, Provenance: prov, App: c.App})
	if err != nil {
		return err
	}
	c.Server = srv
	return nil
}

// useKey publishes the signing key's public half (GET /v1/keys) and retires the one used before it.
func (c *Core) useKey(ctx context.Context, s token.Signer) error {
	j, err := token.PublicJWK(s.Public())
	if err != nil {
		return fmt.Errorf("core: the signing key: %w", err)
	}
	raw, err := json.Marshal(j)
	if err != nil {
		return err
	}
	if err := c.Store.Atomic(ctx, func(tx store.Tx) error {
		return tx.UseSigningKey(ctx, store.SigningKey{KeyID: j.Kid, JWK: raw}, c.clock().UTC())
	}); err != nil {
		return fmt.Errorf("core: publishing the signing key: %w", err)
	}
	c.log.InfoContext(ctx, "clearance tokens: signing", "kid", j.Kid)
	return nil
}

// Close closes the store (once).
func (c *Core) Close() { c.once.Do(c.closeFn) }

// Loops runs the background work until ctx ends: the gate's expiry every ExpireEvery, and the GitHub App's worker.
func (c *Core) Loops(ctx context.Context) {
	done := make(chan struct{})
	if c.App != nil {
		go func() { c.App.Run(ctx); done <- struct{}{} }()
	}
	// A degraded policy bundle loads once its source answers (bundles.Watch); the gate and records never wait on it.
	watched := make(chan struct{})
	go func() { bundles.Watch(ctx, c.Config.Policy, c.Engine, c.log); close(watched) }()
	defer func() { <-watched }()
	every := c.Config.ExpireEvery
	if every <= 0 {
		every = time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	// The grant feeds are re-signed on their own beat, whatever CLEARANCE_EXPIRE_SECONDS is.
	feeds := time.NewTicker(gate.FeedResign / 2)
	defer feeds.Stop()
	c.refresh(ctx) // a restart with a new key re-signs the live tokens at once
	for {
		select {
		case <-feeds.C:
			c.refreshFeeds(ctx)
		case <-ctx.Done():
			if c.App != nil {
				<-done
			}
			return
		case <-t.C:
			ids, err := c.Gate.Expire(ctx)
			if err != nil && ctx.Err() == nil {
				c.log.ErrorContext(ctx, "gate: expiring changes failed", "error", err.Error())
			} else if len(ids) > 0 {
				c.log.InfoContext(ctx, "gate: expired changes", "count", len(ids))
			}
			c.refresh(ctx)
		}
	}
}

// refresh re-issues the clearance tokens due and revokes the lapsed (gate.Service.Refresh), then re-signs the grant
// feeds due (gate.Service.RefreshFeeds).
func (c *Core) refresh(ctx context.Context) {
	n, revoked, err := c.Gate.Refresh(ctx)
	switch {
	case err != nil && ctx.Err() == nil:
		c.log.ErrorContext(ctx, "gate: refreshing clearance tokens failed", "error", err.Error())
	case n > 0 || revoked > 0:
		c.log.InfoContext(ctx, "gate: clearance tokens refreshed", "reissued", n, "revoked", revoked)
	}
	c.refreshFeeds(ctx)
}

// refreshFeeds keeps every cluster's signed grant feed fresh (gate.FeedResign) when none of its tokens changed.
func (c *Core) refreshFeeds(ctx context.Context) {
	signed, err := c.Gate.RefreshFeeds(ctx)
	switch {
	case err != nil && ctx.Err() == nil:
		c.log.ErrorContext(ctx, "gate: re-signing grant feeds failed", "error", err.Error(), "signed", signed)
	case signed > 0:
		c.log.DebugContext(ctx, "gate: grant feeds re-signed", "clusters", signed)
	}
}

// Run builds the core and serves it on cfg.Listen until ctx ends, then drains requests (ShutdownTimeout), stops
// the loops and closes the store. ready, when set, gets the bound address once the listener is up.
func Run(ctx context.Context, cfg Config, log *slog.Logger, ready func(addr string)) error {
	c, err := Build(ctx, cfg, nil, log)
	if err != nil {
		return err
	}
	defer c.Close()
	if log == nil {
		log = slog.Default()
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("core: listen %s: %w", cfg.Listen, err)
	}
	hs := c.Server.HTTPServer(cfg.Listen)
	loopCtx, stopLoops := context.WithCancel(context.Background())
	loopsDone := make(chan struct{})
	go func() { c.Loops(loopCtx); close(loopsDone) }()
	serveErr := make(chan error, 1)
	go func() { serveErr <- hs.Serve(ln) }()
	pol := c.Engine.Policy()
	log.Info("clearance core serving", "addr", ln.Addr().String(), "memory", cfg.Memory, "policy", pol.Bundle,
		"policy_version", pol.Version, "bundles", c.Engine.BundleNames(), "providers", len(cfg.Providers), "github_app", c.App != nil,
		"backstage", cfg.BackstageURL != "")
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
	stopLoops()
	<-loopsDone
	if errors.Is(runErr, http.ErrServerClosed) {
		runErr = nil
	}
	log.Info("clearance core stopped")
	return runErr
}

// DevAuthenticator accepts any bearer token as the principal it names ("Bearer gateway-system/gateway",
// "Bearer user:alice"): `clearance core --memory --insecure-dev-auth` only, for local runs and other packages'
// tests. Never the default, never with a durable store.
func DevAuthenticator() authn.Authenticator {
	return authn.AuthenticatorFunc(func(_ context.Context, token string) (authn.Principal, error) {
		if token == "" || len(token) > 256 || strings.ContainsAny(token, " \t\r\n") {
			return authn.Principal{}, errors.New("dev auth: the token is the principal id")
		}
		kind := authn.KindServiceAccount
		if strings.HasPrefix(token, "user:") {
			kind = authn.KindPerson
		}
		return authn.Principal{ID: token, Kind: kind}, nil
	})
}
