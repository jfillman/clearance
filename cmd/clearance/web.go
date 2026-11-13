package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/jfillman/clearance/internal/cli"
	"github.com/jfillman/clearance/internal/web"
)

func init() {
	cli.Register(cli.Command{Name: "web", Summary: "serve the standalone web UI: sign-in (OIDC code + PKCE), in-memory sessions, forwarding to clearance-api and the core", Run: webCmd})
}

// webCmd is `clearance web`: internal/web on CLEARANCE_WEB_* (docs/web.md); the flags override the environment.
func webCmd(ctx context.Context, args []string, _, stderr io.Writer) int {
	cfg, err := web.FromEnv(os.Getenv)
	if err != nil {
		fmt.Fprintln(stderr, "web:", err)
		return 2
	}
	fs := flag.NewFlagSet("web", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.Listen, "listen", cfg.Listen, "listen address (env CLEARANCE_WEB_LISTEN, default :8080)")
	fs.StringVar(&cfg.PublicURL, "public-url", cfg.PublicURL, "the origin people use, https (env CLEARANCE_WEB_PUBLIC_URL)")
	fs.StringVar(&cfg.Issuer, "issuer", cfg.Issuer, "the people IdP (env CLEARANCE_WEB_ISSUER)")
	fs.StringVar(&cfg.ClientID, "client-id", cfg.ClientID, "the confidential OIDC client id (env CLEARANCE_WEB_CLIENT_ID)")
	fs.StringVar(&cfg.ClientSecretFile, "client-secret-file", cfg.ClientSecretFile, "file holding the client secret (env CLEARANCE_WEB_CLIENT_SECRET_FILE)")
	fs.StringVar(&cfg.UpstreamAudience, "upstream-audience", cfg.UpstreamAudience, "the audience the core and clearance-api require, requested from Dex by cross-client trust; empty: this client's own (env CLEARANCE_WEB_UPSTREAM_AUDIENCE)")
	fs.StringVar(&cfg.APIURL, "api-url", cfg.APIURL, "clearance-api, for reads (env CLEARANCE_WEB_API_URL)")
	fs.StringVar(&cfg.CoreURL, "core-url", cfg.CoreURL, "the core, for writes (env CLEARANCE_WEB_CORE_URL)")
	fs.StringVar(&cfg.GatewayURL, "gateway-url", cfg.GatewayURL, "the agent gateway's person controls, optional (env CLEARANCE_WEB_GATEWAY_URL)")
	fs.DurationVar(&cfg.SessionTTL, "session-ttl", cfg.SessionTTL, "longest session, at most 1h (env CLEARANCE_WEB_SESSION_TTL)")
	fs.DurationVar(&cfg.IdleTimeout, "idle-timeout", cfg.IdleTimeout, "idle timeout (env CLEARANCE_WEB_IDLE_TIMEOUT, default 15m)")
	fs.DurationVar(&cfg.FreshMaxAge, "fresh-max-age", cfg.FreshMaxAge, "max_age asked of the IdP when the core wants a fresh login (default 5m)")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return 2
	}
	log := slog.New(slog.NewJSONHandler(stderr, nil))
	srv, err := web.New(cfg, log, web.Options{Version: cliVersion()})
	if err != nil {
		fmt.Fprintln(stderr, "web:", err)
		return 2
	}
	if err := srv.Run(ctx); err != nil {
		fmt.Fprintln(stderr, "web:", err)
		return 1
	}
	return 0
}
