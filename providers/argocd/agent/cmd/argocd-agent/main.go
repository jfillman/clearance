// Command argocd-agent is the Argo CD gate's agent on a protected cluster (providers/argocd/agent). Settings come
// from flags, each defaulting to an environment variable; it holds no secret: its identity is the pod's projected
// service-account token.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jfillman/clearance/client"
	agent "github.com/jfillman/clearance/providers/argocd/agent"
)

var version = "dev"

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func envBool(k string) bool {
	switch strings.ToLower(os.Getenv(k)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
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
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "argocd-agent:", err)
		os.Exit(1)
	}
}

func run() error {
	fs := flag.NewFlagSet("argocd-agent", flag.ContinueOnError)
	var (
		cluster   = fs.String("cluster", env("CLEARANCE_CLUSTER", ""), "the protected cluster's name (its grant feed, every record's destination)")
		environ   = fs.String("environment", env("CLEARANCE_ENVIRONMENT", "prod"), "the environment of a namespace that has no clearance.hangar.io/environment label")
		apiURL    = fs.String("api-url", env("CLEARANCE_API_URL", ""), "clearance-api's URL (the grant feed, the keys)")
		coreURL   = fs.String("core-url", env("CLEARANCE_CORE_URL", ""), "the core's URL (records, break-glass windows)")
		tokenFile = fs.String("token-file", env("CLEARANCE_TOKEN_FILE", "/var/run/secrets/tokens/clearance"), "the projected service-account token, audience clearance")
		issuer    = fs.String("issuer", env("CLEARANCE_TOKEN_ISSUER", "clearance"), "the tokens' iss (the core's CLEARANCE_TOKEN_ISSUER)")
		argoNS    = fs.String("argocd-namespace", env("ARGOCD_NAMESPACE", "argocd"), "where the Applications live")
		projects  = fs.String("projects", env("CLEARANCE_PROTECTED_PROJECTS", ""), "the protected Argo CD projects, comma-separated (* for all)")
		stateNS   = fs.String("state-namespace", env("POD_NAMESPACE", ""), "the namespace of the agent's state ConfigMap")
		grantGV   = fs.String("grant-api", env("CLEARANCE_GRANT_API", "clearance.hangar.io/v1"), "the ClearanceGrant CRD's group/version")
		grantEvry = fs.Duration("grant-interval", 30*time.Second, "grant sync interval")
		scanEvry  = fs.Duration("scan-interval", time.Minute, "exception scan interval")
		repost    = fs.Bool("repost-on-start", false, "post each Application's last operation again on start (the core de-duplicates only on source.event_id, which the agent does not send yet)")
		waitImage = fs.String("wait-image", env("CLEARANCE_WAIT_IMAGE", ""), "the pinned image of the gate's PreSync wait Job, as the admission policy's exemption has it (empty: the Job is reported as out-of-band)")
		waitURL   = fs.String("wait-url", env("CLEARANCE_WAIT_URL", ""), "the core URL the wait Job polls (default --core-url)")
		waitAlias = fs.String("wait-host-alias", env("CLEARANCE_WAIT_HOST_ALIAS", ""), "the wait Job's host alias, ip=host[,host] (empty: none)")
		optIn     = fs.Bool("optin", envBool("CLEARANCE_OPTIN"), "the annotation opt-in (G-ARGO-10c): switch Applications carrying clearance.hangar.io/protect: \"true\" to the plugin, merge their grants per namespace, label the namespaces and report the protected pairs. Off: the agent does what it did before")
		optPlugin = fs.String("optin-plugin-name", env("CLEARANCE_OPTIN_PLUGIN_NAME", "clearance"), "the plugin name a switched Application gets (the CMP's)")
		optDeny   = fs.String("optin-deny", env("CLEARANCE_OPTIN_DENY", strings.Join(agent.DefaultDenyApps, ",")), "globs on an Application's name or <namespace>/<name> that are never switched (Clearance's own Applications), comma-separated")
		optNS     = fs.String("optin-namespaces", env("CLEARANCE_OPTIN_NAMESPACES", ""), "the destination namespaces the opt-in is configured for (globs, comma-separated): the chart's protectedNamespaces; an Application whose destination is not one of them is never switched")
		optEvery  = fs.Duration("optin-interval", 30*time.Second, "how often the opt-in reconciles the Applications")
		optReport = fs.Duration("optin-report-every", 5*time.Minute, "how often the protected pairs are reported again unchanged")
		optBytes  = fs.Int("optin-max-grant-bytes", 1_500_000, "a merged grant over this many bytes is refused and reported")
		showVer   = fs.Bool("version", false, "print the version")
	)
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}
	if *showVer {
		fmt.Println(agent.ProviderName + "/" + version)
		return nil
	}
	for k, v := range map[string]string{"cluster": *cluster, "api-url": *apiURL, "core-url": *coreURL, "projects": *projects, "state-namespace": *stateNS} {
		if v == "" {
			return fmt.Errorf("--%s is required", k)
		}
	}
	if *waitURL == "" {
		*waitURL = *coreURL
	}
	grants := agent.DefaultGrantAPI
	if g, v, ok := strings.Cut(*grantGV, "/"); ok {
		grants.Group, grants.Version = g, v
	} else {
		return fmt.Errorf("--grant-api is <group>/<version>")
	}
	kube, err := agent.InCluster(grants, *argoNS)
	if err != nil {
		return err
	}
	tok := client.FileToken(*tokenFile)
	cc, err := client.New(client.Options{BaseURL: *coreURL, Token: tok, Provider: agent.ProviderName, Timeout: 10 * time.Second,
		UserAgent: agent.ProviderName + "/" + version})
	if err != nil {
		return err
	}
	a, err := agent.New(agent.Config{Cluster: *cluster, Environment: *environ, Issuer: *issuer, Version: version,
		GrantInterval: *grantEvry, ScanInterval: *scanEvry, ArgoNamespace: *argoNS, Projects: list(*projects),
		StateNS: *stateNS, RepostOnStart: *repost,
		OptIn: agent.OptIn{Enabled: *optIn, PluginName: *optPlugin, DenyApps: list(*optDeny), Namespaces: list(*optNS), Interval: *optEvery,
			ReportEvery: *optReport, MaxGrantBytes: *optBytes},
		Wait: agent.WaitPin{Image: *waitImage, URL: *waitURL, HostAlias: *waitAlias}},
		kube, &agent.HTTPFeeds{Base: *apiURL, Token: tok},
		&agent.HTTPCore{Client: cc, Feeds: agent.HTTPFeeds{Base: *coreURL, Token: tok}}, nil,
		slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := a.Run(ctx); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}
