// Package bundles loads a deployment's policy bundles (internal/decide's clearance.policy/v1 files) from
// configuration, fetching each bundle's sources, and reads the deployment's environment naming. The core and
// clearance-api both load the policy through it, so they decide and explain with the same rules.
//
//	CLEARANCE_BUNDLES               comma-separated bundle files (default none: the core rules only)
//	CLEARANCE_BUNDLE_SOURCES        JSON object, source name -> {"url": "http(s)://...", "tokenFile": "..."} or
//	                                {"file": "..."}: where each bundle source is read from. A source a bundle names
//	                                and this does not configure fails the load.
//	CLEARANCE_BUNDLE_SOURCE_WAIT    how long the start keeps retrying a source it cannot fetch before it goes on
//	                                with that bundle degraded (Go duration, default 10s)
//	CLEARANCE_ENV_LOWER_NAMES       env argument values that are a lower environment (default dev,development,sandbox,scratch)
//	CLEARANCE_ENV_LOWER_PREFIXES    env argument prefixes that are lower (default none)
//	CLEARANCE_ENV_LOWER_PROJECT_SUFFIXES  project argument suffixes that are lower (default none: every project is upper)
//	CLEARANCE_ENV_UPPER_REPO_PREFIXES     repo name prefixes that are upper (default none: every repo is lower)
//
// There is no fallback copy. A source that does not answer within the wait leaves its bundle degraded: the process
// starts, the bundle's tools and the checks that need the source are denied (R000, decide.SourceUnavailable), and
// Watch keeps fetching with backoff and loads the bundle whole once the source answers. A source that answers with
// a document that does not parse, or a version the bundle does not name as compatible, is a configuration error and
// fails the start (after the start, Watch logs it and keeps the bundle degraded).
package bundles

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/decide"
)

// EnvVars are the variables FromEnv reads.
var EnvVars = []string{"CLEARANCE_BUNDLES", "CLEARANCE_BUNDLE_SOURCES", "CLEARANCE_BUNDLE_SOURCE_WAIT",
	"CLEARANCE_ENV_LOWER_NAMES", "CLEARANCE_ENV_LOWER_PREFIXES", "CLEARANCE_ENV_LOWER_PROJECT_SUFFIXES",
	"CLEARANCE_ENV_UPPER_REPO_PREFIXES"}

// Source is where one source is read from: an HTTP(S) URL (with a bearer token read from TokenFile at each
// fetch, e.g. a projected service-account token), or a file.
type Source struct {
	URL       string `json:"url,omitempty"`
	TokenFile string `json:"tokenFile,omitempty"`
	File      string `json:"file,omitempty"`
}

// Config is the policy configuration.
type Config struct {
	Files        []string
	Sources      map[string]Source
	Wait         time.Duration
	Environments decide.Environments
}

// RetryInterval is the wait between fetches at start and Watch's first backoff (tests shorten it).
var RetryInterval = 2 * time.Second

// Defaults.
const (
	DefaultWait  = 10 * time.Second
	FetchTimeout = 10 * time.Second
	// MaxBackoff caps Watch's retry interval (doubling from RetryInterval).
	MaxBackoff     = 60 * time.Second
	MaxSourceBytes = 8 << 20
)

func list(v string) []string {
	out := []string{}
	for _, x := range strings.Split(v, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

// FromEnv reads the configuration.
func FromEnv(get func(string) string) (Config, error) {
	cfg := Config{Files: list(get("CLEARANCE_BUNDLES")), Sources: map[string]Source{}, Wait: DefaultWait,
		Environments: decide.DefaultEnvironments()}
	if v := get("CLEARANCE_BUNDLE_SOURCES"); v != "" {
		dec := json.NewDecoder(strings.NewReader(v))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&cfg.Sources); err != nil {
			return cfg, fmt.Errorf("CLEARANCE_BUNDLE_SOURCES: %w", err)
		}
		for name, s := range cfg.Sources {
			if (s.URL == "") == (s.File == "") || (s.File != "" && s.TokenFile != "") {
				return cfg, fmt.Errorf("CLEARANCE_BUNDLE_SOURCES: %s: give a url (with an optional tokenFile) or a file", name)
			}
			if s.URL != "" {
				u, err := url.Parse(s.URL)
				if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
					return cfg, fmt.Errorf("CLEARANCE_BUNDLE_SOURCES: %s: url must be http(s)://host/...", name)
				}
			}
		}
	}
	if v := get("CLEARANCE_BUNDLE_SOURCE_WAIT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < 0 {
			return cfg, fmt.Errorf("CLEARANCE_BUNDLE_SOURCE_WAIT: %q is not a duration", v)
		}
		cfg.Wait = d
	}
	env := &cfg.Environments
	for _, e := range []struct {
		name string
		dst  *[]string
	}{{"CLEARANCE_ENV_LOWER_NAMES", &env.LowerNames}, {"CLEARANCE_ENV_LOWER_PREFIXES", &env.LowerPrefixes},
		{"CLEARANCE_ENV_LOWER_PROJECT_SUFFIXES", &env.LowerProjectSuffixes},
		{"CLEARANCE_ENV_UPPER_REPO_PREFIXES", &env.UpperRepoPrefixes}} {
		if v := get(e.name); v != "" {
			*e.dst = list(v)
		}
	}
	return cfg, nil
}

// fetcher fetches a source; wait is how long it retries a source that does not answer (0: once).
func fetcher(ctx context.Context, cfg Config, wait time.Duration, log *slog.Logger) decide.Fetch {
	client := &http.Client{Timeout: FetchTimeout}
	return func(bundle string, src decide.SourceSpec) ([]byte, string, error) {
		s, ok := cfg.Sources[src.Name]
		if !ok {
			return nil, "", fmt.Errorf("no CLEARANCE_BUNDLE_SOURCES entry for %q", src.Name)
		}
		if s.File != "" {
			b, err := os.ReadFile(s.File)
			return b, s.File, err
		}
		deadline := time.Now().Add(wait)
		for attempt := 1; ; attempt++ {
			b, err := get(ctx, client, s)
			if err == nil {
				return b, s.URL, nil
			}
			if time.Now().Add(RetryInterval).After(deadline) || ctx.Err() != nil {
				return nil, s.URL, &decide.SourceUnavailable{Err: fmt.Errorf("%s: %w (after %d attempts)", s.URL, err, attempt)}
			}
			log.WarnContext(ctx, "policy bundle source unavailable, retrying", "bundle", bundle, "source", src.Name,
				"url", s.URL, "attempt", attempt, "error", err.Error())
			select {
			case <-ctx.Done():
				return nil, s.URL, &decide.SourceUnavailable{Err: ctx.Err()}
			case <-time.After(RetryInterval):
			}
		}
	}
}

func logLoaded(ctx context.Context, log *slog.Logger, b *decide.Bundle) {
	attrs := []any{"bundle", b.Spec.Name, "version", b.Spec.Version, "digest", b.Digest}
	for _, s := range b.Sources {
		attrs = append(attrs, "source."+s.Name, fmt.Sprintf("%s v%d %s", s.Location, s.Version, s.Digest[:16]))
	}
	if b.Degraded() {
		for _, f := range b.Unavailable {
			attrs = append(attrs, "unavailable."+f.Name, f.Error)
		}
		log.ErrorContext(ctx, "policy bundle degraded: its tools and the checks that need its source are denied (R000) until the source answers", attrs...)
		return
	}
	log.InfoContext(ctx, "policy bundle loaded", attrs...)
}

// Load reads every bundle file and fetches its sources, retrying a source that does not answer until the wait
// runs out and then going on with that bundle degraded. Any other failure is the whole load's.
func Load(ctx context.Context, cfg Config, log *slog.Logger) ([]*decide.Bundle, error) {
	if log == nil {
		log = slog.Default()
	}
	fetch := fetcher(ctx, cfg, cfg.Wait, log)
	var out []*decide.Bundle
	for _, f := range cfg.Files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("CLEARANCE_BUNDLES: %w", err)
		}
		b, err := decide.LoadBundle(data, fetch)
		if err != nil {
			return nil, fmt.Errorf("CLEARANCE_BUNDLES: %s: %w", f, err)
		}
		logLoaded(ctx, log, b)
		out = append(out, b)
	}
	return out, nil
}

// Watch fetches the sources of the engine's degraded bundles until each loads whole, then reloads the engine with
// it; it returns when none is degraded or ctx ends. The retry interval starts at 2 s and doubles to MaxBackoff. A
// source that answers with something the bundle cannot take (a version it does not list) is logged and retried:
// the bundle stays degraded.
func Watch(ctx context.Context, cfg Config, eng *decide.Engine, log *slog.Logger) {
	if log == nil {
		log = slog.Default()
	}
	fetch := fetcher(ctx, cfg, 0, log)
	backoff := RetryInterval
	for {
		deg := eng.Degraded()
		if len(deg) == 0 {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		for _, b := range deg {
			nb, err := decide.LoadBundle(b.Data(), fetch)
			if err != nil {
				log.ErrorContext(ctx, "policy bundle source answered but the bundle cannot load it; still degraded",
					"bundle", b.Spec.Name, "error", err.Error())
				continue
			}
			if nb.Degraded() {
				log.WarnContext(ctx, "policy bundle source still unavailable", "bundle", b.Spec.Name,
					"error", nb.Unavailable[0].Error, "next_retry", (2 * backoff).String())
				continue
			}
			if err := eng.Reload(nb); err != nil {
				log.ErrorContext(ctx, "policy bundle reload failed; still degraded", "bundle", b.Spec.Name, "error", err.Error())
				continue
			}
			logLoaded(ctx, log, nb)
			log.InfoContext(ctx, "policy in force", "policy", eng.Policy().Bundle, "policy_version", eng.Policy().Version)
		}
		backoff = min(2*backoff, MaxBackoff)
	}
}

func get(ctx context.Context, client *http.Client, s Source) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if s.TokenFile != "" {
		tok, err := os.ReadFile(s.TokenFile)
		if err != nil {
			return nil, fmt.Errorf("token file: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+string(bytes.TrimSpace(tok)))
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxSourceBytes+1))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if len(body) > MaxSourceBytes {
		return nil, errors.New("document over 8 MiB")
	}
	return body, nil
}

// Engine loads the policy and builds the engine.
func Engine(ctx context.Context, cfg Config, log *slog.Logger) (*decide.Engine, error) {
	bs, err := Load(ctx, cfg, log)
	if err != nil {
		return nil, err
	}
	env := cfg.Environments
	return decide.New(decide.Options{Bundles: bs, Environments: &env})
}
