// Package bundles loads a deployment's policy bundles (internal/decide's clearance.policy/v1 files) from
// configuration, fetching each bundle's sources, and reads the deployment's environment naming. The core and
// clearance-api both load the policy through it, so they decide and explain with the same rules.
//
//	CLEARANCE_BUNDLES               comma-separated bundle files (default none: the core rules only)
//	CLEARANCE_BUNDLE_SOURCES        JSON object, source name -> {"url": "http(s)://...", "tokenFile": "..."} or
//	                                {"file": "..."}: where each bundle source is read from. A source a bundle names
//	                                and this does not configure fails the load.
//	CLEARANCE_BUNDLE_SOURCE_WAIT    how long the load keeps retrying a source it cannot fetch (Go duration,
//	                                default 60s); then it fails, and the process does not start
//	CLEARANCE_ENV_LOWER_NAMES       env argument values that are a lower environment (default dev,development,sandbox,scratch)
//	CLEARANCE_ENV_LOWER_PREFIXES    env argument prefixes that are lower (default none)
//	CLEARANCE_ENV_LOWER_PROJECT_SUFFIXES  project argument suffixes that are lower (default none: every project is upper)
//	CLEARANCE_ENV_UPPER_REPO_PREFIXES     repo name prefixes that are upper (default none: every repo is lower)
//
// There is no fallback: a source that cannot be fetched within the wait, does not parse, or is a version the
// bundle does not name as compatible fails the load, and the core does not decide on a policy it could not load.
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

// Defaults.
const (
	DefaultWait    = 60 * time.Second
	FetchTimeout   = 10 * time.Second
	retryInterval  = 2 * time.Second
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

// Load reads every bundle file and fetches its sources, retrying a source that cannot be fetched until the wait
// runs out. Any failure is the whole load's.
func Load(ctx context.Context, cfg Config, log *slog.Logger) ([]*decide.Bundle, error) {
	if log == nil {
		log = slog.Default()
	}
	client := &http.Client{Timeout: FetchTimeout}
	fetch := func(bundle string, src decide.SourceSpec) ([]byte, string, error) {
		s, ok := cfg.Sources[src.Name]
		if !ok {
			return nil, "", fmt.Errorf("no CLEARANCE_BUNDLE_SOURCES entry for %q", src.Name)
		}
		if s.File != "" {
			b, err := os.ReadFile(s.File)
			return b, s.File, err
		}
		deadline := time.Now().Add(cfg.Wait)
		for attempt := 1; ; attempt++ {
			b, err := get(ctx, client, s)
			if err == nil {
				return b, s.URL, nil
			}
			if time.Now().Add(retryInterval).After(deadline) || ctx.Err() != nil {
				return nil, s.URL, fmt.Errorf("%s: %w (after %d attempts)", s.URL, err, attempt)
			}
			log.WarnContext(ctx, "policy bundle source unavailable, retrying", "bundle", bundle, "source", src.Name,
				"url", s.URL, "attempt", attempt, "error", err.Error())
			select {
			case <-ctx.Done():
				return nil, s.URL, ctx.Err()
			case <-time.After(retryInterval):
			}
		}
	}
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
		attrs := []any{"bundle", b.Spec.Name, "version", b.Spec.Version, "digest", b.Digest}
		for _, s := range b.Sources {
			attrs = append(attrs, "source."+s.Name, fmt.Sprintf("%s v%d %s", s.Location, s.Version, s.Digest[:16]))
		}
		log.InfoContext(ctx, "policy bundle loaded", attrs...)
		out = append(out, b)
	}
	return out, nil
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
