package core

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/authn"
	"github.com/jfillman/clearance/internal/gate"
)

func TestTheC6Settings(t *testing.T) {
	cfg, err := FromEnv(env(map[string]string{"CLEARANCE_PROTECTED_ENVIRONMENTS": "hangar-prod/*, */prod",
		"CLEARANCE_BREAKGLASS_MAX_TTL": "2h"}))
	if err != nil || strings.Join(cfg.Gate.Protected, "|") != "hangar-prod/*|*/prod" || cfg.Gate.BreakglassMaxTTL != 2*time.Hour {
		t.Fatal(cfg.Gate, err)
	}
	cfg, err = FromEnv(env(map[string]string{}))
	if err != nil || len(cfg.Gate.Protected) != 0 || cfg.Gate.BreakglassMaxTTL != 0 {
		t.Fatal("the defaults are not every environment protected and the 4h cap", cfg.Gate, err)
	}
	for _, bad := range []map[string]string{
		{"CLEARANCE_PROTECTED_ENVIRONMENTS": "prod"},
		{"CLEARANCE_PROTECTED_ENVIRONMENTS": "a/b/c"},
		{"CLEARANCE_PROTECTED_ENVIRONMENTS": "/prod"},
		{"CLEARANCE_BREAKGLASS_MAX_TTL": "5h"},
		{"CLEARANCE_BREAKGLASS_MAX_TTL": "10s"},
		{"CLEARANCE_BREAKGLASS_MAX_TTL": "soon"},
	} {
		if _, err := FromEnv(env(bad)); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}

// The trusted-registry rule fires once CLEARANCE_TRUSTED_REGISTRIES is set (hangar D23): an image bump from
// anywhere else is tier 2.
func TestTheTrustedRegistryRuleFiresFromTheEnvironment(t *testing.T) {
	cfg, err := FromEnv(env(map[string]string{"CLEARANCE_TRUSTED_REGISTRIES": "ghcr.io/riley-roooo/",
		"CLEARANCE_VERIFIERS": "ci/*"}))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Memory, cfg.Auth = true, DevAuthenticator()
	c, err := Build(context.Background(), cfg, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	body := func(image, head string) any {
		var v any
		raw := `{"app":"gate-api","env":"prod","cluster":"prod-1","repo":"o/gitops-gate-api","pr":1,"head":"` + head +
			`","proposer":"user:dana","owner":"group:default/team","treeDigest":"` + strings.Repeat("c", 64) +
			`","objects":[{"apiVersion":"apps/v1","kind":"Deployment","namespace":"ns","name":"gate-api","op":"changed",` +
			`"fields":["/spec/template/spec/containers/0/image"],"images":["` + image + `"]}],` +
			`"checks":{"ci":"pass","provenance":"not-agent","render":"ok"}}`
		dec := json.NewDecoder(strings.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	ci := authn.Principal{ID: "ci/runner", Kind: authn.KindServiceAccount}
	out, err := c.Gate.Register(context.Background(), ci, body("docker.io/library/gate-api:1", strings.Repeat("1", 40)))
	if err != nil || out.Tier != 2 || out.Reasons[0].Rule != "image:not-trusted-registry" || out.State != gate.StateHolding {
		t.Fatal(out, err)
	}
	out, err = c.Gate.Register(context.Background(), ci, body("ghcr.io/riley-roooo/gate-api@sha256:"+strings.Repeat("e", 64), strings.Repeat("2", 40)))
	if err != nil || out.Tier != 1 || out.State != gate.StateCleared {
		t.Fatal(out, err)
	}
}
