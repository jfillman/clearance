package main

// G-ARGO-9: the Argo CD gate passes the provider conformance suite (docs/provider-protocol.md). The adapter below is
// the test-only control interface in front of the real components, run in process: the plugin's Generate (the CMP:
// render, hash, find or register the change, stamp or inject the PreSync wait Job) and the agent's outcome handling
// (providers/argocd/agent), with a fake Argo CD in between. The fake Argo CD syncs what the plugin emitted when it is
// cleared, applies it to the harness's target, and leaves the stamped objects and a finished operation for the agent.
// Nothing in either binary serves the control interface.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jfillman/clearance/client"
	"github.com/jfillman/clearance/internal/conformance"
	"github.com/jfillman/clearance/internal/conformance/fakes"
	agent "github.com/jfillman/clearance/providers/argocd/agent"
)

const conformanceVersion = "0.0.0-conformance"

// fakeArgo is the protected cluster as the agent sees it: the Applications and the live objects Argo CD applied.
// Only what the outcome handler reads does anything.
type fakeArgo struct {
	mu   sync.Mutex
	objs map[string][]agent.ObjectDetail
	data map[string]map[string]string
}

func (k *fakeArgo) ProtectedNamespaces(context.Context) (map[string]map[string]string, error) {
	return map[string]map[string]string{"conformance": {}}, nil
}
func (k *fakeArgo) ListGrants(context.Context) ([]agent.Grant, error) { return nil, nil }
func (k *fakeArgo) CreateGrant(context.Context, agent.Grant) error    { return errors.New("not used") }
func (k *fakeArgo) UpdateGrant(context.Context, agent.Grant, agent.Grant) error {
	return errors.New("not used")
}
func (k *fakeArgo) DeleteGrant(context.Context, string, string) error { return errors.New("not used") }
func (k *fakeArgo) SetGrantValid(context.Context, string, string, bool, string, time.Time) error {
	return errors.New("not used")
}
func (k *fakeArgo) ListApplications(context.Context) ([]agent.Application, string, error) {
	return nil, "1", nil
}
func (k *fakeArgo) WatchApplications(ctx context.Context, _ string, _ func(agent.Application)) error {
	<-ctx.Done()
	return nil
}
func (k *fakeArgo) ListObjects(_ context.Context, r agent.Resource, ns string) ([]agent.ObjectDetail, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	var out []agent.ObjectDetail
	for _, o := range k.objs[ns] {
		if strings.ToLower(o.Kind)+"s" == r.Plural {
			out = append(out, o)
		}
	}
	return out, nil
}
func (k *fakeArgo) GetData(_ context.Context, ns, name string) (map[string]string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.data[ns+"/"+name], nil
}
func (k *fakeArgo) PutData(_ context.Context, ns, name string, d map[string]string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.data == nil {
		k.data = map[string]map[string]string{}
	}
	k.data[ns+"/"+name] = d
	return nil
}

// recordingCore is the agent's core, noting each record's claimed source.provider.
type recordingCore struct {
	*agent.HTTPCore
	mu        sync.Mutex
	providers []string
}

func (c *recordingCore) Record(ctx context.Context, req *client.RecordRequest) (*client.RecordRef, error) {
	if src, ok := req.Record.Source["provider"].(string); ok {
		c.mu.Lock()
		c.providers = append(c.providers, src)
		c.mu.Unlock()
	}
	return c.HTTPCore.Record(ctx, req)
}

func (c *recordingCore) claimed() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.providers...)
}

// streamObjects reads the plugin's output: JSON documents after "---" lines.
func streamObjects(stream []byte) ([]map[string]any, error) {
	var objs []map[string]any
	for _, doc := range strings.Split(string(stream), "\n---\n") {
		doc = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(doc), "---"))
		if doc == "" {
			continue
		}
		var o map[string]any
		if err := json.Unmarshal([]byte(doc), &o); err != nil {
			return nil, err
		}
		objs = append(objs, o)
	}
	return objs, nil
}

func annotations(o map[string]any) map[string]any {
	md, _ := o["metadata"].(map[string]any)
	ann, _ := md["annotations"].(map[string]any)
	return ann
}

// argoAdapter is the Argo CD gate (the plugin and the agent) as a conformance provider.
func argoAdapter() (*fakes.Adapter, *recordingCore) {
	rc := &recordingCore{}
	var ad *fakes.Adapter
	ad = fakes.NewAdapter(conformance.Info{Name: agent.ProviderName, Version: conformanceVersion, Flow: conformance.FlowPushedTree,
		Stamps: []string{AnnRendered, AnnTree, AnnGrant, AnnRelease}},
		func(ctx context.Context, a conformance.ApplyRequest, p fakes.Progress) {
			var ch struct{ App, Env, Cluster, Repo, Head string }
			if err := json.Unmarshal(a.Change, &ch); err != nil {
				p.Failed("the change: " + err.Error())
				return
			}
			dir, err := os.MkdirTemp("", "argo-conformance-")
			if err != nil {
				p.Failed(err.Error())
				return
			}
			defer os.RemoveAll(dir)
			tokenFile := filepath.Join(dir, "token")
			if err := os.WriteFile(tokenFile, []byte(a.Core.Bearer), 0o600); err != nil {
				p.Failed(err.Error())
				return
			}
			// What Argo CD gives the plugin for the Application <app>-<env>, and what the sidecar is set to.
			appName := ch.App + "-" + ch.Env
			vars := map[string]string{
				"ARGOCD_APP_NAME": appName, "ARGOCD_APP_NAMESPACE": "conformance", "ARGOCD_APP_REVISION": ch.Head,
				"ARGOCD_APP_SOURCE_REPO_URL": "https://github.com/" + ch.Repo + ".git",
				"PARAM_APP":                  ch.App, "PARAM_ENV": ch.Env, "PARAM_CLUSTER": ch.Cluster,
				"CLEARANCE_URL": a.Core.URL, "CLEARANCE_TOKEN_FILE": tokenFile, "CLEARANCE_CMP_CACHE_DIR": filepath.Join(dir, "cache"),
				"CLEARANCE_WAIT_IMAGE": "registry.invalid/clearance-wait:conformance",
			}
			cfg, err := ParseConfig(func(k string) string { return vars[k] })
			if err != nil {
				p.Failed(err.Error())
				return
			}
			cc, err := client.New(client.Options{BaseURL: a.Core.URL, Token: client.FileToken(tokenFile), Provider: a.Provider,
				Timeout: 10 * time.Second, UserAgent: "clearance-argocd-cmp"})
			if err != nil {
				p.Failed(err.Error())
				return
			}
			// helm template is the one tool the render needs: the harness's manifest is its output.
			exec := func(_ context.Context, _, name string, _ ...string) ([]byte, error) {
				if name != "helm" {
					return nil, fmt.Errorf("unexpected %s", name)
				}
				return []byte(a.Manifest), nil
			}
			deps := Deps{Exec: exec, Core: cc, Cache: Cache{Dir: cfg.CacheDir}, Now: time.Now, Stderr: io.Discard}

			// Argo CD refreshes the Application: the plugin renders, and the sync waits while the change holds.
			for {
				var stream bytes.Buffer
				outcome, err := Generate(ctx, deps, cfg, dir, &stream)
				if err != nil {
					p.Refused("the plugin refused: " + err.Error()) // ComparisonError: nothing syncs
					return
				}
				objs, err := streamObjects(stream.Bytes())
				if err != nil {
					p.Failed(err.Error())
					return
				}
				if outcome == Held {
					for _, o := range objs {
						if o["kind"] == "Job" {
							p.ChangeID(fmt.Sprint(annotations(o)["clearance.hangar.io/change"]))
						}
					}
					p.Holding()
					select {
					case <-ctx.Done():
						p.Refused("gave up waiting: " + ctx.Err().Error())
						return
					case <-time.After(time.Duration(a.PollIntervalMS) * time.Millisecond):
					}
					continue
				}

				// Cleared: the sync applies what the plugin emitted.
				_, aerr := ad.ApplyTarget(ctx, a, stream.String())
				if aerr != nil {
					p.Failed("the target refused: " + aerr.Error())
					return
				}
				kube := &fakeArgo{objs: map[string][]agent.ObjectDetail{}}
				for _, o := range objs {
					md, _ := o["metadata"].(map[string]any)
					ann := map[string]string{agent.AnnTracking: appName + ":apps/Deployment:conformance/web"}
					for k, v := range annotations(o) {
						ann[k] = fmt.Sprint(v)
					}
					kube.objs["conformance"] = append(kube.objs["conformance"], agent.ObjectDetail{Object: agent.Object{
						APIVersion: fmt.Sprint(o["apiVersion"]), Kind: fmt.Sprint(o["kind"]), Namespace: "conformance",
						Name: fmt.Sprint(md["name"]), UID: "uid-" + a.ID, Annotations: ann, Manager: "argocd-controller"}})
					p.ChangeID(ann[agent.AnnGrant])
				}
				// The agent sees the finished operation and posts the outcome.
				core := &recordingCore{HTTPCore: &agent.HTTPCore{Client: cc, Feeds: agent.HTTPFeeds{Base: a.Core.URL, Token: client.FileToken(tokenFile)}}}
				ag, err := agent.New(agent.Config{Cluster: ch.Cluster, Environment: ch.Env, Version: conformanceVersion,
					ArgoNamespace: "argocd", StateNS: "clearance-system", Projects: []string{"*"}}, kube, nil, core, nil,
					slog.New(slog.NewTextHandler(io.Discard, nil)))
				if err == nil {
					err = ag.Load(ctx)
				}
				if err == nil {
					now := time.Now().UTC()
					err = ag.HandleApplication(ctx, agent.Application{Namespace: "argocd", Name: appName, UID: "uid-" + a.ID,
						Labels:  map[string]string{agent.LabelAppName: ch.App, agent.LabelAppEnv: ch.Env},
						Project: "default", DestNS: "conformance", SyncState: "Synced", Health: "Healthy", Revisions: []string{ch.Head},
						Op: &agent.Operation{Phase: "Succeeded", StartedAt: now.Format(time.RFC3339), FinishedAt: now.Add(time.Second).Format(time.RFC3339),
							Revisions: []string{ch.Head}}})
				}
				if err != nil {
					p.Failed("the agent's outcome: " + err.Error())
					return
				}
				rc.mu.Lock()
				rc.providers = append(rc.providers, core.claimed()...)
				rc.mu.Unlock()
				if got := ag.Provider(); len(core.claimed()) == 0 || core.claimed()[0] != got {
					p.Failed(fmt.Sprintf("the agent named itself %v, not %s", core.claimed(), got))
					return
				}
				p.Applied(nil)
				return
			}
		})
	return ad, rc
}

// TestArgoConformance: the plugin holds a tree nobody cleared (the PreSync wait Job, nothing applied), stamps and syncs
// it once a person clears it, finds a tree a pull request's check cleared by policy, and refuses a denied or expired
// one; the agent's outcome carries the cleared tree's digest and names argocd-agent/<version>.
func TestArgoConformance(t *testing.T) {
	ad, rc := argoAdapter()
	srv := httptest.NewServer(ad.Handler())
	t.Cleanup(func() { ad.Close(); srv.Close() })
	rep, err := conformance.Run(context.Background(), conformance.Options{Provider: srv.URL, Role: conformance.RoleDeployment,
		Timeout: 30 * time.Second, HoldWindow: 300 * time.Millisecond, PollInterval: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	rep.Print(&out)
	t.Log("\n" + out.String())
	if !rep.Pass {
		t.Fatalf("conformance failed: %v", rep.Failed())
	}
	if rep.Provider.Name != "argocd-agent" || rep.Provider.Version != conformanceVersion {
		t.Fatalf("provider %+v", rep.Provider)
	}
	// Two outcomes were applied (held then cleared, and cleared by policy): each named the agent's own identity.
	got := rc.providers
	if len(got) != 2 || got[0] != "argocd-agent/"+conformanceVersion || got[1] != got[0] {
		t.Fatalf("the agent's records named %v", got)
	}
}
