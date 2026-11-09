package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jfillman/clearance/client"
)

// Core is the Clearance core as the agent uses it: its own records, and the break-glass windows open now.
type Core interface {
	Record(ctx context.Context, req *client.RecordRequest) (*client.RecordRef, error)
	Breakglass(ctx context.Context, cluster string) ([]Window, error)
}

// Window is an open break-glass window (GET /v1/breakglass).
type Window struct {
	ID      string  `json:"id"`
	Cluster string  `json:"cluster"`
	Env     string  `json:"env"`
	App     *string `json:"app"`
}

// Feeds is clearance-api as the agent reads it: the verification keys and the cluster's signed grant feed.
type Feeds interface {
	Keys(ctx context.Context) (jwks []byte, err error)
	Feed(ctx context.Context, cluster string) (body []byte, err error)
}

// Config is the agent's settings.
type Config struct {
	Cluster     string // the protected cluster this agent runs on: its feed, and every record's destination
	Environment string // the environment of a namespace that does not say (clearance.hangar.io/environment)
	Issuer      string // the tokens' and feeds' iss (CLEARANCE_TOKEN_ISSUER; default clearance)
	Version     string // the agent's version: argocd-agent/<version> on every record

	GrantInterval time.Duration // grant sync, default 30 s
	ScanInterval  time.Duration // exception scan, default 60 s
	ResyncEvery   time.Duration // outcomes re-list, default 2 min (a post that failed is retried by it)

	ArgoNamespace string   // where the Applications live
	Projects      []string // the protected Argo CD projects ("*": every project)
	StateNS       string   // the ConfigMap holding the agent's state
	StateName     string
	Resources     []Resource // the kinds the exception scan reads
	Ignore        []string   // Kind/name the scan skips (the objects every namespace gets)
	Wait          WaitPin    // the gate's own PreSync wait Job, which the scan does not report
	// PolicyMarkers are the texts that mark an Argo CD sync message as the admission policy's refusal.
	PolicyMarkers []string
	// RepostOnStart posts each Application's last operation again on start. The core de-duplicates only records that
	// carry source.event_id (O-1), which the agent does not send yet (docs/gate.md), so it is off; the state ConfigMap already stops a restart posting what was posted.
	RepostOnStart bool
}

// Defaults fills in what is unset.
func (c *Config) Defaults() {
	set := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	set(&c.GrantInterval, 30*time.Second)
	set(&c.ScanInterval, time.Minute)
	set(&c.ResyncEvery, 2*time.Minute)
	if c.Issuer == "" {
		c.Issuer = "clearance"
	}
	if c.Environment == "" {
		c.Environment = "prod"
	}
	if c.StateName == "" {
		c.StateName = "clearance-argocd-agent-state"
	}
	if c.Resources == nil {
		c.Resources = DefaultResources
	}
	if c.Ignore == nil {
		c.Ignore = []string{"ConfigMap/kube-root-ca.crt", "ServiceAccount/default"}
	}
	if c.PolicyMarkers == nil {
		c.PolicyMarkers = []string{"ValidatingAdmissionPolicy", "clearance.hangar.io"}
	}
}

// DefaultResources are the kinds a protected namespace holds that a writer could change.
var DefaultResources = []Resource{
	{"apps", "v1", "deployments"}, {"apps", "v1", "statefulsets"}, {"apps", "v1", "daemonsets"},
	{"batch", "v1", "cronjobs"}, {"batch", "v1", "jobs"},
	{"", "v1", "services"}, {"", "v1", "configmaps"}, {"", "v1", "serviceaccounts"},
	{"networking.k8s.io", "v1", "networkpolicies"}, {"networking.k8s.io", "v1", "ingresses"},
	{"argoproj.io", "v1alpha1", "rollouts"},
}

// Check refuses a configuration that cannot work.
func (c *Config) Check() error {
	switch {
	case c.Cluster == "":
		return errors.New("agent: the cluster is required")
	case c.ArgoNamespace == "":
		return errors.New("agent: the Argo CD namespace is required")
	case c.StateNS == "":
		return errors.New("agent: the state namespace is required")
	case c.Version == "":
		return errors.New("agent: the version is required")
	}
	return nil
}

// Agent is the controller. Create it with New, run it with Run (the three loops), or call the loops' steps.
type Agent struct {
	cfg   Config
	kube  Kube
	feeds Feeds
	core  Core
	now   func() time.Time
	log   *slog.Logger

	mu   sync.Mutex // the state, and the keys
	st   State
	keys keyCache

	protMu   sync.Mutex // the protected-namespace cache of handleApp
	prot     map[string]map[string]string
	protUpTo time.Time
}

// New builds an agent. now and log may be nil.
func New(cfg Config, kube Kube, feeds Feeds, core Core, now func() time.Time, log *slog.Logger) (*Agent, error) {
	cfg.Defaults()
	if err := cfg.Check(); err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	if log == nil {
		log = slog.Default()
	}
	return &Agent{cfg: cfg, kube: kube, feeds: feeds, core: core, now: now, log: log}, nil
}

// Provider is argocd-agent/<version>, which every record carries in source.provider.
func (a *Agent) Provider() string { return ProviderName + "/" + a.cfg.Version }

// State is what survives a restart: the feed epoch beside the last seq applied, the last outcome posted per
// Application and the exceptions already reported.
type State struct {
	Epoch      string            `json:"epoch"`
	Seq        int64             `json:"seq"`
	Outcomes   map[string]string `json:"outcomes"`
	Exceptions map[string]string `json:"exceptions"`
}

const stateKey = "state.json"

// Load reads the state ConfigMap (none yet: empty state).
func (a *Agent) Load(ctx context.Context) error {
	data, err := a.kube.GetData(ctx, a.cfg.StateNS, a.cfg.StateName)
	if err != nil {
		return fmt.Errorf("agent: reading the state: %w", err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.st = State{}
	if raw, ok := data[stateKey]; ok {
		if err := json.Unmarshal([]byte(raw), &a.st); err != nil {
			return fmt.Errorf("agent: the state is not JSON: %w", err)
		}
	}
	if a.st.Outcomes == nil {
		a.st.Outcomes = map[string]string{}
	}
	if a.st.Exceptions == nil {
		a.st.Exceptions = map[string]string{}
	}
	return nil
}

// saveLocked writes the state; the caller holds a.mu.
func (a *Agent) saveLocked(ctx context.Context) error {
	raw, err := json.Marshal(a.st)
	if err != nil {
		return err
	}
	return a.kube.PutData(ctx, a.cfg.StateNS, a.cfg.StateName, map[string]string{stateKey: string(raw)})
}

// Run starts the three loops and returns when ctx ends. A loop's failure is logged and retried on its interval:
// nothing here deletes or restarts a workload, so a failing loop leaves what runs as it is.
func (a *Agent) Run(ctx context.Context) error {
	if err := a.Load(ctx); err != nil {
		return err
	}
	var wg sync.WaitGroup
	tick := func(every time.Duration, name string, fn func(context.Context) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if err := fn(ctx); err != nil && ctx.Err() == nil {
					a.log.Warn("loop failed", "loop", name, "err", err)
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(every):
				}
			}
		}()
	}
	tick(a.cfg.GrantInterval, "grants", a.SyncGrants)
	tick(a.cfg.ScanInterval, "exceptions", a.ScanExceptions)
	wg.Add(1)
	go func() { defer wg.Done(); a.RunOutcomes(ctx) }()
	wg.Wait()
	return ctx.Err()
}
