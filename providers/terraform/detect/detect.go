// Package detect is the Terraform gate's exception detection (G-TF-5): what happens around the gate rather than
// through it. Two detectors, run on a schedule by `terraform-detector`, each posting deploy.exception through
// POST /v1/records as the registered provider terraform-detector:
//
//   - drift: terraform plan -detailed-exitcode against each protected workspace. Exit 2 (a diff nobody cleared) is
//     kind=drift naming the addresses; the core sets the coverage to observed-not-attributed.
//   - untraced apply: the versions of the workspace's state object in S3, each matched to a deploy.outcome whose
//     apply window contains it. A version no outcome explains is kind=untraced-apply, naming the CloudTrail
//     principal of the PutObject behind it.
//
// The detector only reads: terraform plan (-lock=false), S3 versions, CloudTrail, and Clearance's evidence.
package detect

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/jfillman/clearance/client"
)

// ProviderName is the provider the core registers the detector as (CLEARANCE_PROVIDERS).
const ProviderName = "terraform-detector"

// Workspace is one protected Terraform workspace the detector watches.
type Workspace struct {
	Name    string `json:"name"`    // the Terraform workspace name ("default")
	Key     string `json:"key"`     // the state object's key in Bucket
	Bucket  string `json:"bucket"`  // the S3 state bucket
	Dir     string `json:"dir"`     // the root module's directory, for the plan
	Env     string `json:"env"`     // the environment its deploy.outcome records carry
	Backend string `json:"backend"` // "s3" unless set
}

func (w Workspace) backend() string {
	if w.Backend == "" {
		return "s3"
	}
	return w.Backend
}

// Planner runs terraform plan -detailed-exitcode in ws.Dir: its exit code (0 no diff, 2 diff) and, for 2, the
// addresses that would change. An error is a plan that could not run (exit 1): no exception.
type Planner interface {
	Plan(ctx context.Context, ws Workspace) (exit int, addresses []string, err error)
}

// State lists the versions of a state object.
type State interface {
	ListVersions(ctx context.Context, bucket, key string) ([]StateVersion, error)
}

// Trail finds the PutObject events on a state object.
type Trail interface {
	StatePuts(ctx context.Context, bucket, key string, from, to time.Time) ([]PutEvent, error)
}

// Outcome is an apply window a deploy.outcome reports.
type Outcome struct {
	Env               string
	Started, Finished time.Time
}

// Reported is a deploy.exception the detector already filed: its kind, state version and drift fingerprint.
type Reported struct {
	Kind, Backend, Key, Name, Version, Fingerprint string
}

// Evidence reads Clearance's records.
type Evidence interface {
	Outcomes(ctx context.Context, since time.Time) ([]Outcome, error)
	Reported(ctx context.Context, since time.Time) ([]Reported, error)
}

// Core takes the detector's records.
type Core interface {
	Record(ctx context.Context, req *client.RecordRequest) (*client.RecordRef, error)
}

// Config is the detector's settings.
type Config struct {
	Workspaces []Workspace
	Window     time.Duration // how far back state versions are looked at (default 2h: longer than the schedule)
	DriftDedup time.Duration // how far back a filed drift suppresses the same drift (default 7 days: drift runs nightly)
	Settle     time.Duration // a version younger than this is left for its outcome to arrive (default 10m)
	Slack      time.Duration // how far outside an apply window a state write may fall and still be its (default 5m)
	Version    string
}

func (c *Config) defaults() {
	if c.Window == 0 {
		c.Window = 2 * time.Hour
	}
	if c.DriftDedup == 0 {
		c.DriftDedup = 7 * 24 * time.Hour
	}
	if c.Settle == 0 {
		c.Settle = 10 * time.Minute
	}
	if c.Slack == 0 {
		c.Slack = 5 * time.Minute
	}
}

// Detector runs both detectors.
type Detector struct {
	Cfg   Config
	Plan  Planner
	State State
	Trail Trail
	Ev    Evidence
	Core  Core
	Now   func() time.Time
	Log   *slog.Logger
}

func (d *Detector) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

func (d *Detector) log() *slog.Logger {
	if d.Log != nil {
		return d.Log
	}
	return slog.Default()
}

// Provider is the provider string of every record: terraform-detector/<version>.
func (d *Detector) Provider() string { return ProviderName + "/" + d.Cfg.Version }

// Fingerprint is what a drift is called for de-duplication: the sha256 of its sorted addresses.
func Fingerprint(addresses []string) string {
	a := append([]string(nil), addresses...)
	sort.Strings(a)
	h := sha256.Sum256([]byte(strings.Join(a, "\n")))
	return "sha256:" + hex.EncodeToString(h[:])
}

func (d *Detector) post(ctx context.Context, ws Workspace, result string, x map[string]any, principal string) error {
	x["detected_at"] = d.now().UTC().Format(time.RFC3339)
	dest := map[string]any{"workspace": map[string]any{"backend": ws.backend(), "key": ws.Key, "name": ws.Name}}
	ref, err := d.Core.Record(ctx, &client.RecordRequest{Kind: "deploy.exception", Record: client.ProviderEvent{
		Principal:   client.String(principal),
		Target:      client.String(fmt.Sprintf("%s:%s#%s", ws.backend(), ws.Key, ws.Name)),
		Result:      client.String(result),
		Destination: dest,
		Source:      map[string]any{"provider": d.Provider()},
		Exception:   x}})
	if err != nil {
		return fmt.Errorf("posting deploy.exception for %s: %w", ws.Key, err)
	}
	d.log().Warn("exception reported", "workspace", ws.Key, "kind", x["kind"], "seq", ref.Seq)
	return nil
}

// Drift plans every workspace and reports a diff as kind=drift, once per distinct set of addresses within
// DriftDedup. Every workspace is tried; the errors are joined.
func (d *Detector) Drift(ctx context.Context) error {
	d.Cfg.defaults()
	done, err := d.Ev.Reported(ctx, d.now().Add(-d.Cfg.DriftDedup))
	if err != nil {
		return fmt.Errorf("reading what is already reported: %w", err)
	}
	var errs []string
	for _, ws := range d.Cfg.Workspaces {
		exit, addrs, err := d.Plan.Plan(ctx, ws)
		switch {
		case err != nil:
			errs = append(errs, fmt.Sprintf("plan %s: %v", ws.Key, err))
			continue
		case exit == 0:
			continue
		case exit != 2:
			errs = append(errs, fmt.Sprintf("plan %s: exit %d", ws.Key, exit))
			continue
		}
		fp := Fingerprint(addrs)
		if reportedDrift(done, ws, fp) {
			continue
		}
		n := len(addrs)
		if len(addrs) == 0 { // a diff with no resource change (outputs only) names nothing to report
			addrs = []string{"(outputs or data only)"}
		}
		if len(addrs) > 4000 {
			addrs = addrs[:4000]
		}
		x := map[string]any{"kind": "drift", "addresses": addrs, "observed": fp,
			"detail": fmt.Sprintf("terraform plan -detailed-exitcode exited 2 on %s: %d address(es) differ from the state with no cleared plan behind them", ws.Key, n)}
		if err := d.post(ctx, ws, "drift", x, d.Provider()); err != nil {
			errs = append(errs, err.Error())
		}
	}
	return joinErrs(errs)
}

func reportedDrift(done []Reported, ws Workspace, fp string) bool {
	for _, r := range done {
		if r.Kind == "drift" && sameWorkspace(r, ws) && r.Fingerprint == fp {
			return true
		}
	}
	return false
}

// matches: an outcome explains a state version when it is for the workspace's environment and the version was
// written in its apply window, give or take slack.
func explained(v StateVersion, env string, outs []Outcome, slack time.Duration) bool {
	for _, o := range outs {
		if o.Env == env && !v.Modified.Before(o.Started.Add(-slack)) && !v.Modified.After(o.Finished.Add(slack)) {
			return true
		}
	}
	return false
}

// Untraced lists each workspace's state versions in the window (older than Settle) and reports each that no
// deploy.outcome explains as kind=untraced-apply, with the CloudTrail principal when one is found. A version
// already reported (exception.state.version) is not reported again.
func (d *Detector) Untraced(ctx context.Context) error {
	d.Cfg.defaults()
	now := d.now()
	from, to := now.Add(-d.Cfg.Window), now.Add(-d.Cfg.Settle)
	outs, err := d.Ev.Outcomes(ctx, from.Add(-d.Cfg.Slack-24*time.Hour))
	if err != nil {
		return fmt.Errorf("reading deploy.outcome records: %w", err) // never report from a blind outcome list
	}
	done, err := d.Ev.Reported(ctx, from)
	if err != nil {
		return fmt.Errorf("reading what is already reported: %w", err)
	}
	var errs []string
	for _, ws := range d.Cfg.Workspaces {
		if ws.backend() != "s3" {
			errs = append(errs, fmt.Sprintf("%s: the untraced-apply detector reads S3 backends only", ws.Key))
			continue
		}
		vs, err := d.State.ListVersions(ctx, ws.Bucket, ws.Key)
		if err != nil {
			errs = append(errs, fmt.Sprintf("versions of %s: %v", ws.Key, err))
			continue
		}
		var puts []PutEvent
		var fetched bool
		for _, v := range vs {
			if v.Modified.Before(from) || v.Modified.After(to) || explained(v, ws.Env, outs, d.Cfg.Slack) || reportedVersion(done, ws, v.ID) {
				continue
			}
			if !fetched { // CloudTrail is asked once per workspace, and only when there is something to name
				fetched = true
				if puts, err = d.Trail.StatePuts(ctx, ws.Bucket, ws.Key, from.Add(-d.Cfg.Slack), now); err != nil {
					d.log().Warn("cloudtrail lookup failed; the principal is unknown", "workspace", ws.Key, "err", err.Error())
				}
			}
			actor, why := nearest(puts, v.Modified, d.Cfg.Slack), ""
			if actor == "" {
				actor, why = "unknown", " (no CloudTrail PutObject event found for it)"
			}
			x := map[string]any{"kind": "untraced-apply", "actor": actor,
				"state": map[string]any{"backend": ws.backend(), "key": ws.Key, "version": v.ID},
				"detail": fmt.Sprintf("state version %s of s3://%s/%s was written at %s by %s; no deploy.outcome for %s covers that time%s",
					v.ID, ws.Bucket, ws.Key, v.Modified.UTC().Format(time.RFC3339), actor, ws.Env, why)}
			if err := d.post(ctx, ws, "untraced apply", x, actor); err != nil {
				errs = append(errs, err.Error())
			}
		}
	}
	return joinErrs(errs)
}

// sameWorkspace: the record's destination.workspace is the whole workspace {backend, key, name}.
func sameWorkspace(r Reported, ws Workspace) bool {
	return r.Backend == ws.backend() && r.Key == ws.Key && r.Name == ws.Name
}

func reportedVersion(done []Reported, ws Workspace, id string) bool {
	for _, r := range done {
		if r.Kind == "untraced-apply" && sameWorkspace(r, ws) && r.Version == id {
			return true
		}
	}
	return false
}

func nearest(puts []PutEvent, at time.Time, within time.Duration) string {
	best, who := within+1, ""
	for _, p := range puts {
		diff := p.Time.Sub(at)
		if diff < 0 {
			diff = -diff
		}
		if diff <= within && diff < best {
			best, who = diff, p.Principal
		}
	}
	return who
}

func joinErrs(errs []string) error {
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("%s", strings.Join(errs, "; "))
}
