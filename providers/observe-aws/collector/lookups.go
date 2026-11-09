package collector

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/jfillman/clearance/internal/observe/pipeline"
	"github.com/jfillman/clearance/providers/observe-aws/detect"
)

// ApplySource lists the applies the evidence chain records (detect.HTTPEvidence).
type ApplySource interface {
	Applies(ctx context.Context, since time.Time) ([]detect.Apply, error)
}

// EvidenceLookups is the pipeline's Lookups made from the deploy.outcome records of the chain: a cleared plan that was
// applied names its change (the grant), the digest of the plan and its apply window. That backs the two weakest signals
// of the correlation hierarchy, the plan digest (the runner's TF_APPEND_USER_AGENT claim, checked against the
// outcome) and the apply window, both of which also require the apply role. The stronger signals need records the
// chain does not carry yet (a signed execution attestation, a verified run and its session): Attestation, Run and
// Session answer "unknown" and the pipeline falls through to the next signal. Nothing here is the event's word: an
// event only supplies the key.
//
// An outcome is written after the apply finishes, so an event is assessed only after the reconciler's Settle; it must be
// longer than the longest apply.
type EvidenceLookups struct {
	Src      ApplySource
	ScopeEnv map[string]string // account -> the environment its applies are recorded under (the cleared change's env)
	Slack    time.Duration     // around an apply window (default 2m)
	Lookback time.Duration     // how far back outcomes are read (default 48h)
	Every    time.Duration     // the least time between reads (default 30s)
	Now      func() time.Time

	mu      sync.Mutex
	applies []detect.Apply
	read    time.Time
}

func (l *EvidenceLookups) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now()
}

// Refresh reads the outcomes if the last read is older than Every. On error the previous list stays in force and the
// error is returned: stale lookups only make the pipeline stricter (an event is judged without a clearance it may have).
func (l *EvidenceLookups) Refresh(ctx context.Context) error {
	l.mu.Lock()
	every := l.Every
	if every == 0 {
		every = 30 * time.Second
	}
	if !l.read.IsZero() && l.now().Sub(l.read) < every {
		l.mu.Unlock()
		return nil
	}
	l.mu.Unlock()
	back := l.Lookback
	if back == 0 {
		back = 48 * time.Hour
	}
	as, err := l.Src.Applies(ctx, l.now().Add(-back))
	if err != nil {
		return err
	}
	l.mu.Lock()
	l.applies, l.read = as, l.now()
	l.mu.Unlock()
	return nil
}

func (l *EvidenceLookups) Grant(string) (pipeline.Grant, bool)         { return pipeline.Grant{}, false }
func (l *EvidenceLookups) BreakGlass(string, time.Time) (string, bool) { return "", false }
func (l *EvidenceLookups) Attestation(string) (string, bool)           { return "", false }
func (l *EvidenceLookups) Run(string) (string, bool)                   { return "", false }
func (l *EvidenceLookups) Session(string, string) (string, bool)       { return "", false }

func bare(d string) string { return strings.TrimPrefix(strings.ToLower(d), "sha256:") }

// Plan is the applied plan with this digest, as a digest-only record (it carries no resource-change set, so it is the
// plan-digest signal, low confidence).
func (l *EvidenceLookups) Plan(digest string) (pipeline.Plan, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	d := bare(digest)
	if d == "" {
		return pipeline.Plan{}, false
	}
	for _, a := range l.applies {
		if bare(a.Digest) == d {
			return pipeline.Plan{Grant: a.Change, Digest: "sha256:" + d}, true
		}
	}
	return pipeline.Plan{}, false
}

// Window is the change whose apply window (give or take Slack) holds t, in the environment the account maps to.
func (l *EvidenceLookups) Window(scope string, t time.Time) (string, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	env, ok := l.ScopeEnv[scope]
	if !ok {
		return "", false
	}
	slack := l.Slack
	if slack == 0 {
		slack = 2 * time.Minute
	}
	for _, a := range l.applies {
		if a.Env == env && !t.Before(a.Started.Add(-slack)) && !t.After(a.Finished.Add(slack)) {
			return a.Change, true
		}
	}
	return "", false
}

var _ pipeline.Lookups = (*EvidenceLookups)(nil)
