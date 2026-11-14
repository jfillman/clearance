package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/argosrc"
	"github.com/jfillman/clearance/internal/pycompat"
)

// Annotation opt-in (G-ARGO-10c; docs/gate.md, "Annotation opt-in").
//
// An Application carrying clearance.hangar.io/protect: "true" (exactly that value) is switched to the Clearance plugin
// with its original sources handed over as the plugin's `sources` parameter; the agent also reports its app and
// environment as a protected pair, builds the namespace's merged grant from the cleared trees of every protected
// Application that targets it, and labels the namespace protected once that grant exists. Removing the annotation
// reports the removal, takes the label off, and puts the original sources back. An Application without the annotation
// is read (its annotations and sources, to see whether it was ever switched) and never written, unless it carries the
// agent's own switched marker.
//
// Everything here is off unless Config.OptIn.Enabled.

// OptIn is the opt-in's settings. The zero value is off.
type OptIn struct {
	Enabled bool
	// PluginName is spec.source.plugin.name the switched Application gets (the CMP's name; default clearance).
	PluginName string
	// DenyApps are globs on an Application's name and on <namespace>/<name>: an Application that matches is never
	// switched whatever it carries, and one that was switched is put back. Clearance's own Applications belong here, so
	// the gate can always be repaired through Argo CD.
	DenyApps []string
	// Interval is how often the Applications are reconciled when nothing wakes the loop (default 30 s).
	Interval time.Duration
	// ReportEvery is how often the protected pairs are reported again unchanged (default 5 minutes): it is what tells
	// the core the agent is alive.
	ReportEvery time.Duration
	// ScopesEvery is how often the cluster's discovery is read again (default 10 minutes).
	ScopesEvery time.Duration
	// MaxGrantBytes bounds a merged grant's JSON (default 1,500,000: under etcd's request limit). A merged grant over
	// it is refused and reported; the namespace keeps its last good grant.
	MaxGrantBytes int
	// MaxSwitchesPer10Min bounds how often one Application is written (default 3): a parent, an ApplicationSet or a
	// person that keeps putting the original back is not fought in a loop.
	MaxSwitchesPer10Min int
}

// DefaultDenyApps are the names Clearance's own Applications are given by the charts that deploy it.
var DefaultDenyApps = []string{"clearance", "clearance-*", "*-clearance"}

func (o *OptIn) defaults() {
	if o.PluginName == "" {
		o.PluginName = "clearance"
	}
	if o.Interval <= 0 {
		o.Interval = 30 * time.Second
	}
	if o.ReportEvery <= 0 {
		o.ReportEvery = 5 * time.Minute
	}
	if o.ScopesEvery <= 0 {
		o.ScopesEvery = 10 * time.Minute
	}
	if o.MaxGrantBytes <= 0 {
		o.MaxGrantBytes = 1_500_000
	}
	if o.MaxSwitchesPer10Min <= 0 {
		o.MaxSwitchesPer10Min = 3
	}
}

// Statuses of an opt-in Application, shown in the state ConfigMap (key optin.json) and the log.
const (
	StatusSwitched = "switched"
	StatusDenied   = "denied"
)

const optInStateKey = "optin.json"

var dnsLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// appClass is one Application as the opt-in sees it.
type appClass struct {
	app      Application
	gateApp  string // the app a change is registered under
	env      string
	optedIn  bool // the annotation is exactly "true"
	denied   bool
	switched bool   // the agent switched it: the marker is there and spec.source (or sources[0]) is the plugin source
	foreign  bool   // it uses the plugin without the agent's marker (set up outside the agent): never touched
	marker   string // the switched annotation: the original shape
}

func (c appClass) key() string { return c.app.Namespace + "/" + c.app.Name }

// protectedIntent is whether the Application asks for protection and may have it.
func (c appClass) protectedIntent() bool { return c.optedIn && !c.denied }

// pendingRestore is an Application the agent switched (it carries the marker) that no longer asks to be, or may not be.
func (c appClass) pendingRestore() bool { return c.marker != "" && (!c.optedIn || c.denied) }

func (a *Agent) denied(app Application) bool {
	return pycompat.MatchAny(app.Name, a.cfg.OptIn.DenyApps) || pycompat.MatchAny(app.Namespace+"/"+app.Name, a.cfg.OptIn.DenyApps)
}

// classify reads each Application's opt-in state. It writes nothing.
func (a *Agent) classify(ctx context.Context, apps []Application) []appClass {
	out := make([]appClass, 0, len(apps))
	for _, app := range apps {
		c := appClass{app: app, gateApp: app.GateApp(), env: a.appEnvironment(ctx, app), optedIn: app.Annotations[AnnProtect] == "true",
			denied: a.denied(app), marker: app.Annotations[AnnSwitched]}
		if _, _, ok := a.pluginSource(app); ok {
			c.switched, c.foreign = c.marker != "", c.marker == ""
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	return out
}

// pluginSource is the Application's plugin source when it is this agent's (plugin name matches), with its parameters.
func (a *Agent) pluginSource(app Application) (src map[string]any, params map[string]string, ok bool) {
	raw := app.Source
	if len(raw) == 0 && len(app.Sources) == 1 {
		raw = app.Sources[0]
	}
	if len(raw) == 0 {
		return nil, nil, false
	}
	var w struct {
		Plugin *struct {
			Name       string `json:"name"`
			Parameters []struct {
				Name   string `json:"name"`
				String string `json:"string"`
			} `json:"parameters"`
		} `json:"plugin"`
	}
	if json.Unmarshal(raw, &w) != nil || w.Plugin == nil || w.Plugin.Name != a.cfg.OptIn.PluginName {
		return nil, nil, false
	}
	params = map[string]string{}
	for _, p := range w.Plugin.Parameters {
		params[p.Name] = p.String
	}
	_ = json.Unmarshal(raw, &src)
	return src, params, true
}

// originals are the Application's sources as they were before the switch: spec.source / spec.sources when it is not
// switched, the plugin's `sources` parameter when it is.
func (a *Agent) originals(app Application) ([]json.RawMessage, error) {
	if _, params, ok := a.pluginSource(app); ok {
		var out []json.RawMessage
		if err := json.Unmarshal([]byte(params["sources"]), &out); err != nil || len(out) == 0 {
			return nil, errors.New("the plugin's sources parameter is not the original sources (a JSON array)")
		}
		return out, nil
	}
	switch {
	case len(app.Source) > 0:
		return []json.RawMessage{app.Source}, nil
	case len(app.Sources) > 0:
		return app.Sources, nil
	}
	return nil, errors.New("the Application has no source")
}

type pluginParam struct {
	Name   string `json:"name"`
	String string `json:"string"`
}

type pluginSourceDoc struct {
	RepoURL        string `json:"repoURL"`
	TargetRevision string `json:"targetRevision,omitempty"`
	Path           string `json:"path,omitempty"`
	Plugin         struct {
		Name       string        `json:"name"`
		Parameters []pluginParam `json:"parameters"`
	} `json:"plugin"`
}

// carrier is the source whose repository, revision and path the plugin source takes: the first git source (the CMP
// sidecar gets a checkout of it, and Argo CD's manifest cache keys on its revision). A chart from an HTTP or OCI
// repository cannot carry a plugin.
func carrier(srcs []json.RawMessage) (repo, rev, path string, err error) {
	for _, raw := range srcs {
		var s struct {
			RepoURL        string `json:"repoURL"`
			TargetRevision string `json:"targetRevision"`
			Path           string `json:"path"`
			Chart          string `json:"chart"`
		}
		if json.Unmarshal(raw, &s) != nil {
			return "", "", "", errors.New("a source is not a JSON object")
		}
		if s.Chart == "" && s.RepoURL != "" && !strings.HasPrefix(s.RepoURL, "oci://") {
			return s.RepoURL, s.TargetRevision, s.Path, nil
		}
	}
	return "", "", "", errors.New("no git source to carry the plugin (every source is a chart from an HTTP or OCI repository)")
}

// desiredSource is the plugin source an Application is to have, from its original sources.
func (a *Agent) desiredSource(c appClass, originals []json.RawMessage, scopes []string) (json.RawMessage, error) {
	for _, p := range []struct{ name, v string }{{"app", c.gateApp}, {"env", c.env}, {"cluster", a.cfg.Cluster}} {
		if !dnsLabel.MatchString(p.v) {
			return nil, fmt.Errorf("%s %q is not a DNS label, which the plugin requires", p.name, p.v)
		}
	}
	repo, rev, path, err := carrier(originals)
	if err != nil {
		return nil, err
	}
	srcJSON, err := json.Marshal(originals)
	if err != nil {
		return nil, err
	}
	var d pluginSourceDoc
	d.RepoURL, d.TargetRevision, d.Path = repo, rev, path
	d.Plugin.Name = a.cfg.OptIn.PluginName
	d.Plugin.Parameters = []pluginParam{{"sources", string(srcJSON)}, {"app", c.gateApp}, {"env", c.env}, {"cluster", a.cfg.Cluster}}
	if len(scopes) > 0 {
		d.Plugin.Parameters = append(d.Plugin.Parameters, pluginParam{"clusterScopedKinds", strings.Join(scopes, ",")})
	}
	return json.Marshal(d)
}

func sameJSON(a, b json.RawMessage) bool {
	var x, y any
	return json.Unmarshal(a, &x) == nil && json.Unmarshal(b, &y) == nil && reflect.DeepEqual(x, y)
}

// ---- parents ---------------------------------------------------------------------------------------------------

// parentCheck says whether whatever owns the Application will leave its spec.source and spec.sources alone once the
// agent has changed them. The agent does not edit a parent: an app-of-apps is itself owned by git, and a live edit
// would be reverted by the Application above it or would put the agent in a fight. It reads the parent and reports
// what is missing.
func (a *Agent) parentCheck(ctx context.Context, apps []Application, child Application) (ok bool, reason string) {
	for _, o := range child.Owners {
		if o.Kind != "ApplicationSet" {
			continue
		}
		set, err := a.kube.GetApplicationSet(ctx, o.Name)
		switch {
		case errors.Is(err, ErrNotFound):
			return false, fmt.Sprintf("the ApplicationSet %s that owns it cannot be found", o.Name)
		case err != nil:
			return false, fmt.Sprintf("the ApplicationSet %s that owns it cannot be read: %v", o.Name, err)
		}
		if !ignoresSources(set.IgnoreApplicationDifferences, child, false) {
			return false, fmt.Sprintf("the ApplicationSet %s does not ignore /spec/source and /spec/sources (spec.ignoreApplicationDifferences): it would put the original back", o.Name)
		}
		return true, ""
	}
	parent := parentName(child)
	if parent == "" || parent == child.Name {
		return true, "" // nothing owns it
	}
	for _, p := range apps {
		if p.Name != parent || p.Namespace != child.Namespace {
			continue
		}
		if !ignoresSources(p.IgnoreDifferences, child, true) {
			return false, fmt.Sprintf("the parent Application %s has no spec.ignoreDifferences entry for group argoproj.io, kind Application, jsonPointers /spec/source and /spec/sources: it would put the original back", p.Name)
		}
		if !slices.Contains(p.SyncOptions, "RespectIgnoreDifferences=true") {
			return false, fmt.Sprintf("the parent Application %s does not sync with RespectIgnoreDifferences=true: a sync of it would overwrite the switched source", p.Name)
		}
		return true, ""
	}
	// Tracking says an Application owns it that the agent cannot see: it cannot check what that one will do.
	return false, fmt.Sprintf("the Application %s that tracks it is not in namespace %s, so its ignoreDifferences cannot be checked", parent, child.Namespace)
}

// parentName is the Application that created child, as Argo CD's resource tracking says: the annotation
// argocd.argoproj.io/tracking-id (<app>:<group>/<kind>:<namespace>/<name>) or the label app.kubernetes.io/instance.
func parentName(child Application) string {
	if v := child.Annotations[AnnTracking]; v != "" {
		if app, rest, ok := strings.Cut(v, ":"); ok && strings.HasPrefix(rest, "argoproj.io/Application:") {
			if _, n, ok := strings.Cut(app, "_"); ok {
				return n
			}
			return app
		}
	}
	return child.Labels["app.kubernetes.io/instance"]
}

// ignoresSources is whether entries ignore both /spec/source and /spec/sources (or /spec) of child. For an
// Application's spec.ignoreDifferences an entry names group argoproj.io and kind Application; an ApplicationSet's
// ignoreApplicationDifferences has neither.
func ignoresSources(entries []IgnoreDifference, child Application, resource bool) bool {
	have := map[string]bool{}
	for _, e := range entries {
		if resource && (e.Group != "argoproj.io" || e.Kind != "Application") {
			continue
		}
		if (e.Name != "" && e.Name != child.Name) || (e.Namespace != "" && e.Namespace != child.Namespace) {
			continue
		}
		for _, p := range e.JSONPointers {
			have[p] = true
		}
		for _, q := range e.JQPathExpressions {
			have[strings.TrimSpace(q)] = true
		}
	}
	return have["/spec"] || have[".spec"] || ((have["/spec/source"] && have["/spec/sources"]) || (have[".spec.source"] && have[".spec.sources"]))
}

// ---- the reconcile ---------------------------------------------------------------------------------------------

// optState is what the opt-in keeps in memory (all of it can be lost: the Applications and the cluster are the state).
type optState struct {
	switches map[string][]time.Time // writes made to an Application, to bound how often one is written
	fails    map[string]int         // consecutive failed writes
	retry    map[string]time.Time   // not before
	status   map[string]string      // last status per Application, as written to the state ConfigMap
	written  string                 // the optin.json last written
	loaded   bool                   // written has been read from the state ConfigMap
	warned   map[string]string      // a warning already logged: key -> text
	scopes   map[string]bool        // the cluster's discovery
	scopesAt time.Time
	scopesOK bool
}

func (a *Agent) opt() *optState {
	if a.optS == nil {
		a.optS = &optState{switches: map[string][]time.Time{}, fails: map[string]int{}, retry: map[string]time.Time{},
			status: map[string]string{}, warned: map[string]string{}}
	}
	return a.optS
}

func (a *Agent) warnOnce(key, msg string, kv ...any) {
	s := a.opt()
	if s.warned[key] == msg {
		return
	}
	s.warned[key] = msg
	a.log.Warn(msg, append([]any{"application", key}, kv...)...)
}

// scopeParameter is the plugin's clusterScopedKinds, from the cluster's discovery (read again every ScopesEvery). It
// fails while the discovery has never been read: switching without it would let the plugin scope a kind wrongly and
// stamp a namespace on a cluster-scoped object, so nothing is switched until it has been.
func (a *Agent) scopeParameter(ctx context.Context) ([]string, error) {
	s := a.opt()
	if !s.scopesOK || !a.now().Before(s.scopesAt.Add(a.cfg.OptIn.ScopesEvery)) {
		m, err := a.kube.ClusterScopes(ctx)
		if err != nil {
			if !s.scopesOK {
				return nil, fmt.Errorf("the cluster's discovery cannot be read: %w", err)
			}
			a.log.Warn("the cluster's discovery cannot be read again; the last answer stays", "err", err)
			return argosrc.ScopeCorrections(s.scopes), nil
		}
		s.scopes, s.scopesAt, s.scopesOK = m, a.now(), true
	}
	return argosrc.ScopeCorrections(s.scopes), nil
}

// ReconcileOptIn is one pass of the opt-in loop. It reads every Application, reports the protected pairs, puts back
// the Applications that no longer ask (or may not) be switched, and switches the ones that ask. A pass that cannot
// read the Applications changes nothing. Grants and namespace labels are the grant loop's (SyncGrants): they need the
// signed feed.
func (a *Agent) ReconcileOptIn(ctx context.Context) error {
	if !a.cfg.OptIn.Enabled {
		return nil
	}
	apps, _, err := a.kube.ListApplications(ctx)
	if err != nil {
		return fmt.Errorf("listing the Applications (nothing is changed): %w", err)
	}
	classes := a.classify(ctx, apps)
	var errs []error

	// 1. Report the protected pairs. A pair is added before its Application is switched; a removal is reported before the
	//    namespace is unlabelled or the Application put back, and nothing is put back while the core has not taken it.
	reported := a.reportPairs(ctx, classes)

	// 2. Applications that no longer ask to be protected (or never may): the label first, then the Application.
	for _, c := range classes {
		if !c.pendingRestore() {
			continue
		}
		if !reported {
			a.warnOnce(c.key(), "an opt-out is not put back yet: the core has not taken the report of it (the Application stays on the plugin)")
			continue
		}
		if err := a.restore(ctx, classes, c); err != nil {
			errs = append(errs, fmt.Errorf("restoring %s: %w", c.key(), err))
		}
	}

	// 3. Applications that ask.
	var scopes []string
	var scopeErr error
	scoped := false
	for _, c := range classes {
		if !c.protectedIntent() {
			continue
		}
		if !scoped {
			scopes, scopeErr = a.scopeParameter(ctx)
			scoped = true
		}
		if err := a.switchApp(ctx, apps, c, scopes, scopeErr); err != nil {
			errs = append(errs, fmt.Errorf("switching %s: %w", c.key(), err))
		}
	}
	if err := a.writeStatus(ctx, classes); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (a *Agent) throttled(key string) (string, bool) {
	s := a.opt()
	if t := s.retry[key]; a.now().Before(t) {
		return "retrying after earlier failures", true
	}
	cut := a.now().Add(-10 * time.Minute)
	recent := s.switches[key][:0:0]
	for _, t := range s.switches[key] {
		if t.After(cut) {
			recent = append(recent, t)
		}
	}
	s.switches[key] = recent
	if len(recent) >= a.cfg.OptIn.MaxSwitchesPer10Min {
		return fmt.Sprintf("written %d times in 10 minutes: something keeps changing it back, and the agent does not fight it", len(recent)), true
	}
	return "", false
}

// wrote records a write to an Application (or its failure) for the throttle.
func (a *Agent) wrote(key string, err error) {
	s := a.opt()
	if err != nil {
		s.fails[key]++
		back := a.cfg.OptIn.Interval << min(s.fails[key]-1, 4) // 1, 2, 4, 8, 16 intervals, then constant
		s.retry[key] = a.now().Add(back)
		return
	}
	delete(s.fails, key)
	delete(s.retry, key)
	s.switches[key] = append(s.switches[key], a.now())
}

// switchApp makes an Application that asks to be protected a plugin Application, or leaves it as it is and says why.
func (a *Agent) switchApp(ctx context.Context, apps []Application, c appClass, scopes []string, scopeErr error) error {
	key := c.key()
	block := func(why string) error {
		a.opt().status[key] = "blocked: " + why
		a.warnOnce(key, "the Application asks for protection and is not switched: "+why)
		return nil
	}
	switch {
	case c.foreign:
		return block("it already uses the plugin and was not switched by the agent: left as it is")
	case c.app.DestNS == "":
		return block("it has no destination namespace")
	}
	originals, err := a.originals(c.app)
	if err != nil {
		return block(err.Error())
	}
	if !c.switched {
		for _, raw := range originals {
			var s struct {
				Plugin *struct{} `json:"plugin"`
			}
			if json.Unmarshal(raw, &s) == nil && s.Plugin != nil {
				return block("a source already uses a plugin (the plugin renders helm, kustomize and directories only)")
			}
		}
	}
	if scopeErr != nil {
		return block(scopeErr.Error())
	}
	want, err := a.desiredSource(c, originals, scopes)
	if err != nil {
		return block(err.Error())
	}
	shape := "source"
	if c.switched {
		shape = c.marker
		if shape != "source" && shape != "sources" {
			return block("the switched annotation is " + fmt.Sprintf("%q", c.marker) + ", not source or sources: the original shape is unknown")
		}
	} else if len(c.app.Sources) > 0 {
		shape = "sources"
	}
	live := c.app.Source
	if shape == "sources" && len(c.app.Sources) > 0 {
		live = c.app.Sources[0]
	}
	if c.switched && c.marker == shape && sameJSON(live, want) && (shape == "source" || len(c.app.Sources) == 1) {
		a.opt().status[key] = StatusSwitched
		delete(a.opt().warned, key)
		return nil // nothing to write
	}
	if ok, why := a.parentCheck(ctx, apps, c.app); !ok {
		return block(why)
	}
	if why, stop := a.throttled(key); stop {
		a.opt().status[key] = "held: " + why
		a.warnOnce(key, "the Application is not written now: "+why)
		return nil
	}
	e := SourceEdit{Switched: shape}
	if shape == "source" {
		e.Source = want
	} else {
		e.Sources = []json.RawMessage{want}
	}
	err = a.kube.UpdateApplicationSource(ctx, c.app, e)
	a.wrote(key, err)
	if err != nil {
		a.opt().status[key] = "blocked: the write failed"
		return err
	}
	a.opt().status[key] = StatusSwitched
	delete(a.opt().warned, key)
	a.log.Info("Application switched to the plugin", "application", key, "shape", shape)
	return nil
}

// restore puts an Application the agent switched back exactly as it was: the label off first (a protected namespace
// refuses what the original, unstamped, would write), then the original sources, and the marker off, in one patch.
func (a *Agent) restore(ctx context.Context, classes []appClass, c appClass) error {
	key := c.key()
	if why, stop := a.throttled(key); stop {
		a.opt().status[key] = "held: " + why
		a.warnOnce(key, "the Application is not written now: "+why)
		return nil
	}
	if err := a.unlabelLosers(ctx, classes, c); err != nil {
		return err
	}
	e := SourceEdit{}
	if _, _, ok := a.pluginSource(c.app); ok {
		originals, err := a.originals(c.app)
		if err != nil {
			a.warnOnce(key, "the Application cannot be put back: "+err.Error())
			a.opt().status[key] = "blocked: " + err.Error()
			return nil
		}
		switch c.marker {
		case "source":
			if len(originals) != 1 {
				a.opt().status[key] = "blocked: the original was one source and the parameter holds more"
				return nil
			}
			e.Source = originals[0]
		case "sources":
			e.Sources = originals
		default:
			a.opt().status[key] = "blocked: the switched annotation names no original shape"
			a.warnOnce(key, "the Application cannot be put back: the switched annotation is "+fmt.Sprintf("%q", c.marker))
			return nil
		}
	} else { // the source was already put back by something else: only the marker is left
		e.Source, e.Sources = c.app.Source, c.app.Sources
	}
	err := a.kube.UpdateApplicationSource(ctx, c.app, e)
	a.wrote(key, err)
	if err != nil {
		return err
	}
	delete(a.opt().status, key)
	delete(a.opt().warned, key)
	a.log.Info("Application put back to its original sources", "application", key, "denied", c.denied, "annotated", c.optedIn)
	return nil
}

// writeStatus keeps what the opt-in is doing in the state ConfigMap (optin.json), once per change, so that
// `kubectl get cm <state> -o yaml` shows each opted-in Application's status and why one is blocked.
func (a *Agent) writeStatus(ctx context.Context, classes []appClass) error {
	s := a.opt()
	cur := map[string]string{}
	for _, c := range classes {
		switch {
		case c.optedIn && c.denied:
			cur[c.key()] = StatusDenied + ": the deny list names it"
		case c.protectedIntent():
			st := s.status[c.key()]
			if st == "" {
				st = "pending"
			}
			cur[c.key()] = st
		case c.pendingRestore():
			st := s.status[c.key()]
			if st == "" {
				st = "restore pending"
			}
			cur[c.key()] = st
		}
	}
	raw, err := json.Marshal(cur)
	if err != nil {
		return err
	}
	if !s.loaded { // what an earlier run of the agent wrote is what is there: a restart rewrites nothing
		s.loaded = true
		if data, err := a.kube.GetData(ctx, a.cfg.StateNS, a.cfg.StateName); err == nil {
			s.written = data[optInStateKey]
		}
		if s.written == "" && len(cur) == 0 {
			s.written = string(raw) // nothing opted in and nothing ever written: there is no status to keep
		}
	}
	if string(raw) == s.written {
		return nil
	}
	if err := a.kube.PutData(ctx, a.cfg.StateNS, a.cfg.StateName, map[string]string{optInStateKey: string(raw)}); err != nil {
		return fmt.Errorf("writing the opt-in status: %w", err)
	}
	s.written = string(raw)
	return nil
}

// RunOptIn is the opt-in loop: it reconciles when started, on the interval, and when an Application changes.
func (a *Agent) RunOptIn(ctx context.Context) {
	wake := make(chan struct{}, 1)
	go func() { // watch: any change to an Application wakes the loop
		for ctx.Err() == nil {
			_, rv, err := a.kube.ListApplications(ctx)
			if err != nil {
				sleep(ctx, 5*time.Second)
				continue
			}
			err = a.kube.WatchApplications(ctx, rv, func(Application) {
				select {
				case wake <- struct{}{}:
				default:
				}
			})
			if err != nil && ctx.Err() == nil && !errors.Is(err, ErrWatchGone) {
				sleep(ctx, 2*time.Second)
			}
		}
	}()
	const minGap = 5 * time.Second
	for ctx.Err() == nil {
		if err := a.ReconcileOptIn(ctx); err != nil && ctx.Err() == nil {
			a.log.Warn("loop failed", "loop", "optin", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-wake:
			sleep(ctx, minGap) // many changes arrive together: one pass for them
		case <-time.After(a.cfg.OptIn.Interval):
		}
	}
}
