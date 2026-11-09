package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/jfillman/clearance/client"
	"github.com/jfillman/clearance/internal/gate/render"
)

// The reasons an object is an exception (the result of the record; docs/gate.md, The Argo CD agent).
const (
	ReasonNoStamp  = "no grant annotation"
	ReasonNotListd = "hash listed by no grant"
	ReasonContent  = "content differs from its stamp"
	ReasonRefused  = "sync refused by the admission policy"
)

type finding struct {
	obj    ObjectDetail
	reason string
	detail string
}

// ScanExceptions is one pass of the exception loop: it compares the objects of every protected namespace with that
// namespace's grants and posts a deploy.exception for each object no grant covers, once per finding (the state keeps
// what was reported; a finding that goes away is forgotten, so it is reported again if it comes back). A scan that
// could not read everything forgets nothing.
func (a *Agent) ScanExceptions(ctx context.Context) error {
	nss, err := a.kube.ProtectedNamespaces(ctx)
	if err != nil {
		return fmt.Errorf("listing the protected namespaces: %w", err)
	}
	grants, err := a.kube.ListGrants(ctx)
	if err != nil {
		return fmt.Errorf("listing the grants: %w", err)
	}
	windows, werr := a.core.Breakglass(ctx, a.cfg.Cluster)
	if werr != nil { // the core tags a report in a window itself; this only adds the window to the detail
		a.log.Warn("break-glass windows not read", "err", werr)
	}
	names := make([]string, 0, len(nss))
	for ns := range nss {
		names = append(names, ns)
	}
	sort.Strings(names)
	seen := map[string]bool{}
	complete := true
	var errs []error
	for _, ns := range names {
		idx, app := grantIndex(grants, ns, a.now())
		if app == "" {
			app = nss[ns][LabelApp]
		}
		if app == "" {
			app = ns
		}
		env := nss[ns][LabelEnvironment]
		if env == "" {
			env = a.cfg.Environment
		}
		var found []finding
		for _, r := range a.cfg.Resources {
			objs, err := a.kube.ListObjects(ctx, r, ns)
			if err != nil {
				complete = false
				errs = append(errs, fmt.Errorf("listing %s in %s: %w", r.Plural, ns, err))
				continue
			}
			for _, o := range objs {
				if o.Owned || slices.Contains(a.cfg.Ignore, o.Kind+"/"+o.Name) || isWaitJob(o, a.cfg.Wait) {
					continue
				}
				if f := judge(o, idx); f != nil {
					found = append(found, *f)
				}
			}
		}
		groups := map[[2]string][]finding{}
		for _, f := range found {
			fp := fingerprint(f)
			seen[fp] = true
			a.mu.Lock()
			_, posted := a.st.Exceptions[fp]
			a.mu.Unlock()
			if !posted {
				k := [2]string{f.reason, f.obj.Manager}
				groups[k] = append(groups[k], f)
			}
		}
		keys := make([][2]string, 0, len(groups))
		for k := range groups {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i][0]+keys[i][1] < keys[j][0]+keys[j][1] })
		for _, k := range keys {
			if err := a.postFindings(ctx, ns, app, env, windows, groups[k]); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if complete {
		a.mu.Lock()
		changed := false
		for fp := range a.st.Exceptions {
			if !seen[fp] && !strings.HasPrefix(fp, "refused|") {
				delete(a.st.Exceptions, fp)
				changed = true
			}
		}
		if changed {
			errs = append(errs, a.saveLocked(ctx))
		}
		a.mu.Unlock()
	}
	return errors.Join(errs...)
}

func fingerprint(f finding) string {
	o := f.obj
	return strings.Join([]string{"obj", o.APIVersion, o.Kind, o.Namespace, o.Name, o.UID, f.reason,
		o.Annotations[AnnRendered]}, "|")
}

// grantIndex is, per object key, the hashes the grants of namespace ns that are valid and unexpired list; and the app
// they are for (the newest one's label). Inactive grants count: the object may belong to an older cleared change
// that is still live.
func grantIndex(grants []Grant, ns string, now time.Time) (map[string]map[string]bool, string) {
	idx := map[string]map[string]bool{}
	app := ""
	for _, g := range grants {
		if g.Namespace != ns || g.Valid == nil || !*g.Valid || !expiryAfter(g.Spec.ExpiresAt, now) {
			continue
		}
		if app == "" || g.Active() {
			app = g.Labels[LabelApp]
		}
		for k, o := range g.Spec.Objects {
			if idx[k] == nil {
				idx[k] = map[string]bool{}
			}
			idx[k][trimSHA(o.Rendered)] = true
		}
	}
	return idx, app
}

// judge decides whether a live object is an exception: no stamp, a stamp no grant lists for it, or (when Argo CD's
// client-side apply left its last-applied configuration) content that does not hash to its stamp. The stamp is what
// admission matches; the last-applied content is the only evidence of what was written that survives API-server
// defaulting (docs/gate.md, (b) Grant matching on the stamped annotation).
func judge(o ObjectDetail, idx map[string]map[string]bool) *finding {
	stamp := trimSHA(o.Annotations[AnnRendered])
	if stamp == "" {
		return &finding{o, ReasonNoStamp, "the object carries no " + AnnRendered + " annotation"}
	}
	if !idx[GrantKey(o.Group(), o.Kind, o.Name)][stamp] {
		return &finding{o, ReasonNotListd, fmt.Sprintf("stamp %s is listed by no valid grant of %s", short(stamp), o.Namespace)}
	}
	if o.LastApplied != "" {
		h, err := ContentHash(o.LastApplied)
		if err != nil { // unreadable last-applied evidence is not evidence of a match
			return &finding{o, ReasonContent, "the last-applied configuration cannot be read: " + truncate(err.Error(), 200)}
		}
		if h != stamp {
			return &finding{o, ReasonContent, fmt.Sprintf("the last-applied configuration hashes to %s, the stamp says %s",
				short(h), short(stamp))}
		}
	}
	return nil
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// ContentHash is the rendered-object hash of a last-applied configuration: the object without Argo CD's tracking id
// and without the gate's own annotations, hashed as the manifest-tree digest hashes an object (render.ObjectDigest).
func ContentHash(lastApplied string) (string, error) {
	dec := json.NewDecoder(strings.NewReader(lastApplied))
	dec.UseNumber()
	var o map[string]any
	if err := dec.Decode(&o); err != nil {
		return "", err
	}
	if md, ok := o["metadata"].(map[string]any); ok {
		if ann, ok := md["annotations"].(map[string]any); ok {
			for _, k := range []string{AnnTracking, AnnRendered, AnnGrant, AnnTree, AnnStampRelease} {
				delete(ann, k)
			}
			if len(ann) == 0 {
				delete(md, "annotations")
			}
		}
	}
	raw, err := json.Marshal(o)
	if err != nil {
		return "", err
	}
	set := render.Set{}
	if err := render.Add(set, bytes.TrimSpace(raw)); err != nil {
		return "", err
	}
	if len(set) != 1 {
		return "", errors.New("the last-applied configuration is not one object")
	}
	for _, d := range set {
		return render.ObjectDigest(d), nil
	}
	return "", nil
}

func (a *Agent) breakglassFor(windows []Window, env, app string) string {
	for _, w := range windows {
		if (w.Env == env || w.Env == "*") && (w.App == nil || *w.App == app) {
			return w.ID
		}
	}
	return ""
}

// postFindings posts one deploy.exception (out-of-band) for the findings of one namespace, one reason and one writer.
func (a *Agent) postFindings(ctx context.Context, ns, app, env string, windows []Window, fs []finding) error {
	objs := make([]map[string]any, 0, len(fs))
	for _, f := range fs {
		o := map[string]any{"apiVersion": f.obj.APIVersion, "kind": f.obj.Kind, "namespace": f.obj.Namespace, "name": f.obj.Name}
		if r := f.obj.Annotations[AnnRendered]; r != "" {
			o["rendered"] = r
		}
		if g := f.obj.Annotations[AnnGrant]; g != "" {
			o["grant"] = g
		}
		objs = append(objs, o)
	}
	first := fs[0].obj
	principal := "unknown writer"
	if first.Manager != "" {
		principal = "field manager " + first.Manager
	}
	target := fmt.Sprintf("%s/%s/%s/%s", first.APIVersion, first.Kind, first.Namespace, first.Name)
	if len(fs) > 1 {
		target = fmt.Sprintf("%d objects in %s", len(fs), ns)
	}
	detail := fs[0].detail
	if len(fs) > 1 {
		detail = fmt.Sprintf("%d objects; first: %s", len(fs), detail)
	}
	if w := a.breakglassFor(windows, env, app); w != "" {
		detail += "; break-glass window " + w + " is open here"
	}
	req := &client.RecordRequest{Kind: "deploy.exception", Record: client.ProviderEvent{
		Principal:   client.String(principal),
		Target:      client.String(target),
		App:         client.String(app),
		Result:      client.String(fs[0].reason),
		Destination: map[string]any{"cluster": a.cfg.Cluster, "environment": env, "namespace": ns},
		Source:      map[string]any{"provider": a.Provider()},
		Exception: map[string]any{"kind": "out-of-band", "objects": objs, "detected_at": a.now().UTC().Format(time.RFC3339),
			"detail": truncate(detail, 1000)}}}
	ref, err := a.core.Record(ctx, req)
	if err != nil {
		return fmt.Errorf("posting deploy.exception for %s: %w", ns, err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now().UTC().Format(time.RFC3339)
	for _, f := range fs {
		a.st.Exceptions[fingerprint(f)] = now
	}
	a.log.Warn("exception reported", "namespace", ns, "reason", fs[0].reason, "objects", len(fs), "seq", ref.Seq)
	return a.saveLocked(ctx)
}

// reportRefusedSync posts a deploy.exception for a failed sync whose message is the admission policy's refusal.
func (a *Agent) reportRefusedSync(ctx context.Context, app Application, opKey string) error {
	op := app.Op
	if op.Phase != "Failed" && op.Phase != "Error" {
		return nil
	}
	refusal := func(s string) bool {
		return slices.ContainsFunc(a.cfg.PolicyMarkers, func(m string) bool { return strings.Contains(s, m) })
	}
	var objs []map[string]any
	var why string
	for _, r := range op.Resources {
		if refusal(r.Message) {
			o := map[string]any{"kind": r.Kind, "name": r.Name}
			switch {
			case r.Version == "":
			case r.Group == "":
				o["apiVersion"] = r.Version
			default:
				o["apiVersion"] = r.Group + "/" + r.Version
			}
			if r.Namespace != "" {
				o["namespace"] = r.Namespace
			}
			objs = append(objs, o)
			if why == "" {
				why = r.Message
			}
		}
	}
	if len(objs) == 0 {
		if !refusal(op.Message) {
			return nil
		}
		objs = []map[string]any{{"apiVersion": "argoproj.io/v1alpha1", "kind": "Application", "namespace": app.Namespace, "name": app.Name}}
		why = op.Message
	}
	fp := "refused|" + app.Namespace + "/" + app.Name + "|" + opKey
	a.mu.Lock()
	_, done := a.st.Exceptions[fp]
	a.mu.Unlock()
	if done {
		return nil
	}
	env := a.appEnvironment(ctx, app)
	req := &client.RecordRequest{Kind: "deploy.exception", Record: client.ProviderEvent{
		Principal:   client.String("argocd-application-controller"),
		Target:      client.String(fmt.Sprintf("%s/%s", app.DestNS, app.Name)),
		App:         client.String(app.GateApp()),
		Result:      client.String(ReasonRefused),
		Destination: map[string]any{"cluster": a.cfg.Cluster, "environment": env, "application": app.Name, "namespace": app.DestNS},
		Source:      map[string]any{"provider": a.Provider(), "operation": opKey},
		Exception: map[string]any{"kind": "out-of-band", "objects": objs, "detected_at": a.now().UTC().Format(time.RFC3339),
			"detail": truncate(why, 1000)}}}
	if w, err := a.core.Breakglass(ctx, a.cfg.Cluster); err == nil {
		if id := a.breakglassFor(w, env, app.GateApp()); id != "" {
			req.Record.Exception["detail"] = truncate(why, 900) + "; break-glass window " + id + " is open here"
		}
	}
	ref, err := a.core.Record(ctx, req)
	if err != nil {
		return fmt.Errorf("posting deploy.exception for the refused sync of %s: %w", app.Name, err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for k := range a.st.Exceptions { // only the newest operation's refusal is kept
		if strings.HasPrefix(k, "refused|"+app.Namespace+"/"+app.Name+"|") {
			delete(a.st.Exceptions, k)
		}
	}
	a.st.Exceptions[fp] = a.now().UTC().Format(time.RFC3339)
	a.log.Warn("refused sync reported", "app", app.Namespace+"/"+app.Name, "seq", ref.Seq)
	return a.saveLocked(ctx)
}
