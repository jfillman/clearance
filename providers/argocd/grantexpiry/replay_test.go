package grantexpiry

import (
	"encoding/json"
	"fmt"
	"testing"

	agent "github.com/jfillman/clearance/providers/argocd/agent"
)

// The cases of providers/argocd/crd/test_admission.py (the admission policy against a real kube-apiserver, Deny mode),
// replayed against the webhook's handler with no API server: the same writers, objects, grants and wait Jobs. vap is
// what the policy answers there; hook is what the webhook must answer. They agree everywhere the policy's answer
// depends on matching and the clock, and the webhook must never refuse a write the policy admits under a live grant.
// Where they differ it is on purpose, and the case says why: status.valid is the policy's alone (the webhook defers),
// and an expired grant still marked valid is the I-44 defect the webhook closes.

const (
	waitImage = "registry.invalid/clearance-wait@sha256:0000000000000000000000000000000000000000000000000000000000000000"
	coreURL   = "http://clearance-core.invalid:8080"
	prevURL   = "http://clearance-core-previous.invalid:8080"
	caCM      = "ca-bundle.invalid"
	other     = "system:serviceaccount:default:somebody-else"
	far       = "2099-01-01T00:00:00Z"
)

var replayPins = Pins{WaitPin: agent.WaitPin{Image: waitImage, URL: coreURL, CAConfigMap: caCM}, PreviousURL: prevURL}

// waitJob is the Job exactly as providers/argocd/cmp/job.go builds it (test_admission.py's wait_job), changed by mutate.
func waitJob(mutate func(job, pod, ctr map[string]any)) map[string]any {
	ctr := map[string]any{"name": "wait", "image": waitImage, "args": []any{"--change", "ch-1", "--timeout", "1h0m0s"},
		"env": []any{map[string]any{"name": "CLEARANCE_URL", "value": coreURL},
			map[string]any{"name": "CLEARANCE_TOKEN_FILE", "value": "/var/run/secrets/tokens/clearance"}},
		"volumeMounts":    []any{map[string]any{"name": "clearance-token", "mountPath": "/var/run/secrets/tokens", "readOnly": true}},
		"imagePullPolicy": "IfNotPresent", "terminationMessagePolicy": "FallbackToLogsOnError",
		"resources":       map[string]any{"requests": map[string]any{"cpu": "5m", "memory": "16Mi"}, "limits": map[string]any{"memory": "64Mi"}},
		"securityContext": map[string]any{"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "capabilities": map[string]any{"drop": []any{"ALL"}}}}
	pod := map[string]any{"restartPolicy": "Never", "containers": []any{ctr}, "automountServiceAccountToken": false,
		"securityContext": map[string]any{"runAsNonRoot": true, "runAsUser": 65532, "runAsGroup": 65532, "seccompProfile": map[string]any{"type": "RuntimeDefault"}},
		"volumes": []any{map[string]any{"name": "clearance-token", "projected": map[string]any{"sources": []any{
			map[string]any{"serviceAccountToken": map[string]any{"audience": "clearance", "expirationSeconds": 3600, "path": "clearance"}}}}}}}
	job := map[string]any{"backoffLimit": 0, "activeDeadlineSeconds": 3900,
		"template": map[string]any{"metadata": map[string]any{"labels": map[string]any{"clearance.hangar.io/injected": "wait"}}, "spec": pod}}
	if mutate != nil {
		mutate(job, pod, ctr)
	}
	return map[string]any{"apiVersion": "batch/v1", "kind": "Job", "metadata": map[string]any{"name": agent.WaitJobName, "namespace": "prot",
		"labels": map[string]any{"clearance.hangar.io/injected": "wait"}, "annotations": map[string]any{"argocd.argoproj.io/hook": "PreSync"}},
		"spec": job}
}

func withCA(_, pod, ctr map[string]any) {
	ctr["volumeMounts"] = append(ctr["volumeMounts"].([]any), map[string]any{"name": "clearance-ca", "mountPath": "/etc/clearance-ca", "readOnly": true})
	pod["volumes"] = append(pod["volumes"].([]any), map[string]any{"name": "clearance-ca", "configMap": map[string]any{"name": caCM,
		"items": []any{map[string]any{"key": "ca.crt", "path": "ca.crt"}}}})
}

func onURL(u string) func(job, pod, ctr map[string]any) {
	return func(_, _, ctr map[string]any) {
		ctr["env"] = []any{map[string]any{"name": "CLEARANCE_URL", "value": u},
			map[string]any{"name": "CLEARANCE_TOKEN_FILE", "value": "/var/run/secrets/tokens/clearance"}}
	}
}

func deployDoc(name, rendered string) map[string]any {
	return map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": map[string]any{"name": name, "namespace": "prot",
		"annotations": map[string]any{agent.AnnRendered: rendered}}}
}

func activeGrant(name string, objects map[string]agent.GrantObject, carried ...agent.CarriedTree) agent.Grant {
	return grant(name, far, objects, carried...)
}

func TestReplayTestAdmissionCases(t *testing.T) {
	g1 := activeGrant("g1", objs(cmKey, h1, depKey, h2, "/ConfigMap/later", h1))
	carried := agent.CarriedTree{Change: "ch-old", Tree: "e", ExpiresAt: far, Objects: objs(cmKey, h3, "/ConfigMap/old-only", h3)}
	g1c := activeGrant("g1", g1.Spec.Objects, carried)
	g2 := activeGrant("g2", objs("/ConfigMap/other", h1))
	merged := activeGrant("clearance-merged", map[string]agent.GrantObject{
		"/ConfigMap/web-cfg": {Rendered: h1, App: "argocd/web-cfg", ExpiresAt: far}, depKey: {Rendered: h2, App: "argocd/web", ExpiresAt: far},
		"apps/Deployment/api": {Rendered: h3, App: "argocd/api", ExpiresAt: far}},
		agent.CarriedTree{Change: "ch-web-old", ExpiresAt: far, Objects: objs("/ConfigMap/web-cfg", h3)})
	merged.Labels[agent.LabelMerged] = "true"
	invalid := func(g agent.Grant) agent.Grant { f := false; g.Valid = &f; return g }
	nostatus := func(g agent.Grant) agent.Grant { g.Valid = nil; return g }
	expiredValid := activeGrant("g1", g1.Spec.Objects)
	expiredValid.Spec.ExpiresAt = past

	type rc struct {
		name      string
		user      string
		op        string
		sub       string
		ns        string
		obj       map[string]any
		grants    []agent.Grant
		vap, hook bool
	}
	cases := []rc{
		// -- protected writes: Argo's application-controller
		{name: "admit: a listed ConfigMap at its hash", obj: cmDoc("app-cm", h1), grants: []agent.Grant{g1}, vap: true, hook: true},
		{name: "admit: a listed Deployment (apps group) at its hash", obj: deployDoc("web", h2), grants: []agent.Grant{g1}, vap: true, hook: true},
		{name: "admit: an update of a listed object", op: "UPDATE", obj: cmDoc("app-cm", h1), grants: []agent.Grant{g1}, vap: true, hook: true},
		{name: "refuse: an object the grant does not list", obj: cmDoc("unlisted", h1), grants: []agent.Grant{g1}},
		{name: "refuse: a listed name, not created yet, at another hash (create)", obj: cmDoc("later", h3), grants: []agent.Grant{g1}},
		{name: "refuse: a listed name with the wrong hash (update)", op: "UPDATE", obj: cmDoc("app-cm", h3), grants: []agent.Grant{g1}},
		{name: "refuse: no rendered annotation", obj: cmDoc("bare", ""), grants: []agent.Grant{g1}},
		{name: "refuse: generateName, no name", obj: cmDoc("", h1), grants: []agent.Grant{g1}},
		{name: "not matched: another service account", user: other, obj: cmDoc("by-other", ""), grants: []agent.Grant{g1}, vap: true, hook: true},
		{name: "not matched: an admin", user: "admin", obj: cmDoc("by-admin", ""), grants: []agent.Grant{g1}, vap: true, hook: true},
		{name: "not matched: a cluster-scoped Namespace labelled protected", ns: "-", obj: map[string]any{"apiVersion": "v1", "kind": "Namespace",
			"metadata": map[string]any{"name": "prot2"}}, grants: []agent.Grant{g1}, vap: true, hook: true},
		{name: "not matched: the scale subresource as Argo", sub: "scale", obj: map[string]any{"apiVersion": "autoscaling/v1", "kind": "Scale",
			"metadata": map[string]any{"name": "web"}}, grants: []agent.Grant{g1}, vap: true, hook: true},
		// -- the injected PreSync wait Job
		{name: "admit: the Job exactly as the CMP builds it, no stamp, no grant entry", obj: waitJob(nil), grants: []agent.Grant{g1}, vap: true, hook: true},
		{name: "admit: the Job with the CMP's CA volume and mount", obj: waitJob(withCA), grants: []agent.Grant{g1}, vap: true, hook: true},
		{name: "admit: the CA volume with the API server's defaultMode 420", obj: waitJob(func(j, p, c map[string]any) {
			withCA(j, p, c)
			p["volumes"].([]any)[1].(map[string]any)["configMap"].(map[string]any)["defaultMode"] = 420
		}), grants: []agent.Grant{g1}, vap: true, hook: true},
		{name: "admit: the Job on the previous core URL (one release)", obj: waitJob(onURL(prevURL)), grants: []agent.Grant{g1}, vap: true, hook: true},
		{name: "admit: the previous URL with the CA", obj: waitJob(func(j, p, c map[string]any) { onURL(prevURL)(j, p, c); withCA(j, p, c) }),
			grants: []agent.Grant{g1}, vap: true, hook: true},
		{name: "not matched: the same Job with another image by another writer", user: other,
			obj: waitJob(func(_, _, c map[string]any) { c["image"] = "busybox" }), grants: []agent.Grant{g1}, vap: true, hook: true},
	}
	deviations := map[string]func(job, pod, ctr map[string]any){
		"another image": func(_, _, c map[string]any) { c["image"] = "busybox" },
		"an extra --url style flag": func(_, _, c map[string]any) {
			c["args"] = []any{"--change", "ch-1", "--timeout", "1h", "--url", "http://evil"}
		},
		"a different args shape": func(_, _, c map[string]any) {
			c["args"] = []any{"--url", "http://evil", "--timeout", "1h", "--change", "ch-1"}
		},
		"CLEARANCE_URL pointed elsewhere": onURL("http://evil.example"),
		"a URL near the previous one":     onURL(prevURL + "/x"),
		"an extra env var": func(_, _, c map[string]any) {
			c["env"] = append(c["env"].([]any), map[string]any{"name": "X", "value": "y"})
		},
		"envFrom": func(_, _, c map[string]any) {
			c["envFrom"] = []any{map[string]any{"secretRef": map[string]any{"name": "x"}}}
		},
		"a command override":     func(_, _, c map[string]any) { c["command"] = []any{"/bin/sh"} },
		"hostNetwork":            func(_, p, _ map[string]any) { p["hostNetwork"] = true },
		"hostPID":                func(_, p, _ map[string]any) { p["hostPID"] = true },
		"a privileged container": func(_, _, c map[string]any) { c["securityContext"] = map[string]any{"privileged": true} },
		"an extra volume": func(_, p, _ map[string]any) {
			p["volumes"] = append(p["volumes"].([]any), map[string]any{"name": "x", "emptyDir": map[string]any{}})
		},
		"a token volume for another audience": func(_, p, _ map[string]any) {
			p["volumes"].([]any)[0].(map[string]any)["projected"].(map[string]any)["sources"].([]any)[0].(map[string]any)["serviceAccountToken"].(map[string]any)["audience"] = "kubernetes.default"
		},
		"hostAliases (the pin is none)": func(_, p, _ map[string]any) {
			p["hostAliases"] = []any{map[string]any{"ip": "203.0.113.1", "hostnames": []any{"clearance-core.invalid"}}}
		},
		"an init container": func(_, p, _ map[string]any) {
			p["initContainers"] = []any{map[string]any{"name": "i", "image": "busybox"}}
		},
		"a livenessProbe": func(_, _, c map[string]any) {
			c["livenessProbe"] = map[string]any{"exec": map[string]any{"command": []any{"true"}}}
		},
		"a serviceAccountName":     func(_, p, _ map[string]any) { p["serviceAccountName"] = "default" },
		"a dnsPolicy not default":  func(_, p, _ map[string]any) { p["dnsPolicy"] = "Default" },
		"parallelism 5":            func(j, _, _ map[string]any) { j["parallelism"] = 5; j["completions"] = 5 },
		"automount true":           func(_, p, _ map[string]any) { p["automountServiceAccountToken"] = true },
		"automount unset":          func(_, p, _ map[string]any) { delete(p, "automountServiceAccountToken") },
		"a nodeName":               func(_, p, _ map[string]any) { p["nodeName"] = "somewhere" },
		"allowPrivilegeEscalation": func(_, _, c map[string]any) { c["securityContext"].(map[string]any)["allowPrivilegeEscalation"] = true },
		"a writable token mount":   func(_, _, c map[string]any) { c["volumeMounts"].([]any)[0].(map[string]any)["readOnly"] = false },
		"the CA from another ConfigMap": func(j, p, c map[string]any) {
			withCA(j, p, c)
			p["volumes"].([]any)[1].(map[string]any)["configMap"].(map[string]any)["name"] = "evil"
		},
		"the CA mounted writable": func(j, p, c map[string]any) {
			withCA(j, p, c)
			c["volumeMounts"].([]any)[1].(map[string]any)["readOnly"] = false
		},
		"the CA volume without its mount": func(j, p, c map[string]any) {
			withCA(j, p, c)
			c["volumeMounts"] = c["volumeMounts"].([]any)[:1]
		},
	}
	for what, m := range deviations {
		cases = append(cases, rc{name: "refuse: the labelled Job with " + what, obj: waitJob(m), grants: []agent.Grant{g1}})
	}
	cases = append(cases, []rc{
		// -- expiry is the agent's: status.valid
		{name: "status.valid false: the policy refuses, the webhook defers (the clock says live)", op: "UPDATE", obj: cmDoc("app-cm", h1),
			grants: []agent.Grant{invalid(g1)}, vap: false, hook: true},
		{name: "no status.valid: the policy refuses, the webhook defers", op: "UPDATE", obj: cmDoc("app-cm", h1),
			grants: []agent.Grant{nostatus(g1)}, vap: false, hook: true},
		{name: "I-44: an expired grant still marked valid: the policy admits, the webhook refuses", op: "UPDATE", obj: cmDoc("app-cm", h1),
			grants: []agent.Grant{expiredValid}, vap: true, hook: false},
		// -- the running tree beside the active grant: carried trees
		{name: "refuse: the running tree's hash while no grant carries it", op: "UPDATE", obj: cmDoc("app-cm", h3), grants: []agent.Grant{g1}},
		{name: "admit: self-heal re-applies the running tree (carried)", op: "UPDATE", obj: cmDoc("app-cm", h3), grants: []agent.Grant{g1c}, vap: true, hook: true},
		{name: "admit: the new tree syncs (the active grant's own hash)", op: "UPDATE", obj: cmDoc("app-cm", h1), grants: []agent.Grant{g1c}, vap: true, hook: true},
		{name: "admit: a carried object the active grant does not list at all", obj: cmDoc("old-only", h3), grants: []agent.Grant{g1c}, vap: true, hook: true},
		{name: "refuse: a hash neither the grant nor a carried tree lists", op: "UPDATE", obj: cmDoc("app-cm", h2), grants: []agent.Grant{g1c}},
		{name: "refuse: a carried hash does not admit another object", obj: cmDoc("old-other", h3), grants: []agent.Grant{g1c}},
		{name: "refuse: the carried object at the active grant's hash for another object", obj: cmDoc("old-only-2", h1), grants: []agent.Grant{g1c}},
		{name: "refuse: the running tree once its carried tree is dropped", op: "UPDATE", obj: cmDoc("app-cm", h3), grants: []agent.Grant{g1}},
		// -- one active grant per namespace; no active grant
		{name: "refuse: two active grants, each must pass", op: "UPDATE", obj: cmDoc("app-cm", h1), grants: []agent.Grant{g1, g2}},
		{name: "admit again once one active grant is left", op: "UPDATE", obj: cmDoc("app-cm", h1), grants: []agent.Grant{g1}, vap: true, hook: true},
		{name: "no active grant: refused", obj: cmDoc("no-grant", h3)},
		// -- the merged grant of a namespace two Applications share
		{name: "admit: the first Application's ConfigMap at its hash", obj: cmDoc("web-cfg", h1), grants: []agent.Grant{merged}, vap: true, hook: true},
		{name: "admit: the first Application's Deployment", obj: deployDoc("web", h2), grants: []agent.Grant{merged}, vap: true, hook: true},
		{name: "admit: the second Application's Deployment, same grant", obj: deployDoc("api", h3), grants: []agent.Grant{merged}, vap: true, hook: true},
		{name: "admit: the first Application's older cleared tree (carried)", op: "UPDATE", obj: cmDoc("web-cfg", h3), grants: []agent.Grant{merged}, vap: true, hook: true},
		{name: "refuse: an object no protected Application's clearance lists", obj: cmDoc("stranger", h1), grants: []agent.Grant{merged}},
		{name: "refuse: a listed Deployment at a hash nobody cleared for it", op: "UPDATE", obj: deployDoc("web", h1), grants: []agent.Grant{merged}},
	}...)

	h := handler(t, Enforce, nil)
	h.cfg.Pins = replayPins
	n := 0
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.vap && !c.hook {
				if c.name[:5] != "I-44:" {
					t.Fatal("only the I-44 case may have the webhook refuse what the policy admits")
				}
			}
			h.lookup = fakeLookup{synced: true, grants: map[string][]agent.Grant{"prot": c.grants}}
			req := reqFor(c.obj, func(r map[string]any) {
				if c.user != "" {
					r["userInfo"] = map[string]any{"username": c.user}
				}
				r["operation"] = "CREATE"
				if c.op != "" {
					r["operation"] = c.op
				}
				if c.sub != "" {
					r["subResource"] = c.sub
				}
				if c.ns == "-" {
					delete(r, "namespace")
				}
				md, _ := c.obj["metadata"].(map[string]any)
				r["name"] = fmt.Sprint(md["name"])
			})
			if r := post(t, h, req); r.Allowed != c.hook {
				b, _ := json.Marshal(r)
				t.Fatalf("webhook allowed=%v, want %v (the policy: %v): %s", r.Allowed, c.hook, c.vap, b)
			}
			n++
		})
	}
	if n < 60 {
		t.Fatalf("only %d cases replayed", n)
	}
}
