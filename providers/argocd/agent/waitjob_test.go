package agent

import (
	"encoding/json"
	"testing"
)

var testPin = WaitPin{Image: "ghcr.io/jfillman/clearance-wait@sha256:abc", URL: "http://clearance.hangar-dev.local",
	HostAlias: "192.168.1.75=clearance.hangar-dev.local"}

// liveWaitSpec is the spec of a real wait Job read back from hangar-prod (release ch-1dda08661ae5b7b1), defaults and
// generated selector included, with the image shortened.
const liveWaitSpec = `{
 "activeDeadlineSeconds": 86700, "backoffLimit": 0, "completionMode": "NonIndexed", "completions": 1, "manualSelector": false,
 "parallelism": 1, "podReplacementPolicy": "TerminatingOrFailed",
 "selector": {"matchLabels": {"batch.kubernetes.io/controller-uid": "x"}}, "suspend": false,
 "template": {"metadata": {"labels": {"clearance.hangar.io/injected": "wait"}}, "spec": {
  "automountServiceAccountToken": false, "dnsPolicy": "ClusterFirst", "restartPolicy": "Never", "schedulerName": "default-scheduler",
  "terminationGracePeriodSeconds": 30,
  "hostAliases": [{"hostnames": ["clearance.hangar-dev.local"], "ip": "192.168.1.75"}],
  "securityContext": {"runAsGroup": 65532, "runAsNonRoot": true, "runAsUser": 65532, "seccompProfile": {"type": "RuntimeDefault"}},
  "volumes": [{"name": "clearance-token", "projected": {"defaultMode": 420, "sources": [
    {"serviceAccountToken": {"audience": "clearance", "expirationSeconds": 3600, "path": "clearance"}}]}}],
  "containers": [{"name": "wait", "image": "ghcr.io/jfillman/clearance-wait@sha256:abc", "imagePullPolicy": "IfNotPresent",
   "args": ["--change", "ch-1dda08661ae5b7b1", "--timeout", "24h0m0s"],
   "env": [{"name": "CLEARANCE_URL", "value": "http://clearance.hangar-dev.local"},
           {"name": "CLEARANCE_TOKEN_FILE", "value": "/var/run/secrets/tokens/clearance"}],
   "resources": {"limits": {"memory": "64Mi"}, "requests": {"cpu": "5m", "memory": "16Mi"}},
   "securityContext": {"allowPrivilegeEscalation": false, "capabilities": {"drop": ["ALL"]}, "readOnlyRootFilesystem": true},
   "terminationMessagePath": "/dev/termination-log", "terminationMessagePolicy": "FallbackToLogsOnError",
   "volumeMounts": [{"mountPath": "/var/run/secrets/tokens", "name": "clearance-token", "readOnly": true}]}]}}}`

func waitObject(t *testing.T, mutate func(spec map[string]any, o *ObjectDetail)) ObjectDetail {
	t.Helper()
	var spec map[string]any
	if err := json.Unmarshal([]byte(liveWaitSpec), &spec); err != nil {
		t.Fatal(err)
	}
	o := ObjectDetail{Object: Object{APIVersion: "batch/v1", Kind: "Job", Namespace: "app-gate-api-prod", Name: WaitJobName,
		Labels:      map[string]string{"clearance.hangar.io/injected": "wait"},
		Annotations: map[string]string{"argocd.argoproj.io/hook": "PreSync"}}}
	if mutate != nil {
		mutate(spec, &o)
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	o.Spec = raw
	return o
}

func podOf(spec map[string]any) map[string]any { return child(child(spec, "template"), "spec") }
func ctrOf(spec map[string]any) map[string]any {
	return items(podOf(spec), "containers")[0].(map[string]any)
}

func TestIsWaitJobAcceptsTheInjectedJob(t *testing.T) {
	if !isWaitJob(waitObject(t, nil), testPin) {
		t.Fatal("the Job as it runs on the cluster must be recognised")
	}
}

func TestIsWaitJobRefusesAnythingElse(t *testing.T) {
	type m = map[string]any
	cases := map[string]func(s m, o *ObjectDetail){
		"another name":       func(_ m, o *ObjectDetail) { o.Name = "something-else" },
		"another kind":       func(_ m, o *ObjectDetail) { o.Kind = "CronJob" },
		"no injected label":  func(_ m, o *ObjectDetail) { delete(o.Labels, "clearance.hangar.io/injected") },
		"not a PreSync hook": func(_ m, o *ObjectDetail) { o.Annotations["argocd.argoproj.io/hook"] = "PostSync" },
		"another image":      func(s m, _ *ObjectDetail) { ctrOf(s)["image"] = "ghcr.io/evil/wait@sha256:abc" },
		"a command":          func(s m, _ *ObjectDetail) { ctrOf(s)["command"] = []any{"/bin/sh"} },
		"another core":       func(s m, _ *ObjectDetail) { items(ctrOf(s), "env")[0].(m)["value"] = "http://evil" },
		"an extra env": func(s m, _ *ObjectDetail) {
			ctrOf(s)["env"] = append(items(ctrOf(s), "env"), m{"name": "X", "value": "y"})
		},
		"env from a secret": func(s m, _ *ObjectDetail) {
			items(ctrOf(s), "env")[0].(m)["valueFrom"] = m{"secretKeyRef": m{"name": "s", "key": "k"}}
		},
		"extra args":    func(s m, _ *ObjectDetail) { ctrOf(s)["args"] = append(items(ctrOf(s), "args"), "--x") },
		"bad change id": func(s m, _ *ObjectDetail) { items(ctrOf(s), "args")[1] = "$(evil)" },
		"privilege":     func(s m, _ *ObjectDetail) { child(ctrOf(s), "securityContext")["allowPrivilegeEscalation"] = true },
		"capabilities kept": func(s m, _ *ObjectDetail) {
			child(child(ctrOf(s), "securityContext"), "capabilities")["drop"] = []any{}
		},
		"writable root":     func(s m, _ *ObjectDetail) { child(ctrOf(s), "securityContext")["readOnlyRootFilesystem"] = false },
		"a service account": func(s m, _ *ObjectDetail) { podOf(s)["serviceAccountName"] = "admin" },
		"token automount":   func(s m, _ *ObjectDetail) { podOf(s)["automountServiceAccountToken"] = true },
		"an init container": func(s m, _ *ObjectDetail) { podOf(s)["initContainers"] = []any{m{"name": "x"}} },
		"two containers": func(s m, _ *ObjectDetail) {
			podOf(s)["containers"] = append(items(podOf(s), "containers"), m{"name": "x"})
		},
		"host network":       func(s m, _ *ObjectDetail) { podOf(s)["hostNetwork"] = true },
		"root":               func(s m, _ *ObjectDetail) { child(podOf(s), "securityContext")["runAsUser"] = float64(0) },
		"another host alias": func(s m, _ *ObjectDetail) { items(podOf(s), "hostAliases")[0].(m)["ip"] = "10.0.0.1" },
		"no host alias":      func(s m, _ *ObjectDetail) { delete(podOf(s), "hostAliases") },
		"another audience": func(s m, _ *ObjectDetail) {
			tok := child(items(child(items(podOf(s), "volumes")[0].(m), "projected"), "sources")[0].(m), "serviceAccountToken")
			tok["audience"] = "kubernetes"
		},
		"a second volume":  func(s m, _ *ObjectDetail) { podOf(s)["volumes"] = append(items(podOf(s), "volumes"), m{"name": "x"}) },
		"another mount":    func(s m, _ *ObjectDetail) { items(ctrOf(s), "volumeMounts")[0].(m)["mountPath"] = "/tmp" },
		"a job field":      func(s m, _ *ObjectDetail) { s["ttlSecondsAfterFinished"] = float64(1) },
		"more completions": func(s m, _ *ObjectDetail) { s["completions"] = float64(5) },
		"suspended":        func(s m, _ *ObjectDetail) { s["suspend"] = true },
		"no containers":    func(s m, _ *ObjectDetail) { delete(podOf(s), "containers") },
		"no template":      func(s m, _ *ObjectDetail) { delete(s, "template") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			if isWaitJob(waitObject(t, mutate), testPin) {
				t.Fatal("must be reported, not skipped as the wait Job")
			}
		})
	}
}

func TestIsWaitJobNeedsAPinAndASpec(t *testing.T) {
	if isWaitJob(waitObject(t, nil), WaitPin{}) {
		t.Fatal("no pinned image is no exemption")
	}
	o := waitObject(t, nil)
	o.Spec = nil
	if isWaitJob(o, testPin) {
		t.Fatal("no spec to check is no exemption")
	}
	noAlias := testPin
	noAlias.HostAlias = ""
	if isWaitJob(waitObject(t, nil), noAlias) {
		t.Fatal("a host alias where none is pinned is no exemption")
	}
}
