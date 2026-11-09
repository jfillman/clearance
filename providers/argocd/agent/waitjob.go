package agent

import (
	"encoding/json"
	"regexp"
	"strings"
)

// WaitJobName is the name the CMP gives the PreSync wait Job (providers/argocd/cmp/job.go).
const WaitJobName = "clearance-awaiting-approval"

// WaitPin is what the gate's own PreSync wait Job must run: the same three values the admission policy's exemption
// is rendered with. An empty Image is no exemption, so the Job is reported as any other unstamped object.
type WaitPin struct {
	Image     string // the pinned wait image, a digest reference
	URL       string // the core URL the waiter polls
	HostAlias string // "ip=host[,host]", empty when the waiter has no host alias
}

var (
	waitChangeID = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,80}$`)
	waitTimeout  = regexp.MustCompile(`^[0-9hms.]{1,20}$`)
)

// isWaitJob reports whether a live object is exactly the wait Job the CMP injects. The Job carries no stamp and no
// grant lists it, so without this every held release would report it as out-of-band. The name and label are free for
// anyone to copy and the job mounts a Clearance token, so this checks the same field allowlist as the admission
// policy's exemption (the waitjob, waitpod and exempt expressions of the clearance-protected-writes policy): keep the
// two in step. The scan exists to catch writes admission did not stop, so it cannot rely on admission having checked.
func isWaitJob(o ObjectDetail, pin WaitPin) bool {
	if pin.Image == "" || o.APIVersion != "batch/v1" || o.Kind != "Job" || o.Name != WaitJobName ||
		o.Labels["clearance.hangar.io/injected"] != "wait" || o.Annotations["argocd.argoproj.io/hook"] != "PreSync" {
		return false
	}
	var job map[string]any
	if err := json.Unmarshal(o.Spec, &job); err != nil {
		return false
	}
	pod := child(child(job, "template"), "spec")
	ctrs := items(pod, "containers")
	if len(ctrs) != 1 {
		return false
	}
	ctr, _ := ctrs[0].(map[string]any)
	return waitJobFields(job) && waitPodFields(pod) && waitContainer(ctr, pin) && waitHostAlias(pod, pin.HostAlias) && waitVolume(pod)
}

func waitJobFields(job map[string]any) bool {
	return only(job, "backoffLimit", "activeDeadlineSeconds", "template", "completions", "parallelism", "completionMode",
		"suspend", "podReplacementPolicy", "selector", "manualSelector") &&
		absentOr(job, "completions", float64(1)) && absentOr(job, "parallelism", float64(1)) &&
		absentOr(job, "suspend", false) && absentOr(job, "manualSelector", false) &&
		absentOr(job, "completionMode", "NonIndexed")
}

func waitPodFields(pod map[string]any) bool {
	sc := child(pod, "securityContext")
	sec := child(sc, "seccompProfile")
	return only(pod, "restartPolicy", "automountServiceAccountToken", "securityContext", "containers", "volumes",
		"hostAliases", "dnsPolicy", "schedulerName", "terminationGracePeriodSeconds") &&
		absentOr(pod, "dnsPolicy", "ClusterFirst") && absentOr(pod, "schedulerName", "default-scheduler") &&
		pod["restartPolicy"] == "Never" && pod["automountServiceAccountToken"] == false &&
		only(sc, "runAsNonRoot", "runAsUser", "runAsGroup", "seccompProfile") &&
		sc["runAsNonRoot"] == true && sc["runAsUser"] == float64(65532) && sc["runAsGroup"] == float64(65532) &&
		only(sec, "type") && sec["type"] == "RuntimeDefault"
}

func waitContainer(ctr map[string]any, pin WaitPin) bool {
	sc := child(ctr, "securityContext")
	caps := child(sc, "capabilities")
	drop := items(caps, "drop")
	args := strs(items(ctr, "args"))
	env := items(ctr, "env")
	if !only(ctr, "name", "image", "imagePullPolicy", "args", "env", "securityContext", "resources",
		"terminationMessagePolicy", "terminationMessagePath", "volumeMounts") ||
		!absentOr(ctr, "terminationMessagePath", "/dev/termination-log") || !absentOr(ctr, "imagePullPolicy", "IfNotPresent") ||
		ctr["image"] != pin.Image ||
		len(args) != 4 || args[0] != "--change" || args[2] != "--timeout" ||
		!waitChangeID.MatchString(args[1]) || !waitTimeout.MatchString(args[3]) ||
		!waitEnv(env, 0, "CLEARANCE_URL", pin.URL) || !waitEnv(env, 1, "CLEARANCE_TOKEN_FILE", "/var/run/secrets/tokens/clearance") ||
		len(env) != 2 ||
		!only(sc, "allowPrivilegeEscalation", "readOnlyRootFilesystem", "capabilities") ||
		sc["allowPrivilegeEscalation"] != false || sc["readOnlyRootFilesystem"] != true ||
		!only(caps, "drop") || len(drop) != 1 || drop[0] != "ALL" {
		return false
	}
	if _, ok := ctr["volumeMounts"]; !ok {
		return true
	}
	mounts := items(ctr, "volumeMounts")
	if len(mounts) != 1 {
		return false
	}
	m, _ := mounts[0].(map[string]any)
	return only(m, "name", "mountPath", "readOnly") && m["name"] == "clearance-token" &&
		m["mountPath"] == "/var/run/secrets/tokens" && m["readOnly"] == true
}

func waitEnv(env []any, i int, name, value string) bool {
	if i >= len(env) {
		return false
	}
	e, _ := env[i].(map[string]any)
	return only(e, "name", "value") && e["name"] == name && e["value"] == value
}

func waitHostAlias(pod map[string]any, pin string) bool {
	_, has := pod["hostAliases"]
	if pin == "" {
		return !has
	}
	aliases := items(pod, "hostAliases")
	if len(aliases) != 1 {
		return false
	}
	a, _ := aliases[0].(map[string]any)
	ip, _ := a["ip"].(string)
	return only(a, "ip", "hostnames") && ip+"="+strings.Join(strs(items(a, "hostnames")), ",") == pin
}

func waitVolume(pod map[string]any) bool {
	if _, ok := pod["volumes"]; !ok {
		return true
	}
	vols := items(pod, "volumes")
	if len(vols) != 1 {
		return false
	}
	v, _ := vols[0].(map[string]any)
	proj := child(v, "projected")
	sources := items(proj, "sources")
	if !only(v, "name", "projected") || v["name"] != "clearance-token" || proj == nil ||
		!only(proj, "sources", "defaultMode") || !absentOr(proj, "defaultMode", float64(420)) || len(sources) != 1 {
		return false
	}
	s, _ := sources[0].(map[string]any)
	tok := child(s, "serviceAccountToken")
	return only(s, "serviceAccountToken") && tok != nil && only(tok, "audience", "expirationSeconds", "path") &&
		tok["audience"] == "clearance" && absentOr(tok, "path", "clearance")
}

// only reports that m has no key outside allowed.
func only(m map[string]any, allowed ...string) bool {
	for k := range m {
		found := false
		for _, a := range allowed {
			found = found || a == k
		}
		if !found {
			return false
		}
	}
	return true
}

// absentOr reports that key k is absent from m or holds want.
func absentOr(m map[string]any, k string, want any) bool {
	v, ok := m[k]
	return !ok || v == want
}

func child(m map[string]any, k string) map[string]any {
	c, _ := m[k].(map[string]any)
	return c
}

func items(m map[string]any, k string) []any {
	l, _ := m[k].([]any)
	return l
}

// strs is l as strings; a non-string element becomes "", which no check accepts.
func strs(l []any) []string {
	out := make([]string, len(l))
	for i, v := range l {
		out[i], _ = v.(string)
	}
	return out
}
