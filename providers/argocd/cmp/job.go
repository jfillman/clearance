package main

import (
	"fmt"
	"strings"
)

// WaitJobName is what Argo CD's UI and history show for the hook: "clearance-awaiting-approval".
const WaitJobName = "clearance-awaiting-approval"

// WaitJob is the PreSync hook injected while a change is held for people (providers/argocd/wait). It polls the
// core until the change is cleared (exit 0) or denied, expired or timed out (non-zero), so the sync reads
// "PreSync: clearance awaiting approval" until a person clears it. It is not a control: `argocd app sync
// --strategy apply` skips hooks, and admission (the ClearanceGrant policy) refuses the objects without a grant.
func WaitJob(cfg Config, changeID string) (map[string]any, error) {
	if cfg.WaitImage == "" {
		return nil, fmt.Errorf("a change is held for people but CLEARANCE_WAIT_IMAGE is not set: the PreSync wait Job cannot be injected")
	}
	pod := map[string]any{
		"restartPolicy":                "Never",
		"automountServiceAccountToken": false,
		"securityContext": map[string]any{"runAsNonRoot": true, "runAsUser": 65532, "runAsGroup": 65532,
			"seccompProfile": map[string]any{"type": "RuntimeDefault"}},
		"containers": []any{map[string]any{
			"name": "wait", "image": cfg.WaitImage, "imagePullPolicy": "IfNotPresent",
			"args": []any{"--change", changeID, "--timeout", cfg.WaitTimeout.String()},
			"env": []any{
				map[string]any{"name": "CLEARANCE_URL", "value": cfg.CoreURL},
				map[string]any{"name": "CLEARANCE_TOKEN_FILE", "value": "/var/run/secrets/tokens/clearance"},
			},
			"securityContext": map[string]any{"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true,
				"capabilities": map[string]any{"drop": []any{"ALL"}}},
			"resources": map[string]any{"requests": map[string]any{"cpu": "5m", "memory": "16Mi"},
				"limits": map[string]any{"memory": "64Mi"}},
			"terminationMessagePolicy": "FallbackToLogsOnError",
			"volumeMounts":             []any{map[string]any{"name": "clearance-token", "mountPath": "/var/run/secrets/tokens", "readOnly": true}},
		}},
		"volumes": []any{map[string]any{"name": "clearance-token", "projected": map[string]any{"sources": []any{
			map[string]any{"serviceAccountToken": map[string]any{"audience": "clearance", "expirationSeconds": 3600, "path": "clearance"}}}}}},
	}
	if cfg.WaitSAName != "" {
		pod["serviceAccountName"] = cfg.WaitSAName
	}
	if ip, hosts, ok := strings.Cut(cfg.WaitHost, "="); ok {
		var hs []any
		for _, h := range strings.Split(hosts, ",") {
			hs = append(hs, h)
		}
		pod["hostAliases"] = []any{map[string]any{"ip": ip, "hostnames": hs}}
	}
	labels := map[string]any{"clearance.hangar.io/injected": "wait", "app.kubernetes.io/managed-by": "clearance-cmp"}
	return map[string]any{
		"apiVersion": "batch/v1", "kind": "Job",
		"metadata": map[string]any{
			"name": WaitJobName, "namespace": cfg.Destination, "labels": labels,
			"annotations": map[string]any{
				"argocd.argoproj.io/hook":               "PreSync",
				"argocd.argoproj.io/hook-delete-policy": "BeforeHookCreation,HookSucceeded",
				"clearance.hangar.io/change":            changeID,
				"clearance.hangar.io/injected":          "PreSync wait: clearance awaiting approval",
			},
		},
		"spec": map[string]any{
			"backoffLimit":          0,
			"activeDeadlineSeconds": int64(cfg.WaitTimeout.Seconds()) + 300,
			"template":              map[string]any{"metadata": map[string]any{"labels": labels}, "spec": pod},
		},
	}, nil
}
