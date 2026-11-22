{{- define "agent.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- define "agent.fullname" -}}
{{- if .Values.fullnameOverride -}}{{ .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}{{- else -}}{{ include "agent.name" . }}{{- end -}}
{{- end -}}
{{- define "agent.labels" -}}
app.kubernetes.io/name: {{ include "agent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
{{- define "agent.selector" -}}
app.kubernetes.io/name: {{ include "agent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- /* I-44: the grant-expiry webhook's names and the rules that tie the gate's mode to it. */ -}}
{{- define "agent.ge.name" -}}{{ .Values.grantExpiry.name | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- define "agent.ge.selector" -}}
app.kubernetes.io/name: {{ include "agent.ge.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "agent.ge.labels" -}}
{{ include "agent.ge.selector" . }}
app.kubernetes.io/part-of: clearance
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
{{- define "agent.ge.mode" -}}{{ if .Values.grantExpiry.enforce }}enforce{{ else }}audit{{ end }}{{- end -}}
{{- define "agent.ge.argocdUser" -}}
{{- .Values.grantExpiry.argocdUser | default (printf "system:serviceaccount:%s:argocd-application-controller" .Values.argocd.namespace) -}}
{{- end -}}
{{- define "agent.ge.issuerName" -}}
{{- if .Values.grantExpiry.tls.certManager.issuerRef.name -}}{{ .Values.grantExpiry.tls.certManager.issuerRef.name }}{{- else -}}{{ include "agent.ge.name" . }}-ca{{- end -}}
{{- end -}}
{{- define "agent.ge.secret" -}}
{{- if .Values.grantExpiry.tls.certManager.enabled -}}{{ include "agent.ge.name" . }}-tls{{- else -}}{{ .Values.grantExpiry.tls.existingSecret }}{{- end -}}
{{- end -}}
{{- /* What the chart refuses. gate.enforce is the mode the installer runs the admission policy in: Deny only with the
       webhook enabled AND enforcing (or the recorded override), which also refuses the webhook leaving enforce while the
       policy still denies. */ -}}
{{- define "agent.guards" -}}
{{- $ge := .Values.grantExpiry -}}
{{- if and .Values.gate.enforce (not (and $ge.enabled $ge.enforce)) (not $ge.acceptResidualRisk) -}}
{{- fail "gate.enforce: true (the admission policy denies) needs grantExpiry.enabled: true and grantExpiry.enforce: true: the policy has no clock, so without an enforcing grant-expiry webhook an expired grant admits writes while the agent is stalled (I-44). Turn the webhook to enforce first, the policy to Deny after it; leave in reverse order (gate.enforce: false first, grantExpiry.enforce: false in a later change). The only override is grantExpiry.acceptResidualRisk: true (docs/gate.md, The grant-expiry webhook)" -}}
{{- end -}}
{{- if and $ge.enforce (not $ge.enabled) -}}{{ fail "grantExpiry.enforce needs grantExpiry.enabled" }}{{- end -}}
{{- if $ge.enabled -}}
{{- if and $ge.enforce (lt (int $ge.replicas) 2) -}}{{ fail "grantExpiry.enforce needs grantExpiry.replicas of 2 or more: under failurePolicy Fail one pod is one restart away from refusing every protected write" }}{{- end -}}
{{- if lt (int $ge.replicas) 1 -}}{{ fail "grantExpiry.replicas must be at least 1" }}{{- end -}}
{{- if or (lt (int $ge.timeoutSeconds) 1) (gt (int $ge.timeoutSeconds) 30) -}}{{ fail "grantExpiry.timeoutSeconds must be 1 to 30" }}{{- end -}}
{{- if hasPrefix "-" (toString $ge.skew) -}}{{ fail "grantExpiry.skew cannot be negative" }}{{- end -}}
{{- if and (not $ge.tls.certManager.enabled) (or (not $ge.tls.existingSecret) (not $ge.tls.caBundle)) -}}{{ fail "grantExpiry.tls.certManager.enabled: false needs grantExpiry.tls.existingSecret and grantExpiry.tls.caBundle" }}{{- end -}}
{{- if not (and $ge.syncWaves.certificate $ge.syncWaves.deployment $ge.syncWaves.webhook) -}}{{ fail "grantExpiry.syncWaves needs certificate, deployment and webhook" }}{{- end -}}
{{- if not (and (lt (int $ge.syncWaves.certificate) (int $ge.syncWaves.deployment)) (lt (int $ge.syncWaves.deployment) (int $ge.syncWaves.webhook))) -}}{{ fail "grantExpiry.syncWaves must order certificate < deployment < webhook" }}{{- end -}}
{{- if and .Values.waitJob.image (not (or .Values.waitJob.url .Values.coreURL)) -}}{{ fail "grantExpiry with waitJob.image needs waitJob.url or coreURL" }}{{- end -}}
{{- end -}}
{{- if .Values.ha.enabled -}}
{{- if lt (int .Values.ha.replicas) 2 -}}{{ fail "ha.enabled needs ha.replicas of 2 or more" }}{{- end -}}
{{- end -}}
{{- if .Values.alerts.enabled -}}
{{- if not $ge.enabled -}}{{ fail "alerts.enabled needs grantExpiry.enabled: the grant-expiry pods export the grant times the alerts read (a stalled agent cannot report itself)" }}{{- end -}}
{{- if not .Values.statusHeartbeat -}}{{ fail "alerts.enabled needs statusHeartbeat (e.g. 5m): without it status.checkedAt is written only when valid changes, and its age says nothing" }}{{- end -}}
{{- end -}}
{{- end -}}

{{- /* A duration of one unit (90s, 15m, 1h) in seconds, for a PromQL comparison. */ -}}
{{- define "agent.seconds" -}}
{{- $d := toString . -}}
{{- $n := 0 -}}
{{- if regexMatch "^[0-9]+h$" $d }}{{ $n = mul (trimSuffix "h" $d | int) 3600 }}
{{- else if regexMatch "^[0-9]+m$" $d }}{{ $n = mul (trimSuffix "m" $d | int) 60 }}
{{- else if regexMatch "^[0-9]+s$" $d }}{{ $n = trimSuffix "s" $d | int }}
{{- else }}{{ fail (printf "%q is not a duration of one unit (90s, 15m, 1h)" $d) }}{{ end -}}
{{- if le (int $n) 0 }}{{ fail (printf "%q must be above zero" $d) }}{{ end -}}
{{- $n -}}
{{- end -}}
