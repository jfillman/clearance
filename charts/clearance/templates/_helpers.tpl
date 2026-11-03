{{/* Names */}}
{{- define "clearance.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "clearance.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 50 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 50 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 50 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "clearance.coreName" -}}{{ include "clearance.fullname" . }}-core{{- end -}}
{{- define "clearance.apiName" -}}{{ include "clearance.fullname" . }}-api{{- end -}}
{{- define "clearance.pgName" -}}{{ include "clearance.fullname" . }}-pg{{- end -}}

{{- define "clearance.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: {{ include "clearance.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: clearance
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/* selector labels: (dict "ctx" $ "component" "core") */}}
{{- define "clearance.selector" -}}
app.kubernetes.io/name: {{ include "clearance.name" .ctx }}
app.kubernetes.io/instance: {{ .ctx.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "clearance.coreSA" -}}
{{- if .Values.core.serviceAccount.create -}}{{ default (include "clearance.coreName" .) .Values.core.serviceAccount.name }}{{- else -}}{{ required "core.serviceAccount.name is required when core.serviceAccount.create is false" .Values.core.serviceAccount.name }}{{- end -}}
{{- end -}}
{{- define "clearance.apiSA" -}}
{{- if .Values.api.serviceAccount.create -}}{{ default (include "clearance.apiName" .) .Values.api.serviceAccount.name }}{{- else -}}{{ required "api.serviceAccount.name is required when api.serviceAccount.create is false" .Values.api.serviceAccount.name }}{{- end -}}
{{- end -}}

{{- define "clearance.image" -}}
{{- $repo := required "image.repository is required" .Values.image.repository -}}
{{- if .Values.image.digest -}}
{{- if not (regexMatch "^sha256:[0-9a-f]{64}$" .Values.image.digest) -}}{{- fail "image.digest is sha256:<64 hex>" -}}{{- end -}}
{{- printf "%s@%s" $repo .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" $repo (default (printf "v%s" .Chart.AppVersion) .Values.image.tag) -}}
{{- end -}}
{{- end -}}

{{/* The core's DSN Secret: (list name key) */}}
{{- define "clearance.dbSecretName" -}}
{{- if .Values.database.existingSecret -}}{{ .Values.database.existingSecret }}
{{- else if .Values.cnpg.enabled -}}{{ include "clearance.pgName" . }}-app
{{- else if and .Values.externalSecrets.enabled .Values.externalSecrets.database.dsn.key -}}{{ include "clearance.fullname" . }}-db
{{- else -}}{{ fail "the core needs a database: set database.existingSecret, cnpg.enabled, or externalSecrets.database.dsn" }}
{{- end -}}
{{- end -}}
{{- define "clearance.dbSecretKey" -}}
{{- if or .Values.database.existingSecret (not .Values.cnpg.enabled) -}}{{ .Values.database.key }}{{- else -}}uri{{- end -}}
{{- end -}}

{{/* The api's read-only DSN Secret */}}
{{- define "clearance.readerSecretName" -}}
{{- if .Values.database.reader.existingSecret -}}{{ .Values.database.reader.existingSecret }}
{{- else if and .Values.cnpg.enabled .Values.cnpg.reader.enabled -}}{{ default (printf "%s-reader" (include "clearance.pgName" .)) .Values.cnpg.reader.passwordSecret }}
{{- else -}}{{ include "clearance.dbSecretName" . }}
{{- end -}}
{{- end -}}
{{- define "clearance.readerSecretKey" -}}
{{- if .Values.database.reader.existingSecret -}}{{ .Values.database.reader.key }}
{{- else if and .Values.cnpg.enabled .Values.cnpg.reader.enabled -}}uri
{{- else -}}{{ include "clearance.dbSecretKey" . }}
{{- end -}}
{{- end -}}

{{- define "clearance.githubAppSecret" -}}
{{- if .Values.githubApp.existingSecret -}}{{ .Values.githubApp.existingSecret }}
{{- else if and .Values.externalSecrets.enabled .Values.externalSecrets.githubApp.privateKey.key -}}{{ include "clearance.fullname" . }}-github-app
{{- else -}}{{ fail "githubApp.enabled needs githubApp.existingSecret or externalSecrets.githubApp" }}
{{- end -}}
{{- end -}}

{{- define "clearance.csv" -}}{{ join "," . }}{{- end -}}

{{/* env entries shared by the core and the api: identity, Backstage, definitions. Empty values are omitted. */}}
{{- define "clearance.sharedEnv" -}}
- name: CLEARANCE_LISTEN
  value: ":8080"
- name: CLEARANCE_AUDIENCE
  value: {{ .Values.audience | quote }}
{{- with .Values.delegates }}
- name: CLEARANCE_DELEGATES
  value: {{ include "clearance.csv" . | quote }}
{{- end }}
{{- with .Values.admins }}
- name: CLEARANCE_ADMINS
  value: {{ include "clearance.csv" . | quote }}
{{- end }}
{{- with .Values.packs }}
- name: CLEARANCE_PACKS
  value: {{ include "clearance.csv" . | quote }}
{{- end }}
{{- with .Values.gate.runtimeImagesExtra }}
- name: RUNTIME_IMAGES_EXTRA
  value: {{ include "clearance.csv" . | quote }}
{{- end }}
{{- with .Values.gate.flightRegistries }}
- name: CLEARANCE_FLIGHT_REGISTRIES
  value: {{ include "clearance.csv" . | quote }}
{{- end }}
{{- if .Values.agents.configMap }}
- name: CLEARANCE_AGENTS_DIR
  value: /etc/clearance/agents
{{- end }}
{{- if or .Values.oidc.issuer .Values.oidc.audience }}
- name: CLEARANCE_OIDC_ISSUER
  value: {{ required "oidc.issuer is set together with oidc.audience" .Values.oidc.issuer | quote }}
- name: CLEARANCE_OIDC_AUDIENCE
  value: {{ required "oidc.audience is set together with oidc.issuer" .Values.oidc.audience | quote }}
- name: CLEARANCE_OIDC_ALLOWED_USERS
  value: {{ required "oidc.allowedUsers is required with an issuer (an issuer that federates GitHub signs in anyone)" (include "clearance.csv" .Values.oidc.allowedUsers) | quote }}
{{- with .Values.oidc.jwksURL }}
- name: CLEARANCE_OIDC_JWKS_URL
  value: {{ . | quote }}
{{- end }}
{{- with .Values.oidc.userClaim }}
- name: CLEARANCE_OIDC_USER_CLAIM
  value: {{ . | quote }}
{{- end }}
{{- end }}
{{- if .Values.tower.issuer }}
- name: TOWER_ISSUER
  value: {{ .Values.tower.issuer | quote }}
- name: TOWER_CLUSTER
  value: {{ required "tower.cluster is required with tower.issuer" .Values.tower.cluster | quote }}
- name: TOWER_SERVICE_ACCOUNTS
  value: {{ required "tower.serviceAccounts is required with tower.issuer" (include "clearance.csv" .Values.tower.serviceAccounts) | quote }}
{{- with .Values.tower.jwksURL }}
- name: TOWER_JWKS_URL
  value: {{ . | quote }}
{{- end }}
{{- end }}
{{- with .Values.githubActions.audience }}
- name: CLEARANCE_GITHUB_OIDC_AUDIENCE
  value: {{ . | quote }}
{{- end }}
{{- with .Values.githubActions.allowed }}
- name: CLEARANCE_GITHUB_OIDC_ALLOWED
  value: {{ include "clearance.csv" . | quote }}
{{- end }}
{{- if .Values.backstage.url }}
- name: BACKSTAGE_URL
  value: {{ .Values.backstage.url | quote }}
- name: BACKSTAGE_TOKEN_FILE
  value: /var/run/clearance/backstage-token
{{- end }}
{{- end -}}

{{/* volumes shared by the core and the api */}}
{{- define "clearance.sharedVolumes" -}}
{{- if .Values.backstage.url }}
- name: backstage-token
  projected:
    sources:
      - serviceAccountToken:
          path: backstage-token
          audience: {{ .Values.backstage.tokenAudience | quote }}
          expirationSeconds: {{ .Values.backstage.tokenExpirationSeconds }}
{{- end }}
{{- if .Values.agents.configMap }}
- name: agents
  configMap:
    name: {{ .Values.agents.configMap }}
{{- end }}
{{- end -}}
{{- define "clearance.sharedMounts" -}}
{{- if .Values.backstage.url }}
- name: backstage-token
  mountPath: /var/run/clearance
  readOnly: true
{{- end }}
{{- if .Values.agents.configMap }}
- name: agents
  mountPath: /etc/clearance/agents
  readOnly: true
{{- end }}
{{- end -}}

{{- define "clearance.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: 65532
runAsGroup: 65532
fsGroup: 65532
seccompProfile:
  type: RuntimeDefault
{{- end -}}
{{- define "clearance.securityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
privileged: false
runAsNonRoot: true
runAsUser: 65532
runAsGroup: 65532
capabilities:
  drop: ["ALL"]
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "clearance.probes" -}}
startupProbe:
  httpGet: {path: /healthz, port: http}
  periodSeconds: 5
  failureThreshold: {{ max 1 (div .startupSeconds 5) }}
livenessProbe:
  httpGet: {path: /healthz, port: http}
  periodSeconds: 10
  timeoutSeconds: 3
  failureThreshold: 3
readinessProbe:
  httpGet: {path: /readyz, port: http}
  periodSeconds: 5
  timeoutSeconds: 3
  failureThreshold: 3
{{- end -}}
