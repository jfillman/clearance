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
{{- with .Values.policy.bundles }}
- name: CLEARANCE_BUNDLES
  value: {{ include "clearance.bundleFiles" $ | quote }}
{{- end }}
{{- with .Values.policy.sources }}
- name: CLEARANCE_BUNDLE_SOURCES
  value: {{ include "clearance.bundleSources" $ | quote }}
{{- end }}
{{- with .Values.policy.sourceWait }}
- name: CLEARANCE_BUNDLE_SOURCE_WAIT
  value: {{ . | quote }}
{{- end }}
{{- range $k, $env := dict "lowerNames" "CLEARANCE_ENV_LOWER_NAMES" "lowerPrefixes" "CLEARANCE_ENV_LOWER_PREFIXES" "lowerProjectSuffixes" "CLEARANCE_ENV_LOWER_PROJECT_SUFFIXES" "upperRepoPrefixes" "CLEARANCE_ENV_UPPER_REPO_PREFIXES" }}
{{- with index $.Values.policy.environments $k }}
- name: {{ $env }}
  value: {{ include "clearance.csv" . | quote }}
{{- end }}
{{- end }}
{{- range $k, $env := dict "onBehalfOfHeader" "CLEARANCE_ON_BEHALF_OF_HEADER" "trailerPrefix" "CLEARANCE_TRAILER_PREFIX" "runIdentityNamespace" "CLEARANCE_RUN_IDENTITY_NAMESPACE" "gateOwnerFallback" "CLEARANCE_GATE_OWNER_FALLBACK" "v0Provider" "CLEARANCE_V0_PROVIDER" }}
{{- with index $.Values.vocabulary $k }}
- name: {{ $env }}
  value: {{ . | quote }}
{{- end }}
{{- end }}
{{- range $k, $env := dict "baselineDenyPaths" "CLEARANCE_BASELINE_DENY_PATHS" "baselineDenyFields" "CLEARANCE_BASELINE_DENY_FIELDS" "gateOutsideGroups" "CLEARANCE_GATE_OUTSIDE_GROUPS" }}
{{- with index $.Values.vocabulary $k }}
- name: {{ $env }}
  value: {{ include "clearance.csv" . | quote }}
{{- end }}
{{- end }}
{{- with .Values.gate.runtimeImagesExtra }}
- name: RUNTIME_IMAGES_EXTRA
  value: {{ include "clearance.csv" . | quote }}
{{- end }}
{{- with .Values.gate.trustedRegistries }}
- name: CLEARANCE_TRUSTED_REGISTRIES
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
{{- if .Values.foreignCluster.issuer }}
- name: CLEARANCE_FOREIGN_ISSUER
  value: {{ .Values.foreignCluster.issuer | quote }}
- name: CLEARANCE_FOREIGN_CLUSTER
  value: {{ required "foreignCluster.cluster is required with foreignCluster.issuer" .Values.foreignCluster.cluster | quote }}
- name: CLEARANCE_FOREIGN_SERVICE_ACCOUNTS
  value: {{ required "foreignCluster.serviceAccounts is required with foreignCluster.issuer" (include "clearance.csv" .Values.foreignCluster.serviceAccounts) | quote }}
{{- with .Values.foreignCluster.jwksURL }}
- name: CLEARANCE_FOREIGN_JWKS_URL
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

{{/* CLEARANCE_BUNDLES: each bundle's file, mounted from its ConfigMap */}}
{{- define "clearance.bundleFiles" -}}
{{- $out := list -}}
{{- range .Values.policy.bundles -}}
{{- if not (regexMatch "^[a-z0-9][a-z0-9-]{0,40}$" (.name | default "")) }}{{ fail (printf "policy.bundles: name %q must be [a-z0-9-], at most 41 characters" .name) }}{{ end -}}
{{- $_ := required (printf "policy.bundles: %s needs a configMap" .name) .configMap -}}
{{- $out = append $out (printf "/etc/clearance/bundles/%s/%s" .name (.key | default "bundle.json")) -}}
{{- end -}}
{{- join "," $out -}}
{{- end -}}

{{/* CLEARANCE_BUNDLE_SOURCES as JSON: a url (with this pod's projected token when sendToken) or a ConfigMap file */}}
{{- define "clearance.bundleSources" -}}
{{- $out := dict -}}
{{- range $name, $s := .Values.policy.sources -}}
{{- if not (regexMatch "^[a-z0-9][a-z0-9-]{0,40}$" $name) }}{{ fail (printf "policy.sources: name %q must be [a-z0-9-], at most 41 characters" $name) }}{{ end -}}
{{- if and $s.url $s.configMap }}{{ fail (printf "policy.sources.%s: url or configMap, not both" $name) }}{{ end -}}
{{- if $s.url -}}
{{- if $s.sendToken -}}
{{- $_ := set $out $name (dict "url" $s.url "tokenFile" (printf "/var/run/clearance/sources/%s" $name)) -}}
{{- else -}}
{{- $_ := set $out $name (dict "url" $s.url) -}}
{{- end -}}
{{- else if $s.configMap -}}
{{- $_ := set $out $name (dict "file" (printf "/etc/clearance/sources/%s/%s" $name ($s.key | default "contract.json"))) -}}
{{- else -}}
{{- fail (printf "policy.sources.%s: give a url or a configMap" $name) -}}
{{- end -}}
{{- end -}}
{{- toJson $out -}}
{{- end -}}

{{- define "clearance.sourceTokens" -}}
{{- range $name, $s := .Values.policy.sources }}{{ if and $s.url $s.sendToken }}{{ $name }} {{ end }}{{ end -}}
{{- end -}}

{{/* volumes shared by the core and the api */}}
{{- define "clearance.sharedVolumes" -}}
{{- range .Values.policy.bundles }}
- name: bundle-{{ .name }}
  configMap:
    name: {{ .configMap }}
{{- end }}
{{- range $name, $s := .Values.policy.sources }}
{{- if $s.configMap }}
- name: source-{{ $name }}
  configMap:
    name: {{ $s.configMap }}
{{- end }}
{{- end }}
{{- if include "clearance.sourceTokens" . }}
- name: source-tokens
  projected:
    sources:
      {{- range $name, $s := .Values.policy.sources }}
      {{- if and $s.url $s.sendToken }}
      - serviceAccountToken:
          path: {{ $name }}
          {{- with $s.tokenAudience }}
          audience: {{ . | quote }}
          {{- end }}
          expirationSeconds: {{ $s.tokenExpirationSeconds | default 3600 }}
      {{- end }}
      {{- end }}
{{- end }}
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
{{- range .Values.policy.bundles }}
- name: bundle-{{ .name }}
  mountPath: /etc/clearance/bundles/{{ .name }}
  readOnly: true
{{- end }}
{{- range $name, $s := .Values.policy.sources }}
{{- if $s.configMap }}
- name: source-{{ $name }}
  mountPath: /etc/clearance/sources/{{ $name }}
  readOnly: true
{{- end }}
{{- end }}
{{- if include "clearance.sourceTokens" . }}
- name: source-tokens
  mountPath: /var/run/clearance/sources
  readOnly: true
{{- end }}
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
