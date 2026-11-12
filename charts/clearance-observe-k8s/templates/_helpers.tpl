{{- define "observe.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- define "observe.fullname" -}}
{{- if .Values.fullnameOverride -}}{{ .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}{{- else -}}{{ include "observe.name" . }}{{- end -}}
{{- end -}}
{{- define "observe.labels" -}}
app.kubernetes.io/name: {{ include "observe.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
{{- define "observe.selector" -}}
app.kubernetes.io/name: {{ include "observe.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{/* the namespaces the namespaced watches cover: the protected ones, the Argo CD namespace, where the platform GitOps instances keep their Applications, and watch.extraNamespaces */}}
{{- define "observe.watchNamespaces" -}}
{{- $ns := concat .Values.protectedNamespaces (list .Values.argocd.namespace) .Values.rules.platformGitops.namespaces .Values.watch.extraNamespaces | uniq -}}
{{- join "," $ns -}}
{{- end -}}
