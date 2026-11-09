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
