{{/*
Expand the name of the chart.
*/}}
{{- define "tlapix.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "tlapix.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "tlapix.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "tlapix.labels" -}}
helm.sh/chart: {{ include "tlapix.chart" . }}
{{ include "tlapix.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "tlapix.selectorLabels" -}}
app.kubernetes.io/name: {{ include "tlapix.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Agent selector labels
*/}}
{{- define "tlapix.agentSelectorLabels" -}}
app.kubernetes.io/name: {{ include "tlapix.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: agent
{{- end }}

{{/*
Central selector labels
*/}}
{{- define "tlapix.centralSelectorLabels" -}}
app.kubernetes.io/name: {{ include "tlapix.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: central
{{- end }}

{{/*
Service account name
*/}}
{{- define "tlapix.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "tlapix.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Image tag (defaults to appVersion)
*/}}
{{- define "tlapix.imageTag" -}}
{{- default .Chart.AppVersion .Values.agent.image.tag }}
{{- end }}
