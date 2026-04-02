{{/*
Expand the name of the chart.
*/}}
{{- define "rustgate.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "rustgate.fullname" -}}
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
Common labels
*/}}
{{- define "rustgate.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "rustgate.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "rustgate.selectorLabels" -}}
app.kubernetes.io/name: {{ include "rustgate.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
ExternalSecret secretStoreRef with required validation.
*/}}
{{- define "rustgate.externalSecretStoreRef" -}}
name: {{ required "externalSecrets.secretStoreRef.name must be set when externalSecrets are enabled" .Values.externalSecrets.secretStoreRef.name }}
kind: {{ .Values.externalSecrets.secretStoreRef.kind }}
{{- end }}

{{/*
Whether federation peers are sourced from a Secret (existingSecret or ESO).
*/}}
{{- define "rustgate.federationSecretEnabled" -}}
{{- or .Values.federation.existingSecret (and .Values.externalSecrets.enabled .Values.externalSecrets.federation.enabled) -}}
{{- end }}
