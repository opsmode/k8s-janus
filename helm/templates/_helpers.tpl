{{/*
Expand the name of the chart.
*/}}
{{- define "janus.name" -}}
{{- .Chart.Name }}
{{- end }}

{{/*
Fullname: always "janus" regardless of release name
*/}}
{{- define "janus.fullname" -}}
{{- "janus" }}
{{- end }}

{{/*
Controller resource name
*/}}
{{- define "janus.controller.name" -}}
{{- printf "%s-controller" (include "janus.fullname" .) }}
{{- end }}

{{/*
WebUI resource name
*/}}
{{- define "janus.webui.name" -}}
{{- printf "%s-webui" (include "janus.fullname" .) }}
{{- end }}

{{/*
ConfigMap name
*/}}
{{- define "janus.configmap.name" -}}
{{- printf "%s-config" (include "janus.fullname" .) }}
{{- end }}

{{/*
Common labels (Kubernetes recommended labels)
*/}}
{{- define "janus.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
app.kubernetes.io/name: {{ include "janus.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/part-of: {{ include "janus.name" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.labels }}
{{- toYaml . | nindent 0 }}
{{- end }}
{{- end }}

{{/*
Controller selector labels
*/}}
{{- define "janus.controller.selectorLabels" -}}
app.kubernetes.io/name: {{ include "janus.controller.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: controller
{{- end }}

{{/*
WebUI selector labels
*/}}
{{- define "janus.webui.selectorLabels" -}}
app.kubernetes.io/name: {{ include "janus.webui.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: webui
{{- end }}


{{/*
PostgreSQL — resolved host.
Bundled: internal service name. External: values.postgresql.host.
*/}}
{{- define "janus.postgresql.host" -}}
{{- if (.Values.postgresql.bundled).enabled -}}
{{- printf "%s-postgresql" (include "janus.fullname" .) }}
{{- else -}}
{{- .Values.postgresql.host | default "" }}
{{- end -}}
{{- end }}

{{/*
PostgreSQL — true when either bundled or external is enabled.
*/}}
{{- define "janus.postgresql.enabled" -}}
{{- if or .Values.postgresql.enabled ((.Values.postgresql.bundled).enabled) -}}
true
{{- end -}}
{{- end }}

{{/*
Name of the Secret holding OIDC clientSecret + sessionSecret.
Priority: existingSecret > ESO-created (janus-oidc) > plain Secret (janus-oidc)
ESO and plain Secret both target the same name, so the reference is always the same.
*/}}
{{- define "janus.oidc.secretName" -}}
{{- .Values.oidc.existingSecret | default (printf "%s-oidc" (include "janus.fullname" .)) }}
{{- end }}

{{/*
Name of the Secret holding the MFA encryption key.
Priority: existingSecret > plain Secret (janus-mfa)
*/}}
{{- define "janus.mfa.secretName" -}}
{{- (.Values.webui.mfa).existingSecret | default (printf "%s-mfa" (include "janus.fullname" .)) }}
{{- end }}

{{/*
Name of the Secret holding the session secret.
Always mounted regardless of OIDC mode — prevents session invalidation on pod restart.
Priority: existingSecret > plain Secret (janus-session)
*/}}
{{- define "janus.session.secretName" -}}
{{- (.Values.webui.session).existingSecret | default (printf "%s-session" (include "janus.fullname" .)) }}
{{- end }}
