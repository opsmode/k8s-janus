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
Derive kubeconfig Secret name from cluster name.
Uses secretName if explicitly set, otherwise falls back to "<name>-kubeconfig".
Pass the cluster dict as . e.g: {{ include "janus.cluster.secretName" . }}
*/}}
{{- define "janus.cluster.secretName" -}}
{{- .secretName | default (printf "%s-kubeconfig" .name) }}
{{- end }}
