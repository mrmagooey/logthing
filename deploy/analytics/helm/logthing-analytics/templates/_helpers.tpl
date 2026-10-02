{{- define "la.fullname" -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- define "la.labels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
{{- define "la.selector" -}}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}
{{- define "la.secretName" -}}
{{- .Values.credentials.existingSecret | default (printf "%s-credentials" (include "la.fullname" .)) -}}
{{- end -}}
{{- define "la.secretEnv" -}}
- name: {{ .name }}
  valueFrom:
    secretKeyRef:
      name: {{ include "la.secretName" .root }}
      key: {{ .key }}
{{- end -}}
{{/* S3 creds + endpoint, used by every S3 client */}}
{{- define "la.s3Env" -}}
{{ include "la.secretEnv" (dict "root" . "name" "S3_ACCESS_KEY" "key" "s3-access-key") }}
{{ include "la.secretEnv" (dict "root" . "name" "S3_SECRET_KEY" "key" "s3-secret-key") }}
- name: S3_ENDPOINT
  value: http://{{ include "la.fullname" . }}-garage:3900
{{- end -}}
{{- define "la.bootstrapEnv" -}}
{{ include "la.s3Env" . }}
{{ include "la.secretEnv" (dict "root" . "name" "GARAGE_ADMIN_TOKEN" "key" "garage-admin-token") }}
- {name: GARAGE_ADMIN_URL, value: "http://{{ include "la.fullname" . }}-garage:3903"}
- {name: LAKEKEEPER_URL, value: "http://{{ include "la.fullname" . }}-lakekeeper:8181"}
- {name: GARAGE_CAPACITY_BYTES, value: {{ .Values.garage.capacityBytes | quote }}}
- {name: BOOTSTRAP_TIMEOUT_SECS, value: {{ .Values.bootstrap.timeoutSecs | quote }}}
{{- end -}}
{{/* initContainer that blocks on `bootstrap.py wait <target>` */}}
{{- define "la.waitFor" -}}
- name: wait-{{ .target }}
  image: {{ .root.Values.bootstrap.image }}
  command: ["python", "/bootstrap/bootstrap.py", "wait", {{ .target | quote }}]
  env:
    {{- include "la.bootstrapEnv" .root | nindent 4 }}
  volumeMounts:
    - {name: files, mountPath: /bootstrap/bootstrap.py, subPath: bootstrap.py}
{{- end -}}
{{/* pod volume for the shared files ConfigMap */}}
{{- define "la.filesVolume" -}}
- name: files
  configMap:
    name: {{ include "la.fullname" . }}-files
{{- end -}}
{{/* pod labels: la.labels minus the instance key, which la.selector already supplies */}}
{{- define "la.podLabels" -}}
app.kubernetes.io/name: {{ .root.Chart.Name }}
app.kubernetes.io/version: {{ .root.Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .root.Release.Service }}
{{ include "la.selector" . }}
{{- end -}}
