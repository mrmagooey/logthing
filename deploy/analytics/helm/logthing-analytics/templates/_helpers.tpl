{{- define "la.fullname" -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 40 | trimSuffix "-" -}}
{{- end -}}
{{- define "la.labels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
{{/* labels safe for immutable fields (volumeClaimTemplates): no version/chart keys */}}
{{- define "la.stableLabels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
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
- {name: GARAGE_CAPACITY_BYTES, value: {{ .Values.garage.capacityBytes | int64 | quote }}}
- {name: BOOTSTRAP_TIMEOUT_SECS, value: {{ .Values.bootstrap.timeoutSecs | quote }}}
{{- end -}}
{{/* initContainer that blocks on `bootstrap.py wait <target>`; only the env that target needs */}}
{{- define "la.waitFor" -}}
- name: wait-{{ .target }}
  image: {{ .root.Values.bootstrap.image }}
  command: ["python", "/bootstrap/bootstrap.py", "wait", {{ .target | quote }}]
  env:
    {{- if eq .target "garage" }}
    {{- include "la.secretEnv" (dict "root" .root "name" "S3_ACCESS_KEY" "key" "s3-access-key") | nindent 4 }}
    {{- include "la.secretEnv" (dict "root" .root "name" "GARAGE_ADMIN_TOKEN" "key" "garage-admin-token") | nindent 4 }}
    - {name: GARAGE_ADMIN_URL, value: "http://{{ include "la.fullname" .root }}-garage:3903"}
    {{- else }}
    - {name: LAKEKEEPER_URL, value: "http://{{ include "la.fullname" .root }}-lakekeeper:8181"}
    {{- end }}
    - {name: BOOTSTRAP_TIMEOUT_SECS, value: {{ .root.Values.bootstrap.timeoutSecs | quote }}}
  volumeMounts:
    - {name: files, mountPath: /bootstrap/bootstrap.py, subPath: bootstrap.py}
{{- end -}}
{{/* initContainer for Hue: wait for Postgres (TCP) and Trino (HTTP /v1/info) */}}
{{- define "la.waitHue" -}}
- name: wait-deps
  image: {{ .Values.bootstrap.image }}
  command:
    - python
    - -c
    - |
      import socket, sys, time, urllib.request
      deadline = time.time() + float(sys.argv[1])
      def pg():
          socket.create_connection((sys.argv[2], 5432), 3).close()
      def trino():
          assert urllib.request.urlopen(sys.argv[3], timeout=3).status == 200
      for name, check in (("postgres", pg), ("trino", trino)):
          while True:
              try:
                  check()
                  break
              except Exception as e:
                  if time.time() > deadline:
                      sys.exit(f"wait-deps: {name} not ready: {e}")
                  time.sleep(2)
    - {{ .Values.bootstrap.timeoutSecs | quote }}
    - {{ include "la.fullname" . }}-postgres
    - http://{{ include "la.fullname" . }}-trino:8080/v1/info
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
