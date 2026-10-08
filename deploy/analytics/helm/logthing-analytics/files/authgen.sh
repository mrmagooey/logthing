#!/bin/sh
# Write Trino's password file with bcrypt entries (cost 10), using htpasswd (httpd image).
# Env: OUT_DIR      output directory (default /out)
#      TRINO_USERS  comma list "user:ENVVAR,user:ENVVAR"; the password for each user is read
#                   from the environment variable named after the colon.
# Rewritten on every run so a changed password takes effect on the next start (Trino reloads
# the file every file.refresh-period).
set -eu
OUT_DIR=${OUT_DIR:-/out}
mkdir -p "$OUT_DIR"
tmp="$OUT_DIR/password.db.tmp"
: >"$tmp"
for pair in $(printf '%s' "${TRINO_USERS:?authgen: TRINO_USERS is required}" | tr ',' ' '); do
  user=${pair%%:*}
  var=${pair#*:}
  pw=$(printenv "$var") || { echo "authgen: env var $var is not set" >&2; exit 2; }
  [ -n "$pw" ] || { echo "authgen: env var $var is empty" >&2; exit 2; }
  htpasswd -nbBC 10 "$user" "$pw" >>"$tmp"
done
mv "$tmp" "$OUT_DIR/password.db"
chmod 644 "$OUT_DIR/password.db"
echo "authgen: wrote $OUT_DIR/password.db"
