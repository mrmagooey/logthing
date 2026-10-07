#!/bin/sh
# Generate a private CA and a Trino server certificate.
#
# Runs inside alpine/openssl (compose service `certgen`) or directly on a host with openssl.
# Env: OUT_DIR   output directory (default /out)
#      TLS_SANS  subjectAltName list (default DNS:trino,DNS:localhost,IP:127.0.0.1)
#      TLS_DAYS  server certificate lifetime in days (default 825)
#      TLS_OWNER optional uid:gid to chown the outputs to (Trino runs as 1000:1000)
# Writes ca.pem (clients trust this) and server.pem (certificate + PKCS#8 key, mode 600).
# Idempotent: an existing certificate with more than 30 days left is kept, so clients that
# already trust ca.pem keep working. The CA key is discarded after signing.
# Exits non-zero (loudly) if openssl is missing or any generation step fails.
set -eu
command -v openssl >/dev/null 2>&1 || { echo "certgen: openssl not found in PATH" >&2; exit 127; }
OUT_DIR=${OUT_DIR:-/out}
SANS=${TLS_SANS:-DNS:trino,DNS:localhost,IP:127.0.0.1}
DAYS=${TLS_DAYS:-825}
mkdir -p "$OUT_DIR"
cd "$OUT_DIR"
if [ -s server.pem ] && [ -s ca.pem ] \
   && openssl x509 -in server.pem -noout -checkend 2592000 >/dev/null 2>&1; then
  echo "certgen: existing certificate still valid, keeping it"
  exit 0
fi
# Generate in a private work dir and move the results into place only at the very end, so a
# failure never leaves ca.key behind or a ca.pem that does not match server.pem.
umask 077
work=$(mktemp -d "$OUT_DIR/.certgen.XXXXXX")
trap 'rm -rf "$work"' EXIT
cd "$work"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out ca.key
openssl req -x509 -new -key ca.key -sha256 -days 3650 -subj "/CN=logthing-analytics-ca" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out ca.pem
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out server.key
openssl req -new -key server.key -subj "/CN=trino" -out server.csr
printf 'subjectAltName=%s\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\n' \
  "$SANS" >ext.cnf
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days "$DAYS" \
  -sha256 -extfile ext.cnf -out server.crt
cat server.crt server.key >server.pem
chmod 644 ca.pem
chmod 600 server.pem
if [ -n "${TLS_OWNER:-}" ]; then chown "$TLS_OWNER" server.pem ca.pem; fi
mv -f server.pem "$OUT_DIR/server.pem"
mv -f ca.pem "$OUT_DIR/ca.pem"
echo "certgen: wrote $OUT_DIR/ca.pem and $OUT_DIR/server.pem (SANs: $SANS)"
