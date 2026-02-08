#!/bin/bash
# Generate self-signed certificates for TLS testing

set -e

CERT_DIR="$(dirname "$0")"
cd "$CERT_DIR"

# Generate CA private key
openssl genrsa -out ca.key 2048 2>/dev/null

# Generate CA certificate
openssl req -new -x509 -days 365 -key ca.key -out ca.crt \
    -subj "/C=US/ST=Test/L=Test/O=WEF Server Test/CN=WEF Test CA" 2>/dev/null

# Generate server private key
openssl genrsa -out server.key 2048 2>/dev/null

# Generate server certificate signing request
openssl req -new -key server.key -out server.csr \
    -subj "/C=US/ST=Test/L=Test/O=WEF Server Test/CN=wef-server-tls" 2>/dev/null

# Generate server certificate signed by CA
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 365 2>/dev/null

# Combine certificate and key into PEM format for server
cat server.crt server.key > server.pem

# Generate client certificate (for mutual TLS testing)
openssl genrsa -out client.key 2048 2>/dev/null

openssl req -new -key client.key -out client.csr \
    -subj "/C=US/ST=Test/L=Test/O=WEF Server Test/CN=test-client" 2>/dev/null

openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out client.crt -days 365 2>/dev/null

# Clean up intermediate files
rm -f server.csr client.csr ca.srl

echo "TLS certificates generated successfully:"
ls -la "$CERT_DIR/"*.crt "$CERT_DIR/"*.key "$CERT_DIR/"*.pem 2>/dev/null || true
