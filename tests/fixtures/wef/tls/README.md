# Test CA

`test-ca.pem` is a throwaway self-signed CA (private key discarded) used by
`ca_thumbprints` unit tests. Regenerate with:

    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
      -keyout /dev/null -out test-ca.pem -days 36500 -subj "/CN=logthing test CA"
    openssl x509 -in test-ca.pem -noout -fingerprint -sha1

then update the hard-coded thumbprint in `src/wef/subscription.rs` (colons stripped).
