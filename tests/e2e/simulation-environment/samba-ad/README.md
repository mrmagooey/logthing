# Samba AD DC for `run.sh wef-interop --samba`

Nightly, non-gating variant of the wef-interop e2e. `docker-compose.samba.yml` swaps the MIT
`kdc` service for a Samba Active Directory DC (Debian bookworm, Samba 4.17) with the same
service name, alias `kdc.example.com`, realm `EXAMPLE.COM` and keytab contract
(`logthing.keytab`, `other.keytab`, `clients.keytab` with `WIN10$`, `WIN11$`, `alice`), so
the rest of the scenario is unchanged. Unlike MIT, tickets come from a real AD KDC (PAC
included, machine accounts are real computer objects, AES keys per
`msDS-SupportedEncryptionTypes`).

    tests/e2e/simulation-environment/run.sh wef-interop --samba

Status: verified on this host (full run passes; provisioning takes about 1 minute).

## Notes

- Runs unprivileged (no extra capabilities). The default `security.NTACL` xattr needs
  `CAP_SYS_ADMIN`, so provisioning keeps NT ACLs in a tdb (`vfs objects = ... xattr_tdb`).
- `samba-tool computer create` leaves the account disabled with no password, so provision
  sets a random password and enables it before exporting.
- Service accounts get `msDS-SupportedEncryptionTypes=24` (AES only); without it only RC4
  keys are exported.
- `exportkeytab` truncates its target, so principals are exported separately and merged
  into `clients.keytab` with `ktutil`.
- `samba_dnsupdate ... Record already exists` log lines are harmless noise.
