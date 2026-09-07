# Plan: /wsman Kerberos, /syslog token, OTLP warning

Spec: `docs/superpowers/specs/2026-09-07-wsman-syslog-auth-design.md`
Branch: `feat/wsman-syslog-auth` (worktree `/home/dev/projects/logthing-wt-auth`)
Delivered sequentially: Unit 1 → Unit 2 → Unit 3, one commit each.

## Unit 1 — OTLP empty-bearer_token warning

- [ ] Add a second entry to `insecure_config_warnings` in `src/config/mod.rs`
      when `otlp.enabled` and `bearer_token` is None/empty.
- [ ] Update the now-stale `ponytail:` comment at `src/config/mod.rs:780`
      ("the analogous OTLP bearer_token footgun is real but out of scope here").
- [ ] Unit tests: otlp enabled + no token → warns; enabled + token → silent;
      disabled → silent; both HEC and OTLP misconfigured → two warnings.

## Unit 2 — /syslog HTTP opt-in token

- [ ] Add `syslog.http_token: String` with `#[serde(default)]` to `SyslogConfig`.
- [ ] Extend `handle_syslog_http` to take `HeaderMap` + the configured token,
      checking `Authorization: Bearer <token>` in constant time, length-gated,
      mirroring `check_hec_token`. Empty configured token → check skipped.
- [ ] Update the ~5 existing unit tests that call `handle_syslog_http` directly.
- [ ] Unit tests: no header + token set → 401; wrong token → 401; correct token
      → 200; empty configured token + no header → 200 (back-compat).
- [ ] Integration + e2e coverage through the real router.
- [ ] README callout documenting `syslog.http_token`.

## Unit 3 — /wsman real Kerberos SPNEGO

- [ ] `Cargo.toml`: drop `axum-negotiate`; point `kerberos-auth` at `libgssapi`.
- [ ] Acquire the server `Cred` once at startup from the keytab/SPN; surface
      acquisition failure as a startup error (fail-closed).
- [ ] Replace the 501 stub in `kerberos_auth_middleware` with the RFC 4559
      two-pass flow from the spec. Log the authenticated principal at `debug!`.
- [ ] `apply_kerberos_layer`: `from_fn_with_state` carrying the `Cred`; drop the
      "NOT implemented / rejects all requests" SECURITY error log.
- [ ] Reword `README.md:170` — no `axum_negotiate::Upn`; document that the
      principal is logged, and that NTLM fallback is unsupported (two-pass only).
- [ ] `Dockerfile.kerberos`: generate a keytab offline with `ktutil` for
      `HTTP/wef-server@EXAMPLE.COM`, written to the path the fixture config
      expects (`/etc/wef-server/keytabs/wef.keytab`). No live KDC.
- [ ] Rewrite `test_wsman_with_auth` in `kerberos-test/entrypoint.py`: a garbage
      Negotiate token must now yield 401.
- [ ] Unit tests (no KDC needed): missing header → 401 + `WWW-Authenticate`;
      malformed base64 → 401; non-Negotiate scheme → 401.
- [ ] CHANGELOG entry covering all three units, incl. the licence change
      (LGPL dep removed) and the two-pass-only limitation.

## Verification

- [ ] `cargo test --all-targets` green.
- [ ] `cargo test --all-targets --features kerberos-auth` green.
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` clean.
- [ ] `cargo fmt --check` clean.
- [ ] Confirm `axum-negotiate` is gone from `Cargo.lock`.
