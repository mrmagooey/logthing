//! The simulation environment's logthing config must stay a VALID config: it parses and passes
//! startup validation (in particular every enabled HEC/OTLP section has a sink). This is the
//! Docker-free guard for tests/e2e/simulation-environment/config/logthing.toml.

use logthing::config::{Config, validate_config_invariants};

#[test]
fn simulation_environment_config_parses_and_validates() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/e2e/simulation-environment/config/logthing.toml");
    let text = std::fs::read_to_string(&path).expect("read sim config");
    let mut cfg: Config = toml::from_str(&text).expect("sim config parses");
    // docker-compose.yml sets LOGTHING__TLS__ENABLED=false (the file itself leaves TLS at its
    // default); mirror that so only the sink rules are under test.
    cfg.tls.enabled = false;
    validate_config_invariants(&cfg).expect("sim config passes startup validation");
    assert!(cfg.hec.enabled && cfg.hec.local.is_some());
}

#[cfg(feature = "otlp")]
#[test]
fn simulation_environment_enables_otlp_with_its_own_local_sink() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/e2e/simulation-environment/config/logthing.toml");
    let cfg: Config = toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert!(cfg.otlp.enabled, "sim env must exercise OTLP");
    let local = cfg.otlp.local.expect("[otlp.local] present");
    assert_eq!(
        local.directory,
        std::path::PathBuf::from("/var/log/otlp-local")
    );
    assert_eq!(cfg.otlp.bearer_token.as_deref(), Some("e2e-otlp-token"));
}
