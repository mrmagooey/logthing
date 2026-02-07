mod admin;
mod config;
mod forwarding;
mod middleware;
mod models;
mod parser;
mod protocol;
mod server;
mod stats;
mod syslog;

use server::Server;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load configuration
    let config = config::Config::load()?;

    // Initialize logging
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(&config.logging.level)
        .with_target(false);

    match config.logging.format {
        config::LogFormat::Json => subscriber.json().init(),
        config::LogFormat::Pretty => subscriber.pretty().init(),
    };

    info!("Starting WEF Server v{}", env!("CARGO_PKG_VERSION"));
    info!("Configuration loaded successfully");

    let shared_config = Arc::new(RwLock::new(config.clone()));
    admin::spawn_admin_server(shared_config.clone());
    let throughput = Arc::new(stats::ThroughputStats::new());

    // Start syslog listener if enabled
    let config_clone = config.clone();
    if config.syslog.enabled {
        tokio::spawn(async move {
            let syslog_config = syslog::listener::SyslogListenerConfig {
                udp_port: config_clone.syslog.udp_port,
                tcp_port: config_clone.syslog.tcp_port,
                bind_address: "0.0.0.0".to_string(),
                parse_dns_logs: config_clone.syslog.parse_dns,
            };

            let listener = syslog::listener::SyslogListener::with_default_handler(syslog_config);
            if let Err(e) = listener.start().await {
                error!("Syslog listener error: {}", e);
            }
        });
        info!(
            "Syslog listener started on UDP:{}/TCP:{}",
            config.syslog.udp_port, config.syslog.tcp_port
        );
    }

    // Create and run server
    let server = Server::new(config, shared_config, throughput).await?;

    // Handle shutdown signals
    let shutdown = tokio::spawn(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
        info!("Shutdown signal received");
    });

    // Run server
    tokio::select! {
        result = server.run_tls() => {
            if let Err(e) = result {
                error!("Server error: {}", e);
                std::process::exit(1);
            }
        }
        _ = shutdown => {
            info!("Shutting down gracefully");
        }
    }

    Ok(())
}
