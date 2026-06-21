mod admin;
mod config;
mod forwarding;
mod ipfix;
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

fn main() -> anyhow::Result<()> {
    // Determine number of worker threads (default to all CPU cores)
    let num_cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);

    // Check for environment override
    let worker_threads = std::env::var("WEF_WORKER_THREADS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(num_cpus);

    info!(
        "Starting WEF Server with {} worker threads ({} CPUs available)",
        worker_threads, num_cpus
    );

    // Create multi-threaded Tokio runtime
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()?;

    runtime.block_on(async_main())
}

async fn async_main() -> anyhow::Result<()> {
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

            let handler: Arc<dyn syslog::listener::SyslogHandler> =
                if let Some(s3_cfg) = config_clone.syslog.s3.as_ref() {
                    let parquet_cfg = s3_cfg.to_parquet_s3_config();
                    match forwarding::s3_sink::S3Sink::from_config(&parquet_cfg).await {
                        Ok(sink) => {
                            let writer_cfg = forwarding::syslog_s3::SyslogS3WriterConfig {
                                max_buffer_rows: s3_cfg.max_buffer_rows,
                                flush_interval: std::time::Duration::from_secs(
                                    s3_cfg.flush_interval_secs,
                                ),
                                key_prefix: s3_cfg.key_prefix.clone(),
                            };
                            let handler = forwarding::syslog_s3::SyslogS3Handler::start(
                                writer_cfg,
                                Arc::new(sink),
                            );
                            Arc::new(handler)
                        }
                        Err(e) => {
                            error!(
                                "Failed to create S3Sink for syslog persistence, \
                                 falling back to DefaultSyslogHandler: {e}"
                            );
                            Arc::new(syslog::listener::DefaultSyslogHandler::new(
                                config_clone.syslog.parse_dns,
                            ))
                        }
                    }
                } else {
                    Arc::new(syslog::listener::DefaultSyslogHandler::new(
                        config_clone.syslog.parse_dns,
                    ))
                };

            let listener = syslog::listener::SyslogListener::new(syslog_config, handler);
            if let Err(e) = listener.start().await {
                error!("Syslog listener error: {}", e);
            }
        });
        info!(
            "Syslog listener started on UDP:{}/TCP:{}",
            config.syslog.udp_port, config.syslog.tcp_port
        );
    }

    // Start IPFIX listener if enabled
    if config.ipfix.enabled {
        let ipfix_config_clone = config.clone();
        tokio::spawn(async move {
            let listener_config = ipfix::listener::IpfixListenerConfig {
                udp_port: ipfix_config_clone.ipfix.udp_port,
                bind_address: ipfix_config_clone.ipfix.bind_address.clone(),
            };

            let handler: Arc<dyn ipfix::listener::IpfixHandler> =
                if let Some(s3_cfg) = ipfix_config_clone.ipfix.s3.as_ref() {
                    let parquet_cfg = s3_cfg.to_parquet_s3_config();
                    match forwarding::s3_sink::S3Sink::from_config(&parquet_cfg).await {
                        Ok(sink) => {
                            let writer_cfg = forwarding::ipfix_s3::IpfixS3WriterConfig {
                                flush_threshold_bytes: s3_cfg.flush_threshold_bytes,
                                flush_interval: std::time::Duration::from_secs(
                                    s3_cfg.flush_interval_secs,
                                ),
                                key_prefix: s3_cfg.prefix.clone(),
                                max_buffer_rows: s3_cfg.max_buffer_rows,
                            };
                            let handler = forwarding::ipfix_s3::IpfixS3Handler::start_with_capacity(
                                writer_cfg,
                                Arc::new(sink),
                                s3_cfg.channel_capacity,
                            );
                            Arc::new(handler)
                        }
                        Err(e) => {
                            error!(
                                "Failed to create S3Sink for IPFIX persistence, \
                                 falling back to DefaultIpfixHandler: {e}"
                            );
                            Arc::new(ipfix::listener::DefaultIpfixHandler)
                        }
                    }
                } else {
                    Arc::new(ipfix::listener::DefaultIpfixHandler)
                };

            let listener = ipfix::listener::IpfixListener::new(listener_config, handler);
            if let Err(e) = listener.start().await {
                error!("IPFIX listener error: {}", e);
            }
        });
        info!("IPFIX listener started on UDP:{}", config.ipfix.udp_port);
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
