use logthing::server::Server;
use logthing::{admin, config, forwarding, ipfix, stats, syslog, zeek};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

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

    // Shutdown watch channel — send `true` to trigger graceful shutdown.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Collect writer JoinHandles (one per enabled S3 handler) and listener JoinHandles.
    let mut writer_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    let mut listener_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    // -----------------------------------------------------------------------
    // Start syslog listener if enabled
    // -----------------------------------------------------------------------
    if config.syslog.enabled {
        let config_clone = config.clone();
        let syslog_shutdown_rx = shutdown_rx.clone();

        // Build the handler BEFORE spawning so we can extract the writer JoinHandle.
        let syslog_handler: Arc<dyn syslog::listener::SyslogHandler> =
            if let Some(s3_cfg) = config_clone.syslog.s3.as_ref() {
                match forwarding::s3_sink::S3Sink::from_connection(&s3_cfg.connection).await {
                    Ok(sink) => {
                        let writer_cfg = forwarding::syslog_s3::SyslogS3WriterConfig {
                            max_buffer_rows: s3_cfg.max_buffer_rows,
                            flush_interval: Duration::from_secs(s3_cfg.flush_interval_secs),
                            key_prefix: s3_cfg.prefix.clone(),
                        };
                        let (handler, writer_handle) =
                            forwarding::syslog_s3::SyslogS3Handler::start_with_capacity(
                                writer_cfg,
                                Arc::new(sink),
                                s3_cfg.channel_capacity,
                            );
                        writer_handles.push(writer_handle);
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

        let syslog_config = syslog::listener::SyslogListenerConfig {
            udp_port: config_clone.syslog.udp_port,
            tcp_port: config_clone.syslog.tcp_port,
            bind_address: "0.0.0.0".to_string(),
            parse_dns_logs: config_clone.syslog.parse_dns,
        };
        let handle = tokio::spawn(async move {
            let listener = syslog::listener::SyslogListener::new(syslog_config, syslog_handler);
            if let Err(e) = listener.start_with_shutdown(syslog_shutdown_rx).await {
                error!("Syslog listener error: {}", e);
            }
        });
        listener_handles.push(handle);
    }

    // -----------------------------------------------------------------------
    // Start IPFIX listener if enabled
    // -----------------------------------------------------------------------
    if config.ipfix.enabled {
        let ipfix_config_clone = config.clone();
        let ipfix_shutdown_rx = shutdown_rx.clone();

        let ipfix_handler: Arc<dyn ipfix::listener::IpfixHandler> =
            if let Some(s3_cfg) = ipfix_config_clone.ipfix.s3.as_ref() {
                match forwarding::s3_sink::S3Sink::from_connection(&s3_cfg.connection).await {
                    Ok(sink) => {
                        let (handler, writer_handle) =
                            forwarding::ipfix_s3::ipfix_start(s3_cfg, Arc::new(sink));
                        writer_handles.push(writer_handle);
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

        let listener_config = ipfix::listener::IpfixListenerConfig {
            udp_port: ipfix_config_clone.ipfix.udp_port,
            bind_address: ipfix_config_clone.ipfix.bind_address.clone(),
        };
        let handle = tokio::spawn(async move {
            let listener = ipfix::listener::IpfixListener::new(listener_config, ipfix_handler);
            if let Err(e) = listener.start_with_shutdown(ipfix_shutdown_rx).await {
                error!("IPFIX listener error: {}", e);
            }
        });
        listener_handles.push(handle);
    }

    // -----------------------------------------------------------------------
    // Start Zeek listener if enabled
    // -----------------------------------------------------------------------
    if config.zeek.enabled {
        let zeek_config_clone = config.clone();
        let zeek_shutdown_rx = shutdown_rx.clone();

        let zeek_handler: Arc<dyn zeek::listener::ZeekHandler> =
            if let Some(s3_cfg) = zeek_config_clone.zeek.s3.as_ref() {
                match forwarding::s3_sink::S3Sink::from_connection(&s3_cfg.connection).await {
                    Ok(sink) => {
                        let writer_cfg = forwarding::zeek_s3::ZeekS3WriterConfig {
                            flush_threshold_bytes: s3_cfg.flush_threshold_bytes,
                            flush_interval: Duration::from_secs(s3_cfg.flush_interval_secs),
                            key_prefix: s3_cfg.prefix.clone(),
                            max_buffer_rows: s3_cfg.max_buffer_rows,
                        };
                        let (handler, writer_handle) =
                            forwarding::zeek_s3::ZeekS3Handler::start_with_capacity(
                                writer_cfg,
                                Arc::new(sink),
                                s3_cfg.channel_capacity,
                            );
                        writer_handles.push(writer_handle);
                        Arc::new(handler)
                    }
                    Err(e) => {
                        error!(
                            "Failed to create S3Sink for Zeek persistence, \
                                 falling back to DefaultZeekHandler: {e}"
                        );
                        Arc::new(zeek::listener::DefaultZeekHandler)
                    }
                }
            } else {
                Arc::new(zeek::listener::DefaultZeekHandler)
            };

        let listener_config = zeek::listener::ZeekListenerConfig {
            tcp_port: zeek_config_clone.zeek.tcp_port,
            bind_address: zeek_config_clone.zeek.bind_address.clone(),
        };
        let handle = tokio::spawn(async move {
            let listener = zeek::listener::ZeekListener::new(listener_config, zeek_handler);
            if let Err(e) = listener.start_with_shutdown(zeek_shutdown_rx).await {
                error!("Zeek listener error: {}", e);
            }
        });
        listener_handles.push(handle);
    }

    // -----------------------------------------------------------------------
    // Create axum server
    // -----------------------------------------------------------------------
    let mut server = Server::new(config, shared_config, throughput).await?;

    // Gap-b: Extract the WEF→S3 Parquet worker handle BEFORE the server is
    // consumed by run_tls, so we can await it during the shutdown sequence.
    let wef_worker_handle = server.take_wef_worker_handle();

    // -----------------------------------------------------------------------
    // Shutdown signal task
    // -----------------------------------------------------------------------
    let shutdown_signal = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
        info!("Shutdown signal received");
    };

    // -----------------------------------------------------------------------
    // Run server until shutdown
    // -----------------------------------------------------------------------
    tokio::select! {
        result = server.run_tls(shutdown_rx.clone()) => {
            if let Err(e) = result {
                error!("Server error: {}", e);
                std::process::exit(1);
            }
        }
        _ = shutdown_signal => {
            info!("Shutting down gracefully");
        }
        // H-3: Supervise listener tasks — log if any exits unexpectedly
        result = async {
            // Wait for the first listener handle to complete (unexpectedly)
            let mut futs = futures::stream::FuturesUnordered::new();
            for h in &mut listener_handles {
                futs.push(h);
            }
            use futures::StreamExt;
            futs.next().await
        } => {
            match result {
                Some(Ok(())) => {
                    warn!("A listener task exited unexpectedly (returned Ok); check logs");
                }
                Some(Err(e)) => {
                    error!("A listener task panicked or was cancelled: {e}");
                }
                None => {}
            }
        }
    }

    // -----------------------------------------------------------------------
    // Graceful shutdown sequence
    // -----------------------------------------------------------------------

    // 1. Signal all listeners to stop accepting, and signal the axum server to
    //    begin graceful shutdown (it will stop accepting new connections and
    //    drain in-flight requests, then drop AppState which closes the WEF
    //    worker's channel).
    if let Err(e) = shutdown_tx.send(true) {
        warn!("Failed to send shutdown signal: {e}");
    }

    // 2. Wait briefly for listeners to exit (they hold the last Arc<dyn Handler> clones).
    //    After listeners exit (or are aborted), the Arc refcount drops to zero,
    //    the Sender inside each S3 handler is dropped, the channel closes,
    //    and the writer task flushes then exits.
    //
    //    R-2: Capture abort_handle() before awaiting so that a timed-out
    //    listener task is truly cancelled (not just detached).
    let mut listener_abort_handles: Vec<tokio::task::AbortHandle> = Vec::new();
    for handle in &listener_handles {
        listener_abort_handles.push(handle.abort_handle());
    }

    for (handle, abort_handle) in listener_handles.into_iter().zip(listener_abort_handles) {
        match tokio::time::timeout(Duration::from_secs(2), handle).await {
            Ok(_) => {}
            Err(_) => {
                // Listener didn't exit cleanly within 2s — abort it so the task
                // is truly cancelled (dropped), releasing the Arc<dyn Handler>
                // which closes the writer's channel.
                abort_handle.abort();
            }
        }
    }

    // 3. The handler Arcs created in this function were moved into the listener tasks.
    //    With the listener tasks finished (or aborted), the Arc refcounts hit zero,
    //    the Senders drop, and the writer channels close.
    //    Now await all writer tasks with a 10s combined timeout.
    info!("Waiting for S3 writer tasks to flush (up to 10s)...");
    let flush_deadline = tokio::time::sleep(Duration::from_secs(10));
    tokio::pin!(flush_deadline);

    for handle in writer_handles {
        tokio::select! {
            result = handle => {
                match result {
                    Ok(()) => {}
                    Err(e) => {
                        warn!("S3 writer task error during shutdown: {e}");
                    }
                }
            }
            _ = &mut flush_deadline => {
                warn!("S3 writer flush timed out after 10s; some data may not have been written");
                break;
            }
        }
    }

    // 4. Gap-b: Await the WEF→S3 Parquet worker handle (within the same 10s
    //    deadline, which is shared via the pinned flush_deadline above).
    //    The worker exits when the axum server drops AppState (closing the channel)
    //    and its None arm calls shutdown_flush.
    if let Some(wef_handle) = wef_worker_handle {
        tokio::select! {
            result = wef_handle => {
                match result {
                    Ok(()) => {
                        info!("Parquet S3 WEF worker flushed and exited cleanly");
                    }
                    Err(e) => {
                        warn!("Parquet S3 WEF worker error during shutdown: {e}");
                    }
                }
            }
            _ = &mut flush_deadline => {
                warn!(
                    "Parquet S3 WEF worker flush timed out; some WEF data may not have been written"
                );
            }
        }
    }

    info!("Shutdown complete");
    Ok(())
}
