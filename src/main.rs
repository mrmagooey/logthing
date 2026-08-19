use logthing::server::Server;
use logthing::shutdown::await_handles_with_deadline;
use logthing::{admin, config, forwarding, ipfix, sflow, stats, suricata, syslog, zeek};
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

    // Start CPU profiling if requested. No-op unless LOGTHING_PROFILE_SECS is
    // set; warns if set on a binary built without the `pprof` feature.
    logthing::profiling::maybe_start(Some(Box::new(|| {
        let handle = logthing::server::METRICS_HANDLE.get()?;
        logthing::profiling::parse_counter(&handle.render(), logthing::profiling::ACTIVITY_METRIC)
    })));

    let shared_config = Arc::new(RwLock::new(config.clone()));
    let source_stats = Arc::new(stats::SourceHourlyStats::new());
    let flush_registry = forwarding::flush_registry::FlushIntervalRegistry::new();
    admin::spawn_admin_server(
        shared_config.clone(),
        source_stats.clone(),
        flush_registry.clone(),
    );
    let throughput = Arc::new(stats::ThroughputStats::new());

    // Shutdown watch channel — send `true` to trigger graceful shutdown.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Collect writer JoinHandles (one per enabled S3 handler) and listener JoinHandles.
    let mut writer_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    let mut listener_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    // Shared Iceberg descriptor sink, built once and reused by every source's
    // writer construction below (syslog, ipfix, and future sources) so they
    // all emit descriptors to the same configured destination.
    let descriptor_sink =
        crate::forwarding::buffered_writer::build_iceberg_descriptor_sink(&config.iceberg)
            .await
            .unwrap_or_else(|e| {
                error!("Failed to construct Iceberg descriptor sink, descriptors disabled: {e}");
                None
            });

    // -----------------------------------------------------------------------
    // Build the aggregator (optional). Rules are validated up front: a bad
    // rule means a noisy stream would keep flowing unaggregated, so a config
    // error here is fatal rather than logged-and-skipped.
    // -----------------------------------------------------------------------
    let aggregator: Option<Arc<forwarding::aggregate::Aggregator>> = {
        let rules = forwarding::aggregate::compile_rules(&config)?;
        if rules.is_empty() {
            None
        } else {
            let agg_cfg = &config.aggregate;
            let mut handles: Vec<Arc<forwarding::aggregate::AggregateWriterHandle>> = Vec::new();

            if let Some(s3_cfg) = agg_cfg.s3.as_ref() {
                match forwarding::s3_sink::S3Sink::from_connection(&s3_cfg.connection).await {
                    Ok(sink) => {
                        let (handle, writer_handle) = forwarding::aggregate::start_aggregate_writer(
                            &rules,
                            s3_cfg.prefix.clone(),
                            agg_cfg.flush_interval_secs,
                            agg_cfg.channel_capacity,
                            Arc::new(sink),
                            source_stats.clone(),
                            descriptor_sink.clone(),
                        );
                        writer_handles.push(writer_handle);
                        flush_registry.register("aggregate.s3", handle.flush_interval());
                        handles.push(Arc::new(handle));
                    }
                    Err(e) => {
                        error!("Failed to create S3Sink for aggregation, skipping S3 target: {e}");
                    }
                }
            }

            if let Some(local_cfg) = agg_cfg.local.as_ref() {
                match forwarding::local_sink::LocalDiskSink::new(local_cfg.directory.clone()).await
                {
                    Ok(sink) => {
                        let (handle, writer_handle) = forwarding::aggregate::start_aggregate_writer(
                            &rules,
                            local_cfg.prefix.clone(),
                            agg_cfg.flush_interval_secs,
                            agg_cfg.channel_capacity,
                            Arc::new(sink),
                            source_stats.clone(),
                            descriptor_sink.clone(),
                        );
                        writer_handles.push(writer_handle);
                        flush_registry.register("aggregate.local", handle.flush_interval());
                        handles.push(Arc::new(handle));
                    }
                    Err(e) => {
                        error!(
                            "Failed to create LocalDiskSink for aggregation, \
                             skipping local target: {e}"
                        );
                    }
                }
            }

            if handles.is_empty() {
                error!(
                    "Aggregation is configured with {} rule(s) but no destination could be \
                     created; aggregation is disabled and raw records will flow normally",
                    rules.len()
                );
                None
            } else {
                let agg = Arc::new(forwarding::aggregate::Aggregator::new(
                    rules,
                    agg_cfg.max_groups,
                ));
                let emit = agg.clone().spawn_emit_task(
                    handles,
                    std::time::Duration::from_secs(agg_cfg.flush_interval_secs),
                    shutdown_rx.clone(),
                );
                writer_handles.push(emit);
                info!(
                    "Aggregation enabled: {} rule(s), {}s window",
                    agg.rules().len(),
                    agg_cfg.flush_interval_secs
                );
                Some(agg)
            }
        }
    };

    // -----------------------------------------------------------------------
    // Start syslog listener if enabled
    // -----------------------------------------------------------------------
    if config.syslog.enabled {
        let config_clone = config.clone();
        let syslog_shutdown_rx = shutdown_rx.clone();

        // Build optional structured sink BEFORE building the primary handler.
        let structured_handle: Option<Arc<forwarding::structured_syslog_s3::StructuredS3Handler>> =
            if config_clone.syslog.parse_payloads {
                if let Some(ss3_cfg) = config_clone.syslog.structured_s3.as_ref() {
                    match forwarding::s3_sink::S3Sink::from_connection(&ss3_cfg.connection).await {
                        Ok(sink) => {
                            let (sh, wh) =
                                forwarding::structured_syslog_s3::structured_syslog_start(
                                    ss3_cfg,
                                    Arc::new(sink),
                                    source_stats.clone(),
                                    descriptor_sink.clone(),
                                );
                            writer_handles.push(wh);
                            flush_registry.register("syslog.structured_s3", sh.flush_interval());
                            Some(Arc::new(sh))
                        }
                        Err(e) => {
                            error!("Failed to create S3Sink for structured syslog: {e}");
                            None
                        }
                    }
                } else {
                    None
                }
            } else {
                None
            };

        // Independently attempt each raw-persistence target; each is
        // logged-and-skipped on its own failure (no fallback to
        // DefaultSyslogHandler just because one target failed while the
        // other succeeded).
        let mut syslog_handlers: Vec<Arc<dyn syslog::listener::SyslogHandler>> = Vec::new();

        if let Some(s3_cfg) = config_clone.syslog.s3.as_ref() {
            match forwarding::s3_sink::S3Sink::from_connection(&s3_cfg.connection).await {
                Ok(sink) => {
                    let (handler, writer_handle) = forwarding::syslog_s3::syslog_start(
                        s3_cfg,
                        Arc::new(sink),
                        source_stats.clone(),
                        descriptor_sink.clone(),
                    );
                    writer_handles.push(writer_handle);
                    flush_registry.register("syslog.s3", handler.flush_interval());
                    syslog_handlers.push(Arc::new(handler));
                }
                Err(e) => {
                    error!(
                        "Failed to create S3Sink for syslog persistence, \
                             skipping S3 target: {e}"
                    );
                }
            }
        }

        if let Some(local_cfg) = config_clone.syslog.local.as_ref() {
            match forwarding::local_sink::LocalDiskSink::new(local_cfg.directory.clone()).await {
                Ok(sink) => {
                    let (handler, writer_handle) = forwarding::syslog_s3::syslog_local_start(
                        local_cfg,
                        Arc::new(sink),
                        source_stats.clone(),
                        descriptor_sink.clone(),
                    );
                    writer_handles.push(writer_handle);
                    flush_registry.register("syslog.local", handler.flush_interval());
                    syslog_handlers.push(Arc::new(handler));
                }
                Err(e) => {
                    error!(
                        "Failed to create LocalDiskSink for syslog persistence, \
                             skipping local target: {e}"
                    );
                }
            }
        }

        // If at least one persistence target came up, wrap the combined
        // persistence handler in PayloadDispatchingHandler (payload dispatch
        // + DNS-log parsing does NOT run in this branch — persistence and
        // DNS-log parsing remain mutually exclusive, as documented on
        // SyslogListener). Otherwise fall back to DefaultSyslogHandler,
        // which handles DNS-log parsing and payload dispatch itself.
        let syslog_handler: Arc<dyn syslog::listener::SyslogHandler> = if syslog_handlers.is_empty()
        {
            Arc::new(syslog::listener::DefaultSyslogHandler::new(
                config_clone.syslog.parse_dns,
                config_clone.syslog.parse_payloads,
                structured_handle,
            ))
        } else {
            // Do NOT annotate `combined` as `Arc<dyn SyslogHandler>` here — leave
            // it inferred as the concrete `Arc<MultiSyslogHandler>`.
            // `PayloadDispatchingHandler<H: SyslogHandler>` requires `H: Sized`
            // (implicit), so its `inner: Arc<H>` field cannot hold an unsized
            // `Arc<dyn SyslogHandler>` without relaxing that bound to `?Sized` —
            // which this plan's Global Constraints forbid touching. Keeping
            // `combined` concrete avoids that entirely.
            let combined = Arc::new(forwarding::syslog_s3::MultiSyslogHandler(syslog_handlers));
            Arc::new(syslog::listener::PayloadDispatchingHandler {
                inner: combined,
                parse_payloads: config_clone.syslog.parse_payloads,
                structured_handle,
            })
        };
        // Aggregation wraps the whole chain: matched records are counted here
        // and never reach the raw writer.
        let syslog_handler: Arc<dyn syslog::listener::SyslogHandler> = match aggregator.as_ref() {
            Some(agg) => Arc::new(forwarding::aggregate::handlers::AggregatingSyslogHandler {
                agg: agg.clone(),
                inner: syslog_handler,
            }),
            None => syslog_handler,
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

        let mut ipfix_handlers: Vec<Arc<dyn ipfix::listener::IpfixHandler>> = Vec::new();

        if let Some(s3_cfg) = ipfix_config_clone.ipfix.s3.as_ref() {
            match forwarding::s3_sink::S3Sink::from_connection(&s3_cfg.connection).await {
                Ok(sink) => {
                    let (handler, writer_handle) = forwarding::ipfix_s3::ipfix_start(
                        s3_cfg,
                        Arc::new(sink),
                        source_stats.clone(),
                        descriptor_sink.clone(),
                    );
                    writer_handles.push(writer_handle);
                    flush_registry.register("ipfix.s3", handler.flush_interval());
                    ipfix_handlers.push(Arc::new(handler));
                }
                Err(e) => {
                    error!(
                        "Failed to create S3Sink for IPFIX persistence, \
                             skipping S3 target: {e}"
                    );
                }
            }
        }

        if let Some(local_cfg) = ipfix_config_clone.ipfix.local.as_ref() {
            match forwarding::local_sink::LocalDiskSink::new(local_cfg.directory.clone()).await {
                Ok(sink) => {
                    let (handler, writer_handle) = forwarding::ipfix_s3::ipfix_local_start(
                        local_cfg,
                        Arc::new(sink),
                        source_stats.clone(),
                        descriptor_sink.clone(),
                    );
                    writer_handles.push(writer_handle);
                    flush_registry.register("ipfix.local", handler.flush_interval());
                    ipfix_handlers.push(Arc::new(handler));
                }
                Err(e) => {
                    error!(
                        "Failed to create LocalDiskSink for IPFIX persistence, \
                             skipping local target: {e}"
                    );
                }
            }
        }

        let ipfix_handler: Arc<dyn ipfix::listener::IpfixHandler> = match ipfix_handlers.len() {
            0 => Arc::new(ipfix::listener::DefaultIpfixHandler),
            1 => ipfix_handlers.into_iter().next().unwrap(),
            _ => Arc::new(forwarding::ipfix_s3::MultiIpfixHandler(ipfix_handlers)),
        };
        // Aggregation wraps the whole chain: matched records are counted here
        // and never reach the raw writer.
        let ipfix_handler: Arc<dyn ipfix::listener::IpfixHandler> = match aggregator.as_ref() {
            Some(agg) => Arc::new(forwarding::aggregate::handlers::AggregatingIpfixHandler {
                agg: agg.clone(),
                inner: ipfix_handler,
            }),
            None => ipfix_handler,
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

        let mut zeek_handlers: Vec<Arc<dyn zeek::listener::ZeekHandler>> = Vec::new();

        if let Some(s3_cfg) = zeek_config_clone.zeek.s3.as_ref() {
            match forwarding::s3_sink::S3Sink::from_connection(&s3_cfg.connection).await {
                Ok(sink) => {
                    let (handler, writer_handle) = forwarding::zeek_s3::zeek_start(
                        s3_cfg,
                        Arc::new(sink),
                        source_stats.clone(),
                        descriptor_sink.clone(),
                    );
                    writer_handles.push(writer_handle);
                    flush_registry.register("zeek.s3", handler.flush_interval());
                    zeek_handlers.push(Arc::new(handler));
                }
                Err(e) => {
                    error!(
                        "Failed to create S3Sink for Zeek persistence, \
                             skipping S3 target: {e}"
                    );
                }
            }
        }

        if let Some(local_cfg) = zeek_config_clone.zeek.local.as_ref() {
            match forwarding::local_sink::LocalDiskSink::new(local_cfg.directory.clone()).await {
                Ok(sink) => {
                    let (handler, writer_handle) = forwarding::zeek_s3::zeek_local_start(
                        local_cfg,
                        Arc::new(sink),
                        source_stats.clone(),
                        descriptor_sink.clone(),
                    );
                    writer_handles.push(writer_handle);
                    flush_registry.register("zeek.local", handler.flush_interval());
                    zeek_handlers.push(Arc::new(handler));
                }
                Err(e) => {
                    error!(
                        "Failed to create LocalDiskSink for Zeek persistence, \
                             skipping local target: {e}"
                    );
                }
            }
        }

        let zeek_handler: Arc<dyn zeek::listener::ZeekHandler> = match zeek_handlers.len() {
            0 => Arc::new(zeek::listener::DefaultZeekHandler),
            1 => zeek_handlers.into_iter().next().unwrap(),
            _ => Arc::new(forwarding::zeek_s3::MultiZeekHandler(zeek_handlers)),
        };
        // Aggregation wraps the whole chain: matched records are counted here
        // and never reach the raw writer.
        let zeek_handler: Arc<dyn zeek::listener::ZeekHandler> = match aggregator.as_ref() {
            Some(agg) => Arc::new(forwarding::aggregate::handlers::AggregatingZeekHandler {
                agg: agg.clone(),
                inner: zeek_handler,
            }),
            None => zeek_handler,
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
    // Start Suricata listener if enabled
    // -----------------------------------------------------------------------
    if config.suricata.enabled {
        let suricata_config_clone = config.clone();
        let suricata_shutdown_rx = shutdown_rx.clone();

        let mut suricata_handlers: Vec<Arc<dyn suricata::listener::SuricataHandler>> = Vec::new();

        if let Some(s3_cfg) = suricata_config_clone.suricata.s3.as_ref() {
            match forwarding::s3_sink::S3Sink::from_connection(&s3_cfg.connection).await {
                Ok(sink) => {
                    let (handler, writer_handle) = forwarding::suricata_s3::suricata_start(
                        s3_cfg,
                        Arc::new(sink),
                        source_stats.clone(),
                        descriptor_sink.clone(),
                    );
                    writer_handles.push(writer_handle);
                    flush_registry.register("suricata.s3", handler.flush_interval());
                    suricata_handlers.push(Arc::new(handler));
                }
                Err(e) => {
                    error!(
                        "Failed to create S3Sink for Suricata persistence, \
                             skipping S3 target: {e}"
                    );
                }
            }
        }

        if let Some(local_cfg) = suricata_config_clone.suricata.local.as_ref() {
            match forwarding::local_sink::LocalDiskSink::new(local_cfg.directory.clone()).await {
                Ok(sink) => {
                    let (handler, writer_handle) = forwarding::suricata_s3::suricata_local_start(
                        local_cfg,
                        Arc::new(sink),
                        source_stats.clone(),
                        descriptor_sink.clone(),
                    );
                    writer_handles.push(writer_handle);
                    flush_registry.register("suricata.local", handler.flush_interval());
                    suricata_handlers.push(Arc::new(handler));
                }
                Err(e) => {
                    error!(
                        "Failed to create LocalDiskSink for Suricata persistence, \
                             skipping local target: {e}"
                    );
                }
            }
        }

        let suricata_handler: Arc<dyn suricata::listener::SuricataHandler> =
            match suricata_handlers.len() {
                0 => Arc::new(suricata::listener::DefaultSuricataHandler),
                1 => suricata_handlers.into_iter().next().unwrap(),
                _ => Arc::new(forwarding::suricata_s3::MultiSuricataHandler(
                    suricata_handlers,
                )),
            };
        // Aggregation wraps the whole chain: matched records are counted here
        // and never reach the raw writer.
        let suricata_handler: Arc<dyn suricata::listener::SuricataHandler> =
            match aggregator.as_ref() {
                Some(agg) => Arc::new(
                    forwarding::aggregate::handlers::AggregatingSuricataHandler {
                        agg: agg.clone(),
                        inner: suricata_handler,
                    },
                ),
                None => suricata_handler,
            };

        let listener_config = suricata::listener::SuricataListenerConfig {
            tcp_port: suricata_config_clone.suricata.tcp_port,
            bind_address: suricata_config_clone.suricata.bind_address.clone(),
        };
        let handle = tokio::spawn(async move {
            let listener =
                suricata::listener::SuricataListener::new(listener_config, suricata_handler);
            if let Err(e) = listener.start_with_shutdown(suricata_shutdown_rx).await {
                error!("Suricata listener error: {}", e);
            }
        });
        listener_handles.push(handle);
    }

    // -----------------------------------------------------------------------
    // Start sFlow listener if enabled
    // -----------------------------------------------------------------------
    if config.sflow.enabled {
        let sflow_config_clone = config.clone();
        let sflow_shutdown_rx = shutdown_rx.clone();

        let mut sflow_handlers: Vec<Arc<dyn sflow::listener::SflowHandler>> = Vec::new();

        if let Some(s3_cfg) = sflow_config_clone.sflow.s3.as_ref() {
            match forwarding::s3_sink::S3Sink::from_connection(&s3_cfg.connection).await {
                Ok(sink) => {
                    let (handler, writer_handle) = forwarding::sflow_s3::sflow_start(
                        s3_cfg,
                        Arc::new(sink),
                        source_stats.clone(),
                        descriptor_sink.clone(),
                    );
                    writer_handles.push(writer_handle);
                    flush_registry.register("sflow.s3", handler.flush_interval());
                    sflow_handlers.push(Arc::new(handler));
                }
                Err(e) => {
                    error!(
                        "Failed to create S3Sink for sFlow persistence, \
                             skipping S3 target: {e}"
                    );
                }
            }
        }

        if let Some(local_cfg) = sflow_config_clone.sflow.local.as_ref() {
            match forwarding::local_sink::LocalDiskSink::new(local_cfg.directory.clone()).await {
                Ok(sink) => {
                    let (handler, writer_handle) = forwarding::sflow_s3::sflow_local_start(
                        local_cfg,
                        Arc::new(sink),
                        source_stats.clone(),
                        descriptor_sink.clone(),
                    );
                    writer_handles.push(writer_handle);
                    flush_registry.register("sflow.local", handler.flush_interval());
                    sflow_handlers.push(Arc::new(handler));
                }
                Err(e) => {
                    error!(
                        "Failed to create LocalDiskSink for sFlow persistence, \
                             skipping local target: {e}"
                    );
                }
            }
        }

        let sflow_handler: Arc<dyn sflow::listener::SflowHandler> = match sflow_handlers.len() {
            0 => Arc::new(sflow::listener::DefaultSflowHandler),
            1 => sflow_handlers.into_iter().next().unwrap(),
            _ => Arc::new(forwarding::sflow_s3::MultiSflowHandler(sflow_handlers)),
        };
        // Aggregation wraps the whole chain: matched records are counted here
        // and never reach the raw writer.
        let sflow_handler: Arc<dyn sflow::listener::SflowHandler> = match aggregator.as_ref() {
            Some(agg) => Arc::new(forwarding::aggregate::handlers::AggregatingSflowHandler {
                agg: agg.clone(),
                inner: sflow_handler,
            }),
            None => sflow_handler,
        };

        let listener_config = sflow::listener::SflowListenerConfig {
            udp_port: sflow_config_clone.sflow.udp_port,
            bind_address: sflow_config_clone.sflow.bind_address.clone(),
        };
        let handle = tokio::spawn(async move {
            let listener = sflow::listener::SflowListener::new(listener_config, sflow_handler);
            if let Err(e) = listener.start_with_shutdown(sflow_shutdown_rx).await {
                error!("sFlow listener error: {}", e);
            }
        });
        listener_handles.push(handle);
    }

    // -----------------------------------------------------------------------
    // Create axum server
    // -----------------------------------------------------------------------
    let mut server = Server::new(
        config,
        shared_config,
        throughput,
        source_stats,
        flush_registry,
    )
    .await?;

    // Gap-b: Extract the WEF→S3 Parquet worker handle BEFORE the server is
    // consumed by run_tls, so we can await it during the shutdown sequence.
    let wef_worker_handles = server.take_wef_worker_handles();
    let hec_worker_handles = server.take_hec_worker_handles();

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

    // 2. Wait briefly for listeners to exit. Each listener's accept loop holds
    //    Arc<dyn Handler> clones, so aborting it releases those — but for Zeek
    //    and Suricata it does NOT release every clone: each accepted connection
    //    runs in a detached `tokio::spawn` holding its own clone
    //    (`zeek/listener.rs:107-117`), and nothing here signals or aborts those
    //    tasks. See step 3.
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

    // 3. Await all writer tasks (plus the optional WEF worker) with a shared 10s
    //    combined timeout via `await_handles_with_deadline`.
    //
    //    A writer task only returns once its channel closes, i.e. once the LAST
    //    Sender drops. That happens promptly for sources whose handler Arcs live
    //    solely in the listener task just aborted. It does NOT happen for Zeek or
    //    Suricata while any sensor holds its TCP connection open: those
    //    per-connection tasks are detached and keep an Arc<dyn Handler>, so the
    //    channel stays open, the writer keeps looping, and the 10s deadline below
    //    expires with the warning rather than a clean flush. The buffered rows are
    //    then whatever the last periodic flush did not cover.
    //
    //    Fixing that means giving connection tasks a shutdown signal or tracked
    //    JoinHandles — a lifetime change deliberately out of scope here; recorded
    //    in the final review of `feat/ingest-backpressure`.
    info!("Waiting for S3 writer tasks to flush (up to 10s)...");

    // 4. Gap-b: Bundle the WEF→S3 Parquet worker handle (if present) into the
    //    same flush batch so the entire set shares a single 10s deadline.
    //    The worker exits when the axum server drops AppState (closing the channel)
    //    and its None arm calls shutdown_flush.
    let mut all_writer_handles = writer_handles;
    all_writer_handles.extend(wef_worker_handles);
    all_writer_handles.extend(hec_worker_handles);

    let total = all_writer_handles.len();
    let completed = await_handles_with_deadline(all_writer_handles, Duration::from_secs(10)).await;
    if completed < total {
        // Say *how much*, not just "some". The unfinished writers are still
        // running and still refreshing `parquet_s3_channel_queued` once a
        // second, so reading it back out of the recorder (the same trick
        // `profiling::maybe_start` uses above) gives a near-live figure with no
        // cross-task plumbing. `None` when the metrics server is disabled, and
        // it counts records still in the channels — not rows already moved into
        // a writer's partition buffers, which no live gauge tracks.
        let queued = logthing::server::METRICS_HANDLE.get().and_then(|h| {
            logthing::profiling::parse_counter(&h.render(), "parquet_s3_channel_queued")
        });
        warn!(
            queued_records = queued,
            "S3 writer flush timed out after 10s; {}/{} tasks finished — some data may not have been written",
            completed,
            total,
        );
    }

    info!("Shutdown complete");
    Ok(())
}
