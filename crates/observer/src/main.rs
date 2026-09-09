mod bpf {
    include!(concat!(env!("OUT_DIR"), "/observer.skel.rs"));
}

use anyhow::{anyhow, Context, Result};
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use bpf::ObserverSkelBuilder;
use clap::{Parser, ValueEnum};
use dam_schema::{
    CaptureConfidence, CaptureMetadata, CaptureSource, DamBatch, DamEvent, EventPayload,
    SensorHealth, BATCH_SCHEMA_VERSION, EVENT_SCHEMA_VERSION,
};
use dam_spool::DurableSpool;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    Link, MapCore, MapFlags, MapHandle, ProgramMut, RingBufferBuilder, UprobeOpts,
};
use observer::{CapturedKernelEvent, EventProcessor, KernelEvent, ProcessorConfig, OP_CPU_SAMPLE};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs,
    mem::{size_of, MaybeUninit},
    net::SocketAddr,
    os::fd::{FromRawFd, OwnedFd},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};
use time::OffsetDateTime;
use tokio::{
    net::TcpListener,
    sync::{mpsc, oneshot, watch, Notify},
};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum TlsUprobeMode {
    Auto,
    Required,
    Off,
}

#[derive(Debug, Parser)]
#[command(author, version, about = "Node-local eBPF sensor for MongoDB DAM")]
struct Cli {
    #[arg(long, env = "DAM_CUSTOMER_ID")]
    customer_id: String,
    #[arg(long, env = "DAM_TENANT_ID")]
    tenant_id: String,
    #[arg(long, env = "DAM_SOURCE_ID")]
    source_id: String,
    #[arg(long, env = "DAM_REGIONAL_CELL_ID")]
    regional_cell_id: String,
    #[arg(long, env = "DAM_CLUSTER_NAME")]
    cluster_name: String,
    #[arg(long, env = "NODE_NAME")]
    node_name: String,
    #[arg(long, env = "OBSERVER_SENSOR_ID")]
    sensor_id: Option<String>,
    #[arg(
        long,
        env = "OBSERVER_OUTPOST_URL",
        default_value = "http://mongodb-dam-outpost:8090/v1/observer/batches"
    )]
    outpost_url: String,
    #[arg(long, env = "OBSERVER_INTERNAL_TOKEN_FILE")]
    internal_token_file: Option<PathBuf>,
    #[arg(long, env = "OBSERVER_PRINCIPAL_HASH_SALT_FILE")]
    principal_hash_salt_file: Option<PathBuf>,
    #[arg(long, env = "OBSERVER_HOST_PROC", default_value = "/host/proc")]
    host_proc: PathBuf,
    #[arg(
        long,
        env = "OBSERVER_SPOOL_DIR",
        default_value = "/var/lib/mongodb-dam/observer"
    )]
    spool_dir: PathBuf,
    #[arg(long, env = "OBSERVER_SPOOL_MAX_BYTES", default_value_t = 268_435_456)]
    spool_max_bytes: u64,
    #[arg(long, env = "OBSERVER_BATCH_MAX_EVENTS", default_value_t = 200)]
    batch_max_events: usize,
    #[arg(
        long,
        env = "OBSERVER_BATCH_FLUSH_MILLISECONDS",
        default_value_t = 1_000
    )]
    batch_flush_milliseconds: u64,
    #[arg(long, env = "OBSERVER_EXPORT_INTERVAL_SECONDS", default_value_t = 5)]
    export_interval_seconds: u64,
    #[arg(long, env = "OBSERVER_RESCAN_SECONDS", default_value_t = 2)]
    rescan_seconds: u64,
    #[arg(long, env = "OBSERVER_MAX_MESSAGE_BYTES", default_value_t = 50_331_648)]
    max_message_bytes: usize,
    #[arg(long, env = "OBSERVER_CPU_PROFILE_HZ", default_value_t = 49)]
    cpu_profile_hz: u32,
    #[arg(long, env = "OBSERVER_TLS_UPROBES", value_enum, default_value = "auto")]
    tls_uprobes: TlsUprobeMode,
    #[arg(long, env = "OBSERVER_LOCK_PROFILING", default_value_t = true)]
    lock_profiling: bool,
    #[arg(long, env = "OBSERVER_LISTEN_ADDR", default_value = "0.0.0.0:8091")]
    listen_addr: SocketAddr,
}

#[derive(Default)]
struct RuntimeMetrics {
    bpf_ready: AtomicBool,
    ring_events: AtomicU64,
    malformed_ring_events: AtomicU64,
    userspace_dropped_events: AtomicU64,
    parse_errors: AtomicU64,
    metadata_events: AtomicU64,
    batches_spooled: AtomicU64,
    spool_dropped_events: AtomicU64,
    batches_delivered: AtomicU64,
    delivery_failures: AtomicU64,
    quarantined_batches: AtomicU64,
    bpf_dropped_events: AtomicU64,
    target_processes: AtomicUsize,
    tls_uprobe_processes: AtomicUsize,
}

#[derive(Clone)]
struct HealthState {
    metrics: Arc<RuntimeMetrics>,
    spool: DurableSpool,
    node_name: Arc<String>,
}

#[derive(Serialize)]
struct HealthResponse {
    service: &'static str,
    status: &'static str,
    node_name: String,
    target_processes: usize,
    tls_uprobe_processes: usize,
    spool_items: u64,
    spool_bytes: u64,
    quarantine_items: u64,
    quarantine_bytes: u64,
}

#[derive(Clone)]
struct Assignment {
    customer_id: String,
    tenant_id: String,
    source_id: String,
    regional_cell_id: String,
    sensor_id: String,
    node_name: String,
}

struct UprobeSet {
    ssl_links: Vec<Link>,
    lock_links: Vec<Link>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();
    let cli = Cli::parse();
    validate_cli(&cli)?;

    let sensor_id = cli
        .sensor_id
        .clone()
        .unwrap_or_else(|| format!("mongodb-dam-observer-{}", cli.node_name));
    let assignment = Assignment {
        customer_id: cli.customer_id.clone(),
        tenant_id: cli.tenant_id.clone(),
        source_id: cli.source_id.clone(),
        regional_cell_id: cli.regional_cell_id.clone(),
        sensor_id: sensor_id.clone(),
        node_name: cli.node_name.clone(),
    };
    let internal_token = cli
        .internal_token_file
        .as_deref()
        .map(read_secret)
        .transpose()?;
    let principal_hash_salt = cli
        .principal_hash_salt_file
        .as_deref()
        .map(read_secret)
        .transpose()?;
    let spool = DurableSpool::open(&cli.spool_dir, cli.spool_max_bytes)?;
    let metrics = Arc::new(RuntimeMetrics::default());
    let notify = Arc::new(Notify::new());
    let stopping = Arc::new(AtomicBool::new(false));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let (kernel_tx, mut kernel_rx) = mpsc::channel::<CapturedKernelEvent>(8_192);
    let (event_tx, event_rx) = mpsc::channel::<DamEvent>(4_096);
    let processor_metrics = metrics.clone();
    let processor_config = ProcessorConfig {
        customer_id: cli.customer_id.clone(),
        tenant_id: cli.tenant_id.clone(),
        source_id: cli.source_id.clone(),
        regional_cell_id: cli.regional_cell_id.clone(),
        sensor_id,
        node_name: cli.node_name.clone(),
        cluster_name: cli.cluster_name.clone(),
        host_proc: cli.host_proc.clone(),
        max_message_bytes: cli.max_message_bytes,
        cpu_profile_hz: cli.cpu_profile_hz,
        principal_hash_salt,
    };
    let processor_task = tokio::spawn(async move {
        let mut processor = EventProcessor::new(processor_config);
        while let Some(captured) = kernel_rx.recv().await {
            match processor.process(captured) {
                Ok(events) => {
                    for event in events {
                        processor_metrics
                            .metadata_events
                            .fetch_add(1, Ordering::Relaxed);
                        if event_tx.send(event).await.is_err() {
                            return;
                        }
                    }
                }
                Err(error) => {
                    processor_metrics
                        .parse_errors
                        .fetch_add(1, Ordering::Relaxed);
                    warn!(error, "discarded undecodable bounded MongoDB prefix");
                }
            }
        }
    });

    let batch_task = tokio::spawn(run_batcher(
        event_rx,
        spool.clone(),
        assignment.clone(),
        cli.batch_max_events,
        Duration::from_millis(cli.batch_flush_milliseconds.max(100)),
        notify.clone(),
        metrics.clone(),
    ));
    let exporter_task = tokio::spawn(run_exporter(
        spool.clone(),
        cli.outpost_url.clone(),
        internal_token,
        Duration::from_secs(cli.export_interval_seconds.max(1)),
        notify,
        metrics.clone(),
        shutdown_rx.clone(),
    ));

    let bpf_config = BpfConfig {
        host_proc: cli.host_proc.clone(),
        rescan_interval: Duration::from_secs(cli.rescan_seconds.max(1)),
        cpu_profile_hz: cli.cpu_profile_hz,
        tls_mode: cli.tls_uprobes,
        lock_profiling: cli.lock_profiling,
    };
    let (startup_tx, startup_rx) = oneshot::channel::<std::result::Result<(), String>>();
    let bpf_metrics = metrics.clone();
    let bpf_stopping = stopping.clone();
    let bpf_thread = thread::Builder::new()
        .name("mongodb-dam-ebpf".into())
        .spawn(move || {
            let mut startup_tx = Some(startup_tx);
            if let Err(error) = run_bpf(
                bpf_config,
                kernel_tx,
                bpf_metrics.clone(),
                bpf_stopping,
                &mut startup_tx,
            ) {
                bpf_metrics.bpf_ready.store(false, Ordering::Release);
                if let Some(sender) = startup_tx.take() {
                    let _ = sender.send(Err(format!("{error:#}")));
                }
                error!(error = ?error, "eBPF worker stopped");
            }
        })?;
    match startup_rx
        .await
        .context("eBPF worker exited before reporting startup")?
    {
        Ok(()) => {}
        Err(error) => return Err(anyhow!(error)),
    }

    let health_state = HealthState {
        metrics: metrics.clone(),
        spool: spool.clone(),
        node_name: Arc::new(cli.node_name.clone()),
    };
    let app = Router::new()
        .route("/health", get(health))
        .route("/ready", get(health))
        .route("/metrics", get(prometheus_metrics))
        .with_state(health_state);
    let listener = TcpListener::bind(cli.listen_addr)
        .await
        .with_context(|| format!("binding Observer HTTP server to {}", cli.listen_addr))?;
    info!(address = %cli.listen_addr, "MongoDB DAM Observer ready");

    let mut server_shutdown = shutdown_rx.clone();
    let server = axum::serve(listener, app).with_graceful_shutdown(async move {
        while !*server_shutdown.borrow() {
            if server_shutdown.changed().await.is_err() {
                break;
            }
        }
    });
    tokio::select! {
        result = server => result?,
        result = tokio::signal::ctrl_c() => result.context("waiting for shutdown signal")?,
    }

    stopping.store(true, Ordering::Release);
    let _ = tokio::task::spawn_blocking(move || bpf_thread.join()).await;
    let _ = processor_task.await;
    let _ = batch_task.await;
    let _ = shutdown_tx.send(true);
    let _ = exporter_task.await;
    Ok(())
}

fn validate_cli(cli: &Cli) -> Result<()> {
    for (name, value) in [
        ("customer_id", cli.customer_id.as_str()),
        ("tenant_id", cli.tenant_id.as_str()),
        ("source_id", cli.source_id.as_str()),
        ("regional_cell_id", cli.regional_cell_id.as_str()),
        ("cluster_name", cli.cluster_name.as_str()),
        ("node_name", cli.node_name.as_str()),
        ("outpost_url", cli.outpost_url.as_str()),
    ] {
        anyhow::ensure!(!value.trim().is_empty(), "{name} must not be empty");
    }
    anyhow::ensure!(
        cli.batch_max_events > 0,
        "batch_max_events must be positive"
    );
    anyhow::ensure!(
        cli.cpu_profile_hz <= 999,
        "cpu_profile_hz must be at most 999"
    );
    Ok(())
}

#[derive(Clone)]
struct BpfConfig {
    host_proc: PathBuf,
    rescan_interval: Duration,
    cpu_profile_hz: u32,
    tls_mode: TlsUprobeMode,
    lock_profiling: bool,
}

fn run_bpf(
    config: BpfConfig,
    sender: mpsc::Sender<CapturedKernelEvent>,
    metrics: Arc<RuntimeMetrics>,
    stopping: Arc<AtomicBool>,
    startup: &mut Option<oneshot::Sender<std::result::Result<(), String>>>,
) -> Result<()> {
    raise_memlock_limit();
    let mut object = MaybeUninit::uninit();
    let open = ObserverSkelBuilder::default()
        .open(&mut object)
        .context("opening the eBPF object")?;
    let skel = open.load().context(
        "loading eBPF programs; the node needs BTF, Linux 5.8+, and privileged BPF access",
    )?;

    let mut kernel_links = Vec::new();
    macro_rules! required {
        ($program:expr, $name:literal) => {
            kernel_links.push(
                $program
                    .attach()
                    .with_context(|| format!("attaching {}", $name))?,
            );
        };
    }
    macro_rules! optional {
        ($program:expr, $name:literal) => {
            match $program.attach() {
                Ok(link) => kernel_links.push(link),
                Err(error) => warn!(probe = $name, error = ?error, "optional kernel probe unavailable"),
            }
        };
    }
    required!(skel.progs.handle_sys_enter, "raw_syscalls/sys_enter");
    required!(skel.progs.handle_sys_exit, "raw_syscalls/sys_exit");
    required!(skel.progs.handle_sched_switch, "sched/sched_switch");
    required!(skel.progs.handle_process_exec, "sched/sched_process_exec");
    required!(skel.progs.handle_process_exit, "sched/sched_process_exit");
    required!(skel.progs.handle_tcp_sendmsg, "tcp_sendmsg");
    required!(skel.progs.handle_tcp_recvmsg, "tcp_recvmsg");
    optional!(skel.progs.handle_tcp_connect, "tcp_connect");
    optional!(skel.progs.handle_tcp_accept, "inet_csk_accept");
    optional!(skel.progs.handle_tcp_close, "tcp_close");
    optional!(skel.progs.handle_tcp_rtt, "tcp_rcv_established");
    optional!(skel.progs.handle_tcp_retransmit, "tcp_retransmit_skb");
    optional!(skel.progs.handle_page_fault_enter, "handle_mm_fault entry");
    optional!(skel.progs.handle_page_fault_exit, "handle_mm_fault return");

    let target_map = MapHandle::try_from(&skel.maps.target_tgids)?;
    let dropped_map = MapHandle::try_from(&skel.maps.dropped_events)?;
    let stack_map = Arc::new(MapHandle::try_from(&skel.maps.stack_traces)?);

    let mut perf_fds = Vec::new();
    let mut perf_links = Vec::new();
    if config.cpu_profile_hz > 0 {
        attach_cpu_sampling(
            &skel.progs.handle_cpu_sample,
            config.cpu_profile_hz,
            &mut perf_fds,
            &mut perf_links,
        );
    }

    let ring_metrics = metrics.clone();
    let callback_stack_map = stack_map.clone();
    let mut ring_builder = RingBufferBuilder::new();
    ring_builder.add(&skel.maps.events, move |bytes| {
        ring_metrics.ring_events.fetch_add(1, Ordering::Relaxed);
        let Some(raw) = KernelEvent::from_ring_bytes(bytes) else {
            ring_metrics
                .malformed_ring_events
                .fetch_add(1, Ordering::Relaxed);
            return 0;
        };
        let user_stack_addresses = if raw.operation == OP_CPU_SAMPLE {
            read_stack(&callback_stack_map, i32::try_from(raw.result).unwrap_or(-1))
        } else {
            Vec::new()
        };
        let kernel_stack_addresses = if raw.operation == OP_CPU_SAMPLE {
            read_stack(&callback_stack_map, raw.fd)
        } else {
            Vec::new()
        };
        match sender.try_send(CapturedKernelEvent {
            raw,
            user_stack_addresses,
            kernel_stack_addresses,
        }) {
            Ok(()) => 0,
            Err(mpsc::error::TrySendError::Full(_)) => {
                ring_metrics
                    .userspace_dropped_events
                    .fetch_add(1, Ordering::Relaxed);
                0
            }
            Err(mpsc::error::TrySendError::Closed(_)) => -1,
        }
    })?;
    let ring = ring_builder.build()?;

    let mut uprobes: HashMap<i32, UprobeSet> = HashMap::new();
    scan_and_attach_uprobes(&config, &target_map, &skel.progs, &mut uprobes, &metrics)?;
    metrics.bpf_ready.store(true, Ordering::Release);
    if let Some(sender) = startup.take() {
        let _ = sender.send(Ok(()));
    }

    let mut last_scan = Instant::now();
    while !stopping.load(Ordering::Acquire) {
        ring.poll(Duration::from_millis(250))?;
        if last_scan.elapsed() >= config.rescan_interval {
            scan_and_attach_uprobes(&config, &target_map, &skel.progs, &mut uprobes, &metrics)?;
            if let Ok(Some(value)) = dropped_map.lookup(&0u32.to_ne_bytes(), MapFlags::ANY) {
                if let Some(bytes) = value.get(..8) {
                    metrics.bpf_dropped_events.store(
                        u64::from_ne_bytes(bytes.try_into().unwrap()),
                        Ordering::Relaxed,
                    );
                }
            }
            last_scan = Instant::now();
        }
    }
    metrics.bpf_ready.store(false, Ordering::Release);
    drop((kernel_links, perf_links, perf_fds, uprobes, stack_map));
    Ok(())
}

fn scan_and_attach_uprobes(
    config: &BpfConfig,
    target_map: &MapHandle,
    progs: &bpf::ObserverProgs<'_>,
    attached: &mut HashMap<i32, UprobeSet>,
    metrics: &RuntimeMetrics,
) -> Result<()> {
    let pids = mongodb_pids(&config.host_proc)?;
    let live: HashSet<i32> = pids.iter().copied().collect();
    attached.retain(|pid, _| live.contains(pid));
    for pid in &pids {
        target_map.update(&(*pid as u32).to_ne_bytes(), &[1], MapFlags::ANY)?;
        let set = attached.entry(*pid).or_insert_with(|| UprobeSet {
            ssl_links: Vec::new(),
            lock_links: Vec::new(),
        });
        if !matches!(config.tls_mode, TlsUprobeMode::Off) && set.ssl_links.is_empty() {
            match attach_ssl_uprobes(*pid, &config.host_proc, progs) {
                Ok(links) if !links.is_empty() => set.ssl_links = links,
                Ok(_) => {
                    if matches!(config.tls_mode, TlsUprobeMode::Required) {
                        warn!(
                            pid,
                            "TLS uprobes are required but libssl symbols are not available yet"
                        );
                    }
                }
                Err(error) => warn!(pid, error = ?error, "unable to attach OpenSSL uprobes"),
            }
        }
        if config.lock_profiling && set.lock_links.is_empty() {
            match attach_lock_uprobes(*pid, &config.host_proc, progs) {
                Ok(links) => set.lock_links = links,
                Err(error) => {
                    warn!(pid, error = ?error, "unable to attach lock-contention uprobes")
                }
            }
        }
    }
    metrics
        .target_processes
        .store(pids.len(), Ordering::Relaxed);
    metrics.tls_uprobe_processes.store(
        attached
            .values()
            .filter(|set| !set.ssl_links.is_empty())
            .count(),
        Ordering::Relaxed,
    );
    if matches!(config.tls_mode, TlsUprobeMode::Required)
        && !pids.is_empty()
        && attached.values().all(|set| set.ssl_links.is_empty())
    {
        anyhow::bail!(
            "TLS uprobes are required, but no mongod/mongos OpenSSL symbols could be attached"
        );
    }
    Ok(())
}

fn attach_ssl_uprobes(
    pid: i32,
    host_proc: &Path,
    progs: &bpf::ObserverProgs<'_>,
) -> Result<Vec<Link>> {
    let candidates = mapped_libraries(host_proc, pid, &["libssl.so"])?;
    let mut links = Vec::new();
    for path in candidates {
        let mut candidate_links = Vec::new();
        for (program, symbol, retprobe) in [
            (&progs.handle_ssl_read_enter, "SSL_read", false),
            (&progs.handle_ssl_read_exit, "SSL_read", true),
            (&progs.handle_ssl_write_enter, "SSL_write", false),
            (&progs.handle_ssl_write_exit, "SSL_write", true),
        ] {
            candidate_links.push(attach_symbol(program, pid, &path, symbol, retprobe)?);
        }
        for (program, symbol, retprobe) in [
            (&progs.handle_ssl_read_ex_enter, "SSL_read_ex", false),
            (&progs.handle_ssl_read_ex_exit, "SSL_read_ex", true),
            (&progs.handle_ssl_write_ex_enter, "SSL_write_ex", false),
            (&progs.handle_ssl_write_ex_exit, "SSL_write_ex", true),
            (&progs.handle_ssl_set_fd, "SSL_set_fd", false),
            (&progs.handle_ssl_free, "SSL_free", false),
        ] {
            if let Ok(link) = attach_symbol(program, pid, &path, symbol, retprobe) {
                candidate_links.push(link);
            }
        }
        links.extend(candidate_links);
    }
    Ok(links)
}

fn attach_lock_uprobes(
    pid: i32,
    host_proc: &Path,
    progs: &bpf::ObserverProgs<'_>,
) -> Result<Vec<Link>> {
    for path in mapped_libraries(host_proc, pid, &["libpthread.so", "libc.so"])? {
        let entry = attach_symbol(
            &progs.handle_mutex_lock_enter,
            pid,
            &path,
            "pthread_mutex_lock",
            false,
        );
        let exit = attach_symbol(
            &progs.handle_mutex_lock_exit,
            pid,
            &path,
            "pthread_mutex_lock",
            true,
        );
        if let (Ok(entry), Ok(exit)) = (entry, exit) {
            return Ok(vec![entry, exit]);
        }
    }
    Ok(Vec::new())
}

fn attach_symbol(
    program: &ProgramMut<'_>,
    pid: i32,
    path: &Path,
    symbol: &str,
    retprobe: bool,
) -> libbpf_rs::Result<Link> {
    program.attach_uprobe_with_opts(
        pid,
        path,
        0,
        UprobeOpts {
            retprobe,
            func_name: Some(symbol.to_string()),
            ..Default::default()
        },
    )
}

fn mongodb_pids(host_proc: &Path) -> Result<Vec<i32>> {
    let mut result = Vec::new();
    for entry in fs::read_dir(host_proc)
        .with_context(|| format!("reading host procfs at {}", host_proc.display()))?
    {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
        else {
            continue;
        };
        let comm = fs::read_to_string(entry.path().join("comm")).unwrap_or_default();
        if matches!(comm.trim(), "mongod" | "mongos") {
            result.push(pid);
        }
    }
    result.sort_unstable();
    Ok(result)
}

fn mapped_libraries(host_proc: &Path, pid: i32, needles: &[&str]) -> Result<Vec<PathBuf>> {
    let maps_path = host_proc.join(pid.to_string()).join("maps");
    let maps = fs::read_to_string(&maps_path)
        .with_context(|| format!("reading {}", maps_path.display()))?;
    let mut result = HashSet::new();
    for line in maps.lines() {
        let Some(mapped) = line.split_whitespace().last() else {
            continue;
        };
        if !mapped.starts_with('/') || !needles.iter().any(|needle| mapped.contains(needle)) {
            continue;
        }
        let mapped = mapped.trim_end_matches(" (deleted)");
        result.insert(
            host_proc
                .join(pid.to_string())
                .join("root")
                .join(mapped.trim_start_matches('/')),
        );
    }
    let mut result: Vec<_> = result.into_iter().collect();
    result.sort();
    Ok(result)
}

fn attach_cpu_sampling(
    program: &ProgramMut<'_>,
    frequency_hz: u32,
    fds: &mut Vec<OwnedFd>,
    links: &mut Vec<Link>,
) {
    let cpus = match libbpf_rs::num_possible_cpus() {
        Ok(cpus) => cpus,
        Err(error) => {
            warn!(error = ?error, "CPU profiling disabled: cannot enumerate CPUs");
            return;
        }
    };
    for cpu in 0..cpus {
        let mut attr = libbpf_sys::perf_event_attr::default();
        attr.type_ = libbpf_sys::PERF_TYPE_SOFTWARE;
        attr.size = size_of::<libbpf_sys::perf_event_attr>() as u32;
        attr.config = libbpf_sys::PERF_COUNT_SW_CPU_CLOCK as u64;
        attr.__bindgen_anon_1.sample_freq = frequency_hz as u64;
        attr.set_freq(1);
        attr.set_exclude_hv(1);
        let fd = unsafe {
            libc::syscall(
                libc::SYS_perf_event_open,
                &attr as *const _,
                -1i32,
                cpu as i32,
                -1i32,
                libbpf_sys::PERF_FLAG_FD_CLOEXEC,
            ) as i32
        };
        if fd < 0 {
            warn!(cpu, error = ?std::io::Error::last_os_error(), "cannot open CPU sampling event");
            continue;
        }
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        match program.attach_perf_event(fd) {
            Ok(link) => {
                fds.push(owned);
                links.push(link);
            }
            Err(error) => warn!(cpu, error = ?error, "cannot attach CPU sampling program"),
        }
    }
}

fn read_stack(map: &MapHandle, stack_id: i32) -> Vec<u64> {
    if stack_id < 0 {
        return Vec::new();
    }
    map.lookup(&stack_id.to_ne_bytes(), MapFlags::ANY)
        .ok()
        .flatten()
        .map(|bytes| {
            bytes
                .chunks_exact(8)
                .map(|chunk| u64::from_ne_bytes(chunk.try_into().unwrap()))
                .take_while(|address| *address != 0)
                .collect()
        })
        .unwrap_or_default()
}

fn raise_memlock_limit() {
    let limit = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) } != 0 {
        warn!(error = ?std::io::Error::last_os_error(), "could not raise memlock limit");
    }
}

async fn run_batcher(
    mut receiver: mpsc::Receiver<DamEvent>,
    spool: DurableSpool,
    assignment: Assignment,
    max_events: usize,
    flush_interval: Duration,
    notify: Arc<Notify>,
    metrics: Arc<RuntimeMetrics>,
) {
    let mut events = Vec::with_capacity(max_events);
    let mut ticker = tokio::time::interval(flush_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_health = Instant::now();
    loop {
        let mut timer_fired = false;
        tokio::select! {
            event = receiver.recv() => {
                match event {
                    Some(event) => events.push(event),
                    None => break,
                }
            }
            _ = ticker.tick() => {
                timer_fired = true;
                if last_health.elapsed() >= Duration::from_secs(60) {
                    events.push(sensor_health_event(&assignment, &spool, &metrics));
                    last_health = Instant::now();
                }
            }
        }
        if events.len() >= max_events || (timer_fired && !events.is_empty()) {
            flush_batch(&spool, &assignment, &mut events, &notify, &metrics);
        }
    }
    flush_batch(&spool, &assignment, &mut events, &notify, &metrics);
}

fn flush_batch(
    spool: &DurableSpool,
    assignment: &Assignment,
    events: &mut Vec<DamEvent>,
    notify: &Notify,
    metrics: &RuntimeMetrics,
) {
    if events.is_empty() {
        return;
    }
    let created_at = OffsetDateTime::now_utc();
    let mut digest = Sha256::new();
    digest.update(assignment.sensor_id.as_bytes());
    digest.update(created_at.unix_timestamp_nanos().to_le_bytes());
    for event in events.iter() {
        digest.update(event.event_id.as_bytes());
    }
    let batch_id = format!("batch-{}", hex::encode(&digest.finalize()[..16]));
    let batch = DamBatch {
        schema_version: BATCH_SCHEMA_VERSION,
        batch_id,
        customer_id: assignment.customer_id.clone(),
        tenant_id: assignment.tenant_id.clone(),
        source_id: assignment.source_id.clone(),
        regional_cell_id: assignment.regional_cell_id.clone(),
        created_at,
        events: std::mem::take(events),
    };
    let event_count = batch.events.len() as u64;
    match serde_json::to_vec(&batch)
        .context("serializing Observer batch")
        .and_then(|body| spool.enqueue(&body).map(|_| ()).map_err(Into::into))
    {
        Ok(()) => {
            metrics.batches_spooled.fetch_add(1, Ordering::Relaxed);
            notify.notify_one();
        }
        Err(error) => {
            metrics
                .spool_dropped_events
                .fetch_add(event_count, Ordering::Relaxed);
            error!(error = ?error, batch_id = %batch.batch_id, "metadata batch could not be spooled")
        }
    }
}

fn sensor_health_event(
    assignment: &Assignment,
    spool: &DurableSpool,
    metrics: &RuntimeMetrics,
) -> DamEvent {
    let now = OffsetDateTime::now_utc();
    let spool_bytes = spool.stats().map(|stats| stats.bytes).unwrap_or_default();
    let mut digest = Sha256::new();
    digest.update(assignment.sensor_id.as_bytes());
    digest.update(now.unix_timestamp_nanos().to_le_bytes());
    DamEvent {
        schema_version: EVENT_SCHEMA_VERSION,
        event_id: format!("health-{}", hex::encode(&digest.finalize()[..16])),
        observed_at: now,
        monotonic_timestamp_ns: 0,
        customer_id: assignment.customer_id.clone(),
        tenant_id: assignment.tenant_id.clone(),
        source_id: assignment.source_id.clone(),
        regional_cell_id: assignment.regional_cell_id.clone(),
        capture: CaptureMetadata {
            sensor_id: assignment.sensor_id.clone(),
            node_name: assignment.node_name.clone(),
            source: CaptureSource::Sensor,
            confidence: CaptureConfidence::Complete,
            metadata_only: true,
            truncated: false,
        },
        kubernetes: None,
        process: None,
        payload: EventPayload::SensorHealth(SensorHealth {
            status: if metrics.bpf_ready.load(Ordering::Acquire) {
                "ok".into()
            } else {
                "degraded".into()
            },
            component: "observer".into(),
            reason: "periodic sensor status".into(),
            dropped_events: metrics
                .bpf_dropped_events
                .load(Ordering::Relaxed)
                .saturating_add(metrics.userspace_dropped_events.load(Ordering::Relaxed))
                .saturating_add(metrics.spool_dropped_events.load(Ordering::Relaxed)),
            parse_errors: metrics.parse_errors.load(Ordering::Relaxed),
            spool_bytes,
        }),
    }
}

async fn run_exporter(
    spool: DurableSpool,
    outpost_url: String,
    internal_token: Option<String>,
    retry_interval: Duration,
    notify: Arc<Notify>,
    metrics: Arc<RuntimeMetrics>,
    mut shutdown: watch::Receiver<bool>,
) {
    let client = match reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(20))
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            error!(error = ?error, "cannot build Observer-to-Outpost client");
            return;
        }
    };
    loop {
        if let Err(error) = deliver_observer_spool(
            &client,
            &spool,
            &outpost_url,
            internal_token.as_deref(),
            &metrics,
        )
        .await
        {
            metrics.delivery_failures.fetch_add(1, Ordering::Relaxed);
            warn!(error = ?error, "Observer-to-Outpost delivery pass failed");
        }
        tokio::select! {
            _ = notify.notified() => {}
            _ = tokio::time::sleep(retry_interval) => {}
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    let _ = deliver_observer_spool(
                        &client, &spool, &outpost_url, internal_token.as_deref(), &metrics,
                    ).await;
                    return;
                }
            }
        }
    }
}

async fn deliver_observer_spool(
    client: &reqwest::Client,
    spool: &DurableSpool,
    outpost_url: &str,
    internal_token: Option<&str>,
    metrics: &RuntimeMetrics,
) -> Result<()> {
    for item in spool.pending()? {
        let body = spool.read(&item)?;
        let batch: DamBatch = serde_json::from_slice(&body)
            .with_context(|| format!("invalid local batch {}", item.id))?;
        let mut request = client
            .post(outpost_url)
            .header("content-type", "application/json")
            .header("idempotency-key", &batch.batch_id)
            .body(body);
        if let Some(token) = internal_token {
            request = request.bearer_auth(token);
        }
        let response = request
            .send()
            .await
            .with_context(|| format!("sending batch {} to Outpost", batch.batch_id))?;
        let status = response.status();
        if status.is_success() || status == reqwest::StatusCode::CONFLICT {
            spool.acknowledge(&item)?;
            metrics.batches_delivered.fetch_add(1, Ordering::Relaxed);
        } else if status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            anyhow::bail!("Outpost returned retryable HTTP {status}");
        } else {
            spool.quarantine(&item)?;
            metrics.quarantined_batches.fetch_add(1, Ordering::Relaxed);
            warn!(batch_id = %batch.batch_id, %status, "Outpost rejected batch; retaining it for review");
        }
    }
    Ok(())
}

async fn health(State(state): State<HealthState>) -> Response {
    let ready = state.metrics.bpf_ready.load(Ordering::Acquire);
    match (state.spool.stats(), state.spool.quarantine_stats()) {
        (Ok(stats), Ok(quarantine)) => (
            if ready {
                StatusCode::OK
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            },
            Json(HealthResponse {
                service: "mongodb-dam-observer",
                status: if ready { "ok" } else { "starting" },
                node_name: state.node_name.as_ref().clone(),
                target_processes: state.metrics.target_processes.load(Ordering::Relaxed),
                tls_uprobe_processes: state.metrics.tls_uprobe_processes.load(Ordering::Relaxed),
                spool_items: stats.items,
                spool_bytes: stats.bytes,
                quarantine_items: quarantine.items,
                quarantine_bytes: quarantine.bytes,
            }),
        )
            .into_response(),
        (Err(error), _) | (_, Err(error)) => {
            (StatusCode::SERVICE_UNAVAILABLE, error.to_string()).into_response()
        }
    }
}

async fn prometheus_metrics(State(state): State<HealthState>) -> Response {
    let spool = state.spool.stats().unwrap_or_default();
    let quarantine = state.spool.quarantine_stats().unwrap_or_default();
    let metrics = &state.metrics;
    let body = format!(
        concat!(
            "# TYPE mongodb_dam_observer_ready gauge\n",
            "mongodb_dam_observer_ready {}\n",
            "# TYPE mongodb_dam_observer_ring_events_total counter\n",
            "mongodb_dam_observer_ring_events_total {}\n",
            "mongodb_dam_observer_malformed_ring_events_total {}\n",
            "mongodb_dam_observer_userspace_dropped_events_total {}\n",
            "mongodb_dam_observer_parse_errors_total {}\n",
            "mongodb_dam_observer_metadata_events_total {}\n",
            "mongodb_dam_observer_batches_spooled_total {}\n",
            "mongodb_dam_observer_spool_dropped_events_total {}\n",
            "mongodb_dam_observer_batches_delivered_total {}\n",
            "mongodb_dam_observer_delivery_failures_total {}\n",
            "mongodb_dam_observer_quarantined_batches_total {}\n",
            "mongodb_dam_observer_bpf_dropped_events_total {}\n",
            "mongodb_dam_observer_target_processes {}\n",
            "mongodb_dam_observer_tls_uprobe_processes {}\n",
            "mongodb_dam_observer_spool_items {}\n",
            "mongodb_dam_observer_spool_bytes {}\n",
            "mongodb_dam_observer_quarantine_items {}\n",
            "mongodb_dam_observer_quarantine_bytes {}\n"
        ),
        u8::from(metrics.bpf_ready.load(Ordering::Acquire)),
        metrics.ring_events.load(Ordering::Relaxed),
        metrics.malformed_ring_events.load(Ordering::Relaxed),
        metrics.userspace_dropped_events.load(Ordering::Relaxed),
        metrics.parse_errors.load(Ordering::Relaxed),
        metrics.metadata_events.load(Ordering::Relaxed),
        metrics.batches_spooled.load(Ordering::Relaxed),
        metrics.spool_dropped_events.load(Ordering::Relaxed),
        metrics.batches_delivered.load(Ordering::Relaxed),
        metrics.delivery_failures.load(Ordering::Relaxed),
        metrics.quarantined_batches.load(Ordering::Relaxed),
        metrics.bpf_dropped_events.load(Ordering::Relaxed),
        metrics.target_processes.load(Ordering::Relaxed),
        metrics.tls_uprobe_processes.load(Ordering::Relaxed),
        spool.items,
        spool.bytes,
        quarantine.items,
        quarantine.bytes,
    );
    ([("content-type", "text/plain; version=0.0.4")], body).into_response()
}

fn read_secret(path: &Path) -> Result<String> {
    let value = fs::read_to_string(path)
        .with_context(|| format!("reading secret {}", path.display()))?
        .trim()
        .to_string();
    anyhow::ensure!(!value.is_empty(), "secret {} is empty", path.display());
    Ok(value)
}
