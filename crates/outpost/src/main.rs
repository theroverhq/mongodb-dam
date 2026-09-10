use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use outpost::{
    build_state, read_secret, router, spawn_background_tasks, DestinationConfig,
    HttpDestinationConfig, OutpostConfig, S3DestinationConfig,
};
use std::{net::SocketAddr, path::PathBuf, time::Duration};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(author, version, about = "MongoDB DAM customer-cluster Outpost")]
struct Cli {
    #[arg(long, env = "OUTPOST_LISTEN_ADDR", default_value = "0.0.0.0:8090")]
    listen_addr: SocketAddr,
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
    #[arg(long, env = "OUTPOST_INTERNAL_TOKEN_FILE")]
    internal_token_file: Option<PathBuf>,
    #[arg(long, env = "OUTPOST_DESTINATION")]
    destination: Option<DestinationKind>,
    #[arg(long, env = "OUTPOST_ENDPOINT")]
    endpoint: Option<String>,
    #[arg(long, env = "OUTPOST_BEARER_TOKEN_FILE")]
    bearer_token_file: Option<PathBuf>,
    #[arg(long, env = "OUTPOST_CA_FILE")]
    ca_file: Option<PathBuf>,
    #[arg(long, env = "OUTPOST_S3_BUCKET")]
    s3_bucket: Option<String>,
    #[arg(long, env = "OUTPOST_S3_PREFIX")]
    s3_prefix: Option<String>,
    #[arg(long, env = "OUTPOST_S3_ENDPOINT_URL")]
    s3_endpoint_url: Option<String>,
    #[arg(long, env = "OUTPOST_S3_FORCE_PATH_STYLE", default_value_t = false)]
    s3_force_path_style: bool,
    #[arg(
        long,
        env = "OUTPOST_SPOOL_DIR",
        default_value = "/var/lib/mongodb-dam/outpost"
    )]
    spool_dir: PathBuf,
    #[arg(long, env = "OUTPOST_SPOOL_MAX_BYTES", default_value_t = 1_073_741_824)]
    spool_max_bytes: u64,
    #[arg(long, env = "OUTPOST_MAX_REQUEST_BYTES", default_value_t = 5_242_880)]
    max_request_bytes: usize,
    #[arg(long, env = "OUTPOST_EXPORT_INTERVAL_SECONDS", default_value_t = 5)]
    export_interval_seconds: u64,
    #[arg(long, env = "KUBERNETES_SERVICE_HOST")]
    kubernetes_service_host: Option<String>,
    #[arg(long, env = "KUBERNETES_SERVICE_PORT_HTTPS", default_value = "443")]
    kubernetes_service_port: String,
    #[arg(
        long,
        default_value = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    )]
    kubernetes_token_path: PathBuf,
    #[arg(
        long,
        default_value = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    )]
    kubernetes_ca_path: PathBuf,
    #[arg(long, env = "OUTPOST_KUBERNETES_REFRESH_SECONDS", default_value_t = 30)]
    kubernetes_refresh_seconds: u64,
    #[arg(long, env = "OUTPOST_IDENTITY_MAPPING_FILE")]
    identity_mapping_file: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum DestinationKind {
    Http,
    S3,
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
    let destination_kind = cli.destination.unwrap_or_else(|| {
        if cli.s3_bucket.is_some() || cli.s3_prefix.is_some() {
            DestinationKind::S3
        } else {
            DestinationKind::Http
        }
    });
    let destination = match destination_kind {
        DestinationKind::Http => {
            let endpoint = cli
                .endpoint
                .context("OUTPOST_ENDPOINT is required for the HTTP destination")?;
            let token_file = cli
                .bearer_token_file
                .as_deref()
                .context("OUTPOST_BEARER_TOKEN_FILE is required for the HTTP destination")?;
            DestinationConfig::Http(HttpDestinationConfig {
                endpoint,
                bearer_token: read_secret(token_file)?,
                ca_file: cli.ca_file,
            })
        }
        DestinationKind::S3 => DestinationConfig::S3(S3DestinationConfig {
            bucket: cli
                .s3_bucket
                .context("OUTPOST_S3_BUCKET is required for the S3 destination")?,
            prefix: cli
                .s3_prefix
                .context("OUTPOST_S3_PREFIX is required for the S3 destination")?,
            endpoint_url: cli.s3_endpoint_url,
            force_path_style: cli.s3_force_path_style,
        }),
    };
    let internal_token = cli
        .internal_token_file
        .as_deref()
        .map(read_secret)
        .transpose()?;
    let kubernetes_api_url = cli
        .kubernetes_service_host
        .map(|host| format!("https://{host}:{}", cli.kubernetes_service_port));
    let state = build_state(OutpostConfig {
        customer_id: cli.customer_id,
        tenant_id: cli.tenant_id,
        source_id: cli.source_id,
        regional_cell_id: cli.regional_cell_id,
        cluster_name: cli.cluster_name,
        internal_token,
        destination,
        spool_dir: cli.spool_dir,
        spool_max_bytes: cli.spool_max_bytes,
        max_request_bytes: cli.max_request_bytes,
        export_interval: Duration::from_secs(cli.export_interval_seconds.max(1)),
        kubernetes_api_url,
        kubernetes_token_path: cli.kubernetes_token_path,
        kubernetes_ca_path: cli.kubernetes_ca_path,
        kubernetes_refresh_interval: Duration::from_secs(cli.kubernetes_refresh_seconds.max(5)),
        identity_mapping_file: cli.identity_mapping_file,
    })?;
    spawn_background_tasks(state.clone());
    let listener = TcpListener::bind(cli.listen_addr)
        .await
        .with_context(|| format!("binding Outpost to {}", cli.listen_addr))?;
    info!(address = %cli.listen_addr, "MongoDB DAM Outpost listening");
    axum::serve(listener, router(state)).await?;
    Ok(())
}
