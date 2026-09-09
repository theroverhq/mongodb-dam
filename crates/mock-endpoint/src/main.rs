use anyhow::{Context, Result};
use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use dam_schema::DamBatch;
use serde::Serialize;
use std::{collections::HashSet, net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::{fs, net::TcpListener, sync::Mutex};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Local mock for the regional HTTP-push endpoint"
)]
struct Cli {
    #[arg(
        long,
        env = "MOCK_ENDPOINT_LISTEN_ADDR",
        default_value = "0.0.0.0:8088"
    )]
    listen_addr: SocketAddr,
    #[arg(
        long,
        env = "MOCK_ENDPOINT_BEARER_TOKEN",
        default_value = "local-development-token"
    )]
    token: String,
    #[arg(long, env = "MOCK_ENDPOINT_OUTPUT_DIR")]
    output_dir: Option<PathBuf>,
}

#[derive(Clone)]
struct AppState {
    token: Arc<String>,
    seen: Arc<Mutex<HashSet<String>>>,
    output_dir: Option<PathBuf>,
}

#[derive(Serialize)]
struct Receipt {
    status: &'static str,
    receipt_id: String,
    ingest_batch_id: String,
}

#[derive(Serialize)]
struct Health {
    service: &'static str,
    status: &'static str,
    received_batches: usize,
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
    if let Some(directory) = &cli.output_dir {
        fs::create_dir_all(directory).await?;
    }
    let state = AppState {
        token: Arc::new(cli.token),
        seen: Arc::new(Mutex::new(HashSet::new())),
        output_dir: cli.output_dir,
    };
    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/ingest/mongodb-dam", post(ingest))
        .with_state(state);
    let listener = TcpListener::bind(cli.listen_addr)
        .await
        .with_context(|| format!("binding mock endpoint to {}", cli.listen_addr))?;
    info!(address = %cli.listen_addr, "mock endpoint listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health(State(state): State<AppState>) -> Json<Health> {
    Json(Health {
        service: "mock-endpoint",
        status: "ok",
        received_batches: state.seen.lock().await.len(),
    })
}

async fn ingest(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let token = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok());
    let expected = format!("Bearer {}", state.token);
    if token != Some(expected.as_str()) {
        return (StatusCode::UNAUTHORIZED, "invalid token").into_response();
    }
    let Some(idempotency_key) = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
    else {
        return (StatusCode::BAD_REQUEST, "idempotency-key is required").into_response();
    };
    let batch: DamBatch = match serde_json::from_slice(&body) {
        Ok(batch) => batch,
        Err(error) => return (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    };
    if let Err(error) = batch.validate() {
        return (StatusCode::BAD_REQUEST, error).into_response();
    }
    if idempotency_key != batch.batch_id {
        return (
            StatusCode::BAD_REQUEST,
            "idempotency key must equal batch_id",
        )
            .into_response();
    }
    let mut seen = state.seen.lock().await;
    if !seen.insert(idempotency_key.clone()) {
        return (StatusCode::CONFLICT, "duplicate idempotency key").into_response();
    }
    drop(seen);
    if let Some(directory) = &state.output_dir {
        if let Err(error) =
            fs::write(directory.join(format!("{idempotency_key}.json")), &body).await
        {
            return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
        }
    }
    (
        StatusCode::ACCEPTED,
        Json(Receipt {
            status: "accepted",
            receipt_id: format!("mock-{idempotency_key}"),
            ingest_batch_id: batch.batch_id,
        }),
    )
        .into_response()
}
