use std::convert::Infallible;

use axum::extract::{Path, Query, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use futures_util::StreamExt;
use tonic::Request;
use tower_http::cors::CorsLayer;

mod config;
mod grpc;
mod pb;
mod ws;

use config::Config;
use pb::beemon_service_client::BeemonServiceClient;
use tonic::transport::Channel;

#[derive(Clone)]
struct AppState {
    grpc: BeemonServiceClient<Channel>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cfg = Config::from_env();
    let client = grpc::connect(&cfg.grpc_endpoint).await?;
    let state = AppState { grpc: client };

    let app = Router::new()
        .route("/api/v1/processes", get(list_processes))
        .route("/api/v1/processes/{pid}/metadata", get(get_process_metadata))
        .route("/api/v1/processes/{pid}/events", get(stream_events))
        .route("/api/v1/processes/{pid}/network_flows", get(get_network_flows))
        .route("/api/v1/processes/{pid}/stream/ws", get(ws::ws_events))
        .route("/api/v1/namespaces/{ns_type}/{ns_inode}", get(get_namespace_details))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = format!("0.0.0.0:{}", cfg.http_port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(addr = %addr, "BFF listening");
    axum::serve(listener, app).await?;
    Ok(())
}

#[derive(serde::Deserialize)]
struct FilterQuery {
    filter_name: Option<String>,
}

async fn list_processes(
    State(mut state): State<AppState>,
    Query(q): Query<FilterQuery>,
) -> impl IntoResponse {
    let req = Request::new(pb::ListProcessesRequest {
        filter_name: q.filter_name.unwrap_or_default(),
    });
    match state.grpc.list_processes(req).await {
        Ok(r) => Json(r.into_inner()).into_response(),
        Err(e) => grpc_err(e),
    }
}

async fn get_process_metadata(
    State(mut state): State<AppState>,
    Path(pid): Path<u32>,
) -> impl IntoResponse {
    let req = Request::new(pb::GetProcessMetadataRequest { pid });
    match state.grpc.get_process_metadata(req).await {
        Ok(r) => Json(r.into_inner()).into_response(),
        Err(e) => grpc_err(e),
    }
}

async fn get_network_flows(
    State(mut state): State<AppState>,
    Path(pid): Path<u32>,
) -> impl IntoResponse {
    let req = Request::new(pb::GetNetworkFlowsRequest { pid });
    match state.grpc.get_network_flows(req).await {
        Ok(r) => Json(r.into_inner()).into_response(),
        Err(e) => grpc_err(e),
    }
}

async fn get_namespace_details(
    State(mut state): State<AppState>,
    Path((ns_type, ns_inode)): Path<(String, String)>,
) -> impl IntoResponse {
    let req = Request::new(pb::GetNamespaceDetailsRequest {
        ns_type,
        ns_inode,
        reference_pid: 0,
    });
    match state.grpc.get_namespace_details(req).await {
        Ok(r) => Json(r.into_inner()).into_response(),
        Err(e) => grpc_err(e),
    }
}

async fn stream_events(
    State(mut state): State<AppState>,
    Path(pid): Path<u32>,
) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    let req = Request::new(pb::StreamEventsRequest { pid });
    let resp = state.grpc.stream_events(req).await.unwrap();
    let inner = resp.into_inner();

    let stream = inner.filter_map(|result| async move {
        match result {
            Ok(batch) => {
                let json = serde_json::to_string(&batch).unwrap_or_default();
                Some(Ok::<_, Infallible>(Event::default().data(json)))
            }
            Err(_) => None,
        }
    });

    Sse::new(stream).keep_alive(KeepAlive::default())
}

fn grpc_err(e: tonic::Status) -> axum::response::Response {
    (
        axum::http::StatusCode::from_u16(e.code() as u16)
            .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR),
        e.message().to_string(),
    )
        .into_response()
}
