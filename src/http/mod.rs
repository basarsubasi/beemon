pub mod routes;
pub mod ws;

use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::Router;
use rust_embed::Embed;
use tower_http::cors::{Any, CorsLayer};

use crate::rates::RateSnapshot;
use crate::snapshot::cache::SnapshotCache;
use crate::snapshot::namespace_tree_cache::NamespaceTreeCache;
use crate::stream::StreamRegistry;
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;

use crate::bpf::maps::OwnedNetFlows;

#[derive(Clone)]
pub struct AppState {
    pub snapshot: Arc<RwLock<SnapshotCache>>,
    pub rates: Arc<RwLock<RateSnapshot>>,
    pub registry: StreamRegistry,
    pub net_flows: Arc<Mutex<OwnedNetFlows>>,
    pub namespace_tree: Arc<Mutex<NamespaceTreeCache>>,
    pub event_limit: usize,
}

#[derive(Embed)]
#[folder = "webui/dist"]
struct Asset;

pub fn router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/api/v1/processes", axum::routing::get(routes::list_processes))
        .route("/api/v1/processes/{pid}/metadata", axum::routing::get(routes::get_process_metadata))
        .route("/api/v1/processes/{pid}/events", axum::routing::get(routes::stream_events))
        .route("/api/v1/processes/{pid}/network_flows", axum::routing::get(routes::get_network_flows))
        .route("/api/v1/processes/{pid}/stream/ws", axum::routing::get(ws::ws_events))
        .route("/api/v1/namespaces/{ns_type}/{ns_inode}", axum::routing::get(routes::get_namespace_details))
        .fallback(service_fallback)
        .layer(cors)
        .with_state(state)
}

async fn service_fallback(uri: axum::http::Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    if path.is_empty() || path == "index.html" {
        return match Asset::get("index.html") {
            Some(content) => Html(content.data.to_vec()).into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        };
    }
    match Asset::get(path) {
        Some(content) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            (
                [("content-type", mime.as_ref())],
                content.data.to_vec(),
            )
                .into_response()
        }
        None => match Asset::get("index.html") {
            Some(content) => Html(content.data.to_vec()).into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        },
    }
}
