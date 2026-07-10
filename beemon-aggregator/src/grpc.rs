use anyhow::{Context, Result};
use tonic::transport::{Channel, Endpoint};

use crate::pb::beemon_service_client::BeemonServiceClient;

pub async fn connect(endpoint: &str) -> Result<BeemonServiceClient<Channel>> {
    let uri = format!("http://{}", endpoint);
    let channel = Endpoint::from_shared(uri)
        .context("invalid gRPC endpoint")?
        .initial_stream_window_size(64 * 1024 * 1024)
        .initial_connection_window_size(64 * 1024 * 1024)
        .connect()
        .await
        .context("gRPC connect")?;
    Ok(BeemonServiceClient::new(channel)
        .max_decoding_message_size(4 * 1024 * 1024)
        .max_encoding_message_size(4 * 1024 * 1024))
}
