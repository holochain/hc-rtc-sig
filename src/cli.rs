//! Server-side connection types.

use crate::*;
use futures::sink::SinkExt;
use futures::stream::StreamExt;
use std::sync::Arc;
use tokio_tungstenite::tungstenite::Message;

type Socket = tokio_tungstenite::WebSocketStream<
    tokio_rustls::TlsStream<tokio::net::TcpStream>,
>;

/// Server-side connection type.
pub struct Cli {
    remote_id: Arc<tls::TlsId>,
    sink: futures::stream::SplitSink<Socket, Message>,
}

impl Cli {
    /// Get the TLS certificate digest of the remote end of this connection.
    pub fn remote_id(&self) -> &Arc<tls::TlsId> {
        &self.remote_id
    }

    /// Establish a new outgoing connection to a remote server.
    pub async fn connect(
        tls: tls::TlsConfig,
        addr: std::net::SocketAddr,
    ) -> Result<Self> {
        let socket = tokio::net::TcpStream::connect(addr).await?;
        let socket = tcp_configure(socket)?;
        let name = "stub".try_into().unwrap();
        let socket: tokio_rustls::TlsStream<tokio::net::TcpStream> =
            tokio_rustls::TlsConnector::from(tls.cli.clone())
                .connect(name, socket)
                .await?
                .into();
        let remote_id = hash_cert(&socket)?;
        let (socket, _rsp) = tokio_tungstenite::client_async_with_config(
            "https://stub",
            socket,
            Some(WS_CONFIG),
        )
        .await
        .map_err(other_err)?;
        let (sink, _stream) = socket.split();
        Ok(Self { remote_id, sink })
    }

    /// Send data out to the remote client of this connection.
    pub async fn send(&mut self, data: Vec<u8>) -> Result<()> {
        self.sink
            .send(Message::Binary(data))
            .await
            .map_err(other_err)
    }
}

fn hash_cert(
    socket: &tokio_rustls::TlsStream<tokio::net::TcpStream>,
) -> Result<Arc<tls::TlsId>> {
    let (_, c) = socket.get_ref();
    if let Some(chain) = c.peer_certificates() {
        if !chain.is_empty() {
            use sha2::Digest;
            let mut digest = sha2::Sha256::new();
            digest.update(&chain[0].0);
            let digest = Arc::new(tls::TlsId(digest.finalize().into()));
            return Ok(digest);
        }
    }
    Err(other_err("InvalidPeerCert"))
}
