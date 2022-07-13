//! Server-side connection types.

use crate::*;
use futures::sink::SinkExt;
use futures::stream::StreamExt;
use lair_keystore_api::prelude::*;
use std::sync::Arc;
use tokio_tungstenite::tungstenite::Message;

type Socket = tokio_tungstenite::WebSocketStream<
    tokio_rustls::TlsStream<tokio::net::TcpStream>,
>;

/// Builder for constructing a Cli instance.
pub struct CliBuilder {
    tls: tls::TlsConfig,
    lair_client: Option<LairClient>,
    lair_tag: Option<Arc<str>>,
}

impl Default for CliBuilder {
    fn default() -> Self {
        let tls = tls::TlsConfigBuilder::default().build().unwrap();
        Self {
            tls,
            lair_client: None,
            lair_tag: None,
        }
    }
}

impl CliBuilder {
    /// Set the TlsConfig.
    pub fn set_tls(&mut self, tls: tls::TlsConfig) {
        self.tls = tls;
    }

    /// Apply a TlsConfig.
    pub fn with_tls(mut self, tls: tls::TlsConfig) -> Self {
        self.set_tls(tls);
        self
    }

    /// Set the LairClient.
    pub fn set_lair_client(&mut self, lair_client: LairClient) {
        self.lair_client = Some(lair_client);
    }

    /// Apply the LairClient.
    pub fn with_lair_client(mut self, lair_client: LairClient) -> Self {
        self.set_lair_client(lair_client);
        self
    }

    /// Set the Lair tag.
    pub fn set_lair_tag(&mut self, lair_tag: Arc<str>) {
        self.lair_tag = Some(lair_tag);
    }

    /// Apply the Lair tag.
    pub fn with_lair_tag(mut self, lair_tag: Arc<str>) -> Self {
        self.set_lair_tag(lair_tag);
        self
    }

    /// Build the Srv instance.
    pub async fn build(self) -> Result<Cli> {
        Cli::priv_build(self).await
    }
}

/// Server-side connection type.
pub struct Cli {
    remote_id: Arc<tls::TlsId>,
    sink: futures::stream::SplitSink<Socket, Message>,
}

impl Cli {
    /// Get a CliBuilder.
    pub fn builder() -> CliBuilder {
        CliBuilder::default()
    }

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

    // -- private -- //

    async fn priv_build(builder: CliBuilder) -> Result<Self> {
        let CliBuilder {
            tls: _,
            lair_client,
            lair_tag,
        } = builder;

        let lair_client = match lair_client {
            Some(lair_client) => lair_client,
            None => return Err(other_err("LairClientRequired")),
        };

        let lair_tag = match lair_tag {
            Some(lair_tag) => lair_tag,
            None => return Err(other_err("LairTagRequired")),
        };

        let x25519_pub = match lair_client.get_entry(lair_tag).await {
            Ok(LairEntryInfo::Seed { tag: _, seed_info }) => {
                seed_info.x25519_pub_key
            }
            _ => return Err(other_err("lair_tag invalid seed")),
        };

        tracing::trace!(?x25519_pub);

        todo!()
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
