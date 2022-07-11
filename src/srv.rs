//! Server-side connection types.

use crate::*;
use futures::sink::SinkExt;
use futures::stream::StreamExt;
use tokio_tungstenite::tungstenite::Message;
use parking_lot::Mutex;
use std::sync::Arc;
use std::collections::HashMap;
use std::net::IpAddr;

type Socket = tokio_tungstenite::WebSocketStream<
    tokio_rustls::TlsStream<tokio::net::TcpStream>,
>;

/// Builder for constructing a Srv instance.
pub struct SrvBuilder {
    tls: Option<tls::TlsConfig>,
    bind: Vec<(std::net::SocketAddr, Option<String>, Option<u16>)>,
}

impl Default for SrvBuilder {
    fn default() -> Self {
        Self {
            tls: None,
            bind: Vec::new(),
        }
    }
}

impl SrvBuilder {
    /// Set the TlsConfig.
    pub fn set_tls(&mut self, tls: tls::TlsConfig) {
        self.tls = Some(tls);
    }

    /// Apply a TlsConfig.
    pub fn with_tls(mut self, tls: tls::TlsConfig) -> Self {
        self.set_tls(tls);
        self
    }

    /// Set a bind point.
    pub fn add_bind(
        &mut self,
        iface: std::net::SocketAddr,
        host: Option<String>,
        port: Option<u16>,
    ) {
        self.bind.push((iface, host, port));
    }

    /// Apply a bind point.
    pub fn with_bind(
        mut self,
        iface: std::net::SocketAddr,
        host: Option<String>,
        port: Option<u16>,
    ) -> Self {
        self.add_bind(iface, host, port);
        self
    }

    /// Build the Srv instance.
    pub async fn build(self) -> Result<Srv> {
        Srv::priv_build(self).await
    }
}

/// Server-side connection type.
pub struct Srv {
    srv_term: util::Term,
    addr: url::Url,
}

impl Srv {
    /// Get a SrvBuilder.
    pub fn builder() -> SrvBuilder {
        SrvBuilder::default()
    }

    /// Shutdown this server instance.
    pub fn close(&self) {
        self.srv_term.term();
    }

    /// Get the local addr to which this Srv instance was bound.
    pub fn local_addr(&self) -> &url::Url {
        &self.addr
    }

    // -- private -- //

    async fn priv_build(builder: SrvBuilder) -> Result<Self> {
        let SrvBuilder { tls, bind } = builder;

        let tls = match tls {
            Some(tls) => tls,
            None => return Err(other_err("TlsRequired")),
        };

        let mut bound = Vec::new();
        let srv_term = util::Term::new("srv_term", None);

        let ip_limit = IpLimit::new();

        for (iface, mut host, mut port) in bind {
            let listener = tokio::net::TcpListener::bind(iface).await?;
            let addr = listener.local_addr()?;
            if host.is_none() {
                let ip = addr.ip();
                if ip.is_ipv6() {
                    host = Some(format!("[{}]", addr.ip()));
                } else {
                    host = Some(addr.ip().to_string());
                }
            }
            if port.is_none() {
                port = Some(addr.port());
            }
            bound.push(format!("{}:{}", host.unwrap(), port.unwrap()));

            srv_term.spawn_err(
                listener_task(tls.clone(), srv_term.clone(), listener, ip_limit.clone()),
                |err| {
                    eprintln!("ListenerError: {:?}", err);
                    std::process::abort();
                },
            );
        }

        if bound.is_empty() {
            return Err(other_err("BindingRequired"));
        }

        let id = tls.cert_digest().to_b64();

        let addr = format!("hc-rtc-sig:{}/{}", id, bound.join("/"));
        let addr = url::Url::parse(&addr).map_err(other_err)?;

        println!("addr: {}", addr);

        Ok(Self { addr, srv_term })
    }
}

struct Con {
    con_term: util::Term,
    sink: futures::stream::SplitSink<Socket, Message>,
}

impl Con {
    /// Send data out to the remote client of this connection.
    #[allow(dead_code)]
    pub async fn send(&mut self, data: Vec<u8>) -> Result<()> {
        let on_term_fut = self.con_term.on_term();
        tokio::select! {
            _ = on_term_fut => Err(other_err("ConTerm")),
            r = async {
                match self
                    .sink
                    .send(Message::Binary(data))
                    .await
                    .map_err(other_err)
                {
                    Ok(r) => Ok(r),
                    Err(e) => {
                        self.con_term.term();
                        Err(e)
                    }
                }
            } => r,
        }
    }
}

async fn listener_task(
    tls: tls::TlsConfig,
    srv_term: util::Term,
    listener: tokio::net::TcpListener,
    ip_limit: IpLimit,
) -> Result<()> {
    loop {
        let (socket, addr) = match listener.accept().await {
            Ok(r) => r,
            Err(err) => {
                // TODO: tracing
                eprintln!("AcceptError: {:?}", err);
                continue;
            }
        };
        let con_term = util::Term::new("con_term", None);
        util::Term::spawn_err2(
            &srv_term,
            &con_term,
            con_accept_task(
                tls.clone(),
                srv_term.clone(),
                con_term.clone(),
                socket,
                addr.ip(),
                ip_limit.clone(),
            ),
            |err| {
                // TODO: tracing
                eprintln!("AcceptError: {:?}", err);
            },
        );
    }
}

async fn con_accept_task(
    tls: tls::TlsConfig,
    srv_term: util::Term,
    con_term: util::Term,
    socket: tokio::net::TcpStream,
    ip: std::net::IpAddr,
    ip_limit: IpLimit,
) -> Result<()> {
    let socket = tcp_configure(socket)?;
    let socket: tokio_rustls::TlsStream<tokio::net::TcpStream> =
        tokio_rustls::TlsAcceptor::from(tls.srv.clone())
            .accept(socket)
            .await?
            .into();
    let socket: Socket =
        tokio_tungstenite::accept_async_with_config(socket, Some(WS_CONFIG))
            .await
            .map_err(other_err)?;
    let (sink, stream) = socket.split();
    let _con = Con {
        con_term: con_term.clone(),
        sink,
    };

    let con_term_err = con_term.clone();
    util::Term::spawn_err2(
        &srv_term,
        &con_term,
        con_recv_task(stream, ip, ip_limit),
        move |err| {
            // TODO: tracing
            eprintln!("ConRecvError: {:?}", err);
            con_term_err.term();
        },
    );

    todo!()
}

async fn con_recv_task(
    mut stream: futures::stream::SplitStream<Socket>,
    ip: IpAddr,
    ip_limit: IpLimit,
) -> Result<()> {
    while let Some(msg) = stream.next().await {
        if !ip_limit.check(ip) {
            return Err(other_err("IpLimitReached"));
        }
        let _bin_data: Vec<u8> = match msg.map_err(other_err)? {
            Message::Text(data) => data.into_bytes(),
            Message::Binary(data) => data,
            Message::Ping(data) => data,
            Message::Pong(data) => data,
            Message::Close(close) => {
                return Err(other_err(format!("{:?}", close)))
            }
            Message::Frame(_) => return Err(other_err("RawFrame")),
        };
    }
    Ok(())
}

// 100 msgs in 5 seconds is 20 messages per second
// but ok to burst a bit initially
const IP_LIMIT_WND: std::time::Duration = std::time::Duration::from_secs(5);
const IP_LIMIT_CNT: usize = 100;

#[derive(Clone)]
struct IpLimit(Arc<Mutex<HashMap<IpAddr, Vec<std::time::Instant>>>>);

impl IpLimit {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(HashMap::new())))
    }

    /// Mark an incoming message NOW.
    /// Check the total message count against the window,
    /// if we're still safe under the limit, return TRUE.
    /// Otherwise, return FALSE, we are over limit.
    pub fn check(&self, ip: IpAddr) -> bool {
        let mut map = self.0.lock();
        let hit = map.entry(ip).or_default();
        let now = std::time::Instant::now();
        hit.push(now);
        hit.retain(|t| *t + IP_LIMIT_WND > now);
        hit.len() < IP_LIMIT_CNT
    }
}
