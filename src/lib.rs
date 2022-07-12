#![deny(missing_docs)]
#![deny(warnings)]
#![deny(unsafe_code)]

//! yo

use std::io::Result;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

/// Tx3 helper until `std::io::Error::other()` is stablized
pub fn other_err<E: Into<Box<dyn std::error::Error + Send + Sync>>>(
    error: E,
) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, error)
}

pub(crate) static WS_CONFIG: WebSocketConfig = WebSocketConfig {
    max_send_queue: Some(32),
    max_message_size: Some(1024),
    max_frame_size: Some(1024),
    accept_unmasked_frames: false,
};

pub(crate) fn tcp_configure(
    socket: tokio::net::TcpStream,
) -> Result<tokio::net::TcpStream> {
    let socket = socket.into_std()?;
    let socket = socket2::Socket::from(socket);

    let keepalive = socket2::TcpKeepalive::new()
        .with_time(std::time::Duration::from_secs(7))
        .with_interval(std::time::Duration::from_secs(7));

    // we'll close unresponsive connections after 21-28 seconds (7 * 3)
    // (it's a little unclear how long it'll wait after the final probe)
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    let keepalive = keepalive.with_retries(3);

    socket.set_tcp_keepalive(&keepalive)?;

    let socket = std::net::TcpStream::from(socket);
    tokio::net::TcpStream::from_std(socket)
}

pub mod cli;
pub mod srv;
pub mod tls;
pub mod util;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn sanity() {
        let (cert, key) = tls::gen_tls_cert_pair().unwrap();
        let tls = tls::TlsConfigBuilder::default()
            .with_cert(cert, key)
            .build()
            .unwrap();
        let _srv = srv::Srv::builder()
            .with_tls(tls)
            .with_bind("127.0.0.1:0".parse().unwrap(), None, None)
            .with_bind("[::1]:0".parse().unwrap(), None, None)
            .build()
            .await
            .unwrap();
    }
}
