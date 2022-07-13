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
    use lair_keystore_api::prelude::*;
    use std::sync::Arc;

    fn init_tracing() {
        let subscriber = tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(
                tracing_subscriber::filter::EnvFilter::from_default_env(),
            )
            .with_file(true)
            .with_line_number(true)
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sanity() {
        init_tracing();

        let (cert, key) = tls::gen_tls_cert_pair().unwrap();
        let tls = tls::TlsConfigBuilder::default()
            .with_cert(cert, key)
            .build()
            .unwrap();
        let _srv = srv::Srv::builder()
            .with_tls(tls)
            .with_bind("127.0.0.1:0".parse().unwrap(), "127.0.0.1".into(), 0)
            .with_bind("[::1]:0".parse().unwrap(), "[::1]".into(), 0)
            .build()
            .await
            .unwrap();

        let passphrase = sodoken::BufRead::new_no_lock(b"test-passphrase");
        let keystore_config = PwHashLimits::Minimum
            .with_exec(|| LairServerConfigInner::new("/", passphrase.clone()))
            .await
            .unwrap();

        let keystore = PwHashLimits::Minimum
            .with_exec(|| {
                lair_keystore_api::in_proc_keystore::InProcKeystore::new(
                    Arc::new(keystore_config),
                    lair_keystore_api::mem_store::create_mem_store_factory(),
                    passphrase,
                )
            })
            .await
            .unwrap();

        let lair_client = keystore.new_client().await.unwrap();
        let tag: Arc<str> =
            rand_utf8::rand_utf8(&mut rand::thread_rng(), 32).into();

        lair_client
            .new_seed(tag.clone(), None, false)
            .await
            .unwrap();

        let _cli = cli::Cli::builder()
            .with_lair_client(lair_client)
            .with_lair_tag(tag)
            .build()
            .await
            .unwrap();
    }
}
