use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::Result;
use clap::Parser;
use hotstuff2::types::{PrivateKey, PublicKey};
use rcgen;

mod codec;
mod context;
mod history;
mod node;
mod protocol;
mod quinnext;
mod router;

#[derive(Debug, Parser)]
#[clap(name = "example")]
struct Opt {
    #[clap(
        long = "listen",
        short = 'l',
        default_value = "127.0.0.1:9000",
        help = "address for quic server to listen on"
    )]
    listen: SocketAddr,

    #[clap(
        long,
        short = 'd',
        default_value = "",
        help = "directory to store state"
    )]
    directory: PathBuf,

    #[clap(long, short = 'c', help = "list of sockets")]
    connect: Vec<SocketAddr>,

    #[clap(
        long = "participant",
        short = 'p',
        help = "list of public keys for participants",
        value_parser = try_from_hex,
    )]
    participants: Vec<PublicKey>,

    #[clap(long = "key", short = 'k', help = "list of pathes to private keys")]
    keys: Vec<PathBuf>,

    #[clap(long, help = "maximal network delay", default_value = "100ms")]
    delay: humantime::Duration,
}

fn try_from_hex(s: &str) -> Result<PublicKey> {
    let bytes = hex::decode(s)?;
    Ok(PublicKey::from_bytes(&bytes)?)
}

impl Opt {
    fn ensure_data_dir(&self) -> Result<()> {
        if !self.directory.exists() {
            std::fs::create_dir_all(&self.directory)?;
        }
        Ok(())
    }

    fn privates(&self) -> Result<Vec<PrivateKey>> {
        self.keys
            .iter()
            .map(|path| {
                let bytes = std::fs::read(path)?;
                let private = PrivateKey::from_bytes(&bytes)?;
                Ok(private)
            })
            .collect()
    }
}

fn main() {
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .finish(),
    )
    .unwrap();

    let opt = Opt::parse();
    tracing::debug!(opt=?opt, "running with options");
    if let Err(err) = run(opt) {
        tracing::error!(error = %err, "failed");
        std::process::exit(1);
    }
    tracing::info!("exited");
}

#[tokio::main]
async fn run(opts: Opt) -> Result<()> {
    opts.ensure_data_dir()?;
    let (cert, key) = ensure_cert(&opts)?;
    let crypto = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert, key)?;
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let server = quinn::Endpoint::server(server_config, opts.listen)?;
    let local_addr = server.local_addr()?;
    tracing::info!(address = %local_addr, "started listener");
    let _ = opts.privates();
    while let Some(conn) = server.accept().await {
        tokio::spawn(async move {
            if let Ok(conn) = conn.await {
                if let Ok(_) = conn.open_bi().await {}
            }
        });
    }
    Ok(())
}

fn ensure_cert(opts: &Opt) -> Result<(Vec<rustls::Certificate>, rustls::PrivateKey)> {
    let cert_path = opts.directory.join("cert.der");
    let key_path = opts.directory.join("key.der");
    if cert_path.exists() && key_path.exists() {
        let cert = std::fs::read(cert_path)?;
        let key = std::fs::read(key_path)?;
        Ok((vec![rustls::Certificate(cert)], rustls::PrivateKey(key)))
    } else {
        let selfsigned = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let key = selfsigned.serialize_private_key_der();
        let cert = selfsigned.serialize_der()?;
        std::fs::write(&cert_path, &cert)?;
        std::fs::write(&key_path, &key)?;
        Ok((vec![rustls::Certificate(cert)], rustls::PrivateKey(key)))
    }
}
