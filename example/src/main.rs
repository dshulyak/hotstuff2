#![allow(unused)]

use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::Result;
use clap::Parser;
use hotstuff2::types::{PrivateKey, PublicKey};
use tokio::signal::ctrl_c;

mod codec;
mod context;
mod history;
mod net;
mod node;
mod protocol;

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

    #[clap(long, short = 'c', help = "list of peers to connect with")]
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
}

fn try_from_hex(s: &str) -> Result<PublicKey> {
    Ok(PublicKey::from_bytes(&hex::decode(s)?)?)
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
    if let Err(err) = opt.ensure_data_dir() {
        tracing::error!(error = %err, "failed to create data directory");
        std::process::exit(1);
    }
    let privates = match opt.privates() {
        Ok(privates) => privates,
        Err(err) => {
            tracing::error!(error = %err, "failed to load private keys");
            std::process::exit(1);
        }
    };
    let mut participants = opt.participants.clone();
    participants.sort();
    let mut node = match node::Node::init(
        opt.directory.as_path(),
        opt.listen,
        "example",
        participants.into_boxed_slice(),
        privates.into_boxed_slice(),
        opt.connect,
    ) {
        Ok(node) => node,
        Err(err) => {
            tracing::error!(error = %err, "failed to initialize node");
            std::process::exit(1);
        }
    };
    let ctx = context::Context::new();
    let ctrc_ctx = ctx.clone();
    ctrlc::set_handler(move || {
        tracing::info!("received interrupt signal");
        ctrc_ctx.cancel();
    });
    // pass error up the stack
    node.run(ctx);
    tracing::info!("node exited");
}

#[tokio::main]
async fn run(opts: Opt) -> Result<()> {
    Ok(())
}
