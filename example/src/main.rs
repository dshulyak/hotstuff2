#![allow(dead_code)]

use std::{net::SocketAddr, path::PathBuf};

use anyhow::Result;
use clap::Parser;
use hotstuff2::types::{PrivateKey, PublicKey};
use humantime::Duration;
use rand::{rngs::OsRng, RngCore};

mod codec;
mod context;
mod history;
mod net;
mod node;
mod protocol;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
enum Cli {
    Generate(Generate),
    Run(Run),
}

#[derive(Debug, Parser)]
struct Generate {
    #[clap(
        long,
        short = 'd',
        help = "directory to store keys encoded in hex.
in this directory a file for each key will be created with the name <index>.key.
all public keys will be stored in a file named public_keys."
    )]
    dir: PathBuf,

    #[clap(
        long,
        short = 'n',
        default_value = "4",
        help = "number of keys to generate"
    )]
    count: usize,
}

#[derive(Debug, Parser)]
struct Run {
    #[clap(
        long = "listen",
        short = 'l',
        default_value = "0.0.0.0:9000",
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
        long = "participants",
        short = 'p',
        help = "file with public keys of the partipating nodes. every line is expected to have a key encoded in hexary."
    )]
    participants: PathBuf,

    #[clap(long = "key", short = 'k', help = "list of pathes to private keys")]
    keys: Vec<PathBuf>,

    #[clap(
        long = "network-delay",
        default_value = "200ms",
        help = "expected maximul delay for network messages"
    )]
    network_delay: Duration,
}

impl Run {
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
                let content = std::fs::read_to_string(path)?;
                PrivateKey::from_hex(&content)
            })
            .collect()
    }
}

#[tokio::main]
async fn main() {
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .finish(),
    )
    .unwrap();

    match Cli::parse() {
        Cli::Generate(gen) => generate(gen),
        Cli::Run(opts) => run(opts).await,
    }
}

fn generate(opt: Generate) {
    if !opt.dir.exists() {
        if let Err(err) = std::fs::create_dir_all(&opt.dir) {
            tracing::error!(error = %err, "failed to create directory");
            std::process::exit(1);
        }
    }

    let keys = (0..opt.count)
        .map(|_| {
            let mut seed = [0u8; 32];
            OsRng.fill_bytes(&mut seed);
            PrivateKey::from_seed(&seed)
        })
        .collect::<Vec<_>>();
    let publics = keys.iter().map(|key| key.public()).collect::<Vec<_>>();
    for (index, key) in keys.iter().enumerate() {
        let path = opt.dir.join(format!("{}.key", index));
        std::fs::write(&path, key.to_hex()).unwrap();
        tracing::info!(path = %path.display(), "wrote private key");
    }
    let public_path = opt.dir.join("public_keys");
    std::fs::write(
        &public_path,
        publics
            .iter()
            .map(|key| key.to_hex())
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();
    tracing::info!(path = %public_path.display(), "wrote public keys");
}

async fn run(opt: Run) {
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
    let mut participants = match std::fs::read_to_string(&opt.participants) {
        Ok(participants) => {
            let participants = participants
                .lines()
                .map(|line| PublicKey::from_hex(line))
                .collect::<Result<Vec<_>>>();
            match participants {
                Ok(participants) => participants,
                Err(err) => {
                    tracing::error!(error = %err, "failed to parse participants");
                    std::process::exit(1);
                }
            }
        }
        Err(err) => {
            tracing::error!(error = %err, "failed to load participants");
            std::process::exit(1);
        }
    };
    participants.sort();
    let pool = history::open(opt.directory.join("history.db").as_os_str().to_str().unwrap())
        .await
        .unwrap();
    let mut node = match node::Node::init(
        opt.directory.as_path(),
        pool,
        opt.listen,
        "example",
        participants.into_boxed_slice(),
        privates.into_boxed_slice(),
        opt.connect,
        opt.network_delay.into(),
    ).await {
        Ok(node) => node,
        Err(err) => {
            tracing::error!(error = %err, "failed to initialize node");
            std::process::exit(1);
        }
    };
    let ctx = context::Context::new();
    let ctrc_ctx = ctx.clone();
    if let Err(err) = ctrlc::set_handler(move || {
        tracing::info!("received interrupt signal");
        ctrc_ctx.cancel();
    }) {
        tracing::error!(error = %err, "failed to set interrupt handler");
        std::process::exit(1);
    };
    // pass error up the stack
    node.run(ctx).await;
    tracing::info!("node exited");
}
