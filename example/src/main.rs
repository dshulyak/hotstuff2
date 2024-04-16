#![allow(dead_code)]

use std::{net::SocketAddr, path::PathBuf, str::FromStr};

use anyhow::Result;
use clap::{Parser, Subcommand};
use hotstuff2::types::{PrivateKey, PublicKey};
use humantime::Duration;
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{self as sdk};
use rand::{rngs::OsRng, RngCore};
use sdk::Resource;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt};

mod proto;
mod codec;
mod context;
mod history;
mod net;
mod node;
mod protocol;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[clap(long, short = 't', help = "endpoint to collect opentelemetry traces")]
    tracer: Option<String>,
    #[clap(
        long,
        short = 'i',
        default_value = "undefined",
        help = "unique identifier for the node"
    )]
    id: String,
}

#[derive(Debug, Subcommand)]
enum Commands {
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

    #[clap(
        long = "cidr",
        default_value = "10.0.0.0/24",
        help = "subnet where nodes will be running. the assumption is that each node will run on its own ip starting from the second"
    )]
    cidr: ipnet::IpNet,
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
        long = "peer-list",
        help = "file with list of peers to connect with. every line is expected to be an address."
    )]
    peer_list: PathBuf,

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
        help = "expected maximal delay for network messages"
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

    fn full_peer_list(&self) -> Result<Vec<SocketAddr>> {
        let mut peers = self.connect.clone();
        if self.peer_list.exists() {
            let content = std::fs::read_to_string(&self.peer_list)?;
            let new_peers = content
                .lines()
                .map(|line| {
                    SocketAddr::from_str(str::trim(line))
                        .map_err(|err| anyhow::anyhow!("{:?}", err))
                })
                .collect::<Result<Vec<_>>>()?;
            peers.extend(new_peers);
        }
        Ok(peers)
    }
}

#[tokio::main]
async fn main() {
    let opts = Cli::parse();
    if let Some(endpoint) = opts.tracer {
        let tracer = opentelemetry_otlp::new_pipeline()
            .tracing()
            .with_exporter(
                opentelemetry_otlp::new_exporter()
                    .tonic()
                    .with_endpoint(&endpoint),
            )
            .with_trace_config(
                sdk::trace::config()
                    .with_sampler(sdk::trace::Sampler::AlwaysOn)
                    .with_resource(Resource::new(vec![KeyValue::new(
                        "service.name",
                        opts.id.clone(),
                    )])),
            )
            .install_batch(sdk::runtime::Tokio)
            .expect("install simple");
        tracing_subscriber::registry()
            .with(tracing_subscriber::EnvFilter::from_default_env())
            .with(fmt::Layer::default())
            .with(tracing_opentelemetry::layer().with_tracer(tracer))
            .try_init()
            .expect("init tracing");

        tracing::info!(endpoint=%endpoint, id= %opts.id, "tracing initialized");
    } else {
        tracing::subscriber::set_global_default(
            tracing_subscriber::FmtSubscriber::builder()
                .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
                .finish(),
        )
        .expect("init stdout tracinng");
    }
    match opts.command {
        Commands::Generate(gen) => generate(gen),
        Commands::Run(opts) => run(opts).await,
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

    let mut hosts = opt.cidr.hosts();
    hosts.next(); // drain first ip
    let connect_list = publics
        .iter()
        .zip(hosts)
        .map(|(_, host)| SocketAddr::new(host, 9000).to_string())
        .collect::<Vec<_>>()
        .join("\n");
    let connect_path = opt.dir.join("peer_list");
    std::fs::write(&connect_path, connect_list).unwrap();

    tracing::info!(path = %public_path.display(), connect_list = %connect_path.display(), "wrote public keys and peers connect list");
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
    let peer_list = match opt.full_peer_list() {
        Ok(peer_list) => peer_list,
        Err(err) => {
            tracing::error!(error = %err, "failed to load peer list");
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
    let pool = history::open(
        opt.directory
            .join("history.db")
            .as_os_str()
            .to_str()
            .unwrap(),
    )
    .await
    .unwrap();
    let mut node = match node::Node::init(
        opt.directory.as_path(),
        pool,
        opt.listen,
        "example",
        participants.into_boxed_slice(),
        privates.into_boxed_slice(),
        peer_list,
        opt.network_delay.into(),
    )
    .await
    {
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
    node.run(ctx).await;
    tracing::info!("exited");
}
