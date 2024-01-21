use std::os;

use clap::{Parser, Subcommand};
use hex;
use hotstuff2::types::{PrivateKey, PublicKey};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Parser)]
struct Opt {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Generate {
        #[arg(long, short = 'n', default_value = "4", help = "size of the cluster")]
        size: usize,
        #[arg(
            long,
            short = 'd',
            default_value = "/tmp/hotstufftestbed",
            help = "directory to store state for `n` nodes in the cluster. each node will have its own directory with index name in it"
        )]
        directory: String,
    },
}

#[derive(Debug, Clone)]
struct Private(PrivateKey);

impl Serialize for Private {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.0.to_bytes()))
    }
}

impl<'a> Deserialize<'a> for Private {
    fn deserialize<D: serde::Deserializer<'a>>(deserializer: D) -> Result<Private, D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
        let private = Private(PrivateKey::from_bytes(&bytes).map_err(serde::de::Error::custom)?);
        Ok(private)
    }
}

#[derive(Debug, Clone)]
struct Public(PublicKey);

impl Serialize for Public {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.0.to_bytes()))
    }
}

impl<'a> Deserialize<'a> for Public {
    fn deserialize<D: serde::Deserializer<'a>>(deserializer: D) -> Result<Public, D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
        let public = Public(PublicKey::from_bytes(&bytes).map_err(serde::de::Error::custom)?);
        Ok(public)
    }
}

#[derive(Serialize, Deserialize)]
struct Configuration {
    managed_keys: Vec<Private>,
    participants: Vec<Public>,
}

fn main() {
    match Opt::parse().command {
        Command::Generate { size, directory } => {
            let privates = (0..size)
                .map(|_| {
                    let mut seed = [0u8; 32];
                    OsRng.fill_bytes(&mut seed);
                    PrivateKey::from_seed(&seed)
                })
                .map(Private)
                .collect::<Vec<_>>();

            let publics = privates
                .iter()
                .map(|private| Public(private.0.public()))
                .collect::<Vec<_>>();

            for i in 0..size {
                let path = format!("{}/{}", directory, i);
                let config = Configuration {
                    managed_keys: (i..i + 1).map(|i| privates[i].clone()).collect(),
                    participants: publics.clone(),
                };
                let config = serde_json::to_string_pretty(&config).unwrap();
                std::fs::create_dir_all(&path).expect("create all directories");
                std::fs::write(format!("{}/config.json", path), config).unwrap();
            }
        }
    }
}
