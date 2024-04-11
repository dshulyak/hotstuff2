// ideas for the model based on [Twins: BFT Systems Made Robust](https://drops.dagstuhl.de/storage/00lipics/lipics-vol217-opodis2021/LIPIcs.OPODIS.2021.7/LIPIcs.OPODIS.2021.7.pdf)

use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    fmt::Debug,
};

use arbitrary::Arbitrary;
use bit_vec::BitVec;
use itertools::Itertools;

use crate::{
    sequential::{Action, Actions, Consensus, OnDelay, OnMessage, Proposer},
    types::{
        AggregateSignature, Block, Certificate, Message, PrivateKey, PublicKey, Sync as SyncMsg,
        Vote, ID,
    },
};

fn genesis() -> Certificate<Vote> {
    Certificate {
        inner: Vote {
            view: 0.into(),
            block: Block::new(0, ID::empty(), "genesis".into()),
        },
        signature: AggregateSignature::empty(),
        signers: BitVec::new(),
    }
}

#[derive(Debug)]
struct Sink(RefCell<Vec<Action>>);

impl Sink {
    fn new() -> Self {
        Sink(RefCell::new(vec![]))
    }

    fn drain(&self) -> Vec<Action> {
        self.0.borrow_mut().drain(..).collect()
    }
}

impl Actions for Sink {
    fn send(&self, action: Action) {
        self.0.borrow_mut().push(action);
    }
}

fn privates(n: usize) -> Vec<PrivateKey> {
    let mut keys = (0..=n)
        .map(|i| PrivateKey::from_seed(&[i as u8; 32]))
        .collect::<Vec<_>>();
    keys.sort_by(|a, b| a.public().cmp(&b.public()));
    keys
}

#[derive(Eq, Hash, PartialEq, Copy, Clone, PartialOrd, Ord)]
pub enum Node {
    Honest(u8),
    Twin(u8, u8),
}

impl Node {
    fn num(&self) -> u8 {
        match self {
            Node::Honest(id) => *id,
            Node::Twin(id, twin) => *id + *twin,
        }
    }

    fn parse(value: &str) -> anyhow::Result<Self> {
        let mut parts = value.split('/');
        let id = parts.next().unwrap().parse::<u8>()?;
        match parts.next() {
            None => Ok(Node::Honest(id)),
            Some(twin) => Ok(Node::Twin(id, twin.parse::<u8>()?)),
        }
    }
}

impl Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Node::Honest(id) => write!(f, "{}", id),
            Node::Twin(id, twin) => write!(f, "{}/{}", id, twin),
        }
    }
}

pub enum Op {
    // install routing table
    Routes(Vec<Vec<Node>>),
    // consume and execute actions
    // - send messages
    // - commits
    Advance(usize),
}

pub struct Scenario(Vec<Op>);

impl Scenario {
    pub fn parse(value: &str) -> anyhow::Result<Self> {
        let ops = value
            .lines()
            .map(|line| Op::parse(line.trim()))
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(Scenario(ops))
    }
}

impl Debug for Scenario {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for op in self.0.iter() {
            writeln!(f, "{:?}", op)?;
        }
        Ok(())
    }
}

impl Op {
    pub fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "advance" => {
                let n = value.strip_prefix("advance").unwrap().parse::<usize>()?;
                Ok(Op::Advance(n))
            },
            _ => {
                let mut partitions = vec![];
                for side in value.split("|") {
                    let nodes = side
                        .trim()
                        .strip_prefix("{")
                        .and_then(|side| side.strip_suffix("}"))
                        .ok_or_else(|| anyhow::anyhow!("invalid partition"))?
                        .split(",")
                        .map(|node| Node::parse(node.trim()))
                        .collect::<anyhow::Result<Vec<_>>>()?;
                    partitions.push(nodes);
                }
                Ok(Op::Routes(partitions))
            }
        }
    }
}

impl Debug for Op {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Op::Routes(partition) => {
                for (i, side) in partition.iter().enumerate() {
                    if i > 0 {
                        write!(f, " | ")?;
                    }
                    write!(f, "{{")?;
                    for (j, node) in side.iter().enumerate() {
                        if j > 0 {
                            write!(f, ", ")?;
                        }
                        write!(f, "{:?}", node)?;
                    }
                    write!(f, "}}")?;
                }
                Ok(())
            }
            Op::Advance(n) => write!(f, "advance {}", n),
        }
    }
}

#[derive(Debug)]
pub struct ArbitraryOp<const TOTAL: usize, const TWINS: usize>(Op);

impl<const TOTAL: usize, const TWINS: usize> Into<Op> for ArbitraryOp<TOTAL, TWINS> {
    fn into(self) -> Op {
        self.0
    }
}

impl<'a, const TOTAL: usize, const TWINS: usize> Arbitrary<'a> for ArbitraryOp<TOTAL, TWINS> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        if u.ratio(1, 2)? {
            // generate all nodes into single array
            // split array into 1-3 random partitions
            // only 1 twin can exist in the partition, so any 2nd twin is moved to the next one
            // if partition doesn't exist creeate empty partition

            let nodes = Model::nodes(TOTAL, TWINS);
            Ok(ArbitraryOp(Op::Routes(vec![nodes])))
        } else {
            Ok(ArbitraryOp(Op::Advance(u.int_in_range(1..=7)?)))
        }
    }
}

pub struct Model {
    consensus: HashMap<Node, Consensus<Sink>>,
    public_key_to_node: HashMap<PublicKey, Node>,
    commits: HashMap<Node, BTreeMap<u64, Certificate<Vote>>>,
    locks: HashMap<Node, Certificate<Vote>>,
    proposals_counter: HashMap<Node, u64>,
    routes: Option<HashMap<Node, Node>>,
}

impl Model {
    fn nodes(total: usize, twins: usize) -> Vec<Node> {
        (0..=total - twins)
            .map(|i| Node::Honest(i as u8))
            .chain(
                (total - twins..total).flat_map(|i| (0..=1).map(move |j| Node::Twin(i as u8, j))),
            )
            .collect()
    }

    pub fn new(total: usize, twins: usize) -> Self {
        let keys = privates(total);
        let nodes = Self::nodes(total, twins)
            .into_iter()
            .map(|n| {
                (
                    n,
                    match n {
                        Node::Honest(id) => &keys[id as usize],
                        Node::Twin(id, _) => &keys[id as usize],
                    },
                )
            })
            .map(|(n, key)| {
                (
                    n,
                    Consensus::new(
                        0.into(),
                        keys.iter()
                            .map(|key| key.public())
                            .collect::<Vec<_>>()
                            .into_boxed_slice(),
                        genesis(),
                        genesis(),
                        0.into(),
                        [key.clone()].as_slice(),
                        Sink::new(),
                    ),
                )
            })
            .collect::<HashMap<_, _>>();
        let by_public = nodes
            .iter()
            .flat_map(|(n, c)| c.public_keys().into_iter().map(|(_, public)| (public, *n)))
            .collect::<HashMap<_, _>>();
        Self {
            consensus: nodes,
            public_key_to_node: by_public,
            commits: HashMap::new(),
            locks: HashMap::new(),
            proposals_counter: HashMap::new(),
            routes: None,
        }
    }

    pub fn step(&mut self, op: Op) -> anyhow::Result<()> {
        match op {
            Op::Routes(partition) => {
                self.paritition(partition);
            }
            Op::Advance(n) => {
                for _ in 0..n {
                    self.advance();
                }
            }
        }
        self.verify()
    }

    fn last_commit(&self, node: &Node) -> Option<&Certificate<Vote>> {
        self.commits
            .get(node)
            .and_then(|certs| certs.last_key_value().map(|(_, cert)| cert))
    }

    fn sync_from(&mut self, from: &Node, to: &Node) {
        tracing::debug!("syncing from {:?} to {:?}", from, to);
        let from_last_commit = self.last_commit(from);
        let to_last_commit = self.last_commit(to);
        for height in to_last_commit
            .map(|cert| cert.block.height + 1)
            .unwrap_or(1)
            ..=from_last_commit.map(|cert| cert.block.height).unwrap_or(1)
        {
            tracing::debug!(
                "uploading certificate for height {} from {:?} to {:?}",
                height,
                from,
                to
            );
            let cert = self
                .commits
                .get(from)
                .and_then(|certs| certs.get(&height))
                .unwrap();
            if let Some(consensus) = self.consensus.get(to) {
                let sync = SyncMsg {
                    locked: None,
                    commit: Some(cert.clone()),
                };
                _ = consensus.on_message(Message::Sync(sync));
            };
        }
    }

    fn advance(&mut self) {
        if self.routes.is_none() {
            return;
        }
        let routes = self.routes.as_ref().unwrap();
        for (id, consensus) in self.consensus.iter() {
            for action in consensus.sink().drain() {
                match action {
                    Action::StateChange(change) => {
                        if let Some(cert) = change.commit {
                            self.commits
                                .entry(*id)
                                .or_insert_with(BTreeMap::new)
                                .insert(cert.block.height, cert);
                        }
                        if let Some(lock) = change.lock {
                            self.locks.insert(*id, lock);
                        }
                    }
                    Action::Send(msg, target) => {
                        if let Some(target) = target {
                            _ = self
                                .consensus
                                .get(self.public_key_to_node.get(&target).unwrap())
                                .unwrap()
                                .on_message(msg.clone());
                        } else {
                            for linked in routes.get(id).iter() {
                                _ = self.consensus.get(linked).unwrap().on_message(msg.clone());
                            }
                            _ = consensus.on_message(msg.clone());
                        }
                    }
                    Action::Propose => {
                        let nonce = self.proposals_counter.get(id).unwrap_or(&0);
                        let mut block_id = [0u8; 32];
                        block_id[0..8].copy_from_slice(&nonce.to_be_bytes());
                        block_id[9] = id.num();
                        _ = consensus.propose(block_id.into());
                        self.proposals_counter.insert(*id, nonce + 1);
                    }
                }
            }
        }
        for (_, consensus) in self.consensus.iter() {
            consensus.on_delay();
        }
    }

    fn verify(&self) -> anyhow::Result<()> {
        let certs = self
            .commits
            .iter()
            .flat_map(|(_, certs)| certs.last_key_value());
        let mut by_height = HashMap::new();
        for (height, cert) in certs {
            if let Some(by_height) = by_height.get(height) {
                if by_height != cert {
                    return Err(anyhow::anyhow!("inconsistent commits"));
                }
            } else {
                by_height.insert(*height, cert.clone());
            }
        }
        Ok(())
    }

    fn paritition(&mut self, partition: Vec<Vec<Node>>) {
        match self.routes.take() {
            None => {
                self.routes = Some(
                    partition
                        .iter()
                        .flat_map(|side| {
                            side.iter().permutations(2).map(|pair| (*pair[0], *pair[1]))
                        })
                        .collect::<HashMap<_, _>>(),
                );
            }
            Some(_) => {
                for side in partition.iter() {
                    for pair in side.iter().permutations(2) {
                        self.sync_from(&pair[0], &pair[1]);
                    }
                }
                self.routes = Some(
                    partition
                        .iter()
                        .flat_map(|side| {
                            side.iter().permutations(2).map(|pair| (*pair[0], *pair[1]))
                        })
                        .collect::<HashMap<_, _>>(),
                );
            }
        }
    }
}
