// ideas for the model based on [Twins: BFT Systems Made Robust](https://drops.dagstuhl.de/storage/00lipics/lipics-vol217-opodis2021/LIPIcs.OPODIS.2021.7/LIPIcs.OPODIS.2021.7.pdf)


use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap}, fmt::Debug,
};

use arbitrary::Arbitrary;
use bit_vec::BitVec;
use itertools::Itertools;

use crate::{
    sequential::{Action, Actions, Consensus, OnDelay, OnMessage, Proposer},
    types::{AggregateSignature, Block, Certificate, PrivateKey, PublicKey, Vote, ID},
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
}

impl Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Node::Honest(id) => write!(f, "H{}", id),
            Node::Twin(id, twin) => write!(f, "T{}/{}", id, twin),
        }
    }
}

pub enum Op {
    // install routing table
    Routes(Vec<Vec<Node>>),
    // consume and execute actions
    // - send messages
    // - commits
    Advance,
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
                    for (j, node)  in side.iter().enumerate() {
                        if j > 0 {
                            write!(f, ", ")?;
                        }
                        write!(f, "{:?}", node)?;
                    }
                    write!(f, "}}")?;
                };
                Ok(())
            }
            Op::Advance => f.write_str("advance"),
        }
    }
}

impl<'a> Arbitrary<'a> for Op {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        if u.ratio(1, 10)? {
            // generate all nodes into single array
            // split array into 1-3 random partitions
            // only 1 twin can exist in the partition, so any 2nd twin is moved to the next one
            // if partition doesn't exist creeate empty partition

            let honest = (0..5).map(|i| Node::Honest(i));
            let twins = (5..7)
                .flat_map(|i| (0..=0).map(|j| Node::Twin(i, j)).collect::<Vec<Node>>());
            Ok(Op::Routes(vec![honest.chain(twins).collect()]))
        } else {
            Ok(Op::Advance)
        }
    }
}

pub struct Model {
    consensus: HashMap<Node, Consensus<Sink>>,
    public_key_to_node: HashMap<PublicKey, Node>,
    commits: BTreeMap<u64, HashMap<Node, Block>>,
    locks: HashMap<Node, Certificate<Vote>>,
    proposals_counter: HashMap<Node, u64>,
    routes: Option<HashMap<Node, Node>>,
}

impl Model {
    pub fn new(total: usize, twins: usize) -> Self {
        let keys = privates(total);
        let dishonest =
            (total - twins..total).flat_map(|i| (0..=1).map(move |j| Node::Twin(i as u8, j)));
        let nodes = (0..=total - twins)
            .map(|i| Node::Honest(i as u8))
            .chain(dishonest)
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
            commits: BTreeMap::new(),
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
            Op::Advance => {
                self.advance();
            }
        }
        self.verify()
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
                                .entry(cert.block.height)
                                .or_insert_with(HashMap::new)
                                .insert(*id, cert.block.clone());
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
        if let Some(mut values) = self
            .commits
            .last_key_value()
            .map(|(_, v)| v.values().into_iter())
        {
            let first = values.next().unwrap();
            for other in values {
                anyhow::ensure!(first == other, "commits are not equal");
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
                self.routes = Some(
                    partition
                        .iter()
                        .flat_map(|side| {
                            side.iter().permutations(2).map(|pair| (*pair[0], *pair[1]))
                        })
                        .collect::<HashMap<_, _>>(),
                );
                // TODO restored connections should sync latest commits and locks from each other
            }
        }
    }
}
