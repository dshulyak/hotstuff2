#![no_main]

// ideas for the model based on [Twins: BFT Systems Made Robust](https://drops.dagstuhl.de/storage/00lipics/lipics-vol217-opodis2021/LIPIcs.OPODIS.2021.7/LIPIcs.OPODIS.2021.7.pdf)

use std::{cell::RefCell, collections::HashMap};

use arbitrary::Arbitrary;
use bit_vec::BitVec;
use hotstuff2::{
    sequential::{Action, Actions, Consensus, OnDelay, OnMessage, Proposer},
    types::{AggregateSignature, Block, Certificate, PrivateKey, Vote, ID},
};
use itertools::Itertools;
use libfuzzer_sys::fuzz_target;

const HONEST: u8 = 4;
const TWINS: u8 = 3;
// const MAX_PARTITIONS: u8 = 3;

#[derive(Debug, Eq, Hash, PartialEq, Copy, Clone, PartialOrd, Ord)]
enum Node {
    Honest(u8),
    Twin(u8, u8),
}

impl Node {
    fn id(&self) -> u8 {
        match self {
            Node::Honest(id) => *id,
            Node::Twin(id, twin) => *id + *twin,
        }
    }
}

#[derive(Debug)]
enum Op {
    Partition(Vec<Vec<Node>>),
    Advance,
}

impl<'a> Arbitrary<'a> for Op {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        if u.ratio(1, 10)? {
            // generate all nodes into single array
            // split array into 1-3 random partitions
            // only 1 twin can exist in the partition, so any 2nd twin is moved to the next one
            // if partition doesn't exist creeate empty partition

            let honest = (0..=HONEST).map(|i| Node::Honest(i));
            let twins = (HONEST + 1..=HONEST + TWINS)
                .flat_map(|i| (0..=0).map(|j| Node::Twin(i, j)).collect::<Vec<Node>>());
            Ok(Op::Partition(vec![honest.chain(twins).collect()]))
        } else {
            Ok(Op::Advance)
        }
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

fn genesis() -> Certificate<Vote> {
    Certificate {
        inner: Vote {
            view: 0.into(),
            block: Block::new(0, ID::default(), "genesis".into()),
        },
        signature: AggregateSignature::empty(),
        signers: BitVec::new(),
    }
}

fn privates() -> Vec<PrivateKey> {
    let mut keys = (0..=HONEST + TWINS)
        .map(|i| PrivateKey::from_seed(&[i as u8; 32]))
        .collect::<Vec<_>>();
    keys.sort_by(|a, b| a.public().cmp(&b.public()));
    keys
}

fuzz_target!(|actions: [Op; 100]| {
    let keys = privates();
    let honest = (0..=HONEST).map(|i| Node::Honest(i));
    let twins = (HONEST + 1..=HONEST + TWINS)
        .map(|i| (0..=1).map(|j| Node::Twin(i, j)).collect::<Vec<Node>>());
    let nodes = honest
        .chain(twins.flatten())
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
            let sink = Sink::new();
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
                    sink,
                ),
            )
        })
        .collect::<HashMap<_, _>>();

    let by_public = nodes
        .iter()
        .flat_map(|(n, c)| c.public_keys().into_iter().map(|(_, public)| (public, *n)))
        .collect::<HashMap<_, _>>();
    let mut last_commit = 0u64;
    let mut commits: HashMap<u64, HashMap<Node, Block>> = HashMap::new();
    let mut proposals: HashMap<Node, u64> = HashMap::new();
    let mut links = None;
    for action in actions {
        match action {
            Op::Partition(partition) => {
                links = Some(
                    partition
                        .iter()
                        .flat_map(|side| {
                            side.iter().permutations(2).map(|pair| (*pair[0], *pair[1]))
                        })
                        .collect::<HashMap<_, _>>(),
                );
            }
            Op::Advance => {
                if let Some(links) = &links {
                    for (id, consensus) in nodes.iter() {
                        for action in consensus.sink().drain() {
                            match action {
                                Action::StateChange(change) => {
                                    if let Some(cert) = change.commit {
                                        last_commit = last_commit.max(cert.block.height);
                                        commits
                                            .entry(cert.block.height)
                                            .or_insert_with(HashMap::new)
                                            .insert(*id, cert.block.clone());
                                    }
                                }
                                Action::Send(msg, target) => {
                                    if let Some(target) = target {
                                        _ = nodes
                                            .get(by_public.get(&target).unwrap())
                                            .unwrap()
                                            .on_message(msg.clone());
                                    } else {
                                        for linked in links.get(id).iter() {
                                            _ = nodes.get(linked).unwrap().on_message(msg.clone());
                                        }
                                        _ = consensus.on_message(msg.clone());
                                    }
                                }
                                Action::Propose => {
                                    let nonce = proposals.get(id).unwrap_or(&0);
                                    let mut block_id = [0u8; 32];
                                    block_id[0..8].copy_from_slice(&nonce.to_be_bytes());
                                    block_id[9] = id.id();
                                    _ = consensus.propose(block_id.into());
                                    proposals.insert(*id, nonce + 1);
                                }
                            }
                        }
                    }
                    for (_, consensus) in nodes.iter() {
                        consensus.on_delay();
                    }
                    if last_commit > 0 {
                        let mut values = commits.get(&last_commit).unwrap().values();
                        let first = values.next().unwrap();
                        for other in values {
                            assert_eq!(first, other);
                        }
                    }
                }
            }
        }
    }
});
