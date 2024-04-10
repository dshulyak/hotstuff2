use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
};

use itertools::Itertools;
use bit_vec::BitVec;

use crate::{
    sequential::{Action, Actions, Consensus},
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

#[derive(Debug, Eq, Hash, PartialEq, Copy, Clone, PartialOrd, Ord)]
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

#[derive(Debug)]
pub enum Op {
    // install routing table
    Routes(Vec<Vec<Node>>),
    // consume and execute actions
    // - send messages
    // - commits
    Advance,
}

pub struct Model {
    total: usize,
    twins: usize,
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
            total: total,
            twins: twins,
            consensus: nodes,
            public_key_to_node: by_public,
            commits: BTreeMap::new(),
            locks: HashMap::new(),
            proposals_counter: HashMap::new(),
            routes: None,
        }
    }

    pub fn step(&mut self, op: Op) -> anyhow::Result<()> {
        Ok(())
    }

    pub fn advance(&mut self) {

    }

    pub fn paritition(&mut self, partition: Vec<Vec<Node>>) {
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
