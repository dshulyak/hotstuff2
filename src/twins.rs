use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    iter,
};

use itertools::Itertools;
use proptest::{sample::subsequence, strategy::Strategy};

use crate::{sequential as seq, types::ID};
use crate::types::{PrivateKey, PublicKey};

#[derive(Eq, Hash, PartialEq, Copy, Clone, PartialOrd, Ord)]
pub enum Node {
    Honest(u8),
    Twin(u8, u8),
}

impl Node {
    pub(crate) fn key(&self) -> u8 {
        match self {
            Node::Honest(id) => *id,
            Node::Twin(id, _) => *id,
        }
    }

    pub(crate) fn num(&self) -> u8 {
        match self {
            Node::Honest(id) => *id,
            Node::Twin(id, twin) => *id + *twin,
        }
    }

    pub(crate) fn parse(value: &str) -> anyhow::Result<Self> {
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

#[derive(Clone)]
pub enum Op {
    // install routing table
    Routes(Vec<Vec<Node>>),
    // consume and execute actions
    // - send messages
    // - commits
    Advance(usize),
}

impl Op {
    pub(crate) fn to_routes(&self) -> Option<HashMap<Node, HashSet<Node>>> {
        match self {
            Op::Routes(routes) => {
                let mut rst = HashMap::new();
                for side in routes.iter() {
                    for pair in side.iter().permutations(2) {
                        rst.entry(*pair[0])
                            .or_insert_with(HashSet::new)
                            .insert(*pair[1]);
                    }
                }
                Some(rst)
            }
            _ => None,
        }
    }
}

pub struct Scenario(Vec<Op>);

impl Scenario {
    pub(crate) fn new(ops: Vec<Op>) -> Self {
        Scenario(ops)
    }

    pub(crate) fn parse(value: &str) -> anyhow::Result<Self> {
        let ops = value
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| Op::parse(line.trim()))
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(Scenario(ops))
    }
}

impl IntoIterator for Scenario {
    type Item = Op;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl Debug for Scenario {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut consecutive_advance = 0;
        for op in self.0.iter() {
            match op {
                Op::Routes(_) => {
                    if consecutive_advance > 0 {
                        writeln!(f, "advance {}", consecutive_advance)?;
                        consecutive_advance = 0;
                    }
                    writeln!(f, "{:?}", op)?;
                }
                Op::Advance(n) => {
                    consecutive_advance += n;
                }
            }
        }
        if consecutive_advance > 0 {
            writeln!(f, "advance {}", consecutive_advance)?;
        }
        Ok(())
    }
}

impl Op {
    pub(crate) fn parse(value: &str) -> anyhow::Result<Self> {
        if value.starts_with("advance") {
            Ok(Op::Advance(
                value
                    .strip_prefix("advance")
                    .unwrap()
                    .trim()
                    .parse::<usize>()?,
            ))
        } else {
            let mut partitions = vec![];
            for side in value.split("|") {
                let nodes = side
                    .trim()
                    .strip_prefix("{")
                    .and_then(|side| side.strip_suffix("}"))
                    .ok_or_else(|| anyhow::anyhow!("invalid partition {}", side))?
                    .split(",")
                    .map(|node| Node::parse(node.trim()))
                    .collect::<anyhow::Result<Vec<_>>>()?;
                partitions.push(nodes);
            }
            Ok(Op::Routes(partitions))
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

pub(crate) fn two_sided_partition(nodes: Vec<Node>) -> impl Strategy<Value = Op> {
    subsequence(nodes.clone(), 1..nodes.len() - 1).prop_map(move |partitioned| {
        let left = nodes
            .clone()
            .iter()
            .filter(|n| !partitioned.contains(n))
            .map(|n| *n)
            .collect::<Vec<_>>();
        Op::Routes(vec![left, partitioned])
    })
}

pub(crate) struct Twins {
    total: usize,
    pub(crate) nodes: HashMap<Node, PrivateKey>,
    pub(crate) publics: Vec<PublicKey>,
    public_key_to_node: HashMap<PublicKey, Vec<Node>>,
    proposals_counter: HashMap<Node, u64>,
    installed_partition: Vec<Vec<Node>>,
    routes: HashMap<Node, HashSet<Node>>,
}

impl Twins {
    pub(crate) fn nodes(total: usize, twins: usize) -> Vec<Node> {
        (0..total - twins)
            .map(|i| Node::Honest(i as u8))
            .chain(
                (total - twins..total).flat_map(|i| (0..=1).map(move |j| Node::Twin(i as u8, j))),
            )
            .collect()
    }

    pub(crate) fn new(total: usize, twins: usize) -> Self {
        let keys = seq::testing::privates(total);
        let publics = keys.iter().map(|key| key.public()).collect::<Vec<_>>();
        let nodes = Twins::nodes(total, twins)
            .into_iter()
            .map(|n| {
                (
                    n,
                    match n {
                        Node::Honest(id) => keys[id as usize].clone(),
                        Node::Twin(id, _) => keys[id as usize].clone(),
                    },
                )
            })
            .collect::<HashMap<_, _>>();
        let mut by_public = HashMap::new();
        for (pun, node) in nodes.iter().map(|(n, key)| (key.public(), *n)) {
            by_public.entry(pun).or_insert_with(Vec::new).push(node);
        }
        Twins {
            total: total,
            nodes: nodes,
            publics: publics,
            public_key_to_node: by_public,
            proposals_counter: HashMap::new(),
            installed_partition: vec![],
            routes: HashMap::new(),
        }
    }

    // total returns number of unique nodes in the network.
    pub(crate) fn total(&self) -> usize {
        self.total
    }

    pub(crate) fn route_to_public_key<'a>(
        &'a self,
        from: &'a Node,
        target: &'a PublicKey,
    ) -> impl Iterator<Item = &'a Node> {
        self.public_key_to_node
            .get(target)
            .map(move |route| {
                route.iter().filter(move |target| {
                    self.routes
                        .get(from)
                        .and_then(|linked| linked.get(target))
                        .is_some()
                        || *target == from
                })
            })
            .into_iter()
            .flatten()
    }

    pub(crate) fn broadcast<'a>(&'a self, from: &'a Node) -> impl Iterator<Item = &'a Node> {
        self.routes
            .get(from)
            .into_iter()
            .flatten()
            .chain(iter::once(from))
    }

    pub(crate) fn unique_proposal(&mut self, id: &Node) -> ID {
        let nonce = self.proposals_counter.get(id).unwrap_or(&0);
        let mut block_id = [0u8; 32];
        block_id[0..8].copy_from_slice(&nonce.to_be_bytes());
        block_id[9] = id.num();
        self.proposals_counter.insert(*id, nonce + 1);
        block_id.into()
    }

    pub(crate) fn pair_routes<'a>(&'a self) -> impl Iterator<Item = (Node, Node)> + 'a {
        self.installed_partition
            .iter()
            .flat_map(|side| side.iter().permutations(2).into_iter())
            .map(move |pair| (*pair[0], *pair[1]))
    }

    pub(crate) fn installed_partition(&self) -> &[Vec<Node>] {
        &self.installed_partition
    }

    pub(crate) fn install_partition(&mut self, partition: Vec<Vec<Node>>) {
        tracing::debug!("updating to partition {:?}", partition);
        self.installed_partition = partition.clone();
        self.routes = Op::Routes(partition).to_routes().unwrap();
        tracing::debug!(
            "routes {:?}. partition {:?}",
            self.routes,
            self.installed_partition
        );
    }
}
