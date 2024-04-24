use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
};

use itertools::Itertools;
use proptest::{sample::subsequence, strategy::Strategy};

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