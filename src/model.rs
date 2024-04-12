// ideas for the model based on [Twins: BFT Systems Made Robust](https://drops.dagstuhl.de/storage/00lipics/lipics-vol217-opodis2021/LIPIcs.OPODIS.2021.7/LIPIcs.OPODIS.2021.7.pdf)

use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap, HashSet},
    fmt::Debug,
};

use arbitrary::Arbitrary;
use bit_vec::BitVec;
use itertools::Itertools;

use crate::{
    crypto,
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
    let mut keys = (0..n)
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
    fn to_routes(&self) -> Option<HashMap<Node, HashSet<Node>>> {
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
    pub fn parse(value: &str) -> anyhow::Result<Self> {
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
        for op in self.0.iter() {
            writeln!(f, "{:?}", op)?;
        }
        Ok(())
    }
}

impl Op {
    pub fn parse(value: &str) -> anyhow::Result<Self> {
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

#[derive(Debug)]
pub struct ArbitraryOp<const TOTAL: usize, const TWINS: usize>(Op);

impl<const TOTAL: usize, const TWINS: usize> Into<Op> for ArbitraryOp<TOTAL, TWINS> {
    fn into(self) -> Op {
        self.0
    }
}

impl<'a, const TOTAL: usize, const TWINS: usize> Arbitrary<'a> for ArbitraryOp<TOTAL, TWINS> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        if u.ratio(1, 4)? {
            let mut nodes = Model::nodes(TOTAL, TWINS);
            for i in (1..nodes.len()).rev() {
                let j = u.int_in_range(0..=i)?;
                nodes.swap(i, j);
            }
            let (left, right) = nodes.split_at(u.int_in_range(1..=nodes.len()-2)?);
            Ok(ArbitraryOp(Op::Routes(vec![left.to_vec(), right.to_vec()])))
        } else {
            Ok(ArbitraryOp(Op::Advance(u.int_in_range(1..=4)?)))
        }
    }
}

pub struct Model {
    consensus: HashMap<Node, Consensus<Sink, crypto::NoopBackend>>,
    public_key_to_node: HashMap<PublicKey, Node>,
    commits: HashMap<Node, BTreeMap<u64, Certificate<Vote>>>,
    locks: HashMap<Node, Certificate<Vote>>,
    proposals_counter: HashMap<Node, u64>,
    routes: Option<HashMap<Node, HashSet<Node>>>,
    inboxes: HashMap<Node, Vec<Message>>,
    consecutive_advance: usize,
}

impl Model {
    fn nodes(total: usize, twins: usize) -> Vec<Node> {
        (0..total - twins)
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
        let inboxes = nodes.keys().map(|n| (*n, vec![])).collect();
        Self {
            consensus: nodes,
            public_key_to_node: by_public,
            commits: HashMap::new(),
            locks: HashMap::new(),
            proposals_counter: HashMap::new(),
            inboxes: inboxes,
            routes: None,
            consecutive_advance: 0,
        }
    }

    pub fn step(&mut self, op: Op) -> anyhow::Result<()> {
        match op {
            Op::Routes(partition) => {
                self.paritition(partition);
                self.consecutive_advance = 0;
            }
            Op::Advance(n) => {
                for _ in 0..n {
                    self.consecutive_advance += 1;
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
            let cert = self.commits.get(from).and_then(|certs| certs.get(&height));
            if cert.is_none() {
                continue;
            }
            tracing::trace!(
                "uploading certificate for height {:?} from {:?} to {:?}",
                cert,
                from,
                to
            );
            if let Some(consensus) = self.consensus.get(to) {
                let sync = SyncMsg {
                    locked: None,
                    commit: Some(cert.unwrap().clone()),
                };
                if let Err(err) = consensus.on_message(Message::Sync(sync)) {
                    tracing::warn!("error syncing from {:?} to {:?}: {:?}", from, to, err);
                };
            };
        }
    }

    fn advance(&mut self) {
        if self.routes.is_none() {
            return;
        }
        let routes = self.routes.as_ref().unwrap();
        let mut queue = self.consensus.keys().collect::<Vec<_>>();
        while let Some(id) = queue.pop() {
            let consensus = self.consensus.get(id).unwrap();
            for action in consensus.sink().drain() {
                match action {
                    Action::StateChange(change) => {
                        if let Some(lock) = change.lock {
                            tracing::debug!(
                                "{}, locking block {:?} in view {} on node {:?}",
                                self.consecutive_advance,
                                lock.block,
                                lock.inner.view,
                                id
                            );
                            self.locks.insert(*id, lock);
                        }
                        if let Some(cert) = change.commit {
                            tracing::debug!(
                                "{}: committing block {:?} in view {} on node {:?}",
                                self.consecutive_advance,
                                cert.block,
                                cert.inner.view,
                                id
                            );
                            self.commits
                                .entry(*id)
                                .or_insert_with(BTreeMap::new)
                                .insert(cert.block.height, cert);
                        }
                    }
                    Action::Send(msg, target) => {
                        if let Some(target) = target {
                            let route = self.public_key_to_node.get(&target).unwrap();
                            if routes
                                .get(id)
                                .and_then(|linked| linked.get(route))
                                .is_some()
                                || route == id
                            {
                                tracing::trace!(
                                    "{}: routed {:?} => {:?}: {:?}",
                                    self.consecutive_advance,
                                    id,
                                    route,
                                    msg,
                                );
                                self.inboxes.get_mut(route).unwrap().push(msg.clone());
                            }
                        } else {
                            if let Some(links) = routes.get(id) {
                                for linked in links {
                                    tracing::trace!(
                                        "{}: unrouted {:?} => {:?}: {:?}",
                                        self.consecutive_advance,
                                        id,
                                        linked,
                                        msg,
                                    );
                                    self.inboxes.get_mut(linked).unwrap().push(msg.clone());
                                }
                            }
                            self.inboxes.get_mut(id).unwrap().push(msg);
                        }
                    }
                    Action::Propose => {
                        let nonce = self.proposals_counter.get(id).unwrap_or(&0);
                        let mut block_id = [0u8; 32];
                        block_id[0..8].copy_from_slice(&nonce.to_be_bytes());
                        block_id[9] = id.num();
                        _ = consensus.propose(block_id.into());
                        self.proposals_counter.insert(*id, nonce + 1);
                        queue.push(id);
                    }
                }
            }
        }
        for (target, inbox) in self.inboxes.iter_mut() {
            for msg in inbox.drain(..) {
                if let Err(err) = self.consensus.get(target).unwrap().on_message(msg.clone()) {
                    tracing::trace!(
                        "error processing message {:?} on node {:?}: {:?}",
                        msg,
                        target,
                        err
                    );
                }
            }
        }
        for (_, consensus) in self.consensus.iter() {
            consensus.on_delay();
        }
    }

    #[cfg(test)]
    fn verify_committed(&self, height: u64, nodes: Vec<Node>) -> anyhow::Result<()> {
        let mut commits = nodes
            .into_iter()
            .map(|n| {
                self.commits
                    .get(&n)
                    .and_then(|certs| certs.get(&height))
                    .ok_or_else(|| anyhow::anyhow!("missing commit for node {:?}", n))
            })
            .collect::<anyhow::Result<Vec<_>>>()?
            .into_iter();
        let first = commits.next().unwrap();
        for commit in commits {
            anyhow::ensure!(first.block == commit.block);
        }
        Ok(())
    }

    fn verify(&self) -> anyhow::Result<()> {
        let certs = self
            .commits
            .iter()
            .flat_map(|(_, certs)| certs.last_key_value());
        let mut by_height: HashMap<u64, Certificate<Vote>> = HashMap::new();
        for (height, cert) in certs {
            if let Some(by_height) = by_height.get(height) {
                anyhow::ensure!(
                    by_height.block == cert.block,
                    "inconsistent commits {:?} != {:?}",
                    by_height,
                    cert
                );
            } else {
                by_height.insert(*height, cert.clone());
            }
        }
        Ok(())
    }

    fn paritition(&mut self, partition: Vec<Vec<Node>>) {
        tracing::debug!("updating to partition {:?}", partition);
        match self.routes.take() {
            None => {}
            Some(_) => {
                for side in partition.iter() {
                    for pair in side.iter().permutations(2) {
                        self.sync_from(&pair[0], &pair[1]);
                    }
                }
            }
        }
        self.routes = Op::Routes(partition).to_routes();
        tracing::debug!("routes {:?}", self.routes.as_ref().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::collection::vec;
    use proptest::prelude::*;
    use proptest::sample::subsequence;
    use proptest::test_runner::{Config, TestRunner};

    fn init_tracing() {
        let rst = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .try_init();
        assert!(rst.is_ok());
    }

    #[test]
    fn test_sanity() {
        init_tracing();
        let scenario = Scenario::parse(
            r#"
            {0, 1, 2, 3}
            advance 16
        "#,
        )
        .unwrap();
        let mut model = Model::new(4, 0);
        for op in scenario {
            model.step(op).unwrap();
        }
        model
            .verify_committed(
                1,
                vec![
                    Node::Honest(0),
                    Node::Honest(1),
                    Node::Honest(2),
                    Node::Honest(3),
                ],
            )
            .unwrap();
    }

    #[test]
    fn test_partition() {
        init_tracing();
        let scenario = Scenario::parse(
            r#"
            {0, 1, 2} | {3}
            advance 16
        "#,
        )
        .unwrap();
        let mut model = Model::new(4, 0);
        for op in scenario {
            model.step(op).unwrap();
        }
        model
            .verify_committed(1, vec![Node::Honest(0), Node::Honest(1), Node::Honest(2)])
            .unwrap();
    }

    #[test]
    fn test_sync_after_partition() {
        init_tracing();
        let scenario = Scenario::parse(
            r#"
            {0, 1, 2} | {3}
            advance 16
            {0, 1, 2, 3}
            advance 1
        "#,
        )
        .unwrap();
        let mut model = Model::new(4, 0);
        for op in scenario {
            model.step(op).unwrap();
        }
        model
            .verify_committed(
                1,
                vec![
                    Node::Honest(0),
                    Node::Honest(1),
                    Node::Honest(2),
                    Node::Honest(3),
                ],
            )
            .unwrap();
    }

    #[test]
    fn test_twins_sanity() {
        init_tracing();
        let scenario = Scenario::parse(
            r#"
            {0, 1, 2, 3/0} | {3/1}
            advance 16
        "#,
        )
        .unwrap();
        let mut model = Model::new(4, 1);
        for op in scenario {
            model.step(op).unwrap();
        }
        model
            .verify_committed(
                1,
                vec![
                    Node::Honest(0),
                    Node::Honest(1),
                    Node::Honest(2),
                    Node::Twin(3, 0),
                ],
            )
            .unwrap();
    }

    #[test]
    fn test_twins_noop() {
        init_tracing();
        let scenario = Scenario::parse(
            r#"
            {0, 1, 2, 3/0, 3/1}
            advance 16
        "#,
        )
        .unwrap();
        let mut model = Model::new(4, 1);
        for op in scenario {
            model.step(op).unwrap();
        }
        model
            .verify_committed(
                1,
                vec![
                    Node::Honest(0),
                    Node::Honest(1),
                    Node::Honest(2),
                    Node::Twin(3, 0),
                    Node::Twin(3, 1),
                ],
            )
            .unwrap();
    }

    fn two_sided_partition(nodes: Vec<Node>) -> impl Strategy<Value = Op> {
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

    #[test]
    fn test_commits_in_different_views() {
        init_tracing();
        let scenario = Scenario::parse(
            r#"
advance 2
{0, 1, 2, 3/1} | {3/0}
advance 2
advance 2
advance 1
advance 3
advance 3
advance 1
advance 1
advance 2
advance 3
advance 2
{2, 3/0} | {0, 1, 3/1}
advance 1
{3/0, 3/1} | {0, 1, 2}
advance 1
advance 2
advance 3
advance 3
advance 1
advance 2
advance 1
advance 1
advance 2
advance 2
{1, 2, 3/0} | {0, 3/1}
advance 3
advance 3
advance 2
advance 3
{0, 1, 2, 3/0} | {3/1}
advance 2
advance 3
advance 2
advance 2
advance 3
advance 1
advance 1
{0, 1, 3/0} | {2, 3/1}
advance 2
advance 1
advance 3
advance 3
advance 2
advance 2
advance 3
advance 1
advance 2
advance 1
{0, 2, 3/0, 3/1} | {1}
{2, 3/0} | {0, 1, 3/1}
advance 2
advance 3
"#);
        let mut model = Model::new(4, 1);
        for op in scenario.unwrap() {
            model.step(op).unwrap();
        }
    }

    #[test]
    fn test_random_partitions() {
        init_tracing();
        let mut runner = TestRunner::new(Config {
            cases: 1000,
            ..Config::default()
        });
        let total = 4;
        let twins = 1;
        let nodes = Model::nodes(total, twins);

        runner
            .run(
                &vec(
                    prop_oneof![
                        1 => two_sided_partition(nodes),
                        4 => (1..4usize).prop_map(Op::Advance),
                    ],
                    50..100,
                ),
                |ops| {
                    let scenario = Scenario(ops.clone());
                    tracing::info!("SCENARIO:\n{:?}", scenario);
                    let mut model = Model::new(total, twins);
                    for op in ops {
                        model
                            .step(op)
                            .map_err(|err| TestCaseError::fail(format!("{}", err.to_string())))?;
                    }
                    Ok(())
                },
            )
            .unwrap();
    }
}
