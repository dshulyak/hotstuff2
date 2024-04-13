// ideas for the model based on [Twins: BFT Systems Made Robust](https://drops.dagstuhl.de/storage/00lipics/lipics-vol217-opodis2021/LIPIcs.OPODIS.2021.7/LIPIcs.OPODIS.2021.7.pdf)

use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap, HashSet},
    fmt::Debug,
};

use bit_vec::BitVec;
use itertools::Itertools;

use crate::{
    crypto,
    sequential::{Action, Actions, Consensus, OnDelay, OnMessage, Proposer, TIMEOUT},
    types::{
        AggregateSignature, Block, Certificate, Message, PrivateKey, PublicKey, Sync as SyncMsg,
        Timeout, View, Vote, ID,
    },
};

// LIVENESS_MAX_ROUNDS is a maximal number of rounds that are required to make a new block.
const LIVENESS_MAX_ROUNDS: u8 = 4 * TIMEOUT;

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
    fn key(&self) -> u8 {
        match self {
            Node::Honest(id) => *id,
            Node::Twin(id, _) => *id,
        }
    }

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

pub struct Model {
    total: usize,
    consensus: HashMap<Node, Consensus<Sink, crypto::NoopBackend>>,
    public_key_to_node: HashMap<PublicKey, Vec<Node>>,
    commits: HashMap<Node, BTreeMap<u64, Certificate<Vote>>>,
    locks: HashMap<Node, Certificate<Vote>>,
    timeouts: HashMap<Node, Certificate<View>>,
    proposals_counter: HashMap<Node, u64>,
    installed_partition: Vec<Vec<Node>>,
    routes: HashMap<Node, HashSet<Node>>,
    inboxes: HashMap<Node, Vec<Message>>,
    consecutive_advance: usize,
    tracking_progress: HashSet<Node>,
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
        let mut by_public = HashMap::new();
        for (pun, node) in nodes
            .iter()
            .flat_map(|(n, c)| c.public_keys().into_iter().map(|(_, public)| (public, *n)))
        {
            by_public.entry(pun).or_insert_with(Vec::new).push(node);
        }
        let inboxes = nodes.keys().map(|n| (*n, vec![])).collect();
        let mut model = Self {
            total: total,
            consensus: nodes,
            public_key_to_node: by_public,
            commits: HashMap::new(),
            locks: HashMap::new(),
            timeouts: HashMap::new(),
            proposals_counter: HashMap::new(),
            inboxes: inboxes,
            installed_partition: vec![],
            routes: HashMap::new(),
            consecutive_advance: 0,
            tracking_progress: HashSet::new(),
        };
        model.step(Op::Advance(TIMEOUT as usize)).unwrap();
        model
    }

    pub fn step(&mut self, op: Op) -> anyhow::Result<()> {
        tracing::trace!("step: {:?}", op);
        match op {
            Op::Routes(partition) => {
                self.paritition(partition);
                self.consecutive_advance = 0;
                self.tracking_progress.clear();
            }
            Op::Advance(n) => {
                for _ in 0..n {
                    self.consecutive_advance += 1;
                    self.advance();
                    if self.consecutive_advance == 1 {
                        self.sync();
                    }
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
        let from_last_commit = self.last_commit(from);
        let to_last_commit = self.last_commit(to);

        tracing::debug!(
            "syncing from {:?} to {:?}. certs from={:?} to ={:?}",
            from,
            to,
            from_last_commit,
            to_last_commit,
        );
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
                tracing::debug_span!("sync", node = ?to).in_scope(|| {
                    if let Err(err) = consensus.on_message(Message::Sync(sync)) {
                        tracing::warn!("error syncing from {:?} to {:?}: {:?}", from, to, err);
                    };
                });
            };
        }
        self.sync_timeouts(from, to)
    }

    fn sync_timeouts(&mut self, from: &Node, to: &Node) {
        let from_timeout = self.timeouts.get(from).map_or(0.into(), |cert| cert.inner);
        let to_timeout = self.timeouts.get(to).map_or(0.into(), |cert| cert.inner);
        if from_timeout > to_timeout {
            if let Some(consensus) = self.consensus.get(to) {
                let timeout = self.timeouts.get(from).unwrap().clone();
                tracing::debug_span!("sync timeout", node = ?to).in_scope(|| {
                    if let Err(err) = consensus.on_message(Message::Timeout(Timeout {
                        certificate: timeout,
                    })) {
                        tracing::warn!("error on timeout from {:?} to {:?}: {:?}", from, to, err);
                    };
                });
            }
        }
    }

    fn advance(&mut self) {
        let mut queue = self.consensus.keys().collect::<Vec<_>>();
        while let Some(id) = queue.pop() {
            let consensus = self.consensus.get(id).unwrap();
            for action in consensus.sink().drain() {
                match action {
                    Action::StateChange(change) => {
                        if let Some(lock) = change.locked {
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
                                "{}: commiting block {:?} in view {} on node {:?}",
                                self.consecutive_advance,
                                cert.block,
                                cert.inner.view,
                                id
                            );
                            self.commits
                                .entry(*id)
                                .or_insert_with(BTreeMap::new)
                                .insert(cert.block.height, cert);
                            self.tracking_progress.insert(*id);
                        }
                        if let Some(timeout) = change.timeout {
                            tracing::debug!(
                                "{}: timeout for view {} on node {:?}",
                                self.consecutive_advance,
                                timeout.inner,
                                id
                            );
                            self.timeouts.insert(*id, timeout);
                        }
                    }
                    Action::Send(msg, target) => {
                        if let Some(target) = target {
                            if let Some(route) = self.public_key_to_node.get(&target) {
                                let targets = route
                                    .iter()
                                    .filter(|target| {
                                        self.routes
                                            .get(id)
                                            .and_then(|linked| linked.get(target))
                                            .is_some()
                                            || *target == id
                                    })
                                    .collect::<Vec<_>>();
                                if targets.len() == 0 {
                                    tracing::warn!(
                                        "{}: blocked from {:?} {:?}",
                                        self.consecutive_advance,
                                        id,
                                        msg,
                                    );
                                }
                                for target in targets.into_iter() {
                                    tracing::trace!(
                                        "{}: routed {:?} => {:?}: {:?}",
                                        self.consecutive_advance,
                                        id,
                                        target,
                                        msg,
                                    );
                                    self.inboxes.get_mut(target).unwrap().push(msg.clone());
                                }
                            }
                        } else {
                            if let Some(links) = self.routes.get(id) {
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
            tracing::debug_span!("inbox", node = ?target).in_scope(|| {
                for msg in inbox.drain(..) {
                    if let Err(err) = self.consensus.get(target).unwrap().on_message(msg.clone()) {
                        tracing::warn!(
                            "error processing message {:?} on node {:?}: {:?}",
                            msg,
                            target,
                            err
                        );
                    }
                }
            })
        }
        for (node, consensus) in self.consensus.iter() {
            tracing::debug_span!("delay", node = ?node).in_scope(|| {
                consensus.on_delay();
            });
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

        if self.consecutive_advance >= LIVENESS_MAX_ROUNDS as usize {
            for side in self.installed_partition.iter() {
                let unique = side.iter().map(|n| n.key()).collect::<HashSet<_>>();
                if unique.len() == self.total {
                    tracing::debug!(
                        "checking liveness for side {:?} in {} advances {:?}",
                        side,
                        self.consecutive_advance,
                        self.tracking_progress
                    );
                    for id in side {
                        anyhow::ensure!(
                            self.tracking_progress.get(id).is_some(),
                            "liveness violation on node {:?}",
                            id,
                        );
                    }
                }
            }
        }
        Ok(())
    }

    fn paritition(&mut self, partition: Vec<Vec<Node>>) {
        tracing::debug!("updating to partition {:?}", partition);
        self.installed_partition = partition.clone();
        self.routes = Op::Routes(partition).to_routes().unwrap();
        tracing::debug!(
            "routes {:?}. partition {:?}",
            self.routes,
            self.installed_partition
        );
        self.sync();
    }

    fn sync(&mut self) {
        for side in self.installed_partition.clone().iter() {
            for pair in side.iter().permutations(2) {
                self.sync_from(&pair[0], &pair[1]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::collection::vec;
    use proptest::prelude::*;
    use proptest::sample::subsequence;

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
            advance 9
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
            advance 9
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
            advance 9
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
            advance 9
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
            advance 9
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
"#,
        );
        let mut model = Model::new(4, 1);
        for op in scenario.unwrap() {
            if let Err(err) = model.step(op) {
                assert!(false, "error: {:?}", err);
            }
        }
    }

    #[test]
    // in this test leader for epoch boundary was blocked
    // this lead to inability to enter view as nobody could form timeout certificate
    fn test_liveness_blocked_views() {
        init_tracing();
        let scenario = Scenario::parse(
            r#"
            {0, 1, 2, 3/1} | {3/0}
            {0, 1, 3/0, 3/1} | {2}
            {0, 2, 3/0, 3/1} | {1}
            {1, 2} | {0, 3/0, 3/1}
            {0, 1, 2, 3/0} | {3/1}
            {0, 1, 2, 3/0} | {3/1}
            {0, 1, 2, 3/0} | {3/1}
            {0, 1, 2, 3/1} | {3/0}
            advance 2
            {1, 3/0, 3/1} | {0, 2}
            advance 1
            {0, 1, 2, 3/1} | {3/0}
            {0, 1, 2, 3/0} | {3/1}
            {0, 2, 3/0, 3/1} | {1}
            {0, 2, 3/0, 3/1} | {1}
            {0, 1, 2, 3/0} | {3/1}
            {0, 1, 2, 3/1} | {3/0}
            {0, 2, 3/0, 3/1} | {1}
            {1, 2, 3/0, 3/1} | {0}
            {0, 1, 3/0, 3/1} | {2}
            {0, 1, 3/0, 3/1} | {2}
            {0, 1, 2, 3/1} | {3/0}
            {0, 1, 2, 3/0} | {3/1}
            {0, 1, 2, 3/0} | {3/1}
            {0, 1, 2, 3/1} | {3/0}
            {0, 1, 3/0, 3/1} | {2}
            {0, 1, 3/0, 3/1} | {2}
            {0, 2, 3/0, 3/1} | {1}
            {0, 1, 3/0, 3/1} | {2}
            {0, 1, 2, 3/0} | {3/1}
            {0, 1, 2, 3/1} | {3/0}
            {0, 1, 3/0, 3/1} | {2}
            {0, 1, 2, 3/1} | {3/0}
            {1, 2, 3/0, 3/1} | {0}
            {0, 1, 3/0, 3/1} | {2}
            advance 1
            {0, 1, 2, 3/1} | {3/0}
            {0, 1, 3/0, 3/1} | {2}
            {0, 1, 2, 3/0} | {3/1}
            {0, 1, 3/0, 3/1} | {2}
            {1, 2, 3/0, 3/1} | {0}
            {0, 1, 2, 3/0} | {3/1}
            {0, 1, 2, 3/1} | {3/0}
            {0, 1, 2, 3/1} | {3/0}
            {0, 1, 2, 3/0} | {3/1}
            {1, 2, 3/0, 3/1} | {0}
            {0, 1, 2, 3/0} | {3/1}
            advance 2
            {0, 1, 2, 3/0} | {3/1}
            {1, 2, 3/0, 3/1} | {0}
            advance 4
            {0, 2, 3/0, 3/1} | {1}
            {0, 1, 2, 3/0} | {3/1}
            advance 4
            {0, 1, 2, 3/0} | {3/1}
            advance 3
            {1, 3/0} | {0, 2, 3/1}
            {0, 1, 3/1} | {2, 3/0}
            advance 3
            {0, 2, 3/0, 3/1} | {1}
            advance 28
"#,
        );
        let mut model = Model::new(4, 1);
        for op in scenario.unwrap() {
            if let Err(err) = model.step(op) {
                assert!(false, "error: {:?}", err);
            }
        }
    }

    #[test]
    // in this test participants in the first partition generated timeout certificates and moved to the further round
    // when node 1 rejoins partition it is still in the previous view.
    // so whole cluster is blocked as new timeout certificates can't be formed by {2, 3/0, 3/1}
    fn test_liveness_lost_timeout() {
        init_tracing();
        let scenario = Scenario::parse(
            r#"
{0, 2, 3/0, 3/1} | {1}
advance 11
{0, 1, 2, 3/0, 3/1}
advance 16
"#,
        );
        let mut model = Model::new(4, 1);
        for op in scenario.unwrap() {
            if let Err(err) = model.step(op) {
                assert!(false, "error: {:?}", err);
            }
        }
    }

    #[test]
    // in this test timeout cerrtificate is generated by partition {1, 2, 3/1} and not persisted
    // when partition is fixed.
    // nodes 3/0 and 1 are consecutive leaders and therefore no progress for 2 views
    // after that nodes are casting wishes for different epochs (f+1 segments)
    // due to protocol bug we have partition {0, 3/0} that casts votes for view 7
    // and partition {1, 2} that casts correct votes for view 9
    fn test_liveness_timeout_delivered_before_partition() {
        init_tracing();
        let scenario = Scenario::parse(
            r#"
{0, 1, 3/0, 3/1} | {2}
advance 2
{1, 2, 3/0, 3/1} | {0}
advance 4
{0, 1, 2, 3/1} | {3/0}
advance 9
{3/0, 3/1} | {0, 1, 2}
advance 19
{0, 1, 2, 3/0} | {3/1}
advance 2
{0, 1, 3/0, 3/1} | {2}
advance 12
{1, 2, 3/1} | {0, 3/0}
advance 4
{0, 1, 2, 3/0} | {3/1}
advance 28
"#,
        );
        let mut model = Model::new(4, 1);
        for op in scenario.unwrap() {
            if let Err(err) = model.step(op) {
                assert!(false, "error: {:?}", err);
            }
        }
    }

    #[test]
    fn test_liveness_extend_committed_block() {
        init_tracing();
        let scenario = Scenario::parse(
            r#"advance 1
            {0, 1, 2, 3/0} | {3/1}
            advance 1
            {0, 1, 2, 3/1} | {3/0}
            advance 16
            {1, 3/1} | {0, 2, 3/0}
            advance 12
            {1, 2, 3/0, 3/1} | {0}
            advance 1
            {0, 1, 2, 3/1} | {3/0}
            advance 28"#,
        );
        let mut model = Model::new(4, 1);
        for op in scenario.unwrap() {
            if let Err(err) = model.step(op) {
                assert!(false, "error: {:?}", err);
            }
        }
    }
    proptest! {
        // The next line modifies the number of tests.
        #![proptest_config(ProptestConfig::with_cases(1000))]
        #[test]
        fn test_random_partitions(ops in &vec(
            prop_oneof![
                1 => two_sided_partition(Model::nodes(4, 1)),
                4 => (1..4usize).prop_map(Op::Advance),
            ],
            100,
        ).prop_map(|ops| Scenario(ops))) {
            let mut model = Model::new(4, 1);
            for op in ops {
                if let Err(err) = model.step(op) {
                    assert!(false, "error: {:?}", err);
                }
            }
        }
    }
}
