// ideas for the model based on [Twins: BFT Systems Made Robust](https://drops.dagstuhl.de/storage/00lipics/lipics-vol217-opodis2021/LIPIcs.OPODIS.2021.7/LIPIcs.OPODIS.2021.7.pdf)

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::{
    crypto,
    sequential::{self as seq, Consensus, Event, OnDelay, OnMessage, Proposer, TIMEOUT},
    twins::{self, Node, Op, Twins},
    types::{Certificate, Message, Sync as SyncMsg, Timeout, View, Vote},
};

// LIVENESS_MAX_ROUNDS is a maximal number of rounds that are required to make a new block.
const LIVENESS_MAX_ROUNDS: u8 = 4 * TIMEOUT;

pub(crate) struct Model {
    twins: Twins,

    consecutive_advance: usize,
    tracking_progress: HashSet<Node>,

    consensus: HashMap<Node, Consensus<seq::testing::Sink, crypto::NoopBackend>>,
    commits: HashMap<Node, BTreeMap<u64, Certificate<Vote>>>,
    timeouts: HashMap<Node, Certificate<View>>,
    inboxes: HashMap<Node, Vec<Message>>,
}

impl Model {
    pub(crate) fn new(total: usize, twins: usize) -> Self {
        let twins = Twins::new(total, twins);
        let nodes = twins
            .nodes
            .iter()
            .map(|(n, key)| {
                (
                    *n,
                    Consensus::new(
                        0.into(),
                        twins.publics.clone().into_boxed_slice(),
                        seq::testing::genesis(),
                        seq::testing::genesis(),
                        0.into(),
                        [key.clone()].as_slice(),
                        seq::testing::Sink::new(),
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
            twins: twins,
            consensus: nodes,
            commits: HashMap::new(),
            timeouts: HashMap::new(),
            inboxes: inboxes,
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
                self.twins.install_partition(partition);
                self.sync();
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
            for action in consensus.events().drain() {
                match action {
                    Event::StateChange(change) => {
                        if let Some(lock) = change.locked {
                            tracing::debug!(
                                "{}, locking block {:?} in view {} on node {:?}",
                                self.consecutive_advance,
                                lock.block,
                                lock.inner.view,
                                id
                            );
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
                    Event::Send(msg, target) => {
                        if let Some(target) = target {
                            for target in self.twins.route_to_public_key(id, &target).into_iter() {
                                tracing::trace!(
                                    "{}: routed {:?} => {:?}: {:?}",
                                    self.consecutive_advance,
                                    id,
                                    target,
                                    msg,
                                );
                                self.inboxes.get_mut(target).unwrap().push(msg.clone());
                            }
                        } else {
                            for linked in self.twins.broadcast(id) {
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
                    }
                    Event::Propose => {
                        _ = consensus.propose(self.twins.unique_proposal(id));
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
            for side in self.twins.installed_partition() {
                let unique = side.iter().map(|n| n.key()).collect::<HashSet<_>>();
                if unique.len() == self.twins.total() {
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

    fn sync(&mut self) {
        let pairs = &self.twins.pair_routes().collect::<Vec<_>>();
        for (from, to) in pairs {
            self.sync_from(&from, &to);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::twins::Scenario;

    use super::*;

    use proptest::collection::vec;
    use proptest::prelude::*;

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
        #![proptest_config(ProptestConfig::with_cases(100))]
        #[test]
        fn test_random_partitions(ops in &vec(
            prop_oneof![
                1 => twins::two_sided_partition(twins::Twins::nodes(4, 1)),
                4 => (1..4usize).prop_map(Op::Advance),
            ],
            100,
        ).prop_map(|ops| Scenario::new(ops))) {
            let mut model = Model::new(4, 1);
            for op in ops {
                if let Err(err) = model.step(op) {
                    assert!(false, "error: {:?}", err);
                }
            }
        }
    }
}
