use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    ops::Range,
};

use proptest::{collection::vec, prelude::*, proptest, sample::subsequence};

use crate::{
    crypto::NoopBackend,
    pipelined::{self as pipe, Consensus, Event, Events, Message, Propose},
    twins,
    types::{
        AggregateSignature, Bitfield, Block, Certificate, PrivateKey, Signature, Signed, Signer,
        View, Vote, ID, SIGNATURE_SIZE,
    },
};

struct VecEvents(RefCell<Vec<Event>>);

impl VecEvents {
    fn drain(&self) -> Vec<Event> {
        self.0.borrow_mut().drain(..).collect()
    }
}

impl Events for VecEvents {
    fn new() -> Self {
        Self(RefCell::new(Vec::new()))
    }

    fn send(&self, event: Event) {
        self.0.borrow_mut().push(event);
    }
}

fn genesis() -> Certificate<Vote> {
    Certificate {
        inner: Vote {
            view: 0.into(),
            block: Block {
                height: 0,
                id: "genesis".into(),
                prev: ID::empty(),
            },
        },
        signature: AggregateSignature::empty(),
        signers: Bitfield::new(),
    }
}

fn pks(n: u8) -> Vec<PrivateKey> {
    (0..n).map(|i| PrivateKey::from_seed(&[i; 32])).collect()
}

type Node = pipe::Consensus<VecEvents, NoopBackend>;

fn node(n: u8, private_range: Range<usize>) -> Node {
    let privates = pks(n);
    let publics = privates.iter().map(PrivateKey::public).collect::<Vec<_>>();
    Node::new(
        &publics,
        &privates[private_range],
        0.into(),
        0.into(),
        &vec![genesis()],
    )
}

#[derive(Debug, Clone)]
enum IDChoice {
    PreviousHeight,
    ID(ID),
}

fn cert_strategy1() -> impl Strategy<Value = Certificate<Vote>> {
    (
        0..10u64,
        1..10u64,
        prop_oneof![
            2 => Just(IDChoice::ID("genesis".into())),
            4 => Just(IDChoice::PreviousHeight),
            1 => any::<[u8; 32]>().prop_map(|buf| IDChoice::ID(buf.into())),
        ],
        subsequence((0..7).collect::<Vec<Signer>>(), 4..=5),
    )
        .prop_map(|(view, height, prev_choice, signers)| {
            let mut bitfield = Bitfield::from_elem(10, false);
            for signer in signers {
                bitfield.set(signer as usize, true);
            }
            let id = format!("{}", height).as_str().into();
            let prev = match prev_choice {
                IDChoice::PreviousHeight => format!("{}", height - 1).as_str().into(),
                IDChoice::ID(id) => id,
            };
            Certificate {
                inner: Vote {
                    view: view.into(),
                    block: Block {
                        height: height,
                        prev: prev,
                        id: id,
                    },
                },
                signature: AggregateSignature::empty(),
                signers: bitfield,
            }
        })
}

fn timeout_strategy1() -> impl Strategy<Value = Certificate<View>> {
    (
        0..10u64,
        subsequence((0..10).collect::<Vec<Signer>>(), 0..=10),
    )
        .prop_map(|(view, signers)| {
            let mut bitfield = Bitfield::from_elem(10, false);
            for signer in signers {
                bitfield.set(signer as usize, true);
            }
            Certificate {
                inner: View(view),
                signature: AggregateSignature::empty(),
                signers: bitfield,
            }
        })
}

fn wish_strategy1() -> impl Strategy<Value = Signed<View>> {
    (0..5u64, 0..10u16).prop_map(|(view, signer)| Signed {
        inner: View(view),
        signer: signer,
        signature: Signature::new([0; SIGNATURE_SIZE]),
    })
}

fn valid_timeout_strategy(views: Range<u64>) -> impl Strategy<Value = Certificate<View>> {
    (views, subsequence((0..7).collect::<Vec<Signer>>(), 5)).prop_map(|(view, signers)| {
        let mut bitfield = Bitfield::from_elem(7, false);
        for signer in signers {
            bitfield.set(signer as usize, true);
        }
        Certificate {
            inner: view.into(),
            signature: AggregateSignature::empty(),
            signers: bitfield,
        }
    })
}

fn create_valid_cert(view: u64, height: u64, signers: Vec<Signer>) -> Certificate<Vote> {
    let mut bitfield = Bitfield::from_elem(7, false);
    for signer in signers {
        bitfield.set(signer as usize, true);
    }
    let id = format!("{}", height).as_str().into();
    let prev = match height {
        1 => "genesis".into(),
        _ => format!("{}", height - 1).as_str().into(),
    };
    Certificate {
        inner: Vote {
            view: view.into(),
            block: Block {
                height: height,
                id: id,
                prev: prev,
            },
        },
        signature: AggregateSignature::empty(),
        signers: bitfield,
    }
}

fn valid_block_cert(
    views: Range<u64>,
    heights: Range<u64>,
) -> impl Strategy<Value = Certificate<Vote>> {
    (
        views,
        heights,
        subsequence((0..7).collect::<Vec<Signer>>(), 5),
    )
        .prop_map(|(view, height, signers)| create_valid_cert(view, height, signers))
}

fn valid_propose(views: Range<u64>) -> impl Strategy<Value = Signed<Propose>> {
    (
        views,
        0..7u16,
        subsequence((0..7).collect::<Vec<Signer>>(), 5),
        subsequence((0..7).collect::<Vec<Signer>>(), 5),
    )
        .prop_map(|(view, signer, lock_committee, commit_committee)| {
            let block = Block {
                height: view,
                id: format!("{}", view).as_str().into(),
                prev: match view {
                    1 => "genesis".into(),
                    _ => format!("{}", view - 1).as_str().into(),
                },
            };
            let lock = match view {
                1 => genesis(),
                _ => create_valid_cert(view - 1, view - 1, lock_committee),
            };
            let commit = match view {
                1 | 2 => genesis(),
                _ => create_valid_cert(view - 2, view - 2, commit_committee),
            };
            Signed {
                inner: Propose {
                    view: view.into(),
                    block: block,
                    lock: lock,
                    commit: commit,
                },
                signer: signer,
                signature: Signature::new([0; SIGNATURE_SIZE]),
            }
        })
}

fn vote_strategy1(views: Range<u64>) -> impl Strategy<Value = Signed<Vote>> {
    (views, 1..4u64, 0..10u16).prop_map(|(view, height, signer)| {
        let id = format!("{}", height).as_str().into();
        let prev = match height {
            1 => "genesis".into(),
            _ => format!("{}", height - 1).as_str().into(),
        };
        Signed {
            inner: Vote {
                view: view.into(),
                block: Block {
                    height: height,
                    id: id,
                    prev: prev,
                },
            },
            signer: signer,
            signature: Signature::new([0; SIGNATURE_SIZE]),
        }
    })
}

#[derive(Debug, Clone)]
enum OnDelay {
    Cert(Certificate<Vote>),
    Delay,
}

proptest! {
    #[test]
    fn test_on_wish(msgs in &vec(wish_strategy1(), 100)) {
        let node = node(7, 0..7);
        // assert that
        // - duplicates are ignored
        // - don't generate more than one timeout per view
        // - wishes for current or late views are ignored
        let mut once_per_signer: BTreeSet<(Signer, View)> = BTreeSet::new();
        let mut once_per_view: BTreeSet<View> = BTreeSet::new();
        for wish in msgs {
            let existing = once_per_signer.insert((wish.signer, wish.inner));
            let rst = node.on_wish(wish.clone());
            if !existing {
                assert!(rst.is_err(), "wish {:?} supposed to be rejected", wish);
            }
            if wish.inner == View(0) {
                assert!(rst.is_err(), "wish {:?} supposed to be rejected", wish);
            }
            for ev in node.events().0.borrow_mut().drain(..) {
                match ev {
                    Event::Send(Message::Timeout(timeout), _) => {
                        assert!(once_per_view.insert(timeout.inner), "timeout {:?} was sent twice", timeout);
                    }
                    _ => {
                        assert!(false, "unexpected event: {:?}", ev)
                    },
                }
            }

        }
    }

    #[test]
    fn test_on_timeout(msgs in &vec(timeout_strategy1(),100)) {
        let node = node(7, 0..7);
        let mut max = View(0);
        for timeout in msgs {
            let max_signer = timeout.signers.0.iter().enumerate().filter(|(_, b)| *b).map(|(i, _)| i).max();
            let count = timeout.signers.0.iter().filter(|b| *b).count();
            let rst = node.on_timeout(timeout.clone());
            if timeout.inner <= max {
                assert!(rst.is_err(), "timeout {:?} less than previous max {:?}", timeout, max);
            }
            // 5 is a majority with 7 nodes in total
            if count != 5 {
                assert!(rst.is_err(), "timeout {:?} passed but is not signed by honest majority", timeout);
            }
            // signers are 0-based, hence 6 is a the last signer that participates
            if max_signer > Some(6) {
                assert!(rst.is_err(), "timeout {:?} pass but signer {:?} in the timeout message is not participating", timeout, max_signer);
            }
            if rst.is_ok() {
                max = max.max(timeout.inner);
            }
        }
    }

    #[test]
    fn test_on_synced_certificate(certs in vec(cert_strategy1(), 100)) {
        let node = node(7, 0..7);
        let mut committed = None;
        for cert in certs {
            let _ = node.on_synced_certificate(cert);
            for ev in node.events().0.borrow_mut().drain(..) {
                match ev {
                    Event::StateChange{
                        voted: _,
                        commit,
                        timeout: _,
                        chain,
                    } => {
                        for update in chain {
                            if let Some(commit) = committed {
                                assert!(update.height > commit, "update {:?} can't overwrite committed value", update);
                            }
                        }
                        committed = commit;
                    },
                    _ => {
                        assert!(false, "unexpected event: {:?}", ev)
                    },
                }
            }
        }
    }

    #[test]
    fn test_on_vote(msgs in &vec(prop_oneof![
        1 => valid_timeout_strategy(1..4).prop_map(|timeout| Message::Timeout(timeout)),
        4 => vote_strategy1(1..5).prop_map(|vote| Message::Vote(vote))
    ], 100)) {
        let node = node(7, 0..7);
        let mut entered = View(0);
        let mut valid_votes: BTreeMap<ID, HashSet<Signer>> = BTreeMap::new();
        for msg in msgs {
            match msg {
                Message::Timeout(timeout) => {
                    if timeout.inner > entered {
                        entered = timeout.inner;
                        valid_votes.clear();
                    }
                    let _ = node.on_timeout(timeout);
                },
                Message::Vote(vote) => {
                    if vote.inner.view == entered && vote.signer < 7 {
                        valid_votes.entry(vote.inner.block.id).or_insert(HashSet::new()).insert(vote.signer);
                    }
                    let _ = node.on_vote(vote);
                },
                _ => {
                    assert!(false, "unexpected message: {:?}", msg)
                }
            }
            let events = node.events().0.borrow_mut().drain(..).collect::<Vec<_>>();
            for ev in events {
                match ev {
                    Event::ReadyPropose => {
                        assert!(node.propose(ID::empty()).is_ok(), "propose failed");

                        match node.events().0.borrow_mut().drain(..).next().unwrap() {
                            Event::Send(Message::Propose(proposal), _) => {
                                let votes = valid_votes.get(&proposal.block().prev).unwrap();
                                assert!(votes.len() == 5, "not enough votes for proposal {:?}", proposal);
                            },
                            _ => {
                                assert!(false, "unexpected event: {:?}", ev)
                            }
                        }
                    },
                    _ => {}
                }
            }
        }
    }

    #[test]
    fn test_on_delay(actions in &vec(prop_oneof![
        2 => Just(OnDelay::Delay),
        1 => valid_block_cert(1..7, 1..3).prop_map(|cert| OnDelay::Cert(cert))
    ], 100)) {
        let node = node(7, 0..4);
        for action in actions {
            match action {
                OnDelay::Delay => {
                    let _ = node.on_delay();
                },
                OnDelay::Cert(cert) => {
                    let _ = node.on_synced_certificate(cert);
                }
            }
        }
    }


    #[test]
    fn test_on_propose(proposals in &vec(valid_propose(1..5), 100)) {
        let node = node(7, 0..1);
        let mut voted = View(0);
        for proposal in proposals {
            let _ = node.on_propose(proposal);
            for ev in node.events().0.borrow_mut().drain(..) {
                match ev {
                    Event::Send(Message::Vote(vote), _) => {
                        voted = voted.max(vote.inner.view);
                    },
                    _ => {},
                }
            }
        }
    }
}

pub(crate) struct Model {
    twins: twins::Twins,

    consecutive_advance: usize,
    tracking_progress: HashSet<twins::Node>,

    consensus: HashMap<twins::Node, Node>,
    commit: HashMap<twins::Node, u64>,
    chain: HashMap<twins::Node, BTreeMap<u64, Certificate<Vote>>>,
    timeouts: HashMap<twins::Node, Certificate<View>>,
    inboxes: HashMap<twins::Node, Vec<Message>>,
}

impl Model {
    pub fn new(total: usize, twins: usize) -> Self {
        let twins = twins::Twins::new(total, twins);
        let nodes = twins
            .nodes
            .iter()
            .map(|(n, key)| {
                (
                    *n,
                    Consensus::new(
                        &twins.publics,
                        &[key.clone()],
                        0.into(),
                        0.into(),
                        &vec![genesis()],
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
            commit: HashMap::new(),
            chain: HashMap::new(),
            timeouts: HashMap::new(),
            inboxes: inboxes,
            consecutive_advance: 0,
            tracking_progress: HashSet::new(),
        };
        model
            .step(twins::Op::Advance(pipe::TIMEOUT as usize))
            .unwrap();
        model
    }

    pub fn step(&mut self, op: twins::Op) -> anyhow::Result<()> {
        tracing::trace!("step: {:?}", op);
        match op {
            twins::Op::Routes(partition) => {
                self.twins.install_partition(partition);
                self.sync();
                self.consecutive_advance = 0;
                self.tracking_progress.clear();
            }
            twins::Op::Advance(n) => {
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

    fn last_commit(&self, node: &twins::Node) -> Option<&Certificate<Vote>> {
        let commit = self.commit.get(node).unwrap_or(&0);
        self.chain.get(node).and_then(|chain| chain.get(commit))
    }

    fn sync_from(&mut self, from: &twins::Node, to: &twins::Node) {
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
            let cert = self.chain.get(from).and_then(|certs| certs.get(&height));
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
                tracing::debug_span!("sync", node = ?to).in_scope(|| {
                    if let Err(err) =
                        consensus.on_message(Message::Certificate(cert.unwrap().clone()))
                    {
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
                    if let Err(err) = consensus.on_message(Message::Timeout(timeout)) {
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
            for event in consensus.events().drain() {
                match event {
                    Event::StateChange {
                        voted: _,
                        commit,
                        timeout,
                        chain,
                    } => {
                        if let Some(commit) = commit {
                            tracing::debug!(
                                "{}: node {:?}: commiting {:?}",
                                self.consecutive_advance,
                                id,
                                commit,
                            );
                            self.commit.insert(*id, commit);
                            self.tracking_progress.insert(*id);
                        }
                        if let Some(timeout) = timeout {
                            tracing::debug!(
                                "{}: node {:?}: timeout for view {}",
                                self.consecutive_advance,
                                id,
                                timeout.inner,
                            );
                            self.timeouts.insert(*id, timeout);
                        }
                        for update in chain {
                            tracing::debug!(
                                "{}: node {:?}: updating chain {:?}",
                                self.consecutive_advance,
                                id,
                                update,
                            );
                            self.chain
                                .entry(*id)
                                .or_insert_with(BTreeMap::new)
                                .insert(update.height, update.clone());
                        }
                    }
                    Event::Send(msg, target) => {
                        let is_broadcast = target.is_empty();
                        if !is_broadcast {
                            for target in target {
                                for target in
                                    self.twins.route_to_public_key(id, &target).into_iter()
                                {
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
                    Event::ReadyPropose => {
                        tracing::debug!(
                            "{}: proposing block at node {:?}",
                            self.consecutive_advance,
                            id
                        );
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
                let _ = consensus.on_delay();
            });
        }
    }

    fn verify(&self) -> anyhow::Result<()> {
        let certs = self.commit.iter().map(|(node, height)| {
            if height == &0 {
                return (0, genesis());
            }
            let cert = self
                .chain
                .get(node)
                .expect("btree must be initialized")
                .get(&height)
                .unwrap();
            (*height, cert.clone())
        });
        let mut by_height: HashMap<u64, Certificate<Vote>> = HashMap::new();
        for (height, cert) in certs {
            if let Some(by_height) = by_height.get(&height) {
                anyhow::ensure!(
                    by_height.block == cert.block,
                    "inconsistent commits {:?} != {:?}",
                    by_height,
                    cert
                );
            } else {
                by_height.insert(height, cert.clone());
            }
        }

        if self.consecutive_advance >= 8 * pipe::TIMEOUT as usize {
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

fn init_tracing() {
    let rst = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    assert!(rst.is_ok());
}

#[test]
fn test_debug() {
    init_tracing();
    let scenario = twins::Scenario::parse(
        r#"
        {0, 1, 3/0, 3/1} | {2}
        advance 3
        {0, 1, 2, 3/1} | {3/0}
        advance 3
        {0, 2, 3/0, 3/1} | {1}
        advance 1
        {0, 1, 2, 3/0} | {3/1}
        advance 3
        {3/0, 3/1} | {0, 1, 2}
        advance 5
        {1, 2, 3/0, 3/1} | {0}
        advance 5
        {0, 2, 3/0, 3/1} | {1}
        advance 2
        {0, 1, 3/0, 3/1} | {2}
        advance 7
        {0, 2, 3/0, 3/1} | {1}
        advance 3
        {0, 1, 2, 3/0} | {3/1}
        advance 2
        {0, 1, 3/0} | {2, 3/1}
        advance 15
        {0, 1, 2, 3/1} | {3/0}
        advance 40
        "#,
    )
    .unwrap();
    let mut model = Model::new(4, 1);
    for op in scenario {
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
            4 => (1..4usize).prop_map(twins::Op::Advance),
        ],
        100,
    ).prop_map(|ops| twins::Scenario::new(ops))) {
        let mut model = Model::new(4, 1);
        for op in ops {
            if let Err(err) = model.step(op) {
                assert!(false, "error: {:?}", err);
            }
        }
    }
}
