use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet, HashSet},
    ops::Range,
};

use proptest::{collection::vec, prelude::*, proptest, sample::subsequence};

use crate::{
    crypto::NoopBackend,
    pipelined::{self, Event, Events, Message, Propose},
    types::{
        AggregateSignature, Bitfield, Block, Certificate, PrivateKey, Signature, Signed, Signer,
        View, Vote, ID, SIGNATURE_SIZE,
    },
};

struct VecEvents(RefCell<Vec<Event>>);

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

type Node = pipelined::Consensus<VecEvents, NoopBackend>;

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
