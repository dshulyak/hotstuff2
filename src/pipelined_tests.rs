use std::{cell::RefCell, collections::BTreeSet, ops::Range};

use proptest::{collection::vec, prelude::*, proptest, sample::subsequence};

use crate::{
    crypto::NoopBackend,
    pipelined::{self, Event, Events, Message},
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

proptest! {
    #[test]
    fn test_on_wish(msgs in &vec(
        (0..5u64, 0..10u16).prop_map(|(view, signer)|
            Signed{
                inner: View(view),
                signer: signer,
                signature: Signature::new([0; SIGNATURE_SIZE]),
            }),
        100,
    )) {
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
    fn test_on_timeout(msgs in &vec(
        (0..10u64, subsequence((0..10).collect::<Vec<Signer>>(), 0..=10)).prop_map(|(view, signers)| {
            let mut bitfield = Bitfield::from_elem(10, false);
            for signer in signers {
                bitfield.set(signer as usize, true);
            }
            Certificate{
                inner: View(view),
                signature: AggregateSignature::empty(),
                signers: bitfield,
            }
        }),
        100,
    )) {
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
}
