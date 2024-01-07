use bit_vec::BitVec;

use crate::sequential as seq;
use crate::types::*;

struct Tester {
    keys: Vec<PrivateKey>,
    genesis: Certificate<Vote>,
}

impl Tester {
    fn new(n: usize) -> Self {
        let mut keys: Vec<_> = (0..n).map(|_| PrivateKey::random()).collect();
        keys.sort_by(|a, b| a.public().cmp(&b.public()));

        let genesis = Certificate {
            inner: Vote {
                view: View(0),
                block: Block::new(0, ID::new([0; 32])),
            },
            signature: PrivateKey::random().sign(&[0; 32]).into(),
            signers: BitVec::new(),
        };
        Self { keys, genesis }
    }

    fn genesis(&self) -> Certificate<Vote> {
        self.genesis.clone()
    }

    fn passive(&self) -> seq::Consensus {
        seq::Consensus::new(
            View(0),
            self.publics(),
            self.genesis(),
            self.genesis(),
            View(0),
            &[],
        )
    }

    fn active(&self, i: usize) -> seq::Consensus {
        seq::Consensus::new(
            View(0),
            self.publics(),
            self.genesis(),
            self.genesis(),
            View(0),
            &self.keys[i..i + 1],
        )
    }

    fn leader(&self, view: View) -> Signer {
        let index = view % self.keys.len() as u64;
        index as Signer
    }

    fn sign<T: ToBytes>(&self, _domain: Domain, signer: Signer, message: &T) -> Signature {
        let key = &self.keys[signer as usize];
        key.sign(&message.to_bytes())
    }

    fn publics(&self) -> Vec<PublicKey> {
        self.keys.iter().map(|key| key.public()).collect()
    }

    fn certify<T: ToBytes + Clone>(
        &self,
        domain: Domain,
        signers: Vec<Signer>,
        message: &T,
    ) -> Certificate<T> {
        let signatures = signers
            .iter()
            .map(|signer| self.sign(domain.clone(), *signer, message))
            .collect::<Vec<_>>();
        let aggregated =
            AggregateSignature::aggregate(signatures.iter()).expect("failed to aggregate");
        let mut bitvec = BitVec::from_elem(self.keys.len(), false);
        for signer in signers {
            bitvec.set(signer as usize, true);
        }
        Certificate {
            inner: message.clone(),
            signature: aggregated,
            signers: bitvec,
        }
    }

    fn certify_vote(
        &self,
        view: View,
        height: u64,
        id: &str,
        signers: Vec<Signer>,
    ) -> Certificate<Vote> {
        let vote = Vote {
            view,
            block: {
                let mut _id = [0; 32];
                _id[..id.len()].copy_from_slice(id.as_bytes());
                Block::new(height, ID::new(_id))
            },
        };
        self.certify(Domain::Vote, signers, &vote)
    }

    fn certify_vote2(
        &self,
        view: View,
        height: u64,
        id: &str,
        signers: Vec<Signer>,
    ) -> Certificate<Vote> {
        let vote = Vote {
            view,
            block: {
                let mut _id = [0; 32];
                _id[..id.len()].copy_from_slice(id.as_bytes());
                Block::new(height, ID::new(_id))
            },
        };
        self.certify(Domain::Vote2, signers, &vote)
    }
}

impl Tester {
    fn prepare(&self, view: View, height: u64, id: &str, signers: Vec<Signer>) -> Message {
        let vote = Vote {
            view,
            block: {
                let mut _id = [0; 32];
                _id[..id.len()].copy_from_slice(id.as_bytes());
                Block::new(height, ID::new(_id))
            },
        };
        let certificate = self.certify(Domain::Vote, signers, &vote);
        let prepare = Prepare { certificate };
        let leader = self.leader(view);
        let signature = self.sign(Domain::Prepare, leader, &prepare);
        Message::Prepare(Signed {
            inner: prepare,
            signer: leader,
            signature: signature,
        })
    }

    fn propose_first(&self, view: View, id: &str) -> Message {
        let propose = Propose {
            view,
            block: {
                let mut _id = [0; 32];
                _id[..id.len()].copy_from_slice(id.as_bytes());
                Block::new(1, ID::new(_id))
            },
            locked: self.genesis(),
            double: self.genesis(),
        };
        let leader = self.leader(view);
        let signature = self.sign(Domain::Propose, leader, &propose);
        Message::Propose(Signed {
            inner: propose,
            signer: leader,
            signature: signature,
        })
    }

    fn propose(
        &self,
        view: View,
        height: u64,
        id: &str,
        locked: (View, u64, &str, Vec<Signer>),
        double: (View, u64, &str, Vec<Signer>),
    ) -> Message {
        let block = {
            let mut _id = [0; 32];
            _id[..id.len()].copy_from_slice(id.as_bytes());
            Block::new(height, ID::new(_id))
        };
        let locked = {
            let (view, height, id, signers) = locked;
            let block = {
                let mut _id = [0; 32];
                _id[..id.len()].copy_from_slice(id.as_bytes());
                Block::new(height, ID::new(_id))
            };
            let vote = Vote { view, block };
            self.certify(Domain::Vote, signers, &vote)
        };
        let double = {
            let (view, height, id, signers) = double;
            let block = {
                let mut _id = [0; 32];
                _id[..id.len()].copy_from_slice(id.as_bytes());
                Block::new(height, ID::new(_id))
            };
            let vote = Vote { view, block };
            self.certify(Domain::Vote, signers, &vote)
        };
        let propose = Propose {
            view,
            block,
            locked,
            double,
        };
        let leader = self.leader(view);
        let signature = self.sign(Domain::Propose, leader, &propose);
        Message::Propose(Signed {
            inner: propose,
            signer: leader,
            signature: signature,
        })
    }

    fn vote(&self, view: View, height: u64, id: &str, signer: Signer) -> Message {
        let block = {
            let mut _id = [0; 32];
            _id[..id.len()].copy_from_slice(id.as_bytes());
            Block::new(height, ID::new(_id))
        };
        let vote = Vote { view, block };
        let signature = self.sign(Domain::Vote, signer, &vote);
        Message::Vote(Signed {
            inner: vote,
            signer,
            signature,
        })
    }

    fn vote2(
        &self,
        view: View,
        height: u64,
        id: &str,
        signer: Signer,
        signers: Vec<Signer>,
    ) -> Message {
        let block = {
            let mut _id = [0; 32];
            _id[..id.len()].copy_from_slice(id.as_bytes());
            Block::new(height, ID::new(_id))
        };
        let vote = Vote { view, block };
        let cert = self.certify(Domain::Vote, signers, &vote);
        let signature = self.sign(Domain::Vote2, signer, &vote);
        Message::Vote2(Signed {
            inner: cert,
            signer,
            signature,
        })
    }

    fn wish(&self, view: View, signer: Signer) -> Message {
        let wish = Wish { view };
        let signature = self.sign(Domain::Wish, signer, &wish);
        Message::Wish(Signed {
            inner: wish,
            signer,
            signature,
        })
    }

    fn timeout(&self, view: View, signers: Vec<Signer>) -> Message {
        let certificate = self.certify(Domain::Wish, signers, &view);
        Message::Timeout(Timeout { certificate })
    }

    fn sync_genesis(&self) -> Message {
        Message::Sync(Sync {
            locked: Some(self.genesis()),
            double: Some(self.genesis()),
        })
    }

    fn sync(
        &self,
        locked: Option<(View, u64, &str, Vec<Signer>)>,
        double: Option<(View, u64, &str, Vec<Signer>)>,
    ) -> Message {
        let locked = locked.map(|(view, height, id, signers)| {
            let block = {
                let mut _id = [0; 32];
                _id[..id.len()].copy_from_slice(id.as_bytes());
                Block::new(height, ID::new(_id))
            };
            let vote = Vote { view, block };
            self.certify(Domain::Vote, signers, &vote)
        });
        let double = double.map(|(view, height, id, signers)| {
            let block = {
                let mut _id = [0; 32];
                _id[..id.len()].copy_from_slice(id.as_bytes());
                Block::new(height, ID::new(_id))
            };
            let vote = Vote { view, block };
            self.certify(Domain::Vote, signers, &vote)
        });
        Message::Sync(Sync { locked, double })
    }
}

struct Instance {
    consensus: seq::Consensus,
    signer: Option<Signer>,
}

impl Instance {
    fn on_message(&mut self, message: Message) {
        assert!(self.consensus.on_message(message).is_ok());
    }

    fn on_tick(&mut self) {
        self.consensus.on_tick();
    }

    fn on_delay(&mut self) {
        self.consensus.on_delay();
    }

    fn on_propose(&mut self, id: Option<ID>) {
        assert!(self.consensus.propose(id).is_ok());
    }

    fn action(&mut self, action: seq::Action) {
        assert_eq!(self.consensus.actions.drain(0..1).next(), Some(action));
    }

    fn actions(&mut self, actions: Vec<seq::Action>) {
        for action in actions {
            self.action(action);
        }
    }

    fn no_actions(&mut self) {
        assert_eq!(self.consensus.actions, vec![]);
    }

    fn drain_actions(&mut self) {
        let _ = self.consensus.actions.drain(0..);
    }
}

fn test_nonvoting(f: impl FnOnce(&Tester, &mut Instance)) {
    let cluster = Tester::new(4);
    let mut instance = Instance {
        consensus: cluster.passive(),
        signer: None,
    };
    f(&cluster, &mut instance)
}

fn test_voting(i: usize, f: impl FnOnce(&Tester, &mut Instance)) {
    let cluster = Tester::new(4);
    let mut instance = Instance {
        consensus: cluster.active(i),
        signer: Some(i as u16),
    };
    f(&cluster, &mut instance)
}

fn test_multi(n: usize, f: impl FnOnce(&Tester, &mut Vec<Instance>)) {
    let cluster = Tester::new(n);
    let mut instances = (0..n)
        .map(|i| Instance {
            consensus: cluster.active(i),
            signer: Some(i as u16),
        })
        .collect();
    f(&cluster, &mut instances)
}

#[test]
fn test_nonvoting_sanity() {
    test_nonvoting(|tester, inst: &mut Instance| {
        inst.on_message(tester.timeout(1.into(), vec![0, 1, 2]));
        inst.action(seq::Action::reset_ticks());
        inst.action(seq::Action::wait_delay());
        inst.action(seq::Action::send(tester.sync_genesis()));
        inst.on_message(tester.propose_first(1.into(), "a"));
        inst.action(seq::Action::voted(1.into()));
        inst.on_message(tester.prepare(1.into(), 1, "a", vec![0, 1, 2]));
        inst.action(seq::Action::lock(tester.certify_vote(
            1.into(),
            1,
            "a",
            vec![0, 1, 2],
        )));
        inst.no_actions();
    });
}

#[test]
fn test_voting_sanity() {
    test_voting(0, |tester, inst: &mut Instance| {
        inst.on_message(tester.timeout(1.into(), vec![0, 1, 2]));
        inst.action(seq::Action::reset_ticks());
        inst.action(seq::Action::wait_delay());
        inst.action(seq::Action::send(tester.sync_genesis()));
        inst.on_message(tester.propose_first(1.into(), "a"));
        inst.action(seq::Action::voted(1.into()));

        inst.action(seq::Action::send(tester.vote(
            1.into(),
            1,
            "a",
            inst.signer.unwrap(),
        )));
        inst.on_message(tester.prepare(1.into(), 1, "a", vec![0, 1, 2]));
        inst.action(seq::Action::lock(tester.certify_vote(
            1.into(),
            1,
            "a",
            vec![0, 1, 2],
        )));
        inst.action(seq::Action::send(tester.vote2(
            1.into(),
            1,
            "a",
            inst.signer.unwrap(),
            vec![0, 1, 2],
        )));
    });
}

#[test]
fn test_multi_progress() {
    test_multi(4, |tester, instances| {
        instances.iter_mut().for_each(|i| i.on_tick());
        instances
            .iter_mut()
            .for_each(|i| i.action(seq::Action::send(tester.wish(1.into(), i.signer.unwrap()))));
    })
}
