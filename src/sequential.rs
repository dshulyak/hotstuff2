use crate::types::*;

use anyhow::{anyhow, ensure, Result};
use bit_vec::BitVec;

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt::Debug;
use std::ops::Index;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    // persist the following data before sending messages.
    // committed certificate can be executed.
    Commit(Certificate<Vote>),
    // node should not vote below highest known locked certificate. persisted for safety.
    Lock(Certificate<Vote>),
    // node should not vote more than once in the view. persisted for safety.
    Voted(View),

    // send message to all participants
    Send(Message),
    // TODO
    // // send message to a specific participant. some messages may be delievered directly for aggregation purposes.
    // SendTo(Message, PublicKey),

    // TODO this can be futher simplified. caller can notify every maximal network delay
    // without waiting for any signals from the consensus SM.
    // consensus SM internally can count 7 notifications (see below), and reset them every time it enters a view.

    // wait single network delay. see below what is expected.
    WaitDelay,
    // reset timers. single tick should be sufficient to finish consensus round.
    // - wait delay for leader to receive sync messages. during this delay leader needs to delive timeout certificate
    //   and obtain sync messages from all honest participants. should be equal to two maximal network delays.
    // - wait for 4 normal rounds, each one atleast one maximal network delay.
    // - wait for 1 more to deliver propose to all participants, so that they enter next view.
    // single tick atleast 7 maximal network delays.
    EnteredView(View),

    // node is a leader and ready to propose.
    // leader is risking not finishing a round on time if it does not call `propose` method within short delay.
    Propose,
}

impl Action {
    pub fn commit(certificate: Certificate<Vote>) -> Self {
        Action::Commit(certificate)
    }

    pub fn lock(certificate: Certificate<Vote>) -> Self {
        Action::Lock(certificate)
    }

    pub fn voted(view: View) -> Self {
        Action::Voted(view)
    }

    pub fn send(message: Message) -> Self {
        Action::Send(message)
    }

    pub fn wait_delay() -> Self {
        Action::WaitDelay
    }

    pub fn entered_view(view: View) -> Self {
        Action::EnteredView(view)
    }

    pub fn propose() -> Self {
        Action::Propose
    }
}

#[derive(Debug, Clone)]
pub struct Consensus {
    // participants must be sorted lexicographically across all participating nodes.
    // used to decode public keys by reference.
    participants: Signers,
    keys: HashMap<Signer, PrivateKey>,

    // current view
    view: View,
    // last voted view
    voted: View,
    // single certificate from 2/3*f+1 Vote. initialized to genesis
    locked: Certificate<Vote>,
    // double certificate from 2/3*f+1 Vote2. initialized to genesis
    double: Certificate<Vote>,
    // to aggregate propose and prepare votes
    // key is view, type of the vote, signer
    // TODO this structs do not allow to easily spot equivocation
    votes: BTreeMap<(View, Block), Votes<Vote>>,
    votes2: BTreeMap<(View, Block), Votes<Certificate<Vote>>>,
    timeouts: BTreeMap<View, Votes<Wish>>,
    // after leader is ready to send a proposal it emulates asynchronous upcall
    // and waits for a identifier of the payload
    proposal: Option<Propose>,
    actions: VecDeque<Action>,
}

impl Consensus {
    pub fn new(
        view: View,
        participants: Box<[PublicKey]>,
        lock: Certificate<Vote>,
        commit: Certificate<Vote>,
        voted: View,
        keys: &[PrivateKey],
    ) -> Self {
        let keys = keys
            .iter()
            .map(|key| {
                (
                    participants.binary_search(&key.public()).unwrap() as Signer,
                    key.clone(),
                )
            })
            .collect();
        Self {
            participants: Signers(participants),
            keys: keys,
            view,
            locked: lock,
            double: commit,
            actions: VecDeque::new(),
            voted,
            proposal: None,
            votes: BTreeMap::new(),
            votes2: BTreeMap::new(),
            timeouts: BTreeMap::new(),
        }
    }

    pub fn consume_actions(&mut self, mut f: impl FnMut(Action)) {
        while let Some(action) = self.actions.pop_front() {
            f(action);
        }
    }

    pub fn drain_actions(&mut self) -> impl Iterator<Item = Action> + '_ {
        self.actions.drain(..)
    }

    pub fn is_leader(&self, view: View) -> bool {
        let leader = self.participants.leader(view);
        self.keys.get(&leader).is_some()
    }

    pub fn on_tick(&mut self) {
        if self.is_epoch_boundary() {
            // view will be advanced once leader aggregates timeout certificate from wishes.
            for (signer, pk) in self.keys.iter() {
                let wish = Wish {
                    view: self.view + 1,
                };
                let signature = pk.sign(Domain::Wish, &wish.to_bytes());
                self.actions.push_back(Action::Send(Message::Wish(Signed {
                    inner: wish,
                    signer: *signer,
                    signature,
                })));
            }
        } else {
            self.enter_view(self.view + 1);
            self.wait_delay();
        }
    }

    pub fn on_delay(&mut self) {
        if self
            .keys
            .get(&self.participants.leader(self.view))
            .is_none()
        {
            return;
        }
        // unlike in the paper, i want to obtain double certificate on every block.
        // therefore i extend locked if it is equal to double, otherwise i retry locked block.
        if self.locked.inner != self.double.inner {
            self.proposal = Some(Propose {
                view: self.view,
                block: self.locked.inner.block.clone(),
                locked: self.locked.clone(),
                double: self.double.clone(),
            });
            self.propose(None).expect("failed to propose block");
        } else {
            self.proposal = Some(Propose {
                view: self.view,
                block: Block {
                    height: self.double.inner.block.height + 1,
                    id: ID::default(),
                },
                locked: self.locked.clone(),
                double: self.double.clone(),
            });
            self.actions.push_back(Action::Propose);
        };
    }

    pub fn propose(&mut self, id: Option<ID>) -> Result<()> {
        let mut proposal = self.proposal.take().ok_or_else(|| anyhow!("no proposal"))?;
        ensure!(proposal.view >= self.view, "proposal wasn't built in time");
        if let Some(id) = id {
            proposal.block.id = id;
        }
        let signer = self.participants.leader(proposal.view);
        let pk = self
            .keys
            .get(&signer)
            .expect("propose shouldn't be called if node is not a leader");
        let signature = pk.sign(Domain::Propose, &proposal.to_bytes());
        self.actions
            .push_back(Action::Send(Message::Propose(Signed {
                inner: proposal,
                signer: signer,
                signature,
            })));
        Ok(())
    }

    pub fn on_message(&mut self, message: Message) -> Result<()> {
        match message {
            Message::Sync(sync) => self.on_sync(sync),
            Message::Prepare(prepare) => self.on_prepare(prepare),
            Message::Vote(vote) => self.on_vote(vote),
            Message::Propose(propose) => self.on_propose(propose),
            Message::Vote2(vote) => self.on_vote2(vote),
            Message::Wish(wish) => self.on_wish(wish),
            Message::Timeout(timeout) => self.on_timeout(timeout),
        }
    }

    fn on_sync(&mut self, sync: Sync) -> Result<()> {
        if let Some(double) = &sync.double {
            ensure!(double.signers.len() <= self.participants.len());
            if double.view > View(0) {
                double.signature.verify(
                    Domain::Vote2,
                    &double.inner.to_bytes(),
                    self.participants.decode(&double.signers),
                )?;
            }
        }
        if let Some(locked) = &sync.locked {
            ensure!(locked.signers.len() <= self.participants.len());
            if locked.view > View(0) {
                locked.signature.verify(
                    Domain::Vote,
                    &locked.inner.to_bytes(),
                    self.participants.decode(&locked.signers),
                )?;
            }
        }
        if let Some(locked) = sync.locked {
            if locked.view > self.locked.view {
                self.locked = locked;
                self.actions.push_back(Action::Lock(self.locked.clone()));
            }
        }
        if let Some(double) = sync.double {
            if double.block.height == self.double.inner.block.height + 1 {
                self.double = double;
                self.actions.push_back(Action::Commit(self.double.clone()));
                self.enter_view(self.double.inner.view + 1);
            }
        }
        Ok(())
    }

    fn on_wish(&mut self, wish: Signed<Wish>) -> Result<()> {
        ensure!(
            wish.signer < self.participants.len() as u16,
            "invalid signer"
        );
        wish.signature.verify(
            Domain::Wish,
            &wish.inner.to_bytes(),
            &self.participants[wish.signer],
        )?;

        ensure!(wish.inner.view > self.view, "old view");

        let wishes = self
            .timeouts
            .entry(wish.inner.view)
            .or_insert_with(|| Votes::new(self.participants.len()));
        ensure!(
            !wishes.voted(wish.signer),
            "signer {} already casted wish for view {:?}",
            wish.signer,
            wish.inner.view,
        );
        wishes.add(wish);
        if wishes.count() == self.participants.honest_majority() {
            self.actions
                .push_back(Action::Send(Message::Timeout(Timeout {
                    certificate: Certificate {
                        inner: wishes.message().view,
                        signature: AggregateSignature::aggregate(wishes.signatures())
                            .expect("failed to aggregate signatures"),
                        signers: wishes.signers(),
                    },
                })));
        }
        Ok(())
    }

    fn on_timeout(&mut self, timeout: Timeout) -> Result<()> {
        ensure!(timeout.certificate.signers.len() <= self.participants.len());
        ensure!(
            timeout.certificate.signers.iter().filter(|b| *b).count()
                == self.participants.honest_majority(),
            "must be signed exactly by an honest majority: {:?}",
            self.participants.honest_majority(),
        );
        timeout.certificate.signature.verify(
            Domain::Wish,
            &timeout.certificate.inner.to_bytes(),
            self.participants.decode(&timeout.certificate.signers),
        )?;

        ensure!(timeout.certificate.inner > self.view, "old view");
        self.enter_view(timeout.certificate.inner);
        self.wait_delay();
        Ok(())
    }

    fn on_propose(&mut self, propose: Signed<Propose>) -> Result<()> {
        // signature checks. should be executed before acquiring locks on state.
        ensure!(
            propose.signer < self.participants.len() as u16,
            "signer identifier is out of bounds"
        );
        propose.signature.verify(
            Domain::Propose,
            &propose.inner.to_bytes(),
            &self.participants[propose.signer],
        )?;
        if propose.inner.locked.inner.view > View(0) {
            ensure!(propose.inner.locked.signers.len() <= self.participants.len());
            ensure!(
                propose.inner.locked.signers.iter().filter(|b| *b).count()
                    == self.participants.honest_majority(),
                "locked signed by more than 2/3 participants"
            );
            propose.inner.locked.signature.verify(
                Domain::Vote,
                &propose.inner.locked.inner.to_bytes(),
                self.participants.decode(&propose.inner.locked.signers),
            )?;
        }
        if propose.inner.double.inner.view > View(0) {
            ensure!(propose.inner.double.signers.len() <= self.participants.len());
            ensure!(
                propose.inner.double.signers.iter().filter(|b| *b).count()
                    == self.participants.honest_majority(),
                "double signed by more than 2/3 participants"
            );
            propose.inner.double.signature.verify(
                Domain::Vote2,
                &propose.inner.double.inner.to_bytes(),
                self.participants.decode(&propose.inner.double.signers),
            )?;
        }

        if propose.inner.locked.view > self.locked.view {
            self.locked = propose.inner.locked.clone();
            self.actions.push_back(Action::Lock(self.locked.clone()));
        }
        ensure!(
            propose.inner.locked.inner.view == self.locked.inner.view,
            "proposed block must use cert no lower then locally locked block"
        );

        if propose.inner.double.view > self.double.view {
            self.double = propose.inner.double.clone();
            self.actions.push_back(Action::Commit(self.double.clone()));
            self.enter_view(self.double.inner.view + 1);
        }
        ensure!(
            propose.inner.double.inner == self.double.inner,
            "propose must extend known highest doubly certified block"
        );

        ensure!(
            propose.inner.view == self.view,
            "node must be in the same round as propose"
        );
        ensure!(
            self.voted < propose.inner.view,
            "should not vote more than once in the same view"
        );
        ensure!(
            propose.inner.block.height == self.double.inner.block.height + 1,
            "proposed block height {:?} must be one after the commited block {:?}",
            propose.inner.block.height,
            self.double.inner.block.height,
        );

        self.voted = propose.inner.view;
        self.actions.push_back(Action::Voted(self.voted));
        self.keys.iter().for_each(|(signer, pk)| {
            let vote = Vote {
                view: propose.inner.view.clone(),
                block: propose.inner.block.clone(),
            };
            let signature = pk.sign(Domain::Vote, &vote.to_bytes());
            self.actions.push_back(Action::Send(Message::Vote(Signed {
                inner: vote,
                signer: *signer,
                signature,
            })));
        });
        Ok(())
    }

    fn on_prepare(&mut self, prepare: Signed<Prepare>) -> Result<()> {
        ensure!(
            prepare.signer < self.participants.len() as u16,
            "invalid signer {:?}",
            prepare.signer,
        );
        prepare.signature.verify(
            Domain::Prepare,
            &prepare.inner.to_bytes(),
            &self.participants[prepare.signer],
        )?;

        ensure!(prepare.inner.certificate.signers.len() <= self.participants.len());
        ensure!(
            prepare
                .inner
                .certificate
                .signers
                .iter()
                .filter(|b| *b)
                .count()
                == self.participants.honest_majority(),
            "must be signed by honest majority"
        );
        prepare.inner.certificate.signature.verify(
            Domain::Vote,
            &prepare.certificate.inner.to_bytes(),
            self.participants.decode(&prepare.inner.certificate.signers),
        )?;

        ensure!(
            prepare.inner.certificate.inner.view == self.view,
            "accepting prepare only for view {:?}",
            self.view,
        );
        ensure!(
            prepare.inner.certificate.inner.view > self.locked.inner.view,
            "certificatate for old view {:?}",
            prepare.inner.certificate.inner.view,
        );
        self.locked = prepare.inner.certificate.clone();
        self.actions.push_back(Action::Lock(self.locked.clone()));

        let locked: Certificate<Vote> = prepare.inner.certificate;
        self.keys.iter().for_each(|(signer, pk)| {
            let vote = locked.inner.to_bytes();
            let signature = pk.sign(Domain::Vote2, &vote);
            self.actions.push_back(Action::Send(Message::Vote2(Signed {
                inner: locked.clone(),
                signer: *signer,
                signature,
            })));
        });
        Ok(())
    }

    fn on_vote(&mut self, vote: Signed<Vote>) -> Result<()> {
        ensure!(
            vote.signer < self.participants.len() as u16,
            "invalid signer"
        );
        vote.signature.verify(
            Domain::Vote,
            &vote.to_bytes(),
            &self.participants[vote.signer],
        )?;

        ensure!(vote.inner.view == self.view, "invalid view");
        let signer = self.participants.leader(self.view);
        let pk = self
            .keys
            .get(&signer)
            .ok_or_else(|| anyhow!("not a leader in view {:?}", self.view))?;

        let votes = self
            .votes
            .entry((vote.inner.view, vote.inner.block.clone()))
            .or_insert_with(|| Votes::new(self.participants.len()));
        ensure!(
            !votes.voted(vote.signer),
            "signer {} already voted",
            vote.signer,
        );
        votes.add(vote.clone());
        if votes.count() == self.participants.honest_majority() {
            let signature = AggregateSignature::aggregate(votes.signatures())
                .expect("failed to aggregate signatures");
            let cert = Prepare {
                certificate: Certificate {
                    inner: votes.message(),
                    signature: signature.clone(),
                    signers: votes.signers(),
                },
            };
            let signature = pk.sign(Domain::Prepare, &cert.to_bytes());
            self.actions
                .push_back(Action::Send(Message::Prepare(Signed {
                    inner: cert,
                    signer: signer,
                    signature,
                })));
        }
        Ok(())
    }

    fn on_vote2(&mut self, vote: Signed<Certificate<Vote>>) -> Result<()> {
        ensure!(
            vote.signer < self.participants.len() as u16,
            "invalid signer index {:?}",
            vote.signer
        );
        vote.signature.verify(
            Domain::Vote2,
            &vote.inner.inner.to_bytes(),
            &self.participants[vote.signer],
        )?;
        ensure!(
            vote.inner.signers.iter().filter(|b| *b).count() == self.participants.honest_majority(),
            "must be signed by honest majority"
        );
        vote.inner.signature.verify(
            Domain::Vote,
            &vote.inner.inner.to_bytes(),
            self.participants.decode(&vote.inner.signers),
        )?;

        ensure!(
            self.keys
                .get(&self.participants.leader(self.view + 1))
                .is_some(),
            "not a leader in view {:?}",
            self.view + 1
        );
        ensure!(
            vote.inner.view == self.view,
            "vote view {:?} not equal to local view {:?}",
            vote.inner.view,
            self.view
        );

        let votes = self
            .votes2
            .entry((vote.inner.view, vote.inner.block.clone()))
            .or_insert_with(|| Votes::new(self.participants.len()));
        ensure!(
            !votes.voted(vote.signer),
            "signer {} already voted",
            vote.signer
        );
        votes.add(vote);
        if votes.count() == self.participants.honest_majority() {
            let cert = Certificate {
                inner: votes.message().inner.clone(),
                signature: AggregateSignature::aggregate(votes.signatures())
                    .expect("failed to aggregate signatures"),
                signers: votes.signers(),
            };
            self.proposal = Some(Propose {
                view: cert.view + 1,
                block: Block {
                    height: cert.height + 1,
                    id: ID::default(),
                },
                locked: votes.message().clone(),
                double: cert,
            });
            self.actions.push_back(Action::Propose);
        }
        Ok(())
    }

    fn is_epoch_boundary(&self) -> bool {
        self.view % self.participants.atleast_one_honest() as u64 == 0
    }

    fn enter_view(&mut self, view: View) {
        self.view = view;
        self.timeouts.retain(|view, _| view >= &self.view);
        self.votes.retain(|(view, _), _| view >= &self.view);
        self.votes2.retain(|(view, _), _| view >= &self.view);
        self.actions.push_back(Action::EnteredView(self.view));
    }

    fn wait_delay(&mut self) {
        // it will be more optimal to output it only if this node
        // is not a leader in the next view
        self.actions.push_back(Action::WaitDelay);
        self.actions.push_back(Action::Send(Message::Sync(Sync {
            locked: Some(self.locked.clone()),
            double: Some(self.double.clone()),
        })));
    }
}

#[derive(Debug, Clone)]
struct Signers(Box<[PublicKey]>);

impl Signers {
    fn decode<'a>(&'a self, bits: &'a BitVec) -> impl IntoIterator<Item = &'a PublicKey> {
        bits.iter()
            .enumerate()
            .filter(|(_, b)| *b)
            .map(|(i, _)| &self.0[i])
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn atleast_one_honest(&self) -> usize {
        self.0.len() / 3 + 1
    }

    fn honest_majority(&self) -> usize {
        self.0.len() * 2 / 3 + 1
    }

    fn leader(&self, view: View) -> Signer {
        let i = view % self.0.len() as u64;
        i as Signer
    }
}

impl Index<u16> for Signers {
    type Output = PublicKey;
    fn index(&self, index: u16) -> &Self::Output {
        &self.0[index as usize]
    }
}

#[derive(Debug, Clone)]
struct Votes<T: ToBytes + Clone + Debug> {
    signers: BitVec,
    votes: Vec<Signed<T>>,
}

impl<T: ToBytes + Clone + Debug> Votes<T> {
    fn new(n: usize) -> Self {
        Self {
            signers: BitVec::from_elem(n, false),
            votes: Vec::new(),
        }
    }

    fn voted(&self, signer: Signer) -> bool {
        self.signers.get(signer as usize).map_or(false, |b| b)
    }

    fn add(&mut self, vote: Signed<T>) {
        self.signers.set(vote.signer as usize, true);
        self.votes.push(vote);
    }

    fn count(&self) -> usize {
        self.signers.iter().filter(|b| *b).count()
    }

    fn signers(&self) -> BitVec {
        self.signers.clone()
    }

    fn signatures<'a>(&'a self) -> impl IntoIterator<Item = &'a Signature> {
        self.votes.iter().map(|v| &v.signature)
    }

    fn message(&self) -> T {
        self.votes[0].inner.clone()
    }
}
