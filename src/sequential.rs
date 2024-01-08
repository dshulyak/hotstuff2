use crate::types::*;

use anyhow::{anyhow, ensure, Result};
use bit_vec::BitVec;
use std::collections::{BTreeMap, HashMap};
use std::fmt::Debug;
use std::ops::Index;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    // persist the following data before sending messages
    // committed certificate can be executed.
    Commit(Certificate<Vote>),
    // latest locked certificate has to be durable for safety.
    Lock(Certificate<Vote>),
    // node should not vote more than once in the view. persisted for safety.
    Voted(View),

    // send message to all participants
    Send(Message),
    // send message to a specific participant
    SendTo(Message, PublicKey),

    // wait single network delay
    WaitDelay(),
    // reset ticks
    ResetTicks(),

    // node is a leader and ready to propose
    // when this action received call Consensus::propose()
    // TODO consider notifying a node that it is a leader in the next view after it voted
    Propose(),
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

    pub fn send_to(message: Message, to: PublicKey) -> Self {
        Action::SendTo(message, to)
    }

    pub fn wait_delay() -> Self {
        Action::WaitDelay()
    }

    pub fn reset_ticks() -> Self {
        Action::ResetTicks()
    }

    pub fn propose() -> Self {
        Action::Propose()
    }
}

pub struct Consensus {
    // current view
    view: View,
    next_tick: View,
    // last voted view
    voted: View,
    // participants must be sorted lexicographically across all participating nodes.
    // used to decode public keys by reference.
    participants: Signers,
    // single certificate from 2/3*f+1 Vote. initialized to genesis
    locked: Certificate<Vote>,
    // double certificate from 2/3*f+1 Vote2. initialized to genesis
    double: Certificate<Vote>,
    keys: HashMap<PublicKey, PrivateKey>,
    // to aggregate propose and prepare votes
    // key is view, type of the vote, signer
    // TODO this structs do not allow to easily spot equivocation
    votes: BTreeMap<(View, Block), Votes<Vote>>,
    votes2: BTreeMap<(View, Block), Votes<Certificate<Vote>>>,
    timeouts: BTreeMap<View, Votes<Wish>>,

    proposal: Option<Propose>,

    pub actions: Vec<Action>,
}

impl Consensus {
    pub fn new(
        view: View,
        participants: Vec<PublicKey>,
        lock: Certificate<Vote>,
        commit: Certificate<Vote>,
        voted: View,
        keys: &[PrivateKey],
    ) -> Self {
        debug_assert!(participants.len() >= 4);
        Self {
            view,
            next_tick: View(0),
            participants: Signers(participants),
            locked: lock,
            double: commit,
            actions: Vec::new(),
            voted,
            keys: keys.iter().map(|key| (key.public(), key.clone())).collect(),
            proposal: None,
            votes: BTreeMap::new(),
            votes2: BTreeMap::new(),
            timeouts: BTreeMap::new(),
        }
    }
}

impl Consensus {
    pub fn is_leader(&self, view: View) -> bool {
        let leader = self.participants.leader(view);
        self.keys.get(leader.1).is_some()
    }

    pub fn on_tick(&mut self) {
        if self.next_tick <= self.view && self.view != View(0) {
            return;
        }
        if self.is_epoch_boundary() {
            // execute view synchronization protocol
            for (id, pk) in self.keys.iter() {
                if let Some(i) = self.participants.0.iter().position(|p| p == id) {
                    let wish = Wish {
                        view: self.view + 1,
                    };
                    let signature = pk.sign(Domain::Wish, &wish.to_bytes());
                    self.actions.push(Action::Send(Message::Wish(Signed {
                        inner: wish,
                        signer: i as u16,
                        signature,
                    })));
                }
            }
        } else {
            self.enter_view(self.next_tick);
            self.wait_delay();
            self.next_tick += 1;
        }
    }

    pub fn on_delay(&mut self) {
        if self
            .keys
            .get(self.participants.leader(self.view).1)
            .is_none()
        {
            return;
        }
        // unlike the paper, i want to obtain double certificate on every block.
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
            self.actions.push(Action::Propose());
        };
    }

    pub fn propose(&mut self, id: Option<ID>) -> Result<()> {
        let mut proposal = self.proposal.take().ok_or(anyhow!("no proposal"))?;
        ensure!(proposal.view >= self.view, "proposal wasn't built in time");
        if let Some(id) = id {
            proposal.block.id = id;
        }
        let leader = self.participants.leader(proposal.view);
        let key = self
            .keys
            .get(leader.1)
            .ok_or(anyhow!("no key for a view leader"))?;
        let signature = key.sign(Domain::Propose, &proposal.to_bytes());
        self.actions.push(Action::Send(Message::Propose(Signed {
            inner: proposal,
            signer: leader.0,
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
        if let Some(double) = sync.double {
            if double.block.height == self.double.inner.block.height + 1 {
                double.signature.verify(
                    Domain::Vote2,
                    &double.inner.block.to_bytes(),
                    self.participants.decode(&double.signers),
                )?;
                self.double = double;
                self.actions.push(Action::Commit(self.double.clone()));
            }
        }
        if let Some(locked) = sync.locked {
            if locked.view > self.locked.view {
                locked.signature.verify(
                    Domain::Vote,
                    &locked.inner.block.to_bytes(),
                    self.participants.decode(&locked.signers),
                )?;
                self.locked = locked;
                self.actions.push(Action::Lock(self.locked.clone()));
            }
        }
        Ok(())
    }

    fn on_wish(&mut self, wish: Signed<Wish>) -> Result<()> {
        ensure!(wish.inner.view > self.view, "old view");
        ensure!(
            wish.signer < self.participants.len() as u16,
            "invalid signer"
        );
        wish.signature.verify(
            Domain::Wish,
            &wish.inner.to_bytes(),
            &self.participants[wish.signer],
        )?;

        let wishes = self
            .timeouts
            .entry(wish.inner.view)
            .or_insert_with(|| Votes::new(self.participants.len()));
        wishes.add(wish)?;

        if wishes.count() >= self.participants.honest_majority() {
            self.actions.push(Action::Send(Message::Timeout(Timeout {
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
        ensure!(timeout.certificate.inner > self.view, "old view");
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
        ensure!(
            (self.locked.inner.view == View(0) && propose.inner.locked.inner.view == View(0))
                || propose.inner.locked.signers.iter().filter(|b| *b).count()
                    == self.participants.honest_majority(),
            "locked signed by more than 2/3 participants"
        );
        ensure!(
            (self.double.inner.view == View(0) && propose.inner.double.inner.view == View(0))
                || propose.inner.double.signers.iter().filter(|b| *b).count()
                    == self.participants.honest_majority(),
            "double signed by more than 2/3 participants"
        );
        propose.signature.verify(
            Domain::Propose,
            &propose.inner.to_bytes(),
            &self.participants[propose.signer],
        )?;
        if propose.inner.locked.view > View(0) {
            propose.inner.locked.signature.verify(
                Domain::Vote,
                &propose.inner.locked.inner.to_bytes(),
                self.participants.decode(&propose.inner.locked.signers),
            )?;
        }
        if propose.inner.double.view > View(0) {
            propose.inner.double.signature.verify(
                Domain::Vote2,
                &propose.inner.double.inner.to_bytes(),
                self.participants.decode(&propose.inner.double.signers),
            )?;
        }

        if propose.inner.locked.view > self.locked.view {
            self.locked = propose.inner.locked.clone();
            self.actions.push(Action::Lock(self.locked.clone()));
        }
        if propose.inner.double.view > self.double.view {
            self.double = propose.inner.double.clone();
            self.actions.push(Action::Commit(self.double.clone()));
            self.enter_view(self.double.inner.view + 1);
        }

        ensure!(propose.inner.locked == self.locked);
        ensure!(propose.inner.double == self.double);
        ensure!(propose.inner.view == self.view);
        ensure!(
            self.voted < propose.inner.view,
            "already voted in this view"
        );
        ensure!(
            propose.inner.block.height == self.double.inner.block.height + 1,
            "proposed block height {:?} must be one after the commited block {:?}",
            propose.inner.block.height,
            self.double.inner.block.height,
        );

        self.voted = propose.inner.view;
        self.actions.push(Action::Voted(self.voted));
        for (public, private) in self.keys.iter() {
            if let Ok(i) = self.participants.binary_search(public) {
                let vote = Vote {
                    view: propose.inner.view.clone(),
                    block: propose.inner.block.clone(),
                };
                let signature = private.sign(Domain::Vote, &vote.to_bytes());
                self.actions.push(Action::Send(Message::Vote(Signed {
                    inner: vote,
                    signer: i as Signer,
                    signature,
                })));
            }
        }

        Ok(())
    }

    fn on_prepare(&mut self, prepare: Signed<Prepare>) -> Result<()> {
        ensure!(
            prepare.signer < self.participants.len() as u16,
            "invalid signer {:?}",
            prepare.signer,
        );
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
        prepare.signature.verify(
            Domain::Prepare,
            &prepare.inner.to_bytes(),
            &self.participants[prepare.signer],
        )?;
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
        self.actions.push(Action::Lock(self.locked.clone()));

        for (public, private) in self.keys.iter() {
            if let Ok(i) = self.participants.binary_search(public) {
                let vote = self.locked.inner.clone();
                let signature = private.sign(Domain::Vote2, &vote.to_bytes());
                self.actions.push(Action::Send(Message::Vote2(Signed {
                    inner: self.locked.clone(),
                    signer: i as Signer,
                    signature,
                })));
            }
        }
        Ok(())
    }

    fn on_vote(&mut self, vote: Signed<Vote>) -> Result<()> {
        let (leader, public) = self.participants.leader(self.view);
        let key = self
            .keys
            .get(public)
            .ok_or_else(|| anyhow!("not a leader in view {:?}", self.view))?;
        ensure!(vote.inner.view == self.view, "invalid view");
        ensure!(
            vote.signer < self.participants.len() as u16,
            "invalid signer"
        );
        vote.signature.verify(
            Domain::Vote,
            &vote.to_bytes(),
            &self.participants[vote.signer],
        )?;

        let votes = self
            .votes
            .entry((vote.inner.view, vote.inner.block.clone()))
            .or_insert_with(|| Votes::new(self.participants.len()));
        if !votes.sent {
            votes.add(vote)?;
        }
        if !votes.sent && votes.count() == self.participants.honest_majority() {
            votes.sent = true;
            let signature = AggregateSignature::aggregate(votes.signatures())
                .expect("failed to aggregate signatures");
            let cert = Prepare {
                certificate: Certificate {
                    inner: votes.message(),
                    signature: signature.clone(),
                    signers: votes.signers(),
                },
            };
            let signature = key.sign(Domain::Prepare, &cert.to_bytes());
            self.actions.push(Action::Send(Message::Prepare(Signed {
                inner: cert,
                signer: leader,
                signature,
            })));
        }
        Ok(())
    }

    fn on_vote2(&mut self, vote: Signed<Certificate<Vote>>) -> Result<()> {
        ensure!(
            self.keys
                .get(self.participants.leader(self.view + 1).1)
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
        ensure!(
            vote.signer < self.participants.len() as u16,
            "invalid signer index {:?}",
            vote.signer
        );
        let signed = &vote.inner.inner;
        vote.signature.verify(
            Domain::Vote2,
            &signed.to_bytes(),
            &self.participants[vote.signer],
        )?;

        let votes = self
            .votes2
            .entry((vote.inner.view, vote.inner.block.clone()))
            .or_insert_with(|| Votes::new(self.participants.len()));
        if votes.count() == 0 {
            ensure!(
                vote.inner.signers.iter().filter(|b| *b).count()
                    == self.participants.honest_majority(),
                "must be signed by honest majority"
            );
            vote.inner.signature.verify(
                Domain::Vote,
                &signed.to_bytes(),
                self.participants.decode(&vote.inner.signers),
            )?;
        }
        if !votes.sent {
            votes.add(vote)?;
        }
        if !votes.sent && votes.count() == self.participants.honest_majority() {
            votes.sent = true;
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
            self.actions.push(Action::Propose());
        }
        Ok(())
    }

    fn is_epoch_boundary(&self) -> bool {
        self.view % self.participants.atleast_one_honest() as u64 == 0
    }

    fn enter_view(&mut self, view: View) {
        if self.view % self.participants.atleast_one_honest() as u64 == 0 {
            self.next_tick = self.view + 1;
            self.actions.push(Action::ResetTicks());
        }
        self.view = view;
        self.timeouts.retain(|view, _| view >= &self.view);
        self.votes.retain(|(view, _), _| view >= &self.view);
        self.votes2.retain(|(view, _), _| view >= &self.view);
    }

    fn wait_delay(&mut self) {
        self.actions.push(Action::WaitDelay());
        self.actions.push(Action::Send(Message::Sync(Sync {
            locked: Some(self.locked.clone()),
            double: Some(self.double.clone()),
        })));
    }
}

struct Signers(Vec<PublicKey>);

impl Signers {
    fn decode<'a>(&'a self, bits: &'a BitVec) -> impl IntoIterator<Item = Result<&'a PublicKey>> {
        bits.iter().enumerate().filter(|(_, b)| *b).map(|(i, _)| {
            if i < self.0.len() {
                Ok(&self.0[i])
            } else {
                Err(anyhow!("invalid signer"))
            }
        })
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn binary_search(&self, key: &PublicKey) -> Result<usize, usize> {
        self.0.binary_search(key)
    }

    fn atleast_one_honest(&self) -> usize {
        self.0.len() / 3 + 1
    }

    fn honest_majority(&self) -> usize {
        self.0.len() * 2 / 3 + 1
    }

    fn leader(&self, view: View) -> (Signer, &PublicKey) {
        let i = view % self.0.len() as u64;
        (i as Signer, &self[i as u16])
    }
}

impl Index<u16> for Signers {
    type Output = PublicKey;
    fn index(&self, index: u16) -> &Self::Output {
        &self.0[index as usize]
    }
}

impl Index<u64> for Signers {
    type Output = PublicKey;
    fn index(&self, index: u64) -> &Self::Output {
        &self.0[index as usize]
    }
}

struct Votes<T: ToBytes + Clone + Debug> {
    signers: BitVec,
    votes: Vec<Signed<T>>,
    pub sent: bool,
}

impl<T: ToBytes + Clone + Debug> Votes<T> {
    fn new(n: usize) -> Self {
        Self {
            signers: BitVec::from_elem(n, false),
            votes: Vec::new(),
            sent: false,
        }
    }

    fn add(&mut self, vote: Signed<T>) -> Result<()> {
        ensure!(
            self.signers.get(vote.signer as usize).is_some(),
            "bit vector length is too small for signer {:?}",
            vote.signer,
        );
        ensure!(
            self.signers.get(vote.signer as usize).map_or(false, |b| !b),
            "vote already registered {:?}",
            vote,
        );
        self.signers.set(vote.signer as usize, true);
        self.votes.push(vote);
        Ok(())
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
