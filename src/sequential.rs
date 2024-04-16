use std::collections::{BTreeMap, HashMap};
use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops::Index;

use anyhow::{anyhow, ensure, Ok, Result};
use bit_vec::BitVec;
use parking_lot::Mutex;

use crate::{crypto, types::*};

// TIMEOUT should be sufficient to:
// - 2 delays for a leader to receive latest lock 
//   - participants receive timeout certificate
//   - leader receives all `sync` messages within maximal delay
// - 4 delays to conclude normal round
//   - participants receive propose
//   - leader receves 2f+1 votes on propose
//   - participants receive prepare
//   - leader receives 2f+1 votes on prepare
// - 1 delay for next `propose` to all participants
// single tick atleast 7 maximal network delays.
pub(crate) const TIMEOUT: u8 = 7;
pub(crate) const LEADER_TIMEOUT_DELAY: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateChange {
    // committed certificate can be executed.
    pub commit: Option<Certificate<Vote>>,
    // node should not vote below highest known locked certificate. persisted for safety.
    pub locked: Option<Certificate<Vote>>,
    // latest timeout should be provided to joined participants in order to synchronize views. 
    pub timeout: Option<Certificate<View>>,
    // node should not vote more than once in the view. hence when this even is received it has to be persisted.
    pub voted: Option<View>,
}

impl StateChange {
    fn new() -> Self {
        Self {
            commit: None,
            locked: None,
            voted: None,
            timeout: None
        }
    }

    fn is_empty(&self) -> bool {
        self.commit.is_none() && self.locked.is_none() && self.voted.is_none() && self.timeout.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    StateChange(StateChange),

    // send message, optionally include participant that should receive this message.
    Send(Message, Option<PublicKey>),

    // node is a leader and ready to propose.
    // leader will not finish a round on time if it does not call `propose` method within short delay.
    Propose,
}

pub trait OnMessage {
    fn on_message(&self, message: Message) -> Result<()>;
}

pub trait OnDelay {
    fn on_delay(&self);
}

pub trait Proposer {
    fn propose(&self, block: ID) -> Result<()>;
}

pub trait Actions: Debug {
    fn send(&self, action: Action);
}

#[derive(Debug)]
pub struct Consensus<T: Actions, C: crypto::Backend = crypto::BLSTBackend> {
    // participants must be sorted lexicographically across all participating nodes.
    // used to decode public keys by reference.
    participants: Signers,
    keys: HashMap<Signer, PrivateKey>,
    actions: T,
    state: Mutex<State>,
    crypto: PhantomData<C>,
}

impl<T: Actions, C: crypto::Backend> Consensus<T, C> {
    pub fn new(
        view: View,
        participants: Box<[PublicKey]>,
        lock: Certificate<Vote>,
        commit: Certificate<Vote>,
        voted: View,
        keys: &[PrivateKey],
        actions: T,
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
            keys,
            actions: actions,
            state: Mutex::new(State {
                view,
                voted,
                locked: lock,
                commit,
                proposal: None,
                votes: BTreeMap::new(),
                votes2: BTreeMap::new(),
                timeouts: BTreeMap::new(),
                ticks: 0,
                waiting_delay_view: None,
            }),
            crypto: PhantomData,
        }
    }

    pub fn public_keys(&self) -> impl IntoIterator<Item = (Signer, PublicKey)> + '_ {
        self.keys.iter().map(|(signer, key)| (*signer, key.public()))
    }

    pub fn sink(&self) -> &T {
        &self.actions
    }

    pub(crate) fn is_leader(&self, view: View) -> bool {
        let leader = self.participants.leader(view);
        self.keys.get(&leader).is_some()
    }

    #[cfg(test)]
    pub(crate) fn public_key_by_index(&self, index: Signer) -> PublicKey {
        self.participants[index].clone()
    }

    fn send_all(&self, msg: Message) {
        self.actions.send(Action::Send(msg, None));
    }

    fn send_leader(&self, msg: Message, view: View) {
        self.actions.send(Action::Send(
            msg,
            Some(self.participants.leader_pub_key(view)),
        ));
    }

    fn send_proposal(&self, proposal: Propose) {
        let signer = self.participants.leader(proposal.view);
        let pk = self
            .keys
            .get(&signer)
            .expect("propose shouldn't be called if node is not a leader");
        let signature = C::sign(pk, Domain::Propose, &proposal.to_bytes());
        self.send_all(Message::Propose(Signed {
            inner: proposal,
            signer: signer,
            signature,
        }));
    }

    #[tracing::instrument(skip(self, sync))]
    fn on_sync(&self, sync: Sync) -> Result<()> {
        if let Some(double) = &sync.commit {
            if double.inner.view > View(0) {
                self.verify_certificate(Domain::Vote2, &double.inner, &double.signature, &double.signers)?;
            }
        }
        if let Some(locked) = &sync.locked {
            if locked.inner.view > View(0) {
                self.verify_certificate(Domain::Vote, &locked.inner, &locked.signature, &locked.signers)?;
            }
        }

        let mut state = self.state.lock();
        let mut change = StateChange::new();
        if let Some(locked) = sync.locked {
            if locked.inner.view > state.locked.inner.view {
                state.locked = locked;
                change.locked = Some(state.locked.clone());
            }
        }
        if let Some(commit) = sync.commit {
            // see motivation in on_propose
            // in on_sync we enforce a chain for commit messages
            if commit.inner.block.prev == state.commit.inner.block.id || 
                (commit.inner.block.id == state.commit.inner.block.id && commit.inner.view > state.commit.inner.view)  {
                state.commit = commit;
                change.commit = Some(state.commit.clone());
                let next = state.commit.inner.view + 1;
                if next > state.view {
                    state.enter_view(next);
                }
            }
        }
        if !change.is_empty() {
            self.actions.send(Action::StateChange(change));
        }
        Ok(())
    }

    #[tracing::instrument(
        skip(self, wish), 
        fields(view = %wish.view),
    )]
    fn on_wish(&self, wish: Signed<Wish>) -> Result<()> {
        self.verify_one(Domain::Wish, &wish.inner, &wish.signature, wish.signer)?;

        let wishes = {
            let mut state = self.state.lock();
            ensure!(wish.inner.view > state.view);

            let wishes = state
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
                Some(wishes.clone())
            } else {
                None
            }
        };

        if let Some(wishes) = wishes {
            self.send_all(Message::Timeout(Timeout {
                certificate: Certificate {
                    inner: wishes.message().view,
                    signature: C::aggregate(wishes.signatures())
                        .expect("failed to aggregate signatures"),
                    signers: wishes.signers().into(),
                },
            }));
        }
        Ok(())
    }

    #[tracing::instrument(
        skip(self, timeout), 
        fields(view = %timeout.certificate.inner),
    )]
    fn on_timeout(&self, timeout: Timeout) -> Result<()> {
        self.verify_certificate(
            Domain::Wish, 
            &timeout.certificate.inner, 
            &timeout.certificate.signature, 
            &timeout.certificate.signers,
        )?;

        let mut state = self.state.lock();
        ensure!(timeout.certificate.inner > state.view);
        state.enter_view(timeout.certificate.inner);
        state.wait_first_delay(timeout.certificate.inner);
        self.send_leader(
            Message::Sync(Sync {
                locked: Some(state.locked.clone()),
                commit: Some(state.commit.clone()),
            }),
            state.view,
        );
        self.actions.send(Action::StateChange(StateChange {
            timeout: Some(timeout.certificate),
            ..StateChange::new()
        }));
        Ok(())
    }

    #[tracing::instrument(
        skip(self, propose), 
        fields(view = %propose.view, height = propose.block.height, id = %propose.block.id),
    )]
    fn on_propose(&self, propose: Signed<Propose>) -> Result<()> {
        self.verify_one(Domain::Propose, &propose.inner, &propose.signature, propose.signer)?;
        if propose.inner.locked.inner.view > View(0) {
            self.verify_certificate(
                Domain::Vote, 
                &propose.inner.locked.inner, 
                &propose.inner.locked.signature, 
                &propose.inner.locked.signers,
            )?;
        }
        if propose.inner.commit.inner.view > View(0) {
            self.verify_certificate(
                Domain::Vote2, 
                &propose.inner.commit.inner, 
                &propose.inner.commit.signature, 
                &propose.inner.commit.signers,
            )?;
        }
        let mut change = StateChange::new();
        {
            let mut state = self.state.lock();
            if propose.inner.locked.inner.view > state.locked.inner.view {
                state.locked = propose.inner.locked.clone();
                change.locked = Some(state.locked.clone());
            }
            ensure!(propose.inner.locked.block == state.locked.block, 
                "{:?} != {:?}", propose.inner.locked.block, state.locked.block);

            if propose.inner.commit.inner.view > state.commit.inner.view {
                state.commit = propose.inner.commit.clone();
                change.commit = Some(state.commit.clone());
                let next = state.commit.inner.view + 1;
                if next > state.view {
                    state.enter_view(next);
                }
            }

            ensure!(
                propose.inner.view == state.view,
                "node view {} must be in the same round as propose {}",
                state.view, propose.inner.view,
            );
            ensure!(
                state.voted < propose.inner.view,
                "should not vote more than once in the same view"
            );
            // motivation for the second condition is to acquire commit certificate for every block.
            // in the original protocol i can reach consensus for locked certificate 
            // by forming a certificate on top of the locked certifate that doesn't have commit certificate
            //
            // consider the following chain of certificates, numbers are used for view and letters for block:
            // LOCK(1, A) -> COMMIT(1, A) -> LOCK(2, B) -> LOCK(3, C) -> COMMIT(3, C)
            // as a result whole chain will be committed
            // 
            // instead i require for form commit certificate for every block in history
            // LOCK(1, A) -> COMMIT(1, A) -> LOCK(2, B) -> LOCK(3, B) -> COMMIT(3, B)
            ensure!(
                propose.inner.block.prev == state.locked.inner.block.id || 
                (propose.inner.block.id == state.locked.inner.block.id && propose.inner.view > state.locked.inner.view),
                "proposed block id={} prev={} must extend locked block id={}",
                propose.inner.block.id,
                propose.inner.block.prev,
                state.commit.inner.block.id,
            );

            state.voted = propose.inner.view;
            change.voted = Some(state.voted);
        };
        if !change.is_empty() {
            self.actions.send(Action::StateChange(change));
        }
        self.keys.iter().for_each(|(signer, pk)| {
            let vote = Vote {
                view: propose.inner.view,
                block: propose.inner.block.clone(),
            };
            let signature = C::sign(pk, Domain::Vote, &vote.to_bytes());
            self.send_leader(
                Message::Vote(Signed {
                    inner: vote,
                    signer: *signer,
                    signature,
                }),
                propose.inner.view,
            );
        });
        Ok(())
    }

    #[tracing::instrument(
        skip(self, prepare), 
        fields(view = %prepare.certificate.view, height = prepare.certificate.height, id = %prepare.certificate.id),
    )]
    fn on_prepare(&self, prepare: Signed<Prepare>) -> Result<()> {
        self.verify_one(Domain::Prepare, &prepare.inner, &prepare.signature, prepare.signer)?;
        self.verify_certificate(
            Domain::Vote, 
            &prepare.certificate.inner, 
            &prepare.inner.certificate.signature, 
            &prepare.inner.certificate.signers,
        )?;
        let mut change = StateChange::new();
        {
            let mut state = self.state.lock();
            ensure!(
                prepare.inner.certificate.inner.view == state.view,
                "accepting prepare {:?} only for current view {:?}",
                prepare.inner.certificate.inner.view,
                state.view,
            );
            ensure!(
                prepare.inner.certificate.inner.view > state.locked.inner.view,
                "certificatate {:?} is expected to be of a higher view then currently locked {:?}",
                prepare.inner.certificate.inner.view, state.locked.inner.view,
            );
            state.locked = prepare.inner.certificate.clone();
            change.locked = Some(state.locked.clone());
        }
        if !change.is_empty() {
            self.actions.send(Action::StateChange(change));
        }

        let locked: Certificate<Vote> = prepare.inner.certificate;
        self.keys.iter().for_each(|(signer, pk)| {
            let vote = locked.inner.to_bytes();
            let signature = C::sign(pk, Domain::Vote2, &vote);
            self.send_leader(
                Message::Vote2(Signed {
                    inner: locked.clone(),
                    signer: *signer,
                    signature,
                }),
                locked.inner.view + 1,
            );
        });
        Ok(())
    }

    #[tracing::instrument(
        skip(self, vote), 
        fields(view = %vote.inner.view, height = vote.inner.block.height, id = %vote.inner.block.id),
    )]
    fn on_vote(&self, vote: Signed<Vote>) -> Result<()> {
        self.verify_one(Domain::Vote, &vote.inner, &vote.signature, vote.signer)?;

        let signer = self.participants.leader(vote.inner.view);
        let pk = self
            .keys
            .get(&signer)
            .ok_or_else(|| anyhow!("not a leader in view {:?}", vote.inner.view))?;
        let votes = {
            let mut state = self.state.lock();

            ensure!(vote.inner.view == state.view, "invalid view");
            let votes = state
                .votes
                .entry((vote.inner.view, vote.inner.block.clone()))
                .or_insert_with(|| Votes::new(self.participants.len()));
            ensure!(
                !votes.voted(vote.signer),
                "signer {} already voted", vote.signer,
            );
            votes.add(vote.clone());
            if votes.count() == self.participants.honest_majority() {
                Some(votes.clone())
            } else {
                None
            }
        };

        if let Some(votes) = votes {
            let signature = C::aggregate(votes.signatures())
                .expect("failed to aggregate signatures");
            let cert = Prepare {
                certificate: Certificate {
                    inner: votes.message(),
                    signature: signature.clone(),
                    signers: votes.signers().into(),
                },
            };
            let signature = C::sign(pk, Domain::Prepare, &cert.to_bytes());
            self.send_all(Message::Prepare(Signed {
                inner: cert,
                signer: signer,
                signature,
            }));
        }
        Ok(())
    }

    #[tracing::instrument(
        skip(self, vote), 
        fields(view = %vote.inner.view, height = vote.inner.block.height, id = %vote.inner.block.id),
    )]
    fn on_vote2(&self, vote: Signed<Certificate<Vote>>) -> Result<()> {
        self.verify_one(Domain::Vote2, &vote.inner.inner, &vote.signature, vote.signer)?;
        self.verify_certificate(Domain::Vote, &vote.inner.inner, &vote.inner.signature, &vote.inner.signers)?;

        ensure!(
            self.keys
                .get(&self.participants.leader(vote.inner.view + 1))
                .is_some(),
            "not a leader in view {:?}",
            vote.inner.view + 1
        );

        let votes = {
            let mut state = self.state.lock();
            ensure!(
                vote.inner.view == state.view,
                "vote view {:?} not equal to local view {:?}",
                vote.inner.view,
                state.view
            );
            let votes = state
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
                Some(votes.clone())
            } else {
                None
            }
        };
        if let Some(votes) = votes {
            let cert = Certificate {
                inner: votes.message().inner.clone(),
                signature: C::aggregate(votes.signatures())
                    .expect("failed to aggregate signatures"),
                signers: votes.signers().into(),
            };
            self.state.lock().proposal = Some(Propose {
                view: cert.view + 1,
                block: Block {
                    height: cert.height + 1,
                    prev: cert.id,
                    id: ID::default(),
                },
                locked: votes.message().clone(),
                commit: cert,
            });
            self.actions.send(Action::Propose);
        }
        Ok(())
    }

    #[tracing::instrument(skip(self, signed, signature))]
    fn verify_one(&self, domain: Domain, signed: &impl ToBytes, signature: &Signature, signer: Signer) -> Result<()> {
        ensure!(
            signer < self.participants.len() as u16,
            "invalid signer index {:?}",
            signer
        );
        C::verify(domain, &self.participants[signer], signature, &signed.to_bytes())
    }

    #[tracing::instrument(skip(self, signed, signature, signers))]
    fn verify_certificate(&self, domain: Domain, signed: &impl ToBytes, signature: &AggregateSignature, signers: &BitVec) -> Result<()> {
        ensure!(
            signers.iter().filter(|b| *b).count() == self.participants.honest_majority(),
            "must be signed by honest majority"
        );
        C::verify_aggregated(domain, self.participants.decode(&signers),signature, &signed.to_bytes())
    }
}

impl<T: Actions, C: crypto::Backend> OnDelay for Consensus<T, C> {
    fn on_delay(&self) {
        let rst = {
            let mut state = self.state.lock();
            state.ticks += 1;
            if state.ticks == TIMEOUT {
                state.ticks = 0;
                if state.is_epoch_boundary(self.participants.atleast_one_honest() as u64) {
                    (
                        None,
                        Some(Wish {
                            view: state.view + 1,
                        }),
                    )
                } else {
                    let next = state.view + 1;
                    state.enter_view(next);
                    state.wait_first_delay(next);
                    self.send_leader(
                        Message::Sync(Sync {
                            locked: Some(state.locked.clone()),
                            commit: Some(state.commit.clone()),
                        }),
                        next,
                    );
                    (None, None)
                }
            } else if state.ticks == LEADER_TIMEOUT_DELAY
                && state.is_waiting(state.view)
                && self.is_leader(state.view)
            {
                state.waiting_delay_view = None;
                // i want to obtain double certificate on every block.
                // therefore i extend locked if it is equal to double, otherwise i retry locked block.
                if state.locked.inner != state.commit.inner {
                    (
                        Some(Propose {
                            view: state.view,
                            block: state.locked.inner.block.clone(),
                            locked: state.locked.clone(),
                            commit: state.commit.clone(),
                        }),
                        None,
                    )
                } else {
                    state.proposal = Some(Propose {
                        view: state.view,
                        block: Block {
                            height: state.commit.inner.block.height + 1,
                            prev: state.commit.inner.block.id,
                            id: ID::default(), // will be overwritten in propose method
                        },
                        locked: state.locked.clone(),
                        commit: state.commit.clone(),
                    });
                    self.actions.send(Action::Propose);
                    (None, None)
                }
            } else {
                (None, None)
            }
        };
        match rst {
            (Some(proposal), None) => self.send_proposal(proposal),
            (None, Some(wish)) => {
                for (signer, pk) in self.keys.iter() {
                    let signature = C::sign(pk, Domain::Wish, &wish.to_bytes());
                    // TODO this should target f+1 nodes rather then everyone
                    self.send_all(
                        Message::Wish(Signed {
                            inner: wish.clone(),
                            signer: *signer,
                            signature,
                        }),
                    );
                }
            }
            _ => (),
        }
    }
}

impl<T: Actions, C: crypto::Backend> OnMessage for Consensus<T, C> {
    fn on_message(&self, message: Message) -> Result<()> {
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
}

impl<T: Actions, C: crypto::Backend> Proposer for Consensus<T, C> {
    #[tracing::instrument(
        skip(self), 
        fields(id = %id),
    )]
    fn propose(&self, id: ID) -> Result<()> {
        let proposal = {
            let mut proposal = self.state.lock().take_proposal()?;
            proposal.block.id = id;
            Ok(proposal)
        }?;
        self.send_proposal(proposal);
        Ok(())
    }
}

#[derive(Debug)]
struct State {
    // current view
    view: View,
    // last voted view
    voted: View,
    // single certificate from 2/3*f+1 Vote. initialized to genesis
    locked: Certificate<Vote>,
    // double certificate from 2/3*f+1 Vote2. initialized to genesis
    commit: Certificate<Vote>,
    // to aggregate propose and prepare votes
    // key is view, type of the vote, signer
    // TODO this structs do not allow to easily spot equivocation
    votes: BTreeMap<(View, Block), Votes<Vote>>,
    votes2: BTreeMap<(View, Block), Votes<Certificate<Vote>>>,
    timeouts: BTreeMap<View, Votes<Wish>>,
    // after leader is ready to send a proposal it notifies caller to produce a block without blocking state machine.
    // once block is ready the identifier is passed to `propose` method
    proposal: Option<Propose>,

    ticks: u8,
    waiting_delay_view: Option<View>,
}

impl State {
    fn is_epoch_boundary(&self, threshold: u64) -> bool {
        self.view % threshold == 0
    }

    fn enter_view(&mut self, view: View) {
        tracing::debug!(view=%view, current=%self.view, "enter view");
        self.view = view;
        self.ticks = 0;
        self.timeouts.retain(|view, _| view >= &self.view);
        self.votes.retain(|(view, _), _| view >= &self.view);
        self.votes2.retain(|(view, _), _| view >= &self.view);
    }

    fn wait_first_delay(&mut self, view: View) {
        self.waiting_delay_view = Some(view);
    }

    fn is_waiting(&self, view: View) -> bool {
        if let Some(current) = self.waiting_delay_view {
            current == view
        } else {
            false
        }
    }

    fn take_proposal(&mut self) -> Result<Propose> {
        let proposal = self.proposal.take().ok_or_else(|| anyhow!("no proposal"))?;
        ensure!(
            proposal.view >= self.view,
            "proposal wasn't built in time. proposal view {:?}. current view {:?} ticks {}",
            proposal.view,
            self.view,
            self.ticks,
        );
        Ok(proposal)
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

    fn leader_pub_key(&self, view: View) -> PublicKey {
        self[self.leader(view)].clone()
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
        self.signers().iter().filter(|b| *b).count()
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
