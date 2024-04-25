use std::{
    collections::{BTreeMap, HashMap}, fmt, marker::PhantomData
};

use anyhow::{anyhow, bail, ensure, Result, Context};
use parking_lot::Mutex;

use crate::{
    common::{Participants, Votes},
    crypto,
    types::{
        AggregateSignature, Bitfield, Block, Certificate, Domain, PrivateKey, PublicKey, Signature,
        Signed, Signer, ToBytes, View, Vote, ID,
    },
};

// TIMEOUT is composed from 5 maximal network delays in order to give sufficient amount of time
// for a leader to make progress:
// - delay to deliver aggregated timeout message to all participants
// - delay to gather highest certificates
// - delay to deliver proposals
// - delay to gather votes
// - delay to send proposal for the next round, that will reset delay counter
pub(crate) const TIMEOUT: u8 = 5;
// after two delays we expect to receive highest certificate and will be ready to create proposal
pub(crate) const LEADER_TIMEOUT_DELAY: u8 = 2;

#[derive(Debug, Clone)]
pub enum Message {
    Certificate(Certificate<Vote>),
    Propose(Signed<Propose>),
    Vote(Signed<Vote>),
    Wish(Signed<View>),
    Timeout(Certificate<View>),
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Message::Certificate(cert) => write!(f, "cert height={:?} view={:?} id={}", 
                cert.height, cert.view, cert.block.id),
            Message::Propose(propose) => write!(f, "propose height={:?} view={:?} id={}", 
                propose.block.height, propose.view, propose.block.id),
            Message::Vote(vote) => write!(f, "vote height={:?} view={:?} id={} signer={:?}", 
                vote.block.height, vote.view, vote.block.id, vote.signer),
            Message::Wish(wish) => write!(f, "wish view={:?} signer={:?}", wish.inner, wish.signer),
            Message::Timeout(timeout) => write!(f, "timeout view={:?}", timeout.inner),
        }
    }
}

#[derive(Debug)]
pub enum Event {
    StateChange {
        voted: Option<View>,
        // commit points to the certificate in the vector
        commit: Option<u64>,
        timeout: Option<Certificate<View>>,
        // certificate are ordered by height where blocks extend each other
        chain: Vec<Certificate<Vote>>,
    },
    ReadyPropose,
    Send(Message, Vec<PublicKey>),
}

pub trait Events {
    fn new() -> Self;

    fn send(&self, event: Event);
}

#[derive(Debug, Clone)]
pub struct Propose {
    pub view: View,
    pub block: Block,
    pub lock: Certificate<Vote>,
    pub commit: Certificate<Vote>,
}

impl Propose {
    pub fn block(&self) -> &Block {
        &self.block
    }
}

impl ToBytes for Propose {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![];
        buf.extend_from_slice(&self.view.to_bytes());
        buf.extend_from_slice(&self.block.to_bytes());
        buf.extend_from_slice(&self.lock.to_bytes());
        buf.extend_from_slice(&self.commit.to_bytes());
        buf
    }
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

pub trait EventsAccess<EVENTS: Events>{
    fn events(&self) -> &EVENTS;
}

#[derive(Debug)]
pub struct Consensus<EVENTS: Events, CRYPTO: crypto::Backend = crypto::BLSTBackend> {
    participants: Participants,
    keys: HashMap<Signer, PrivateKey>,
    state: Mutex<State>,
    crypto: PhantomData<CRYPTO>,
    events: EVENTS,
}

impl<EVENTS: Events, CRYPTO: crypto::Backend> Consensus<EVENTS, CRYPTO> {
    pub fn new(
        participants: &[PublicKey],
        keys: &[PrivateKey],
        view: View,
        voted: View,
        chain: &[Certificate<Vote>],
    ) -> Self {
        let mut participants: Participants = participants.into();
        participants.ensure_sorted();
        let keys = keys
            .iter()
            .map(|key| {
                (
                    participants.binary_search(&key.public()).unwrap() as Signer,
                    key.clone(),
                )
            })
            .collect();
        let committed = chain.first().map_or(0, |cert| cert.height);
        let chain = chain
            .into_iter()
            .map(|cert| (cert.height, cert.clone()))
            .collect();
        Self {
            participants,
            keys,
            state: Mutex::new(State {
                view: view,
                voted: voted,
                votes: BTreeMap::new(),
                timeouts: BTreeMap::new(),
                committed: committed,
                chain: chain,
                proposal: None,
                ticks: 0,
                waiting_delay_view: None,
            }),
            events: EVENTS::new(),
            crypto: PhantomData,
        }
    }

    pub fn public_keys(&self) -> impl IntoIterator<Item = (Signer, PublicKey)> + '_ {
        self.keys.iter().map(|(signer, key)| (*signer, key.public()))
    }

    #[tracing::instrument(
        skip(self, cert), 
        fields(view = ?cert.view, height = cert.block.height),
    )]
    pub(crate) fn on_synced_certificate(&self, cert: Certificate<Vote>) -> Result<()> {
        self.verify_certificate(Domain::Vote, &cert.inner, &cert.signature, &cert.signers)?;

        let mut state = self.state.lock();
        let last_cert: &Certificate<Vote> = state.chain.last_key_value().map(|(_, cert)| cert).unwrap();
        ensure!(cert.view > last_cert.view);
        let dependency = state.chain.get(&(cert.height - 1));
        ensure!(dependency.is_some());
        let dependency = dependency.unwrap();
        ensure!(dependency.block.id == cert.block.prev);

        let commit = if cert.view == dependency.view + 1 && dependency.view != View(0) {
            Some(dependency.height)
        } else {
            None
        };
        self.events.send(
            Event::StateChange {
                voted: None,
                timeout: None,
                commit: commit,
                chain: vec![cert.clone()],
            }
        );
        if cert.view + 1 > state.view {
            state.enter_view(cert.view+1);
        }
        state.update_chain(cert, commit);
        Ok(())
    }

    #[tracing::instrument(
        skip(self, propose), 
        fields(view = ?propose.view, signer = propose.signer, height = propose.block.height),
    )]
    pub(crate) fn on_propose(&self, propose: Signed<Propose>) -> Result<()> {
        tracing::debug!(propose = ?propose, "received propose");
        ensure!(propose.signer == self.participants.leader(propose.view));
        self.verify_one(Domain::Propose, &propose.inner, &propose.signature, propose.signer)?;
        if propose.block.height > 1 {
            ensure!(propose.block.height == propose.lock.height + 1);
            ensure!(propose.block.prev == propose.lock.id);
            self.verify_certificate(Domain::Vote, &propose.lock.inner, &propose.lock.signature, &propose.lock.signers)?;
        }
        if propose.block.height > 2 {
            ensure!(propose.lock.height == propose.commit.height + 1);
            ensure!(propose.lock.block.prev == propose.commit.block.id);
            if !self.state.lock().is_known_cert(&propose.commit) {
                self.verify_certificate(Domain::Vote, &propose.commit.inner, &propose.commit.signature, &propose.commit.signers)?;
            }
        }
        
        let (commit, update) = {
            let mut state = self.state.lock();

            if propose.lock.view + 1 > state.view {
                state.enter_view(propose.lock.view + 1);
            }
            ensure!(propose.view == state.view);
            ensure!(propose.view > state.voted);
            
            let last_cert = state.chain.last_key_value().map(|(_, cert)| cert).unwrap();
            ensure!(propose.lock.view >= last_cert.view);

            let mut update = vec![];
            if !state.is_known_cert(&propose.commit) {
                update.push(propose.commit.clone());
                state.update_chain(propose.commit.clone(), None);
            }
            let commit = if propose.commit.view + 1 == propose.lock.view {
                Some(propose.commit.height)
            } else {
                None
            };
            if propose.lock.view > View(1) {
                update.push(propose.lock.clone());
                state.update_chain(propose.lock.clone(), commit.clone());
            }

            state.voted = propose.view;
            (commit, update)
        };
        self.events.send(
            Event::StateChange {
                voted: Some(propose.view),
                commit: commit,
                chain: update,
                timeout: None,
            }
        );

        let vote = Vote {
            view: propose.view,
            block: propose.block.clone(),
        };
        let to_sign = &vote.to_bytes();
        self.keys.iter().for_each(|(signer, pk)| {
            self.send_leader(
                Message::Vote(Signed {
                    inner: vote.clone(),
                    signer: *signer,
                    signature: CRYPTO::sign(pk, Domain::Vote, to_sign),
                }),
                propose.view + 1,
            );
        });
        Ok(())
    }

    #[tracing::instrument(
        skip(self, vote), 
        fields(view = ?vote.inner.view, signer = vote.signer, height = vote.inner.height),
    )]
    pub(crate) fn on_vote(&self, vote: Signed<Vote>) -> Result<()> {
        ensure!(vote.view == self.state.lock().view);
        self.verify_one(Domain::Vote, &vote.inner, &vote.signature, vote.signer)?;

        let votes = {
            let mut state = self.state.lock();

            let last_cert = state.chain.last_key_value().map(|(_, cert)| cert).unwrap();
            ensure!(vote.block.height == last_cert.block.height + 1);
            ensure!(vote.block.prev == last_cert.block.id);

            let entry = state
                .votes
                .entry((vote.view, vote.block.clone()))
                .or_insert_with(|| Some(Votes::new(self.participants.len())));
            match entry {
                Some(votes) => {
                    votes.add(vote)?;
                    if votes.count() == self.participants.honest_majority() {
                        entry.take()
                    } else {
                        None
                    }
                },
                None => bail!("votes for view {:?} were already aggregated", vote.view),
            }
        };
    
        if let Some(votes) = votes {
            let cert = Certificate {
                inner: votes.message(),
                signature: CRYPTO::aggregate(votes.signatures()).expect("aggregate signatures"),
                signers: votes.signers().into(),
            };
            let mut state = self.state.lock();
            let prev_cert = state.chain
                .get(&(cert.height - 1))
                .expect("commit certificate is never pruned from the chain")
                .clone();

            tracing::debug!(
                view=%cert.inner.view, height=%cert.height, 
                prev=%prev_cert.inner.view, prev_height=%prev_cert.height, 
                "aggregated certificate",
            );

            state.proposal = Some(Propose{
                view: cert.view + 1,
                block: Block { height: cert.block.height+1, prev: cert.block.id, id: ID::default() },
                lock: cert,
                commit: prev_cert,
            });
            self.events.send(Event::ReadyPropose);
        }
        Ok(())
    }

    #[tracing::instrument(skip(self, wish), fields(view = ?wish.inner, signer = wish.signer))]
    pub fn on_wish(&self, wish: Signed<View>) -> Result<()> {
        ensure!(wish.inner > self.state.lock().view);
        self.verify_one(Domain::Wish, &wish.inner, &wish.signature, wish.signer)?;
        let wishes = {
            let mut state = self.state.lock();
            let entry = state
                .timeouts
                .entry(wish.inner)
                .or_insert_with(|| Some(Votes::new(self.participants.len())));
            match entry {
                None => bail!("timeout for view {:?} was already aggregated", wish.inner),
                Some(wishes) => {
                    wishes.add(wish)?;
                    if wishes.count() == self.participants.honest_majority() {
                        entry.take()
                    } else {
                        None
                    }
                },
            }
        };
        if let Some(wishes) = wishes {
            self.send_all(Message::Timeout(Certificate {
                inner: wishes.message(),
                signature: CRYPTO::aggregate(wishes.signatures()).expect("aggregate signatures"),
                signers: wishes.signers().into(),
            }));
        }
        Ok(())
    }

    #[tracing::instrument(skip(self, timeout), fields(view = ?timeout.inner))]
    pub(crate) fn on_timeout(&self, timeout: Certificate<View>) -> Result<()> {
        ensure!(timeout.inner > self.state.lock().view);
        self.verify_certificate(Domain::Wish, &timeout.inner, &timeout.signature, &timeout.signers)?;

        let mut state = self.state.lock();
        ensure!(timeout.inner > state.view);
        state.enter_view(timeout.inner);
        if self.is_leader(timeout.inner) {
            state.wait_delay(timeout.inner);
        } else {
            self.send_certs_to_leader(&mut state);
        }
        self.events.send(Event::StateChange{
            timeout: Some(timeout.clone()),
            voted: None,
            commit: None,
            chain: vec![],
        });
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    fn on_delay(&self) {
        let action = {
            let mut state = self.state.lock();
            state.ticks += 1;
            if state.ticks == TIMEOUT {
                state.ticks = 0;
                if state.is_epoch_boundary(self.participants.atleast_one_honest()) {
                    Some(state.view + 1)
                } else {
                    let next = state.view + 1;
                    state.enter_view(next);
                    state.wait_delay(next);
                    if self.is_leader(next) {
                        state.wait_delay(next);
                    } else {
                        self.send_certs_to_leader(&mut state);
                    }
                    None
                }
            } else if state.ticks == LEADER_TIMEOUT_DELAY && self.is_leader(state.view) && state.is_waiting_delay(state.view) {
                let last_cert = state.chain.last_key_value().map(|(_, cert)| cert).unwrap();
                let pre_last_cert = if last_cert.height == 0 {
                    last_cert
                } else {
                    state.chain.get(&(last_cert.height - 1)).expect("last certificate is always in the chain")
                };
                state.proposal = Some(Propose{
                    view: state.view,
                    block: Block { height: last_cert.height + 1, prev: last_cert.block.id, id: ID::default() },
                    lock: last_cert.clone(),
                    commit: pre_last_cert.clone(),
                });
                self.events.send(Event::ReadyPropose);
                None
            } else {
                None
            }
        };
        if let Some(view) = action {
            // we do it here so that signing is done without holding the state lock
            let to_sign = &view.to_bytes();
            self.keys.iter().for_each(|(signer, pk)| {
                self.send_all(Message::Wish(Signed {
                    inner: view,
                    signer: *signer,
                    signature: CRYPTO::sign(pk, Domain::Wish, to_sign),
                }));
            });
        }
    }

    #[tracing::instrument(skip(self))]
    fn propose(&self, id: ID) -> Result<()> {
        let mut proposal = self.state.lock().take_proposal()?;
        proposal.block.id = id;
        self.send_proposal(proposal);
        Ok(())
    }

    #[tracing::instrument(skip(self, signed, signature))]
    fn verify_one(
        &self,
        domain: Domain,
        signed: &impl ToBytes,
        signature: &Signature,
        signer: Signer,
    ) -> Result<()> {
        ensure!(
            signer < self.participants.len() as u16,
            "invalid signer index {:?}",
            signer
        );
        CRYPTO::verify(
            domain,
            &self.participants[signer],
            signature,
            &signed.to_bytes(),
        )
    }

    #[tracing::instrument(skip(self, signed, signature, signers))]
    fn verify_certificate(
        &self,
        domain: Domain,
        signed: &impl ToBytes,
        signature: &AggregateSignature,
        signers: &Bitfield,
    ) -> Result<()> {
        ensure!(
            signers.count() == self.participants.honest_majority(),
            "must be signed by honest majority"
        );
        CRYPTO::verify_aggregated(
            domain,
            self.participants.decode(&signers),
            signature,
            &signed.to_bytes(),
        ).context("aggregated signature verification")
    }

    fn send_all(&self, msg: Message) {
        self.events.send(Event::Send(msg, vec![]));
    }

    fn send_leader(&self, msg: Message, view: View) {
        self.events.send(Event::Send(
            msg,
            vec![self.participants.leader_pub_key(view)],
        ));
    }

    fn send_proposal(&self, proposal: Propose) {
        let signer = self.participants.leader(proposal.view);
        let pk = self
            .keys
            .get(&signer)
            .expect("propose shouldn't be called if node is not a leader");
        let signature = CRYPTO::sign(pk, Domain::Propose, &proposal.to_bytes());
        self.send_all(Message::Propose(Signed {
            inner: proposal,
            signer,
            signature,
        }));
    }

    fn is_leader(&self, view: View) -> bool {
        self.keys.get(&self.participants.leader(view)).is_some()
    }

    fn send_certs_to_leader(&self, state: &mut State) {
        match state.chain.last_key_value().map(|(height, _)| *height).unwrap_or(0) {
            0 => {},
            1 => {
                let last_cert = state.chain.get(&1).unwrap();
                self.send_leader(Message::Certificate(last_cert.clone()), state.view);
            },
            last => {
                let prev_cert = state.chain.get(&(last - 1)).unwrap();
                let last_cert = state.chain.get(&last).unwrap();
                self.send_leader(Message::Certificate(prev_cert.clone()), state.view);
                self.send_leader(Message::Certificate(last_cert.clone()), state.view);
            }
        };
    }
}

impl<EVENTS: Events, CRYPTO: crypto::Backend> Proposer for Consensus<EVENTS, CRYPTO> {
    fn propose(&self, block: ID) -> Result<()> {
        self.propose(block)
    }
}

impl<EVENTS: Events, CRYPTO: crypto::Backend> OnDelay for Consensus<EVENTS, CRYPTO> { 
    fn on_delay(&self) {
        self.on_delay();
    }
}

impl<EVENTS: Events, CRYPTO: crypto::Backend> OnMessage for Consensus<EVENTS, CRYPTO> {
    fn on_message(&self, msg: Message) -> Result<()> {
        match msg {
            Message::Certificate(cert) => self.on_synced_certificate(cert),
            Message::Propose(propose) => self.on_propose(propose),
            Message::Vote(vote) => self.on_vote(vote),
            Message::Wish(wish) => self.on_wish(wish),
            Message::Timeout(timeout) => self.on_timeout(timeout),
        }
    }
}

impl<EVENTS: Events, CRYPTO: crypto::Backend> EventsAccess<EVENTS> for Consensus<EVENTS, CRYPTO> {
    fn events(&self) -> &EVENTS {
        &self.events
    }
}

#[derive(Debug)]
struct State {
    view: View,
    voted: View,
    votes: BTreeMap<(View, Block), Option<Votes<Vote>>>,
    timeouts: BTreeMap<View, Option<Votes<View>>>,
    committed: u64,
    // chain contains certificates starting from committed to the last known certificate
    // it must overwrite everything after update height, for example:
    // chain contains certificates for heights 10, 11, 12. committed is 10.
    // if certificate 11 is overwritten, 12 must be removed as well.
    chain: BTreeMap<u64, Certificate<Vote>>,

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
    }

    fn wait_delay(&mut self, view: View) {
        self.waiting_delay_view = Some(view);
    }

    fn is_waiting_delay(&self, view: View) -> bool {
        if let Some(current) = self.waiting_delay_view {
            current == view
        } else {
            false
        }
    }

    fn update_chain(&mut self, cert: Certificate<Vote>, commit: Option<u64>) {
        tracing::debug!(view=%cert.view, height=%cert.block.height, block=%cert.block.id, "update chain");
        let cert_height = cert.height;
        self.chain.insert(cert_height, cert);
        if let Some(commit) = commit {
            self.committed = commit;
            self.chain.retain(|height, _| height >= &commit);
        }
        self.chain.retain(|height, _| height <= &height);
    }

    fn is_known_cert(&self, cert: &Certificate<Vote>) -> bool {
        self.chain.get(&cert.height).map_or(false, |local_cert| local_cert == cert)
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