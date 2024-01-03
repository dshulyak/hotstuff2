use ::blst::{min_pk::AggregatePublicKey, BLST_ERROR};
use bit_vec::BitVec;
use blake3;
use blst::min_pk as blst;
use std::{
    collections::{BTreeMap, HashMap},
    hash,
    ops::{Add, AddAssign, Rem},
};

type ID = blake3::Hash;

pub trait ToBytes {
    fn to_bytes(&self) -> Vec<u8>;
}

pub trait FromBytes {
    fn from_bytes(bytes: &[u8]) -> Self;
}

#[derive(Clone, PartialEq)]
pub struct Block {
    pub height: u64,
    pub id: ID,
    pub prev: ID,
}

impl ToBytes for Block {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.height.to_le_bytes());
        bytes.extend_from_slice(self.id.as_bytes());
        bytes.extend_from_slice(self.prev.as_bytes());
        bytes
    }
}

pub struct Propose {
    pub view: View,
    pub block: Block,
    pub locked: Certificate<Vote>,
    pub double: Certificate<Vote>,
}

impl ToBytes for Propose {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.view.to_bytes());
        bytes.extend_from_slice(&self.block.to_bytes());
        bytes.extend_from_slice(&self.locked.to_bytes());
        bytes.extend_from_slice(&self.double.to_bytes());
        bytes
    }
}

pub struct Prepare {
    pub certificate: Certificate<Vote>,
}

impl ToBytes for Prepare {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.certificate.to_bytes());
        bytes
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey(blst::PublicKey);

impl hash::Hash for PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(&self.0.to_bytes());
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.0.to_bytes().cmp(&other.0.to_bytes()))
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.to_bytes().cmp(&other.0.to_bytes())
    }
}

#[derive(Clone)]
pub struct AggregateSignature(blst::AggregateSignature);

impl AggregateSignature {
    pub fn aggregate<'a>(
        signatures: impl IntoIterator<Item = &'a Signature>,
    ) -> Result<Self, ::blst::BLST_ERROR> {
        let signature = blst::AggregateSignature::aggregate(
            &signatures.into_iter().map(|sig| &sig.0).collect::<Vec<_>>(),
            false,
        )?;
        Ok(AggregateSignature(signature))
    }

    pub fn verify<'a>(
        &self,
        message: &[u8],
        public_keys: impl IntoIterator<Item = &'a PublicKey>,
    ) -> ::blst::BLST_ERROR {
        let public = AggregatePublicKey::aggregate(
            &public_keys.into_iter().map(|pk| &pk.0).collect::<Vec<_>>(),
            true,
        );
        match public {
            Ok(public) => {
                self.0
                    .to_signature()
                    .verify(true, message, &[], &[], &public.to_public_key(), true)
            }
            Err(e) => e,
        }
    }
}

impl Into<Signature> for AggregateSignature {
    fn into(self) -> Signature {
        Signature(self.0.to_signature())
    }
}

impl ToBytes for AggregateSignature {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_signature().to_bytes().to_vec()
    }
}

pub struct PrivateKey(blst::SecretKey);

impl PrivateKey {
    fn sign(&self, message: &[u8]) -> Signature {
        Signature(self.0.sign(message, &[], &[]))
    }
}

pub struct Signature(blst::Signature);

impl ToBytes for Signature {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
}

impl Signature {
    fn verify(&self, message: &[u8], public_key: &PublicKey) -> ::blst::BLST_ERROR {
        self.0.verify(true, message, &[], &[], &public_key.0, true)
    }
}

#[derive(Clone)]
pub struct Certificate<T: ToBytes> {
    pub message: T,
    pub signature: AggregateSignature,
    pub signers: BitVec,
}

impl<T: ToBytes> ToBytes for Certificate<T> {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.message.to_bytes());
        bytes.extend_from_slice(&self.signature.to_bytes());
        bytes.extend_from_slice(&self.signers.to_bytes());
        bytes
    }
}

#[derive(Clone, PartialEq)]
pub struct Vote {
    pub view: View,
    pub block: Block,
}

impl ToBytes for Vote {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.view.to_bytes());
        bytes.extend_from_slice(&self.block.to_bytes());
        bytes
    }
}

#[derive(Clone)]
pub struct Wish {
    pub view: View,
}

impl ToBytes for Wish {
    fn to_bytes(&self) -> Vec<u8> {
        self.view.to_bytes()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct View(u64);

impl ToBytes for View {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_le_bytes().to_vec()
    }
}

impl Add<u64> for View {
    type Output = View;

    fn add(self, rhs: u64) -> Self::Output {
        View(self.0 + rhs)
    }
}

impl AddAssign<u64> for View {
    fn add_assign(&mut self, rhs: u64) {
        self.0 += rhs;
    }
}

impl Rem<u64> for View {
    type Output = u64;

    fn rem(self, rhs: u64) -> Self::Output {
        self.0 % rhs
    }
}

pub struct Timeout {
    pub certificate: Certificate<View>,
}

enum Domain {
    Propose = 0,
    Prepare = 1,
    Vote = 2,
    Vote2 = 3,
    Wish = 4,
}

pub struct Signed<T: ToBytes> {
    pub message: T,
    pub signer: Signer,
    pub signature: Signature,
}

pub enum Message {
    Propose(Signed<Propose>),
    Prepare(Signed<Prepare>),
    Vote(Signed<Vote>),
    Vote2(Signed<Vote>),
    Wish(Signed<Wish>),
    Timeout(Timeout),
    Certificate(Certificate<Vote>),
}

pub enum Action {
    // persist the following data before sending messages
    // committed certificate can be executed.
    Commit(Certificate<Vote>),
    // latest locked certificate has to be durable for safety.
    Lock(Certificate<Vote>),
    // node should not vote more than once.
    Voted(View),

    // send message to all participants
    Send(Message),
    // send message to a specific participant
    SendTo(Message, blst::PublicKey),

    // wait single network delay
    WaitDelay(),
    // reset f+1 ticks
    ResetTicks(usize),
}

type Signer = u16;

pub struct Consensus {
    // current view
    view: View,
    next_tick: View,
    // last voted view
    voted: View,
    // participants are sorted lexicographically. used to decode public keys from bitvec in certificates
    participants: Vec<PublicKey>,
    // single certificate from 2/3*f+1 Vote. initialized to genesis
    lock: Certificate<Vote>,
    // double certificate from 2/3*f+1 Vote2. initialized to genesis
    commit: Certificate<Vote>,
    keys: HashMap<PublicKey, PrivateKey>,
    // to aggregate propose and prepare votes
    // key is view, type of the vote, signer
    votes: BTreeMap<View, HashMap<Signer, Signed<Vote>>>,
    votes2: BTreeMap<View, HashMap<Signer, Signed<Vote>>>,
    timeouts: BTreeMap<View, HashMap<Signer, Signed<Wish>>>,
    // next block to propose
    proposal: Option<ID>,

    pub actions: Vec<Action>,
}

impl Consensus {
    pub fn new(
        view: View,
        participants: Vec<PublicKey>,
        lock: Certificate<Vote>,
        commit: Certificate<Vote>,
        voted: View,
        keys: HashMap<PublicKey, PrivateKey>,
    ) -> Self {
        Self {
            view,
            next_tick: View(0),
            participants,
            lock,
            commit,
            actions: Vec::new(),
            voted,
            keys,
            proposal: None,
            votes: BTreeMap::new(),
            votes2: BTreeMap::new(),
            timeouts: BTreeMap::new(),
        }
    }
}

impl Consensus {
    pub fn on_tick(&mut self) {
        if self.next_tick <= self.view || self.view == View(0) {
            return;
        }
        if self.view % self.participants.len() as u64 / 3 + 1 == 0 {
            // send wish for view synchronization
            for (id, pk) in self.keys.iter() {
                if let Some(i) = self.participants.iter().position(|p| p == id) {
                    let wish = Wish { view: self.view };
                    let signature = pk.sign(&wish.to_bytes());
                    self.actions.push(Action::Send(Message::Wish(Signed {
                        message: wish,
                        signer: i as u16,
                        signature,
                    })));
                }
            }
        } else {
            self.view = self.next_tick;
            self.next_tick += 1;
            self.actions
                .push(Action::Send(Message::Certificate(self.lock.clone())));
            self.actions.push(Action::WaitDelay());
        }
    }

    fn on_wish(&mut self, wish: Signed<Wish>) {
        if wish.message.view <= self.view {
            return;
        }
        if wish.signer >= self.participants.len() as u16 {
            return;
        }
        match wish.signature.verify(
            &wish.message.to_bytes(),
            &self.participants[wish.signer as usize],
        ) {
            BLST_ERROR::BLST_SUCCESS => {}
            err => return,
        }
        let wishes = self
            .timeouts
            .entry(wish.message.view)
            .or_insert_with(HashMap::new);
        wishes.insert(wish.signer, wish);
        if wishes.len() > self.participants.len() * 2 / 3 {
            let signature =
                AggregateSignature::aggregate(wishes.iter().map(|(_, wish)| &wish.signature))
                    .expect("signatures expected to be aggregated");
            let mut signers = BitVec::new();
            wishes.iter().for_each(|(i, _)| {
                signers.set(*i as usize, true);
            });
            self.actions.push(Action::Send(Message::Timeout(Timeout {
                certificate: Certificate {
                    message: wishes.iter().next().unwrap().1.message.view,
                    signature,
                    signers: signers,
                },
            })));
        }
    }

    fn on_timeout(&mut self, timeout: Timeout) {
        if timeout.certificate.message <= self.view {
            return;
        }
        self.view = timeout.certificate.message;
        self.next_tick = self.view + 1;
        self.actions
            .push(Action::ResetTicks(self.participants.len() / 3 + 1));
        // wait one maximal network delay to receive highest lock.
        self.actions.push(Action::WaitDelay());
        self.actions
            .push(Action::Send(Message::Certificate(self.lock.clone())));
    }

    pub fn on_delay(&mut self) {
        let leader = self.view.0 as usize % self.participants.len();
        let key = self.keys.get(&self.participants[leader]);
        if key.is_none() {
            return;
        }
        // unlike the paper, i want to simplify protocol and obtain double certificate on every block.
        // therefore i extend locked if it is equal to double, otherwise i retry locked block.
        let propose = if self.lock.message != self.commit.message {
            Some(Propose {
                view: self.view,
                block: self.lock.message.block.clone(),
                locked: self.lock.clone(),
                double: self.commit.clone(),
            })
        } else if let Some(proposal) = self.proposal.take() {
            Some(Propose {
                view: self.view,
                block: Block {
                    height: self.commit.message.block.height + 1,
                    id: proposal,
                    prev: self.commit.message.block.id,
                },
                locked: self.lock.clone(),
                double: self.commit.clone(),
            })
        } else {
            None
        };
        if let Some(proposal) = propose {
            let signature = key.unwrap().sign(&proposal.to_bytes());
            self.actions.push(Action::Send(Message::Propose(Signed {
                message: proposal,
                signer: leader as u16,
                signature,
            })));
        }
    }

    fn on_propose(&mut self, propose: Signed<Propose>) {
        if propose.message.view < self.view || self.voted >= self.view {
            return;
        }
        if propose.signer >= self.participants.len() as u16 {
            return;
        }
        match propose.signature.verify(
            &propose.message.to_bytes(),
            &self.participants[propose.signer as usize],
        ) {
            BLST_ERROR::BLST_SUCCESS => {}
            err => return,
        }
        if propose.message.locked.signers.iter().filter(|b| *b).count()
            < self.participants.len() * 2 / 3 + 1
        {
            return;
        }
        let keys = propose
            .message
            .locked
            .signers
            .iter()
            .enumerate()
            .filter(|(_, b)| *b)
            .map(|(i, _)| &self.participants[i]);
        match propose
            .message
            .locked
            .signature
            .verify(&propose.message.locked.message.to_bytes(), keys)
        {
            BLST_ERROR::BLST_SUCCESS => {}
            err => return,
        }
        if propose.message.double.signers.iter().filter(|b| *b).count()
            < self.participants.len() * 2 / 3 + 1
        {
            return;
        }
        let keys = propose
            .message
            .double
            .signers
            .iter()
            .enumerate()
            .filter(|(_, b)| *b)
            .map(|(i, _)| &self.participants[i]);
        match propose
            .message
            .double
            .signature
            .verify(&propose.message.double.message.to_bytes(), keys)
        {
            BLST_ERROR::BLST_SUCCESS => {}
            err => return,
        }

        // if locked is ranked no lower than current locked
        if propose.message.locked.message.view <= self.lock.message.view {
            return;
        }
        // locked either extends double or equal to double if it was finalized in the same view
        if propose.message.locked.message.block.prev != propose.message.double.message.block.id
            && propose.message.locked.message.block.id != propose.message.double.message.block.id
        {
            return;
        }
        // double always extends known double. it is also true when node downloads state.
        if propose.message.double.message.block.prev != self.commit.message.block.id {
            return;
        }

        self.voted = propose.message.view;
        self.lock = propose.message.locked.clone();
        self.commit = propose.message.double.clone();

        // persist updates
        self.actions.push(Action::Voted(self.voted));
        self.actions.push(Action::Lock(self.lock.clone()));
        self.actions.push(Action::Commit(self.commit.clone()));

        if self.commit.message.view > self.view {
            self.view = self.commit.message.view + 1;
            self.next_tick = self.view + 1;
            self.actions
                .push(Action::ResetTicks(self.participants.len() / 3 + 1));
        }
        if self.view != propose.message.view {
            return;
        }

        for (public, private) in self.keys.iter() {
            if let Some(i) = self.participants.iter().position(|p| p == public) {
                let vote = Vote {
                    view: propose.message.view.clone(),
                    block: propose.message.block.clone(),
                };
                let signature = private.sign(&vote.to_bytes());
                self.actions.push(Action::Send(Message::Vote(Signed {
                    message: vote,
                    signer: i as Signer,
                    signature,
                })));
            }
        }
    }

    fn on_prepare(&mut self, prepare: Signed<Prepare>) {
        if prepare.message.certificate.message.view != self.view {
            return;
        }
        if prepare.signer >= self.participants.len() as u16 {
            return;
        }
        match prepare.signature.verify(
            &prepare.message.to_bytes(),
            &self.participants[prepare.signer as usize],
        ) {
            BLST_ERROR::BLST_SUCCESS => {}
            err => return,
        }
        if prepare
            .message
            .certificate
            .signers
            .iter()
            .filter(|b| *b)
            .count()
            < self.participants.len() * 2 / 3 + 1
        {
            return;
        }
        let keys = prepare
            .message
            .certificate
            .signers
            .iter()
            .enumerate()
            .filter(|(_, b)| *b)
            .map(|(i, _)| &self.participants[i]);
        match prepare
            .message
            .certificate
            .signature
            .verify(&prepare.message.certificate.message.to_bytes(), keys)
        {
            BLST_ERROR::BLST_SUCCESS => {}
            err => return,
        }

        if prepare.message.certificate.message.view <= self.lock.message.view
            || prepare.message.certificate.message.block.prev != self.lock.message.block.id
        {
            return;
        }
        self.lock = prepare.message.certificate.clone();
        self.actions.push(Action::Lock(self.lock.clone()));
        for (public, private) in self.keys.iter() {
            if let Ok(i) = self.participants.binary_search(public) {
                let vote = Vote {
                    view: prepare.message.certificate.message.view.clone(),
                    block: prepare.message.certificate.message.block.clone(),
                };
                let signature = private.sign(&vote.to_bytes());
                self.actions.push(Action::Send(Message::Vote(Signed {
                    message: vote,
                    signer: i as Signer,
                    signature,
                })));
            }
        }
    }
}
