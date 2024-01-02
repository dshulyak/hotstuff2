use ::blst::BLST_ERROR;
use bit_vec::BitVec;
use blake3::Hash;
use blst::min_pk as blst;
use std::collections::{BTreeMap, HashMap};

#[derive(Clone)]
pub struct Block {
    pub height: u64,
    pub id: Hash,
    pub prev: Hash,
}

pub struct Propose {
    pub view: u64,
    pub block: Block,
    pub highest: Certificate<Block>,
    pub double: Certificate<Block>,
    pub signer: u16,
    pub signature: blst::Signature,
}

pub struct Prepare {
    pub view: u64,
    pub certificate: Certificate<Block>,
    pub signer: u16,
    pub signature: blst::Signature,
}

#[derive(Clone)]
pub struct Certificate<T> {
    pub message: T,
    pub signature: blst::AggregateSignature,
    pub signers: BitVec,
}

pub struct Vote {
    pub view: u64,
    pub block: Block,
    pub signer: u16,
    pub signature: blst::Signature,
}

pub struct Wish {
    pub view: u64,
    pub signer: u16,
    pub signature: blst::Signature,
}

impl Wish {
    fn signed(&self) -> Vec<u8> {
        signed_wish(self.view)
    }
}

fn signed_wish(view: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(Domain::Wish as u8).to_le_bytes());
    bytes.extend_from_slice(&view.to_le_bytes());
    bytes
}

pub struct Timeout {
    pub certificate: Certificate<u64>,
    pub signer: u16,
    pub signature: blst::Signature,
}

enum Domain {
    Propose = 0,
    Prepare = 1,
    Vote = 2,
    Vote2 = 3,
    Wish = 4,
    Timeout = 5,
}

pub enum Message {
    Propose(Propose),
    Prepare(Prepare),
    Vote(Vote),
    Vote2(Vote),
    Wish(Wish),
    Timeout(Timeout),
    Certificate(Certificate<Block>),
}

pub enum Action {
    // persist the following data before sending messages
    // committed certificate can be executed.
    Commit(Certificate<Block>),
    // latest locked certificate has to be durable for safety.
    Lock(Certificate<Block>),
    // node should not vote more than once.
    Voted(u64),

    // send message to all participants
    Send(Message),
    // send message to a specific participant
    SendTo(Message, blst::PublicKey),

    // wait single network delay
    WaitDelay(),
    // reset f+1 ticks
    ResetTicks(usize),
}

pub struct Consensus {
    // current view
    view: u64,
    next_tick: u64,
    // last voted view
    voted: u64,
    // participants are sorted lexicographically. used to decode public keys from bitvec in certificates
    participants: Vec<blst::PublicKey>,
    // single certificate from 2/3*f+1 Vote. initialized to genesis
    lock: Certificate<Block>,
    // chain of blocks is committed with single double certificate/
    // until we obtain a double certificate, we need to maintain potentially several chain that extend local block.
    uncomitted: BTreeMap<(u64, Hash), Block>,
    // double certificate from 2/3*f+1 Vote2. initialized to genesis
    commit: Certificate<Block>,
    keys: HashMap<blst::PublicKey, blst::SecretKey>,
    // to aggregate propose and prepare votes
    // key is view, type of the vote, signer
    votes: BTreeMap<u64, Vec<Vote>>,
    votes2: BTreeMap<u64, Vec<Vote>>,
    timeouts: BTreeMap<u64, Vec<Wish>>,
    // next block to propose
    proposal: Option<Hash>,

    pub actions: Vec<Action>,
}

impl Consensus {
    pub fn new(
        view: u64,
        participants: Vec<blst::PublicKey>,
        lock: Certificate<Block>,
        commit: Certificate<Block>,
        voted: u64,
        keys: HashMap<blst::PublicKey, blst::SecretKey>,
    ) -> Self {
        Self {
            view,
            next_tick: 0,
            participants,
            lock,
            commit,
            uncomitted: BTreeMap::new(),
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
        if self.next_tick <= self.view || self.view == 0 {
            return;
        }
        if self.view % self.participants.len() as u64 / 3 + 1 == 0 {
            // send wish for view synchronization
            for (id, pk) in self.keys.iter() {
                if let Some(i) = self.participants.iter().position(|p| p == id) {
                    let wish = Wish {
                        view: self.view,
                        signer: i as u16,
                        signature: pk.sign(&signed_wish(&self.view + 1), &[], &[]),
                    };
                    self.actions.push(Action::Send(Message::Wish(wish)));
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

    fn on_wish(&mut self, wish: Wish) {
        if wish.view <= self.view {
            return;
        }
        if wish.signer >= self.participants.len() as u16 {
            return;
        }
        match wish.signature.verify(
            true,
            &wish.signed(),
            &[],
            &[],
            &self.participants[wish.signer as usize],
            true,
        ) {
            BLST_ERROR::BLST_SUCCESS => {}
            err => return,
        }
        let wishes = self
            .timeouts
            .entry(wish.view)
            .or_insert_with(|| Vec::with_capacity(self.participants.len()));
        wishes.insert(wish.signer as usize, wish);
        if wishes.iter().filter(|wish| wish.view != 0).count() > self.participants.len() * 2 / 3 {
            // aggregate timeout certificate and send it
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
        // if you are a leader in the round send propose with locked
        if let Some(proposal) = self.proposal.take() {
            let propose = Propose {
                view: self.view,
                proposal,
                signer: 0,
                signature: blst::Signature::default(),
            };
            self.actions.push(Action::Send(Message::Propose(propose)));
        }
    }

    fn on_propose(&mut self, propose: Propose) {
        // any double certificate commits whole chain.
        // double certificate is not necessary for every single view.
    }
}
