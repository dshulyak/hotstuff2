use bit_vec::BitVec;
use blake3::Hash;
use blst::min_pk as blst;
use std::collections::{BTreeMap, HashMap};

pub struct Block {
    pub height: u64,
    pub id: Hash,
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
}

pub enum Action {
    // persist the following data before sending messages
    // committed certificate can be executed.
    Commit(Certificate<Block>),
    // locked certificate has to be durable for safety.
    Lock(Certificate<Block>),
    // node should not vote more than once.
    Voted(u64),

    // send message to all participants
    Send(Message),
    // send message to a specific participant
    SendTo(Message, blst::PublicKey),

    // wait single network delay
    WaitDelay(),
    // reset f+1 timers
    ResetTimers(u64),
}

pub struct Consensus {
    // current view
    view: u64,
    // last voted view
    voted: u64,
    // participants are sorted lexicographically. used to decode public keys from bitvec in certificates
    participants: Vec<blst::PublicKey>,
    // single certificate from 2/3*f+1 Vote. initialized to genesis
    lock: Certificate<Block>,
    // double certificate from 2/3*f+1 Vote2. initialized to genesis
    commit: Certificate<Block>,
    keys: HashMap<blst::PublicKey, blst::SecretKey>,
    // to aggregate propose and prepare votes
    votes: BTreeMap<(u64, Domain, u16), Vote>,
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
            participants,
            lock,
            commit,
            actions: Vec::new(),
            voted,
            keys,
            proposal: None,
            votes: BTreeMap::new(),
        }
    }
}
