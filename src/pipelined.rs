use blake3;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    vec,
};

type Hash = [u8; blake3::OUT_LEN];
type Signature = [u8; 64];
type PrivateKey = [u8; 64];
type CertiticateID = Hash;

#[derive(Clone, Hash, Ord, PartialOrd, Eq, PartialEq)]
struct PublicKey([u8; 32]);

#[derive(Clone)]
pub struct Vote {
    view: u64,
    cert: CertiticateID,
    identity: PublicKey,
    signature: Signature,
}

impl Vote {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend_from_slice(&self.view.to_be_bytes());
        bytes.extend_from_slice(&self.cert);
        bytes.extend_from_slice(&self.identity.0);
        bytes.extend_from_slice(&self.signature);
        bytes
    }

    pub fn len() -> usize {
        8 + 32 + 32 + 64
    }

    pub fn from_bytes(buf: &[u8]) -> Self {
        let mut view = [0u8; 8];
        view.copy_from_slice(&buf[0..8]);
        let mut cert = [0u8; 32];
        cert.copy_from_slice(&buf[8..40]);
        let mut identity = [0u8; 32];
        identity.copy_from_slice(&buf[40..72]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&buf[72..136]);
        Self {
            view: u64::from_be_bytes(view),
            cert,
            identity: PublicKey(identity),
            signature,
        }
    }
}

#[derive(Clone, Hash)]
pub struct Generic {
    view: u64,
    // height of the executed block, derived from position in the hashchain.
    height: u64,
    // block to execute.
    block: Hash,
    // hash of the previous generic message.
    previous: Hash,
    // set of signatures for the `previous` hash in the hashchain.
    votes: Vec<(PublicKey, Signature)>,
}

impl Generic {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend_from_slice(&self.view.to_be_bytes());
        bytes.extend_from_slice(&self.block);
        bytes.extend_from_slice(&self.previous);
        bytes.extend_from_slice(&self.votes.len().to_be_bytes());
        for (identity, signature) in &self.votes {
            bytes.extend_from_slice(&identity.0);
            bytes.extend_from_slice(signature);
        }
        bytes
    }

    pub fn from_bytes(buf: &[u8]) -> Self {
        let mut view = [0u8; 8];
        view.copy_from_slice(&buf[0..8]);
        let mut block = [0u8; 32];
        block.copy_from_slice(&buf[8..40]);
        let mut previous = [0u8; 32];
        previous.copy_from_slice(&buf[40..72]);
        let mut votes_len = [0u8; 8];
        votes_len.copy_from_slice(&buf[72..80]);
        let votes_len = u64::from_be_bytes(votes_len);
        let mut votes = vec![];
        let mut offset = 80;
        for _ in 0..votes_len {
            let mut identity = [0u8; 32];
            identity.copy_from_slice(&buf[offset..offset + 32]);
            offset += 32;
            let mut signature = [0u8; 64];
            signature.copy_from_slice(&buf[offset..offset + 64]);
            offset += 64;
            votes.push((PublicKey(identity), signature));
        }
        Self {
            view: u64::from_be_bytes(view),
            height: 0,
            block,
            previous,
            votes,
        }
    }

    pub fn id(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.to_bytes());
        hasher.finalize().into()
    }
}

#[derive(Clone)]
pub struct Timeout {
    view: u64,
    votes: Vec<(PublicKey, Signature)>,
}

impl Default for Timeout {
    fn default() -> Self {
        Self {
            view: 0,
            votes: vec![],
        }
    }
}

impl Timeout {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend_from_slice(&self.view.to_be_bytes());
        bytes.extend_from_slice(&self.votes.len().to_be_bytes());
        for (identity, signature) in &self.votes {
            bytes.extend_from_slice(&identity.0);
            bytes.extend_from_slice(signature);
        }
        bytes
    }

    pub fn from_bytes(buf: &[u8]) -> Self {
        let mut view = [0u8; 8];
        view.copy_from_slice(&buf[0..8]);
        let mut votes_len = [0u8; 8];
        votes_len.copy_from_slice(&buf[8..16]);
        let votes_len = u64::from_be_bytes(votes_len);
        let mut votes = vec![];
        let mut offset = 16;
        for _ in 0..votes_len {
            let mut identity = [0u8; 32];
            identity.copy_from_slice(&buf[offset..offset + 32]);
            offset += 32;
            let mut signature = [0u8; 64];
            signature.copy_from_slice(&buf[offset..offset + 64]);
            offset += 64;
            votes.push((PublicKey(identity), signature));
        }
        Self {
            view: u64::from_be_bytes(view),
            votes,
        }
    }
}

#[derive(Clone)]
pub struct Wish {
    view: u64,
    identity: PublicKey,
    signature: Signature,
}

impl Wish {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend_from_slice(&self.view.to_be_bytes());
        bytes.extend_from_slice(&self.identity.0);
        bytes.extend_from_slice(&self.signature);
        bytes
    }

    pub fn from_bytes(buf: &[u8]) -> Self {
        let mut view = [0u8; 8];
        view.copy_from_slice(&buf[0..8]);
        let mut identity = [0u8; 32];
        identity.copy_from_slice(&buf[8..40]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&buf[40..104]);
        Self {
            view: u64::from_be_bytes(view),
            identity: PublicKey(identity),
            signature,
        }
    }
}

#[derive(Clone)]
pub enum Message {
    Vote(Vote),
    QC(Generic),
    Wish(Wish),
    TC(Timeout),
}

impl Message {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Message::Vote(vote) => {
                let mut bytes = vec![];
                bytes.push(0);
                bytes.extend_from_slice(&vote.to_bytes());
                bytes
            }
            Message::QC(certificate) => {
                let mut bytes = vec![];
                bytes.push(1);
                bytes.extend_from_slice(&certificate.to_bytes());
                bytes
            }
            Message::Wish(wish) => {
                let mut bytes = vec![];
                bytes.push(2);
                bytes.extend_from_slice(&wish.to_bytes());
                bytes
            }
            Message::TC(tc) => {
                let mut bytes = vec![];
                bytes.push(3);
                bytes.extend_from_slice(&tc.to_bytes());
                bytes
            }
        }
    }
}

pub enum Action {
    // Protocol communication.
    Send(Message),
    // Wait for all participants to send its highest locked certificate.
    WaitDelay(),
    // Set timers for an epoch. Epoch is a t+1 consecutive views.
    ResetTimers((u64, u64)),
}

struct TCAggregator {
    cert: Timeout,
    participants: BTreeSet<PublicKey>,
    sent: bool,
}

impl Default for TCAggregator {
    fn default() -> Self {
        Self {
            cert: Timeout::default(),
            participants: BTreeSet::new(),
            sent: false,
        }
    }
}

struct QCAggregator {
    votes: Vec<(PublicKey, Signature)>,
    participants: BTreeSet<PublicKey>,
    sent: bool,
}

struct HotStuff {
    view: u64,
    voted: u64,
    chain: BTreeMap<u64, Generic>,
    highest: u64,
    keys: HashMap<PublicKey, PrivateKey>,
    participants: BTreeSet<PublicKey>,
    propose: Option<Hash>,
    wishes: BTreeMap<u64, TCAggregator>,
    certs: BTreeMap<(u64, Hash), QCAggregator>,
    pub actions: Vec<Action>,
}

impl Default for HotStuff {
    fn default() -> Self {
        Self {
            view: 0,
            voted: 0,
            chain: BTreeMap::new(),
            highest: 0,
            keys: HashMap::new(),
            participants: BTreeSet::new(),
            propose: None,
            wishes: BTreeMap::new(),
            certs: BTreeMap::new(),
            actions: vec![],
        }
    }
}

impl HotStuff {
    pub fn on_view_timer(&mut self, next: u64) {
        if next <= self.view {
            return;
        }
        if self.view % (self.participants.len() as u64 / 3 + 1) == 0 {
            let message = Message::Wish(Wish {
                view: next,
                identity: PublicKey([0u8; 32]),
                signature: [0u8; 64],
            });
            self.keys.iter().for_each(|key| {
                self.actions.push(Action::Send(message.clone()));
            });
        } else {
            self.advance(next);
            self.actions.push(Action::WaitDelay());
            if let Some(prev) = self.chain.get(&self.highest) {
                let qc = Message::QC(prev.clone());
                self.actions.push(Action::Send(qc));
            }
        }
    }

    pub fn on_timeout_certificate(&mut self, cert: Timeout) {
        self.advance(cert.view + 1);
        self.actions.push(Action::WaitDelay());
        if let Some(prev) = self.chain.get(&self.highest) {
            let qc = Message::QC(prev.clone());
            self.actions.push(Action::Send(qc));
        }
    }

    pub fn on_delay(&mut self) {
        let cert = if let Some(highest) = self.chain.get(&self.highest) {
            Generic {
                view: self.view,
                height: self.highest,
                block: highest.block,
                previous: highest.previous,
                votes: highest.votes.clone(),
            }
        } else if let Some(propose) = self.propose {
            Generic {
                view: self.view,
                height: 1,
                block: propose,
                previous: [0; 32],
                votes: vec![],
            }
        } else {
            return;
        };
        self.actions.push(Action::Send(Message::QC(cert)));
    }

    pub fn on_certificate(&mut self, cert: Generic) {
        if let Some(prev) = self.chain.get(&(cert.height - 1)) {
            // check that certificate votes are for block that is ranked no lower than currently locked certificate.
            if prev.id() != cert.previous || cert.votes.len() <= self.participants.len() * 2 / 3 {
                return;
            }
            let height = cert.height;
            self.advance(prev.view + 1);
            if self.view == cert.view && self.voted < cert.view {
                self.highest = height;
                self.voted = cert.view;
                self.actions.push(Action::Send(Message::Vote(Vote {
                    view: self.view,
                    cert: cert.id(),
                    identity: PublicKey([0; 32]),
                    signature: [0; 64],
                })));
                self.chain.insert(height, cert);
            }
        }
    }

    pub fn on_vote(&mut self, vote: Vote) {
        let cert = self
            .certs
            .entry((vote.view, vote.cert))
            .or_insert_with(|| QCAggregator {
                votes: vec![],
                participants: BTreeSet::new(),
                sent: false,
            });
        if !cert.participants.insert(vote.identity.clone()) {
            return;
        };
        cert.votes.push((vote.identity, vote.signature));
        if cert.votes.len() <= self.participants.len() * 2 / 3 {
            return;
        };
        if cert.sent {
            return;
        }
        cert.sent = true;
        let signer = leader(self.view, &self.participants);
        if signer.is_none() {
            return;
        }
        let key = self.keys.get(&signer.unwrap());
        if key.is_none() {
            return;
        }
        let proposal = self.propose.take();
        if proposal.is_none() {
            return;
        }
        let cert = Generic {
            height: self.highest + 1,
            view: vote.view + 1,
            previous: vote.cert,
            block: proposal.unwrap(),
            votes: cert.votes.clone(),
        };
        self.actions.push(Action::Send(Message::QC(cert)));
    }

    pub fn on_wish(&mut self, identity: PublicKey, sig: Signature, wish: Wish) {
        let agg = self
            .wishes
            .entry(wish.view)
            .or_insert_with(|| TCAggregator {
                cert: Timeout {
                    view: wish.view,
                    votes: vec![],
                },
                participants: BTreeSet::new(),
                sent: false,
            });
        if agg.participants.insert(identity.clone()) {
            agg.cert.votes.push((identity, sig));
            if agg.cert.votes.len() > self.participants.len() * 2 / 3 && !agg.sent {
                agg.sent = true;
                self.actions
                    .push(Action::Send(Message::TC(agg.cert.clone())));
            }
        }
    }

    pub fn schedule_block(&mut self, id: Hash) {
        self.propose = Some(id);
    }

    fn advance(&mut self, next: u64) {
        if next > self.view {
            if self.view % self.participants.len() as u64 / 3 + 1 == 0 {
                self.actions.push(Action::ResetTimers((
                    self.view,
                    self.participants.len() as u64 / 3 + 1,
                )));
            }
            self.view = next;
        }
    }
}

fn leader(view: u64, participants: &BTreeSet<PublicKey>) -> Option<&PublicKey> {
    let i = view as usize % participants.len();
    participants.iter().nth(i)
}

#[cfg(test)]
mod tests {}
