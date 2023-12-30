use blake3;
use ed25519_dalek;
use ed25519_dalek::{Keypair, PublicKey, Signer, Verifier};
use std::collections::{BTreeMap, BTreeSet, HashMap};

type Hash = [u8; blake3::OUT_LEN];
type Identity = [u8; ed25519_dalek::PUBLIC_KEY_LENGTH];
type Signature = [u8; ed25519_dalek::SIGNATURE_LENGTH];
type CertiticateID = Hash;

#[derive(Clone)]
pub struct Vote {
    view: u64,
    cert: CertiticateID,
    identity: Identity,
    signature: Signature,
}

impl Vote {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend_from_slice(&self.view.to_be_bytes());
        bytes.extend_from_slice(&self.cert);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut previous = [0; blake3::OUT_LEN];
        previous.copy_from_slice(&bytes[8..8 + blake3::OUT_LEN]);
        Self {
            view: u64::from_be_bytes(bytes[0..8].try_into().unwrap()),
            cert: previous,
            identity: [0; ed25519_dalek::PUBLIC_KEY_LENGTH],
            signature: [0; ed25519_dalek::SIGNATURE_LENGTH],
        }
    }
}

#[derive(Clone, Hash)]
pub struct Certificate {
    view: u64,
    height: u64,
    block: Hash,
    prev: Hash,
    prev_votes: Vec<(Identity, Signature)>,
}

impl Default for Certificate {
    fn default() -> Self {
        Self {
            view: 0,
            height: 0,
            block: [0; blake3::OUT_LEN],
            prev: [0; blake3::OUT_LEN],
            prev_votes: vec![],
        }
    }
}

impl Certificate {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend_from_slice(&self.view.to_be_bytes());
        bytes.extend_from_slice(&self.block);
        bytes.extend_from_slice(&self.prev);
        bytes.extend_from_slice(&self.prev_votes.len().to_be_bytes());
        for (identity, signature) in &self.prev_votes {
            bytes.extend_from_slice(identity);
            bytes.extend_from_slice(signature);
        }
        bytes
    }

    pub fn id(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.to_bytes());
        hasher.finalize().into()
    }
}

#[derive(Clone)]
pub struct TimeoutCertificate {
    view: u64,
    votes: Vec<(Identity, Signature)>,
}

impl Default for TimeoutCertificate {
    fn default() -> Self {
        Self {
            view: 0,
            votes: vec![],
        }
    }
}

impl TimeoutCertificate {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend_from_slice(&self.view.to_be_bytes());
        bytes.extend_from_slice(&self.votes.len().to_be_bytes());
        for (identity, signature) in &self.votes {
            bytes.extend_from_slice(identity);
            bytes.extend_from_slice(signature);
        }
        bytes
    }
}

#[derive(Clone)]
pub struct Wish {
    view: u64,
}

impl Wish {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend_from_slice(&self.view.to_be_bytes());
        bytes
    }
}

#[derive(Clone)]
pub enum Message {
    Vote(Vote),
    QC(Certificate),
    Wish(Wish),
    TC(TimeoutCertificate),
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
    SetEpochTimers(u64),
}

struct TCAggregator {
    cert: TimeoutCertificate,
    participants: BTreeSet<Identity>,
    sent: bool,
}

impl Default for TCAggregator {
    fn default() -> Self {
        Self {
            cert: TimeoutCertificate::default(),
            participants: BTreeSet::new(),
            sent: false,
        }
    }
}

struct QCAggregator {
    votes: Vec<(Identity, Signature)>,
    participants: BTreeSet<Identity>,
    sent: bool,
}

struct HotStuff {
    view: u64,
    voted: u64,
    t: u64,
    chain: BTreeMap<u64, Certificate>,
    executed: u64,
    locked: u64,
    highest: u64,
    keys: BTreeSet<ed25519_dalek::Keypair>,
    participants: BTreeSet<ed25519_dalek::PublicKey>,
    proposed_block: Option<Hash>,
    wishes: BTreeMap<u64, TCAggregator>,
    certs: BTreeMap<(u64, Hash), QCAggregator>,
    pub actions: Vec<Action>,
}

impl Default for HotStuff {
    fn default() -> Self {
        Self {
            view: 0,
            voted: 0,
            t: 0,
            chain: BTreeMap::new(),
            executed: 0,
            locked: 0,
            highest: 0,
            keys: BTreeSet::new(),
            participants: BTreeSet::new(),
            proposed_block: None,
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
        if self.view % (self.t + 1) == 0 {
            let message = Message::Wish(Wish { view: next });
            let buf = message.to_bytes();
            self.keys.iter().for_each(|key| {
                self.actions.push(Action::Send(message.clone()));
            });
        } else {
            self.advance_with_delay(next)
        }
    }

    fn advance_with_delay(&mut self, next: u64) {
        self.advance(next);
        self.actions.push(Action::WaitDelay());
        if let Some(prev) = self.chain.get(&self.highest) {
            let qc = Message::QC(prev.clone());
            self.actions.push(Action::Send(qc));
        }
    }

    pub fn on_delay(&mut self) {
        self.propose(self.view);
    }

    pub fn on_message(msg: Message) {}

    fn on_certificate(&mut self, cert: Certificate) {
        if let Some(prev) = self.chain.get(&(cert.height - 1)) {
            if prev.id() != cert.prev || cert.prev_votes.len() <= self.participants.len() * 2 / 3 {
                return;
            }
            let height = cert.height;
            self.advance(prev.view + 1);
            if self.view == cert.view && self.voted < cert.view {
                self.highest = height;
                self.locked = height - 1;
                self.executed = height - 2;
                self.voted = cert.view;
                self.actions.push(Action::Send(Message::Vote(Vote {
                    view: self.view,
                    cert: cert.id(),
                    identity: [0; 32],
                    signature: [0; 64],
                })));
                self.chain.insert(height, cert);
            }
        }
    }

    fn on_timeout_certificate(&mut self, cert: TimeoutCertificate) {
        self.advance_with_delay(cert.view + 1);
    }

    fn on_vote(&mut self, vote: Vote) {
        let cert = self
            .certs
            .entry((vote.view, vote.cert))
            .or_insert_with(|| QCAggregator {
                votes: vec![],
                participants: BTreeSet::new(),
                sent: false,
            });
        if cert.participants.insert(vote.identity.clone()) {
            cert.votes.push((vote.identity, vote.signature));
            if cert.votes.len() > self.participants.len() * 2 / 3 && !cert.sent {
                cert.sent = true;
                self.propose(self.view + 1);
            }
        }
    }

    fn on_wish(&mut self, identity: Identity, sig: Signature, wish: Wish) {
        let agg = self
            .wishes
            .entry(wish.view)
            .or_insert_with(|| TCAggregator {
                cert: TimeoutCertificate {
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
        self.proposed_block = Some(id);
    }

    fn propose(&mut self, view: u64) {
        if let Some(id) = self.proposed_block {
            if let Some(prev) = self.chain.get(&self.highest) {
                let cert = Certificate {
                    view: view,
                    height: prev.height + 1,
                    block: id,
                    prev: prev.id(),
                    ..Default::default()
                };
                let message = Message::QC(cert);
                let buf = message.to_bytes();
                self.keys.iter().for_each(|key| {
                    self.actions.push(Action::Send(message.clone()));
                });
            }
        }
    }

    fn advance(&mut self, next: u64) {
        if next > self.view {
            if self.view % self.t + 1 == 0 {
                self.actions.push(Action::SetEpochTimers(self.view));
            }
            self.view = next;
        }
    }
}

#[cfg(test)]
mod tests {
    fn test_view_synchronization() {}
}
