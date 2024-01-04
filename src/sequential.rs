use crate::bls::{AggregateSignature, PrivateKey, PublicKey};
use crate::codec::ToBytes;
use crate::types::{
    Block, Certificate, Message, Prepare, Propose, Signed, Signer, Sync, Timeout, View, Vote, Wish,
    ID,
};

use anyhow::{anyhow, ensure, Result};
use bit_vec::BitVec;
use std::collections::{BTreeMap, HashMap};
use std::ops::Index;

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
}

pub struct Consensus {
    // current view
    view: View,
    next_tick: View,
    // last voted view
    voted: View,
    // participants are sorted lexicographically. used to decode public keys from bitvec in certificates
    participants: Signers,
    // single certificate from 2/3*f+1 Vote. initialized to genesis
    lock: Certificate<Vote>,
    // double certificate from 2/3*f+1 Vote2. initialized to genesis
    commit: Certificate<Vote>,
    keys: HashMap<PublicKey, PrivateKey>,
    // to aggregate propose and prepare votes
    // key is view, type of the vote, signer
    votes: BTreeMap<(View, ID), HashMap<Signer, Signed<Vote>>>,
    votes2: BTreeMap<(View, ID), HashMap<Signer, Signed<Vote>>>,
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
            participants: Signers(participants),
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
    fn is_epoch_boundary(&self) -> bool {
        self.view % self.participants.atleast_one_honest() as u64 == 0
    }

    fn enter_view(&mut self, view: View) {
        if self.view % self.participants.atleast_one_honest() as u64 == 0 {
            self.next_tick = self.view + 1;
            self.actions.push(Action::ResetTicks());
        }
        self.view = view;
    }

    fn wait_delay(&mut self) {
        self.actions.push(Action::WaitDelay());
        self.actions.push(Action::Send(Message::Sync(Sync {
            locked: Some(self.lock.clone()),
            double: Some(self.commit.clone()),
        })));
    }

    pub fn on_tick(&mut self) {
        if self.next_tick <= self.view && self.view != View(0) {
            return;
        }
        if self.is_epoch_boundary() {
            // execute view synchronization protocol
            for (id, pk) in self.keys.iter() {
                if let Some(i) = self.participants.0.iter().position(|p| p == id) {
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
            self.enter_view(self.next_tick);
            self.wait_delay();
            self.next_tick += 1;
        }
    }

    fn on_wish(&mut self, wish: Signed<Wish>) -> Result<()> {
        ensure!(wish.message.view > self.view, "old view");
        ensure!(
            wish.signer < self.participants.len() as u16,
            "invalid signer"
        );
        wish.signature
            .verify(&wish.message.to_bytes(), &self.participants[wish.signer])?;

        let wishes = self
            .timeouts
            .entry(wish.message.view)
            .or_insert_with(HashMap::new);
        wishes.insert(wish.signer, wish);

        if wishes.len() > self.participants.len() as usize * 2 / 3 {
            self.actions.push(Action::Send(Message::Timeout(Timeout {
                certificate: Certificate {
                    message: wishes.iter().next().unwrap().1.message.view,
                    signature: AggregateSignature::aggregate(
                        wishes.iter().map(|(_, wish)| &wish.signature),
                    )
                    .expect("failed to aggregate signatures"),
                    signers: wishes.iter().fold(BitVec::new(), |mut bits, (_, wish)| {
                        bits.set(wish.signer as usize, true);
                        bits
                    }),
                },
            })));
        }
        Ok(())
    }

    pub fn on_message(&mut self, message: Message) -> Result<()> {
        match message {
            Message::Sync(sync) => Ok(()),
            Message::Prepare(prepare) => self.on_prepare(prepare),
            Message::Vote(vote) => Ok(()),
            Message::Propose(propose) => self.on_propose(propose),
            Message::Vote2(vote2) => Ok(()),
            Message::Wish(wish) => self.on_wish(wish),
            Message::Timeout(timeout) => self.on_timeout(timeout),
        }
    }

    fn on_timeout(&mut self, timeout: Timeout) -> Result<()> {
        ensure!(timeout.certificate.message > self.view, "old view");

        self.view = timeout.certificate.message;
        self.enter_view(timeout.certificate.message);
        self.wait_delay();
        Ok(())
    }

    pub fn on_delay(&mut self) {
        let leader = self.view.0 % self.participants.len() as u64;
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

    fn on_propose(&mut self, propose: Signed<Propose>) -> Result<()> {
        // verification is roughly in the order of computational complexity
        ensure!(propose.message.view >= self.view, "old view");
        ensure!(self.voted > self.view, "already votedin this view");
        ensure!(
            propose.signer < self.participants.len() as u16,
            "signer identifier is out of bounds"
        );
        ensure!(
            propose.message.locked.message.view >= self.lock.message.view,
            "locked ranked lower than current locked"
        );
        ensure!(
            propose.message.locked.message.block.prev == propose.message.double.message.block.id
                || propose.message.locked.message.block.id
                    == propose.message.double.message.block.id,
            "locked either extends double or equal to double if it was finalized in the same view"
        );
        ensure!(
            propose.message.double.message.block.prev == self.commit.message.block.id,
            "double always extends known double block"
        );
        ensure!(
            propose.message.locked.signers.iter().filter(|b| *b).count()
                > self.participants.len() * 2 / 3,
            "locked signed by more than 2/3 participants"
        );
        ensure!(
            propose.message.double.signers.iter().filter(|b| *b).count()
                > self.participants.len() * 2 / 3,
            "double signed by more than 2/3 participants"
        );

        propose.signature.verify(
            &propose.message.to_bytes(),
            &self.participants[propose.signer],
        )?;
        propose.message.locked.signature.verify(
            &propose.message.locked.message.to_bytes(),
            self.participants.decode(&propose.message.locked.signers),
        )?;
        propose.message.double.signature.verify(
            &propose.message.double.message.to_bytes(),
            self.participants.decode(&propose.message.double.signers),
        )?;

        self.voted = propose.message.view;
        self.lock = propose.message.locked.clone();
        self.commit = propose.message.double.clone();

        // persist updates
        self.actions.push(Action::Voted(self.voted));
        self.actions.push(Action::Lock(self.lock.clone()));
        self.actions.push(Action::Commit(self.commit.clone()));

        if self.commit.message.view > self.view {
            self.enter_view(self.commit.message.view + 1);
        }
        if self.view != propose.message.view {
            return Ok(());
        }

        for (public, private) in self.keys.iter() {
            if let Some(i) = self.participants.0.iter().position(|p| p == public) {
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
        Ok(())
    }

    fn on_prepare(&mut self, prepare: Signed<Prepare>) -> Result<()> {
        ensure!(
            prepare.message.certificate.message.view == self.view,
            "invalid view"
        );
        ensure!(
            prepare.signer < self.participants.len() as u16,
            "invalid signer"
        );
        ensure!(
            prepare.message.certificate.message.view > self.lock.message.view,
            "double for old view"
        );
        ensure!(
            prepare.message.certificate.message.block.prev == self.lock.message.block.id,
            "double should extend locked"
        );
        ensure!(
            prepare
                .message
                .certificate
                .signers
                .iter()
                .filter(|b| *b)
                .count()
                > self.participants.len() * 2 / 3,
            "must be signed by honest majority"
        );

        prepare.signature.verify(
            &prepare.message.to_bytes(),
            &self.participants[prepare.signer],
        )?;
        prepare.message.certificate.signature.verify(
            &prepare.message.certificate.message.to_bytes(),
            self.participants
                .decode(&prepare.message.certificate.signers),
        )?;

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
        Ok(())
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
