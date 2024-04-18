use std::{fmt::Debug, ops::Index};

use crate::types::{Bitfield, PublicKey, Signature, Signed, Signer, ToBytes, View};


#[derive(Debug, Clone)]
pub(crate) struct Votes<T: ToBytes + Clone + Debug> {
    signers: Bitfield,
    votes: Vec<Signed<T>>,
}

impl<T: ToBytes + Clone + Debug> Votes<T> {
    pub(crate) fn new(n: usize) -> Self {
        Self {
            signers: Bitfield::from_elem(n, false),
            votes: Vec::new(),
        }
    }

    pub(crate) fn voted(&self, signer: Signer) -> bool {
        self.signers.get(signer as usize).map_or(false, |b| b)
    }

    pub(crate) fn add(&mut self, vote: Signed<T>) {
        self.signers.set(vote.signer as usize, true);
        self.votes.push(vote);
    }

    pub(crate) fn count(&self) -> usize {
        self.signers().iter().filter(|b| *b).count()
    }

    pub(crate) fn signers(&self) -> Bitfield {
        self.signers.clone()
    }

    pub(crate) fn signatures<'a>(&'a self) -> impl IntoIterator<Item = &'a Signature> {
        self.votes.iter().map(|v| &v.signature)
    }

    pub(crate) fn message(&self) -> T {
        self.votes[0].inner.clone()
    }
}


#[derive(Debug, Clone)]
pub(crate) struct Signers(Box<[PublicKey]>);

impl Signers {
    pub(crate) fn new(keys: Box<[PublicKey]>) -> Self {
        Self(keys)
    }

    pub(crate) fn decode<'a>(&'a self, bits: &'a Bitfield) -> impl IntoIterator<Item = &'a PublicKey> {
        bits.iter()
            .enumerate()
            .filter(|(_, b)| *b)
            .map(|(i, _)| &self.0[i])
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn atleast_one_honest(&self) -> usize {
        self.0.len() / 3 + 1
    }

    pub(crate) fn honest_majority(&self) -> usize {
        self.0.len() * 2 / 3 + 1
    }

    pub(crate) fn leader(&self, view: View) -> Signer {
        let i = view % self.0.len() as u64;
        i as Signer
    }

    pub(crate) fn leader_pub_key(&self, view: View) -> PublicKey {
        self[self.leader(view)].clone()
    }
}

impl Index<u16> for Signers {
    type Output = PublicKey;
    fn index(&self, index: u16) -> &Self::Output {
        &self.0[index as usize]
    }
}