use std::{fmt::Debug, ops::Index};

use anyhow::Result;

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

    pub(crate) fn add(&mut self, vote: Signed<T>) -> Result<()> {
        anyhow::ensure!(self.signers.len() > vote.signer as usize, "invalid signer {:?}", vote.signer);
        anyhow::ensure!(!self.voted(vote.signer), "signer already voted {:?}", vote.signer);

        self.signers.set(vote.signer as usize, true);
        self.votes.push(vote);
        Ok(())
    }

    pub(crate) fn count(&self) -> u64 {
        self.signers().iter().filter(|b| *b).count() as u64
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
pub(crate) struct Participants(Box<[PublicKey]>);

impl Participants {
    pub(crate) fn ensure_sorted(&mut self) {
        self.0.sort();
    }

    pub(crate) fn decode<'a>(&'a self, bits: &'a Bitfield) -> impl IntoIterator<Item = Option<&'a PublicKey>> {
        bits.iter()
            .enumerate()
            .filter(|(_, b)| *b)
            .map(|(i, _)| self.0.get(i))
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn atleast_one_honest(&self) -> u64 {
        self.0.len() as u64 / 3 + 1
    }

    pub(crate) fn honest_majority(&self) -> u64 {
        self.0.len() as u64 * 2 / 3 + 1
    }

    pub(crate) fn leader(&self, view: View) -> Signer {
        let i = view % self.0.len() as u64;
        i as Signer
    }

    pub(crate) fn leader_pub_key(&self, view: View) -> PublicKey {
        self[self.leader(view)].clone()
    }

    pub(crate) fn binary_search(&self, key: &PublicKey) -> Result<Signer, Signer> {
        self.0.binary_search(key).map_or_else(|e| Err(e as Signer), |i| Ok(i as Signer))
    }
}

impl From<Vec<PublicKey>> for Participants {
    fn from(keys: Vec<PublicKey>) -> Self {
        Self(keys.into_boxed_slice())
    }
}

impl From<Box<[PublicKey]>> for Participants {
    fn from(keys: Box<[PublicKey]>) -> Self {
        Self(keys)
    }
}

impl From<&[PublicKey]> for Participants {
    fn from(keys: &[PublicKey]) -> Self {
        Self(keys.into())
    }
}

impl Index<u16> for Participants {
    type Output = PublicKey;
    fn index(&self, index: u16) -> &Self::Output {
        &self.0[index as usize]
    }
}