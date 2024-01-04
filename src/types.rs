use crate::bls::{AggregateSignature, Signature};
use crate::codec::ToBytes;

use bit_vec::BitVec;
use blake3;
use std::ops::{Add, AddAssign, Rem};

pub type Signer = u16;
pub type ID = blake3::Hash;

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
pub struct View(pub u64);

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

pub struct Signed<T: ToBytes> {
    pub message: T,
    pub signer: Signer,
    pub signature: Signature,
}

pub struct Sync {
    pub locked: Option<Certificate<Vote>>,
    pub double: Option<Certificate<Vote>>,
}

impl ToBytes for Sync {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        if let Some(locked) = &self.locked {
            bytes.extend_from_slice(&locked.to_bytes());
        } else {
            bytes.extend_from_slice(&[0; 1]);
        }
        if let Some(double) = &self.double {
            bytes.extend_from_slice(&double.to_bytes());
        } else {
            bytes.extend_from_slice(&[0; 1]);
        }
        bytes
    }
}

pub enum Message {
    Propose(Signed<Propose>),
    Prepare(Signed<Prepare>),
    Vote(Signed<Vote>),
    Vote2(Signed<Vote>),
    Wish(Signed<Wish>),
    Timeout(Timeout),
    Sync(Sync),
}
