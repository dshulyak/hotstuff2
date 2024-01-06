use anyhow::{Error, Result};
use bit_vec::BitVec;
use blake3;
use blst::min_pk as blst;

use std::hash;
use std::ops::{Add, AddAssign, Deref, Rem};

pub trait ToBytes {
    fn to_bytes(&self) -> Vec<u8>;
}

pub trait FromBytes {
    fn from_bytes(bytes: &[u8]) -> Self;
}

pub type Signer = u16;

#[derive(Clone, PartialEq, Eq)]
pub struct ID(blake3::Hash);

impl ID {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl Default for ID {
    fn default() -> Self {
        ID([0; blake3::OUT_LEN].into())
    }
}

impl PartialOrd<ID> for ID {
    fn partial_cmp(&self, other: &ID) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ID {
    fn cmp(&self, other: &ID) -> std::cmp::Ordering {
        self.0.as_bytes().cmp(other.0.as_bytes())
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Block {
    pub height: u64,
    pub id: ID,
}

impl Default for Block {
    fn default() -> Self {
        Block {
            height: 0,
            id: ID([0; blake3::OUT_LEN].into()),
        }
    }
}

impl ToBytes for Block {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.height.to_le_bytes());
        bytes.extend_from_slice(self.id.as_bytes());
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
    pub inner: T,
    pub signature: AggregateSignature,
    pub signers: BitVec,
}

impl<T: ToBytes> Deref for Certificate<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T: ToBytes> ToBytes for Certificate<T> {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.inner.to_bytes());
        bytes.extend_from_slice(&self.signature.to_bytes());
        bytes.extend_from_slice(&self.signers.to_bytes());
        bytes
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Vote {
    pub view: View,
    pub block: Block,
}

impl Deref for Vote {
    type Target = Block;

    fn deref(&self) -> &Self::Target {
        &self.block
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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

#[derive(Clone)]
pub struct Signed<T: ToBytes> {
    pub inner: T,
    pub signer: Signer,
    pub signature: Signature,
}

impl<T: ToBytes> Deref for Signed<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
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
    Vote2(Signed<Certificate<Vote>>),
    Wish(Signed<Wish>),
    Timeout(Timeout),
    Sync(Sync),
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
        public_keys: impl IntoIterator<Item = Result<&'a PublicKey>>,
    ) -> Result<()> {
        let public = blst::AggregatePublicKey::aggregate(
            &public_keys
                .into_iter()
                .map(|key| key.map(|key| &key.0))
                .collect::<Result<Vec<_>, _>>()?,
            true,
        )
        .expect("failed to aggregate public key");
        match self
            .0
            .to_signature()
            .verify(true, message, &[], &[], &public.to_public_key(), true)
        {
            ::blst::BLST_ERROR::BLST_SUCCESS => Ok(()),
            _ => Err(Error::msg("invalid aggregate signature")),
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
    pub(crate) fn sign(&self, message: &[u8]) -> Signature {
        Signature(self.0.sign(message, &[], &[]))
    }
}

#[derive(Clone)]
pub struct Signature(blst::Signature);

impl ToBytes for Signature {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
}

impl Signature {
    pub(crate) fn verify(&self, message: &[u8], public_key: &PublicKey) -> Result<()> {
        match self.0.verify(true, message, &[], &[], &public_key.0, true) {
            ::blst::BLST_ERROR::BLST_SUCCESS => Ok(()),
            _ => Err(Error::msg("invalid signature")),
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Domain {
    Propose = 0,
    Prepare = 1,
    Vote = 2,
    Vote2 = 3,
    Wish = 4,
}
