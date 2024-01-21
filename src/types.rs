use anyhow::{anyhow, Result};
use bit_vec::BitVec;
use blst::min_pk as blst;
use std::ops::{Add, AddAssign, Deref, Rem};

pub trait ToBytes {
    fn to_bytes(&self) -> Vec<u8>;
}

pub type Signer = u16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ID([u8; 32]);

impl ID {
    pub fn new(bytes: [u8; 32]) -> Self {
        ID(bytes.into())
    }
}

impl ID {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Default for ID {
    fn default() -> Self {
        ID([0; 32].into())
    }
}

impl PartialOrd<ID> for ID {
    fn partial_cmp(&self, other: &ID) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ID {
    fn cmp(&self, other: &ID) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Block {
    pub height: u64,
    pub id: ID,
}

impl Block {
    pub fn new(height: u64, id: ID) -> Self {
        Block { height, id }
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

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, Eq, PartialEq)]
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
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

impl From<i32> for View {
    fn from(v: i32) -> Self {
        View(v as u64)
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

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Timeout {
    pub certificate: Certificate<View>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
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

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Sync {
    pub locked: Option<Certificate<Vote>>,
    pub double: Option<Certificate<Vote>>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Message {
    Propose(Signed<Propose>),
    Prepare(Signed<Prepare>),
    Vote(Signed<Vote>),
    Vote2(Signed<Certificate<Vote>>),
    Wish(Signed<Wish>),
    Timeout(Timeout),
    Sync(Sync),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey(blst::PublicKey);

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

#[derive(Debug, Clone)]
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
        domain: Domain,
        message: &[u8],
        public_keys: impl IntoIterator<Item = &'a PublicKey>,
    ) -> Result<()> {
        let public = blst::AggregatePublicKey::aggregate(
            &public_keys
                .into_iter()
                .map(|key| &key.0)
                .collect::<Vec<_>>(),
            false,
        )
        .expect("failed to aggregate public key");
        match self.0.to_signature().verify(
            true,
            message,
            domain.into(),
            &[],
            &public.to_public_key(),
            false,
        ) {
            ::blst::BLST_ERROR::BLST_SUCCESS => Ok(()),
            err => Err(anyhow!("failed to verify signature: {:?}", err)),
        }
    }
}

impl PartialEq for AggregateSignature {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_signature() == other.0.to_signature()
    }
}

impl Eq for AggregateSignature {}

impl ToBytes for AggregateSignature {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_signature().to_bytes().to_vec()
    }
}

#[derive(Debug, Clone)]
pub struct PrivateKey(blst::SecretKey);

impl PrivateKey {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        PrivateKey(blst::SecretKey::key_gen(seed, &[]).expect("failed to generate private key"))
    }

    pub(crate) fn sign(&self, dst: Domain, message: &[u8]) -> Signature {
        Signature(self.0.sign(message, dst.into(), &[]))
    }

    pub(crate) fn public(&self) -> PublicKey {
        PublicKey(self.0.sk_to_pk())
    }
}

#[derive(Debug, Clone)]
pub struct Signature(blst::Signature);

impl Into<AggregateSignature> for Signature {
    fn into(self) -> AggregateSignature {
        AggregateSignature(blst::AggregateSignature::from_signature(&self.0))
    }
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for Signature {}

impl Signature {
    pub(crate) fn verify(
        &self,
        domain: Domain,
        message: &[u8],
        public_key: &PublicKey,
    ) -> Result<()> {
        match self
            .0
            .verify(true, message, domain.into(), &[], &public_key.0, false)
        {
            ::blst::BLST_ERROR::BLST_SUCCESS => Ok(()),
            err => Err(anyhow!("invalid signature: {:?}", err)),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Domain {
    Propose,
    Prepare,
    Vote,
    Vote2,
    Wish,
    Possesion,
}

impl Into<&'static [u8]> for Domain {
    fn into(self) -> &'static [u8] {
        match self {
            Domain::Propose => b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_PRO_",
            Domain::Prepare => b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_PRE_",
            Domain::Vote => b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_V_",
            Domain::Vote2 => b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_V2_",
            Domain::Wish => b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_W_",
            Domain::Possesion => b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_",
        }
    }
}
