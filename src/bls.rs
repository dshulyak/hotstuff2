use crate::codec::ToBytes;
use crate::errors::Error;

use blst::min_pk as blst;
use std::hash;

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
        public_keys: impl IntoIterator<Item = &'a PublicKey>,
    ) -> Option<Error> {
        let public = blst::AggregatePublicKey::aggregate(
            &public_keys.into_iter().map(|pk| &pk.0).collect::<Vec<_>>(),
            true,
        );

        match public {
            Ok(public) => {
                match self.0.to_signature().verify(
                    true,
                    message,
                    &[],
                    &[],
                    &public.to_public_key(),
                    true,
                ) {
                    ::blst::BLST_ERROR::BLST_SUCCESS => None,
                    _ => Some(Error::Invalid),
                }
            }
            Err(e) => Some(Error::Invalid),
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

pub struct Signature(blst::Signature);

impl ToBytes for Signature {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
}

impl Signature {
    pub(crate) fn verify(&self, message: &[u8], public_key: &PublicKey) -> Option<Error> {
        match self.0.verify(true, message, &[], &[], &public_key.0, true) {
            ::blst::BLST_ERROR::BLST_SUCCESS => None,
            _ => Some(Error::Invalid),
        }
    }
}

enum Domain {
    Propose = 0,
    Prepare = 1,
    Vote = 2,
    Vote2 = 3,
    Wish = 4,
}
