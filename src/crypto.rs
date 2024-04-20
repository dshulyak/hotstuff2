use anyhow::Result;

use crate::types::{AggregateSignature, Domain, PrivateKey, PublicKey, Signature, SIGNATURE_SIZE};

pub trait Backend {
    fn sign(private_key: &PrivateKey, domain: Domain, msg: &[u8]) -> Signature;

    fn verify(domain: Domain, pubkey: &PublicKey, sig: &Signature, msg: &[u8]) -> Result<()>;

    fn aggregate<'a>(
        signatures: impl IntoIterator<Item = &'a Signature>,
    ) -> Result<AggregateSignature>;

    fn verify_aggregated<'a>(
        domain: Domain,
        pubks: impl IntoIterator<Item = Option<&'a PublicKey>>,
        sig: &AggregateSignature,
        msg: &[u8],
    ) -> Result<()>;
}

#[derive(Debug)]
pub struct BLSTBackend;

impl Backend for BLSTBackend {
    fn sign(private_key: &PrivateKey, domain: Domain, msg: &[u8]) -> Signature {
        private_key.sign(domain, msg)
    }

    fn verify(domain: Domain, pubkey: &PublicKey, sig: &Signature, msg: &[u8]) -> Result<()> {
        sig.verify(domain, msg, pubkey)
    }

    fn aggregate<'a>(
        signatures: impl IntoIterator<Item = &'a Signature>,
    ) -> Result<AggregateSignature> {
        // Aggregate the signatures
        AggregateSignature::aggregate(signatures)
            .map_err(|err| anyhow::anyhow!("invalid signature: {:?}", err))
    }

    fn verify_aggregated<'a>(
        domain: Domain,
        public_keys: impl IntoIterator<Item = Option<&'a PublicKey>>,
        sig: &AggregateSignature,
        msg: &[u8],
    ) -> Result<()> {
        sig.verify(domain, msg, public_keys)
    }
}

pub struct NoopBackend;

impl Backend for NoopBackend {
    fn sign(_private_key: &PrivateKey, _domain: Domain, _msg: &[u8]) -> Signature {
        Signature::new([0u8; SIGNATURE_SIZE])
    }

    fn verify(_domain: Domain, _pubkey: &PublicKey, _sig: &Signature, _msg: &[u8]) -> Result<()> {
        Ok(())
    }

    fn aggregate<'a>(
        _signatures: impl IntoIterator<Item = &'a Signature>,
    ) -> Result<AggregateSignature> {
        Ok(AggregateSignature::empty())
    }

    fn verify_aggregated<'a>(
        _domain: Domain,
        _pubks: impl IntoIterator<Item = Option<&'a PublicKey>>,
        _sig: &AggregateSignature,
        _msg: &[u8],
    ) -> Result<()> {
        Ok(())
    }
}