include!(concat!(env!("OUT_DIR"), "/hotstuff.messages.rs"));

use std::borrow::Borrow;

use anyhow::Result;
use hotstuff2::types;

impl From<&types::Signed<types::Vote>> for Vote {
    fn from(vote: &types::Signed<types::Vote>) -> Self {
        Vote {
            view: vote.view.into(),
            block: Some(vote.block.borrow().into()),
            signature: vote.signature.borrow().into(),
            signer: vote.signer.into(),
        }
    }
}

impl TryInto<types::Signed<types::Vote>> for &Vote {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<types::Signed<types::Vote>> {
        let block = self
            .block
            .as_ref()
            .map_or_else(|| Err(anyhow::anyhow!("missing block")), |b| b.try_into())?;
        Ok(types::Signed {
            inner: types::Vote {
                view: self.view.into(),
                block: block,
            },
            signature: self.signature.as_slice().try_into()?,
            signer: self.signer.try_into()?,
        })
    }
}

impl From<&types::Signed<types::Certificate<types::Vote>>> for CommitVote {
    fn from(cert: &types::Signed<types::Certificate<types::Vote>>) -> Self {
        CommitVote {
            cert: Some(cert.inner.borrow().into()),
            signature: cert.signature.borrow().into(),
            signer: cert.signer.into(),
        }
    }
}

impl TryInto<types::Signed<types::Certificate<types::Vote>>> for &CommitVote {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<types::Signed<types::Certificate<types::Vote>>> {
        let cert = self.cert.as_ref().map_or_else(
            || Err(anyhow::anyhow!("missing certificate")),
            |c| c.try_into(),
        )?;
        Ok(types::Signed {
            inner: cert,
            signature: self.signature.as_slice().try_into()?,
            signer: self.signer.try_into()?,
        })
    }
}

impl From<&types::Signed<types::Wish>> for Timeout {
    fn from(timeout: &types::Signed<types::Wish>) -> Self {
        Timeout {
            view: timeout.view.into(),
            signature: timeout.signature.borrow().into(),
            signer: timeout.signer.into(),
        }
    }
}

impl TryInto<types::Signed<types::Wish>> for &Timeout {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<types::Signed<types::Wish>> {
        Ok(types::Signed {
            inner: types::Wish {
                view: self.view.into(),
            },
            signature: self.signature.as_slice().try_into()?,
            signer: self.signer.try_into()?,
        })
    }
}

impl From<&types::Certificate<types::View>> for TimeoutCertificate {
    fn from(cert: &types::Certificate<types::View>) -> Self {
        TimeoutCertificate {
            view: cert.inner.into(),
            aggregated_signature: cert.signature.borrow().into(),
            signers: cert.signers.to_bytes(),
        }
    }
}

impl TryInto<types::Certificate<types::View>> for &TimeoutCertificate {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<types::Certificate<types::View>> {
        Ok(types::Certificate {
            inner: self.view.into(),
            signature: self.aggregated_signature.as_slice().try_into()?,
            signers: self.signers.as_slice().into(),
        })
    }
}

impl From<&types::Block> for Block {
    fn from(block: &types::Block) -> Self {
        Block {
            height: block.height,
            id: block.id.into(),
            previous: block.prev.into(),
        }
    }
}

impl TryInto<types::Block> for &Block {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<types::Block> {
        Ok(types::Block {
            height: self.height,
            id: self.id.as_slice().try_into()?,
            prev: self.previous.as_slice().try_into()?,
        })
    }
}

impl From<&types::Signed<types::Propose>> for Propose {
    fn from(propose: &types::Signed<types::Propose>) -> Self {
        Propose {
            view: propose.view.into(),
            block: Some(propose.block.borrow().into()),
            locked: Some(propose.locked.borrow().into()),
            commit: Some(propose.commit.borrow().into()),
            signature: propose.signature.borrow().into(),
            signer: propose.signer.into(),
        }
    }
}

impl TryInto<types::Signed<types::Propose>> for &Propose {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<types::Signed<types::Propose>> {
        let block = self
            .block
            .as_ref()
            .map_or_else(|| Err(anyhow::anyhow!("missing block")), |b| b.try_into())?;
        let locked = self
            .locked
            .as_ref()
            .map_or_else(|| Err(anyhow::anyhow!("missing locked")), |l| l.try_into())?;
        let commit = self
            .commit
            .as_ref()
            .map_or_else(|| Err(anyhow::anyhow!("missing commit")), |c| c.try_into())?;
        Ok(types::Signed {
            inner: types::Propose {
                view: self.view.into(),
                block: block,
                locked: locked,
                commit: commit,
            },
            signature: self.signature.as_slice().try_into()?,
            signer: self.signer.try_into()?,
        })
    }
}

impl From<&types::Signed<types::Prepare>> for Prepare {
    fn from(prepare: &types::Signed<types::Prepare>) -> Self {
        Prepare {
            locked: Some(prepare.certificate.borrow().into()),
            signature: prepare.signature.borrow().into(),
            signer: prepare.signer.into(),
        }
    }
}

impl TryInto<types::Signed<types::Prepare>> for &Prepare {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<types::Signed<types::Prepare>> {
        let cert = self.locked.as_ref().map_or_else(
            || Err(anyhow::anyhow!("missing certificate")),
            |c| c.try_into(),
        )?;
        Ok(types::Signed {
            inner: types::Prepare { certificate: cert },
            signature: self.signature.as_slice().try_into()?,
            signer: self.signer.try_into()?,
        })
    }
}

impl From<&types::Certificate<types::Vote>> for BlockCertificate {
    fn from(cert: &types::Certificate<types::Vote>) -> Self {
        BlockCertificate {
            view: cert.view.into(),
            block: Some(cert.block.borrow().into()),
            aggregated_signature: cert.signature.borrow().into(),
            signers: cert.signers.to_bytes(),
        }
    }
}

impl TryInto<types::Certificate<types::Vote>> for &BlockCertificate {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<types::Certificate<types::Vote>> {
        Ok(types::Certificate {
            inner: types::Vote {
                view: self.view.into(),
                block: self
                    .block
                    .as_ref()
                    .map_or_else(|| Err(anyhow::anyhow!("missing block")), |b| b.try_into())?,
            },
            signature: self.aggregated_signature.as_slice().try_into()?,
            signers: self.signers.as_slice().into(),
        })
    }
}

impl From<&types::Sync> for Sync {
    fn from(sync: &types::Sync) -> Self {
        Sync {
            locked: sync.locked.as_ref().map(|cert| cert.into()),
            commit: sync.commit.as_ref().map(|cert| cert.into()),
        }
    }
}

impl TryInto<types::Sync> for &Sync {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<types::Sync> {
        Ok(types::Sync {
            locked: if let Some(cert) = &self.locked {
                Some(cert.try_into()?)
            } else {
                None
            },
            commit: if let Some(cert) = &self.commit {
                Some(cert.try_into()?)
            } else {
                None
            },
        })
    }
}

impl From<&types::ProofOfPossession> for ProofOfPossession {
    fn from(pop: &types::ProofOfPossession) -> Self {
        Self {
            signature: pop.signature.borrow().into(),
            public_key: pop.public_key.borrow().into(),
        }
    }
}

impl TryInto<types::ProofOfPossession> for &ProofOfPossession {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<types::ProofOfPossession> {
        Ok(types::ProofOfPossession {
            signature: self.signature.as_slice().try_into()?,
            public_key: self.public_key.as_slice().try_into()?,
        })
    }
}

impl From<&types::Message> for protocol::Payload {
    fn from(msg: &types::Message) -> Self {
        match msg {
            types::Message::Propose(propose) => protocol::Payload::Propose(propose.into()),
            types::Message::Vote(vote) => protocol::Payload::VoteLock(vote.into()),
            types::Message::Prepare(prepare) => protocol::Payload::Prepare(prepare.into()),
            types::Message::Vote2(commit) => protocol::Payload::VoteCommit(commit.into()),
            types::Message::Wish(wish) => protocol::Payload::Timeout(wish.into()),
            types::Message::Timeout(cert) => {
                protocol::Payload::TimeoutCertificate(cert.certificate.borrow().into())
            }
            types::Message::Sync(sync) => protocol::Payload::Sync(sync.into()),
        }
    }
}

impl TryInto<types::Message> for &protocol::Payload {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<types::Message> {
        match self {
            protocol::Payload::Propose(propose) => Ok(types::Message::Propose(propose.try_into()?)),
            protocol::Payload::VoteLock(vote) => Ok(types::Message::Vote(vote.try_into()?)),
            protocol::Payload::Prepare(prepare) => Ok(types::Message::Prepare(prepare.try_into()?)),
            protocol::Payload::VoteCommit(commit) => Ok(types::Message::Vote2(commit.try_into()?)),
            protocol::Payload::Timeout(wish) => Ok(types::Message::Wish(wish.try_into()?)),
            protocol::Payload::TimeoutCertificate(cert) => {
                Ok(types::Message::Timeout(types::Timeout {
                    certificate: cert.try_into()?,
                }))
            }
            protocol::Payload::Sync(sync) => Ok(types::Message::Sync(sync.try_into()?)),
            _ => Err(anyhow::anyhow!("invalid payload")),
        }
    }
}
