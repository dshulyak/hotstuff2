include!(concat!(env!("OUT_DIR"), "/hotstuff.messages.rs"));

use std::borrow::Borrow;

use anyhow::Result;
use hotstuff2::{pipelined, types};
use opentelemetry::{
    trace::{SpanContext, TraceContextExt, TraceFlags, TraceState},
    Context,
};

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

impl From<&types::Signed<types::View>> for Timeout {
    fn from(timeout: &types::Signed<types::View>) -> Self {
        Timeout {
            view: timeout.inner.into(),
            signature: timeout.signature.borrow().into(),
            signer: timeout.signer.into(),
        }
    }
}

impl TryInto<types::Signed<types::View>> for &Timeout {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<types::Signed<types::View>> {
        Ok(types::Signed {
            inner: self.view.into(),
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

impl From<&types::Signed<pipelined::Propose>> for Propose {
    fn from(propose: &types::Signed<pipelined::Propose>) -> Self {
        Propose {
            view: propose.view.into(),
            block: Some(propose.block.borrow().into()),
            lock: Some(propose.lock.borrow().into()),
            double: Some(propose.commit.borrow().into()),
            signature: propose.signature.borrow().into(),
            signer: propose.signer.into(),
        }
    }
}

impl TryInto<types::Signed<pipelined::Propose>> for &Propose {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<types::Signed<pipelined::Propose>> {
        let block = self
            .block
            .as_ref()
            .map_or_else(|| Err(anyhow::anyhow!("missing block")), |b| b.try_into())?;
        let lock = self
            .lock
            .as_ref()
            .map_or_else(|| Err(anyhow::anyhow!("missing locked")), |l| l.try_into())?;
        let commit = self
            .double
            .as_ref()
            .map_or_else(|| Err(anyhow::anyhow!("missing commit")), |c| c.try_into())?;
        Ok(types::Signed {
            inner: pipelined::Propose {
                view: self.view.into(),
                block: block,
                lock,
                commit: commit,
            },
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

impl From<&pipelined::Message> for protocol::Payload {
    fn from(msg: &pipelined::Message) -> Self {
        match msg {
            pipelined::Message::Propose(propose) => protocol::Payload::Propose(propose.into()),
            pipelined::Message::Vote(vote) => protocol::Payload::Vote(vote.into()),
            pipelined::Message::Wish(view) => protocol::Payload::Timeout(view.into()),
            pipelined::Message::Timeout(timeout) => {
                protocol::Payload::TimeoutCertificate(timeout.into())
            }
            pipelined::Message::Certificate(cert) => protocol::Payload::Certificate(cert.into()),
        }
    }
}

impl TryInto<pipelined::Message> for &protocol::Payload {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<pipelined::Message> {
        match self {
            protocol::Payload::Propose(propose) => {
                Ok(pipelined::Message::Propose(propose.try_into()?))
            }
            protocol::Payload::Vote(vote) => Ok(pipelined::Message::Vote(vote.try_into()?)),
            protocol::Payload::Timeout(view) => Ok(pipelined::Message::Wish(view.try_into()?)),
            protocol::Payload::TimeoutCertificate(cert) => {
                Ok(pipelined::Message::Timeout(cert.try_into()?))
            }
            protocol::Payload::Certificate(cert) => {
                Ok(pipelined::Message::Certificate(cert.try_into()?))
            },
            _ => Err(anyhow::anyhow!("invalid message")),
        }
    }
}

impl From<&Context> for TraceParent {
    fn from(span: &Context) -> Self {
        let span = span.span();
        let span_context = span.span_context();
        let traceid = span_context.trace_id();
        let spanid = u64::from_be_bytes(span_context.span_id().to_bytes());
        let flags = span_context.trace_flags() & TraceFlags::SAMPLED;
        TraceParent {
            version: 0,
            trace_id: traceid.to_bytes().to_vec(),
            parent_id: spanid,
            trace_flags: flags.to_u8().into(),
        }
    }
}

impl TryInto<SpanContext> for &TraceParent {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<SpanContext> {
        Ok(SpanContext::new(
            u128::from_be_bytes(self.trace_id.as_slice().try_into()?).into(),
            self.parent_id.into(),
            TraceFlags::new(self.trace_flags.try_into()?),
            true,
            TraceState::default(),
        ))
    }
}
