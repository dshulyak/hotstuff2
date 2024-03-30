use async_trait::async_trait;
use bit_vec::BitVec;
use hotstuff2::types::{
    Block, Certificate, Message, Prepare, Propose, PublicKey, Signature, Signed, Sync as SyncMsg,
    Timeout, ToBytes, View, Vote, Wish, PUBLIC_KEY_SIZE, SIGNATURE_SIZE,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter, Error, ErrorKind, Result};

#[async_trait]
pub(crate) trait AsyncEncode {
    async fn encode<W: AsyncWriteExt + Unpin + Send>(&self, w: &mut W) -> Result<()>;

    async fn encode_to_bytes(&self) -> Result<Box<[u8]>> {
        let mut buf = Vec::new();
        let mut bw = BufWriter::new(&mut buf);
        self.encode(&mut bw).await?;
        bw.flush().await?;
        Ok(buf.into())
    }

    // short_id returns the first 8 chars of the hexary enncoding for blake3 hash of the encoded bytes.
    async fn short_id(&self) -> Result<String> {
        Ok(blake3::hash(&self.encode_to_bytes().await?).to_hex()[..8].to_string())
    }
}

#[async_trait]
pub(crate) trait AsyncDecode: Sized {
    async fn decode<R: AsyncReadExt + Unpin + Send>(r: &mut R) -> Result<Self>;

    async fn decode_from_bytes(buf: &[u8]) -> Result<Self> {
        Self::decode(&mut &buf[..]).await
    }
}

#[async_trait]
impl AsyncEncode for Block {
    async fn encode<W: AsyncWriteExt + Unpin + Send>(&self, w: &mut W) -> Result<()> {
        w.write_all(self.prev.as_bytes()).await?;
        w.write_all(self.id.as_bytes()).await?;
        Ok(())
    }
}

#[async_trait]
impl AsyncDecode for Block {
    async fn decode<R: AsyncReadExt + Unpin + Send>(r: &mut R) -> Result<Self> {
        let mut prev = [0; 32];
        r.read_exact(&mut prev).await?;
        let mut id = [0; 32];
        r.read_exact(&mut id).await?;
        Ok(Block::new(prev.into(), id.into()))
    }
}

#[async_trait]
impl AsyncEncode for Vote {
    async fn encode<W: AsyncWriteExt + Unpin + Send>(&self, w: &mut W) -> Result<()> {
        w.write_u64(self.view.into()).await?;
        self.block.encode(w).await?;
        Ok(())
    }
}

#[async_trait]
impl AsyncDecode for Vote {
    async fn decode<R: AsyncReadExt + Unpin + Send>(r: &mut R) -> Result<Self> {
        let view = r.read_u64().await?;
        let block = Block::decode(r).await?;
        Ok(Vote {
            view: view.into(),
            block,
        })
    }
}

#[async_trait]
impl AsyncEncode for Wish {
    async fn encode<W: AsyncWriteExt + Unpin + Send>(&self, w: &mut W) -> Result<()> {
        w.write_u64(self.view.into()).await?;
        Ok(())
    }
}

#[async_trait]
impl AsyncDecode for Wish {
    async fn decode<R: AsyncReadExt + Unpin + Send>(r: &mut R) -> Result<Self> {
        let view = r.read_u64().await?;
        Ok(Wish { view: view.into() })
    }
}

#[async_trait]
impl<T: AsyncEncode + ToBytes + Sync> AsyncEncode for Signed<T> {
    async fn encode<W: AsyncWriteExt + Unpin + Send>(&self, w: &mut W) -> Result<()> {
        self.inner.encode(w).await?;
        w.write_u16(self.signer).await?;
        w.write_all(self.signature.to_bytes()).await?;
        Ok(())
    }
}

#[async_trait]
impl<T: AsyncDecode + ToBytes + Send> AsyncDecode for Signed<T> {
    async fn decode<R: AsyncReadExt + Unpin + Send>(r: &mut R) -> Result<Self> {
        let inner = T::decode(r).await?;
        let signer = r.read_u16().await?;
        let mut signature = [0; SIGNATURE_SIZE];
        r.read_exact(&mut signature).await?;
        Ok(Signed {
            inner,
            signer,
            signature: Signature::from_bytes(&signature)
                .map_err(|_| Error::new(ErrorKind::InvalidData, "failed to parse signature"))?,
        })
    }
}

#[async_trait]
impl AsyncEncode for View {
    async fn encode<W: AsyncWriteExt + Unpin + Send>(&self, w: &mut W) -> Result<()> {
        w.write_u64(self.0).await?;
        Ok(())
    }
}

#[async_trait]
impl AsyncDecode for View {
    async fn decode<R: AsyncReadExt + Unpin + Send>(r: &mut R) -> Result<Self> {
        let view = r.read_u64().await?;
        Ok(View(view))
    }
}

#[async_trait]
impl<T: AsyncEncode + ToBytes + Sync> AsyncEncode for Certificate<T> {
    async fn encode<W: AsyncWriteExt + Unpin + Send>(&self, w: &mut W) -> Result<()> {
        self.inner.encode(w).await?;
        w.write_all(&self.signature.to_bytes()).await?;
        let signers = self.signers.to_bytes();
        w.write_u16(signers.len() as u16).await?;
        w.write_all(&signers).await?;
        Ok(())
    }
}

#[async_trait]
impl<T: AsyncDecode + ToBytes + Send> AsyncDecode for Certificate<T> {
    async fn decode<R: AsyncReadExt + Unpin + Send>(r: &mut R) -> Result<Self> {
        let inner = T::decode(r).await?;
        let mut signature = [0; SIGNATURE_SIZE];
        r.read_exact(&mut signature).await?;

        let len = r.read_u16().await?;
        let mut signers = vec![0; len as usize];
        r.read_exact(&mut signers).await?;
        Ok(Certificate {
            inner,
            signature: Signature::from_bytes(&signature)
                .map_err(|_| Error::new(ErrorKind::InvalidData, "failed to parse signature"))?
                .into(),
            signers: BitVec::from_bytes(&signers),
        })
    }
}

#[async_trait]
impl AsyncEncode for Timeout {
    async fn encode<W: AsyncWriteExt + Unpin + Send>(&self, w: &mut W) -> Result<()> {
        self.certificate.encode(w).await?;
        Ok(())
    }
}

#[async_trait]
impl AsyncDecode for Timeout {
    async fn decode<R: AsyncReadExt + Unpin + Send>(r: &mut R) -> Result<Self> {
        let certificate = Certificate::decode(r).await?;
        Ok(Timeout { certificate })
    }
}

#[async_trait]
impl AsyncEncode for Propose {
    async fn encode<W: AsyncWriteExt + Unpin + Send>(&self, w: &mut W) -> Result<()> {
        self.view.encode(w).await?;
        self.block.encode(w).await?;
        self.locked.encode(w).await?;
        self.double.encode(w).await?;
        Ok(())
    }
}

#[async_trait]
impl AsyncDecode for Propose {
    async fn decode<R: AsyncReadExt + Unpin + Send>(r: &mut R) -> Result<Self> {
        let view = View::decode(r).await?;
        let block = Block::decode(r).await?;
        let locked = Certificate::<Vote>::decode(r).await?;
        let double = Certificate::<Vote>::decode(r).await?;
        Ok(Propose {
            view,
            block,
            locked,
            double,
        })
    }
}

#[async_trait]
impl AsyncEncode for Prepare {
    async fn encode<W: AsyncWriteExt + Unpin + Send>(&self, w: &mut W) -> Result<()> {
        self.certificate.encode(w).await?;
        Ok(())
    }
}

#[async_trait]
impl AsyncDecode for Prepare {
    async fn decode<R: AsyncReadExt + Unpin + Send>(r: &mut R) -> Result<Self> {
        let certificate = Certificate::decode(r).await?;
        Ok(Prepare { certificate })
    }
}

#[async_trait]
impl AsyncEncode for SyncMsg {
    async fn encode<W: AsyncWriteExt + Unpin + Send>(&self, w: &mut W) -> Result<()> {
        if let Some(locked) = &self.locked {
            w.write_u8(1).await?;
            locked.encode(w).await?;
        } else {
            w.write_u8(0).await?;
        }
        if let Some(double) = &self.commit {
            w.write_u8(1).await?;
            double.encode(w).await?;
        } else {
            w.write_u8(0).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl AsyncDecode for SyncMsg {
    async fn decode<R: AsyncReadExt + Unpin + Send>(r: &mut R) -> Result<Self> {
        let locked = match r.read_u8().await? {
            0 => None,
            1 => Some(Certificate::decode(r).await?),
            tag => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("invalid tag for locked {}", tag),
                ));
            }
        };
        let commit = match r.read_u8().await? {
            0 => None,
            1 => Some(Certificate::decode(r).await?),
            tag => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("invalid tag for double {}", tag),
                ));
            }
        };
        Ok(SyncMsg { locked, commit })
    }
}

#[async_trait]
impl AsyncEncode for Message {
    async fn encode<W: AsyncWriteExt + Unpin + Send>(&self, w: &mut W) -> Result<()> {
        match self {
            Message::Propose(msg) => {
                w.write_u8(0).await?;
                msg.encode(w).await?;
            }
            Message::Prepare(msg) => {
                w.write_u8(1).await?;
                msg.encode(w).await?;
            }
            Message::Vote(msg) => {
                w.write_u8(2).await?;
                msg.encode(w).await?;
            }
            Message::Vote2(msg) => {
                w.write_u8(3).await?;
                msg.encode(w).await?;
            }
            Message::Wish(msg) => {
                w.write_u8(4).await?;
                msg.encode(w).await?;
            }
            Message::Timeout(msg) => {
                w.write_u8(5).await?;
                msg.encode(w).await?;
            }
            Message::Sync(msg) => {
                w.write_u8(6).await?;
                msg.encode(w).await?;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl AsyncDecode for Message {
    async fn decode<R: AsyncReadExt + Unpin + Send>(r: &mut R) -> Result<Self> {
        match r.read_u8().await? {
            0 => Ok(Message::Propose(Signed::<Propose>::decode(r).await?)),
            1 => Ok(Message::Prepare(Signed::<Prepare>::decode(r).await?)),
            2 => Ok(Message::Vote(Signed::<Vote>::decode(r).await?)),
            3 => Ok(Message::Vote2(
                Signed::<Certificate<Vote>>::decode(r).await?,
            )),
            4 => Ok(Message::Wish(Signed::<Wish>::decode(r).await?)),
            5 => Ok(Message::Timeout(Timeout::decode(r).await?)),
            6 => Ok(Message::Sync(SyncMsg::decode(r).await?)),
            tag => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("invalid tag {}", tag),
                ))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Protocol(u16);

impl Protocol {
    pub(crate) const fn new(v: u16) -> Self {
        Protocol(v)
    }
}

#[async_trait]
impl AsyncEncode for Protocol {
    async fn encode<W: AsyncWriteExt + Unpin + Send>(&self, w: &mut W) -> Result<()> {
        w.write_u16(self.0).await?;
        Ok(())
    }
}

#[async_trait]
impl AsyncDecode for Protocol {
    async fn decode<R: AsyncReadExt + Unpin + Send>(r: &mut R) -> Result<Self> {
        let v = r.read_u16().await?;
        Ok(Protocol(v))
    }
}

pub(crate) struct ProofOfPossesion {
    pub(crate) key: PublicKey,
    pub(crate) signature: Signature,
}

#[async_trait]
impl AsyncEncode for ProofOfPossesion {
    async fn encode<W: AsyncWriteExt + Unpin + Send>(&self, w: &mut W) -> Result<()> {
        let pubk = self.key.to_bytes();
        w.write_all(&pubk).await?;
        w.write_all(self.signature.to_bytes()).await?;
        Ok(())
    }
}

#[async_trait]
impl AsyncDecode for ProofOfPossesion {
    async fn decode<R: AsyncReadExt + Unpin + Send>(r: &mut R) -> Result<Self> {
        let mut pubk = [0u8; PUBLIC_KEY_SIZE];
        r.read_exact(&mut pubk).await?;
        let key = PublicKey::from_bytes(&pubk).map_err(|err| {
            Error::new(
                ErrorKind::InvalidData,
                format!("invalid public key: {}", err),
            )
        })?;
        let mut sig = [0u8; SIGNATURE_SIZE];
        r.read_exact(&mut sig).await?;
        let signature = Signature::from_bytes(&sig).map_err(|err| {
            Error::new(
                ErrorKind::InvalidData,
                format!("invalid signature: {}", err),
            )
        })?;
        Ok(ProofOfPossesion { key, signature })
    }
}
