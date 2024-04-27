use std::borrow::Borrow;
use std::io::{Error, ErrorKind};
use std::time::Duration;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use anyhow::Context;
use hotstuff2::pipelined::Message;
use hotstuff2::types::PublicKey;
use opentelemetry::trace::TraceContextExt;
use parking_lot::Mutex;
use prost::{decode_length_delimiter, Message as ProstMessage};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter, Result};
use tokio::sync::mpsc;
use tracing::Span;
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::proto::{self, protocol};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Protocol(u16);

impl Protocol {
    pub(crate) const fn new(v: u16) -> Self {
        Protocol(v)
    }

    async fn encode<W: AsyncWriteExt + Unpin + Send>(&self, w: &mut W) -> Result<()> {
        w.write_u16(self.0).await?;
        Ok(())
    }

    async fn decode<R: AsyncReadExt + Unpin + Send>(r: &mut R) -> Result<Self> {
        let v = r.read_u16().await?;
        Ok(Protocol(v))
    }
}

pub(crate) struct Connection(quinn::Connection);

impl Connection {
    pub(crate) fn new(conn: quinn::Connection) -> Self {
        Self(conn)
    }

    pub(crate) async fn open(&self, proto: Protocol) -> Result<MsgStream> {
        let (mut send, recv) = self.0.open_bi().await?;
        proto.encode(&mut send).await?;
        Ok(MsgStream::new(
            proto,
            self.0.remote_address(),
            Box::new(send),
            Box::new(recv),
        ))
    }

    pub(crate) async fn accept(&self) -> Result<MsgStream> {
        let (send, mut recv) = self.0.accept_bi().await?;
        let proto = Protocol::decode(&mut recv).await?;
        Ok(MsgStream::new(
            proto,
            self.0.remote_address(),
            Box::new(send),
            Box::new(recv),
        ))
    }

    pub(crate) fn remote(&self) -> SocketAddr {
        self.0.remote_address()
    }

    pub(crate) fn cert(&self) -> anyhow::Result<rustls::Certificate> {
        self.0
            .peer_identity()
            .context("peer didn't return identity")?
            .downcast::<Vec<rustls::Certificate>>()
            .map_err(|_| anyhow::anyhow!("invalid certificate"))?
            .into_iter()
            .next()
            .context("no certificate in returned")
    }
}

pub(crate) struct MsgStream {
    protocol: Protocol,
    remote: SocketAddr,
    send_buf: bytes::BytesMut,
    send: BufWriter<Box<dyn AsyncWrite + Unpin + Send>>,
    recv_buf: bytes::BytesMut,
    recv: BufReader<Box<dyn AsyncRead + Unpin + Send>>,
}

impl MsgStream {
    pub(crate) fn new(
        protocol: Protocol,
        remote: SocketAddr,
        send: Box<dyn AsyncWrite + Unpin + Send>,
        recv: Box<dyn AsyncRead + Unpin + Send>,
    ) -> Self {
        Self {
            protocol,
            remote,
            send_buf: bytes::BytesMut::with_capacity(4096),
            send: BufWriter::new(send),
            recv_buf: bytes::BytesMut::with_capacity(4096),
            recv: BufReader::new(recv),
        }
    }

    pub(crate) fn protocol(&self) -> Protocol {
        self.protocol
    }

    pub(crate) fn remote(&self) -> SocketAddr {
        self.remote
    }

    pub(crate) async fn send_payload(&mut self, payload: protocol::Payload) -> Result<()> {
        let protocol_message = proto::Protocol {
            payload: Some(payload),
            headers: match Span::current().id() {
                Some(_) => Some(proto::Headers {
                    sent_millis: since_unix_epoch().as_millis() as u64,
                    traceparent: Some(Span::current().context().borrow().into()),
                }),
                None => None,
            },
        };
        self.send_message(&protocol_message).await
    }

    pub(crate) async fn recv_payload(&mut self) -> Result<protocol::Payload> {
        let protocol_message = self.recv_message::<proto::Protocol>().await?;
        if let Some(headers) = protocol_message.headers {
            tracing::debug!(
                latency = ?since_unix_epoch().saturating_sub(Duration::from_millis(headers.sent_millis)),
            );
            if let Some(traceparent) = headers.traceparent {
                let remote = Span::current().context().with_remote_span_context(
                    traceparent
                        .borrow()
                        .try_into()
                        .map_err(|err| Error::new(ErrorKind::InvalidData, err))?,
                );
                Span::current().set_parent(remote);
            }
        }
        protocol_message
            .payload
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing payload"))
    }

    pub(crate) async fn send_message<T: ProstMessage>(&mut self, msg: &T) -> Result<()> {
        self.send_buf.resize(0, 0);
        msg.encode_length_delimited(&mut self.send_buf)?;
        self.send.write_all(&self.send_buf).await?;
        self.send.flush().await?;
        Ok(())
    }

    pub(crate) async fn recv_message<T: ProstMessage + Default>(&mut self) -> Result<T> {
        let n = {
            for i in 0..10 {
                self.recv_buf.resize(i + 1, 0);
                self.recv.read_exact(&mut self.recv_buf[i..i + 1]).await?;
                if *self.recv_buf.last().unwrap() < 0x80 {
                    break;
                }
            }
            decode_length_delimiter(&self.recv_buf[..])?
        };
        self.recv_buf.resize(n, 0);
        self.recv.read_exact(&mut self.recv_buf[..n]).await?;
        T::decode(&mut self.recv_buf).map_err(|err| Error::new(ErrorKind::InvalidData, err))
    }
}

struct Table {
    sockets: HashMap<SocketAddr, mpsc::Sender<Arc<Message>>>,
    public_keys: HashMap<PublicKey, mpsc::Sender<Arc<Message>>>,
}

impl Table {
    fn new() -> Self {
        Self {
            sockets: HashMap::new(),
            public_keys: HashMap::new(),
        }
    }
}

pub(crate) struct Router {
    per_channel_buffer_size: usize,
    table: Mutex<Table>,
}

impl Router {
    pub(crate) fn new(per_channel_buffer_size: usize) -> Self {
        Self {
            per_channel_buffer_size: per_channel_buffer_size,
            table: Mutex::new(Table::new()),
        }
    }

    pub(crate) fn register(
        &self,
        addr: SocketAddr,
        publics: impl Iterator<Item = PublicKey>,
    ) -> anyhow::Result<mpsc::Receiver<Arc<Message>>> {
        let (sender, receiver) = mpsc::channel(self.per_channel_buffer_size);
        let mut table = self.table.lock();
        for pubk in publics {
            table.public_keys.insert(pubk, sender.clone());
        }
        table.sockets.insert(addr, sender);
        Ok(receiver)
    }

    pub(crate) fn remove<'a>(
        &self,
        addr: &SocketAddr,
        publics: impl Iterator<Item = &'a PublicKey>,
    ) {
        let mut table = self.table.lock();
        for pubk in publics {
            table.public_keys.remove(&pubk);
        }
        table.sockets.remove(addr);
    }

    pub(crate) fn send_all(&self, msg: Message) {
        let msg = Arc::new(msg);
        self.table.lock().sockets.retain(|_, sender| {
            if let Err(err) = sender.try_send(msg.clone()) {
                tracing::debug!(error = ?err, "failed to send message");
                return false;
            }
            return true;
        });
    }

    pub(crate) fn send_to(&self, pubk: &PublicKey, msg: Message) -> anyhow::Result<()> {
        let msg = Arc::new(msg);
        if let Some(sender) = self.table.lock().public_keys.get(pubk) {
            sender.try_send(msg.clone())?;
        } else {
            anyhow::bail!("peer with public key {:?} is not registered", pubk);
        }
        Ok(())
    }
}

fn since_unix_epoch() -> Duration {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("infallible")
}
