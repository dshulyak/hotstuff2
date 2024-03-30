use std::rc::Rc;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use hotstuff2::types::{Message, PublicKey};
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, BufWriter, Result};
use tokio::sync::mpsc;

use crate::codec::{AsyncDecode, AsyncEncode, Protocol};

pub(crate) struct Connection(quinn::Connection);

impl Connection {
    pub(crate) fn new(conn: quinn::Connection) -> Self {
        Self(conn)
    }

    pub(crate) async fn open(&self, proto: Protocol) -> Result<MsgStream> {
        let (mut send, recv) = self.0.open_bi().await?;
        proto.encode(&mut send).await?;
        Ok(MsgStream {
            protocol: proto,
            remote: self.0.remote_address(),
            send: BufWriter::new(Box::new(send)),
            recv: BufReader::new(Box::new(recv)),
        })
    }

    pub(crate) async fn accept(&self) -> Result<MsgStream> {
        let (send, mut recv) = self.0.accept_bi().await?;
        let proto = Protocol::decode(&mut recv).await?;
        Ok(MsgStream {
            protocol: proto,
            remote: self.0.remote_address(),
            send: BufWriter::new(Box::new(send)),
            recv: BufReader::new(Box::new(recv)),
        })
    }

    pub(crate) fn remote(&self) -> SocketAddr {
        self.0.remote_address()
    }
}

pub(crate) struct MsgStream {
    protocol: Protocol,
    remote: SocketAddr,
    send: BufWriter<Box<dyn AsyncWrite + Unpin + Send>>,
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
            send: BufWriter::new(send),
            recv: BufReader::new(recv),
        }
    }

    pub(crate) fn protocol(&self) -> Protocol {
        self.protocol
    }

    pub(crate) fn remote(&self) -> SocketAddr {
        self.remote
    }

    pub(crate) async fn send_msg(&mut self, msg: &Message) -> Result<()> {
        msg.encode(&mut self.send).await?;
        self.send.flush().await
    }

    pub(crate) async fn recv_msg(&mut self) -> Result<Message> {
        Message::decode(&mut self.recv).await
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
        if table.sockets.contains_key(&addr) {
            anyhow::bail!("peer with address is already registered");
        }
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
