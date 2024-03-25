use std::net::SocketAddr;

use hotstuff2::types::Message;
use tokio::io::{AsyncWriteExt, BufReader, BufWriter};

use crate::codec::{AsyncDecode, AsyncEncode, Protocol};

pub(crate) struct Connection(quinn::Connection);

impl Connection {
    pub(crate) fn new(conn: quinn::Connection) -> Self {
        Self(conn)
    }

    pub(crate) async fn open(&self, proto: Protocol) -> anyhow::Result<MsgStream> {
        let (mut send, recv) = self.0.open_bi().await?;
        proto.encode(&mut send).await?;
        Ok(MsgStream {
            protocol: proto,
            remote: self.0.remote_address(),
            send: BufWriter::new(send),
            recv: BufReader::new(recv),
        })
    }

    pub(crate) async fn accept(&self) -> anyhow::Result<MsgStream> {
        let (send, mut recv) = self.0.accept_bi().await?;
        let proto = Protocol::decode(&mut recv).await?;
        Ok(MsgStream {
            protocol: proto,
            remote: self.0.remote_address(),
            send: BufWriter::new(send),
            recv: BufReader::new(recv),
        })
    }
}

pub(crate) struct MsgStream {
    protocol: Protocol,
    remote: SocketAddr,
    send: BufWriter<quinn::SendStream>,
    recv: BufReader<quinn::RecvStream>,
}

impl MsgStream {
    pub(crate) fn new(
        protocol: Protocol,
        remote: SocketAddr,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
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

    pub(crate) async fn send_msg(&mut self, msg: &Message) -> anyhow::Result<()> {
        msg.encode(&mut self.send).await?;
        self.send.flush().await.map_err(|err| anyhow::anyhow!(err))
    }

    pub(crate) async fn recv_msg(&mut self) -> anyhow::Result<Message> {
        Message::decode(&mut self.recv).await
    }
}
