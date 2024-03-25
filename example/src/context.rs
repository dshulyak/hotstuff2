use std::future::Future;
use std::time::Duration;

use tokio::select;
use tokio::time::sleep;
use tokio_util::sync::{CancellationToken, WaitForCancellationFuture};

pub(crate) struct Context {
    cancel: CancellationToken,
}

impl Context {
    pub(crate) fn new() -> Self {
        Self {
            cancel: CancellationToken::new(),
        }
    }

    pub(crate) fn cancel(&self) {
        self.cancel.cancel();
    }

    pub(crate) fn cancelled(&self) -> WaitForCancellationFuture<'_> {
        self.cancel.cancelled()
    }

    pub(crate) fn timeout<'a>(&'a self, timeout: Duration) -> Timeout<'a> {
        Timeout { ctx: self, timeout }
    }

    pub(crate) fn timeout_secs<'a>(&'a self, secs: u64) -> Timeout<'a> {
        self.timeout(Duration::from_secs(secs))
    }

    pub(crate) async fn select<T, F: Future<Output = T>>(&self, f: F) -> anyhow::Result<T> {
        select! {
            _ = self.cancel.cancelled() => {
                anyhow::bail!("cancelled");
            },
            res = f => {
                Ok(res)
            }
        }
    }
}

pub(crate) struct Timeout<'a> {
    ctx: &'a Context,
    timeout: Duration,
}

impl<'a> Timeout<'a> {
    pub(crate) async fn select<T, F: Future<Output = T>>(&self, f: F) -> anyhow::Result<T> {
        select! {
            _ = self.ctx.cancelled() => {
                anyhow::bail!("cancelled");
            },
            _ = sleep(self.timeout) => {
                anyhow::bail!("timeout");
            },
            res = f => {
                Ok(res)
            }
        }
    }
}
