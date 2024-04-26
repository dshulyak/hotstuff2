use std::{
    error::Error,
    marker::PhantomData,
    pin::Pin,
    sync::{Arc, Weak},
};

use futures::Future;
use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;

type ErrorHandler<E> = Arc<Mutex<Option<E>>>;

struct Guard<E> {
    error: ErrorHandler<E>,
    cancel: CancellationToken,
}

impl<E> Drop for Guard<E> {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

pub struct ScopedJoinHandle<'scope, T>(
    tokio::task::JoinHandle<T>,
    std::marker::PhantomData<&'scope mut &'scope ()>,
);

type ScopedFuture<'scope, T> = Pin<Box<dyn 'scope + Send + Future<Output = T>>>;

#[macro_export]
macro_rules! scope {
    ($f:expr) => {{
        $crate::scope::Scope::new().run($f)
    }};
}

#[derive(Debug)]
pub(crate) struct Terminated;

impl std::fmt::Display for Terminated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "terminated")
    }
}

impl Error for Terminated {}

pub struct Scope<'scope, E: 'static> {
    error: ErrorHandler<E>,
    cancel: CancellationToken,
    guard: Weak<Guard<E>>,
    _scope: std::marker::PhantomData<&'scope mut &'scope ()>,
}

impl<'scope, E: 'static + Send> Scope<'scope, E> {
    pub fn new() -> Self {
        Scope {
            error: Arc::new(Mutex::new(None)),
            cancel: CancellationToken::new(),
            guard: Weak::new(),
            _scope: PhantomData,
        }
    }

    pub async fn run<T, F, Fut>(&'scope mut self, f: F) -> Result<T, E>
    where
        T: 'static + Send,
        F: 'scope + FnOnce(&'scope Self) -> Fut,
        Fut: 'scope + Send + Future<Output = Result<T, E>>,
    {
        let guard = Arc::new(Guard {
            error: self.error.clone(),
            cancel: self.cancel.clone(),
        });
        self.guard = Arc::downgrade(&guard);
        let handle = self.spawn(f(self));
        drop(guard);
        self.cancel.cancelled().await;
        let rst = handle.0.await.unwrap();
        match self.error.lock().take() {
            None => Ok(rst.unwrap()),
            Some(err) => Err(err),
        }
    }

    pub fn spawn<T: 'static + Send>(
        &self,
        future: impl 'scope + Send + Future<Output = Result<T, E>>,
    ) -> ScopedJoinHandle<'scope, Result<T, Terminated>> {
        let guard = self.guard.upgrade().expect("scope is dropped");
        let task = Box::pin(async move {
            match future.await {
                Ok(value) => Ok(value),
                Err(err) => {
                    let mut error_handler = guard.error.lock();
                    if error_handler.is_none() {
                        *error_handler = Some(err);
                    }
                    Err(Terminated)
                }
            }
        });
        let f = unsafe {
            std::mem::transmute::<ScopedFuture<'scope, _>, ScopedFuture<'static, _>>(task)
        };
        ScopedJoinHandle(tokio::task::spawn(f), std::marker::PhantomData)
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn test_scope() {
        let result = scope!(|s| async {
            s.spawn(async { Ok(()) });
            Ok::<_, String>(42)
        })
        .await;
        assert_eq!(result, Ok(42));
    }
}
