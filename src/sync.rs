#![allow(unused)]

#[cfg(not(all(test, loom)))]
pub(crate) mod parking {
    #[derive(Debug)]
    pub(crate) struct Mutex<T>(parking_lot::Mutex<T>);

    #[allow(dead_code)]
    impl<T> Mutex<T> {
        #[inline]
        pub(crate) fn new(t: T) -> Mutex<T> {
            Mutex(parking_lot::Mutex::new(t))
        }

        #[inline]
        pub(crate) fn lock(&self) -> parking_lot::MutexGuard<'_, T> {
            self.0.lock()
        }
    }
}

#[cfg(not(all(test, loom)))]
pub(crate) use parking::Mutex;

#[cfg(all(test, loom))]
pub(crate) mod loom {
    #[derive(Debug)]
    pub(crate) struct Mutex<T>(loom::sync::Mutex<T>);

    #[allow(dead_code)]
    impl<T> Mutex<T> {
        #[inline]
        pub(crate) fn new(t: T) -> Mutex<T> {
            Mutex(loom::sync::Mutex::new(t))
        }

        #[inline]
        pub(crate) fn lock(&self) -> loom::sync::MutexGuard<'_, T> {
            self.0.lock().unwrap()
        }
    }
}

#[cfg(all(test, loom))]
pub(crate) use loom::Mutex;
