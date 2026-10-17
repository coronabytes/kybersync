//! Background work for the UI: a future runs on the tokio runtime and its
//! result is picked up by polling from the UI thread.

use anyhow::Result;
use std::future::Future;
use std::sync::mpsc::{Receiver, channel};
use tokio::runtime::Handle;
use tokio::task::AbortHandle;

pub struct Job<T> {
    rx: Receiver<Result<T>>,
    abort: AbortHandle,
}

impl<T: Send + 'static> Job<T> {
    pub fn spawn(rt: &Handle, fut: impl Future<Output = Result<T>> + Send + 'static) -> Self {
        let (tx, rx) = channel();
        let task = rt.spawn(async move {
            let _ = tx.send(fut.await);
            crate::wake::wake();
        });
        Job { rx, abort: task.abort_handle() }
    }

    /// The result, once; `None` while still running.
    pub fn poll(&mut self) -> Option<Result<T>> {
        self.rx.try_recv().ok()
    }
}

impl<T> Drop for Job<T> {
    fn drop(&mut self) {
        self.abort.abort();
    }
}

/// Poll an optional job slot: clears it and returns the result when done.
pub fn finish<T: Send + 'static>(slot: &mut Option<Job<T>>) -> Option<Result<T>> {
    let r = slot.as_mut()?.poll()?;
    *slot = None;
    Some(r)
}
