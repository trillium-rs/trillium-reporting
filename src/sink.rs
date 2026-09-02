use crate::Report;
use std::{
    collections::VecDeque,
    future::Future,
    sync::{Arc, Mutex},
};
use trillium::Conn;

/// Destination for received reports.
///
/// Implemented for any `Fn(Vec<Report>) -> impl Future<Output = ()>`. Implement it directly on a
/// named type to also inspect the delivering [`Conn`]: same-origin deliveries carry the page's
/// cookies, so session and identity handlers that ran earlier in the tuple have already populated
/// its state.
///
/// Receiving cannot fail. Browsers retry any non-2xx delivery with backoff, so a sink that
/// cannot store a batch should log and drop it rather than cause a retry storm.
pub trait ReportSink: Send + Sync + 'static {
    /// Receives one delivery's worth of reports.
    fn receive(&self, reports: Vec<Report>, conn: &Conn) -> impl Future<Output = ()> + Send;
}

impl<F, Fut> ReportSink for F
where
    F: Fn(Vec<Report>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send,
{
    fn receive(&self, reports: Vec<Report>, _conn: &Conn) -> impl Future<Output = ()> + Send {
        self(reports)
    }
}

/// A [`ReportSink`] that logs each report at info level with the `log` crate.
#[derive(Debug, Clone, Copy, Default)]
pub struct LogSink;

impl ReportSink for LogSink {
    #[allow(
        clippy::unused_async_trait_impl,
        reason = "logging needs no io; async is the trait's signature"
    )]
    async fn receive(&self, reports: Vec<Report>, _conn: &Conn) {
        for report in reports {
            log::info!(
                "{} report from {} ({}): {:?}",
                report.type_name(),
                report.url,
                report.user_agent.as_deref().unwrap_or("unknown user agent"),
                report.body
            );
        }
    }
}

/// A [`ReportSink`] that keeps the most recent reports in memory.
///
/// Cloning yields a handle to the same buffer, so one clone can be given to the receiver and
/// another kept to read from. Once the buffer is full, each new report evicts the oldest.
#[derive(Debug, Clone)]
pub struct MemorySink {
    buffer: Arc<Mutex<VecDeque<Report>>>,
    capacity: usize,
}

impl MemorySink {
    /// Constructs a sink that retains at most `capacity` reports.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is zero.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "MemorySink capacity must be nonzero");
        Self {
            buffer: Arc::new(Mutex::new(VecDeque::with_capacity(capacity))),
            capacity,
        }
    }

    /// Retains a report, evicting the oldest if the buffer is full.
    pub fn push(&self, report: Report) {
        let mut buffer = self.lock();
        if buffer.len() == self.capacity {
            buffer.pop_front();
        }
        buffer.push_back(report);
    }

    /// Returns a copy of the retained reports, oldest first.
    pub fn reports(&self) -> Vec<Report> {
        self.lock().iter().cloned().collect()
    }

    /// Removes and returns the retained reports, oldest first.
    pub fn drain(&self) -> Vec<Report> {
        self.lock().drain(..).collect()
    }

    /// The number of retained reports.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether no reports are retained.
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// The maximum number of reports retained.
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, VecDeque<Report>> {
        self.buffer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Default for MemorySink {
    fn default() -> Self {
        Self::new(1000)
    }
}

impl ReportSink for MemorySink {
    #[allow(
        clippy::unused_async_trait_impl,
        reason = "the buffer is a sync mutex; async is the trait's signature"
    )]
    async fn receive(&self, reports: Vec<Report>, _conn: &Conn) {
        for report in reports {
            self.push(report);
        }
    }
}
