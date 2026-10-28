pub mod cache;
pub mod image;
pub mod kernel_diagnostics;
pub mod linux;
pub mod pattern;
pub mod plugin;
mod report;
pub mod store;
pub mod symbols;
pub mod tui;

use anyhow::{Result, bail};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

pub const ENGINE_VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "-native-33");
#[derive(Clone)]
pub struct Job {
    pub cancel: Arc<AtomicBool>,
    progress: Arc<dyn Fn(String) + Send + Sync>,
    cached: Arc<AtomicBool>,
    prepared: Arc<AtomicBool>,
}
impl Default for Job {
    fn default() -> Self {
        Self::new(|_| {})
    }
}
impl Job {
    pub fn new(progress: impl Fn(String) + Send + Sync + 'static) -> Self {
        Self {
            cancel: Arc::new(AtomicBool::new(false)),
            progress: Arc::new(progress),
            cached: Arc::new(AtomicBool::new(false)),
            prepared: Arc::new(AtomicBool::new(false)),
        }
    }
    pub fn check(&self) -> Result<()> {
        if self.cancel.load(Ordering::Relaxed) {
            bail!("任务已取消 / cancelled");
        }
        Ok(())
    }
    pub fn report(&self, message: impl Into<String>) {
        (self.progress)(message.into());
    }
    /// Record that the result was read from the successful-result cache.
    pub fn mark_cached(&self) {
        self.cached.store(true, Ordering::Relaxed);
    }
    pub fn served_from_cache(&self) -> bool {
        self.cached.load(Ordering::Relaxed)
    }
    /// Record that this job verified a newly opened image's full content digest.
    pub fn mark_prepared(&self) {
        self.prepared.store(true, Ordering::Relaxed);
    }
    pub fn prepared_image(&self) -> bool {
        self.prepared.load(Ordering::Relaxed)
    }
}

pub mod prepare;

pub mod workspace;

pub mod browser;

pub mod dump;

pub mod analysis;
pub mod windows;
pub mod windows_symbols;

pub mod resources;

pub mod result_view;

pub mod snapshots;

mod windows_symbols_archive;

mod engine_service;
