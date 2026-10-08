pub mod cache;
pub mod image;
pub mod linux;
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

pub const ENGINE_VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "-native-15");
#[derive(Clone)]
pub struct Job {
    pub cancel: Arc<AtomicBool>,
    progress: Arc<dyn Fn(String) + Send + Sync>,
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
