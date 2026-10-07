//! Native Linux analysis: sessions, kernel discovery and ISF-driven plugins.
pub use crate::plugin::{Descriptor, PLUGINS, Plugin};
use crate::{
    Job,
    image::{Image, VirtualMemory},
    report::{hex, partial},
    store::{self, Results},
    symbols::{self, Isf},
};
use anyhow::{Context, Result, bail, ensure};
use std::{
    collections::{BTreeMap, HashSet},
    net::{Ipv4Addr, Ipv6Addr},
    path::Path,
};

mod discover;
mod engine;
mod fs;
mod kernel;
mod memory;
mod net;
mod process;
mod session;
#[cfg(test)]
pub(crate) mod tests;
mod walk;

pub use discover::discover;
pub use engine::Linux;
pub(crate) use engine::Task;
use engine::unrouted;
pub use session::Session;

const REGION_LIMIT: u64 = 1024 * 1024;
const OBJECT_LIMIT: u64 = 1_000_000;
const LIMIT: usize = 1_000_000;
const DEPTH_LIMIT: usize = 1024;
fn add(base: u64, offset: u64) -> Result<u64> {
    base.checked_add(offset).context("对象地址溢出")
}
fn nul_strings(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|b| *b == 0)
        .filter(|b| !b.is_empty())
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .collect()
}
fn command_line(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let bytes = bytes.strip_suffix(&[0]).unwrap_or(bytes);
    bytes
        .split(|b| *b == 0)
        .map(|b| String::from_utf8_lossy(b))
        .collect::<Vec<_>>()
        .join(" ")
}
fn permissions(flags: u64) -> String {
    [
        if flags & 1 != 0 { 'r' } else { '-' },
        if flags & 2 != 0 { 'w' } else { '-' },
        if flags & 4 != 0 { 'x' } else { '-' },
        if flags & 8 != 0 { 's' } else { 'p' },
    ]
    .iter()
    .collect()
}
fn inode_type(mode: u64) -> &'static str {
    match mode & 0xf000 {
        0x1000 => "FIFO",
        0x2000 => "Character",
        0x4000 => "Directory",
        0x6000 => "Block",
        0x8000 => "Regular",
        0xa000 => "Symlink",
        0xc000 => "Socket",
        _ => "Unknown",
    }
}
fn user_string(vm: &VirtualMemory<'_>, start: u64, limit: usize, job: &Job) -> Result<String> {
    let mut bytes = Vec::new();
    while bytes.len() < limit {
        job.check()?;
        let addr = start
            .checked_add(bytes.len() as u64)
            .context("用户字符串地址溢出")?;
        let n = (4096 - (addr & 4095) as usize).min(limit - bytes.len());
        let mut chunk = vec![0; n];
        vm.read(addr, &mut chunk)?;
        if let Some(end) = chunk.iter().position(|b| *b == 0) {
            bytes.extend_from_slice(&chunk[..end]);
            return Ok(String::from_utf8_lossy(&bytes).into_owned());
        }
        bytes.extend(chunk);
    }
    anyhow::bail!("用户字符串超过 {limit} 字节")
}

pub enum Outcome {
    Ready(Results),
    Choose(Vec<String>),
}
pub fn analyze(
    image_path: &Path,
    symbols_path: &Path,
    choice: Option<&str>,
    plugin: Plugin,
    cache: &Path,
    use_cache: bool,
    job: &Job,
) -> Result<Outcome> {
    Session::default().analyze(
        &Request {
            image: image_path,
            symbols: symbols_path,
            choice,
            plugin,
            cache,
            use_cache,
            network: false,
        },
        job,
    )
}
pub struct Request<'a> {
    pub image: &'a Path,
    pub symbols: &'a Path,
    pub choice: Option<&'a str>,
    pub plugin: Plugin,
    pub cache: &'a Path,
    pub use_cache: bool,
    pub network: bool,
}
pub fn banner_result(image: &Image, job: &Job) -> Result<Results> {
    let rows = image
        .banners(job)?
        .into_iter()
        .map(|(p, b)| {
            vec![
                format!("{p:#018x}"),
                String::from_utf8_lossy(&b[..b.len() - 1]).into_owned(),
            ]
        })
        .collect();
    let rows: Vec<Vec<String>> = rows;
    let mut rows = if rows.is_empty() {
        image
            .windows_candidates(job)?
            .iter()
            .map(|c| {
                vec![
                    format!("{:#018x}", c.offset),
                    format!("Windows PDB {}", c.pdb.key()),
                ]
            })
            .collect()
    } else {
        rows
    };
    if rows.is_empty() && image.windows_container.is_some() {
        rows.push(vec![
            "[container]".into(),
            format!("Windows container {}", image.format),
        ]);
    }
    let system = if image.windows_container.is_some()
        || rows.iter().any(|r| r[1].starts_with("Windows PDB "))
    {
        "windows"
    } else {
        "linux"
    };
    Ok(Results {
        plugin: "banners".into(),
        columns: Plugin::Banners
            .descriptor()
            .columns
            .iter()
            .map(|s| (*s).into())
            .collect(),
        rows,
        complete: true,
        diagnostics: vec![],
        banner: String::new(),
        symbol: String::new(),
        page_table: 0,
        historical: false,
        system: system.into(),
        kernel_identity: serde_json::Value::Null,
    })
}
