//! A discovery session fetches and parses each official directory at most once.
use super::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

pub(super) type Entries = Arc<Vec<(String, Option<String>)>>;
const LIMIT: u64 = 16 * 1024 * 1024;
const TTL: Duration = Duration::from_secs(24 * 60 * 60);

pub(super) struct Indexes<'a> {
    cache: &'a Path,
    network: bool,
    force: bool,
    job: &'a Job,
    entries: BTreeMap<String, std::result::Result<Entries, String>>,
    cached: BTreeSet<String>,
}
impl<'a> Indexes<'a> {
    pub fn new(cache: &'a Path, network: bool, force: bool, job: &'a Job) -> Self {
        Self {
            cache,
            network,
            force,
            job,
            entries: BTreeMap::new(),
            cached: BTreeSet::new(),
        }
    }
    pub fn get(&mut self, url: &str) -> Result<Entries> {
        self.get_with(url, &mut |url| {
            self.job.report(format!("查找官方内核调试包: {url}"));
            let mut file = tempfile::tempfile()?;
            http::download(
                http::Request {
                    url,
                    range: None,
                    limit: LIMIT,
                    timeout: Duration::from_secs(45),
                    https_only: true,
                },
                file.try_clone()?,
                self.job,
            )?;
            file.rewind()?;
            let mut html = String::new();
            file.read_to_string(&mut html)?;
            Ok(html)
        })
    }
    fn get_with(
        &mut self,
        url: &str,
        fetch: &mut impl FnMut(&str) -> Result<String>,
    ) -> Result<Entries> {
        self.job.check()?;
        if let Some(result) = self.entries.get(url) {
            return result.clone().map_err(anyhow::Error::msg);
        }
        let result = self.load(url, fetch).map_err(|e| format!("{e:#}"));
        // Including errors prevents repeated slow failures for images with many banners.
        self.entries.insert(url.into(), result.clone());
        self.job.check()?;
        result.map_err(anyhow::Error::msg)
    }
    fn load(
        &mut self,
        url: &str,
        fetch: &mut impl FnMut(&str) -> Result<String>,
    ) -> Result<Entries> {
        let path = index_path(self.cache, url);
        let cached = path
            .metadata()
            .ok()
            .filter(|m| m.is_file() && m.len() <= LIMIT)
            .and_then(|m| {
                fs::read_to_string(&path)
                    .ok()
                    .and_then(|html| parse(&html).ok().map(|entries| (m, entries)))
            });
        if let Some((metadata, entries)) = &cached {
            let fresh = metadata
                .modified()
                .ok()
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|age| age < TTL);
            if !self.network || (!self.force && fresh) {
                self.cached.insert(url.into());
                self.job.report(format!("复用官方索引缓存: {url}"));
                return Ok(entries.clone());
            }
        }
        ensure!(self.network, "离线模式且缺少有效官方索引缓存: {url}");
        let fetched = fetch(url).and_then(|html| {
            self.job.check()?;
            let entries = parse(&html)?;
            store::atomic_stream(&path, self.job, |writer| {
                writer.write_all(html.as_bytes())?;
                Ok(())
            })?;
            Ok(entries)
        });
        match fetched {
            Ok(entries) => Ok(entries),
            Err(error) => {
                self.job.check()?;
                if let Some((_, entries)) = cached {
                    self.job
                        .report(format!("官方源不可用，使用旧索引缓存: {url} · {error:#}"));
                    // A failed refresh has already attempted this URL in this session.
                    Ok(entries)
                } else {
                    Err(error)
                }
            }
        }
    }
    /// Retry a cache miss once, refreshing only URLs not yet fetched this session.
    pub fn refresh_cached(&mut self) -> bool {
        if !self.network || self.force || self.cached.is_empty() {
            return false;
        }
        for url in std::mem::take(&mut self.cached) {
            self.entries.remove(&url);
        }
        self.force = true;
        true
    }
}
fn parse(html: &str) -> Result<Entries> {
    ensure!(
        html.len() as u64 <= LIMIT && html.contains("href=") && html.contains('<'),
        "官方索引格式无效或超过 16 MiB"
    );
    Ok(Arc::new(packages::links(html)))
}
fn index_path(cache: &Path, url: &str) -> PathBuf {
    use sha2::{Digest, Sha256};
    cache
        .join("symbols/build/indexes")
        .join(format!("{:x}.html", Sha256::digest(url.as_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;
    const URL: &str = "https://example.test/pool/";
    const OLD: &str = "<a href=\"old.deb\">old</a>";
    const NEW: &str = "<a href=\"new.deb\">new</a>";
    fn cached(cache: &Path, text: &str, expired: bool) {
        let path = index_path(cache, URL);
        store::atomic_write(&path, text.as_bytes()).unwrap();
        if expired {
            File::options()
                .write(true)
                .open(path)
                .unwrap()
                .set_times(
                    std::fs::FileTimes::new()
                        .set_modified(std::time::SystemTime::now() - TTL - Duration::from_secs(1)),
                )
                .unwrap();
        }
    }
    #[test]
    fn fresh_indexes_are_parsed_once_and_a_cache_miss_refreshes_only_once() {
        let dir = tempfile::tempdir().unwrap();
        let job = Job::default();
        cached(dir.path(), OLD, false);
        let mut indexes = Indexes::new(dir.path(), true, false, &job);
        let mut calls = 0;
        let mut fetch = |_: &str| {
            calls += 1;
            Ok(NEW.to_owned())
        };
        let first = indexes.get_with(URL, &mut fetch).unwrap();
        let second = indexes.get_with(URL, &mut fetch).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(first[0].0, "old.deb");
        assert!(indexes.refresh_cached());
        let refreshed = indexes.get_with(URL, &mut fetch).unwrap();
        assert_eq!(refreshed[0].0, "new.deb");
        assert!(!indexes.refresh_cached());
        assert_eq!(calls, 1);
    }
    #[test]
    fn expired_index_falls_back_after_one_failed_request_and_errors_are_memoized() {
        let dir = tempfile::tempdir().unwrap();
        let job = Job::default();
        cached(dir.path(), OLD, true);
        let mut indexes = Indexes::new(dir.path(), true, false, &job);
        let mut calls = 0;
        let mut fetch = |_: &str| -> Result<String> {
            calls += 1;
            anyhow::bail!("network unavailable")
        };
        assert_eq!(indexes.get_with(URL, &mut fetch).unwrap()[0].0, "old.deb");
        assert!(indexes.get_with(URL, &mut fetch).is_ok());
        assert!(!indexes.refresh_cached());
        assert!(
            indexes
                .get_with("https://missing.test/", &mut fetch)
                .is_err()
        );
        assert!(
            indexes
                .get_with("https://missing.test/", &mut fetch)
                .is_err()
        );
        assert_eq!(calls, 2);
        assert_eq!(
            fs::read_to_string(index_path(dir.path(), URL)).unwrap(),
            OLD
        );
    }
    #[test]
    fn explicit_refresh_ignores_fresh_cache_but_offline_never_fetches() {
        let dir = tempfile::tempdir().unwrap();
        let job = Job::default();
        cached(dir.path(), OLD, false);
        let mut indexes = Indexes::new(dir.path(), true, true, &job);
        assert_eq!(
            indexes.get_with(URL, &mut |_| Ok(NEW.into())).unwrap()[0].0,
            "new.deb"
        );
        let mut offline = Indexes::new(dir.path(), false, false, &job);
        let mut calls = 0;
        let mut fetch = |_: &str| {
            calls += 1;
            Ok(OLD.into())
        };
        assert_eq!(offline.get_with(URL, &mut fetch).unwrap()[0].0, "new.deb");
        assert!(
            offline
                .get_with("https://absent.test/", &mut fetch)
                .is_err()
        );
        assert_eq!(calls, 0);
    }
    #[test]
    fn invalid_responses_and_cancellation_never_replace_valid_cached_indexes() {
        let dir = tempfile::tempdir().unwrap();
        let job = Job::default();
        cached(dir.path(), OLD, false);
        let mut indexes = Indexes::new(dir.path(), true, true, &job);
        assert_eq!(
            indexes
                .get_with(URL, &mut |_| Ok("bad response".into()))
                .unwrap()[0]
                .0,
            "old.deb"
        );
        let mut indexes = Indexes::new(dir.path(), true, true, &job);
        assert!(
            indexes
                .get_with(URL, &mut |_| {
                    job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                    Ok(NEW.into())
                })
                .is_err()
        );
        assert_eq!(
            fs::read_to_string(index_path(dir.path(), URL)).unwrap(),
            OLD
        );
    }
}
