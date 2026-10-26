//! Routing for public GitHub symbol resources; canonical repository URLs stay unchanged.
use crate::{Job, store};
use anyhow::{Context, Result};
use std::path::Path;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GithubAccess {
    #[default]
    Auto,
    Direct,
    GhProxy,
}
impl GithubAccess {
    pub fn label(self) -> &'static str {
        match self {
            Self::Auto => "自动（直连失败后 gh-proxy.com）",
            Self::Direct => "直连 GitHub",
            Self::GhProxy => "gh-proxy.com",
        }
    }
    pub fn next(self) -> Self {
        match self {
            Self::Auto => Self::Direct,
            Self::Direct => Self::GhProxy,
            Self::GhProxy => Self::Auto,
        }
    }
}
fn proxy_url(url: &str) -> Option<String> {
    ["https://github.com/", "https://raw.githubusercontent.com/"]
        .iter()
        .any(|prefix| url.starts_with(prefix))
        .then(|| format!("https://gh-proxy.com/{url}"))
}
fn fetch_routed(
    url: &str,
    access: GithubAccess,
    job: &Job,
    mut fetch: impl FnMut(&str, u64) -> Result<Vec<u8>>,
) -> Result<Vec<u8>> {
    job.check()?;
    let Some(proxy) = proxy_url(url).filter(|_| access != GithubAccess::Direct) else {
        return fetch(url, 90);
    };
    if access == GithubAccess::GhProxy {
        job.report(format!("通过 gh-proxy.com 下载: {url}"));
        return fetch(&proxy, 90);
    }
    match fetch(url, 20) {
        Ok(bytes) => Ok(bytes),
        Err(error) => {
            job.check()?;
            if super::is_not_found(&error) {
                return Err(error);
            }
            job.report("GitHub 直连失败，尝试 gh-proxy.com");
            fetch(&proxy, 90).with_context(|| {
                format!("GitHub 直连失败: {error:#}；gh-proxy.com 也未能下载 {url}")
            })
        }
    }
}
pub(super) fn fetch_github(url: &str, cache: &Path, job: &Job) -> Result<Vec<u8>> {
    fetch_routed(
        url,
        store::read_settings(cache).github_access,
        job,
        |url, timeout| {
            Ok(super::transfer_with_timeout(url, None, 256 * 1024 * 1024, timeout, job)?.0)
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    const URL: &str =
        "https://raw.githubusercontent.com/owner/repo/master/banners/banners_plain.json";
    #[test]
    fn auto_uses_proxy_after_connection_failure_but_not_after_success() {
        let mut calls = Vec::new();
        let result = fetch_routed(URL, GithubAccess::Auto, &Job::default(), |url, timeout| {
            calls.push((url.to_owned(), timeout));
            if calls.len() == 1 {
                anyhow::bail!("connection failed")
            }
            Ok(b"symbols".to_vec())
        })
        .unwrap();
        assert_eq!(result, b"symbols");
        assert_eq!(
            calls,
            [
                (URL.into(), 20),
                (format!("https://gh-proxy.com/{URL}"), 90)
            ]
        );
        let mut calls = 0;
        fetch_routed(URL, GithubAccess::Auto, &Job::default(), |url, _| {
            calls += 1;
            assert_eq!(url, URL);
            Ok(vec![])
        })
        .unwrap();
        assert_eq!(calls, 1);
    }
    #[test]
    fn explicit_modes_and_release_assets_keep_the_original_url_intact() {
        for (mode, expected) in [
            (GithubAccess::Direct, URL.into()),
            (GithubAccess::GhProxy, format!("https://gh-proxy.com/{URL}")),
        ] {
            let mut calls = 0;
            fetch_routed(URL, mode, &Job::default(), |url, timeout| {
                calls += 1;
                assert_eq!(url, expected);
                assert_eq!(timeout, 90);
                Ok(vec![])
            })
            .unwrap();
            assert_eq!(calls, 1);
        }
        let release = "https://github.com/owner/repo/releases/download/tag/a%20b.json.xz";
        assert_eq!(
            proxy_url(release).unwrap(),
            format!("https://gh-proxy.com/{release}")
        );
        for url in [
            "https://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/id/ntkrnlmp.pdb",
            "https://github.com.evil.test/file",
            "http://github.com/owner/repo",
            "https://gh-proxy.com/https://github.com/owner/repo",
        ] {
            assert!(proxy_url(url).is_none());
        }
    }
    #[test]
    fn missing_resources_and_cancellation_do_not_trigger_proxy_retry() {
        let mut calls = 0;
        let error = fetch_routed(URL, GithubAccess::Auto, &Job::default(), |_, _| {
            calls += 1;
            Err(super::super::HttpError {
                status: 404,
                url: URL.into(),
            }
            .into())
        })
        .unwrap_err();
        assert!(super::super::is_not_found(&error));
        assert_eq!(calls, 1);
        let job = Job::default();
        let mut calls = 0;
        assert!(
            fetch_routed(URL, GithubAccess::Auto, &job, |_, _| {
                calls += 1;
                job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                anyhow::bail!("cancelled")
            })
            .is_err()
        );
        assert_eq!(calls, 1);
        assert!(
            fetch_routed(URL, GithubAccess::GhProxy, &job, |_, _| panic!(
                "cancelled transfer started"
            ))
            .is_err()
        );
    }
    #[test]
    fn proxy_failure_preserves_both_errors_and_non_github_urls_stay_direct() {
        let error = fetch_routed(URL, GithubAccess::Auto, &Job::default(), |url, _| {
            anyhow::bail!("failed {url}")
        })
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("GitHub 直连失败") && message.contains("https://gh-proxy.com/"));
        fetch_routed(
            "https://msdl.microsoft.com/file",
            GithubAccess::GhProxy,
            &Job::default(),
            |url, _| {
                assert_eq!(url, "https://msdl.microsoft.com/file");
                Ok(vec![])
            },
        )
        .unwrap();
    }
}
