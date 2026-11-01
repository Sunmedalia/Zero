//! Native HTTPS downloads. Every redirect hop stays HTTPS, bodies stream to a caller
//! file under a hard size limit, and cancellation returns without waiting for the socket.
#![cfg_attr(not(test), deny(clippy::indexing_slicing))]
use super::HttpError;
use crate::Job;
use anyhow::{Context, Result, anyhow, bail, ensure};
use std::{
    fs::File,
    io::{Read, Write},
    sync::mpsc::{self, RecvTimeoutError},
    thread,
    time::Duration,
};
use ureq::tls::{RootCerts, TlsConfig};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const CANCEL_POLL: Duration = Duration::from_millis(50);

pub(crate) struct Request<'a> {
    pub url: &'a str,
    pub range: Option<&'a str>,
    pub limit: u64,
    pub timeout: Duration,
    /// Only local plain-HTTP test servers clear this.
    pub https_only: bool,
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Response {
    pub status: u16,
    pub content_range: Option<String>,
}
/// Stream one response into `file`, returning as soon as `job` is cancelled.
pub(crate) fn download(request: Request<'_>, file: File, job: &Job) -> Result<Response> {
    job.check()?;
    let (url, range) = (request.url.to_owned(), request.range.map(str::to_owned));
    let (limit, timeout, https_only) = (request.limit, request.timeout, request.https_only);
    let worker_job = job.clone();
    let (sender, receiver) = mpsc::channel();
    thread::Builder::new()
        .name("zero-download".into())
        .spawn(move || {
            let request = Request {
                url: &url,
                range: range.as_deref(),
                limit,
                timeout,
                https_only,
            };
            // The receiver is gone after cancellation; the socket ends with this thread.
            let _ = sender.send(with_trust_fallback(&request, &file, &worker_job));
        })
        .context("无法启动下载线程")?;
    loop {
        match receiver.recv_timeout(CANCEL_POLL) {
            Ok(result) => {
                job.check()?;
                return result;
            }
            Err(RecvTimeoutError::Timeout) => job.check()?,
            Err(RecvTimeoutError::Disconnected) => bail!("下载线程意外退出"),
        }
    }
}
/// System roots first; the bundled Mozilla roots serve systems without a CA store.
/// Both verify the certificate chain, so the retry never relaxes validation.
fn with_trust_fallback(request: &Request<'_>, file: &File, job: &Job) -> Result<Response> {
    match attempt(request, RootCerts::PlatformVerifier, file, job) {
        Err(error) if is_tls_failure(&error) => attempt(request, RootCerts::WebPki, file, job),
        result => result,
    }
}
fn is_tls_failure(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<ureq::Error>(),
            Some(ureq::Error::Rustls(_) | ureq::Error::Tls(_))
        )
    })
}
fn attempt(request: &Request<'_>, roots: RootCerts, file: &File, job: &Job) -> Result<Response> {
    let agent = ureq::Agent::config_builder()
        .https_only(request.https_only)
        .http_status_as_error(false)
        .timeout_connect(Some(CONNECT_TIMEOUT))
        .timeout_global(Some(request.timeout))
        .user_agent(concat!("zero/", env!("CARGO_PKG_VERSION")))
        .tls_config(TlsConfig::builder().root_certs(roots).build())
        .build()
        .new_agent();
    let mut call = agent.get(request.url);
    if let Some(range) = request.range {
        call = call.header("Range", format!("bytes={range}"));
    }
    let failed =
        |error: ureq::Error| anyhow!(error).context(format!("符号下载失败: {}", request.url));
    let response = call.call().map_err(failed)?;
    let status = response.status().as_u16();
    if status >= 400 {
        return Err(HttpError {
            status,
            url: request.url.into(),
        }
        .into());
    }
    ensure!(
        response.status().is_success(),
        "符号下载返回意外状态 HTTP {status}：{}",
        request.url
    );
    let content_range = response
        .headers()
        .get("content-range")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let mut body = response.into_body().into_reader();
    let mut output = file;
    let mut written = 0u64;
    let mut buffer = vec![0; 64 * 1024];
    loop {
        job.check()?;
        let read = body
            .read(&mut buffer)
            .with_context(|| format!("符号下载中断: {}", request.url))?;
        let Some(chunk) = buffer.get(..read).filter(|chunk| !chunk.is_empty()) else {
            break;
        };
        written += read as u64;
        ensure!(written <= request.limit, "下载响应超过大小限制");
        output.write_all(chunk)?;
    }
    output.flush()?;
    Ok(Response {
        status,
        content_range,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader, Seek},
        net::TcpListener,
        sync::atomic::Ordering,
        time::Instant,
    };
    /// Serve one canned response per connection, recording each request head.
    fn serve(responses: Vec<Vec<u8>>) -> (String, thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            let mut requests = Vec::new();
            for response in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut head = String::new();
                while reader.read_line(&mut head).unwrap() > 2 && !head.ends_with("\r\n\r\n") {}
                requests.push(head);
                let _ = stream.write_all(&response);
            }
            requests
        });
        (url, handle)
    }
    fn reply(status: &str, headers: &str, body: &[u8]) -> Vec<u8> {
        let mut out = format!(
            "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        out.extend_from_slice(body);
        out
    }
    fn get(url: &str, range: Option<&str>, limit: u64, job: &Job) -> Result<(Response, Vec<u8>)> {
        let mut file = tempfile::tempfile()?;
        let response = download(
            Request {
                url,
                range,
                limit,
                timeout: Duration::from_secs(10),
                https_only: false,
            },
            file.try_clone()?,
            job,
        )?;
        file.rewind()?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok((response, bytes))
    }
    #[test]
    fn body_and_range_headers_round_trip() {
        let (url, server) = serve(vec![reply(
            "206 Partial Content",
            "Content-Range: bytes 2-4/9\r\n",
            b"abc",
        )]);
        let (response, bytes) = get(&url, Some("2-4"), 16, &Job::default()).unwrap();
        assert_eq!(bytes, b"abc");
        assert_eq!(response.status, 206);
        assert_eq!(response.content_range.as_deref(), Some("bytes 2-4/9"));
        let head = server.join().unwrap().remove(0).to_ascii_lowercase();
        assert!(head.contains("range: bytes=2-4\r\n"), "{head}");
        assert!(!head.contains("accept-encoding"), "{head}");
    }
    #[test]
    fn http_errors_keep_their_status_for_the_404_fallback() {
        let (url, server) = serve(vec![reply("404 Not Found", "", b"gone")]);
        let error = get(&url, None, 16, &Job::default()).unwrap_err();
        assert!(super::super::is_not_found(&error), "{error:#}");
        server.join().unwrap();
        let (url, server) = serve(vec![reply("503 Unavailable", "", b"")]);
        let error = get(&url, None, 16, &Job::default()).unwrap_err();
        assert_eq!(error.downcast_ref::<HttpError>().unwrap().status, 503);
        server.join().unwrap();
    }
    #[test]
    fn oversized_bodies_are_rejected() {
        let (url, server) = serve(vec![reply("200 OK", "", &[7; 32])]);
        let error = get(&url, None, 31, &Job::default()).unwrap_err();
        assert!(error.to_string().contains("大小限制"), "{error:#}");
        server.join().unwrap();
    }
    #[test]
    fn redirects_are_followed() {
        let (url, server) = serve(vec![
            reply("302 Found", "Location: /next\r\n", b""),
            reply("200 OK", "", b"final"),
        ]);
        let (_, bytes) = get(&url, None, 16, &Job::default()).unwrap();
        assert_eq!(bytes, b"final");
        server.join().unwrap();
    }
    #[test]
    fn plain_http_is_refused_before_any_connection() {
        let file = tempfile::tempfile().unwrap();
        let error = download(
            Request {
                url: "http://127.0.0.1:9/",
                range: None,
                limit: 16,
                timeout: Duration::from_secs(5),
                https_only: true,
            },
            file,
            &Job::default(),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("https only"), "{error:#}");
    }
    #[test]
    fn cancellation_returns_while_the_server_stalls() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let job = Job::default();
        let cancel = job.cancel.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            cancel.store(true, Ordering::Relaxed);
        });
        let started = Instant::now();
        let error = get(&url, None, 16, &job).unwrap_err();
        assert!(error.to_string().contains("cancelled"), "{error:#}");
        assert!(started.elapsed() < Duration::from_secs(3));
        drop(listener);
    }
}
