//! Query before Crossterm starts consuming input. DA1 bounds the response window.
use std::io::Write;

pub(super) fn from_env(value: &str) -> Option<bool> {
    let background = value.rsplit(';').next()?.parse::<u8>().ok()?;
    Some(background == 7 || (9..=15).contains(&background))
}
pub(super) fn parse(reply: &str) -> Option<bool> {
    let reply = reply.to_ascii_lowercase();
    let value = reply.split("11;").nth(1)?;
    let rgb = value
        .strip_prefix("rgb:")
        .or_else(|| value.strip_prefix("rgba:"))?;
    let rgb: Vec<_> = rgb
        .split(['/', '\x07', '\x1b'])
        .take(3)
        .map(|v| {
            let number = u32::from_str_radix(v, 16).ok()?;
            let maximum = (1u64 << (v.len().min(4) * 4)) - 1;
            (maximum > 0).then_some(number as f64 / maximum as f64)
        })
        .collect::<Option<_>>()?;
    (rgb.len() == 3).then(|| 0.2126 * rgb[0] + 0.7152 * rgb[1] + 0.0722 * rgb[2] > 0.5)
}
pub(super) fn detect() -> bool {
    query()
        .or_else(|| std::env::var("COLORFGBG").ok().and_then(|s| from_env(&s)))
        .unwrap_or(false)
}
#[cfg(unix)]
fn query() -> Option<bool> {
    let mut stdout = std::io::stdout();
    write!(stdout, "\x1b]11;?\x07\x1b[c").ok()?;
    stdout.flush().ok()?;
    let started = std::time::Instant::now();
    let mut reply = Vec::new();
    while started.elapsed() < std::time::Duration::from_millis(1000) && reply.len() < 4096 {
        let mut fd = libc::pollfd {
            fd: libc::STDIN_FILENO,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll receives one initialized descriptor; read receives a valid buffer.
        let ready = unsafe { libc::poll(&mut fd, 1, 20) };
        if ready <= 0 {
            continue;
        }
        let mut bytes = [0u8; 256];
        let read =
            unsafe { libc::read(libc::STDIN_FILENO, bytes.as_mut_ptr().cast(), bytes.len()) };
        if read <= 0 {
            break;
        }
        reply.extend_from_slice(&bytes[..read as usize]);
        let value = String::from_utf8_lossy(&reply);
        if value.contains("\x1b[?") && value.ends_with('c') {
            break;
        }
    }
    parse(&String::from_utf8_lossy(&reply))
}
#[cfg(not(unix))]
fn query() -> Option<bool> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn osc_background_and_environment() {
        assert_eq!(parse("\x1b]11;rgb:ffff/ffff/ffff\x07"), Some(true));
        assert_eq!(parse("\x1b]11;rgb:1515/1b1b/2424\x1b\\"), Some(false));
        assert_eq!(parse("\x1b[?1;2c"), None);
        assert_eq!(from_env("15;0"), Some(false));
        assert_eq!(from_env("0;15"), Some(true));
        assert_eq!(from_env("0;8"), Some(false));
        for value in [7, 9, 10, 11, 12, 13, 14] {
            assert_eq!(from_env(&format!("0;{value}")), Some(true));
        }
        assert_eq!(parse("\x1b]11;RGBA:F/F/F/F\x07"), Some(true));
        assert_eq!(parse("\x1b]11;rgb:00/00/00\x07"), Some(false));
    }
}
