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
    match rgb.as_slice() {
        [r, g, b] => Some(0.2126 * r + 0.7152 * g + 0.0722 * b > 0.5),
        _ => None,
    }
}
/// Whether the terminal background is light, plus any input the user typed
/// while the terminal was being asked.
///
/// Only the `auto` theme depends on the answer, so other themes never query the
/// terminal and start without waiting. `COLORFGBG` is the fallback either way.
pub(super) fn detect(probe: bool) -> (bool, Vec<u8>) {
    let (reply, typed) = if probe { query() } else { (None, Vec::new()) };
    let light = reply
        .or_else(|| std::env::var("COLORFGBG").ok().and_then(|s| from_env(&s)))
        .unwrap_or(false);
    (light, typed)
}
/// Split raw terminal input into the OSC 11 / DA1 replies and everything
/// else, which is what the user typed while the query was outstanding.
pub(super) fn split_replies(bytes: &[u8]) -> (String, Vec<u8>) {
    let mut replies = Vec::new();
    let mut typed = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let rest = bytes.get(i..).unwrap_or_default();
        let end = if rest.starts_with(b"\x1b]") {
            // OSC: ends at BEL or ST (ESC \\).
            rest.iter()
                .enumerate()
                .skip(2)
                .find(|&(k, &b)| b == 0x07 || (b == b'\\' && rest.get(k - 1) == Some(&0x1b)))
                .map(|(k, _)| k + 1)
        } else if rest.starts_with(b"\x1b[?") {
            // DA1: ESC [ ? params c
            rest.iter().position(|&b| b == b'c').map(|k| k + 1)
        } else {
            None
        };
        match end {
            Some(n) => {
                replies.extend_from_slice(rest.get(..n).unwrap_or_default());
                i += n;
            }
            None => {
                typed.extend(rest.first());
                i += 1;
            }
        }
    }
    (String::from_utf8_lossy(&replies).into_owned(), typed)
}
/// Key events for bytes typed during the query, so they are not lost.
/// Covers printable text, Enter, Tab, Backspace, Esc, arrows and Ctrl+letter.
pub(super) fn typed_keys(bytes: &[u8]) -> Vec<crossterm::event::KeyEvent> {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
    let mut keys = Vec::new();
    let text = String::from_utf8_lossy(bytes);
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        keys.push(match c {
            '\r' | '\n' => key(KeyCode::Enter),
            '\t' => key(KeyCode::Tab),
            '\x7f' | '\x08' => key(KeyCode::Backspace),
            '\x1b' if chars.peek() == Some(&'[') => {
                chars.next();
                match chars.next() {
                    Some('A') => key(KeyCode::Up),
                    Some('B') => key(KeyCode::Down),
                    Some('C') => key(KeyCode::Right),
                    Some('D') => key(KeyCode::Left),
                    _ => continue,
                }
            }
            '\x1b' => key(KeyCode::Esc),
            '\x01'..='\x1a' => KeyEvent::new(
                KeyCode::Char(char::from(b'a' + (c as u8 - 1))),
                KeyModifiers::CONTROL,
            ),
            c if c.is_control() || c == char::REPLACEMENT_CHARACTER => continue,
            c => key(KeyCode::Char(c)),
        });
    }
    keys
}
#[cfg(unix)]
fn query() -> (Option<bool>, Vec<u8>) {
    let mut stdout = std::io::stdout();
    if write!(stdout, "\x1b]11;?\x07\x1b[c").is_err() || stdout.flush().is_err() {
        return (None, Vec::new());
    }
    let started = std::time::Instant::now();
    let mut input = Vec::new();
    // DA1 is answered by every terminal, so the deadline is only reached by
    // one that answers nothing at all.
    while started.elapsed() < std::time::Duration::from_millis(1000) && input.len() < 4096 {
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
        // One byte at a time: input typed after the DA1 reply stays queued
        // for Crossterm instead of being consumed here.
        let mut byte = [0u8; 1];
        let read = unsafe { libc::read(libc::STDIN_FILENO, byte.as_mut_ptr().cast(), 1) };
        if read <= 0 {
            break;
        }
        input.extend_from_slice(&byte);
        if byte == [b'c'] && split_replies(&input).0.contains("\x1b[?") {
            break;
        }
    }
    let (replies, typed) = split_replies(&input);
    (parse(&replies), typed)
}
#[cfg(not(unix))]
fn query() -> (Option<bool>, Vec<u8>) {
    (None, Vec::new())
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
    #[test]
    fn keys_typed_during_the_query_are_kept_apart_from_the_replies() {
        use crossterm::event::{KeyCode, KeyModifiers};
        let input = b"q\x1b]11;rgb:ffff/ffff/ffff\x1b\\j\x1b[A\x1b[?62;22c";
        let (replies, typed) = split_replies(input);
        assert_eq!(parse(&replies), Some(true));
        assert!(replies.contains("\x1b[?62;22c"));
        assert_eq!(typed, b"qj\x1b[A");
        let keys = typed_keys(&typed);
        let codes: Vec<_> = keys.iter().map(|k| k.code).collect();
        assert_eq!(codes, [KeyCode::Char('q'), KeyCode::Char('j'), KeyCode::Up]);
        let control = typed_keys(b"\x03\r\x1b");
        assert_eq!(control[0].code, KeyCode::Char('c'));
        assert_eq!(control[0].modifiers, KeyModifiers::CONTROL);
        assert_eq!(control[1].code, KeyCode::Enter);
        assert_eq!(control[2].code, KeyCode::Esc);
        // BEL-terminated OSC as well.
        let (replies, typed) = split_replies(b"\x1b]11;rgb:0/0/0\x07x");
        assert_eq!(parse(&replies), Some(false));
        assert_eq!(typed, b"x");
    }
}
