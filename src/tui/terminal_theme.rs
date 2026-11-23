//! Query before Crossterm starts consuming input. DA1 bounds the response window.
use crossterm::event::{self, Event};
use std::collections::VecDeque;
#[cfg(unix)]
use std::io::Write;
use std::{io, time::Duration};

const PASTE_START: &[u8] = b"\x1b[200~";
const PASTE_END: &[u8] = b"\x1b[201~";
const READ_BATCH: usize = 4096;

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
pub(super) fn detect(probe: bool) -> (bool, StartupInput) {
    let (reply, typed) = if probe { query() } else { (None, Vec::new()) };
    let light = reply
        .or_else(|| std::env::var("COLORFGBG").ok().and_then(|s| from_env(&s)))
        .unwrap_or(false);
    (light, StartupInput::from_bytes(&typed))
}
/// Split raw terminal input into the OSC 11 / DA1 replies and everything
/// else, which is what the user typed while the query was outstanding.
pub(super) fn split_replies(bytes: &[u8]) -> (String, Vec<u8>) {
    let mut replies = Vec::new();
    let mut typed = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let rest = bytes.get(i..).unwrap_or_default();
        if let Some(paste) = rest.strip_prefix(PASTE_START) {
            let end = memchr::memmem::find(paste, PASTE_END)
                .map_or(rest.len(), |end| PASTE_START.len() + end + PASTE_END.len());
            typed.extend_from_slice(&rest[..end]);
            i += end;
            continue;
        }
        let end = if rest.starts_with(b"\x1b]11;") {
            // OSC: ends at BEL or ST (ESC \\).
            rest.iter()
                .enumerate()
                .skip(2)
                .find(|&(k, &b)| b == 0x07 || (b == b'\\' && rest.get(k - 1) == Some(&0x1b)))
                .map(|(k, _)| k + 1)
        } else if rest.starts_with(b"\x1b[?") {
            // DA1: ESC [ ? params c
            let tail = &rest[3..];
            let end = tail
                .iter()
                .take_while(|b| b.is_ascii_digit() || **b == b';')
                .count();
            (tail.get(end) == Some(&b'c')).then_some(3 + end + 1)
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
/// Input already taken from stdin by the probe. If the probe stopped inside
/// a paste, read the rest of that frame before handing stdin to Crossterm.
pub(super) struct StartupInput {
    events: VecDeque<Event>,
    pending_paste: Option<Vec<u8>>,
}

impl StartupInput {
    pub(super) fn from_bytes(mut bytes: &[u8]) -> Self {
        let mut input = Self {
            events: VecDeque::new(),
            pending_paste: None,
        };
        while let Some(start) = memchr::memmem::find(bytes, PASTE_START) {
            input.events.extend(typed_keys(&bytes[..start]));
            let body = &bytes[start + PASTE_START.len()..];
            let Some(end) = memchr::memmem::find(body, PASTE_END) else {
                input.pending_paste = Some(body.to_vec());
                return input;
            };
            input.events.push_back(paste_event(&body[..end]));
            bytes = &body[end + PASTE_END.len()..];
        }
        input.events.extend(typed_keys(bytes));
        input
    }

    pub(super) fn next_event(&mut self, wait: Duration) -> io::Result<Option<Event>> {
        if let Some(event) = self.events.pop_front() {
            return Ok(Some(event));
        }
        if let Some(paste) = self.pending_paste.as_mut() {
            let mut wait = wait;
            for _ in 0..READ_BATCH {
                let Some(byte) = read_byte(wait)? else {
                    break;
                };
                wait = Duration::ZERO;
                if let Some(event) = append_paste_byte(paste, byte) {
                    self.pending_paste = None;
                    return Ok(Some(event));
                }
            }
            return Ok(None);
        }
        if event::poll(wait)? {
            return event::read().map(Some);
        }
        Ok(None)
    }
}

fn paste_event(bytes: &[u8]) -> Event {
    Event::Paste(String::from_utf8_lossy(bytes).into_owned())
}

fn append_paste_byte(paste: &mut Vec<u8>, byte: u8) -> Option<Event> {
    paste.push(byte);
    paste.strip_suffix(PASTE_END).map(paste_event)
}

/// Key events for bytes typed during the query, so they are not lost.
/// Covers printable text, Enter, Tab, Backspace, Esc, arrows and Ctrl+letter.
fn typed_keys(bytes: &[u8]) -> impl Iterator<Item = Event> {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
    let text = String::from_utf8_lossy(bytes);
    let mut chars = text.chars().peekable();
    let mut keys = Vec::new();
    while let Some(c) = chars.next() {
        keys.push(Event::Key(match c {
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
                    Some(c) if (' '..='?').contains(&c) => {
                        // Consume the rest of an unsupported CSI sequence as
                        // one unit so its parameters cannot become shortcuts.
                        for ch in chars.by_ref() {
                            if ('@'..='~').contains(&ch) {
                                break;
                            }
                        }
                        continue;
                    }
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
        }));
    }
    keys.into_iter()
}
#[cfg(unix)]
fn query() -> (Option<bool>, Vec<u8>) {
    let mut stdout = std::io::stdout();
    if write!(stdout, "\x1b]11;?\x07\x1b[c").is_err() || stdout.flush().is_err() {
        return (None, Vec::new());
    }
    let started = std::time::Instant::now();
    let mut input = Vec::new();
    while started.elapsed() < Duration::from_secs(1) && input.len() < READ_BATCH {
        let byte = match read_byte(Duration::from_millis(20)) {
            Ok(Some(byte)) => byte,
            Ok(None) => continue,
            Err(_) => break,
        };
        input.push(byte);
        if byte == b'c' && split_replies(&input).0.contains("\x1b[?") {
            break;
        }
    }
    // The byte or time limit may land inside the opening marker. Complete
    // an already queued marker before passing the rest of stdin to Crossterm.
    if let Some(prefix) = (1..PASTE_START.len())
        .rev()
        .find(|&n| input.ends_with(&PASTE_START[..n]))
    {
        for &expected in &PASTE_START[prefix..] {
            let Ok(Some(byte)) = read_byte(Duration::ZERO) else {
                break;
            };
            input.push(byte);
            if byte != expected {
                break;
            }
        }
    }
    let (replies, typed) = split_replies(&input);
    (parse(&replies), typed)
}
#[cfg(unix)]
fn read_byte(wait: Duration) -> io::Result<Option<u8>> {
    let mut fd = libc::pollfd {
        fd: libc::STDIN_FILENO,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll receives one initialized descriptor; read receives a valid buffer.
    let ready = unsafe { libc::poll(&mut fd, 1, wait.as_millis() as libc::c_int) };
    if ready == 0 {
        return Ok(None);
    }
    if ready < 0 {
        return match io::Error::last_os_error() {
            error if error.kind() == io::ErrorKind::Interrupted => Ok(None),
            error => Err(error),
        };
    }
    // Stop exactly at the end of DA1 or the paste, leaving the next input queued.
    let mut byte = 0u8;
    match unsafe { libc::read(libc::STDIN_FILENO, (&mut byte as *mut u8).cast(), 1) } {
        1 => Ok(Some(byte)),
        0 => Err(io::ErrorKind::UnexpectedEof.into()),
        _ => match io::Error::last_os_error() {
            error if error.kind() == io::ErrorKind::Interrupted => Ok(None),
            error => Err(error),
        },
    }
}

#[cfg(not(unix))]
fn read_byte(_: Duration) -> io::Result<Option<u8>> {
    Ok(None)
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
        let keys = StartupInput::from_bytes(&typed);
        assert_eq!(
            keys.events,
            [KeyCode::Char('q'), KeyCode::Char('j'), KeyCode::Up]
                .map(|code| Event::Key(crossterm::event::KeyEvent::new(code, KeyModifiers::NONE)))
        );
        let control: Vec<_> = typed_keys(b"\x03\r\x1b").collect();
        assert_eq!(
            control,
            [
                Event::Key(crossterm::event::KeyEvent::new(
                    KeyCode::Char('c'),
                    KeyModifiers::CONTROL
                )),
                Event::Key(KeyCode::Enter.into()),
                Event::Key(KeyCode::Esc.into()),
            ]
        );
        // BEL-terminated OSC as well.
        let (replies, typed) = split_replies(b"\x1b]11;rgb:0/0/0\x07x");
        assert_eq!(parse(&replies), Some(false));
        assert_eq!(typed, b"x");
    }
    #[test]
    fn paste_is_replayed_as_one_event_and_its_contents_are_not_terminal_replies() {
        let bytes = b"\x1b]11;rgb:f/f/f\x07\x1b[200~q\n\x1b[?1;2c\x1b[201~\x1b[?62;22c";
        let (replies, typed) = split_replies(bytes);
        assert_eq!(replies, "\x1b]11;rgb:f/f/f\x07\x1b[?62;22c");
        let input = StartupInput::from_bytes(&typed);
        assert_eq!(input.events, [Event::Paste("q\n\x1b[?1;2c".into())]);
        assert!(input.pending_paste.is_none());
    }

    #[test]
    fn paste_split_by_probe_limit_keeps_payload_and_partial_end_marker() {
        let (_, typed) = split_replies(b"\x1b[200~q\n\x1b[2");
        let mut input = StartupInput::from_bytes(&typed);
        assert!(input.events.is_empty());
        let paste = input.pending_paste.as_mut().unwrap();
        assert_eq!(append_paste_byte(paste, b'0'), None);
        assert_eq!(append_paste_byte(paste, b'1'), None);
        assert_eq!(
            append_paste_byte(paste, b'~'),
            Some(Event::Paste("q\n".into()))
        );
    }
}
