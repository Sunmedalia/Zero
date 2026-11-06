//! Canonical TaskCache binary decoding against the pinned ScheduledTasks schema.
use super::*;
const CACHE: &str = "Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache";
const NA: &str = "N/A";
const LIMIT: usize = 4096;
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }
    fn take(&mut self, size: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(size)?;
        let value = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(value)
    }
    fn skip(&mut self, size: usize) -> Option<()> {
        self.take(size).map(|_| ())
    }
    fn uint(&mut self, size: usize, aligned: bool) -> Option<u64> {
        let mut b = [0; 8];
        b.get_mut(..size)?.copy_from_slice(self.take(size)?);
        if aligned {
            self.skip(8 - size)?;
        }
        Some(u64::from_le_bytes(b))
    }
    fn u32(&mut self) -> Option<u64> {
        self.uint(4, false)
    }
    fn block(&mut self, aligned: bool) -> Option<&'a [u8]> {
        let size = usize::try_from(self.uint(4, aligned)?).ok()?;
        let data = self.take(size)?;
        if aligned {
            self.skip((8 - size % 8) % 8)?;
        }
        Some(data)
    }
    fn string(&mut self, aligned: bool) -> Option<String> {
        nonempty(wide(self.block(aligned)?))
    }
    fn expand(&mut self) -> Option<String> {
        let chars = usize::try_from(self.uint(4, true)?).ok()?;
        if chars == 0 {
            return None;
        }
        let size = chars.checked_mul(2)?.checked_add(2)?;
        let text = wide(self.take(size)?);
        self.skip((8 - size % 8) % 8)?;
        nonempty(text)
    }
    fn time(&mut self) -> Option<u64> {
        self.uint(1, true)?;
        let ticks = self.uint(8, false)?;
        valid_time(ticks).map(|_| ticks)
    }
    fn pad_from(&mut self, start: usize) -> Option<()> {
        self.skip((8 - (self.at.checked_sub(start)? % 8)) % 8)
    }
}
fn wide(bytes: &[u8]) -> String {
    crate::bytes::utf16_lossy_marked(bytes)
        .trim_end_matches('\0')
        .to_owned()
}
fn nonempty(s: String) -> Option<String> {
    if s.is_empty() { None } else { Some(s) }
}
fn value(s: Option<String>) -> String {
    s.unwrap_or_else(|| NA.into())
}
fn valid_time(ticks: u64) -> Option<String> {
    if ticks == 0 || ticks == u64::MAX {
        return None;
    }
    let seconds = i64::try_from(ticks / 10_000_000)
        .ok()?
        .checked_sub(11_644_473_600)?;
    if !(-62_135_596_800..=253_402_300_799).contains(&seconds) {
        return None;
    }
    Some(
        crate::report::utc(seconds)
            .replace(" UTC", "+00:00")
            .replacen(' ', "T", 1),
    )
}
fn guid(b: &[u8]) -> Option<String> {
    if b.len() != 16 {
        return None;
    }
    // Pinned windows_bytes_to_guid renders all five integers without padding.
    let tail = b
        .get(10..16)?
        .iter()
        .fold(0u64, |value, byte| value * 256 + u64::from(*byte));
    Some(format!(
        "{{{:x}-{:x}-{:x}-{:x}-{:x}}}",
        u32::from_le_bytes(b.get(0..4)?.try_into().ok()?),
        u16::from_le_bytes(b.get(4..6)?.try_into().ok()?),
        u16::from_le_bytes(b.get(6..8)?.try_into().ok()?),
        u16::from_be_bytes(b.get(8..10)?.try_into().ok()?),
        tail
    ))
}

struct Action {
    kind: String,
    action: String,
    args: String,
    directory: String,
}
impl Action {
    fn absent() -> Self {
        Self {
            kind: NA.into(),
            action: NA.into(),
            args: NA.into(),
            directory: NA.into(),
        }
    }
}
fn actions(bytes: &[u8]) -> (Option<String>, Vec<Action>) {
    let mut r = Reader::new(bytes);
    let Some(version) = r.uint(2, false) else {
        return (None, Vec::new());
    };
    let context = if matches!(version, 2 | 3) {
        r.string(false)
    } else {
        None
    };
    let mut out = Vec::new();
    for _ in 0..LIMIT {
        let Some(magic) = r.uint(2, false) else {
            break;
        };
        r.string(false); // identifier
        let action = match magic {
            0x6666 => {
                let command = r.string(false);
                let args = r.string(false);
                let directory = r.string(false);
                if version == 3 {
                    r.uint(2, false);
                }
                // The fixed reference rejects empty commands or arguments.
                match (command, args) {
                    (Some(command), Some(args)) => Action {
                        kind: "Exe".into(),
                        action: command,
                        args,
                        directory: value(directory),
                    },
                    _ => Action::absent(),
                }
            }
            0x7777 => {
                let Some(clsid) = r.take(16).and_then(guid) else {
                    break;
                };
                Action {
                    kind: "ComHandler".into(),
                    action: clsid,
                    args: value(r.string(false)),
                    directory: NA.into(),
                }
            }
            0x9999 => {
                let caption = r.string(false).unwrap_or_else(|| "<Unknown>".into());
                let content = r.string(false).unwrap_or_else(|| "<Unknown>".into());
                Action {
                    kind: "MessageBox".into(),
                    action: format!("\"{caption}\": {content}"),
                    args: NA.into(),
                    directory: NA.into(),
                }
            }
            0x8888 => {
                // v2.28.2 consumes Email properties but returns no action object.
                for _ in 0..8 {
                    r.string(false);
                }
                let Some(n) = r.u32().filter(|n| *n <= LIMIT as u64) else {
                    break;
                };
                for _ in 0..n {
                    r.string(false);
                }
                let Some(n) = r.u32().filter(|n| *n <= LIMIT as u64) else {
                    break;
                };
                for _ in 0..n {
                    r.string(false);
                    r.string(false);
                }
                Action::absent()
            }
            _ => break,
        };
        out.push(action);
    }
    (context, out)
}
struct User {
    username: Option<String>,
    sid: Option<String>,
    sid_type: u64,
}
fn user(r: &mut Reader<'_>) -> Option<User> {
    if r.uint(1, true)? != 0 {
        return Some(User {
            username: None,
            sid: None,
            sid_type: 8,
        });
    }
    let skip_sid = r.uint(1, true)? != 0;
    let (sid_type, sid) = if !skip_sid {
        let ty = r.uint(4, true)?;
        let b = r.block(true)?;
        let sid = (|| {
            let rev = *b.first()?;
            let count = *b.get(1)? as usize;
            let mut authority = 0u64;
            for v in b.get(2..8)? {
                authority = authority * 256 + u64::from(*v);
            }
            let mut text = format!("S-{rev}-{authority}");
            for i in 0..count {
                let at = 8 + i * 4;
                text.push_str(&format!(
                    "-{}",
                    u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?)
                ));
            }
            Some(text)
        })();
        (ty, sid)
    } else {
        (8, None)
    };
    Some(User {
        username: r.string(true),
        sid,
        sid_type,
    })
}
#[derive(Default)]
struct Trigger {
    kind: String,
    description: String,
    enabled: Option<bool>,
}
#[derive(Default)]
struct Triggers {
    principal: Option<String>,
    display: Option<String>,
    items: Vec<Trigger>,
    incomplete: bool,
}
fn triggers(bytes: &[u8]) -> Option<Triggers> {
    let mut r = Reader::new(bytes);
    let version = r.uint(1, true)?;
    r.time();
    r.time();
    r.uint(4, true)?;
    r.uint(4, true)?;
    let principal = if version >= 0x16 {
        r.string(true)
    } else {
        None
    };
    let display = if version >= 0x17 {
        r.string(true)
    } else {
        None
    };
    user(&mut r);
    let mut out = Triggers {
        principal,
        display,
        items: Vec::new(),
        incomplete: false,
    };
    let optional = (|| -> Option<()> {
        let length = r.uint(4, true)?;
        if length != 0 {
            r.skip(48)?;
            if matches!(length, 0x38 | 0x58) {
                r.skip(8)?;
            }
            if length == 0x58 {
                r.skip(32)?;
            }
        }
        Some(())
    })();
    if optional.is_none() {
        out.incomplete = true;
        return Some(out);
    }
    for _ in 0..LIMIT {
        let Some(magic) = r.uint(4, true) else {
            break;
        };
        let kind = match magic {
            0x6666 => "WindowsNotificationFacility",
            0x7777 => "Session",
            0x8888 | 0xaaaa | 0xeeee => "Logon",
            0xcccc => "Event",
            0xdddd => "Time",
            0xffff => "Boot",
            _ => break,
        };
        let decoded = (|| -> Option<Trigger> {
            if magic == 0xdddd {
                r.time();
                r.time();
                r.time();
                r.skip(16)?;
                r.skip(8)?;
                r.uint(1, false);
                let enabled = r.uint(1, false).map(|v| v != 0);
                r.skip(14)?;
                if version >= 0x16 {
                    let start = r.at;
                    r.string(false);
                    r.pad_from(start)?;
                }
                // Pinned TimeMode has string enum values: every encoded integer mode is Unknown.
                return Some(Trigger {
                    kind: kind.into(),
                    description: NA.into(),
                    enabled,
                });
            }
            r.time();
            r.time();
            r.skip(20)?;
            r.skip(4)?;
            let enabled = r.uint(1, true).map(|v| v != 0);
            r.skip(8)?;
            if version >= 0x16 {
                let start = r.at;
                r.string(false);
                r.pad_from(start)?;
            }
            let mut description = format!("{kind} trigger");
            match magic {
                0xaaaa => {
                    if let Some(u) = user(&mut r)
                        && let Some(name) = u.username
                    {
                        let sid = u.sid.unwrap_or_else(|| "None".into());
                        let ty = match u.sid_type {
                            1 => "User",
                            2 => "Group",
                            3 => "Domain",
                            4 => "Alias",
                            5 => "WellKnownGroup",
                            6 => "DeletedAccount",
                            7 => "Invalid",
                            9 => "Computer",
                            10 => "Label",
                            11 => "LogonSession",
                            _ => "Unknown",
                        };
                        description = format!("{name}: {sid} (SidType.{ty})");
                    }
                }
                0x7777 => {
                    let state = r.u32()?;
                    r.skip(4)?;
                    let state = match state {
                        1 => "ConsoleConnect",
                        2 => "ConsoleDisconnect",
                        3 => "RemoteConnect",
                        4 => "RemoteDisconnect",
                        5 => "SessionLock",
                        6 => "SessionUnlock",
                        _ => "Unknown",
                    };
                    description = if let Some(u) = user(&mut r)
                        && let Some(name) = u.username
                    {
                        format!("{state} for user {name}")
                    } else {
                        state.into()
                    };
                }
                0x6666 => {
                    let state: String = r.take(8)?.iter().map(|b| format!("{b:02x}")).collect();
                    let length = usize::try_from(r.uint(4, true)?).ok()?;
                    r.skip(length)?;
                    description = format!("WNF state {state}");
                }
                0xcccc => {
                    let subscription = r.expand().unwrap_or_else(|| "None".into());
                    r.skip(8)?;
                    r.expand();
                    let count = r.uint(4, true)?;
                    if count > LIMIT as u64 {
                        return None;
                    }
                    let mut pairs = Vec::new();
                    for _ in 0..count {
                        let k = r.expand();
                        let v = r.expand();
                        if let (Some(k), Some(v)) = (k, v) {
                            pairs.push(format!("({}, {})", python_repr(&k), python_repr(&v)));
                        }
                    }
                    description = format!(
                        "Event trigger: Subscription: {subscription}, Queries: [{}]",
                        pairs.join(", ")
                    );
                }
                _ => {}
            }
            Some(Trigger {
                kind: kind.into(),
                description,
                enabled,
            })
        })();
        match decoded {
            Some(trigger) => out.items.push(trigger),
            None => {
                out.incomplete = true;
                break;
            }
        }
    }
    if out.items.len() == LIMIT {
        out.incomplete = true;
    }
    Some(out)
}
fn python_repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = quote.to_string();
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out.push(quote);
    out
}
fn dynamic(bytes: &[u8]) -> [String; 3] {
    let mut r = Reader::new(bytes);
    if r.u32() != Some(3) {
        return std::array::from_fn(|_| NA.into());
    }
    let created = r.uint(8, false).and_then(valid_time);
    let last = r.uint(8, false).and_then(valid_time);
    r.skip(8);
    let success = r.uint(8, false).and_then(valid_time);
    // Fixed reference constructor swaps the first two time fields.
    [value(last), value(created), value(success)]
}
impl Windows<'_> {
    pub(super) fn scheduled_tasks_canonical(&self, job: &Job) -> Result<Results> {
        ensure!(
            matches!(
                Architecture::from_isf(self.vm.isf)?,
                Architecture::X86 | Architecture::X64
            ),
            "ScheduledTasks 仅支持 Intel x86/x64"
        );
        let mut result = self.result(Plugin::WinScheduledTasksV4);
        let hives = self.hives_matching(&["software"], job, &mut result)?;
        let Some((cmhive, _)) = hives.first() else {
            return Ok(result);
        };
        let hive = self.field(*cmhive, "_CMHIVE", "Hive")?;
        let root = self.registry_root(hive)?;
        let tasks = match self.registry_index_partial(
            hive,
            root,
            &format!("{CACHE}\\Tasks"),
            job,
            &mut result,
            false,
        ) {
            Ok(key) => key,
            Err(e) if e.to_string().starts_with("注册表键不存在:") => return Ok(result),
            Err(e) => return Err(e),
        };
        let tree = self.registry_index_partial(
            hive,
            root,
            &format!("{CACHE}\\Tree"),
            job,
            &mut result,
            false,
        );
        let mut names = BTreeMap::new();
        match tree {
            Ok(tree) => {
                let mut stack = vec![tree];
                let mut seen = HashSet::new();
                while let Some(index) = stack.pop() {
                    job.check()?;
                    if !seen.insert(index) {
                        Self::issue(&mut result, "TaskCache Tree", "子键循环");
                        continue;
                    }
                    ensure!(seen.len() <= MAX_OBJECTS, "TaskCache Tree 超过上限");
                    let read = (|| -> Result<()> {
                        let node = self.cell(hive, index)?;
                        let name = self.key_name(&node)?;
                        // Queue descendants independently of this key's optional Id value.
                        stack.extend(self.subkeys(hive, &node, job)?.into_iter().rev());
                        for entry in self.value_indices(hive, index)? {
                            job.check()?;
                            let read = (|| -> Result<()> {
                                if self.value_name(hive, entry)?.as_str() == "Id"
                                    && let (_, 1, bytes) = self.value_bytes(hive, entry, job)?
                                {
                                    names.insert(wide(&bytes), name.clone());
                                }
                                Ok(())
                            })();
                            if let Err(e) = read {
                                job.check()?;
                                Self::issue(&mut result, format!("TaskCache Id {entry:#x}"), e);
                            }
                        }
                        Ok(())
                    })();
                    if let Err(e) = read {
                        job.check()?;
                        Self::issue(&mut result, format!("TaskCache Tree {index:#x}"), e);
                    }
                }
            }
            Err(e) => {
                job.check()?;
                if !e.to_string().starts_with("注册表键不存在:") {
                    Self::issue(&mut result, "TaskCache Tree", e);
                }
            }
        }
        let node = self.cell(hive, tasks)?;
        for key in self.subkeys(hive, &node, job)? {
            job.check()?;
            let entry = (|| -> Result<()> {
                let node = self.cell(hive, key)?;
                let guid = self.key_name(&node)?;
                let mut bytes = BTreeMap::new();
                for index in self.value_indices(hive, key)? {
                    job.check()?;
                    let name = match self.value_name(hive, index) {
                        Ok(name) => name,
                        Err(e) => {
                            job.check()?;
                            Self::issue(&mut result, format!("task value {index:#x}"), e);
                            continue;
                        }
                    };
                    if !matches!(name.as_str(), "Actions" | "Triggers" | "DynamicInfo") {
                        continue;
                    }
                    match self.value_bytes(hive, index, job) {
                        Ok((name, ty, data)) if !matches!(ty, 4 | 5 | 11) => {
                            bytes.insert(name, if ty == 0 { Vec::new() } else { data });
                        }
                        Ok(_) => {}
                        Err(e) => {
                            job.check()?;
                            Self::issue(&mut result, format!("task {guid} {name}"), e);
                        }
                    }
                }
                let (context, mut actions) =
                    bytes.get("Actions").map(|b| actions(b)).unwrap_or_default();
                let decoded = bytes.get("Triggers").and_then(|b| triggers(b));
                if bytes.contains_key("Triggers") && decoded.is_none() {
                    Self::issue(
                        &mut result,
                        format!("task {guid} Triggers"),
                        "触发器头部截断或无效",
                    );
                }
                let mut triggers = decoded.unwrap_or_default();
                if triggers.incomplete {
                    Self::issue(
                        &mut result,
                        format!("task {guid} Triggers"),
                        "触发器截断或超过解析上限；已保留先前记录",
                    );
                }
                if actions.len() == LIMIT {
                    Self::issue(
                        &mut result,
                        format!("task {guid} Actions"),
                        "动作数量达到解析上限",
                    );
                }
                let times = bytes
                    .get("DynamicInfo")
                    .map(|b| dynamic(b))
                    .unwrap_or_else(|| std::array::from_fn(|_| NA.into()));
                if actions.is_empty() {
                    actions.push(Action::absent());
                }
                if triggers.items.is_empty() {
                    triggers.items.push(Trigger {
                        kind: NA.into(),
                        description: NA.into(),
                        enabled: None,
                    });
                }
                for action in actions {
                    for trigger in &triggers.items {
                        job.check()?;
                        ensure!(result.rows.len() < MAX_OBJECTS, "计划任务输出超过上限");
                        result.rows.push(vec![
                            names.get(&guid).cloned().unwrap_or_else(|| NA.into()),
                            value(triggers.principal.clone()),
                            value(triggers.display.clone()),
                            trigger
                                .enabled
                                .map(|b| b.to_string())
                                .unwrap_or_else(|| NA.into()),
                            times[0].clone(),
                            times[1].clone(),
                            times[2].clone(),
                            trigger.kind.clone(),
                            trigger.description.clone(),
                            action.kind.clone(),
                            action.action.clone(),
                            action.args.clone(),
                            value(context.clone()),
                            action.directory.clone(),
                            guid.clone(),
                        ]);
                    }
                }
                Ok(())
            })();
            if let Err(e) = entry {
                job.check()?;
                Self::issue(&mut result, format!("task key {key:#x}"), e);
            }
        }
        *result.kernel_identity.key_mut("time_format")? =
            serde_json::json!("ISO 8601 UTC (seconds)");
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn number(b: &mut Vec<u8>, n: u64, size: usize, aligned: bool) {
        b.extend(&n.to_le_bytes()[..size]);
        if aligned {
            b.resize(b.len() + 8 - size, 0);
        }
    }
    fn string(b: &mut Vec<u8>, s: &str, aligned: bool) {
        let bytes: Vec<_> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
        number(b, bytes.len() as u64, 4, aligned);
        b.extend(&bytes);
        if aligned {
            b.resize(b.len() + (8 - bytes.len() % 8) % 8, 0);
        }
    }
    fn header() -> Vec<u8> {
        let mut b = Vec::new();
        number(&mut b, 0x17, 1, true);
        b.resize(b.len() + 32, 0);
        number(&mut b, 0, 4, true);
        number(&mut b, 123, 4, true);
        string(&mut b, "LocalSystem", true);
        string(&mut b, "Test task", true);
        number(&mut b, 1, 1, true); // skip user
        number(&mut b, 0, 4, true); // optional settings
        b
    }
    fn generic(b: &mut Vec<u8>, magic: u64, enabled: bool) {
        number(b, magic, 4, true);
        b.resize(b.len() + 32 + 20 + 4, 0);
        number(b, u64::from(enabled), 1, true);
        b.resize(b.len() + 8, 0);
        let start = b.len();
        string(b, "ID", false);
        b.resize(b.len() + (8 - (b.len() - start) % 8) % 8, 0);
    }
    #[test]
    fn mixed_actions_preserve_context_order_and_reference_guid_format() {
        let mut b = Vec::new();
        number(&mut b, 3, 2, false);
        string(&mut b, "User", false);
        number(&mut b, 0x6666, 2, false);
        string(&mut b, "run", false);
        string(&mut b, "cmd.exe", false);
        string(&mut b, "/c whoami", false);
        string(&mut b, "C:\\Temp", false);
        number(&mut b, 0, 2, false);
        number(&mut b, 0x7777, 2, false);
        string(&mut b, "", false);
        let mut id = [0; 16];
        id[0] = 1;
        id[4] = 2;
        id[6] = 3;
        id[9] = 4;
        id[15] = 5;
        b.extend(id);
        string(&mut b, "parameters", false);
        let (context, rows) = actions(&b);
        assert_eq!(context.as_deref(), Some("User"));
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].action, "cmd.exe");
        assert_eq!(rows[0].directory, "C:\\Temp");
        assert_eq!(rows[1].action, "{1-2-3-4-5}");
        assert_eq!(rows[1].args, "parameters");
        assert_eq!(rows[1].kind, "ComHandler");
        // An empty argument list is deliberately absent in the pinned plugin.
        let mut empty = Vec::new();
        number(&mut empty, 1, 2, false);
        number(&mut empty, 0x6666, 2, false);
        string(&mut empty, "", false);
        string(&mut empty, "cmd.exe", false);
        string(&mut empty, "", false);
        string(&mut empty, "", false);
        assert_eq!(actions(&empty).1[0].kind, NA);
        for end in 0..b.len() {
            let _ = actions(&b[..end]);
        }
    }
    #[test]
    fn generic_wnf_session_and_event_trigger_alignment() {
        let mut b = header();
        generic(&mut b, 0xffff, true);
        generic(&mut b, 0x6666, false);
        b.extend([0x75, 0x20, 0xbd, 0xa3, 0x3e, 6, 0x83, 0x0d]);
        number(&mut b, 3, 4, true);
        b.extend([1, 2, 3]);
        generic(&mut b, 0x7777, true);
        number(&mut b, 6, 4, true);
        number(&mut b, 1, 1, true);
        let t = triggers(&b).unwrap();
        assert_eq!(t.principal.as_deref(), Some("LocalSystem"));
        assert_eq!(t.display.as_deref(), Some("Test task"));
        assert_eq!(t.items.len(), 3);
        assert_eq!(t.items[0].description, "Boot trigger");
        assert_eq!(t.items[1].description, "WNF state 7520bda33e06830d");
        assert_eq!(t.items[1].enabled, Some(false));
        assert_eq!(t.items[2].description, "SessionUnlock");
        for end in 0..b.len() {
            let _ = triggers(&b[..end]);
        }
        let mut huge = header();
        generic(&mut huge, 0x6666, true);
        huge.extend([0; 8]);
        number(&mut huge, u32::MAX as u64, 4, true);
        assert!(triggers(&huge).unwrap().incomplete);
    }
    #[test]
    fn time_schedule_and_dynamic_information_follow_pinned_fields() {
        let mut b = header();
        number(&mut b, 0xdddd, 4, true);
        b.resize(b.len() + 48 + 16 + 8, 0);
        number(&mut b, 0, 1, false);
        number(&mut b, 1, 1, false);
        b.resize(b.len() + 14, 0);
        string(&mut b, "", false);
        b.resize(b.len() + 4, 0);
        let t = triggers(&b).unwrap();
        assert_eq!(t.items.len(), 1);
        assert_eq!(t.items[0].kind, "Time");
        assert_eq!(t.items[0].enabled, Some(true));
        assert_eq!(t.items[0].description, NA);
        let epoch = 116_444_736_000_000_000;
        let mut b = Vec::new();
        number(&mut b, 3, 4, false);
        number(&mut b, epoch, 8, false);
        number(&mut b, epoch + 10_000_000, 8, false);
        number(&mut b, 0, 8, false);
        number(&mut b, epoch + 20_000_000, 8, false);
        assert_eq!(
            dynamic(&b),
            [
                "1970-01-01T00:00:01+00:00",
                "1970-01-01T00:00:00+00:00",
                "1970-01-01T00:00:02+00:00"
            ]
        );
        assert_eq!(dynamic(&[0; 36]), [NA, NA, NA]);
        assert_eq!(valid_time(u64::MAX), None);
        assert!(Reader::new(&[255; 4]).block(false).is_none());
    }

    fn expanded(b: &mut Vec<u8>, s: &str) {
        number(b, s.encode_utf16().count() as u64, 4, true);
        if s.is_empty() {
            return;
        }
        let raw: Vec<_> = s
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect();
        b.extend(&raw);
        b.resize(b.len() + (8 - raw.len() % 8) % 8, 0);
    }
    #[test]
    fn event_queries_and_truncated_later_trigger_preserve_prior_records() {
        let mut b = header();
        generic(&mut b, 0xcccc, true);
        expanded(&mut b, "<QueryList/>");
        b.resize(b.len() + 8, 0);
        expanded(&mut b, "");
        number(&mut b, 1, 4, true);
        expanded(&mut b, "path");
        expanded(&mut b, "Event/'Data'");
        let t = triggers(&b).unwrap();
        assert_eq!(t.items.len(), 1);
        assert_eq!(
            t.items[0].description,
            "Event trigger: Subscription: <QueryList/>, Queries: [('path', \"Event/'Data'\")]"
        );
        assert!(!t.incomplete);
        generic(&mut b, 0x6666, true);
        b.extend([0; 8]);
        number(&mut b, u32::MAX as u64, 4, true);
        let t = triggers(&b).unwrap();
        assert_eq!(t.items.len(), 1);
        assert!(t.incomplete);
        assert_eq!(t.principal.as_deref(), Some("LocalSystem"));
    }
    #[test]
    fn messagebox_and_email_consume_properties_and_continue_to_later_actions() {
        let mut b = Vec::new();
        number(&mut b, 2, 2, false);
        string(&mut b, "Context", false);
        number(&mut b, 0x9999, 2, false);
        string(&mut b, "", false);
        string(&mut b, "Title", false);
        string(&mut b, "Content", false);
        number(&mut b, 0x8888, 2, false);
        string(&mut b, "", false);
        for name in [
            "sender", "to", "cc", "bcc", "reply", "server", "subject", "body",
        ] {
            string(&mut b, name, false);
        }
        number(&mut b, 1, 4, false);
        string(&mut b, "attachment", false);
        number(&mut b, 1, 4, false);
        string(&mut b, "header", false);
        string(&mut b, "value", false);
        number(&mut b, 0x7777, 2, false);
        string(&mut b, "", false);
        b.extend([0; 16]);
        string(&mut b, "", false);
        let (_, a) = actions(&b);
        assert_eq!(a.len(), 3);
        assert_eq!(a[0].action, "\"Title\": Content");
        assert_eq!(a[1].kind, NA);
        assert_eq!(a[2].action, "{0-0-0-0-0}");
    }
    #[test]
    fn sid_and_query_strings_preserve_binary_and_text_values() {
        let mut b = Vec::new();
        number(&mut b, 0, 1, true);
        number(&mut b, 0, 1, true);
        number(&mut b, 1, 4, true);
        let sid = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        number(&mut b, sid.len() as u64, 4, true);
        b.extend(sid);
        b.resize(b.len() + 4, 0);
        string(&mut b, "SYSTEM", true);
        let u = user(&mut Reader::new(&b)).unwrap();
        assert_eq!(u.sid.as_deref(), Some("S-1-5-18"));
        assert_eq!(u.username.as_deref(), Some("SYSTEM"));
        assert_eq!(python_repr("a'b"), "\"a'b\"");
        assert_eq!(python_repr("a\\b\n"), "'a\\\\b\\n'");
    }
}
