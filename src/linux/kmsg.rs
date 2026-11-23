//! Volatility-compatible Linux kernel ring buffer (`linux.kmsg.Kmsg`).
//! Supports all three printk generations:
//! 1. Linux 5.10+ lockless `printk_ringbuffer` (`prb`)
//! 2. Linux 3.5–5.9 variable-length `printk_log`/`log` records (`log_first_idx`/`log_next_idx`)
//! 3. Linux < 3.5 raw circular `log_buf` (`log_end`/`logged_chars`)
use super::*;
use crate::bytes::JsonKey as _;

const FACILITIES: [&str; 24] = [
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv",
    "ftp", "ntp", "logaudit", "logalert", "clock", "local0", "local1", "local2", "local3",
    "local4", "local5", "local6", "local7",
];

const LEVELS: [&str; 8] = [
    "emerg", "alert", "crit", "err", "warn", "notice", "info", "debug",
];

fn facility_name(value: u64) -> String {
    usize::try_from(value)
        .ok()
        .and_then(|i| FACILITIES.get(i).copied())
        .map(str::to_owned)
        .unwrap_or_else(|| format!("facility({value})"))
}

fn level_name(value: u64) -> String {
    usize::try_from(value & 0x7)
        .ok()
        .and_then(|i| LEVELS.get(i).copied())
        .unwrap_or("info")
        .into()
}

fn format_ts_nsec(ts_nsec: u64) -> String {
    let sec = ts_nsec / 1_000_000_000;
    let usec = (ts_nsec % 1_000_000_000) / 1_000;
    format!("{sec}.{usec:06}")
}

fn format_caller_id(caller_id: Option<u64>) -> String {
    match caller_id {
        Some(v) if v & 0x8000_0000 != 0 => format!("C{}", v & 0x7fff_ffff),
        Some(v) if v != 0 => format!("T{v}"),
        _ => String::new(),
    }
}

/// Parse pre-3.5 text lines of the form `<N>[   12.345678] message`.
fn parse_legacy_line(raw: &str) -> (String, String, String, String, String) {
    let mut rest = raw;
    let mut facility = "kern".to_string();
    let mut level = "info".to_string();
    if let Some(after_lt) = rest.strip_prefix('<')
        && let Some((num, tail)) = after_lt.split_once('>')
        && let Ok(pri) = num.parse::<u64>()
    {
        facility = facility_name(pri >> 3);
        level = level_name(pri & 0x7);
        rest = tail;
    }
    let mut timestamp = String::new();
    if let Some(after_br) = rest.strip_prefix('[')
        && let Some((ts, tail)) = after_br.split_once(']')
    {
        let trimmed = ts.trim();
        if trimmed.bytes().all(|b| b.is_ascii_digit() || b == b'.') && trimmed.contains('.') {
            timestamp = trimmed.to_string();
            rest = tail.strip_prefix(' ').unwrap_or(tail);
        }
    }
    (facility, level, timestamp, String::new(), rest.to_string())
}

struct KmsgRecord {
    facility: String,
    level: String,
    timestamp: String,
    caller: String,
    text: String,
}

fn push_kmsg_lines(result: &mut Results, rec: &KmsgRecord) {
    let mut emitted = false;
    for line in rec.text.split('\n') {
        if emitted && line.is_empty() {
            continue;
        }
        result.rows.push(vec![
            rec.facility.clone(),
            rec.level.clone(),
            rec.timestamp.clone(),
            rec.caller.clone(),
            line.to_string(),
        ]);
        emitted = true;
    }
}

impl Linux<'_> {
    pub(super) fn kmsg(&self, job: &Job) -> Result<Results> {
        let mut result = self.result(Plugin::LinuxKmsg);
        if self.isf.address("prb").is_ok() {
            self.kmsg_prb(&mut result, job)?;
        } else if self.isf.address("log_first_idx").is_ok()
            && self.isf.address("log_next_idx").is_ok()
            && self.isf.address("log_buf").is_ok()
            && self.isf.address("log_buf_len").is_ok()
        {
            self.kmsg_variable(&mut result, job)?;
        } else if self.isf.address("log_buf").is_ok()
            && self.isf.address("log_buf_len").is_ok()
            && self.isf.address("logged_chars").is_ok()
            && self.isf.address("log_end").is_ok()
        {
            self.kmsg_legacy(&mut result, job)?;
        } else {
            bail!(
                "不支持: 缺少 printk 环形缓冲区符号（需要 prb，或 log_first_idx/log_next_idx，或 log_buf/logged_chars/log_end）"
            );
        }
        job.check()?;
        Ok(result)
    }

    fn kmsg_prb(&self, result: &mut Results, job: &Job) -> Result<()> {
        let prb = self.vm.uint(self.isf.address("prb")?, 8)?;
        let desc = self.field_address(prb, "printk_ringbuffer", "desc_ring")?;
        let data = self.field_address(prb, "printk_ringbuffer", "text_data_ring")?;
        let count_bits = self.number(desc, "prb_desc_ring", "count_bits")?;
        let size_bits = self.number(data, "prb_data_ring", "size_bits")?;
        ensure!(
            count_bits <= 20 && size_bits <= 24,
            "printk ring 超过安全上限"
        );
        let count = 1u64 << count_bits;
        let size = 1u64 << size_bits;
        let descs = self.number(desc, "prb_desc_ring", "descs")?;
        let infos = self.number(desc, "prb_desc_ring", "infos")?;
        let bytes = self.number(data, "prb_data_ring", "data")?;
        let tail = self.number(desc, "prb_desc_ring", "tail_id.counter")?;
        let head = self.number(desc, "prb_desc_ring", "head_id.counter")?;
        let mask = (1u64 << 62) - 1;
        let length = head.wrapping_sub(tail) & mask;
        ensure!(length < count, "printk descriptor 范围无效");
        let desc_size = self.isf.data.key("user_types")["prb_desc"]
            .key("size")
            .as_u64()
            .context("prb_desc size")?;
        let info_size = self.isf.data.key("user_types")["printk_info"]
            .key("size")
            .as_u64()
            .context("printk_info size")?;
        let has_caller = self.isf.field("printk_info", "caller_id").is_ok();

        for n in 0..=length {
            job.check()?;
            let id = tail.wrapping_add(n) & mask;
            let idx = id & (count - 1);
            let read = (|| -> Result<Option<KmsgRecord>> {
                let d = add(descs, idx.checked_mul(desc_size).context("desc 偏移溢出")?)?;
                let state = self.number(d, "prb_desc", "state_var.counter")?;
                if state & mask != id || !matches!(state >> 62, 1 | 2) {
                    return Ok(None);
                }
                let info = add(infos, idx.checked_mul(info_size).context("info 偏移溢出")?)?;
                let len = self.number(info, "printk_info", "text_len")?;
                let begin = self.number(d, "prb_desc", "text_blk_lpos.begin")?;
                let next = self.number(d, "prb_desc", "text_blk_lpos.next")?;
                if begin & 1 != 0 {
                    ensure!(len == 0, "printk dataless 记录长度不为 0");
                    return Ok(None);
                }
                ensure!(begin & 7 == 0 && next & 7 == 0, "printk block 未对齐");
                let (pos, capacity) = if begin / size == next / size && begin < next {
                    (begin & (size - 1), next - begin)
                } else if begin.wrapping_add(size) / size == next / size {
                    (0, next & (size - 1))
                } else {
                    bail!("printk block wrap 无效");
                };
                ensure!(
                    capacity >= 8 && len <= capacity - 8 && pos + capacity <= size,
                    "printk 记录越界"
                );
                ensure!(
                    self.vm.uint(add(bytes, pos)?, 8)? == id,
                    "printk 文本 descriptor ID 不一致"
                );
                let mut text = vec![0; usize::try_from(len)?];
                self.vm.read(add(bytes, pos + 8)?, &mut text)?;
                let facility = facility_name(self.number(info, "printk_info", "facility")?);
                let level = level_name(self.number(info, "printk_info", "level")?);
                let timestamp = format_ts_nsec(self.number(info, "printk_info", "ts_nsec")?);
                let caller = format_caller_id(if has_caller {
                    self.number(info, "printk_info", "caller_id").ok()
                } else {
                    None
                });
                Ok(Some(KmsgRecord {
                    facility,
                    level,
                    timestamp,
                    caller,
                    text: String::from_utf8_lossy(&text).into_owned(),
                }))
            })();
            match read {
                Ok(Some(rec)) => push_kmsg_lines(result, &rec),
                Ok(None) => {}
                Err(error) => {
                    job.check()?;
                    partial(result, format!("printk descriptor {id:#x}"), error);
                }
            }
        }
        Ok(())
    }

    fn kmsg_variable(&self, result: &mut Results, job: &Job) -> Result<()> {
        let rec_ty = if self.isf.data.key("user_types")["printk_log"].is_object() {
            "printk_log"
        } else if self.isf.data.key("user_types")["log"].is_object() {
            "log"
        } else {
            bail!("不支持: ISF 缺少 printk_log / log 结构");
        };
        let header_size = self.isf.data.key("user_types")[rec_ty]
            .key("size")
            .as_u64()
            .context("printk_log size 缺失")?;
        ensure!(
            header_size > 0 && header_size <= 256,
            "printk_log size 无效"
        );

        let ptr_size = usize::try_from(
            self.isf.data.key("base_types")["pointer"]
                .key("size")
                .as_u64()
                .unwrap_or(8),
        )?;
        let buf = self.vm.uint(self.isf.address("log_buf")?, ptr_size)?;
        let buf_len = self.vm.uint(self.isf.address("log_buf_len")?, 4)?;
        ensure!(
            buf != 0 && buf_len > 0 && buf_len <= 16 * 1024 * 1024,
            "log_buf 长度无效或超过 16 MiB"
        );
        let first_idx = self.vm.uint(self.isf.address("log_first_idx")?, 4)?;
        let next_idx = self.vm.uint(self.isf.address("log_next_idx")?, 4)?;
        ensure!(first_idx < buf_len && next_idx < buf_len, "log_idx 越界");

        let has_caller = self.isf.field(rec_ty, "caller_id").is_ok();
        let has_facility = self.isf.field(rec_ty, "facility").is_ok();
        let has_level = self.isf.field(rec_ty, "level").is_ok();

        let mut idx = first_idx;
        let mut seen = 0usize;
        while idx != next_idx && seen < LIMIT {
            job.check()?;
            seen += 1;
            let rec_addr = add(buf, idx)?;
            let rec_len = match self.number(rec_addr, rec_ty, "len") {
                Ok(v) => v,
                Err(error) => {
                    partial(result, format!("kmsg record @ {idx:#x}"), error);
                    break;
                }
            };
            if rec_len == 0 {
                // Length 0 is the wrap marker back to offset 0 in Linux log_buf.
                if idx == 0 {
                    break;
                }
                idx = 0;
                continue;
            }
            if rec_len < header_size || idx + rec_len > buf_len {
                partial(
                    result,
                    format!("kmsg record @ {idx:#x}"),
                    anyhow::anyhow!("记录长度异常: {rec_len}"),
                );
                break;
            }
            let read = (|| -> Result<()> {
                let text_len = self.number(rec_addr, rec_ty, "text_len")?;
                ensure!(header_size + text_len <= rec_len, "text_len 超过记录长度");
                let ts = format_ts_nsec(self.number(rec_addr, rec_ty, "ts_nsec")?);
                let fac = if has_facility {
                    facility_name(self.number(rec_addr, rec_ty, "facility")?)
                } else {
                    "kern".into()
                };
                let lvl = if has_level {
                    level_name(self.number(rec_addr, rec_ty, "level")?)
                } else {
                    "info".into()
                };
                let caller = format_caller_id(if has_caller {
                    self.number(rec_addr, rec_ty, "caller_id").ok()
                } else {
                    None
                });
                let mut text = vec![0; usize::try_from(text_len)?];
                self.vm.read(add(rec_addr, header_size)?, &mut text)?;
                push_kmsg_lines(
                    result,
                    &KmsgRecord {
                        facility: fac,
                        level: lvl,
                        timestamp: ts,
                        caller,
                        text: String::from_utf8_lossy(&text).into_owned(),
                    },
                );
                Ok(())
            })();
            if let Err(error) = read {
                job.check()?;
                partial(result, format!("kmsg record @ {idx:#x}"), error);
            }
            idx += rec_len;
            if idx == buf_len {
                idx = 0;
            }
        }
        Ok(())
    }

    fn kmsg_legacy(&self, result: &mut Results, job: &Job) -> Result<()> {
        let mut raw = self.result(Plugin::Dmesg);
        self.logs(&mut raw, job)?;
        result.complete = raw.complete;
        result.diagnostics = raw.diagnostics;
        for row in raw.rows {
            job.check()?;
            let line = row.cell(1);
            let (fac, lvl, ts, caller, msg) = parse_legacy_line(line);
            result.rows.push(vec![fac, lvl, ts, caller, msg]);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::tests::{engine, fixture, image};
    use serde_json::json;

    fn put_u16(b: &mut [u8], at: usize, v: u16) {
        b[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn put_u32(b: &mut [u8], at: usize, v: u32) {
        b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn put_u64(b: &mut [u8], at: usize, v: u64) {
        b[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }

    #[test]
    fn kmsg_parses_variable_length_printk_log_records_and_wrap_marker() {
        let (mut b, mut isf) = fixture();
        isf.data["base_types"]["u16"] = json!({"size":2});
        isf.data["base_types"]["u8"] = json!({"size":1});
        isf.data["user_types"]["printk_log"] = json!({
            "size": 16,
            "fields": {
                "ts_nsec": {"offset": 0, "type": {"kind": "base", "name": "u64"}},
                "len": {"offset": 8, "type": {"kind": "base", "name": "u16"}},
                "text_len": {"offset": 10, "type": {"kind": "base", "name": "u16"}},
                "facility": {"offset": 12, "type": {"kind": "base", "name": "u8"}},
                "level": {"offset": 13, "type": {"kind": "base", "name": "u8"}}
            }
        });
        for (sym, addr) in [
            ("log_buf", 0x10000usize),
            ("log_buf_len", 0x10008),
            ("log_first_idx", 0x10010),
            ("log_next_idx", 0x10018),
        ] {
            isf.data["symbols"][sym] = json!({"address": addr});
        }
        put_u64(&mut b, 0x10000, 0x12000); // log_buf ptr
        put_u32(&mut b, 0x10008, 128); // log_buf_len
        put_u32(&mut b, 0x10010, 64); // log_first_idx (starts near end, wraps to 0)
        put_u32(&mut b, 0x10018, 32); // log_next_idx

        // Record 1 at offset 64 (len 32, text "boot ok"): facility=0 (kern), level=6 (info)
        put_u64(&mut b, 0x12000 + 64, 1_500_000_000);
        put_u16(&mut b, 0x12000 + 64 + 8, 32);
        put_u16(&mut b, 0x12000 + 64 + 10, 7);
        b[0x12000 + 64 + 12] = 0;
        b[0x12000 + 64 + 13] = 6;
        b[0x12000 + 64 + 16..0x12000 + 64 + 23].copy_from_slice(b"boot ok");
        // Wrap marker (len = 0) at offset 96
        put_u16(&mut b, 0x12000 + 96 + 8, 0);

        // Record 2 at offset 0 (len 32, text "oom!"): facility=3 (daemon), level=3 (err)
        put_u64(&mut b, 0x12000, 2_000_123_000);
        put_u16(&mut b, 0x12000 + 8, 32);
        put_u16(&mut b, 0x12000 + 10, 4);
        b[0x12000 + 12] = 3;
        b[0x12000 + 13] = 3;
        b[0x12000 + 16..0x12000 + 20].copy_from_slice(b"oom!");

        let img = image(&b);
        let linux = engine(&img, &isf);
        let result = linux.kmsg(&Job::default()).unwrap();
        assert!(result.complete, "{:?}", result.diagnostics);
        assert_eq!(result.rows.len(), 2);
        assert_eq!(
            result.rows[0],
            vec!["kern", "info", "1.500000", "", "boot ok"]
        );
        assert_eq!(
            result.rows[1],
            vec!["daemon", "err", "2.000123", "", "oom!"]
        );
    }

    #[test]
    fn legacy_kmsg_line_parser_decodes_priority_and_timestamp() {
        assert_eq!(
            parse_legacy_line("<4>[   12.345678] warning msg"),
            (
                "kern".into(),
                "warn".into(),
                "12.345678".into(),
                String::new(),
                "warning msg".into()
            )
        );
        assert_eq!(format_caller_id(Some(0x8000_0003)), "C3");
        assert_eq!(format_caller_id(Some(421)), "T421");
    }
}
