//! Bounded, cancellable stack-word reads. This scans saved words, not frame-pointer
//! unwinding; positions count zero words and stop at the first unavailable word.
use crate::Job;
use crate::bytes::Checked as _;
use anyhow::{Context, Result, ensure};
use serde::Serialize;
#[derive(Default, Serialize)]
pub(crate) struct Coverage {
    pub words_read: u64,
    pub nonzero_words: u64,
    pub first_unreadable: Option<String>,
    pub output_stopped: bool,
}
pub(crate) struct Word {
    pub position: u64,
    pub address: u64,
    pub value: u64,
}
pub(crate) fn words(
    base: u64,
    sp: u64,
    size: u64,
    width: usize,
    job: &Job,
    mut read: impl FnMut(u64, &mut [u8]) -> Result<()>,
    mut visit: impl FnMut(Word) -> Result<bool>,
) -> Result<Coverage> {
    ensure!(matches!(width, 4 | 8), "栈指针宽度必须为 4 或 8");
    ensure!(
        size > 0 && size <= 1024 * 1024,
        "栈扫描范围超过 1 MiB 或为空"
    );
    let top = base.checked_add(size).context("栈顶地址溢出")?;
    ensure!(base <= sp && sp < top, "保存的 SP 不在栈扫描范围内");
    let mut at = sp;
    let mut out = Coverage::default();
    // The reference tests the word's starting address against the stack top;
    // an unaligned final word can extend beyond that top if its bytes exist.
    while at < top {
        job.check()?;
        let mut bytes = [0; 8];
        if let Err(e) = read(at, bytes.at_mut(..width)?) {
            job.check()?;
            out.first_unreadable = Some(format!("{at:#x}: {e:#}"));
            break;
        }
        let position = out.words_read;
        out.words_read += 1;
        let value = u64::from_le_bytes(bytes);
        if value != 0 {
            out.nonzero_words += 1;
            if !visit(Word {
                position,
                address: at,
                value,
            })? {
                out.output_stopped = true;
                break;
            }
        }
        if top - at <= width as u64 {
            break;
        }
        at += width as u64;
    }
    job.check()?;
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_task_stack_vectors_cover_unaligned_tail_and_first_fault() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/reference/parity/fixtures/callstack-module-gates.json"
        ))
        .unwrap();
        for case in vectors["stack"].as_array().unwrap() {
            let data: Vec<_> = case["data_hex"]
                .as_str()
                .unwrap()
                .as_bytes()
                .chunks_exact(2)
                .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
                .collect();
            let base = case["base"].as_u64().unwrap();
            let mut found = Vec::new();
            let report = words(
                base,
                case["sp"].as_u64().unwrap(),
                case["size"].as_u64().unwrap(),
                case["width"].as_u64().unwrap() as usize,
                &Job::default(),
                |at, out| {
                    ensure!(
                        !case["faults"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|p| p.as_u64() == Some(at)),
                        "synthetic missing word"
                    );
                    let start = (at - base) as usize;
                    ensure!(start + out.len() <= data.len(), "synthetic bounds");
                    out.copy_from_slice(&data[start..start + out.len()]);
                    Ok(())
                },
                |word| {
                    found.push(serde_json::json!({"position":word.position,"address":word.address,"value":word.value}));
                    Ok(true)
                },
            );
            assert_eq!(
                report.is_err(),
                case["expected_error"].as_bool().unwrap(),
                "{}",
                case["id"]
            );
            assert_eq!(serde_json::json!(found), case["expected"], "{}", case["id"]);
        }
    }
    #[test]
    fn positions_include_zero_words_and_holes_preserve_prefix() {
        let mut hits = Vec::new();
        let c = words(
            0x1000,
            0x1008,
            32,
            8,
            &Job::default(),
            |at, out| {
                ensure!(at != 0x1018, "hole");
                out.copy_from_slice(&(if at == 0x1010 { 0x1234u64 } else { 0 }).to_le_bytes());
                Ok(())
            },
            |w| {
                hits.push((w.position, w.address, w.value));
                Ok(true)
            },
        )
        .unwrap();
        assert_eq!(hits, [(1, 0x1010, 0x1234)]);
        assert_eq!(c.words_read, 2);
        assert!(c.first_unreadable.is_some());
    }
    #[test]
    fn invalid_sp_overflow_output_stop_and_cancel_are_explicit() {
        assert!(
            words(
                0x1000,
                0x2000,
                32,
                8,
                &Job::default(),
                |_, _| Ok(()),
                |_| Ok(true)
            )
            .is_err()
        );
        assert!(
            words(
                u64::MAX - 8,
                u64::MAX - 8,
                32,
                8,
                &Job::default(),
                |_, _| Ok(()),
                |_| Ok(true)
            )
            .is_err()
        );
        let c = words(
            0,
            0,
            32,
            8,
            &Job::default(),
            |_, out| {
                out.fill(1);
                Ok(())
            },
            |_| Ok(false),
        )
        .unwrap();
        assert!(c.output_stopped);
        assert_eq!(c.words_read, 1);
        let job = Job::default();
        job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(words(0, 0, 32, 8, &job, |_, _| Ok(()), |_| Ok(true)).is_err());
    }
}
