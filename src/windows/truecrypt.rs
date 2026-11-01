//! TrueCrypt's DWORD-aligned cached Password records in the first .data section.
use super::*;
use crate::bytes::{Checked as _, JsonKey as _};
const SCAN_LIMIT: u64 = 64 * 1024 * 1024;
const HIT_LIMIT: usize = 100_000;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Section {
    start: u64,
    size: u64,
}
fn data_section(
    base: u64,
    mut read: impl FnMut(u64, &mut [u8]) -> Result<()>,
    job: &Job,
) -> Result<Section> {
    job.check()?;
    let mut dos = [0; 64];
    read(base, &mut dos)?;
    ensure!(&dos[..2] == b"MZ", "TrueCrypt 缺少 MZ 头");
    let nt = add(base, u64::from(u32::from_le_bytes(dos[60..64].try_into()?)))?;
    let mut header = [0; 24];
    read(nt, &mut header)?;
    ensure!(&header[..4] == b"PE\0\0", "TrueCrypt PE 签名无效");
    let count = u16::from_le_bytes(header[6..8].try_into()?) as u64;
    ensure!(count <= 96, "TrueCrypt PE section 数量超限");
    let optional = u16::from_le_bytes(header[20..22].try_into()?) as u64;
    let mut magic = [0; 2];
    read(add(nt, 24)?, &mut magic)?;
    ensure!(
        matches!(u16::from_le_bytes(magic), 0x10b | 0x20b),
        "TrueCrypt PE 位宽无效"
    );
    ensure!(optional >= 2, "TrueCrypt PE 可选头长度无效");
    let sections = add(add(nt, 24)?, optional)?;
    for index in 0..count {
        job.check()?;
        let mut bytes = [0; 40];
        read(add(sections, index * 40)?, &mut bytes)?;
        let end = bytes[..8].iter().position(|b| *b == 0).unwrap_or(8);
        if bytes.at(..end)? == b".data" {
            let size = u64::from(u32::from_le_bytes(bytes[8..12].try_into()?));
            let start = add(
                base,
                u64::from(u32::from_le_bytes(bytes[12..16].try_into()?)),
            )?;
            add(start, size)?;
            ensure!(size.is_multiple_of(4), "PE data section not DWORD-aligned!");
            return Ok(Section { start, size });
        }
    }
    bail!("TrueCrypt PE 缺少 .data section")
}
#[derive(Default)]
struct Scan {
    rows: Vec<(u64, String)>,
    length_words: u64,
    missing_words: u64,
    missing_records: u64,
    first_error: Option<String>,
    stopped: bool,
}
fn scan(
    section: Section,
    min: i64,
    job: &Job,
    mut read: impl FnMut(u64, &mut [u8]) -> Result<()>,
) -> Result<Scan> {
    ensure!(
        section.size.is_multiple_of(4),
        "PE data section not DWORD-aligned!"
    );
    let mut result = Scan::default();
    let size = section.size.min(SCAN_LIMIT);
    result.stopped = size != section.size;
    let end = add(section.start, size)?;
    let mut at = section.start;
    while at < end {
        job.check()?;
        let n = usize::try_from((4096 - (at & 4095)).min(end - at))?;
        // At an unaligned virtual section base, preserve the section-relative DWORD grid.
        let n = if n < 4 {
            4.min(usize::try_from(end - at)?)
        } else {
            n - n % 4
        };
        let mut words = vec![0; n];
        if let Err(error) = read(at, &mut words) {
            result.missing_words += n as u64 / 4;
            if result.first_error.is_none() {
                result.first_error = Some(format!("{at:#x}: {error:#}"));
            }
            at = add(at, n as u64)?;
            continue;
        }
        for (index, word) in words.chunks_exact(4).enumerate() {
            job.check()?;
            result.length_words += 1;
            let length = i64::from(i32::from_le_bytes(word.try_into()?));
            if length < min || length > 64 {
                continue;
            }
            ensure!(
                length >= 0,
                "TrueCrypt 候选密码长度为负数；固定参考同样无法构造该记录"
            );
            let offset = add(at, index as u64 * 4 + 4)?;
            let mut password = vec![0; usize::try_from(length)?];
            let mut padding = [0; 3];
            let found = (|| -> Result<bool> {
                if !password.is_empty() {
                    read(offset, &mut password)?;
                }
                if !password.iter().all(|b| (0x20..0x7f).contains(b)) {
                    return Ok(false);
                }
                // The pinned reference does NOT inspect the would-be NUL byte.
                read(add(offset, length as u64 + 1)?, &mut padding)?;
                Ok(padding == [0; 3])
            })();
            match found {
                Ok(true) => {
                    if result.rows.len() == HIT_LIMIT {
                        result.stopped = true;
                        return Ok(result);
                    }
                    result.rows.push((offset, String::from_utf8(password)?));
                }
                Ok(false) => (),
                Err(error) => {
                    result.missing_records += 1;
                    if result.first_error.is_none() {
                        result.first_error = Some(format!("{offset:#x}: {error:#}"));
                    }
                }
            }
        }
        at = add(at, n as u64)?;
    }
    Ok(result)
}
impl Windows<'_> {
    pub(super) fn truecrypt_passphrase(&self, options: &Options, job: &Job) -> Result<Results> {
        ensure!(
            matches!(
                Architecture::from_isf(self.vm.isf)?,
                Architecture::X86 | Architecture::X64
            ),
            "TrueCrypt Passphrase 仅支持 Intel x86/x64"
        );
        let mut r = self.result(Plugin::WinTruecryptPassphrase);
        let modules = self.module_entries(job, &mut r, false)?;
        let Some(module) = modules
            .iter()
            .find(|m| m.name.to_lowercase() == "truecrypt.sys")
        else {
            *r.kernel_identity.key_mut("truecrypt")? = serde_json::json!({"module_found":false,"min_length":options.min_length.unwrap_or(5)});
            return Ok(r);
        };
        let section = data_section(module.base, |at, b| self.vm.read_captured(at, b), job)?;
        let min = options.min_length.unwrap_or(5);
        let found = scan(section, min, job, |at, b| self.vm.read_captured(at, b))?;
        if found.missing_words > 0 || found.missing_records > 0 || found.stopped {
            Self::issue(
                &mut r,
                "TrueCrypt .data",
                format!(
                    "长度字段缺失 {} 个；候选记录缺失 {} 个；达到上限 {}；{}",
                    found.missing_words,
                    found.missing_records,
                    found.stopped,
                    found.first_error.as_deref().unwrap_or("扫描结束")
                ),
            );
        }
        *r.kernel_identity.key_mut("truecrypt")? = serde_json::json!({"module_found":true,"module_base":hex(module.base),"section_start":hex(section.start),"section_size":section.size,"min_length":min,"length_words":found.length_words,"missing_words":found.missing_words,"missing_records":found.missing_records,"stopped":found.stopped,"scan_limit":SCAN_LIMIT,"hit_limit":HIT_LIMIT,"terminator":"pinned reference skips the would-be NUL byte; requires the following three zero bytes"});
        r.rows = found
            .rows
            .into_iter()
            .map(|(at, password)| vec![hex(at), password.len().to_string(), password])
            .collect();
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{K, fixture, image, put};
    use super::*;
    use serde_json::{Value, json};
    fn fixture_bytes(c: &Value) -> Vec<u8> {
        let mut bytes = vec![0xcc; 0x3000];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[60..64].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        let wide = c["wide"].as_bool().unwrap();
        let optional = if wide { 240u16 } else { 224 };
        bytes[0x84..0x86].copy_from_slice(&(if wide { 0x8664u16 } else { 0x14c }).to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&optional.to_le_bytes());
        bytes[0x98..0x9a].copy_from_slice(&(if wide { 0x20bu16 } else { 0x10b }).to_le_bytes());
        let table = 0x98 + optional as usize;
        bytes[table..table + 8].fill(0);
        let name = c["section_name"].as_str().unwrap_or(".data");
        bytes[table..table + name.len()].copy_from_slice(name.as_bytes());
        bytes[table + 8..table + 12]
            .copy_from_slice(&(c["section_size"].as_u64().unwrap() as u32).to_le_bytes());
        bytes[table + 12..table + 16]
            .copy_from_slice(&(c["section_start"].as_u64().unwrap_or(0x1000) as u32).to_le_bytes());
        for patch in c["patches"].as_array().unwrap() {
            let at = patch[0].as_u64().unwrap() as usize;
            let hex = patch[1].as_str().unwrap();
            for (i, word) in hex.as_bytes().chunks_exact(2).enumerate() {
                bytes[at + i] = u8::from_str_radix(std::str::from_utf8(word).unwrap(), 16).unwrap();
            }
        }
        bytes
    }
    #[test]
    fn exact_reference_vectors_cover_x86_x64_signed_lengths_padding_and_boundaries() {
        let v: Value = serde_json::from_str(include_str!(
            "../../tests/reference/parity/fixtures/truecrypt.json"
        ))
        .unwrap();
        for c in v["cases"].as_array().unwrap() {
            let bytes = fixture_bytes(c);
            let mut read = |at: u64, out: &mut [u8]| -> Result<()> {
                out.copy_from_slice(
                    bytes
                        .get(at as usize..at as usize + out.len())
                        .context("missing")?,
                );
                Ok(())
            };
            let result = data_section(0, &mut read, &Job::default()).and_then(|section| {
                scan(
                    section,
                    c["min_length"].as_i64().unwrap(),
                    &Job::default(),
                    &mut read,
                )
            });
            if c.get("error_type").is_some() {
                assert!(result.is_err(), "{}", c["id"]);
                continue;
            }
            let result = result.unwrap();
            assert!(!result.stopped);
            assert_eq!(result.missing_records, 0);
            let rows = result
                .rows
                .iter()
                .map(|(offset, password)| json!({"offset":offset,"password":password}))
                .collect::<Vec<_>>();
            assert_eq!(json!(rows), c["expected"], "{}", c["id"]);
        }
    }
    fn prepared() -> (Vec<u8>, Isf) {
        let (mut b, mut isf) = fixture();
        let pointer = |offset| json!({"offset":offset,"type":{"kind":"pointer"}});
        isf.data["user_types"]["_KLDR_DATA_TABLE_ENTRY"] = json!({"size":64,"fields":{"InLoadOrderLinks":{"offset":0,"type":{"kind":"struct","name":"_LIST_ENTRY"}},"DllBase":pointer(16),"SizeOfImage":pointer(24),"BaseDllName":{"offset":32,"type":{"kind":"struct","name":"_UNICODE_STRING"}}}});
        put(&mut b, 0x8700, K + 0x6000);
        put(&mut b, 0x8708, K + 0x6000);
        put(&mut b, 0xe000, K + 0x700);
        put(&mut b, 0xe008, K + 0x700);
        put(&mut b, 0xe010, K);
        put(&mut b, 0xe018, 0x20000);
        let name: Vec<_> = "TrUeCrYpT.SyS"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        b[0xe020..0xe022].copy_from_slice(&(name.len() as u16).to_le_bytes());
        b[0xe022..0xe024].copy_from_slice(&(name.len() as u16).to_le_bytes());
        put(&mut b, 0xe028, K + 0x7000);
        b[0xf000..0xf000 + name.len()].copy_from_slice(&name);
        b[0x8086..0x8088].copy_from_slice(&1u16.to_le_bytes());
        b[0x8094..0x8096].copy_from_slice(&240u16.to_le_bytes());
        let table = 0x8188;
        b[table..table + 8].fill(0);
        b[table..table + 5].copy_from_slice(b".data");
        b[table + 8..table + 12].copy_from_slice(&0x100u32.to_le_bytes());
        b[table + 12..table + 16].copy_from_slice(&0x10000u32.to_le_bytes());
        b[0x18000..0x18100].fill(0xcc);
        password(&mut b, 0x18000, b"Test phrase");
        password(&mut b, 0x18060, b"tiny");
        (b, isf)
    }
    fn password(bytes: &mut [u8], at: usize, text: &[u8]) {
        bytes[at..at + 4].copy_from_slice(&(text.len() as i32).to_le_bytes());
        bytes[at + 4..at + 4 + text.len()].copy_from_slice(text);
        bytes[at + 4 + text.len()..at + 8 + text.len()].fill(0);
    }
    fn run(bytes: &[u8], isf: &Isf, min_length: Option<i64>) -> Results {
        let image = image(bytes);
        let w = Windows {
            vm: Memory::new(&image, 0x1000, isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(isf).unwrap(),
        };
        w.run(
            Plugin::WinTruecryptPassphrase,
            &Options {
                min_length,
                ..Default::default()
            },
            &Job::default(),
        )
        .unwrap()
    }
    #[test]
    fn full_plugin_uses_first_case_insensitive_driver_and_needs_no_full_path() {
        let (mut b, isf) = prepared();
        let r = run(&b, &isf, None);
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(
            r.rows,
            [vec![hex(K + 0x10004), "11".into(), "Test phrase".into()]]
        );
        assert_eq!(run(&b, &isf, Some(4)).rows.len(), 2);
        assert!(run(&b, &isf, Some(65)).rows.is_empty());
        b[0xf000..0xf002].copy_from_slice(&('x' as u16).to_le_bytes());
        let r = run(&b, &isf, None);
        assert!(r.rows.is_empty());
        assert_eq!(r.kernel_identity["truecrypt"]["module_found"], false);
    }
    #[test]
    fn missing_length_pages_and_password_tails_never_become_zero_filled_records() {
        let mut bytes = vec![0xcc; 8192];
        password(&mut bytes, 0, b"Testing");
        password(&mut bytes, 4092, b"Crossing");
        let read = |at: u64, out: &mut [u8]| -> Result<()> {
            ensure!(at + out.len() as u64 <= 4096, "missing page");
            out.copy_from_slice(&bytes[at as usize..at as usize + out.len()]);
            Ok(())
        };
        let r = scan(
            Section {
                start: 0,
                size: 8192,
            },
            5,
            &Job::default(),
            read,
        )
        .unwrap();
        assert_eq!(r.rows, [(4, "Testing".into())]);
        assert_eq!(r.missing_words, 1024);
        assert_eq!(r.missing_records, 1);
        let job = Job::default();
        job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(scan(Section { start: 0, size: 4 }, 5, &job, |_, _| Ok(())).is_err());
    }
    #[test]
    fn analysis_cache_never_reuses_a_different_minimum() -> Result<()> {
        let (bytes, isf) = prepared();
        let dir = tempfile::tempdir()?;
        let image = dir.path().join("image.raw");
        let symbols = dir.path().join("kernel.json");
        std::fs::write(&image, bytes)?;
        std::fs::File::options()
            .write(true)
            .open(&image)?
            .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(60))?;
        std::fs::write(&symbols, serde_json::to_vec(&isf.data)?)?;
        let mut request = Request {
            image: &image,
            symbols: &symbols,
            choice: None,
            plugin: Plugin::WinTruecryptPassphrase,
            cache: dir.path(),
            use_cache: true,
            network: false,
        };
        let mut session = crate::linux::Session::default();
        let Outcome::Ready(first) = crate::analysis::analyze(
            &mut session,
            &request,
            None,
            &Options::default(),
            &Job::default(),
        )?
        else {
            bail!("unexpected symbol choice");
        };
        let options = Options {
            min_length: Some(4),
            ..Default::default()
        };
        let job = Job::default();
        let Outcome::Ready(second) =
            crate::analysis::analyze(&mut session, &request, None, &options, &job)?
        else {
            bail!("unexpected symbol choice");
        };
        assert_eq!(first.rows.len(), 1);
        assert_eq!(second.rows.len(), 2);
        assert!(!job.served_from_cache());
        request.plugin = Plugin::WinPslist;
        let err = crate::analysis::analyze(&mut session, &request, None, &options, &Job::default())
            .err()
            .unwrap();
        assert!(err.to_string().contains("min-length"));
        Ok(())
    }
    #[test]
    fn zero_length_output_limit_is_explicit() {
        let r = scan(
            Section {
                start: 0,
                size: ((HIT_LIMIT + 1) * 4) as u64,
            },
            0,
            &Job::default(),
            |_, b| {
                b.fill(0);
                Ok(())
            },
        )
        .unwrap();
        assert!(r.stopped);
        assert_eq!(r.rows.len(), HIT_LIMIT);
        assert!(r.rows.iter().all(|(_, p)| p.is_empty()));
    }
    #[test]
    fn scan_limits_preserve_prefix_and_mark_truncation() {
        let r = scan(
            Section {
                start: 0,
                size: SCAN_LIMIT + 4,
            },
            65,
            &Job::default(),
            |_, b| {
                b.fill(0);
                Ok(())
            },
        )
        .unwrap();
        assert!(r.stopped);
        assert_eq!(r.length_words, SCAN_LIMIT / 4);
        assert!(r.rows.is_empty());
    }
}
