//! External decimal strings output, attributed using the fixed Strings mapping contract.
use super::*;
use crate::bytes::{Checked as _, JsonKey as _};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::Path;
const INPUT_LIMIT: u64 = 64 * 1024 * 1024;
const LINE_LIMIT: usize = 1024 * 1024;
struct Entry {
    address: u64,
    text: String,
}
fn word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}
/// Byte-regex semantics of ^\W*([0-9]+)\W*(\w[\w\W]+)\n?.
/// In particular, group two keeps the newline, and digit-only lines backtrack.
fn parse_line(bytes: &[u8]) -> Option<Entry> {
    let start = bytes.iter().position(|b| word(*b))?;
    if !bytes.get(start)?.is_ascii_digit() {
        return None;
    }
    let end = start
        + bytes
            .get(start..)?
            .iter()
            .take_while(|b| b.is_ascii_digit())
            .count();
    for cut in (start + 1..=end).rev() {
        let mut at = cut;
        while at < bytes.len() && !word(*bytes.get(at)?) {
            at += 1;
        }
        if at.checked_add(1)? >= bytes.len() {
            continue;
        }
        let address = bytes.get(start..cut)?.iter().try_fold(0u64, |value, b| {
            value.checked_mul(10)?.checked_add(u64::from(b - b'0'))
        })?;
        let text = bytes.get(at..)?.iter().map(|b| char::from(*b)).collect();
        return Some(Entry { address, text });
    }
    None
}
struct Input {
    rows: Vec<Entry>,
    stamp: String,
    sha256: String,
    invalid: usize,
}
impl Input {
    fn open(path: &Path, job: &Job) -> Result<Self> {
        let mut file = std::fs::File::open(path)
            .with_context(|| format!("读取字符串文件 {}", path.display()))?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file() && metadata.len() <= INPUT_LIMIT,
            "字符串文件必须是普通文件且不超过 64 MiB"
        );
        let stamp = crate::image::metadata_stamp(&metadata)?;
        let mut bytes = Vec::new();
        let mut chunk = [0; 65536];
        loop {
            job.check()?;
            let n = file.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            ensure!(
                bytes.len() + n <= usize::try_from(INPUT_LIMIT)?,
                "字符串文件读取时超过 64 MiB"
            );
            bytes.extend_from_slice(chunk.at(..n)?);
        }
        ensure!(
            stamp == crate::image::metadata_stamp(&file.metadata()?)?,
            "字符串文件读取时已改变"
        );
        let mut rows = Vec::new();
        let mut invalid = 0;
        for line in bytes.split_inclusive(|b| *b == b'\n') {
            job.check()?;
            ensure!(line.len() <= LINE_LIMIT, "字符串行超过 1 MiB");
            ensure!(rows.len() < MAX_OBJECTS, "字符串记录超过上限");
            if let Some(entry) = parse_line(line) {
                rows.push(entry);
            } else {
                invalid += 1;
            }
        }
        let input = Self {
            rows,
            stamp,
            sha256: format!("{:x}", sha2::Sha256::digest(&bytes)),
            invalid,
        };
        input.validate(path)?;
        Ok(input)
    }
    fn validate(&self, path: &Path) -> Result<()> {
        ensure!(
            self.stamp == crate::image::metadata_stamp(&std::fs::metadata(path)?)?,
            "字符串文件在分析时已改变"
        );
        Ok(())
    }
}
/// Ordered output for the reference's unordered set of (owner, address) members.
type Owners = BTreeMap<u64, BTreeSet<(String, u64)>>;
fn add_owners(
    targets: &BTreeSet<u64>,
    owners: &mut Owners,
    maps: &[memmap::Mapping],
    process: Option<u64>,
    count: &mut usize,
    job: &Job,
) -> Result<()> {
    for map in maps {
        job.check()?;
        // The fixed reference ignores the mapping's backing-layer label.
        if let Some(pid) = process {
            // Fixed reference keys process records by virtual page, and stores physical start.
            let key = map.virtual_start >> 12;
            if targets.contains(&key) {
                let set = owners.entry(key).or_default();
                if set.insert((format!("Process {pid}"), map.physical_start)) {
                    *count += 1;
                }
            }
        } else {
            let end = map
                .physical_start
                .checked_add(map.size)
                .context("映射范围溢出")?;
            let end_page = (end >> 12) + u64::from(end & 4095 != 0);
            for key in targets.range((map.physical_start >> 12)..end_page) {
                job.check()?;
                let set = owners.entry(*key).or_default();
                // Every physical page in the contiguous mapping keeps the same virtual start.
                if set.insert(("kernel".into(), map.virtual_start)) {
                    *count += 1;
                }
                ensure!(*count <= MAX_OBJECTS, "字符串归属成员超过上限");
            }
        }
        ensure!(*count <= MAX_OBJECTS, "字符串归属成员超过上限");
    }
    Ok(())
}
fn owner_text(owners: Option<&BTreeSet<(String, u64)>>) -> String {
    match owners {
        Some(members) if !members.is_empty() => members
            .iter()
            .map(|(name, address)| format!("{name}:{address:#x}"))
            .collect::<Vec<_>>()
            .join(", "),
        _ => "FREE MEMORY".into(),
    }
}
impl Windows<'_> {
    pub(super) fn strings(&self, options: &Options, job: &Job) -> Result<Results> {
        ensure!(
            matches!(
                Architecture::from_isf(self.vm.isf)?,
                Architecture::X86 | Architecture::X64
            ),
            "Strings 仅支持 Intel x86/x64"
        );
        let path = options
            .strings_file
            .as_deref()
            .context("Strings 需要 --strings-file")?;
        let input = Input::open(path, job)?;
        let mut result = self.result(Plugin::WinStrings);
        if input.invalid > 0 {
            Self::issue(
                &mut result,
                "strings input",
                format!("跳过 {} 行无法识别的内容", input.invalid),
            );
        }
        let targets = input
            .rows
            .iter()
            .map(|r| r.address >> 12)
            .collect::<BTreeSet<_>>();
        let mut owners = Owners::new();
        let mut count = 0;
        if !targets.is_empty() {
            let (maps, diagnostics) = memmap::mappings(&self.vm, job)?;
            for diagnostic in diagnostics {
                Self::issue(&mut result, "kernel", diagnostic);
            }
            add_owners(&targets, &mut owners, &maps, None, &mut count, job)?;
            let (processes, diagnostics) = self.processes_partial(job)?;
            result.diagnostics.extend(diagnostics);
            let pids: HashSet<_> = options
                .pids
                .iter()
                .copied()
                .chain(options.pid)
                .map(u64::from)
                .collect();
            for process in processes
                .iter()
                .filter(|p| pids.is_empty() || pids.contains(&p.pid))
            {
                job.check()?;
                job.report(format!("Strings: 映射进程 {}", process.pid));
                let vm = match self.process_memory(process) {
                    Ok(vm) => vm,
                    Err(e) => {
                        Self::issue(&mut result, format!("PID {}", process.pid), e);
                        continue;
                    }
                };
                let (maps, diagnostics) = memmap::mappings(&vm, job)?;
                for diagnostic in diagnostics {
                    Self::issue(&mut result, format!("PID {}", process.pid), diagnostic);
                }
                add_owners(
                    &targets,
                    &mut owners,
                    &maps,
                    Some(process.pid),
                    &mut count,
                    job,
                )?;
            }
        }
        if !result.diagnostics.is_empty() {
            result.complete = false;
        }
        for entry in &input.rows {
            job.check()?;
            result.rows.push(vec![
                entry.text.clone(),
                format!("{:#x}", entry.address),
                owner_text(owners.get(&(entry.address >> 12))),
            ]);
        }
        input.validate(path)?;
        *result.kernel_identity.key_mut("strings_input")? = serde_json::json!({
            "path":path.display().to_string(),"sha256":input.sha256,"invalid_lines":input.invalid,
            "records":input.rows.len(),"queried_pages":targets.len(),"owner_members":count,
            "mapping_contract":"pinned v2.28.2: kernel physical keys, process virtual keys",
            "member_order":"sorted; reference members are unordered"
        });
        Ok(result)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn decimal_parser_retains_newlines_latin1_and_reference_backtracking() {
        let r = parse_line(b"  4097 : hello!\xff\r\n").unwrap();
        assert_eq!(r.address, 4097);
        assert_eq!(r.text, "hello!ÿ\r\n");
        let r = parse_line(b"1234\n").unwrap();
        assert_eq!(r.address, 123);
        assert_eq!(r.text, "4\n");
        assert!(parse_line(b"abc 1234").is_none());
        let r = parse_line(b"123 x").unwrap();
        assert_eq!(r.address, 12);
        assert_eq!(r.text, "3 x");
        assert!(parse_line(b"184467440737095516160 text\n").is_none());
        assert!(parse_line(b"  - garbage").is_none());
    }
    #[test]
    fn kernel_and_process_domains_follow_reference_even_for_contiguous_ranges() {
        let maps = [memmap::Mapping {
            virtual_start: 0x10000,
            physical_start: 0x3000,
            size: 8192,
            backing: memmap::Backing::Physical,
        }];
        let targets = [3, 4, 16, 17].into_iter().collect();
        let mut owners = Owners::new();
        let mut n = 0;
        add_owners(&targets, &mut owners, &maps, None, &mut n, &Job::default()).unwrap();
        add_owners(
            &targets,
            &mut owners,
            &maps,
            Some(42),
            &mut n,
            &Job::default(),
        )
        .unwrap();
        assert_eq!(owner_text(owners.get(&3)), "kernel:0x10000");
        assert_eq!(owner_text(owners.get(&4)), "kernel:0x10000");
        assert_eq!(owner_text(owners.get(&16)), "Process 42:0x3000");
        assert_eq!(owner_text(owners.get(&17)), "FREE MEMORY");
        assert_eq!(n, 3);
        let job = Job::default();
        job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(add_owners(&targets, &mut owners, &maps, None, &mut n, &job).is_err());
    }
    #[test]
    fn pagefile_layer_offsets_follow_the_same_reference_key_rule() {
        let maps = [memmap::Mapping {
            virtual_start: 0x10000,
            physical_start: 0x3000,
            size: 4096,
            backing: memmap::Backing::Pagefile(2),
        }];
        let targets = [3, 16].into_iter().collect();
        let mut owners = Owners::new();
        let mut n = 0;
        add_owners(&targets, &mut owners, &maps, None, &mut n, &Job::default()).unwrap();
        add_owners(
            &targets,
            &mut owners,
            &maps,
            Some(9),
            &mut n,
            &Job::default(),
        )
        .unwrap();
        assert_eq!(owner_text(owners.get(&3)), "kernel:0x10000");
        assert_eq!(owner_text(owners.get(&16)), "Process 9:0x3000");
    }
    #[test]
    fn analysis_does_not_reuse_results_after_the_strings_file_changes() -> Result<()> {
        use super::super::tests::fixture;
        let (bytes, isf) = fixture();
        let dir = tempfile::tempdir()?;
        let image = dir.path().join("image.raw");
        let symbols = dir.path().join("kernel.json");
        let strings = dir.path().join("strings.txt");
        std::fs::write(&image, bytes)?;
        std::fs::File::options()
            .write(true)
            .open(&image)?
            .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(60))?;
        std::fs::write(&symbols, serde_json::to_vec(&isf.data)?)?;
        let request = Request {
            image: &image,
            symbols: &symbols,
            choice: None,
            plugin: Plugin::WinStrings,
            cache: dir.path(),
            use_cache: true,
            network: false,
        };
        let options = Options {
            strings_file: Some(strings.clone()),
            pids: vec![4],
            ..Default::default()
        };
        let mut session = crate::linux::Session::default();
        std::fs::write(&strings, b"32768 first\n")?;
        let Outcome::Ready(first) =
            crate::analysis::analyze(&mut session, &request, None, &options, &Job::default())?
        else {
            bail!("unexpected symbol choice");
        };
        std::fs::write(&strings, b"32768 second\n")?;
        let job = Job::default();
        let Outcome::Ready(second) =
            crate::analysis::analyze(&mut session, &request, None, &options, &job)?
        else {
            bail!("unexpected symbol choice");
        };
        assert_eq!(first.rows[0][0], "first\n");
        assert_eq!(second.rows[0][0], "second\n");
        assert_ne!(
            first.kernel_identity["strings_input"]["sha256"],
            second.kernel_identity["strings_input"]["sha256"]
        );
        assert!(!job.served_from_cache());
        Ok(())
    }
    #[test]
    fn external_file_changes_duplicates_and_bad_lines_are_explicit() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        use std::io::Write;
        f.write_all(b"4096 one\ninvalid\n4096 one\n").unwrap();
        let i = Input::open(f.path(), &Job::default()).unwrap();
        assert_eq!(i.rows.len(), 2);
        assert_eq!(i.invalid, 1);
        assert_eq!(i.rows[0].text, i.rows[1].text);
        f.write_all(b"4096 two\n").unwrap();
        assert!(i.validate(f.path()).is_err());
    }
}
