//! Registry-backed artifacts: scheduled tasks, Amcache inventory and the
//! system certificate stores. Values are decoded in place; nothing is exported.
use super::*;

const TASKS: &str = "Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks";
const AMCACHE: &str = "Root\\InventoryApplicationFile";
const STORES: &[&str] = &[
    "ROOT",
    "CA",
    "My",
    "AuthRoot",
    "Disallowed",
    "TrustedPublisher",
    "TrustedPeople",
];
const CERTIFICATE_PROPERTY: u32 = 0x20;
const FRIENDLY_NAME_PROPERTY: u32 = 0x0b;

fn unhex(text: &str) -> Option<Vec<u8>> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}
fn utf16(bytes: &[u8]) -> String {
    String::from_utf16_lossy(
        &bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect::<Vec<_>>(),
    )
    .trim_end_matches('\0')
    .to_string()
}

/// Exec actions of a TaskCache `Actions` value: (command, arguments,
/// working directory). Non-exec actions (COM handlers, email) are skipped.
pub(super) fn task_actions(bytes: &[u8]) -> Vec<[String; 3]> {
    let mut at = 2; // version
    let string = |at: &mut usize| -> Option<String> {
        let length = u32::from_le_bytes(bytes.get(*at..*at + 4)?.try_into().ok()?) as usize;
        let text = bytes.get(*at + 4..*at + 4 + length)?;
        *at += 4 + length;
        Some(utf16(text))
    };
    let mut out = Vec::new();
    // The context (principal id) precedes the actions.
    if string(&mut at).is_none() {
        return out;
    }
    while let Some(magic) = bytes.get(at..at + 2) {
        at += 2;
        if magic != [0x66, 0x66] {
            break;
        }
        let parsed = (|| {
            string(&mut at)?; // action id
            Some([string(&mut at)?, string(&mut at)?, string(&mut at)?])
        })();
        match parsed {
            Some(action) => out.push(action),
            None => break,
        }
        // Version 3 exec actions end with a 16-bit flag word.
        if bytes.get(..2) == Some(&[3, 0]) {
            at += 2;
        }
    }
    out
}
/// Creation and last-run FILETIMEs of a TaskCache `DynamicInfo` value.
pub(super) fn task_times(bytes: &[u8]) -> Option<(u64, u64)> {
    let word = |at: usize| Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?));
    Some((word(4)?, word(12)?))
}
/// DER certificate and friendly name from a SystemCertificates `Blob`.
pub(super) fn certificate_blob(bytes: &[u8]) -> (Option<&[u8]>, String) {
    let mut at = 0;
    let mut certificate = None;
    let mut name = String::new();
    while let Some(header) = bytes.get(at..at + 12) {
        let id = u32::from_le_bytes(header[..4].try_into().unwrap());
        let length = u32::from_le_bytes(header[8..12].try_into().unwrap()) as usize;
        let Some(data) = bytes.get(at + 12..at + 12 + length) else {
            break;
        };
        match id {
            CERTIFICATE_PROPERTY => certificate = Some(data),
            FRIENDLY_NAME_PROPERTY => name = utf16(data),
            _ => {}
        }
        at += 12 + length;
    }
    (certificate, name)
}

/// A DER element: tag, contents and the bytes that follow it.
fn der(bytes: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *bytes.first()?;
    let first = *bytes.get(1)?;
    let (length, header) = if first & 0x80 == 0 {
        (usize::from(first), 2)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 {
            return None;
        }
        let mut length = 0usize;
        for byte in bytes.get(2..2 + count)? {
            length = length << 8 | usize::from(*byte);
        }
        (length, 2 + count)
    };
    let contents = bytes.get(header..header + length)?;
    Some((tag, contents, &bytes[header + length..]))
}
/// The commonName of an X.509 Name, or its organisation as a fallback.
fn common_name(name: &[u8]) -> String {
    let (mut cn, mut org) = (String::new(), String::new());
    let mut sets = name;
    while let Some((_, set, rest)) = der(sets) {
        sets = rest;
        let Some((_, attribute, _)) = der(set) else {
            continue;
        };
        let Some((_, oid, value)) = der(attribute) else {
            continue;
        };
        let Some((_, text, _)) = der(value) else {
            continue;
        };
        let text = String::from_utf8_lossy(text).into_owned();
        match oid {
            [0x55, 0x04, 0x03] => cn = text,
            [0x55, 0x04, 0x0a] => org = text,
            _ => {}
        }
    }
    if cn.is_empty() { org } else { cn }
}
/// Subject, issuer and validity (as written) of a DER certificate.
pub(super) fn certificate_summary(certificate: &[u8]) -> Option<[String; 4]> {
    let (_, outer, _) = der(certificate)?;
    let (_, tbs, _) = der(outer)?;
    let mut fields = tbs;
    // Optional explicit [0] version.
    if fields.first() == Some(&0xa0) {
        fields = der(fields)?.2;
    }
    let (_, _, rest) = der(fields)?; // serial
    let (_, _, rest) = der(rest)?; // signature algorithm
    let (_, issuer, rest) = der(rest)?;
    let (_, validity, rest) = der(rest)?;
    let (_, subject, _) = der(rest)?;
    let (_, before, after) = der(validity)?;
    let (_, after, _) = der(after)?;
    Some([
        common_name(subject),
        common_name(issuer),
        String::from_utf8_lossy(before).into_owned(),
        String::from_utf8_lossy(after).into_owned(),
    ])
}

/// Entries of an AppCompatCache value: (path, last-modified FILETIME).
/// Windows 8+ entries carry a `00ts`/`10ts` signature; Windows 7 x64 uses a
/// 0xbadc0fee header with fixed 48-byte records pointing into the value.
pub(super) fn shimcache_entries(bytes: &[u8]) -> Vec<(String, u64)> {
    let u16_at = |at: usize| {
        bytes
            .get(at..at + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
    };
    let u32_at = |at: usize| {
        bytes
            .get(at..at + 4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
    };
    let u64_at = |at: usize| {
        bytes
            .get(at..at + 8)
            .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
    };
    let mut out = Vec::new();
    if u32_at(0) == Some(0xbadc_0fee) {
        let count = u32_at(4).unwrap_or(0).min(4096) as usize;
        for i in 0..count {
            let at = 128 + i * 48;
            let (Some(length), Some(offset), Some(time)) =
                (u16_at(at), u64_at(at + 8), u64_at(at + 16))
            else {
                break;
            };
            let Some(path) = bytes.get(offset as usize..offset as usize + usize::from(length))
            else {
                break;
            };
            out.push((utf16(path), time));
        }
        return out;
    }
    // Windows 8+: entries start after a variable header; find the first.
    let Some(mut at) = memchr::memmem::find_iter(bytes, b"0ts")
        .map(|i| i.saturating_sub(1))
        .find(|i| matches!(bytes.get(*i..*i + 4), Some(b"10ts") | Some(b"00ts")))
    else {
        return out;
    };
    while matches!(bytes.get(at..at + 4), Some(b"10ts") | Some(b"00ts")) && out.len() < 4096 {
        let (Some(entry), Some(length)) = (u32_at(at + 8), u16_at(at + 12)) else {
            break;
        };
        let start = at + 14;
        let Some(path) = bytes.get(start..start + usize::from(length)) else {
            break;
        };
        let time = u64_at(start + usize::from(length)).unwrap_or(0);
        out.push((utf16(path), time));
        at += 12 + entry as usize;
    }
    out
}

impl Windows<'_> {
    fn hives_matching(
        &self,
        suffix: &[&str],
        job: &Job,
        r: &mut Results,
    ) -> Result<Vec<(u64, String)>> {
        let hives = self.registry(Plugin::WinHivelist, &Options::default(), job)?;
        if !hives.complete {
            r.complete = false;
            r.diagnostics.extend(hives.diagnostics);
        }
        let mut out = Vec::new();
        for hive in hives.rows {
            let lower = hive[1].to_ascii_lowercase();
            if suffix.iter().any(|s| lower.ends_with(s)) {
                out.push((
                    u64::from_str_radix(hive[0].trim_start_matches("0x"), 16)?,
                    hive[1].clone(),
                ));
            }
        }
        Ok(out)
    }
    fn values(rows: &Results) -> BTreeMap<String, (String, String)> {
        rows.rows
            .iter()
            .filter(|row| row[2] == "Value")
            .map(|row| {
                (
                    row[3].to_ascii_lowercase(),
                    (row[4].clone(), row[5].clone()),
                )
            })
            .collect()
    }
    /// windows.registry.scheduled_tasks: TaskCache entries with decoded actions.
    pub(super) fn scheduled_tasks(&self, job: &Job) -> Result<Results> {
        let mut r = self.result(Plugin::WinScheduledTasks);
        for (hive, _) in self.hives_matching(&["software"], job, &mut r)? {
            let Some(tasks) = self.optional_registry(hive, TASKS, job, &mut r)? else {
                continue;
            };
            for task in tasks.rows.iter().filter(|row| row[2] == "SubKey") {
                job.check()?;
                let key = format!("{TASKS}\\{}", task[3]);
                let Some(entry) = self.optional_registry(hive, &key, job, &mut r)? else {
                    continue;
                };
                let values = Self::values(&entry);
                let path = values.get("path").map(|v| v.1.clone()).unwrap_or_default();
                let (created, last) = values
                    .get("dynamicinfo")
                    .and_then(|v| unhex(&v.1))
                    .and_then(|b| task_times(&b))
                    .map_or((String::new(), String::new()), |(c, l)| {
                        (filetime(c), filetime(l))
                    });
                let actions = values
                    .get("actions")
                    .and_then(|v| unhex(&v.1))
                    .map(|b| task_actions(&b))
                    .unwrap_or_default();
                let actions = if actions.is_empty() {
                    vec![[String::new(), String::new(), String::new()]]
                } else {
                    actions
                };
                for [command, arguments, directory] in actions {
                    r.rows.push(vec![
                        path.clone(),
                        task[3].clone(),
                        command,
                        arguments,
                        directory,
                        created.clone(),
                        last.clone(),
                    ]);
                }
            }
        }
        Ok(r)
    }
    /// windows.registry.shimcache: AppCompatCache of the current ControlSet.
    pub(super) fn shimcache(&self, job: &Job) -> Result<Results> {
        let mut r = self.result(Plugin::WinShimcache);
        for (hive, _) in self.hives_matching(&["system"], job, &mut r)? {
            let Some(select) = self.optional_registry(hive, "Select", job, &mut r)? else {
                continue;
            };
            let Some(current) = Self::values(&select).get("current").map(|v| v.1.clone()) else {
                Self::issue(&mut r, hex(hive), "SYSTEM hive 缺少 Select.Current");
                continue;
            };
            let n = current
                .parse::<u32>()
                .context("Select.Current 不是 DWORD")?;
            ensure!((1..=999).contains(&n), "Select.Current 越界");
            let key = format!("ControlSet{n:03}\\Control\\Session Manager\\AppCompatCache");
            let Some(cache) = self.optional_registry(hive, &key, job, &mut r)? else {
                continue;
            };
            let Some(bytes) = Self::values(&cache)
                .get("appcompatcache")
                .and_then(|v| unhex(&v.1))
            else {
                continue;
            };
            for (index, (path, time)) in shimcache_entries(&bytes).into_iter().enumerate() {
                r.rows.push(vec![index.to_string(), path, filetime(time)]);
            }
        }
        Ok(r)
    }
    /// windows.registry.amcache: InventoryApplicationFile records.
    pub(super) fn amcache(&self, job: &Job) -> Result<Results> {
        let mut r = self.result(Plugin::WinAmcache);
        for (hive, _) in self.hives_matching(&["amcache.hve"], job, &mut r)? {
            let Some(files) = self.optional_registry(hive, AMCACHE, job, &mut r)? else {
                continue;
            };
            for file in files.rows.iter().filter(|row| row[2] == "SubKey") {
                job.check()?;
                let key = format!("{AMCACHE}\\{}", file[3]);
                let Some(entry) = self.optional_registry(hive, &key, job, &mut r)? else {
                    continue;
                };
                let values = Self::values(&entry);
                let get = |name: &str| values.get(name).map(|v| v.1.clone()).unwrap_or_default();
                let sha1 = get("fileid");
                r.rows.push(vec![
                    get("lowercaselongpath"),
                    sha1.strip_prefix("0000").unwrap_or(&sha1).to_string(),
                    get("publisher"),
                    get("version"),
                    get("linkdate"),
                    entry
                        .rows
                        .first()
                        .map(|row| row[6].clone())
                        .unwrap_or_default(),
                ]);
            }
        }
        Ok(r)
    }
    /// windows.registry.certificates: certificates in machine and user stores.
    pub(super) fn certificates(&self, job: &Job) -> Result<Results> {
        let mut r = self.result(Plugin::WinCertificates);
        for (hive, path) in self.hives_matching(&["software", "ntuser.dat"], job, &mut r)? {
            let root = if path.to_ascii_lowercase().ends_with("software") {
                "Microsoft\\SystemCertificates"
            } else {
                "Software\\Microsoft\\SystemCertificates"
            };
            for store in STORES {
                job.check()?;
                let key = format!("{root}\\{store}\\Certificates");
                let Some(certificates) = self.optional_registry(hive, &key, job, &mut r)? else {
                    continue;
                };
                for certificate in certificates.rows.iter().filter(|row| row[2] == "SubKey") {
                    job.check()?;
                    let Some(entry) = self.optional_registry(
                        hive,
                        &format!("{key}\\{}", certificate[3]),
                        job,
                        &mut r,
                    )?
                    else {
                        continue;
                    };
                    let values = Self::values(&entry);
                    let Some(blob) = values.get("blob").and_then(|v| unhex(&v.1)) else {
                        continue;
                    };
                    let (der, friendly) = certificate_blob(&blob);
                    let [subject, issuer, before, after] = der
                        .and_then(certificate_summary)
                        .unwrap_or_else(|| std::array::from_fn(|_| String::new()));
                    r.rows.push(vec![
                        path.clone(),
                        (*store).into(),
                        certificate[3].clone(),
                        friendly,
                        subject,
                        issuer,
                        before,
                        after,
                    ]);
                }
            }
        }
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(text: &str) -> Vec<u8> {
        let mut bytes: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut out = (bytes.len() as u32).to_le_bytes().to_vec();
        out.append(&mut bytes);
        out
    }

    #[test]
    fn task_actions_decode_exec_entries_and_dynamic_times() {
        let mut actions = vec![3, 0];
        actions.extend(wide("Author"));
        actions.extend([0x66, 0x66]);
        actions.extend(wide(""));
        actions.extend(wide("C:\\Windows\\system32\\cmd.exe"));
        actions.extend(wide("/c whoami"));
        actions.extend(wide("C:\\Temp"));
        actions.extend([0, 0]);
        assert_eq!(
            task_actions(&actions),
            [["C:\\Windows\\system32\\cmd.exe", "/c whoami", "C:\\Temp"].map(String::from)]
        );
        // A COM handler action (magic 0x7777) is not an exec action.
        let mut com = vec![3, 0];
        com.extend(wide("Author"));
        com.extend([0x77, 0x77]);
        assert!(task_actions(&com).is_empty());
        let mut dynamic = vec![0u8; 28];
        dynamic[4..12].copy_from_slice(&11u64.to_le_bytes());
        dynamic[12..20].copy_from_slice(&22u64.to_le_bytes());
        assert_eq!(task_times(&dynamic), Some((11, 22)));
        assert_eq!(task_times(&[0; 8]), None);
    }

    #[test]
    fn shimcache_decodes_windows10_and_windows7_layouts() {
        let path = |text: &str| {
            text.encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<u8>>()
        };
        let mut modern = vec![0u8; 0x34];
        modern[0] = 0x34;
        for (name, time) in [("C:\\a.exe", 7u64), ("C:\\b.exe", 9)] {
            let p = path(name);
            let data = 4u32;
            let entry = 2 + p.len() as u32 + 8 + 4 + data;
            modern.extend(b"10ts");
            modern.extend([0; 4]);
            modern.extend(entry.to_le_bytes());
            modern.extend((p.len() as u16).to_le_bytes());
            modern.extend(&p);
            modern.extend(time.to_le_bytes());
            modern.extend(data.to_le_bytes());
            modern.extend([0; 4]);
        }
        assert_eq!(
            shimcache_entries(&modern),
            [("C:\\a.exe".into(), 7), ("C:\\b.exe".into(), 9)]
        );
        let mut legacy = vec![0u8; 128 + 48];
        legacy[..4].copy_from_slice(&0xbadc_0feeu32.to_le_bytes());
        legacy[4..8].copy_from_slice(&1u32.to_le_bytes());
        let p = path("C:\\c.exe");
        legacy[128..130].copy_from_slice(&(p.len() as u16).to_le_bytes());
        legacy[136..144].copy_from_slice(&(176u64).to_le_bytes());
        legacy[144..152].copy_from_slice(&5u64.to_le_bytes());
        legacy.extend(&p);
        assert_eq!(shimcache_entries(&legacy), [("C:\\c.exe".into(), 5)]);
        assert!(shimcache_entries(&[0; 16]).is_empty());
    }

    #[test]
    fn certificate_blobs_and_der_names_are_decoded() {
        // Minimal certificate: issuer CN=Root CA, subject O=Example.
        let name = |oid: u8, text: &[u8]| {
            let mut value = vec![0x0c, text.len() as u8];
            value.extend_from_slice(text);
            let mut attribute = vec![0x06, 3, 0x55, 0x04, oid];
            attribute.extend(value);
            let mut sequence = vec![0x30, attribute.len() as u8];
            sequence.extend(attribute);
            let mut set = vec![0x31, sequence.len() as u8];
            set.extend(sequence);
            let mut name = vec![0x30, set.len() as u8];
            name.extend(set);
            name
        };
        let mut validity = vec![0x17, 13];
        validity.extend(b"200101000000Z");
        validity.extend([0x17, 13]);
        validity.extend(b"300101000000Z");
        let mut tbs = vec![0xa0, 3, 0x02, 1, 2, 0x02, 1, 7, 0x30, 0];
        tbs.extend(name(3, b"Root CA"));
        tbs.extend([0x30, validity.len() as u8]);
        tbs.extend(validity);
        tbs.extend(name(0x0a, b"Example"));
        let mut inner = vec![0x30, tbs.len() as u8];
        inner.extend(tbs);
        let mut certificate = vec![0x30, 0x81, inner.len() as u8];
        certificate.extend(inner);
        assert_eq!(
            certificate_summary(&certificate).unwrap(),
            ["Example", "Root CA", "200101000000Z", "300101000000Z"].map(String::from)
        );
        let mut blob = Vec::new();
        for (id, data) in [
            (
                FRIENDLY_NAME_PROPERTY,
                "Test\0"
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect::<Vec<_>>(),
            ),
            (CERTIFICATE_PROPERTY, certificate.clone()),
        ] {
            blob.extend(id.to_le_bytes());
            blob.extend(1u32.to_le_bytes());
            blob.extend((data.len() as u32).to_le_bytes());
            blob.extend(data);
        }
        let (der, friendly) = certificate_blob(&blob);
        assert_eq!(friendly, "Test");
        assert_eq!(der, Some(certificate.as_slice()));
        assert!(certificate_summary(&[0x30, 0x05, 1]).is_none());
    }
}
