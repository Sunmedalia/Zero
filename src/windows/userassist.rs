//! Twelve-column UserAssist registry view; the seven-column legacy view stays separate.
use super::security::rot13;
use super::*;
use crate::bytes::{Checked as _, JsonKey as _};
use crate::bytes::{le_u32, le_u64};

const PATH: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist";
const NA: &str = "N/A";
mod folders {
    include!("userassist_folders.rs");
}
fn timestamp(ticks: u64) -> String {
    // The pinned renderer intentionally truncates FILETIME to whole seconds.
    let seconds = ticks / 10_000_000;
    if seconds == 0 || seconds > 265_046_774_399 {
        return NA.to_owned();
    }
    crate::report::utc(seconds as i64 - 11_644_473_600)
        .replace(' ', "T")
        .replace("TUTC", "+00:00")
}
fn focused(milliseconds: u32) -> String {
    let millis = u64::from(milliseconds) + 500;
    let seconds = millis / 1000;
    let day = seconds / 86400;
    let day_prefix = match day {
        0 => String::new(),
        1 => "1 day, ".to_owned(),
        _ => format!("{day} days, "),
    };
    let fraction = if millis.is_multiple_of(1000) {
        String::new()
    } else {
        format!(".{:06}", millis % 1000 * 1000)
    };
    format!(
        "{day_prefix}{}:{:02}:{:02}{fraction}",
        seconds % 86400 / 3600,
        seconds % 3600 / 60,
        seconds % 60
    )
}
fn decoded_name(name: &str, modern: bool) -> String {
    let name = rot13(name);
    if modern {
        let guid = name.split('\\').next().unwrap_or("");
        if let Some((_, path)) = folders::FOLDERS.iter().find(|(key, _)| *key == guid) {
            return name.replace(guid, path);
        }
    }
    name
}
/// ID, count, focus count, time focused, last updated, raw bytes.
fn record(bytes: &[u8], modern: Option<bool>) -> [String; 6] {
    let mut fields: [String; 6] = std::array::from_fn(|_| NA.to_owned());
    fields[5] = bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    let minimum = if modern == Some(false) { 16 } else { 72 };
    if modern.is_none() || bytes.len() < minimum {
        return fields;
    }
    let uint = |at| le_u32(bytes, at).unwrap_or_default();
    let at = if modern == Some(true) {
        fields[1] = uint(4).to_string();
        fields[2] = uint(8).to_string();
        fields[3] = focused(uint(12));
        60
    } else {
        fields[0] = uint(0).to_string();
        let count = uint(4);
        fields[1] = if count < 5 { count } else { count - 5 }.to_string();
        8
    };
    fields[4] = timestamp(le_u64(bytes, at).unwrap_or_default());
    fields
}
impl Windows<'_> {
    fn userassist_key_path(
        &self,
        hive: u64,
        mut cell: u32,
        name: &str,
        job: &Job,
    ) -> Result<String> {
        let root = self.registry_root(hive)?;
        let mut parts = Vec::new();
        let mut seen = HashSet::new();
        while cell != root {
            job.check()?;
            ensure!(
                seen.len() < 512 && seen.insert(cell),
                "UserAssist 键 Parent 循环或超限"
            );
            let node = self.cell(hive, cell)?;
            parts.push(self.key_name(&node)?);
            cell = u32::try_from(objects::physical_number(
                self.vm.isf,
                &node,
                "_CM_KEY_NODE",
                "Parent",
            )?)?;
        }
        parts.push(name.rsplit('\\').next().unwrap_or(name).to_owned());
        parts.reverse();
        Ok(parts.join("\\"))
    }
    pub(super) fn userassist_count(
        &self,
        hive: u64,
        name: &str,
        count: u32,
        modern: Option<bool>,
        r: &mut Results,
        job: &Job,
    ) -> Result<()> {
        let hhive = self.field(hive, "_CMHIVE", "Hive")?;
        let node = self.cell(hhive, count)?;
        let path = self.userassist_key_path(hhive, count, name, job)?;
        let time = timestamp(objects::physical_number(
            self.vm.isf,
            &node,
            "_CM_KEY_NODE",
            "LastWriteTime",
        )?);
        let row = |kind: &str, value_name: String, data: [String; 6]| {
            let mut row = vec![
                hex(hive),
                name.to_owned(),
                path.clone(),
                time.clone(),
                kind.to_owned(),
                value_name,
            ];
            row.extend(data);
            row
        };
        ensure!(r.rows.len() < MAX_OBJECTS, "UserAssist 记录超过上限");
        r.rows.push(row(
            "Key",
            NA.to_owned(),
            std::array::from_fn(|_| NA.to_owned()),
        ));
        match self.subkeys(hhive, &node, job) {
            Ok(children) => {
                for child in children {
                    job.check()?;
                    ensure!(r.rows.len() < MAX_OBJECTS, "UserAssist 记录超过上限");
                    let name = match self
                        .cell(hhive, child)
                        .and_then(|node| self.key_name(&node))
                    {
                        Ok(name) => name,
                        Err(error) => {
                            Self::issue(r, format!("UserAssist subkey {child:#x}"), error);
                            NA.to_owned()
                        }
                    };
                    r.rows
                        .push(row("Subkey", name, std::array::from_fn(|_| NA.to_owned())));
                }
            }
            Err(error) => Self::issue(r, "UserAssist subkeys", error),
        }
        for index in self.value_indices(hhive, count)? {
            job.check()?;
            ensure!(r.rows.len() < MAX_OBJECTS, "UserAssist 记录超过上限");
            if index == 0 {
                continue;
            }
            // A list entry is not a recovered value until its vk cell is validated.
            match self.cell(hhive, index) {
                Ok(cell) if cell.starts_with(b"vk") => {}
                Ok(_) => {
                    Self::issue(r, format!("UserAssist value cell {index:#x}"), "非 vk cell");
                    continue;
                }
                Err(error) => {
                    Self::issue(r, format!("UserAssist value cell {index:#x}"), error);
                    continue;
                }
            }
            let name = match self.value_name(hhive, index) {
                Ok(name) => decoded_name(&name, modern == Some(true)),
                Err(error) => {
                    Self::issue(r, format!("UserAssist value name {index:#x}"), error);
                    NA.to_owned()
                }
            };
            let data = match self.value_bytes(hhive, index, job) {
                Ok((_, ty, bytes)) => {
                    if ty == 0 {
                        record(&[], modern)
                    } else if matches!(ty, 4 | 5 | 11) {
                        Self::issue(
                            r,
                            format!("UserAssist value {index:#x}"),
                            "非字节型注册表值，无法解码执行记录",
                        );
                        std::array::from_fn(|_| NA.to_owned())
                    } else {
                        record(&bytes, modern)
                    }
                }
                Err(error) => {
                    Self::issue(r, format!("UserAssist value {index:#x}"), error);
                    std::array::from_fn(|_| NA.to_owned())
                }
            };
            r.rows.push(row("Value", name, data));
        }
        Ok(())
    }
    pub(super) fn userassist_canonical(&self, options: &Options, job: &Job) -> Result<Results> {
        ensure!(
            matches!(
                Architecture::from_isf(self.vm.isf)?,
                Architecture::X86 | Architecture::X64
            ),
            "UserAssist 标准插件仅支持 Intel x86/x64"
        );
        let mut r = self.result(Plugin::WinUserAssistV4);
        let modern = self.vm.isf.data.key("user_types")["_KUSER_SHARED_DATA"]
            .as_object()
            .map(|_| self.vm.isf.field("_KUSER_SHARED_DATA", "CookiePad").is_ok());
        let hives = if let Some(address) = options.hive {
            let hhive = self.field(address, "_CMHIVE", "Hive")?;
            ensure!(
                self.number(hhive, "_HHIVE", "Signature")? == 0xbee0_bee0,
                "UserAssist hive Signature 无效"
            );
            let mut selected = self.result(Plugin::WinHivelist);
            let mut name = "[NONAME]".to_owned();
            for field in ["FileFullPath", "FileUserName", "HiveRootPath"] {
                if self.vm.isf.field("_CMHIVE", field).is_err() {
                    continue;
                }
                match self.vm.unicode(self.field(address, "_CMHIVE", field)?) {
                    Ok(value) if !value.is_empty() => {
                        name = value;
                        break;
                    }
                    Ok(_) => {}
                    Err(error) => {
                        Self::issue(&mut selected, format!("{address:#x} {field}"), error)
                    }
                }
            }
            selected.rows.push(vec![hex(address), name]);
            selected
        } else {
            self.registry(Plugin::WinHivelist, &Options::default(), job)?
        };
        r.complete = hives.complete;
        r.diagnostics = hives.diagnostics;
        for hive in hives.rows {
            job.check()?;
            let address = u64::from_str_radix(hive.at(0)?.trim_start_matches("0x"), 16)?;
            if let Some(selected) = options.hive {
                if address != selected {
                    continue;
                }
            } else if !hive.at(1)?.to_ascii_lowercase().contains("ntuser.dat") {
                continue;
            }
            let hhive = self.field(address, "_CMHIVE", "Hive")?;
            let index = match self
                .registry_root(hhive)
                .and_then(|root| self.registry_index_partial(hhive, root, PATH, job, &mut r, false))
            {
                Ok(index) => index,
                Err(error) => {
                    job.check()?;
                    if !error.to_string().starts_with("注册表键不存在:") {
                        Self::issue(&mut r, format!("UserAssist hive {address:#x}"), error);
                    }
                    continue;
                }
            };
            let scan = (|| -> Result<()> {
                let root = self.cell(hhive, index)?;
                for guid in self.subkeys(hhive, &root, job)? {
                    job.check()?;
                    let read = (|| -> Result<()> {
                        let node = self.cell(hhive, guid)?;
                        for count in self.subkeys(hhive, &node, job)? {
                            job.check()?;
                            if let Err(error) = self.userassist_count(
                                address,
                                hive.at(1)?,
                                count,
                                modern,
                                &mut r,
                                job,
                            ) {
                                job.check()?;
                                Self::issue(
                                    &mut r,
                                    format!("UserAssist hive {address:#x} key {count:#x}"),
                                    error,
                                );
                            }
                        }
                        Ok(())
                    })();
                    if let Err(error) = read {
                        job.check()?;
                        Self::issue(&mut r, format!("UserAssist GUID {guid:#x}"), error);
                    }
                }
                Ok(())
            })();
            if let Err(error) = scan {
                job.check()?;
                Self::issue(&mut r, format!("UserAssist hive {address:#x}"), error);
            }
        }
        job.check()?;
        *r.kernel_identity.key_mut("userassist")? = serde_json::json!({"layout":match modern {Some(true)=>"win7+",Some(false)=>"xp",None=>"raw-only"},"source":"loaded hives; absent bytes are never zero-filled"});
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn both_layouts_short_raw_unknown_and_trailing_data() {
        let mut xp = vec![0; 16];
        xp[..4].copy_from_slice(&9u32.to_le_bytes());
        for count in [0u32, 1, 4, 5, 6, 100] {
            xp[4..8].copy_from_slice(&count.to_le_bytes());
            let r = record(&xp, Some(false));
            assert_eq!(r[0], "9");
            assert_eq!(r[1], if count < 5 { count } else { count - 5 }.to_string());
            assert_eq!(r[2], NA);
        }
        let mut modern = vec![0; 80];
        modern[4..8].copy_from_slice(&7u32.to_le_bytes());
        modern[8..12].copy_from_slice(&3u32.to_le_bytes());
        modern[12..16].copy_from_slice(&1000u32.to_le_bytes());
        let r = record(&modern, Some(true));
        assert_eq!(&r[..5], &[NA, "7", "3", "0:00:01.500000", NA]);
        assert_eq!(r[5].split(' ').count(), 80);
        let r = record(&modern[..8], Some(true));
        assert!(r[..5].iter().all(|s| s == NA));
        assert_ne!(r[5], NA);
        assert!(record(&modern, None)[..5].iter().all(|s| s == NA));
    }
    #[test]
    fn focused_duration_and_filetime_boundaries() {
        assert_eq!(focused(0), "0:00:00.500000");
        assert_eq!(focused(500), "0:00:01");
        assert_eq!(focused(86_399_500), "1 day, 0:00:00");
        assert_eq!(focused(u32::MAX), "49 days, 17:02:47.795000");
        assert_eq!(timestamp(0), NA);
        assert_eq!(
            timestamp(116_444_736_009_999_999),
            "1970-01-01T00:00:00+00:00"
        );
        assert_eq!(timestamp(u64::MAX), NA);
    }
    #[test]
    fn rot13_known_folders_are_exact_case_and_modern_only() {
        let original = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\cmd.exe";
        let encoded = rot13(original);
        assert_eq!(decoded_name(&encoded, true), "%windir%\\system32\\cmd.exe");
        assert_eq!(decoded_name(&encoded, false), original);
        let unknown = "{00000000-0000-0000-0000-000000000000}\\abc.exe";
        assert_eq!(decoded_name(&rot13(unknown), true), unknown);
    }
}
