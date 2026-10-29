//! Canonical Amcache records. Legacy six-column inventory remains separate.
use super::*;
use std::collections::BTreeMap;

const NA: &str = "N/A";
type Values = BTreeMap<String, (u32, Vec<u8>)>;
#[derive(Clone, Copy)]
pub(super) enum Layout {
    Driver,
    Program,
    File,
    Application,
    ApplicationFile,
}
fn wanted(layout: Layout, name: &str) -> bool {
    let keys: &[&str] = match layout {
        Layout::Driver => &[
            "DriverId",
            "DriverName",
            "DriverCompany",
            "Product",
            "Service",
            "DriverTimeStamp",
        ],
        Layout::Program => &["0", "1", "2", "a"],
        Layout::File => &["100", "101", "0", "1", "11", "12", "15", "17", "f"],
        Layout::Application => &["Name", "Publisher", "RootDirPath", "Version"],
        Layout::ApplicationFile => &[
            "FileId",
            "LowerCaseLongPath",
            "ProductName",
            "ProductVersion",
            "ProgramId",
            "Publisher",
        ],
    };
    keys.contains(&name)
}
fn text(values: &Values, key: &str) -> Option<String> {
    let (ty, bytes) = values.get(key)?;
    if matches!(ty, 4 | 5 | 11) {
        return None;
    }
    let bytes = if *ty == 0 { &[][..] } else { bytes.as_slice() };
    let mut units: Vec<_> = bytes
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();
    if bytes.len() % 2 != 0 {
        units.push(0xfffd);
    }
    Some(
        String::from_utf16_lossy(&units)
            .trim_end_matches('\0')
            .to_owned(),
    )
}
fn integer(values: &Values, key: &str) -> Option<u64> {
    let (ty, bytes) = values.get(key)?;
    match (*ty, bytes.as_slice()) {
        (4, b) if b.len() == 4 => Some(u32::from_le_bytes(b.try_into().ok()?) as u64),
        (5, b) if b.len() == 4 => Some(u32::from_be_bytes(b.try_into().ok()?) as u64),
        (11, b) if b.len() == 8 => Some(u64::from_le_bytes(b.try_into().ok()?)),
        _ => None,
    }
}
fn utc(seconds: i64) -> String {
    if !(-62_135_596_800..=253_402_300_799).contains(&seconds) {
        return NA.to_owned();
    }
    crate::report::utc(seconds)
        .replace(' ', "T")
        .replace("TUTC", "+00:00")
}
fn filetime(ticks: u64) -> String {
    if ticks / 10_000_000 == 0 {
        return NA.to_owned();
    }
    let seconds = ticks / 10_000_000;
    if seconds > 265_046_774_399 {
        return NA.to_owned();
    }
    utc(seconds as i64 - 11_644_473_600)
}
fn epoch(values: &Values, key: &str) -> String {
    integer(values, key)
        .and_then(|v| i64::try_from(v).ok())
        .map(utc)
        .unwrap_or_else(|| NA.to_owned())
}
fn row(layout: Layout, name: &str, written: u64, values: &Values) -> (String, Vec<String>) {
    let mut r = vec![NA.to_owned(); 11];
    let get = |key| text(values, key).unwrap_or_else(|| NA.to_owned());
    let mut program = String::new();
    r[3] = filetime(written);
    match layout {
        Layout::Driver => {
            r[0] = "Driver".to_owned();
            if name.contains('/') {
                r[1] = name.to_owned();
                r[7] = get("DriverId");
            } else {
                r[1] = get("DriverName");
                r[7] = name.to_owned();
            }
            r[2] = get("DriverCompany");
            r[6] = epoch(values, "DriverTimeStamp");
            r[8] = get("Service");
            r[9] = get("Product");
        }
        Layout::Program | Layout::Application => {
            r[0] = "Program".to_owned();
            program = name.trim().trim_matches('\0').to_owned();
            if matches!(layout, Layout::Program) {
                r[2] = get("2");
                r[5] = epoch(values, "a");
                r[9] = get("0");
                r[10] = get("1");
            } else {
                r[1] = get("RootDirPath");
                r[2] = get("Publisher");
                r[9] = text(values, "Name").unwrap_or_else(|| "UNKNOWN".to_owned());
                r[10] = get("Version");
                // Pinned v2.28.2's string-date helper rejects all decoded types.
                // Keep InstallDate absent, explicitly documented as a reference limitation.
            }
        }
        Layout::File => {
            r[0] = "File".to_owned();
            program = text(values, "100").unwrap_or_default();
            r[1] = get("15");
            r[2] = get("1");
            for (at, key) in [(3, "11"), (4, "17"), (5, "12")] {
                r[at] = integer(values, key)
                    .map(filetime)
                    .unwrap_or_else(|| NA.to_owned());
            }
            r[6] = epoch(values, "f");
            r[7] = get("101");
            r[9] = get("0");
        }
        Layout::ApplicationFile => {
            r[0] = "File".to_owned();
            program = text(values, "ProgramId").unwrap_or_default();
            r[1] = get("LowerCaseLongPath");
            r[2] = get("Publisher");
            r[7] = get("FileId");
            r[9] = get("ProductName");
            r[10] = get("ProductVersion");
            // LinkDate has the same pinned string-date limitation as InstallDate.
        }
    }
    if r[7] != NA {
        r[7] = r[7].trim_start_matches('0').to_owned();
    }
    (program, r)
}
impl Windows<'_> {
    fn amcache_children(&self, hive: u64, index: u32, job: &Job) -> Result<Vec<u32>> {
        self.subkeys(hive, &self.cell(hive, index)?, job)
    }
    pub(super) fn amcache_records(
        &self,
        hive: u64,
        path: &str,
        layout: Layout,
        job: &Job,
        r: &mut Results,
    ) -> Result<Vec<(String, Vec<String>)>> {
        let root = self.registry_root(hive)?;
        let index = match self.registry_index_partial(hive, root, path, job, r, false) {
            Ok(index) => index,
            Err(e) if e.to_string().starts_with("注册表键不存在:") => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut children = self.amcache_children(hive, index, job)?;
        if matches!(layout, Layout::File) {
            let mut nested = Vec::new();
            for child in children {
                job.check()?;
                match self.amcache_children(hive, child, job) {
                    Ok(items) => {
                        ensure!(
                            nested.len() + items.len() <= MAX_OBJECTS,
                            "Amcache 子键超过上限"
                        );
                        nested.extend(items);
                    }
                    Err(e) => Self::issue(r, format!("Amcache volume {child:#x}"), e),
                }
            }
            children = nested;
        }
        let mut records = Vec::new();
        for child in children {
            job.check()?;
            let read = (|| -> Result<_> {
                let node = self.cell(hive, child)?;
                let name = self.key_name(&node)?;
                let written =
                    objects::physical_number(self.vm.isf, &node, "_CM_KEY_NODE", "LastWriteTime")?;
                let mut values = Values::new();
                for index in self.value_indices(hive, child)? {
                    job.check()?;
                    if index == 0 {
                        continue;
                    }
                    match self.value_name(hive, index) {
                        Ok(name) if wanted(layout, &name) => {}
                        Ok(_) => continue,
                        Err(e) => {
                            Self::issue(r, format!("Amcache value name {index:#x}"), e);
                            continue;
                        }
                    }
                    match self.value_bytes(hive, index, job) {
                        Ok((name, ty, bytes)) => {
                            values.insert(name, (ty, bytes));
                        }
                        Err(e) => Self::issue(r, format!("Amcache value {index:#x}"), e),
                    }
                }
                Ok(row(layout, &name, written, &values))
            })();
            match read {
                Ok(record) => {
                    ensure!(records.len() < MAX_OBJECTS, "Amcache 记录超过上限");
                    records.push(record);
                }
                Err(e) => {
                    job.check()?;
                    Self::issue(r, format!("Amcache key {child:#x}"), e);
                }
            }
        }
        Ok(records)
    }
    pub(super) fn amcache_canonical(&self, job: &Job) -> Result<Results> {
        ensure!(
            matches!(
                Architecture::from_isf(self.vm.isf)?,
                Architecture::X86 | Architecture::X64
            ),
            "Amcache 标准插件仅支持 Intel x86/x64"
        );
        let mut r = self.result(Plugin::WinAmcacheV4);
        let hives = self.registry(Plugin::WinHivelist, &Options::default(), job)?;
        r.complete = hives.complete;
        r.diagnostics = hives.diagnostics;
        let Some(hive) = hives
            .rows
            .iter()
            .find(|h| h[1].to_ascii_lowercase().contains("amcache"))
        else {
            return Ok(r);
        };
        let address = u64::from_str_radix(hive[0].trim_start_matches("0x"), 16)?;
        let hive = self.field(address, "_CMHIVE", "Hive")?;
        let mut read = |path, layout| -> Result<_> {
            match self.amcache_records(hive, path, layout, job, &mut r) {
                Ok(rows) => Ok(rows),
                Err(e) => {
                    job.check()?;
                    Self::issue(&mut r, path, e);
                    Ok(Vec::new())
                }
            }
        };
        let drivers = read("Root\\InventoryDriverBinary", Layout::Driver)?;
        let old_programs = read("Root\\Programs", Layout::Program)?;
        let old_files = read("Root\\File", Layout::File)?;
        let programs = read("Root\\InventoryApplication", Layout::Application)?;
        let files = read("Root\\InventoryApplicationFile", Layout::ApplicationFile)?;
        let assembled = (|| -> Result<()> {
            r.rows.extend(drivers.into_iter().map(|(_, row)| row));
            for (programs, mut files) in [(old_programs, old_files), (programs, files)] {
                // Preserve dictionary insertion order with logarithmic ID lookup.
                let mut positions = BTreeMap::new();
                let mut grouped: Vec<Option<Vec<String>>> = Vec::new();
                for (id, row) in programs {
                    job.check()?;
                    let at = *positions.entry(id).or_insert_with(|| {
                        grouped.push(None);
                        grouped.len() - 1
                    });
                    grouped[at] = Some(row);
                }
                files.sort_by(|a, b| a.0.cmp(&b.0));
                for (id, row) in files {
                    job.check()?;
                    let id = id.trim().trim_matches('\0');
                    if let Some(at) = positions.remove(id) {
                        ensure!(r.rows.len() < MAX_OBJECTS, "Amcache 输出超过上限");
                        r.rows.push(grouped[at].take().unwrap());
                    }
                    ensure!(r.rows.len() < MAX_OBJECTS, "Amcache 输出超过上限");
                    r.rows.push(row);
                }
                for row in grouped.into_iter().flatten() {
                    job.check()?;
                    ensure!(r.rows.len() < MAX_OBJECTS, "Amcache 输出超过上限");
                    r.rows.push(row);
                }
            }
            Ok(())
        })();
        if let Err(e) = assembled {
            job.check()?;
            Self::issue(&mut r, "Amcache output", e);
        }
        Ok(r)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn string(v: &mut Values, key: &str, value: &str) {
        v.insert(
            key.to_owned(),
            (1, value.encode_utf16().flat_map(u16::to_le_bytes).collect()),
        );
    }
    #[test]
    fn layouts_decode_exact_types_and_preserve_absence() {
        let mut v = Values::new();
        string(&mut v, "FileId", "000000123");
        string(&mut v, "LowerCaseLongPath", " a\0b \0\0");
        string(&mut v, "LinkDate", "01/01/2020 12:00:00");
        let (_, r) = row(Layout::ApplicationFile, "x", 0, &v);
        assert_eq!(r[1], " a\0b ");
        assert_eq!(r[7], "123");
        assert_eq!(r[6], NA);
        let (_, r) = row(Layout::Application, " \0id\0 ", 0, &v);
        assert_eq!(r[9], "UNKNOWN");
        assert_eq!(r[5], NA);
        string(&mut v, "Name", "");
        assert_eq!(row(Layout::Application, "", 0, &v).1[9], "");
        v.insert("f".to_owned(), (4, 1u32.to_le_bytes().to_vec()));
        v.insert(
            "11".to_owned(),
            (11, 116444736010000000u64.to_le_bytes().to_vec()),
        );
        let (_, r) = row(Layout::File, "", 0, &v);
        assert_eq!(r[3], "1970-01-01T00:00:01+00:00");
        assert_eq!(r[6], r[3]);
        assert_eq!(r[10], NA);
        assert!(text(&v, "f").is_none());
        assert_eq!(integer(&v, "FileId"), None);
        let (_, r) = row(Layout::Driver, "000000abc", 0, &v);
        assert_eq!(r[7], "abc");
        string(&mut v, "DriverId", "000000def");
        let (_, r) = row(Layout::Driver, "dir/driver", 0, &v);
        assert_eq!(r[1], "dir/driver");
        assert_eq!(r[7], "def");
    }
    #[test]
    fn old_programs_and_registry_scalar_boundaries() {
        let mut v = Values::new();
        string(&mut v, "0", "product");
        string(&mut v, "1", "version");
        string(&mut v, "2", "publisher");
        v.insert("a".to_owned(), (5, 1u32.to_be_bytes().to_vec()));
        let (id, r) = row(Layout::Program, " \0id\0 ", 116444736000000000, &v);
        assert_eq!(id, "id");
        assert_eq!(r[9], "product");
        assert_eq!(r[10], "version");
        assert_eq!(r[2], "publisher");
        assert_eq!(r[5], "1970-01-01T00:00:01+00:00");
        assert_eq!(r[1], NA);
        v.insert("Name".to_owned(), (3, vec![0x61]));
        assert_eq!(text(&v, "Name").unwrap(), "\u{fffd}");
        v.insert("Name".to_owned(), (0, vec![1, 2]));
        assert_eq!(text(&v, "Name").unwrap(), "");
        v.insert("a".to_owned(), (11, u64::MAX.to_le_bytes().to_vec()));
        assert_eq!(epoch(&v, "a"), NA);
        v.insert("a".to_owned(), (4, vec![1, 2]));
        assert_eq!(integer(&v, "a"), None);
        assert!(!wanted(Layout::ApplicationFile, "publisher"));
        assert!(wanted(Layout::ApplicationFile, "Publisher"));
        assert_eq!(filetime(1), NA);
        assert_eq!(filetime(u64::MAX), NA);
    }
}
