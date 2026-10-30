//! Canonical window station scan. Session objects are reread in a process of that session.
use super::*;
use std::collections::{HashMap, HashSet};

const STATION_SIZE: u64 = 152;
const SESSION_ID: u64 = 0;
const NEXT_STATION: u64 = 8;

fn gui_table(major: u16, minor: u16, build: u16) -> Option<&'static str> {
    // Newest match first, matching WindowStations._win_version_file_map.
    const MINIMUMS: &[((u16, u16, u16), &str)] = &[
        ((10, 0, 19577), "gui-win10-19577-x64"),
        ((10, 0, 19041), "gui-win10-19041-x64"),
        ((10, 0, 18362), "gui-win10-18362-x64"),
        ((10, 0, 17763), "gui-win10-17763-x64"),
        ((10, 0, 17134), "gui-win10-17134-x64"),
        ((10, 0, 16299), "gui-win10-16299-x64"),
        ((10, 0, 15063), "gui-win10-15063-x64"),
        ((10, 0, 10586), "gui-win10-10586-x64"),
        ((6, 2, 0), "gui-win8-x64"),
    ];
    let version = (major, minor, build);
    if let Some((_, name)) = MINIMUMS.iter().find(|(minimum, _)| version >= *minimum) {
        return Some(name);
    }
    match version {
        (6, 1, 7601) => Some("gui-win7sp1-x64"),
        (6, 1, 7600) => Some("gui-win7sp0-x64"),
        _ => None,
    }
}

impl Windows<'_> {
    pub(super) fn window_stations(&self, job: &Job) -> Result<Results> {
        ensure!(
            Architecture::from_isf(self.vm.isf)? == Architecture::X64,
            "WindowStations 仅支持 x64"
        );
        let Some(table) = self.gui_symbol_table() else {
            bail!("此 Windows 版本没有窗口站符号表");
        };
        let mut result = self.result(Plugin::WinWindowStations);
        let (virtual_scan, bodies, notes) = self.scan_gui_pool(b"Wind", STATION_SIZE, 0x90, job)?;
        for note in notes {
            Self::issue(&mut result, "WindowStations", note);
        }
        let sessions = match self.session_layers(job) {
            Ok(sessions) => sessions,
            Err(error) => {
                Self::issue(&mut result, "会话层", format!("{error:#}"));
                result.kernel_identity["windowstations"] = serde_json::json!({
                    "table": table,
                    "rows": 0,
                });
                return Ok(result);
            }
        };
        let mut seen = HashSet::new();
        let mut rows = 0usize;
        let candidates = bodies.len();
        for body in bodies {
            job.check()?;
            let Some(session_id) = self.gui_u32(body, virtual_scan) else {
                continue;
            };
            if session_id >= 256 {
                continue;
            }
            let Some(process) = sessions.get(&u64::from(session_id)) else {
                continue;
            };
            let memory = match self.process_memory(process) {
                Ok(memory) => memory,
                Err(error) => {
                    Self::issue(
                        &mut result,
                        format!("会话 {session_id}"),
                        format!("{error:#}"),
                    );
                    continue;
                }
            };
            let mut probe = [0u8; 4];
            if memory.read(add(body, SESSION_ID)?, &mut probe).is_err() {
                continue;
            }
            if u32::from_le_bytes(probe) != session_id {
                continue;
            }
            for station in self.station_chain(&memory, body) {
                if !seen.insert(station) {
                    continue;
                }
                let Some((name, session_id)) = self.station_info(&memory, station) else {
                    continue;
                };
                ensure!(rows < MAX_OBJECTS, "窗口站结果数量超限");
                result.rows.push(vec![
                    format!("{:#018x}", station & 0x0000_ffff_ffff_ffff),
                    name,
                    session_id.to_string(),
                ]);
                rows += 1;
            }
        }
        result.kernel_identity["windowstations"] = serde_json::json!({
            "source": "Wind pool tag and session address space",
            "table": table,
            "virtual_scan": virtual_scan,
            "candidates": candidates,
            "rows": rows,
        });
        Ok(result)
    }

    fn gui_symbol_table(&self) -> Option<&'static str> {
        let identity = self.version_identity();
        let value = |name| {
            identity[name]
                .as_u64()
                .filter(|value| *value <= u16::MAX as u64)
        };
        if let (Some(major), Some(minor), Some(build)) =
            (value("major"), value("minor"), value("build"))
        {
            return gui_table(major as u16, minor as u16, build as u16);
        }
        let build = self.build_number().ok()?;
        const BUILD_TABLES: &[(u32, &str)] = &[
            (19577, "gui-win10-19577-x64"),
            (19041, "gui-win10-19041-x64"),
            (18362, "gui-win10-18362-x64"),
            (17763, "gui-win10-17763-x64"),
            (17134, "gui-win10-17134-x64"),
            (16299, "gui-win10-16299-x64"),
            (15063, "gui-win10-15063-x64"),
            (10586, "gui-win10-10586-x64"),
            (9200, "gui-win8-x64"),
            (7601, "gui-win7sp1-x64"),
            (7600, "gui-win7sp0-x64"),
        ];
        BUILD_TABLES
            .iter()
            .find(|(minimum, _)| build >= *minimum)
            .map(|(_, table)| *table)
    }

    fn session_layers(&self, job: &Job) -> Result<HashMap<u64, Process>> {
        let (processes, diagnostics) = self.processes_partial(job)?;
        if !diagnostics.is_empty() {
            // Session selection still uses every recovered process. The caller records the partial walk.
        }
        let mut sessions = HashMap::new();
        for process in processes {
            if let Some(session_id) = self.process_session_id(&process)
                && !sessions.contains_key(&session_id)
            {
                sessions.insert(session_id, process);
            }
        }
        let _ = diagnostics;
        Ok(sessions)
    }

    fn process_session_id(&self, process: &Process) -> Option<u64> {
        let session = self.number(process.address, "_EPROCESS", "Session").ok()?;
        if !self.vm.kernel(session) {
            return None;
        }
        let id = if self.vm.isf.has_field("_MM_SESSION_SPACE", "SessionId") {
            self.number(session, "_MM_SESSION_SPACE", "SessionId")
                .ok()?
        } else {
            self.vm.uint(add(session, 8).ok()?, 4).ok()?
        };
        Some(id)
    }

    fn gui_u32(&self, address: u64, virtual_scan: bool) -> Option<u32> {
        let mut bytes = [0u8; 4];
        self.pool_read(add(address, SESSION_ID).ok()?, &mut bytes, virtual_scan)
            .ok()?;
        Some(u32::from_le_bytes(bytes))
    }

    /// The reference walk reads `self.rpwinstaNext` on every iteration, so a chain contributes at most two stations.
    fn station_chain(&self, memory: &Memory<'_>, station: u64) -> Vec<u64> {
        let mut found = vec![station];
        let mut seen = HashSet::new();
        while seen.len() < 15 {
            let Ok(next) = memory.uint(
                add(station, NEXT_STATION).unwrap_or(0),
                self.vm.pointer_size(),
            ) else {
                break;
            };
            if !self.vm.kernel(next) || !seen.insert(next) {
                break;
            }
            found.push(next);
        }
        found
    }

    fn station_info(&self, memory: &Memory<'_>, station: u64) -> Option<(String, u32)> {
        let mut bytes = [0u8; 4];
        memory
            .read(add(station, SESSION_ID).ok()?, &mut bytes)
            .ok()?;
        let session_id = u32::from_le_bytes(bytes);
        if session_id >= 256 {
            return None;
        }
        let name = self.session_object_name(memory, station)?;
        if !(2..=128).contains(&name.chars().count()) || name.chars().any(|unit| unit.is_control())
        {
            return None;
        }
        Some((name, session_id))
    }

    fn session_object_name(&self, memory: &Memory<'_>, body: u64) -> Option<String> {
        let header = body.checked_sub(self.vm.isf.offset("_OBJECT_HEADER", "Body").ok()?)?;
        let name = if self.vm.isf.has_field("_OBJECT_HEADER", "InfoMask") {
            let mask = memory
                .uint(
                    add(
                        header,
                        self.vm.isf.offset("_OBJECT_HEADER", "InfoMask").ok()?,
                    )
                    .ok()?,
                    1,
                )
                .ok()?;
            if mask & 2 == 0 {
                return None;
            }
            let table = self.symbol("ObpInfoMaskToOffset").ok()?;
            let delta = self.vm.uint(add(table, mask & 3).ok()?, 1).ok()?;
            if delta == 0 {
                return None;
            }
            header.checked_sub(delta)?
        } else {
            let delta = memory
                .uint(
                    add(
                        header,
                        self.vm
                            .isf
                            .offset("_OBJECT_HEADER", "NameInfoOffset")
                            .ok()?,
                    )
                    .ok()?,
                    1,
                )
                .ok()?;
            if delta == 0 {
                return None;
            }
            header.checked_sub(delta)?
        };
        let descriptor = add(
            name,
            self.vm
                .isf
                .offset("_OBJECT_HEADER_NAME_INFO", "Name")
                .ok()?,
        )
        .ok()?;
        self.session_unicode(memory, descriptor).ok()
    }

    fn session_unicode(&self, memory: &Memory<'_>, descriptor: u64) -> Result<String> {
        let length = memory.uint(descriptor, 2)?;
        let maximum = memory.uint(add(descriptor, 2)?, 2)?;
        if length == 0 || maximum == 0 || length > maximum || length > 65534 || length % 2 != 0 {
            bail!("对象名称长度无效");
        }
        let buffer = memory.uint(
            add(descriptor, self.vm.isf.offset("_UNICODE_STRING", "Buffer")?)?,
            self.vm.pointer_size(),
        )?;
        let mut bytes = vec![0u8; length as usize];
        memory.read(buffer, &mut bytes)?;
        Ok(String::from_utf16_lossy(
            &bytes
                .chunks_exact(2)
                .map(|word| u16::from_le_bytes([word[0], word[1]]))
                .collect::<Vec<_>>(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{K, fixture, image, put};
    use super::*;

    #[test]
    fn gui_tables_follow_the_reference_version_order() {
        assert_eq!(gui_table(10, 0, 22000), Some("gui-win10-19577-x64"));
        assert_eq!(gui_table(10, 0, 15063), Some("gui-win10-15063-x64"));
        assert_eq!(gui_table(10, 0, 10240), Some("gui-win8-x64"));
        assert_eq!(gui_table(6, 3, 9600), Some("gui-win8-x64"));
        assert_eq!(gui_table(6, 1, 7601), Some("gui-win7sp1-x64"));
        assert_eq!(gui_table(6, 1, 7600), Some("gui-win7sp0-x64"));
        assert_eq!(gui_table(5, 2, 3790), None);
    }

    #[test]
    fn station_names_require_a_unicode_name_without_controls() {
        let (bytes, isf) = fixture();
        let snapshot = image(&bytes);
        let windows = Windows {
            vm: Memory::new(&snapshot, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        assert_eq!(windows.station_info(&windows.vm, K + 0x9000), None);
        assert!(windows.station_chain(&windows.vm, K + 0x9000).len() <= 15);
    }

    #[test]
    fn an_unmapped_windows_version_is_rejected() {
        let (mut bytes, isf) = fixture();
        put(&mut bytes, 0x8200, 3790);
        let snapshot = image(&bytes);
        let windows = Windows {
            vm: Memory::new(&snapshot, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let error = windows.window_stations(&Job::default()).unwrap_err();
        assert!(error.to_string().contains("窗口站"), "{error:#}");
    }
}
