//! Canonical window station scan. Session objects are reread in a process of that session.
use super::*;
use std::collections::{HashMap, HashSet};

const STATION_SIZE: u64 = 152;
const SESSION_ID: u64 = 0;
const NEXT_STATION: u64 = 8;
const DESKTOP_LIST: u64 = 16;
struct GuiLayout {
    #[allow(dead_code)]
    desktop_next: u64,
    desktop_parent: u64,
    desktop_info: u64,
    desktop_threads: u64,
    thread_link: u64,
    thread_process: u64,
    window_top: u64,
    window_next: u64,
    window_child: u64,
    window_procedure: u64,
    window_subprocedure: Option<u64>,
    window_name: u64,
    window_direct_name: Option<u64>,
}

pub(super) fn reference_unicode_name(bytes: &[u8]) -> String {
    let (bytes, big_endian) = if bytes.starts_with(&[0xfe, 0xff]) {
        (bytes.get(2..).unwrap_or(&[]), true)
    } else if bytes.starts_with(&[0xff, 0xfe]) {
        (bytes.get(2..).unwrap_or(&[]), false)
    } else {
        (bytes, false)
    };
    let mut units: Vec<_> = bytes
        .chunks_exact(2)
        .map(|b| {
            if big_endian {
                crate::bytes::le_u16(b, 0).unwrap_or(0).swap_bytes()
            } else {
                crate::bytes::le_u16(b, 0).unwrap_or(0)
            }
        })
        .collect();
    if bytes.len() % 2 != 0 {
        units.push(0xfffd);
    }
    String::from_utf16_lossy(&units)
        .split('\0')
        .next()
        .unwrap_or_default()
        .to_owned()
}

fn classify_window_procedure(value: Option<u64>) -> Option<String> {
    match value {
        None => Some("N/A".into()),
        Some(1..=0x1000) => None,
        Some(value) => Some(format!("{value:#x}")),
    }
}

pub(super) fn reference_process_name(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .split(['\0', '\u{fffd}'])
        .next()
        .unwrap_or_default()
        .to_owned()
}

fn gui_layout(table: &str) -> GuiLayout {
    // Offsets follow the reference GUI JSON for desktops, threads, and tagWND.
    let desktop_info = 8;
    let (desktop_next, desktop_parent, desktop_threads, thread_link, thread_process) = match table {
        "gui-win7sp0-x64" | "gui-win7sp1-x64" => (24, 32, 168, 608, 344),
        "gui-win8-x64" => (16, 24, 160, 640, 368),
        "gui-win10-10586-x64" => (16, 24, 160, 656, 376),
        "gui-win10-15063-x64" => (32, 40, 168, 656, 376),
        "gui-win10-16299-x64" => (32, 40, 168, 712, 400),
        "gui-win10-17134-x64" => (32, 40, 168, 728, 416),
        _ => (32, 40, 168, 736, 416),
    };
    let (
        window_top,
        window_next,
        window_child,
        window_procedure,
        window_subprocedure,
        window_name,
        window_direct_name,
    ) = match table {
        "gui-win7sp0-x64" | "gui-win7sp1-x64" | "gui-win8-x64" | "gui-win10-10586-x64" => {
            (16, 72, 96, 144, None, 216, None)
        }
        "gui-win10-15063-x64" | "gui-win10-16299-x64" => (16, 88, 112, 160, None, 232, None),
        "gui-win10-17134-x64" | "gui-win10-17763-x64" => {
            (24, 64, 88, 160, Some(40), 232, Some(168))
        }
        _ => (24, 88, 112, 160, Some(40), 232, Some(184)),
    };
    GuiLayout {
        desktop_next,
        desktop_parent,
        desktop_info,
        desktop_threads,
        thread_link,
        thread_process,
        window_top,
        window_next,
        window_child,
        window_procedure,
        window_subprocedure,
        window_name,
        window_direct_name,
    }
}

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

struct ScanInput {
    virtual_scan: bool,
    bodies: Vec<u64>,
    table: &'static str,
}

mod sessions;
mod window_walk;

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
                *result.kernel_identity.key_mut("windowstations")? = serde_json::json!({
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
        *result.kernel_identity.key_mut("windowstations")? = serde_json::json!({
            "source": "Wind pool tag and session address space",
            "table": table,
            "virtual_scan": virtual_scan,
            "candidates": candidates,
            "rows": rows,
        });
        Ok(result)
    }

    pub(super) fn windows(&self, job: &Job) -> Result<Results> {
        self.desktop_rows(job, Plugin::WinWindows, false, true)
    }

    pub(super) fn desktops(&self, job: &Job) -> Result<Results> {
        self.desktop_rows(job, Plugin::WinDesktops, false, false)
    }

    pub(super) fn deskscan(&self, job: &Job) -> Result<Results> {
        self.desktop_rows(job, Plugin::WinDeskScan, true, false)
    }

    fn desktop_rows(
        &self,
        job: &Job,
        plugin: Plugin,
        scan: bool,
        windows: bool,
    ) -> Result<Results> {
        ensure!(
            Architecture::from_isf(self.vm.isf)? == Architecture::X64,
            "桌面插件仅支持 x64"
        );
        let Some(table) = self.gui_symbol_table() else {
            bail!("此 Windows 版本没有桌面符号表");
        };
        let layout = gui_layout(table);
        let mut result = self.result(plugin);
        let (virtual_scan, bodies, notes) = if scan {
            self.scan_gui_pool(b"Desk", 224, 0, job)?
        } else {
            self.scan_gui_pool(b"Wind", STATION_SIZE, 0x90, job)?
        };
        for note in notes {
            Self::issue(
                &mut result,
                if scan { "DeskScan" } else { "WindowStations" },
                note,
            );
        }
        let sessions = match self.session_memberships(job) {
            Ok(sessions) => sessions,
            Err(error) => {
                Self::issue(&mut result, "会话层", format!("{error:#}"));
                *result.kernel_identity.key_mut("desktops")? = serde_json::json!({
                    "table": table,
                    "rows": 0,
                });
                return Ok(result);
            }
        };
        if scan {
            return self.scanned_desktops(
                job,
                &mut result,
                &sessions,
                &layout,
                ScanInput {
                    virtual_scan,
                    bodies,
                    table,
                },
            );
        }
        let mut stations = Vec::new();
        let mut seen_stations = HashSet::new();
        for body in bodies {
            job.check()?;
            let Some(session_id) = self.gui_u32(body, virtual_scan) else {
                continue;
            };
            if session_id >= 256 {
                continue;
            }
            let Some(processes) = sessions.get(&u64::from(session_id)) else {
                continue;
            };
            let Some(process) = processes.first() else {
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
            let Some(station_dtb) = self.address_space(process) else {
                continue;
            };
            let mut probe = [0u8; 4];
            if memory.read(add(body, SESSION_ID)?, &mut probe).is_err() {
                continue;
            }
            if u32::from_le_bytes(probe) != session_id {
                continue;
            }
            for station in self.station_chain(&memory, body) {
                if !seen_stations.insert(station) {
                    continue;
                }
                let Some((name, confirmed)) = self.station_info(&memory, station) else {
                    continue;
                };
                if confirmed != session_id {
                    continue;
                }
                stations.push((station, name, session_id, station_dtb));
            }
        }
        let mut rows = 0usize;
        let named_stations = stations.len();
        for (station, station_name, session_id, station_dtb) in stations {
            job.check()?;
            let Some(processes) = sessions.get(&u64::from(session_id)) else {
                continue;
            };
            let Some((desktop, dtb)) =
                self.session_kernel_pointer(processes, station_dtb, add(station, DESKTOP_LIST)?)
            else {
                continue;
            };
            let Some(desktop_name) = self.desktop_name(processes, dtb, desktop) else {
                continue;
            };
            if windows {
                rows += self.desktop_windows(DesktopWindows {
                    job,
                    result: &mut result,
                    processes,
                    preferred_dtb: dtb,
                    desktop,
                    station_name: &station_name,
                    session_id,
                    desktop_name: &desktop_name,
                    layout: &layout,
                })?;
                continue;
            }
            let head = add(desktop, layout.desktop_threads)?;
            let Some((mut link, list_dtb)) = self.session_kernel_pointer(processes, dtb, head)
            else {
                continue;
            };
            let mut links = HashSet::from([head]);
            while link != head && self.vm.kernel(link) && links.insert(link) && links.len() <= 4096
            {
                job.check()?;
                let thread = link.saturating_sub(layout.thread_link);
                if let Some((process_name, pid)) = self.desktop_thread_in_session(
                    processes,
                    list_dtb,
                    thread,
                    layout.thread_process,
                ) {
                    ensure!(rows < MAX_OBJECTS, "桌面结果数量超限");
                    result.rows.push(vec![
                        format!("{:#018x}", desktop & 0x0000_ffff_ffff_ffff),
                        station_name.clone(),
                        session_id.to_string(),
                        desktop_name.clone(),
                        process_name,
                        pid.to_string(),
                    ]);
                    rows += 1;
                } else if let Some(pid) =
                    self.unreadable_process_id(processes, list_dtb, thread, layout.thread_process)
                {
                    ensure!(rows < MAX_OBJECTS, "桌面结果数量超限");
                    result.rows.push(vec![
                        format!("{:#018x}", desktop & 0x0000_ffff_ffff_ffff),
                        station_name.clone(),
                        session_id.to_string(),
                        desktop_name.clone(),
                        String::new(),
                        pid.to_string(),
                    ]);
                    rows += 1;
                }
                let Some(list_memory) = self.process_memory_dtb(list_dtb) else {
                    break;
                };
                link = list_memory.uint(link, self.vm.pointer_size()).unwrap_or(0);
            }
        }
        *result.kernel_identity.key_mut("desktops")? = serde_json::json!({
            "source": "window station rpdeskList and tagTHREADINFO.PtiLink",
            "table": table,
            "stations": named_stations,
            "rows": rows,
        });
        Ok(result)
    }

    fn scanned_desktops(
        &self,
        job: &Job,
        result: &mut Results,
        sessions: &HashMap<u64, Vec<Process>>,
        layout: &GuiLayout,
        input: ScanInput,
    ) -> Result<Results> {
        let ScanInput {
            virtual_scan,
            bodies,
            table,
        } = input;
        let mut rows = 0usize;
        let mut seen = HashSet::new();
        let candidates = bodies.len();
        for body in bodies {
            job.check()?;
            let Some(parent) =
                self.session_pointer_any(sessions, add(body, layout.desktop_parent)?, virtual_scan)
            else {
                continue;
            };
            let Some(session_id) = self.gui_u32(parent, virtual_scan) else {
                continue;
            };
            if session_id >= 256 {
                continue;
            }
            let Some(processes) = sessions.get(&u64::from(session_id)) else {
                continue;
            };
            let Some((station_name, confirmed, station_dtb)) =
                self.named_station(processes, parent, session_id)
            else {
                continue;
            };
            if confirmed != session_id {
                continue;
            }
            let Some(desktop_name) = self.desktop_name(processes, station_dtb, body) else {
                continue;
            };
            if !seen.insert(body) {
                continue;
            }
            let head = add(body, layout.desktop_threads)?;
            let Some((mut link, list_dtb)) =
                self.session_kernel_pointer(processes, station_dtb, head)
            else {
                continue;
            };
            let mut links = HashSet::from([head]);
            while link != head && kernel(link) && links.insert(link) && links.len() <= 4096 {
                job.check()?;
                let thread = link.saturating_sub(layout.thread_link);
                if let Some((process_name, pid)) = self.desktop_thread_in_session(
                    processes,
                    list_dtb,
                    thread,
                    layout.thread_process,
                ) {
                    ensure!(rows < MAX_OBJECTS, "桌面结果数量超限");
                    result.rows.push(vec![
                        format!("{:#018x}", body & 0x0000_ffff_ffff_ffff),
                        station_name.clone(),
                        session_id.to_string(),
                        desktop_name.clone(),
                        process_name,
                        pid.to_string(),
                    ]);
                    rows += 1;
                } else if let Some(pid) =
                    self.unreadable_process_id(processes, list_dtb, thread, layout.thread_process)
                {
                    ensure!(rows < MAX_OBJECTS, "桌面结果数量超限");
                    result.rows.push(vec![
                        format!("{:#018x}", body & 0x0000_ffff_ffff_ffff),
                        station_name.clone(),
                        session_id.to_string(),
                        desktop_name.clone(),
                        String::new(),
                        pid.to_string(),
                    ]);
                    rows += 1;
                }
                let Some(list_memory) = self.process_memory_dtb(list_dtb) else {
                    break;
                };
                link = list_memory.uint(link, self.vm.pointer_size()).unwrap_or(0);
            }
        }
        *result.kernel_identity.key_mut("deskscan")? = serde_json::json!({
            "source": "Desk pool tag, parent window station, and desktop thread list",
            "table": table,
            "candidates": candidates,
            "desktops": seen.len(),
            "rows": rows,
        });
        Ok(std::mem::replace(result, self.result(Plugin::WinDeskScan)))
    }

    fn session_pointer_any(
        &self,
        sessions: &HashMap<u64, Vec<Process>>,
        address: u64,
        virtual_scan: bool,
    ) -> Option<u64> {
        if virtual_scan
            && let Ok(value) = self.vm.uint(address, self.vm.pointer_size())
            && kernel(value)
        {
            return Some(value);
        }
        for processes in sessions.values() {
            if let Some((value, _)) = self.session_kernel_pointer(processes, 0, address) {
                return Some(value);
            }
        }
        None
    }

    fn named_station(
        &self,
        processes: &[Process],
        station: u64,
        session_id: u32,
    ) -> Option<(String, u32, u64)> {
        for process in processes {
            let dtb = self.address_space(process)?;
            let memory = self.process_memory_dtb(dtb)?;
            let (name, confirmed) = self.station_info(&memory, station)?;
            if confirmed == session_id {
                return Some((name, confirmed, dtb));
            }
        }
        None
    }
}

struct DesktopWindows<'a> {
    job: &'a Job,
    result: &'a mut Results,
    processes: &'a [Process],
    preferred_dtb: u64,
    desktop: u64,
    station_name: &'a str,
    session_id: u32,
    desktop_name: &'a str,
    layout: &'a GuiLayout,
}

struct WindowWalk<'a> {
    job: &'a Job,
    result: &'a mut Results,
    processes: &'a [Process],
    dtb: u64,
    field: u64,
    window: u64,
    station_name: &'a str,
    session_id: u32,
    desktop_name: &'a str,
    layout: &'a GuiLayout,
    seen: &'a mut HashSet<u64>,
    rows: &'a mut usize,
}

#[cfg(test)]
mod tests;
