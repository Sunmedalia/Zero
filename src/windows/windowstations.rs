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

fn classify_window_procedure(value: Option<u64>) -> Option<String> {
    match value {
        None => Some("N/A".into()),
        Some(1..=0x1000) => None,
        Some(value) => Some(format!("{value:#x}")),
    }
}

fn reference_process_name(bytes: &[u8]) -> String {
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
                result.kernel_identity["desktops"] = serde_json::json!({
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
        result.kernel_identity["desktops"] = serde_json::json!({
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
        result.kernel_identity["deskscan"] = serde_json::json!({
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

    fn desktop_windows(&self, request: DesktopWindows<'_>) -> Result<usize> {
        let DesktopWindows {
            job,
            result,
            processes,
            preferred_dtb,
            desktop,
            station_name,
            session_id,
            desktop_name,
            layout,
        } = request;
        let Some((info, info_dtb)) = self.session_kernel_pointer(
            processes,
            preferred_dtb,
            add(desktop, layout.desktop_info)?,
        ) else {
            return Ok(0);
        };
        let Some((top, top_dtb)) =
            self.session_kernel_pointer(processes, info_dtb, add(info, layout.window_top)?)
        else {
            return Ok(0);
        };
        if top == 0 {
            return Ok(0);
        }
        let mut rows = 0usize;
        let mut seen = HashSet::new();
        // The reference yields the pointer field first and only dereferences `spwndNext`.
        self.walk_window_field(WindowWalk {
            job,
            result,
            processes,
            dtb: top_dtb,
            field: add(info, layout.window_top)?,
            window: top,
            station_name,
            session_id,
            desktop_name,
            layout,
            seen: &mut seen,
            rows: &mut rows,
        })?;
        Ok(rows)
    }

    fn walk_window_field(&self, walk: WindowWalk<'_>) -> Result<()> {
        let WindowWalk {
            job,
            result,
            processes,
            dtb,
            field,
            mut window,
            station_name,
            session_id,
            desktop_name,
            layout,
            seen,
            rows,
        } = walk;
        let mut siblings = Vec::new();
        let mut reported = field;
        let mut followed = HashSet::new();
        while window != 0 && kernel(window) && seen.len() < 10000 {
            job.check()?;
            if !followed.insert(window) {
                break;
            }
            if seen.insert(reported) {
                siblings.push((reported, window));
                if let Some((name, procedure, process_name, pid)) =
                    self.window_record(processes, dtb, window, layout)
                {
                    ensure!(result.rows.len() < MAX_OBJECTS, "窗口结果数量超限");
                    if procedure == "N/A" {
                        Self::issue(
                            result,
                            format!("window {reported:#x} Procedure"),
                            "窗口过程地址不可读，保留 N/A",
                        );
                    }
                    result.rows.push(vec![
                        format!("{:#018x}", reported & 0x0000_ffff_ffff_ffff),
                        station_name.to_string(),
                        session_id.to_string(),
                        desktop_name.to_string(),
                        name,
                        procedure,
                        process_name,
                        pid.to_string(),
                    ]);
                    *rows += 1;
                }
            }
            let Some(memory) = self.process_memory_dtb(dtb) else {
                break;
            };
            let next = self
                .raw_pointer(&memory, add(window, layout.window_next)?)
                .filter(|next| kernel(*next))
                .unwrap_or(0);
            if next == 0 {
                break;
            }
            reported = next;
            window = next;
        }
        for sibling in siblings {
            let (_reported, mut child) = sibling;
            let mut seen_children = HashSet::new();
            while seen.len() + seen_children.len() < 10000 {
                let Some(memory) = self.process_memory_dtb(dtb) else {
                    break;
                };
                let child_field = add(child, layout.window_child)?;
                let Some(next) = self
                    .raw_pointer(&memory, add(child, layout.window_child)?)
                    .filter(|value| *value != 0 && kernel(*value))
                else {
                    break;
                };
                if !seen_children.insert(child_field) {
                    break;
                }
                self.walk_window_field(WindowWalk {
                    job,
                    result,
                    processes,
                    dtb,
                    field: child_field,
                    window: next,
                    station_name,
                    session_id,
                    desktop_name,
                    layout,
                    seen,
                    rows,
                })?;
                child = next;
            }
        }
        Ok(())
    }

    fn window_record(
        &self,
        processes: &[Process],
        dtb: u64,
        window: u64,
        layout: &GuiLayout,
    ) -> Option<(String, String, String, u64)> {
        let memory = self.process_memory_dtb(dtb)?;
        let thread = self.raw_pointer(&memory, add(window, 16).ok()?)?;
        if !kernel(thread) {
            return None;
        }
        let (process_name, pid) =
            self.window_process(processes, dtb, thread, layout.thread_process)?;
        let session = self.window_session(processes, dtb, window)?;
        if session >= 256 {
            return None;
        }
        let procedure = self.window_procedure(&memory, window, layout)?;
        let name = self
            .window_name(processes, dtb, window, layout)
            .unwrap_or_default();
        Some((name, procedure, process_name, pid))
    }

    fn window_session(&self, processes: &[Process], dtb: u64, window: u64) -> Option<u32> {
        let memory = self.process_memory_dtb(dtb)?;
        let desktop = self.raw_pointer(&memory, add(window, 24).ok()?)?;
        if !kernel(desktop) {
            return None;
        }
        let parent = self
            .session_kernel_pointer(processes, dtb, add(desktop, 40).ok()?)
            .map(|(value, _)| value)
            .or_else(|| self.raw_pointer(&memory, add(desktop, 40).ok()?))?;
        if !kernel(parent) {
            return None;
        }
        let bytes_memory = self.process_memory_dtb(dtb)?;
        let mut bytes = [0u8; 4];
        bytes_memory.read(parent, &mut bytes).ok()?;
        Some(u32::from_le_bytes(bytes))
    }

    fn window_procedure(
        &self,
        memory: &Memory<'_>,
        window: u64,
        layout: &GuiLayout,
    ) -> Option<String> {
        let read = (|| {
            if let Some(sub) = layout.window_subprocedure {
                let pointer = self.raw_pointer(memory, add(window, sub).ok()?)?;
                self.raw_pointer(memory, add(pointer, layout.window_procedure).ok()?)
            } else {
                self.raw_pointer(memory, add(window, layout.window_procedure).ok()?)
            }
        })();
        classify_window_procedure(read)
    }

    /// Same process link as the desktop walk, but a short image-name read still counts.
    /// The reference keeps a string when the first bytes are present and the PID read succeeds.
    fn window_process(
        &self,
        processes: &[Process],
        preferred_dtb: u64,
        thread: u64,
        process_offset: u64,
    ) -> Option<(String, u64)> {
        if let Some(found) =
            self.desktop_thread_in_session(processes, preferred_dtb, thread, process_offset)
        {
            return Some((reference_process_name(found.0.as_bytes()), found.1));
        }
        let mut ordered = Vec::new();
        if preferred_dtb != 0 {
            ordered.push(preferred_dtb);
        }
        for process in processes {
            if let Some(dtb) = self.address_space(process)
                && dtb != preferred_dtb
            {
                ordered.push(dtb);
            }
        }
        for dtb in ordered {
            let Some(memory) = self.process_memory_dtb(dtb) else {
                continue;
            };
            let Some(process) = self.thread_process(&memory, thread, process_offset) else {
                continue;
            };
            if let Some(found) = self.partial_process_identity(&memory, process) {
                return Some(found);
            }
            if let Some(found) = self.partial_process_identity(&self.vm, process) {
                return Some(found);
            }
        }
        None
    }

    fn partial_process_identity(&self, memory: &Memory<'_>, process: u64) -> Option<(String, u64)> {
        let name_at = add(
            process,
            self.vm.isf.offset("_EPROCESS", "ImageFileName").ok()?,
        )
        .ok()?;
        let length = self.vm.isf.size("_EPROCESS", "ImageFileName").ok()?;
        if length == 0 || length > 64 {
            return None;
        }
        let mut bytes = vec![0u8; length];
        let mut got = 0usize;
        while got < length {
            if memory
                .read(name_at + got as u64, &mut bytes[got..got + 1])
                .is_err()
            {
                break;
            }
            got += 1;
        }
        if got == 0 {
            return None;
        }
        // The fixed utility decodes with replacement, then truncates at the
        // first NUL or replacement character (even a literal encoded U+FFFD).
        let name = reference_process_name(&bytes[..got]);
        let pid = memory
            .uint(
                add(
                    process,
                    self.vm.isf.offset("_EPROCESS", "UniqueProcessId").ok()?,
                )
                .ok()?,
                self.vm.pointer_size(),
            )
            .ok()?;
        Some((name, pid))
    }

    fn window_name(
        &self,
        processes: &[Process],
        dtb: u64,
        window: u64,
        layout: &GuiLayout,
    ) -> Option<String> {
        let memory = self.process_memory_dtb(dtb)?;
        if let Some(direct) = layout.window_direct_name {
            let pointer = self.raw_pointer(&memory, add(window, direct).ok()?)?;
            if let Some(name) = self.utf16_capped(processes, dtb, pointer, 256) {
                return Some(name);
            }
        }
        let length = memory.uint(add(window, layout.window_name).ok()?, 4).ok()?;
        if length == 0 || length > 1024 {
            return None;
        }
        let buffer = self.raw_pointer(&memory, add(window, layout.window_name + 8).ok()?)?;
        self.utf16_exact(processes, dtb, buffer, length as usize)
    }

    fn utf16_exact(
        &self,
        processes: &[Process],
        preferred: u64,
        address: u64,
        bytes: usize,
    ) -> Option<String> {
        if bytes == 0 || bytes > 2048 || !bytes.is_multiple_of(2) {
            return None;
        }
        let mut ordered = vec![preferred];
        for process in processes {
            if let Some(dtb) = self.address_space(process)
                && dtb != preferred
            {
                ordered.push(dtb);
            }
        }
        for dtb in ordered {
            let memory = self.process_memory_dtb(dtb)?;
            let mut data = vec![0u8; bytes];
            if memory.read(address, &mut data).is_err() {
                continue;
            }
            let units = data
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect::<Vec<_>>();
            return Some(String::from_utf16_lossy(&units));
        }
        None
    }

    fn utf16_capped(
        &self,
        processes: &[Process],
        preferred: u64,
        address: u64,
        chars: usize,
    ) -> Option<String> {
        let text = self.utf16_exact(processes, preferred, address, chars * 2)?;
        let end = text.find('\0').unwrap_or(text.len());
        Some(text[..end].to_string())
    }

    fn address_space(&self, process: &Process) -> Option<u64> {
        let user = self
            .number(process.address, "_EPROCESS", "Pcb.UserDirectoryTableBase")
            .unwrap_or(0)
            & self.vm.root_mask();
        let dtb = if process.dtb != 0 { process.dtb } else { user };
        (dtb != 0).then_some(dtb)
    }

    fn process_memory_dtb(&self, dtb: u64) -> Option<Memory<'_>> {
        if dtb == 0 {
            return None;
        }
        Some(Memory::new(
            self.vm.image,
            dtb,
            self.vm.isf,
            self.vm.sources,
        ))
    }

    /// Reads a kernel pointer, preferring the session process that owns the station.
    /// A mapped zero from that process is not accepted ahead of another process.
    fn session_kernel_pointer(
        &self,
        processes: &[Process],
        preferred_dtb: u64,
        address: u64,
    ) -> Option<(u64, u64)> {
        let mut ordered = Vec::with_capacity(processes.len());
        if preferred_dtb != 0 {
            ordered.push(preferred_dtb);
        }
        for process in processes {
            if let Some(dtb) = self.address_space(process)
                && dtb != preferred_dtb
            {
                ordered.push(dtb);
            }
        }
        for dtb in &ordered {
            let Some(memory) = self.process_memory_dtb(*dtb) else {
                continue;
            };
            let Ok(value) = memory.uint(address, self.vm.pointer_size()) else {
                continue;
            };
            if self.vm.kernel(value) {
                return Some((value, *dtb));
            }
        }
        None
    }

    fn desktop_name(
        &self,
        processes: &[Process],
        preferred_dtb: u64,
        desktop: u64,
    ) -> Option<String> {
        let mut ordered = Vec::new();
        if preferred_dtb != 0 {
            ordered.push(preferred_dtb);
        }
        for process in processes {
            if let Some(dtb) = self.address_space(process)
                && dtb != preferred_dtb
            {
                ordered.push(dtb);
            }
        }
        for dtb in &ordered {
            let Some(memory) = self.process_memory_dtb(*dtb) else {
                continue;
            };
            let Some(name) = self.session_object_name(&memory, desktop) else {
                continue;
            };
            if !name.is_empty()
                && name.chars().count() <= 128
                && !name.chars().any(char::is_control)
            {
                return Some(name);
            }
        }
        None
    }

    fn process_identity(&self, memory: &Memory<'_>, process: u64) -> Option<(String, u64)> {
        let name_at = add(
            process,
            self.vm.isf.offset("_EPROCESS", "ImageFileName").ok()?,
        )
        .ok()?;
        let length = self.vm.isf.size("_EPROCESS", "ImageFileName").ok()?;
        if length == 0 || length > 64 {
            return None;
        }
        let mut bytes = vec![0u8; length];
        memory.read(name_at, &mut bytes).ok()?;
        let end = bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len());
        let name = String::from_utf8_lossy(&bytes[..end]).into_owned();
        if name.chars().any(char::is_control) {
            return None;
        }
        let pid = memory
            .uint(
                add(
                    process,
                    self.vm.isf.offset("_EPROCESS", "UniqueProcessId").ok()?,
                )
                .ok()?,
                self.vm.pointer_size(),
            )
            .ok()?;
        Some((name, pid))
    }

    fn desktop_thread_in_session(
        &self,
        processes: &[Process],
        preferred_dtb: u64,
        thread: u64,
        process_offset: u64,
    ) -> Option<(String, u64)> {
        let mut ordered = Vec::new();
        if preferred_dtb != 0 {
            ordered.push(preferred_dtb);
        }
        for process in processes {
            if let Some(dtb) = self.address_space(process)
                && dtb != preferred_dtb
            {
                ordered.push(dtb);
            }
        }
        for dtb in &ordered {
            let Some(memory) = self.process_memory_dtb(*dtb) else {
                continue;
            };
            let Some(process) = self.thread_process(&memory, thread, process_offset) else {
                continue;
            };
            if let Some(found) = self.process_identity(&self.vm, process) {
                return Some(found);
            }
            for space in &ordered {
                let Some(space_memory) = self.process_memory_dtb(*space) else {
                    continue;
                };
                if let Some(found) = self.process_identity(&space_memory, process) {
                    return Some(found);
                }
            }
        }
        None
    }

    fn unreadable_process_id(
        &self,
        processes: &[Process],
        preferred_dtb: u64,
        thread: u64,
        process_offset: u64,
    ) -> Option<u64> {
        let mut ordered = Vec::new();
        if preferred_dtb != 0 {
            ordered.push(preferred_dtb);
        }
        for process in processes {
            if let Some(dtb) = self.address_space(process)
                && dtb != preferred_dtb
            {
                ordered.push(dtb);
            }
        }
        for dtb in ordered {
            let memory = self.process_memory_dtb(dtb)?;
            let process = self.thread_process(&memory, thread, process_offset)?;
            let pid = self.raw_pointer(
                &memory,
                add(
                    process,
                    self.vm.isf.offset("_EPROCESS", "UniqueProcessId").ok()?,
                )
                .ok()?,
            )?;
            if pid != 0 {
                return Some(pid);
            }
        }
        None
    }

    fn raw_pointer(&self, memory: &Memory<'_>, address: u64) -> Option<u64> {
        let width = self.vm.pointer_size();
        let mut bytes = vec![0u8; width];
        let mut done = 0usize;
        while done < width {
            let page_left = 4096 - ((address as usize + done) & 4095);
            let take = (width - done).min(page_left);
            if memory
                .read(address + done as u64, &mut bytes[done..done + take])
                .is_err()
            {
                break;
            }
            done += take;
        }
        if done == 0 {
            return None;
        }
        let mut wide = [0u8; 8];
        wide[..done].copy_from_slice(&bytes[..done]);
        Some(u64::from_le_bytes(wide))
    }

    fn thread_process(&self, memory: &Memory<'_>, thread: u64, process_offset: u64) -> Option<u64> {
        let process_info = self.raw_pointer(memory, add(thread, process_offset).ok()?)?;
        if !kernel(process_info) {
            return None;
        }
        // The reference follows ppi.Process even when the pointer is truncated.
        self.raw_pointer(memory, process_info)
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

    fn session_memberships(&self, job: &Job) -> Result<HashMap<u64, Vec<Process>>> {
        let (processes, _) = self.processes_partial(job)?;
        let mut sessions: HashMap<u64, Vec<Process>> = HashMap::new();
        for process in processes {
            if let Some(session_id) = self.process_session_id(&process) {
                sessions.entry(session_id).or_default().push(process);
            }
        }
        Ok(sessions)
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
        let layout = gui_layout("gui-win10-15063-x64");
        assert_eq!(layout.desktop_threads, 168);
        assert_eq!(layout.thread_link, 656);
        assert_eq!(layout.thread_process, 376);
        assert_eq!(gui_layout("gui-win10-17134-x64").thread_link, 728);
        assert_eq!(gui_layout("gui-win10-17763-x64").thread_link, 736);
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
    fn partial_window_process_names_match_fixed_decoding_vectors() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/reference/parity/fixtures/gui-process-names.json"
        ))
        .unwrap();
        for c in vectors["cases"].as_array().unwrap() {
            let (mut bytes, isf) = fixture();
            bytes[0xa030..0xa040].fill(0);
            let raw: Vec<_> = c["hex"]
                .as_str()
                .unwrap()
                .as_bytes()
                .chunks_exact(2)
                .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
                .collect();
            assert!(raw.len() <= 16);
            bytes[0xa030..0xa030 + raw.len()].copy_from_slice(&raw);
            put(&mut bytes, 0xa020, 2743092250712); // Synthetic out-of-range PID remains an observed field.
            let img = image(&bytes);
            let w = Windows {
                vm: Memory::new(&img, 0x1000, &isf, None),
                base: K,
                pdb: PdbIdentity::from_isf(&isf).unwrap(),
            };
            let (name, pid) = w.partial_process_identity(&w.vm, K + 0x2000).unwrap();
            assert_eq!(name, c["expected"].as_str().unwrap(), "{}", c["id"]);
            assert_eq!(pid, 2743092250712);
            let thread = K + 0x6000;
            drop(w);
            drop(img);
            put(&mut bytes, 0xe000 + 376, K + 0x7000);
            put(&mut bytes, 0xf000, K + 0x2000);
            let img = image(&bytes);
            let w = Windows {
                vm: Memory::new(&img, 0x1000, &isf, None),
                base: K,
                pdb: PdbIdentity::from_isf(&isf).unwrap(),
            };
            let found = w.window_process(&[], 0x1000, thread, 376).unwrap();
            assert_eq!(
                found,
                (name, pid),
                "first-choice and fallback must use identical decoding: {}",
                c["id"]
            );
        }
    }
    #[test]
    fn partial_name_prefix_requires_a_real_first_byte_and_a_complete_pid() {
        let (mut bytes, isf) = fixture();
        let process = K + 0x1fc8;
        put(&mut bytes, 0x9fe8, 1234);
        bytes[0x9ff8..0xa000].copy_from_slice(b"prefixab");
        put(&mut bytes, 0x4010, 0);
        let img = image(&bytes);
        let w = Windows {
            vm: Memory::new(&img, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        assert_eq!(
            w.partial_process_identity(&w.vm, process),
            Some(("prefixab".into(), 1234))
        );
        assert!(w.partial_process_identity(&w.vm, K + 0x1fd8).is_none()); // No first name byte.
        let (mut bytes, isf) = fixture();
        put(&mut bytes, 0x4008, 0); // PID absent, following name page readable.
        bytes[0xa008..0xa00d].copy_from_slice(b"name\0");
        let img = image(&bytes);
        let w = Windows {
            vm: Memory::new(&img, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        assert!(w.partial_process_identity(&w.vm, K + 0x1fd8).is_none());
    }
    #[test]
    fn procedure_classification_matches_the_actual_reference_generator() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/reference/parity/fixtures/gui-window-procedures.json"
        ))
        .unwrap();
        for c in vectors["cases"].as_array().unwrap() {
            let got = classify_window_procedure(c["value"].as_u64());
            assert_eq!(got.is_some(), c["retained"].as_bool().unwrap());
            assert_eq!(got.as_deref(), c["expected"].as_str());
        }
    }
    #[test]
    fn unreadable_procedure_preserves_window_row_and_marks_partial() {
        let (mut bytes, isf) = fixture();
        let window = K + 0x10f80;
        put(&mut bytes, 0x18f90, K + 0x12000); // head.pti
        put(&mut bytes, 0x18f98, K + 0x14000); // head.rpdesk
        put(&mut bytes, 0x1a000 + 376, K + 0x13000); // pti.ppi
        put(&mut bytes, 0x1b000, K + 0x2000); // ppi.Process
        put(&mut bytes, 0x1c000 + 40, K + 0x15000); // desktop.rpwinstaParent
        bytes[0x1d000..0x1d004].copy_from_slice(&1u32.to_le_bytes());
        let layout = gui_layout("gui-win10-15063-x64");
        put(&mut bytes, 0x19020, 0); // lpfnWndProc, next page after head
        let img = image(&bytes);
        let w = Windows {
            vm: Memory::new(&img, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        assert_eq!(
            w.window_record(&[], 0x1000, window, &layout).unwrap().1,
            "0x0"
        );
        drop(w);
        drop(img);
        put(&mut bytes, 0x19020, 0x1000);
        let img = image(&bytes);
        let w = Windows {
            vm: Memory::new(&img, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        assert!(w.window_record(&[], 0x1000, window, &layout).is_none());
        drop(w);
        drop(img);
        put(&mut bytes, 0x4000 + 17 * 8, 0); // Procedure page absent; process and session remain readable.
        let img = image(&bytes);
        let w = Windows {
            vm: Memory::new(&img, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        assert_eq!(
            w.window_record(&[], 0x1000, window, &layout).unwrap().1,
            "N/A"
        );
        let mut result = w.result(Plugin::WinWindows);
        let mut seen = HashSet::new();
        let mut rows = 0;
        w.walk_window_field(WindowWalk {
            job: &Job::default(),
            result: &mut result,
            processes: &[],
            dtb: 0x1000,
            field: window,
            window,
            station_name: "WinSta0",
            session_id: 1,
            desktop_name: "Default",
            layout: &layout,
            seen: &mut seen,
            rows: &mut rows,
        })
        .unwrap();
        assert_eq!(rows, 1);
        assert_eq!(result.rows[0][5], "N/A");
        assert_eq!(result.rows[0][6], "child");
        assert!(!result.complete);
        assert!(result.diagnostics.iter().any(|d| d.contains("Procedure")));
        // Newer layouts read the procedure through subPointer. Missing targets are absent, not invalid values.
        let mut newer = gui_layout("gui-win10-17134-x64");
        newer.window_subprocedure = Some(40);
        assert_eq!(
            w.window_procedure(&w.vm, window, &newer),
            Some("N/A".into())
        );
        drop(w);
        drop(img);
        // Reference follows readable subPointer addresses without imposing a kernel-only range.
        put(&mut bytes, 0x1000, 0x2003);
        put(&mut bytes, 0x18fa8, 0x2000);
        put(&mut bytes, 0xa0a0, 0x1001);
        let img = image(&bytes);
        let w = Windows {
            vm: Memory::new(&img, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        assert_eq!(
            w.window_procedure(&w.vm, window, &newer),
            Some("0x1001".into())
        );
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
