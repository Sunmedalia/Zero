//! Session address spaces, station chains and process identity for GUI objects.
use super::*;

impl Windows<'_> {
    pub(super) fn address_space(&self, process: &Process) -> Option<u64> {
        let user = self
            .number(process.address, "_EPROCESS", "Pcb.UserDirectoryTableBase")
            .unwrap_or(0)
            & self.vm.root_mask();
        let dtb = if process.dtb != 0 { process.dtb } else { user };
        (dtb != 0).then_some(dtb)
    }

    pub(super) fn process_memory_dtb(&self, dtb: u64) -> Option<Memory<'_>> {
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
    pub(super) fn session_kernel_pointer(
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

    pub(super) fn desktop_name(
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

    pub(super) fn process_identity(
        &self,
        memory: &Memory<'_>,
        process: u64,
    ) -> Option<(String, u64)> {
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

    pub(super) fn desktop_thread_in_session(
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

    pub(super) fn unreadable_process_id(
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

    pub(super) fn raw_pointer(&self, memory: &Memory<'_>, address: u64) -> Option<u64> {
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

    pub(super) fn thread_process(
        &self,
        memory: &Memory<'_>,
        thread: u64,
        process_offset: u64,
    ) -> Option<u64> {
        let process_info = self.raw_pointer(memory, add(thread, process_offset).ok()?)?;
        if !kernel(process_info) {
            return None;
        }
        // The reference follows ppi.Process even when the pointer is truncated.
        self.raw_pointer(memory, process_info)
    }

    pub(super) fn gui_symbol_table(&self) -> Option<&'static str> {
        let identity = self.version_identity();
        let value = |name| {
            identity[name]
                .as_u64()
                .and_then(|value| u16::try_from(value).ok())
        };
        if let (Some(major), Some(minor), Some(build)) =
            (value("major"), value("minor"), value("build"))
        {
            return gui_table(major, minor, build);
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

    pub(super) fn session_memberships(&self, job: &Job) -> Result<HashMap<u64, Vec<Process>>> {
        let (processes, _) = self.processes_partial(job)?;
        let mut sessions: HashMap<u64, Vec<Process>> = HashMap::new();
        for process in processes {
            if let Some(session_id) = self.process_session_id(&process) {
                sessions.entry(session_id).or_default().push(process);
            }
        }
        Ok(sessions)
    }

    pub(super) fn session_layers(&self, job: &Job) -> Result<HashMap<u64, Process>> {
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

    pub(super) fn process_session_id(&self, process: &Process) -> Option<u64> {
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

    pub(super) fn gui_u32(&self, address: u64, virtual_scan: bool) -> Option<u32> {
        let mut bytes = [0u8; 4];
        self.pool_read(add(address, SESSION_ID).ok()?, &mut bytes, virtual_scan)
            .ok()?;
        Some(u32::from_le_bytes(bytes))
    }

    /// The reference walk reads `self.rpwinstaNext` on every iteration, so a chain contributes at most two stations.
    pub(super) fn station_chain(&self, memory: &Memory<'_>, station: u64) -> Vec<u64> {
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

    pub(super) fn station_info(&self, memory: &Memory<'_>, station: u64) -> Option<(String, u32)> {
        let mut bytes = [0u8; 4];
        memory
            .read(add(station, SESSION_ID).ok()?, &mut bytes)
            .ok()?;
        let session_id = u32::from_le_bytes(bytes);
        if session_id >= 256 {
            return None;
        }
        let name = self.session_object_name(memory, station)?;
        if name.chars().count() <= 1 {
            return None;
        }
        Some((name, session_id))
    }

    pub(super) fn session_object_name(&self, memory: &Memory<'_>, body: u64) -> Option<String> {
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

    pub(super) fn session_unicode(&self, memory: &Memory<'_>, descriptor: u64) -> Result<String> {
        let length = memory.uint(descriptor, 2)?;
        let maximum = memory.uint(add(descriptor, 2)?, 2)?;
        if length == 0 || maximum == 0 || length > maximum {
            bail!("对象名称长度无效");
        }
        let buffer = memory.uint(
            add(descriptor, self.vm.isf.offset("_UNICODE_STRING", "Buffer")?)?,
            self.vm.pointer_size(),
        )?;
        let mut bytes = vec![0u8; length as usize];
        memory.read(buffer, &mut bytes)?;
        Ok(reference_unicode_name(&bytes))
    }
}
