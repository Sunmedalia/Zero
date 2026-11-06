//! Desktop window trees: bounded walks and per-window records.
use super::*;

impl Windows<'_> {
    pub(super) fn desktop_windows(&self, request: DesktopWindows<'_>) -> Result<usize> {
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

    pub(super) fn walk_window_field(&self, walk: WindowWalk<'_>) -> Result<()> {
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

    pub(super) fn window_record(
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

    pub(super) fn window_session(
        &self,
        processes: &[Process],
        dtb: u64,
        window: u64,
    ) -> Option<u32> {
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

    pub(super) fn window_procedure(
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
    pub(super) fn window_process(
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

    pub(super) fn partial_process_identity(
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
        let mut got = 0usize;
        while got < length {
            if memory
                .read(name_at + got as u64, bytes.get_mut(got..got + 1)?)
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
        let name = reference_process_name(bytes.get(..got)?);
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

    pub(super) fn window_name(
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
        self.utf16_exact(processes, dtb, buffer, usize::try_from(length).ok()?)
    }

    pub(super) fn utf16_exact(
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
            return Some(crate::bytes::utf16_lossy(&data));
        }
        None
    }

    pub(super) fn utf16_capped(
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
}
