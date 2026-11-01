//! Object validation behind pool scanning: reference type maps, process and thread checks.
use super::*;

impl Windows<'_> {
    pub(in crate::windows) fn reference_dispatch_drivers(
        &self,
        result: &mut Results,
        job: &Job,
    ) -> Result<Vec<(u64, u64)>> {
        let type_size = self.vm.isf.data["user_types"]["_DRIVER_OBJECT"]["size"]
            .as_u64()
            .context("缺少驱动对象大小")?;
        ensure!((16..=65536).contains(&type_size), "驱动对象大小无效");
        let types = self.pool_reference_type_map()?;
        let threshold = self.driver_kernel_start()?;
        let body_offset = self.vm.isf.offset("_OBJECT_HEADER", "Body")?;
        let mut out = Vec::new();
        let mut candidate_read_failures = 0usize;
        let constraints: Vec<_> = CONSTRAINTS
            .iter()
            .filter(|c| c.object_type == Some("Driver"))
            .collect();
        let (virtual_scan, bodies, notes) = self.scan_pool_objects(&constraints, type_size, job)?;
        for note in notes {
            Self::issue(result, "驱动池扫描", note);
        }
        for body in bodies {
            job.check()?;
            let valid = (|| -> Result<bool> {
                let header = body.checked_sub(body_offset).context("驱动对象头下溢")?;
                if self
                    .pool_reference_object_type(header, virtual_scan, &types)?
                    .as_deref()
                    != Some("Driver")
                {
                    return Ok(false);
                }
                self.reference_driver_start(body, virtual_scan, threshold)
            })();
            match valid {
                Ok(true) => {
                    ensure!(out.len() < MAX_OBJECTS, "驱动候选数量超限");
                    out.push((body, body));
                }
                Ok(false) => {}
                Err(_) => {
                    job.check()?;
                    // Invalid carved objects are expected during a tag
                    // scan; the reference rejects them without a row.
                    candidate_read_failures += 1;
                }
            }
        }
        result.kernel_identity["driver_pool"] = serde_json::json!({"source":"shared reference pool constraints and carving","offset_layer":if self.build_number()?>=10240 {"primary virtual"}else{"physical"},"driver_count":out.len(),"rejected_candidate_reads":candidate_read_failures,"driver_start":"8 readable bytes; zero or strictly above masked MmSystemRangeStart"});
        Ok(out)
    }
    pub(super) fn reference_driver_start(
        &self,
        body: u64,
        virtual_scan: bool,
        threshold: u64,
    ) -> Result<bool> {
        let offset = self.vm.isf.offset("_DRIVER_OBJECT", "DriverStart")?;
        // DriverScan requires eight readable bytes even for an x86 pointer.
        let mut bytes = [0; 8];
        self.pool_read(add(body, offset)?, &mut bytes, virtual_scan)?;
        let raw = if self.vm.pointer_size() == 4 {
            le_u32(&bytes, 0).map_or(0, u64::from)
        } else {
            u64::from_le_bytes(bytes)
        };
        let start = raw & self.driver_address_mask();
        Ok(start == 0 || start > threshold)
    }
    pub(in crate::windows) fn pool_read(
        &self,
        address: u64,
        out: &mut [u8],
        virtual_scan: bool,
    ) -> Result<()> {
        if virtual_scan {
            self.vm.read(address, out)
        } else {
            self.vm.image.read(address, out)
        }
    }

    pub(super) fn pool_read_padded(
        &self,
        mut address: u64,
        mut out: &mut [u8],
        virtual_scan: bool,
    ) -> Result<()> {
        while !out.is_empty() {
            let length = out.len().min(4096 - (address & 4095) as usize);
            let (chunk, rest) = out.split_at_mut(length);
            if self.pool_read(address, chunk, virtual_scan).is_err() {
                // Preserve captured bytes even if a physical segment ends part
                // way through this page. Unreadable bytes alone become zero.
                for (offset, byte) in chunk.iter_mut().enumerate() {
                    let mut value = [0];
                    *byte = if self
                        .pool_read(add(address, offset as u64)?, &mut value, virtual_scan)
                        .is_ok()
                    {
                        value[0]
                    } else {
                        0
                    };
                }
            }
            address = add(address, length as u64)?;
            out = rest;
        }
        Ok(())
    }

    pub(super) fn pool_value(
        &self,
        address: u64,
        structure: &str,
        field: &str,
        virtual_scan: bool,
    ) -> Result<u64> {
        if virtual_scan {
            self.number(address, structure, field)
        } else {
            self.physical_field(address, structure, field)
        }
    }

    pub(super) fn pool_object_valid(
        &self,
        constraint: &Constraint,
        body: u64,
        virtual_scan: bool,
        validation: &PoolValidation,
        result: &mut Results,
        diagnostics: &mut usize,
    ) -> Result<bool> {
        let valid = (|| -> Result<bool> {
            if let Some(kind) = constraint.object_type
                && !constraint.skip_type
            {
                let header = body
                    .checked_sub(self.vm.isf.offset("_OBJECT_HEADER", "Body")?)
                    .context("对象头下溢")?;
                if self
                    .pool_reference_object_type(header, virtual_scan, &validation.types)?
                    .as_deref()
                    != Some(kind)
                {
                    return Ok(false);
                }
            }
            Ok(match constraint.type_name {
                "_EPROCESS" => self.pool_process_valid(body, virtual_scan, None)?,
                "_ETHREAD" => self.pool_thread_valid(body, virtual_scan, None)?,
                "_FILE_OBJECT" => {
                    let length =
                        self.pool_value(body, "_FILE_OBJECT", "FileName.Length", virtual_scan)?;
                    let buffer =
                        self.pool_value(body, "_FILE_OBJECT", "FileName.Buffer", virtual_scan)?;
                    length > 0 && self.address_readable(buffer)
                }
                _ => true,
            })
        })();
        match valid {
            Ok(valid) => Ok(valid),
            Err(error) => {
                self.pool_note(
                    result,
                    diagnostics,
                    "pool object",
                    format!("{body:#x}: {error:#}"),
                );
                Ok(false)
            }
        }
    }

    pub(super) fn pool_reference_unicode(&self, descriptor: u64) -> Result<String> {
        let length = self.vm.uint(descriptor, 2)?;
        let buffer = self.pool_reference_pointer(self.vm.pointer(add(
            descriptor,
            self.vm.isf.offset("_UNICODE_STRING", "Buffer")?,
        )?)?);
        let mut bytes = vec![0; usize::try_from(length)?];
        self.vm.read(buffer, &mut bytes)?;
        Ok(windowstations::reference_unicode_name(&bytes))
    }

    pub(super) fn pool_reference_type_map(&self) -> Result<BTreeMap<u64, String>> {
        let mut types = BTreeMap::new();
        if !self.vm.isf.has_field("_OBJECT_HEADER", "TypeIndex") {
            return Ok(types);
        }
        let table = self
            .symbol("ObTypeIndexTable")
            .or_else(|_| self.symbol("ObpObjectTypes"))?;
        if !self.address_readable(table) {
            return Ok(types);
        }
        // Handles.get_type_map reads 100 pointers and stops at the first null
        // after index zero. An unreadable name skips only that index; exported
        // type variables do not provide a fallback in this reference path.
        for index in 0..100 {
            let pointer = self.pool_reference_pointer(
                self.vm
                    .pointer(add(table, index * self.vm.pointer_size() as u64)?)?,
            );
            if index > 0 && pointer == 0 {
                break;
            }
            if let Ok(name) = self
                .field(pointer, "_OBJECT_TYPE", "Name")
                .and_then(|descriptor| self.pool_reference_unicode(descriptor))
            {
                types.insert(index, name);
            }
        }
        Ok(types)
    }

    pub(super) fn pool_reference_object_type(
        &self,
        header: u64,
        virtual_scan: bool,
        types: &BTreeMap<u64, String>,
    ) -> Result<Option<String>> {
        if self.vm.isf.has_field("_OBJECT_HEADER", "TypeIndex") {
            let encoded = self.pool_value(header, "_OBJECT_HEADER", "TypeIndex", virtual_scan)?;
            let index = if let Ok(cookie_address) = self.symbol("ObHeaderCookie") {
                let cookie = self.vm.uint(cookie_address, 1)?;
                ((header >> 8) ^ cookie ^ encoded) & 0xff
            } else {
                encoded
            };
            return Ok(types.get(&index).cloned());
        }
        let pointer = self.pool_reference_pointer(self.pool_value(
            header,
            "_OBJECT_HEADER",
            "Type",
            virtual_scan,
        )?);
        let descriptor = self.field(pointer, "_OBJECT_TYPE", "Name")?;
        let length = self.vm.uint(descriptor, 2)?;
        if length == 0 || length > 128 {
            return Ok(None);
        }
        let name = self.pool_reference_unicode(descriptor)?;
        Ok((!name.is_empty() && name.chars().count() <= 128).then_some(name))
    }

    pub(super) fn address_readable(&self, address: u64) -> bool {
        self.vm
            .translate(self.pool_reference_pointer(address))
            .is_ok_and(|physical| self.vm.image.read(physical, &mut [0]).is_ok())
    }

    pub(super) fn pool_reference_pointer(&self, value: u64) -> u64 {
        if self.vm.pointer_size() == 4 {
            value & 0xffff_ffff
        } else {
            let value = value & 0xffff_ffff_ffff;
            if value & (1 << 47) != 0 {
                value | 0xffff_0000_0000_0000
            } else {
                value
            }
        }
    }

    pub(super) fn pool_year(ticks: i64) -> Option<i64> {
        let seconds = ticks.div_euclid(10_000_000);
        if seconds == 0 {
            return None;
        }
        let stamp = crate::report::utc(seconds - 11_644_473_600);
        let year = stamp.split('-').next()?.parse().ok()?;
        (1..=9999).contains(&year).then_some(year)
    }

    pub(super) fn pool_process_valid(
        &self,
        body: u64,
        virtual_scan: bool,
        current_year: Option<i64>,
    ) -> Result<bool> {
        let layout = self.vm.isf.layout("_EPROCESS", "ImageFileName")?;
        let mut bytes = vec![0u8; usize::try_from(layout.size)?];
        self.pool_read(add(body, layout.offset)?, &mut bytes, virtual_scan)?;
        let name = windowstations::reference_process_name(&bytes);
        if name.is_empty() {
            return Ok(false);
        }
        let pid = self.pool_typed_value(body, "_EPROCESS", "UniqueProcessId", virtual_scan)?;
        if pid == 0 || pid % 4 != 0 || pid > 0xffff_fffc {
            return Ok(false);
        }
        let system = name == "System" && pid == 4;
        if !system {
            let created = self.pool_value(body, "_EPROCESS", "CreateTime", virtual_scan)? as i64;
            let Some(year) = Self::pool_year(created) else {
                return Ok(false);
            };
            let current_year = current_year.map_or_else(current_local_year, Ok)?;
            if !(1998 < year && year < current_year + 10) {
                return Ok(false);
            }
            let exited = self.pool_value(body, "_EPROCESS", "ExitTime", virtual_scan)? as i64;
            if exited != 0
                && let Some(exit_year) = Self::pool_year(exited)
                && (!(1998 < exit_year && exit_year < current_year + 10)
                    || exited.div_euclid(10_000_000) < created.div_euclid(10_000_000))
            {
                return Ok(false);
            }
        }
        let dtb =
            self.pool_typed_value(body, "_EPROCESS", "Pcb.DirectoryTableBase", virtual_scan)?;
        if dtb == 0 || dtb & !0xfff == 0 {
            return Ok(false);
        }
        let flink =
            self.pool_typed_value(body, "_EPROCESS", "ThreadListHead.Flink", virtual_scan)?;
        let blink =
            self.pool_typed_value(body, "_EPROCESS", "ThreadListHead.Blink", virtual_scan)?;
        Ok(flink >= 0x8000_0000 && blink >= 0x8000_0000)
    }

    pub(super) fn pool_thread_valid(
        &self,
        body: u64,
        virtual_scan: bool,
        current_year: Option<i64>,
    ) -> Result<bool> {
        let pid = self.pool_typed_value(body, "_ETHREAD", "Cid.UniqueProcess", virtual_scan)?;
        let tid = self.pool_typed_value(body, "_ETHREAD", "Cid.UniqueThread", virtual_scan)?;
        if pid % 4 != 0 || tid % 4 != 0 {
            return Ok(false);
        }
        if pid != 4 {
            let mut created = self.pool_value(body, "_ETHREAD", "CreateTime", virtual_scan)? as i64;
            if self.vm.isf.has_field("_ETHREAD", "ThreadsProcess") {
                created >>= 3;
            }
            let Some(year) = Self::pool_year(created) else {
                return Ok(false);
            };
            let current_year = current_year.map_or_else(current_local_year, Ok)?;
            if !(1998 < year && year < current_year + 10) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(super) fn pool_typed_value(
        &self,
        body: u64,
        ty: &str,
        field: &str,
        virtual_scan: bool,
    ) -> Result<u64> {
        let raw = self.pool_value(body, ty, field, virtual_scan)?;
        let kind = self.vm.isf.field(ty, field)?["type"]["kind"].as_str();
        // EPROCESS's array DTB is cast to a native pointer by the reference.
        if kind == Some("pointer") || (field == "Pcb.DirectoryTableBase" && kind == Some("array")) {
            Ok(self.pool_reference_pointer(raw))
        } else {
            Ok(raw)
        }
    }

    pub(super) fn pool_scanner_name(
        &self,
        constraint: &Constraint,
        body: u64,
        virtual_scan: bool,
    ) -> Result<Option<String>> {
        match constraint.object_type {
            Some("Process") => {
                let layout = self.vm.isf.layout("_EPROCESS", "ImageFileName")?;
                let mut bytes = vec![0u8; usize::try_from(layout.size)?];
                self.pool_read(add(body, layout.offset)?, &mut bytes, virtual_scan)?;
                let end = bytes
                    .iter()
                    .position(|byte| *byte == 0)
                    .unwrap_or(bytes.len());
                Ok(Some(String::from_utf8_lossy(&bytes[..end]).into_owned()))
            }
            Some("File") => {
                // The reference generator skips a file whose name faults and
                // continues scanning. Propagating this read error truncates all
                // later pool observations, including unrelated object types.
                let name = (|| -> Result<String> {
                    let length =
                        self.pool_value(body, "_FILE_OBJECT", "FileName.Length", virtual_scan)?;
                    let buffer = self.pool_reference_pointer(self.pool_value(
                        body,
                        "_FILE_OBJECT",
                        "FileName.Buffer",
                        virtual_scan,
                    )?);
                    let mut bytes = vec![0u8; usize::try_from(length)?];
                    self.vm.read(buffer, &mut bytes)?;
                    Ok(windowstations::reference_unicode_name(&bytes))
                })();
                Ok(name.ok())
            }
            _ => Ok(Some(String::new())),
        }
    }
}
