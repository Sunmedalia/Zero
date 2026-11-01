use super::*;
impl Windows<'_> {
    pub(super) fn registry(&self, p: Plugin, options: &Options, job: &Job) -> Result<Results> {
        let mut r = self.result(p);
        let (hives, diagnostics) = self.list_partial(
            self.symbol("CmpHiveListHead")?,
            self.vm.isf.offset("_CMHIVE", "HiveList")?,
            job,
        )?;
        r.complete = diagnostics.is_empty();
        r.diagnostics = diagnostics;
        if p == Plugin::WinHivelist {
            for h in hives {
                job.check()?;
                let mut path = String::new();
                for field in ["FileFullPath", "FileUserName", "HiveRootPath"] {
                    if self.vm.isf.field("_CMHIVE", field).is_err() {
                        continue;
                    }
                    match self.vm.unicode(self.field(h, "_CMHIVE", field)?) {
                        Ok(name) if !name.is_empty() => {
                            path = name;
                            break;
                        }
                        Ok(_) => {}
                        Err(e) => Self::issue(&mut r, format!("{h:#x} {field}"), e),
                    }
                }
                r.rows.push(vec![hex(h), path]);
            }
            return Ok(r);
        }
        let hive = options.hive.context("注册表键查询需要 hive 地址")?;
        ensure!(hives.contains(&hive), "hive 不在已验证列表中");
        let hhive = self.field(hive, "_CMHIVE", "Hive")?;
        let cell = self.registry_index(hhive, &options.key, job)?;
        let node = self.cell(hhive, cell)?;
        ensure!(&node[..2] == b"nk", "非注册表键节点");
        let name = self.key_name(&node)?;
        let time = objects::physical_number(self.vm.isf, &node, "_CM_KEY_NODE", "LastWriteTime")?;
        r.rows.push(vec![
            hex(hive),
            options.key.clone(),
            "Key".into(),
            name,
            String::new(),
            String::new(),
            filetime(time),
        ]);
        for child in self.subkeys(hhive, &node, job)? {
            job.check()?;
            let read = (|| -> Result<Vec<String>> {
                let n = self.cell(hhive, child)?;
                Ok(vec![
                    hex(hive),
                    options.key.clone(),
                    "SubKey".into(),
                    self.key_name(&n)?,
                    String::new(),
                    String::new(),
                    filetime(objects::physical_number(
                        self.vm.isf,
                        &n,
                        "_CM_KEY_NODE",
                        "LastWriteTime",
                    )?),
                ])
            })();
            match read {
                Ok(row) => r.rows.push(row),
                Err(e) => Self::issue(&mut r, format!("hive {hive:#x} cell {child:#x}"), e),
            }
        }
        let list_offset = usize::try_from(self.vm.isf.offset("_CM_KEY_NODE", "ValueList")?)?;
        let list = node.get(list_offset..).context("注册表 ValueList 截断")?;
        let count = objects::physical_number(self.vm.isf, list, "_CHILD_LIST", "Count")?;
        let index = u32::try_from(objects::physical_number(
            self.vm.isf,
            list,
            "_CHILD_LIST",
            "List",
        )?)?;
        ensure!(count <= MAX_OBJECTS as u64, "注册表值超限");
        if count > 0 {
            let indices = self.cell(hhive, index)?;
            ensure!(
                usize::try_from(count)? * 4 <= indices.len(),
                "注册表值列表截断"
            );
            for chunk in indices[..usize::try_from(count)? * 4].chunks_exact(4) {
                job.check()?;
                let index = u32::from_le_bytes(chunk.try_into()?);
                let read = self.value(hhive, index, job).map(|(name, ty, data)| {
                    vec![
                        hex(hive),
                        options.key.clone(),
                        "Value".into(),
                        name,
                        ty,
                        data,
                        filetime(time),
                    ]
                });
                match read {
                    Ok(row) => r.rows.push(row),
                    Err(e) => Self::issue(&mut r, format!("hive {hive:#x} value {index:#x}"), e),
                }
            }
        }
        Ok(r)
    }
    pub(super) fn autoruns(&self, options: &Options, job: &Job) -> Result<Results> {
        let mut result = self.result(Plugin::WinAutoruns);
        let hives = self.registry(Plugin::WinHivelist, &Options::default(), job)?;
        result.complete = hives.complete;
        result.diagnostics = hives.diagnostics;
        if let Some(selected) = options.hive {
            ensure!(
                hives.rows.iter().any(|row| u64::from_str_radix(
                    row[0].trim_start_matches("0x"),
                    16
                )
                .ok()
                    == Some(selected)),
                "hive 不在已验证列表中"
            );
        }
        for hive in hives.rows {
            job.check()?;
            let address = u64::from_str_radix(hive[0].trim_start_matches("0x"), 16)?;
            if options.hive.is_some_and(|selected| selected != address) {
                continue;
            }
            let lower = hive[1].to_ascii_lowercase();
            let mut keys = Vec::new();
            if lower.ends_with("software") || lower.ends_with("ntuser.dat") {
                for prefix in [
                    "Microsoft\\Windows\\CurrentVersion",
                    "Wow6432Node\\Microsoft\\Windows\\CurrentVersion",
                ] {
                    for suffix in ["Run", "RunOnce"] {
                        keys.push(format!("{prefix}\\{suffix}"));
                    }
                }
                if lower.ends_with("software") {
                    keys.push("Microsoft\\Windows NT\\CurrentVersion\\Winlogon".into());
                    let ifeo =
                        "Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
                    if let Some(parent) = self.optional_registry(address, ifeo, job, &mut result)? {
                        for row in parent.rows.into_iter().filter(|row| row[2] == "SubKey") {
                            keys.push(format!("{ifeo}\\{}", row[3]));
                        }
                    }
                }
            } else if lower.ends_with("system")
                && let Some(select) = self.optional_registry(address, "Select", job, &mut result)?
            {
                let current = select
                    .rows
                    .iter()
                    .find(|row| row[2] == "Value" && row[3].eq_ignore_ascii_case("Current"));
                if let Some(current) = current {
                    let n = current[5]
                        .parse::<u32>()
                        .context("Select.Current 不是 DWORD")?;
                    ensure!((1..=999).contains(&n), "Select.Current 越界");
                    let services = format!("ControlSet{n:03}\\Services");
                    if let Some(parent) =
                        self.optional_registry(address, &services, job, &mut result)?
                    {
                        for row in parent.rows.into_iter().filter(|row| row[2] == "SubKey") {
                            keys.push(format!("{services}\\{}", row[3]));
                        }
                    }
                } else {
                    Self::issue(&mut result, hex(address), "SYSTEM hive 缺少 Select.Current");
                }
            }
            for key in keys {
                job.check()?;
                if let Some(query) = self.optional_registry(address, &key, job, &mut result)? {
                    for row in query.rows.into_iter().filter(|row| row[2] == "Value") {
                        let name = row[3].to_ascii_lowercase();
                        if key.ends_with("Winlogon")
                            && !["shell", "userinit", "taskman"].contains(&name.as_str())
                        {
                            continue;
                        }
                        if key.contains("Image File Execution Options")
                            && !["debugger", "globalflag", "verifierdlls"].contains(&name.as_str())
                        {
                            continue;
                        }
                        if key.contains("\\Services\\")
                            && !["imagepath", "start", "type", "objectname"]
                                .contains(&name.as_str())
                        {
                            continue;
                        }
                        result.rows.push(row);
                    }
                }
            }
        }
        result.diagnostics.sort();
        result.diagnostics.dedup();
        result.kernel_identity["coverage"] = serde_json::json!(
            "Run/RunOnce, Winlogon, IFEO, current ControlSet services; not all persistence mechanisms"
        );
        Ok(result)
    }
    pub(super) fn optional_registry(
        &self,
        hive: u64,
        key: &str,
        job: &Job,
        result: &mut Results,
    ) -> Result<Option<Results>> {
        let query = self.registry(
            Plugin::WinPrintkey,
            &Options {
                hive: Some(hive),
                key: key.into(),
                ..Default::default()
            },
            job,
        );
        match query {
            Ok(query) => {
                if !query.complete {
                    result.complete = false;
                    result.diagnostics.extend(query.diagnostics.clone());
                }
                Ok(Some(query))
            }
            Err(e) => {
                job.check()?;
                if !e.to_string().starts_with("注册表键不存在:") {
                    Self::issue(result, format!("hive {hive:#x} {key}"), format!("{e:#}"));
                }
                Ok(None)
            }
        }
    }
    fn cell_address(&self, hive: u64, index: u32) -> Result<u64> {
        ensure!(index != u32::MAX, "无效 hive cell");
        let storage = (index >> 31) as u64;
        let index = u64::from(index & 0x7fff_ffff);
        let dual_size = self.vm.isf.data["user_types"]["_DUAL"]["size"]
            .as_u64()
            .context("缺少 _DUAL")?;
        let dual = add(self.field(hive, "_HHIVE", "Storage")?, storage * dual_size)?;
        ensure!(
            index < self.number(dual, "_DUAL", "Length")?,
            "hive cell 越界"
        );
        let directory = self.number(dual, "_DUAL", "Map")?;
        let table = self.vm.pointer(add(
            self.field(directory, "_HMAP_DIRECTORY", "Directory")?,
            (index >> 21) * self.vm.pointer_size() as u64,
        )?)?;
        ensure!(table != 0, "hive 映射表缺失");
        let entry_size = self.vm.isf.data["user_types"]["_HMAP_ENTRY"]["size"]
            .as_u64()
            .context("缺少 _HMAP_ENTRY")?;
        let entry = add(
            self.field(table, "_HMAP_TABLE", "Table")?,
            ((index >> 12) & 511) * entry_size,
        )?;
        let block = if self
            .vm
            .isf
            .field("_HMAP_ENTRY", "PermanentBinAddress")
            .is_ok()
        {
            add(
                self.number(entry, "_HMAP_ENTRY", "PermanentBinAddress")? & !15,
                self.number(entry, "_HMAP_ENTRY", "BlockOffset")?,
            )?
        } else {
            self.number(entry, "_HMAP_ENTRY", "BlockAddress")? & !15
        };
        add(block, index & 4095)
    }
    pub(super) fn cell(&self, hive: u64, index: u32) -> Result<Vec<u8>> {
        let address = self.cell_address(hive, index)?;
        let length = u32::try_from(self.vm.uint(address, 4)?)? as i32;
        ensure!(
            length < 0,
            "hive cell 未分配 index={index:#x} address={address:#x} length={length}"
        );
        let length = length.unsigned_abs() as usize;
        ensure!((8..=1024 * 1024).contains(&length), "hive cell 大小无效");
        let mut out = vec![0; length - 4];
        let mut copied = 0;
        while copied < out.len() {
            let cell_index = index
                .checked_add(4)
                .and_then(|i| i.checked_add(u32::try_from(copied).ok()?))
                .context("hive cell 索引溢出")?;
            ensure!(cell_index >> 31 == index >> 31, "hive cell 跨存储边界");
            let count = (4096 - (cell_index as usize & 4095)).min(out.len() - copied);
            self.vm.read(
                self.cell_address(hive, cell_index)?,
                &mut out[copied..copied + count],
            )?;
            copied += count;
        }
        Ok(out)
    }
    pub(super) fn key_name(&self, node: &[u8]) -> Result<String> {
        ensure!(node.len() >= 2 && &node[..2] == b"nk", "无效 nk cell");
        let flags = objects::physical_number(self.vm.isf, node, "_CM_KEY_NODE", "Flags")?;
        let len = usize::try_from(objects::physical_number(
            self.vm.isf,
            node,
            "_CM_KEY_NODE",
            "NameLength",
        )?)?;
        let offset = usize::try_from(self.vm.isf.offset("_CM_KEY_NODE", "Name")?)?;
        decode_name(
            node.get(offset..offset + len).context("键名截断")?,
            flags & 0x20 != 0,
        )
    }
    pub(super) fn subkeys(&self, hive: u64, node: &[u8], job: &Job) -> Result<Vec<u32>> {
        let counts = usize::try_from(self.vm.isf.offset("_CM_KEY_NODE", "SubKeyCounts")?)?;
        let lists = usize::try_from(self.vm.isf.offset("_CM_KEY_NODE", "SubKeyLists")?)?;
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for storage in 0..2 {
            let count = u32::from_le_bytes(
                node.get(counts + storage * 4..counts + storage * 4 + 4)
                    .context("子键计数截断")?
                    .try_into()?,
            );
            if count == 0 {
                continue;
            }
            ensure!(count <= MAX_OBJECTS as u32, "子键超限");
            let index = u32::from_le_bytes(
                node.get(lists + storage * 4..lists + storage * 4 + 4)
                    .context("子键索引截断")?
                    .try_into()?,
            );
            let before = out.len();
            self.subkey_list(hive, index, &mut out, &mut seen, job)?;
            ensure!(out.len() - before == count as usize, "子键计数不一致");
        }
        Ok(out)
    }
    fn subkey_list(
        &self,
        hive: u64,
        index: u32,
        out: &mut Vec<u32>,
        seen: &mut HashSet<u32>,
        job: &Job,
    ) -> Result<()> {
        job.check()?;
        ensure!(
            seen.insert(index) && seen.len() <= MAX_OBJECTS,
            "子键索引循环/超限"
        );
        let cell = self.cell(hive, index)?;
        ensure!(cell.len() >= 4, "子键列表截断");
        let count = u16::from_le_bytes(cell[2..4].try_into()?) as usize;
        let sig = &cell[..2];
        let width = match sig {
            b"lf" | b"lh" => 8,
            b"li" | b"ri" => 4,
            _ => bail!("未知子键索引类型"),
        };
        ensure!(4 + count * width <= cell.len(), "子键索引越界");
        for chunk in cell[4..4 + count * width].chunks_exact(width) {
            job.check()?;
            let child = u32::from_le_bytes(chunk[..4].try_into()?);
            if sig == b"ri" {
                self.subkey_list(hive, child, out, seen, job)?;
            } else {
                out.push(child);
            }
        }
        Ok(())
    }
    /// Read only value metadata: a missing unrelated data page must not
    /// prevent locating a different named value in the same key.
    pub(super) fn value_name(&self, hive: u64, index: u32) -> Result<String> {
        self.value_cell_name(&self.cell(hive, index)?)
    }
    fn value_cell_name(&self, cell: &[u8]) -> Result<String> {
        ensure!(cell.len() >= 2 && &cell[..2] == b"vk", "非 vk cell");
        let get = |f| objects::physical_number(self.vm.isf, cell, "_CM_KEY_VALUE", f);
        let len = usize::try_from(get("NameLength")?)?;
        let offset = usize::try_from(self.vm.isf.offset("_CM_KEY_VALUE", "Name")?)?;
        decode_name(
            cell.get(offset..offset + len).context("值名截断")?,
            get("Flags")? & 1 != 0,
        )
    }
    /// 读取 `vk` 值单元的原始字节（名称、类型、数据），供需要二进制数据的
    /// 凭证分析使用；`value` 是它的格式化视图。
    pub(super) fn value_bytes(
        &self,
        hive: u64,
        index: u32,
        job: &Job,
    ) -> Result<(String, u32, Vec<u8>)> {
        let cell = self.cell(hive, index)?;
        let name = self.value_cell_name(&cell)?;
        let get = |f| objects::physical_number(self.vm.isf, &cell, "_CM_KEY_VALUE", f);
        let length = u32::try_from(get("DataLength")?)?;
        let inline = length & 0x8000_0000 != 0;
        let length = (length & 0x7fff_ffff) as usize;
        ensure!(length <= 1024 * 1024, "注册表值超过 1 MiB");
        let bytes = if inline {
            ensure!(length <= 4, "内联值长度无效");
            u32::try_from(get("Data")?)?.to_le_bytes()[..length].to_vec()
        } else if length == 0 {
            Vec::new()
        } else {
            let data = self.cell(hive, u32::try_from(get("Data")?)?)?;
            if length <= data.len() {
                data[..length].to_vec()
            } else {
                segmented_value(&data, length, |index| {
                    job.check()?;
                    self.cell(hive, index)
                })?
            }
        };
        let ty = u32::try_from(get("Type")?)?;
        Ok((name, ty, bytes))
    }
    /// 读取 `nk` 键单元的 class 数据（SAM bootkey 片段存放位置）。
    pub(super) fn key_class(&self, hive: u64, key_index: u32) -> Result<Vec<u8>> {
        let node = self.cell(hive, key_index)?;
        ensure!(node.len() >= 2 && &node[..2] == b"nk", "非 nk cell");
        let length = usize::try_from(objects::physical_number(
            self.vm.isf,
            &node,
            "_CM_KEY_NODE",
            "ClassLength",
        )?)?;
        if length == 0 {
            return Ok(Vec::new());
        }
        ensure!(length <= 4096, "注册表键 class 超长");
        let class = u32::try_from(objects::physical_number(
            self.vm.isf,
            &node,
            "_CM_KEY_NODE",
            "Class",
        )?)?;
        ensure!(class != 0, "注册表键 class 缺失");
        let data = self.cell(hive, class)?;
        ensure!(length <= data.len(), "注册表键 class 截断");
        Ok(data[..length].to_vec())
    }
    /// 在父键下按名称（大小写不敏感）查找子键 cell index。
    pub(super) fn subkey_named(
        &self,
        hive: u64,
        parent: u32,
        name: &str,
        job: &Job,
    ) -> Result<u32> {
        let node = self.cell(hive, parent)?;
        for index in self.subkeys(hive, &node, job)? {
            let n = self.cell(hive, index)?;
            if self.key_name(&n)?.eq_ignore_ascii_case(name) {
                return Ok(index);
            }
        }
        bail!("子键不存在: {name}")
    }
    /// 键的 ValueList 索引（cell index 序列）。
    pub(super) fn value_indices(&self, hive: u64, key: u32) -> Result<Vec<u32>> {
        let node = self.cell(hive, key)?;
        let list_offset = usize::try_from(self.vm.isf.offset("_CM_KEY_NODE", "ValueList")?)?;
        let list = node.get(list_offset..).context("注册表 ValueList 截断")?;
        let count = usize::try_from(objects::physical_number(
            self.vm.isf,
            list,
            "_CHILD_LIST",
            "Count",
        )?)?;
        ensure!(count <= MAX_OBJECTS, "注册表值超限");
        if count == 0 {
            return Ok(Vec::new());
        }
        let index = u32::try_from(objects::physical_number(
            self.vm.isf,
            list,
            "_CHILD_LIST",
            "List",
        )?)?;
        let indices = self.cell(hive, index)?;
        ensure!(count * 4 <= indices.len(), "注册表值列表截断");
        Ok(indices[..count * 4]
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| u32::from_le_bytes(*c))
            .collect())
    }
    /// 键的具名值原始数据（大小写不敏感）。
    pub(super) fn key_value_bytes(
        &self,
        hive: u64,
        key: u32,
        name: &str,
        job: &Job,
    ) -> Result<Option<Vec<u8>>> {
        for index in self.value_indices(hive, key)? {
            job.check()?;
            let (value_name, _, bytes) = self.value_bytes(hive, index, job)?;
            if value_name.eq_ignore_ascii_case(name) {
                return Ok(Some(bytes));
            }
        }
        Ok(None)
    }
    /// 键的第一个（默认）值原始数据。
    pub(super) fn key_first_value(&self, hive: u64, key: u32, job: &Job) -> Result<Vec<u8>> {
        let indices = self.value_indices(hive, key)?;
        let index = indices.first().context("注册表键没有值")?;
        self.value_bytes(hive, *index, job)
            .map(|(_, _, bytes)| bytes)
    }
    /// 键的全部值（名称、原始数据）。
    pub(super) fn key_values(
        &self,
        hive: u64,
        key: u32,
        job: &Job,
    ) -> Result<Vec<(String, Vec<u8>)>> {
        let mut out = Vec::new();
        for index in self.value_indices(hive, key)? {
            job.check()?;
            let (name, _, bytes) = self.value_bytes(hive, index, job)?;
            out.push((name, bytes));
        }
        Ok(out)
    }
    /// Resolve a named path while preserving diagnostics for unreadable siblings.
    pub(super) fn registry_index_partial(
        &self,
        hive: u64,
        mut cell: u32,
        key: &str,
        job: &Job,
        r: &mut Results,
        case_sensitive: bool,
    ) -> Result<u32> {
        for part in key.split('\\').filter(|s| !s.is_empty()) {
            job.check()?;
            let node = self.cell(hive, cell)?;
            let mut found = None;
            for index in self.subkeys(hive, &node, job)? {
                job.check()?;
                let name = self.cell(hive, index).and_then(|n| self.key_name(&n));
                match name {
                    Ok(name)
                        if if case_sensitive {
                            name == part
                        } else {
                            name.eq_ignore_ascii_case(part)
                        } =>
                    {
                        ensure!(found.is_none(), "注册表键名称歧义");
                        found = Some(index);
                    }
                    Ok(_) => {}
                    Err(e) => {
                        Self::issue(r, format!("registry sibling {index:#x}"), format!("{e:#}"))
                    }
                }
            }
            cell = found.with_context(|| format!("注册表键不存在: {part}"))?;
        }
        Ok(cell)
    }
    /// Base blocks may be paged out while their hive bins remain resident.
    /// Match the registry layer's conventional root only after validating an nk cell.
    pub(super) fn registry_root(&self, hive: u64) -> Result<u32> {
        let recorded = (|| -> Result<u32> {
            let base = self.number(hive, "_HHIVE", "BaseBlock")?;
            ensure!(base != 0, "hive BaseBlock 为空");
            if self.vm.isf.field("_HBASE_BLOCK", "Signature").is_ok() {
                ensure!(
                    self.number(base, "_HBASE_BLOCK", "Signature")? == 0x6667_6572,
                    "hive base block Signature 非 regf"
                );
            }
            Ok(u32::try_from(self.number(
                base,
                "_HBASE_BLOCK",
                "RootCell",
            )?)?)
        })();
        match recorded {
            Ok(root) => Ok(root),
            Err(original) => {
                self.cell(hive, 0x20)
                    .and_then(|node| self.key_name(&node))
                    .with_context(|| format!("hive 根回退校验失败（BaseBlock: {original:#}）"))?;
                Ok(0x20)
            }
        }
    }
    /// 从 hive 根开始按 `a\b\c` 路径解析键并返回其 cell index。
    pub(super) fn registry_index(&self, hive: u64, key: &str, job: &Job) -> Result<u32> {
        let mut cell = self.registry_root(hive)?;
        for part in key.split(['\\', '/']).filter(|s| !s.is_empty()) {
            job.check()?;
            let node = self.cell(hive, cell)?;
            let mut found = None;
            for index in self.subkeys(hive, &node, job)? {
                let n = self.cell(hive, index)?;
                if self.key_name(&n)?.eq_ignore_ascii_case(part) {
                    ensure!(found.is_none(), "注册表键名称歧义");
                    found = Some(index);
                }
            }
            cell = found.with_context(|| format!("注册表键不存在: {part}"))?;
        }
        Ok(cell)
    }
    fn value(&self, hive: u64, index: u32, job: &Job) -> Result<(String, String, String)> {
        let (name, ty, bytes) = self.value_bytes(hive, index, job)?;
        let (label, data) = match ty {
            1 | 2 | 7 => (
                match ty {
                    1 => "REG_SZ",
                    2 => "REG_EXPAND_SZ",
                    _ => "REG_MULTI_SZ",
                }
                .to_string(),
                decode_name(&bytes, false)?
                    .trim_end_matches('\0')
                    .to_string(),
            ),
            4 => {
                ensure!(bytes.len() == 4, "DWORD 长度无效");
                (
                    "REG_DWORD".into(),
                    u32::from_le_bytes(bytes.as_slice().try_into()?).to_string(),
                )
            }
            11 => {
                ensure!(bytes.len() == 8, "QWORD 长度无效");
                (
                    "REG_QWORD".into(),
                    u64::from_le_bytes(bytes.as_slice().try_into()?).to_string(),
                )
            }
            _ => (
                format!("REG_TYPE_{ty}"),
                bytes.iter().map(|b| format!("{b:02x}")).collect(),
            ),
        };
        Ok((name, label, data))
    }
}
fn decode_name(bytes: &[u8], compressed: bool) -> Result<String> {
    if compressed {
        Ok(bytes.iter().map(|b| char::from(*b)).collect())
    } else {
        ensure!(bytes.len().is_multiple_of(2), "UTF-16 长度无效");
        Ok(String::from_utf16_lossy(
            &bytes
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect::<Vec<_>>(),
        ))
    }
}

fn segmented_value(
    header: &[u8],
    length: usize,
    mut cell: impl FnMut(u32) -> Result<Vec<u8>>,
) -> Result<Vec<u8>> {
    const SEGMENT: usize = 0x3fd8;
    ensure!(
        length > SEGMENT && length <= 1024 * 1024 && header.len() >= 8 && &header[..2] == b"db",
        "注册表分段值头部无效"
    );
    let count = u16::from_le_bytes(header[2..4].try_into()?) as usize;
    ensure!(count == length.div_ceil(SEGMENT), "注册表分段计数不一致");
    let list_index = u32::from_le_bytes(header[4..8].try_into()?);
    let list = cell(list_index)?;
    ensure!(count * 4 <= list.len(), "注册表分段索引截断");
    let mut seen = HashSet::from([list_index]);
    let mut out = Vec::with_capacity(length);
    for chunk in list[..count * 4].chunks_exact(4) {
        let index = u32::from_le_bytes(chunk.try_into()?);
        ensure!(seen.insert(index), "注册表分段索引重复/循环");
        let data = cell(index)?;
        let needed = (length - out.len()).min(SEGMENT);
        ensure!(data.len() >= needed, "注册表分段数据截断");
        out.extend_from_slice(&data[..needed]);
    }
    ensure!(out.len() == length, "注册表分段数据长度不一致");
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::super::tests::{K, fixture, image, put};
    use super::*;
    use serde_json::json;
    #[test]
    fn cell_mapping_rejects_free_and_out_of_range_cells() {
        let (mut b, mut isf) = fixture();
        let pointer = |offset| json!({"offset":offset,"type":{"kind":"pointer"}});
        let number = |offset| json!({"offset":offset,"type":{"kind":"base","name":"u64"}});
        isf.data["user_types"]["_HHIVE"] = json!({"size":64,"fields":{"Storage":{"offset":0,"type":{"kind":"array","count":2,"subtype":{"kind":"struct","name":"_DUAL"}}}}});
        isf.data["user_types"]["_DUAL"] =
            json!({"size":32,"fields":{"Length":number(0),"Map":pointer(8)}});
        isf.data["user_types"]["_HMAP_DIRECTORY"] = json!({"size":8,"fields":{"Directory":{"offset":0,"type":{"kind":"array","count":1,"subtype":{"kind":"pointer"}}}}});
        isf.data["user_types"]["_HMAP_TABLE"] = json!({"size":8192,"fields":{"Table":{"offset":0,"type":{"kind":"array","count":512,"subtype":{"kind":"struct","name":"_HMAP_ENTRY"}}}}});
        isf.data["user_types"]["_HMAP_ENTRY"] = json!({"size":16,"fields":{"BlockAddress":number(0),"BlockOffset":number(0),"PermanentBinAddress":number(8)}});
        put(&mut b, 0xb000, 8192);
        put(&mut b, 0xb008, K + 0x4000);
        put(&mut b, 0xc000, K + 0x5000);
        put(&mut b, 0xd008, K + 0x6000);
        b[0xe020..0xe024].copy_from_slice(&(-8i32).to_le_bytes());
        b[0xe024..0xe028].copy_from_slice(b"nkxx");
        // A cell crossing a hive page must follow HMAP, not contiguous VM.
        put(&mut b, 0xd018, K + 0x9000);
        b[0xeff0..0xeff4].copy_from_slice(&(-32i32).to_le_bytes());
        b[0xeff4..0xf000].fill(0x11);
        b[0x11000..0x11010].fill(0x22);
        let good = image(&b);
        let engine = Windows {
            vm: Memory::new(&good, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        assert_eq!(engine.cell(K + 0x3000, 0x20).unwrap(), b"nkxx");
        assert!(engine.cell(K + 0x3000, 0x2000).is_err());
        let crossing = engine.cell(K + 0x3000, 0xff0).unwrap();
        assert_eq!(&crossing[..12], &[0x11; 12]);
        assert_eq!(&crossing[12..], &[0x22; 16]);
        b[0xe020..0xe024].copy_from_slice(&8i32.to_le_bytes());
        let free = image(&b);
        let engine = Windows {
            vm: Memory::new(&free, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        assert!(engine.cell(K + 0x3000, 0x20).is_err());
    }
    #[test]
    fn big_values_reconstruct_and_reject_repeated_segments() {
        let header = b"db\x02\x00\x01\x00\x00\x00";
        let read = |index| -> Result<Vec<u8>> {
            Ok(match index {
                1 => vec![2, 0, 0, 0, 3, 0, 0, 0],
                2 => vec![0x11; 0x3fd8],
                3 => vec![0x22; 17],
                _ => bail!("bad index"),
            })
        };
        let bytes = segmented_value(header, 0x3fd8 + 17, read).unwrap();
        assert_eq!(&bytes[..0x3fd8], &vec![0x11; 0x3fd8]);
        assert_eq!(&bytes[0x3fd8..], &[0x22; 17]);
        assert!(segmented_value(header, 0x3fd8 + 18, read).is_err());
        assert!(
            segmented_value(header, 0x3fd8 + 17, |index| if index == 1 {
                Ok(vec![2, 0, 0, 0, 2, 0, 0, 0])
            } else {
                read(index)
            })
            .is_err()
        );
    }
    #[test]
    fn compressed_names_and_utf16() {
        assert_eq!(decode_name(b"hello", true).unwrap(), "hello");
        assert_eq!(
            decode_name(&[0x2d, 0x4e, 0x87, 0x65], false).unwrap(),
            "中文"
        );
        assert!(decode_name(&[1], false).is_err());
    }
    #[test]
    fn key_class_value_bytes_and_index_walk_raw_cells() {
        let (mut b, mut isf) = fixture();
        let pointer = |offset| json!({"offset":offset,"type":{"kind":"pointer"}});
        let number = |offset| json!({"offset":offset,"type":{"kind":"base","name":"u32"}});
        let short = |offset| json!({"offset":offset,"type":{"kind":"base","name":"u16"}});
        isf.data["base_types"]["u32"] = json!({"size":4});
        isf.data["user_types"]["_HHIVE"] = json!({"size":64,"fields":{"BaseBlock":pointer(0),"Storage":{"offset":8,"type":{"kind":"array","count":2,"subtype":{"kind":"struct","name":"_DUAL"}}}}});
        isf.data["user_types"]["_DUAL"] =
            json!({"size":24,"fields":{"Length":number(0),"Map":pointer(8)}});
        isf.data["user_types"]["_HBASE_BLOCK"] = json!({"size":4,"fields":{"RootCell":number(0)}});
        isf.data["user_types"]["_HMAP_DIRECTORY"] = json!({"size":8,"fields":{"Directory":{"offset":0,"type":{"kind":"array","count":1,"subtype":{"kind":"pointer"}}}}});
        isf.data["user_types"]["_HMAP_TABLE"] = json!({"size":8192,"fields":{"Table":{"offset":0,"type":{"kind":"array","count":512,"subtype":{"kind":"struct","name":"_HMAP_ENTRY"}}}}});
        isf.data["user_types"]["_HMAP_ENTRY"] =
            json!({"size":16,"fields":{"BlockOffset":pointer(0),"PermanentBinAddress":pointer(8)}});
        let array = |offset| json!({"offset":offset,"type":{"kind":"array","count":2,"subtype":{"kind":"base","name":"u32"}}});
        isf.data["user_types"]["_CM_KEY_NODE"] = json!({"size":48,"fields":{"Flags":short(2),"NameLength":short(4),"LastWriteTime":pointer(8),"ValueList":{"offset":16,"type":{"kind":"struct","name":"_CHILD_LIST"}},"SubKeyCounts":array(24),"SubKeyLists":array(32),"Class":number(36),"ClassLength":short(40),"Name":{"offset":44,"type":{"kind":"array","count":0}}}});
        isf.data["user_types"]["_CHILD_LIST"] =
            json!({"size":8,"fields":{"Count":number(0),"List":number(4)}});
        isf.data["user_types"]["_CM_KEY_VALUE"] = json!({"size":32,"fields":{"NameLength":short(2),"Flags":short(4),"Type":number(8),"DataLength":number(12),"Data":number(16),"Name":{"offset":24,"type":{"kind":"array","count":2}}}});
        // Registry-process view (DTB 0x5000) maps kernel K-area and hive user memory.
        put(&mut b, 0x5000, 0x2003);
        put(&mut b, 0x5000 + 256 * 8, 0x2003);
        put(&mut b, 0xb020, K + 0x4000);
        put(&mut b, 0xb028, 8192);
        put(&mut b, 0xb030, K + 0x5000);
        put(&mut b, 0xc000, 0x20);
        put(&mut b, 0xd000, K + 0x6000);
        put(&mut b, 0xe008, 0x9000);
        // Root nk: subkey Lsa via lf list, one value, class data 16 bytes.
        b[0x11020..0x11024].copy_from_slice(&(-60i32).to_le_bytes());
        let mut nk = [0u8; 56];
        nk[..2].copy_from_slice(b"nk");
        nk[2..4].copy_from_slice(&0x20u16.to_le_bytes());
        nk[4..6].copy_from_slice(&4u16.to_le_bytes());
        nk[16..20].copy_from_slice(&1u32.to_le_bytes());
        nk[20..24].copy_from_slice(&0x80u32.to_le_bytes());
        nk[24..28].copy_from_slice(&1u32.to_le_bytes());
        nk[32..36].copy_from_slice(&0x100u32.to_le_bytes());
        nk[36..40].copy_from_slice(&0xe0u32.to_le_bytes());
        nk[40..42].copy_from_slice(&16u16.to_le_bytes());
        nk[44..48].copy_from_slice(b"Root");
        b[0x11024..0x11024 + 56].copy_from_slice(&nk);
        // Value index cell -> vk cell with REG_BINARY data.
        b[0x11080..0x11084].copy_from_slice(&(-8i32).to_le_bytes());
        b[0x11084..0x11088].copy_from_slice(&0x90u32.to_le_bytes());
        b[0x11090..0x11094].copy_from_slice(&(-36i32).to_le_bytes());
        let mut vk = [0u8; 32];
        vk[..2].copy_from_slice(b"vk");
        vk[2..4].copy_from_slice(&2u16.to_le_bytes());
        vk[8..12].copy_from_slice(&3u32.to_le_bytes());
        vk[12..16].copy_from_slice(&8u32.to_le_bytes());
        vk[16..20].copy_from_slice(&0xc0u32.to_le_bytes());
        vk[24..26].copy_from_slice(b"F\0");
        b[0x11094..0x11094 + 32].copy_from_slice(&vk);
        b[0x110c0..0x110c4].copy_from_slice(&(-12i32).to_le_bytes());
        b[0x110c4..0x110cc].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4]);
        // Class cell: UTF-16 "0123abcd" as the SAM bootkey fragments store it.
        b[0x110e0..0x110e4].copy_from_slice(&(-20i32).to_le_bytes());
        for (i, ch) in "0123abcd".encode_utf16().enumerate() {
            b[0x110e4 + i * 2..0x110e4 + i * 2 + 2].copy_from_slice(&ch.to_le_bytes());
        }
        // lf subkey list (8-byte entries) pointing at the Lsa nk cell.
        b[0x11100..0x11104].copy_from_slice(&(-16i32).to_le_bytes());
        b[0x11104..0x11106].copy_from_slice(b"lf");
        b[0x11106..0x11108].copy_from_slice(&1u16.to_le_bytes());
        b[0x11108..0x1110c].copy_from_slice(&0x120u32.to_le_bytes());
        b[0x1110c..0x11110].copy_from_slice(&0u32.to_le_bytes());
        b[0x11120..0x11124].copy_from_slice(&(-52i32).to_le_bytes());
        let mut child = [0u8; 48];
        child[..2].copy_from_slice(b"nk");
        child[2..4].copy_from_slice(&0x20u16.to_le_bytes());
        child[4..6].copy_from_slice(&3u16.to_le_bytes());
        child[44..47].copy_from_slice(b"Lsa");
        b[0x11124..0x11124 + 48].copy_from_slice(&child);
        let img = image(&b);
        let engine = Windows {
            vm: Memory::new(&img, 0x5000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let job = Job::default();
        let class = engine.key_class(K + 0x3020, 0x20).unwrap();
        let expected: Vec<u8> = "0123abcd"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        assert_eq!(class, expected);
        let (name, ty, bytes) = engine.value_bytes(K + 0x3020, 0x90, &job).unwrap();
        assert_eq!(
            (name.as_str(), ty, bytes),
            ("F", 3, vec![0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4])
        );
        assert_eq!(
            engine.registry_index(K + 0x3020, "Lsa", &job).unwrap(),
            0x120
        );
        assert!(engine.registry_index(K + 0x3020, "SAM", &job).is_err());
        // A corrupt sibling must not hide an independently readable target.
        b[0x1103c..0x11040].copy_from_slice(&2u32.to_le_bytes());
        b[0x11100..0x11104].copy_from_slice(&(-24i32).to_le_bytes());
        b[0x11106..0x11108].copy_from_slice(&2u16.to_le_bytes());
        b[0x11108..0x1110c].copy_from_slice(&0x200u32.to_le_bytes());
        b[0x11110..0x11114].copy_from_slice(&0x120u32.to_le_bytes());
        let img = image(&b);
        let engine = Windows {
            vm: Memory::new(&img, 0x5000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let mut r = engine.result(Plugin::WinSvcList);
        assert_eq!(
            engine
                .registry_index_partial(K + 0x3020, 0x20, "Lsa", &job, &mut r, false)
                .unwrap(),
            0x120
        );
        assert!(!r.complete);
        assert!(r.diagnostics.iter().any(|d| d.contains("sibling 0x200")));
        assert!(
            engine
                .registry_index_partial(K + 0x3020, 0x20, "lsa", &job, &mut r, true)
                .is_err()
        );
        assert_eq!(
            engine
                .registry_index_partial(K + 0x3020, 0x20, "lsa", &job, &mut r, false)
                .unwrap(),
            0x120
        );
        assert_eq!(
            engine.service_registry_value(K + 0x3020, 0x20, "f", &job, &mut r),
            "N/A"
        );
        assert_ne!(
            engine.service_registry_value(K + 0x3020, 0x20, "F", &job, &mut r),
            "N/A"
        );
        // First value has readable metadata but an invalid data cell. Name
        // selection must skip its data and still find the second value.
        b[0x11034..0x11038].copy_from_slice(&2u32.to_le_bytes());
        b[0x11080..0x11084].copy_from_slice(&(-12i32).to_le_bytes());
        b[0x11084..0x11088].copy_from_slice(&0x200u32.to_le_bytes());
        b[0x11088..0x1108c].copy_from_slice(&0x90u32.to_le_bytes());
        b[0x11200..0x11204].copy_from_slice(&(-36i32).to_le_bytes());
        let mut unreadable = vk;
        unreadable[24..26].copy_from_slice(b"X\0");
        unreadable[16..20].copy_from_slice(&0x10000u32.to_le_bytes());
        b[0x11204..0x11224].copy_from_slice(&unreadable);
        let img = image(&b);
        let engine = Windows {
            vm: Memory::new(&img, 0x5000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        assert_eq!(engine.value_name(K + 0x3020, 0x200).unwrap(), "X");
        assert!(engine.value_bytes(K + 0x3020, 0x200, &job).is_err());
        let mut r = engine.result(Plugin::WinSvcScanV4);
        assert_ne!(
            engine.service_registry_value(K + 0x3020, 0x20, "F", &job, &mut r),
            "N/A"
        );
        assert!(r.complete);
        assert!(r.diagnostics.is_empty());
        assert_eq!(
            engine.service_registry_value(K + 0x3020, 0x20, "X", &job, &mut r),
            "N/A"
        );
        assert!(!r.complete);
        // An invalid sibling node is skipped with diagnostics, just like the
        // reference get_values iterator; the matching later value survives.
        b[0x11200..0x11204].copy_from_slice(&36i32.to_le_bytes());
        let img = image(&b);
        let engine = Windows {
            vm: Memory::new(&img, 0x5000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let mut r = engine.result(Plugin::WinSvcScanV4);
        assert_ne!(
            engine.service_registry_value(K + 0x3020, 0x20, "F", &job, &mut r),
            "N/A"
        );
        assert!(!r.complete);
        assert!(r.diagnostics.iter().any(|d| d.contains("value 0x200 name")));
    }
}

#[cfg(test)]
mod ownership_tests {
    use super::super::tests::{K, fixture, image, put};
    use super::*;
    use serde_json::json;
    fn user_hive_fixture() -> (Vec<u8>, Isf) {
        let (mut b, mut isf) = fixture();
        let pointer = |offset| json!({"offset":offset,"type":{"kind":"pointer"}});
        let number = |offset| json!({"offset":offset,"type":{"kind":"base","name":"u32"}});
        let short = |offset| json!({"offset":offset,"type":{"kind":"base","name":"u16"}});
        isf.data["base_types"]["u32"] = json!({"size":4});
        isf.data["symbols"]["CmpHiveListHead"] = json!({"address":0x7000});
        isf.data["user_types"]["_CMHIVE"] = json!({"size":128,"fields":{"HiveList":{"offset":0,"type":{"kind":"struct","name":"_LIST_ENTRY"}},"FileFullPath":{"offset":16,"type":{"kind":"struct","name":"_UNICODE_STRING"}},"Hive":{"offset":32,"type":{"kind":"struct","name":"_HHIVE"}}}});
        isf.data["user_types"]["_HHIVE"] = json!({"size":64,"fields":{"BaseBlock":pointer(0),"Storage":{"offset":8,"type":{"kind":"array","count":2,"subtype":{"kind":"struct","name":"_DUAL"}}}}});
        isf.data["user_types"]["_DUAL"] =
            json!({"size":24,"fields":{"Length":number(0),"Map":pointer(8)}});
        isf.data["user_types"]["_HBASE_BLOCK"] = json!({"size":4,"fields":{"RootCell":number(0)}});
        isf.data["user_types"]["_HMAP_DIRECTORY"] = json!({"size":8,"fields":{"Directory":{"offset":0,"type":{"kind":"array","count":1,"subtype":{"kind":"pointer"}}}}});
        isf.data["user_types"]["_HMAP_TABLE"] = json!({"size":8192,"fields":{"Table":{"offset":0,"type":{"kind":"array","count":512,"subtype":{"kind":"struct","name":"_HMAP_ENTRY"}}}}});
        isf.data["user_types"]["_HMAP_ENTRY"] =
            json!({"size":16,"fields":{"BlockOffset":pointer(0),"PermanentBinAddress":pointer(8)}});
        let array = |offset| json!({"offset":offset,"type":{"kind":"array","count":2,"subtype":{"kind":"base","name":"u32"}}});
        isf.data["user_types"]["_CM_KEY_NODE"] = json!({"size":40,"fields":{"Flags":short(2),"NameLength":short(4),"LastWriteTime":pointer(8),"ValueList":{"offset":16,"type":{"kind":"struct","name":"_CHILD_LIST"}},"SubKeyCounts":array(24),"SubKeyLists":array(32),"Name":{"offset":40,"type":{"kind":"array","count":0}}}});
        isf.data["user_types"]["_CHILD_LIST"] =
            json!({"size":8,"fields":{"Count":number(0),"List":number(4)}});
        b[0xa030..0xa040].fill(0);
        b[0xa030..0xa038].copy_from_slice(b"Registry");
        put(&mut b, 0xa070, 0x5000);
        // Registry's root shares kernel mappings and additionally maps low hive memory.
        put(&mut b, 0x5000 + 256 * 8, 0x2003);
        put(&mut b, 0x5000, 0x2003);
        put(&mut b, 0xf000, K + 0x3000);
        put(&mut b, 0xf008, K + 0x3000);
        put(&mut b, 0xb000, K + 0x7000);
        put(&mut b, 0xb008, K + 0x7000);
        put(&mut b, 0xb020, K + 0x4000);
        put(&mut b, 0xb028, 8192);
        put(&mut b, 0xb030, K + 0x5000);
        put(&mut b, 0xc000, 0x20);
        put(&mut b, 0xd000, K + 0x6000);
        put(&mut b, 0xe008, 0x9000);
        b[0x11020..0x11024].copy_from_slice(&(-48i32).to_le_bytes());
        b[0x11024..0x11026].copy_from_slice(b"nk");
        b[0x11026..0x11028].copy_from_slice(&0x20u16.to_le_bytes());
        b[0x11028..0x1102a].copy_from_slice(&4u16.to_le_bytes());
        b[0x1104c..0x11050].copy_from_slice(b"Root");
        (b, isf)
    }
    #[test]
    fn user_mapped_hive_reads_only_in_validated_registry_process_space() {
        let (b, isf) = user_hive_fixture();
        let img = image(&b);
        let engine = Windows {
            vm: Memory::new(&img, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let options = Options {
            hive: Some(K + 0x3000),
            ..Default::default()
        };
        assert!(
            engine
                .registry(Plugin::WinPrintkey, &options, &Job::default())
                .is_err()
        );
        let r = engine
            .run(Plugin::WinPrintkey, &options, &Job::default())
            .unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(r.rows[0][3], "Root");
        assert_eq!(r.page_table, 0x5000);
        assert_eq!(r.kernel_identity["registry_process"]["pid"], 8);
    }
    #[test]
    fn canonical_amcache_real_cell_walk_missing_data_and_cancellation() {
        let (mut b, mut isf) = user_hive_fixture();
        isf.data["user_types"]["_CM_KEY_VALUE"] = json!({"size":24,"fields":{"NameLength":{"offset":2,"type":{"kind":"base","name":"u16"}},"Flags":{"offset":4,"type":{"kind":"base","name":"u16"}},"Type":{"offset":8,"type":{"kind":"base","name":"u32"}},"DataLength":{"offset":12,"type":{"kind":"base","name":"u32"}},"Data":{"offset":16,"type":{"kind":"base","name":"u32"}},"Name":{"offset":24,"type":{"kind":"array","count":0}}}});
        // Root -> Root -> InventoryApplicationFile -> file, with an inline
        // UTF16 path and an unreadable unrelated value that must not be read.
        let node = |b: &mut [u8], index: usize, name: &str, children: Option<u32>| {
            let at = 0x11000 + index;
            b[at..at + 4].copy_from_slice(&(-128i32).to_le_bytes());
            let n = &mut b[at + 4..at + 128];
            n.fill(0);
            n[..2].copy_from_slice(b"nk");
            n[2..4].copy_from_slice(&0x20u16.to_le_bytes());
            n[4..6].copy_from_slice(&(name.len() as u16).to_le_bytes());
            n[40..40 + name.len()].copy_from_slice(name.as_bytes());
            if let Some(list) = children {
                n[24..28].copy_from_slice(&1u32.to_le_bytes());
                n[32..36].copy_from_slice(&list.to_le_bytes());
            }
        };
        let list = |b: &mut [u8], index: usize, child: u32| {
            let at = 0x11000 + index;
            b[at..at + 4].copy_from_slice(&(-16i32).to_le_bytes());
            b[at + 4..at + 8].copy_from_slice(b"li\x01\x00");
            b[at + 8..at + 12].copy_from_slice(&child.to_le_bytes());
        };
        node(&mut b, 0x20, "Amcache", Some(0x100));
        list(&mut b, 0x100, 0x120);
        node(&mut b, 0x120, "Root", Some(0x200));
        list(&mut b, 0x200, 0x220);
        node(&mut b, 0x220, "InventoryApplicationFile", Some(0x300));
        list(&mut b, 0x300, 0x320);
        node(&mut b, 0x320, "file", None);
        b[0x11334..0x11338].copy_from_slice(&2u32.to_le_bytes());
        b[0x11338..0x1133c].copy_from_slice(&0x400u32.to_le_bytes());
        b[0x11400..0x11404].copy_from_slice(&(-16i32).to_le_bytes());
        b[0x11404..0x11408].copy_from_slice(&0x420u32.to_le_bytes());
        b[0x11408..0x1140c].copy_from_slice(&0x480u32.to_le_bytes());
        let value = |b: &mut [u8], index: usize, name: &str, data: u32, length: u32| {
            let at = 0x11000 + index;
            b[at..at + 4].copy_from_slice(&(-96i32).to_le_bytes());
            let v = &mut b[at + 4..at + 96];
            v.fill(0);
            v[..2].copy_from_slice(b"vk");
            v[2..4].copy_from_slice(&(name.len() as u16 * 2).to_le_bytes());
            v[12..16].copy_from_slice(&length.to_le_bytes());
            v[8..12].copy_from_slice(&1u32.to_le_bytes());
            v[16..20].copy_from_slice(&data.to_le_bytes());
            let bytes: Vec<_> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
            v[24..24 + bytes.len()].copy_from_slice(&bytes);
        };
        value(&mut b, 0x420, "LowerCaseLongPath", 0x00420041, 0x80000004);
        value(&mut b, 0x480, "Unrelated", 0x10000, 8);
        let run = |b: &[u8], job: &Job, old: bool| {
            let img = image(b);
            let engine = Windows {
                vm: Memory::new(&img, 0x5000, &isf, None),
                base: K,
                pdb: PdbIdentity::from_isf(&isf).unwrap(),
            };
            let mut result = engine.result(Plugin::WinAmcacheV4);
            let records = engine.amcache_records(
                K + 0x3020,
                if old {
                    r"Root\File"
                } else {
                    r"Root\InventoryApplicationFile"
                },
                if old {
                    super::super::amcache::Layout::File
                } else {
                    super::super::amcache::Layout::ApplicationFile
                },
                job,
                &mut result,
            )?;
            Ok::<_, anyhow::Error>((records, result))
        };
        let (rows, result) = run(&b, &Job::default(), false).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1[1], "AB");
        assert!(result.complete, "{:?}", result.diagnostics);
        // A wanted value with missing bytes remains an absent field and partial.
        value(&mut b, 0x480, "Publisher", 0x10000, 8);
        let (rows, result) = run(&b, &Job::default(), false).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1[2], "N/A");
        assert!(!result.complete);
        // Win8 File entries are nested below volume keys, not direct children.
        node(&mut b, 0x220, "File", Some(0x300));
        node(&mut b, 0x320, "volume", Some(0x500));
        list(&mut b, 0x500, 0x520);
        node(&mut b, 0x520, "oldfile", None);
        b[0x11534..0x11538].copy_from_slice(&1u32.to_le_bytes());
        b[0x11538..0x1153c].copy_from_slice(&0x400u32.to_le_bytes());
        value(&mut b, 0x420, "15", 0x00440043, 0x80000004);
        let (rows, result) = run(&b, &Job::default(), true).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1[1], "CD");
        assert!(result.complete);
        let job = Job::default();
        job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(run(&b, &job, false).is_err());
    }
    #[test]
    fn canonical_userassist_key_subkey_value_missing_data_and_validated_root_fallback() {
        let (mut b, isf) = user_hive_fixture();
        // The root owns one direct child and a short binary value.
        b[0x11034..0x11038].copy_from_slice(&1u32.to_le_bytes());
        b[0x11038..0x1103c].copy_from_slice(&0x300u32.to_le_bytes());
        b[0x1103c..0x11040].copy_from_slice(&1u32.to_le_bytes());
        b[0x11044..0x11048].copy_from_slice(&0x100u32.to_le_bytes());
        b[0x11100..0x11104].copy_from_slice(&(-16i32).to_le_bytes());
        b[0x11104..0x11108].copy_from_slice(b"li\x01\x00");
        b[0x11108..0x1110c].copy_from_slice(&0x120u32.to_le_bytes());
        b[0x11120..0x11124].copy_from_slice(&(-52i32).to_le_bytes());
        let child = &mut b[0x11124..0x11154];
        child.fill(0);
        child[..2].copy_from_slice(b"nk");
        child[2..4].copy_from_slice(&0x20u16.to_le_bytes());
        child[4..6].copy_from_slice(&5u16.to_le_bytes());
        child[40..45].copy_from_slice(b"Child");
        b[0x11300..0x11304].copy_from_slice(&(-8i32).to_le_bytes());
        b[0x11304..0x11308].copy_from_slice(&0x320u32.to_le_bytes());
        b[0x11320..0x11324].copy_from_slice(&(-36i32).to_le_bytes());
        let v = &mut b[0x11324..0x11344];
        v.fill(0);
        v[..2].copy_from_slice(b"vk");
        v[2..4].copy_from_slice(&4u16.to_le_bytes());
        v[4..6].copy_from_slice(&1u16.to_le_bytes());
        v[8..12].copy_from_slice(&3u32.to_le_bytes());
        v[12..16].copy_from_slice(&0x8000_0004u32.to_le_bytes());
        v[16..20].copy_from_slice(&[1, 2, 3, 4]);
        v[24..28].copy_from_slice(b"abgr");
        let mut isf = isf;
        isf.data["user_types"]["_CM_KEY_VALUE"] = json!({"size":32,"fields":{"NameLength":{"offset":2,"type":{"kind":"base","name":"u16"}},"Flags":{"offset":4,"type":{"kind":"base","name":"u16"}},"Type":{"offset":8,"type":{"kind":"base","name":"u32"}},"DataLength":{"offset":12,"type":{"kind":"base","name":"u32"}},"Data":{"offset":16,"type":{"kind":"base","name":"u32"}},"Name":{"offset":24,"type":{"kind":"array","count":0}}}});
        isf.data["user_types"]["_CM_KEY_NODE"]["fields"]["Parent"] =
            json!({"offset":36,"type":{"kind":"base","name":"u32"}});
        b[0x11148..0x1114c].copy_from_slice(&0x20u32.to_le_bytes());
        let run = |b: &[u8]| {
            let img = image(b);
            let engine = Windows {
                vm: Memory::new(&img, 0x5000, &isf, None),
                base: K,
                pdb: PdbIdentity::from_isf(&isf).unwrap(),
            };
            let mut r = engine.result(Plugin::WinUserAssistV4);
            engine
                .userassist_count(
                    K + 0x3000,
                    r"C:\Users\Test\NTUSER.DAT",
                    0x20,
                    Some(true),
                    &mut r,
                    &Job::default(),
                )
                .unwrap();
            r
        };
        let r = run(&b);
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(r.rows.len(), 3);
        assert_eq!(&r.rows[0][2..6], &["NTUSER.DAT", "N/A", "Key", "N/A"]);
        assert_eq!(&r.rows[1][4..6], &["Subkey", "Child"]);
        assert_eq!(&r.rows[2][4..6], &["Value", "note"]);
        assert_eq!(r.rows[2][11], "01 02 03 04");
        let img = image(&b);
        let engine = Windows {
            vm: Memory::new(&img, 0x5000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let mut nested = engine.result(Plugin::WinUserAssistV4);
        engine
            .userassist_count(
                K + 0x3000,
                "NTUSER.DAT",
                0x120,
                None,
                &mut nested,
                &Job::default(),
            )
            .unwrap();
        assert_eq!(nested.rows[0][2], r"NTUSER.DAT\Child");
        let mut cyclic = b.clone();
        cyclic[0x11148..0x1114c].copy_from_slice(&0x120u32.to_le_bytes());
        let img = image(&cyclic);
        let engine = Windows {
            vm: Memory::new(&img, 0x5000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let mut invalid = engine.result(Plugin::WinUserAssistV4);
        assert!(
            engine
                .userassist_count(
                    K + 0x3000,
                    "NTUSER.DAT",
                    0x120,
                    None,
                    &mut invalid,
                    &Job::default()
                )
                .is_err()
        );
        assert!(invalid.rows.is_empty());
        // BaseBlock is absent, but the conventional root is independently readable.
        put(&mut b, 0xb020, 0);
        assert_eq!(run(&b).rows, r.rows);
        // Missing value data stays absent and carries a diagnostic.
        b[0x11330..0x11334].copy_from_slice(&8u32.to_le_bytes());
        b[0x11334..0x11338].copy_from_slice(&0x1f00u32.to_le_bytes());
        let partial = run(&b);
        assert!(!partial.complete);
        assert_eq!(partial.rows[2][11], "N/A");
        assert!(
            partial
                .diagnostics
                .iter()
                .any(|d| d.contains("value 0x320"))
        );
        // Explicit hive selection works without membership in the hive list;
        // the shared dispatcher still chooses the Registry process address space.
        isf.data["user_types"]["_HHIVE"]["fields"]["Signature"] =
            json!({"offset":56,"type":{"kind":"base","name":"u32"}});
        b[0xb058..0xb05c].copy_from_slice(&0xbee0_bee0u32.to_le_bytes());
        put(&mut b, 0xf000, K + 0x7000);
        put(&mut b, 0xf008, K + 0x7000);
        let img = image(&b);
        let engine = Windows {
            vm: Memory::new(&img, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let options = Options {
            hive: Some(K + 0x3000),
            ..Default::default()
        };
        let selected = engine
            .run(Plugin::WinUserAssistV4, &options, &Job::default())
            .unwrap();
        assert!(selected.rows.is_empty()); // This synthetic hive has no UserAssist path.
        assert!(selected.complete, "{:?}", selected.diagnostics);
        assert_eq!(selected.page_table, 0x5000);
        assert_eq!(selected.kernel_identity["registry_process"]["pid"], 8);
        b[0xb058..0xb05c].fill(0);
        let img = image(&b);
        let engine = Windows {
            vm: Memory::new(&img, 0x5000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        assert!(
            engine
                .userassist_canonical(&options, &Job::default())
                .is_err()
        );
        // The fallback must reject an invalid nk signature.
        b[0x11024..0x11026].copy_from_slice(b"xx");
        let img = image(&b);
        let engine = Windows {
            vm: Memory::new(&img, 0x5000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        assert!(engine.registry_root(K + 0x3020).is_err());
        let job = Job::default();
        job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(
            engine
                .run(Plugin::WinUserAssistV4, &Options::default(), &job)
                .is_err()
        );
    }
}
