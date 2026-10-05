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
        let base = self.number(hhive, "_HHIVE", "BaseBlock")?;
        let mut cell = self.number(base, "_HBASE_BLOCK", "RootCell")? as u32;
        for part in options.key.split(['\\', '/']).filter(|s| !s.is_empty()) {
            job.check()?;
            let node = self.cell(hhive, cell)?;
            let mut found = None;
            for index in self.subkeys(hhive, &node, job)? {
                let n = self.cell(hhive, index)?;
                if self.key_name(&n)?.eq_ignore_ascii_case(part) {
                    ensure!(found.is_none(), "注册表键名称歧义");
                    found = Some(index);
                }
            }
            cell = found.with_context(|| format!("注册表键不存在: {part}"))?;
        }
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
        let list_offset = self.vm.isf.offset("_CM_KEY_NODE", "ValueList")? as usize;
        let list = node.get(list_offset..).context("注册表 ValueList 截断")?;
        let count = objects::physical_number(self.vm.isf, list, "_CHILD_LIST", "Count")?;
        let index = objects::physical_number(self.vm.isf, list, "_CHILD_LIST", "List")? as u32;
        ensure!(count <= MAX_OBJECTS as u64, "注册表值超限");
        if count > 0 {
            let indices = self.cell(hhive, index)?;
            ensure!(count as usize * 4 <= indices.len(), "注册表值列表截断");
            for chunk in indices[..count as usize * 4].chunks_exact(4) {
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
        let table = self.vm.uint(
            add(
                self.field(directory, "_HMAP_DIRECTORY", "Directory")?,
                (index >> 21) * 8,
            )?,
            8,
        )?;
        ensure!(table != 0, "hive 映射表缺失");
        let entry_size = self.vm.isf.data["user_types"]["_HMAP_ENTRY"]["size"]
            .as_u64()
            .context("缺少 _HMAP_ENTRY")?;
        let entry = add(
            self.field(table, "_HMAP_TABLE", "Table")?,
            ((index >> 12) & 511) * entry_size,
        )?;
        let block = if self.vm.isf.field("_HMAP_ENTRY", "BlockAddress").is_ok() {
            self.number(entry, "_HMAP_ENTRY", "BlockAddress")? & !15
        } else {
            add(
                self.number(entry, "_HMAP_ENTRY", "PermanentBinAddress")? & !15,
                self.number(entry, "_HMAP_ENTRY", "BlockOffset")?,
            )?
        };
        add(block, index & 4095)
    }
    fn cell(&self, hive: u64, index: u32) -> Result<Vec<u8>> {
        let address = self.cell_address(hive, index)?;
        let length = self.vm.uint(address, 4)? as u32 as i32;
        ensure!(length < 0, "hive cell 未分配");
        let length = length.unsigned_abs() as usize;
        ensure!((8..=1024 * 1024).contains(&length), "hive cell 大小无效");
        let mut out = vec![0; length - 4];
        let mut copied = 0;
        while copied < out.len() {
            let cell_index = index
                .checked_add(4)
                .and_then(|i| i.checked_add(copied as u32))
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
    fn key_name(&self, node: &[u8]) -> Result<String> {
        ensure!(node.len() >= 2 && &node[..2] == b"nk", "无效 nk cell");
        let flags = objects::physical_number(self.vm.isf, node, "_CM_KEY_NODE", "Flags")?;
        let len =
            objects::physical_number(self.vm.isf, node, "_CM_KEY_NODE", "NameLength")? as usize;
        let offset = self.vm.isf.offset("_CM_KEY_NODE", "Name")? as usize;
        decode_name(
            node.get(offset..offset + len).context("键名截断")?,
            flags & 0x20 != 0,
        )
    }
    fn subkeys(&self, hive: u64, node: &[u8], job: &Job) -> Result<Vec<u32>> {
        let counts = self.vm.isf.offset("_CM_KEY_NODE", "SubKeyCounts")? as usize;
        let lists = self.vm.isf.offset("_CM_KEY_NODE", "SubKeyLists")? as usize;
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
    fn value(&self, hive: u64, index: u32, job: &Job) -> Result<(String, String, String)> {
        let cell = self.cell(hive, index)?;
        ensure!(cell.len() >= 2 && &cell[..2] == b"vk", "非 vk cell");
        let get = |f| objects::physical_number(self.vm.isf, &cell, "_CM_KEY_VALUE", f);
        let len = get("NameLength")? as usize;
        let offset = self.vm.isf.offset("_CM_KEY_VALUE", "Name")? as usize;
        let name = decode_name(
            cell.get(offset..offset + len).context("值名截断")?,
            get("Flags")? & 1 != 0,
        )?;
        let length = get("DataLength")? as u32;
        let inline = length & 0x8000_0000 != 0;
        let length = (length & 0x7fff_ffff) as usize;
        ensure!(length <= 1024 * 1024, "注册表值超过 1 MiB");
        let bytes = if inline {
            ensure!(length <= 4, "内联值长度无效");
            (get("Data")? as u32).to_le_bytes()[..length].to_vec()
        } else if length == 0 {
            Vec::new()
        } else {
            let data = self.cell(hive, get("Data")? as u32)?;
            if length <= data.len() {
                data[..length].to_vec()
            } else {
                segmented_value(&data, length, |index| {
                    job.check()?;
                    self.cell(hive, index)
                })?
            }
        };
        let ty = get("Type")?;
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
        isf.data["user_types"]["_HMAP_ENTRY"] =
            json!({"size":16,"fields":{"BlockOffset":number(0),"PermanentBinAddress":number(8)}});
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
            vm: Memory {
                image: &good,
                root: 0x1000,
                isf: &isf,
                sources: None,
            },
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
            vm: Memory {
                image: &free,
                root: 0x1000,
                isf: &isf,
                sources: None,
            },
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
}
