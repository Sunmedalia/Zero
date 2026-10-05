//! Symbol-driven SMKM store reconstruction. Unknown keys/layouts remain missing pages.
//! Structural facts: mandiant/win10_rekall, win10_memcompression research (2019).
use super::*;
#[derive(Default)]
pub(super) struct State {
    pages: BTreeMap<(u64, u64), Vec<u8>>,
    evidence: BTreeMap<(u64, u64), serde_json::Value>,
}
impl paging::Sources {
    pub(super) fn compressed_page(
        &self,
        vm: &Memory<'_>,
        va: u64,
        pte: u64,
        index: u8,
    ) -> Result<Vec<u8>> {
        self.job.check()?;
        ensure!(
            self.virtual_indexes.contains(&index),
            "分页索引 {index} 未验证为虚拟压缩 store"
        );
        let key = (vm.root, va & !4095);
        if let Some(bytes) = self
            .compressed
            .lock()
            .map_err(|_| anyhow::anyhow!("store cache 锁失败"))?
            .pages
            .get(&key)
        {
            return Ok(bytes.clone());
        }
        let (root, base) = self.kernel_context.context("缺少压缩 store 内核上下文")?;
        let kernel = Windows {
            vm: Memory {
                image: vm.image,
                root,
                isf: vm.isf,
                sources: Some(self),
            },
            base,
            pdb: PdbIdentity::from_isf(vm.isf)?,
        };
        let build = kernel.vm.uint(kernel.symbol("NtBuildNumber")?, 4)? & 0xffff;
        let arch = Architecture::from_isf(vm.isf)?;
        ensure!(
            matches!(arch, Architecture::X86 | Architecture::X64)
                && (10240..=19041).contains(&build),
            "尚未验证此架构/build 的压缩 store 页键布局"
        );
        let mut high = json_number(vm.isf, pte, "_MMPTE_SOFTWARE", "PageFileHigh")?;
        if build >= 17134 && json_number(vm.isf, pte, "_MMPTE_SOFTWARE", "SwizzleBit")? == 0 {
            let state = kernel.symbol("MiState")?;
            high &=
                !(kernel
                    .vm
                    .number(state, "_MI_SYSTEM_INFORMATION", "Hardware.InvalidPteMask")?
                    >> 32);
        }
        ensure!(high < 1 << 28, "压缩 store 页键越界");
        let page_key = (u32::from(index) << 28) | high as u32;
        let globals = kernel
            .symbol("SmGlobals")
            .context("压缩 store 需要精确 SmGlobals 符号和 SMKM 类型")?;
        let mgr = kernel.field(globals, "_SM_GLOBALS", "SmkmStoreMgr")?;
        let tree = kernel
            .vm
            .pointer(kernel.field(mgr, "_SMKM_STORE_MGR", "KeyToStoreTree")?)?;
        let store_index = tree_search(&kernel.vm, tree, page_key, &self.job)?;
        ensure!(store_index >> 24 != 1, "store index 无效");
        let store_index = store_index & 0x3ff;
        let smkm = kernel.field(mgr, "_SMKM_STORE_MGR", "Smkm")?;
        let array = kernel.field(smkm, "_SMKM", "StoreMetaDataArray")?;
        let width = vm.pointer_size() as u64;
        let row = kernel
            .vm
            .pointer(add(array, u64::from(store_index >> 5) * width)?)?;
        let meta_size = vm.isf.data["user_types"]["_SMKM_STORE_METADATA"]["size"]
            .as_u64()
            .context("缺少 store metadata 尺寸")?;
        ensure!(
            (width..=4096).contains(&meta_size),
            "store metadata 尺寸无效"
        );
        let meta = add(row, u64::from(store_index & 31) * meta_size)?;
        let store =
            kernel
                .vm
                .pointer(kernel.field(meta, "_SMKM_STORE_METADATA", "SmkmStore")?)?;
        ensure!(kernel.vm.kernel(store), "store 地址无效");
        let st = kernel.field(store, "_SMKM_STORE", "StStore")?;
        let data = kernel.field(st, "_ST_STORE", "StDataMgr")?;
        let pages_tree = kernel
            .vm
            .pointer(kernel.field(data, "_ST_DATA_MGR", "PagesTree")?)?;
        let region_key = tree_search(&kernel.vm, pages_tree, page_key, &self.job)?;
        let chunk = kernel.field(data, "_ST_DATA_MGR", "ChunkMetaData")?;
        let mut region_key = region_key;
        let mut seen = HashSet::new();
        let mut record = 0;
        for _ in 0..32 {
            self.job.check()?;
            ensure!(seen.insert(region_key), "压缩 store record 循环");
            let bits = kernel
                .vm
                .number(chunk, "_SMHP_CHUNK_METADATA", "BitValue")?
                & 255;
            ensure!(bits < 32, "store chunk 位移无效");
            let region = u64::from(region_key) >> bits;
            ensure!(region != 0, "store chunk 索引为零");
            let row_index = 63 - region.leading_zeros() as u64;
            let multiplier = if build >= 15063 && arch == Architecture::X86 {
                3
            } else {
                2
            };
            let slot = (region ^ (1 << row_index))
                .checked_mul(multiplier)
                .context("store chunk 索引溢出")?;
            let ptr_array = kernel.field(chunk, "_SMHP_CHUNK_METADATA", "ChunkPtrArray")?;
            let row = kernel.vm.pointer(add(ptr_array, row_index * width)?)?;
            let chunk_base = kernel.vm.pointer(add(
                row,
                slot.checked_mul(width).context("store chunk 偏移溢出")?,
            )?)?;
            let mask =
                kernel
                    .vm
                    .number(chunk, "_SMHP_CHUNK_METADATA", "PageRecordsPerChunkMask")?;
            let size = kernel
                .vm
                .number(chunk, "_SMHP_CHUNK_METADATA", "PageRecordSize")?;
            let header = kernel
                .vm
                .number(chunk, "_SMHP_CHUNK_METADATA", "ChunkPageHeaderSize")?;
            ensure!(
                (8..=4096).contains(&size) && header <= 65536,
                "store page record 尺寸无效"
            );
            let offset = ((u64::from(region_key) & mask)
                .checked_mul(size)
                .context("record 偏移溢出")?)
                & 0xfffffff;
            record = add(chunk_base, add(header, offset)?)?;
            let record_key = kernel.vm.number(record, "_ST_PAGE_RECORD", "Key")?;
            if record_key != u32::MAX as u64 {
                break;
            }
            region_key = u32::try_from(kernel.vm.number(record, "_ST_PAGE_RECORD", "NextKey")?)?;
            record = 0;
        }
        ensure!(record != 0, "store record 链超过上限");
        let key_value = kernel.vm.number(record, "_ST_PAGE_RECORD", "Key")?;
        let shift = kernel.vm.number(data, "_ST_DATA_MGR", "RegionIndexMask")? & 255;
        ensure!(shift < 32, "压缩区域索引位移无效");
        let region_index = key_value >> shift;
        ensure!(region_index < 65536, "压缩区域索引越界");
        let region_array =
            kernel
                .vm
                .pointer(kernel.field(store, "_SMKM_STORE", "CompressedRegionPtrArray")?)?;
        let region = kernel
            .vm
            .pointer(add(region_array, region_index * width)?)?;
        let region = region
            & if width == 8 {
                0x7fffffffffff0000
            } else {
                0x7fff0000
            };
        let mask = kernel.vm.number(data, "_ST_DATA_MGR", "RegionSizeMask")?;
        let offset = (key_value & mask)
            .checked_mul(16)
            .context("store 数据偏移溢出")?;
        let address = add(region, offset)?;
        let owner = kernel
            .vm
            .pointer(kernel.field(store, "_SMKM_STORE", "OwnerProcess")?)?;
        let process = kernel.process(owner)?;
        let process_vm = kernel.process_memory(&process)?;
        let length = kernel
            .vm
            .number(record, "_ST_PAGE_RECORD", "CompressedSize")?;
        ensure!((1..=4096).contains(&length), "压缩页长度无效");
        let algorithm = u16::try_from(kernel.vm.number(
            data,
            "_ST_DATA_MGR",
            "CompressionAlgorithm",
        )?)?;
        let mut input = vec![0; length as usize];
        process_vm.read(address, &mut input)?;
        let bytes = if length == 4096 {
            input
        } else {
            codec::decompress(algorithm, &input, 4096)?
        };
        let mut state = self
            .compressed
            .lock()
            .map_err(|_| anyhow::anyhow!("store cache 锁失败"))?;
        ensure!(
            state.evidence.len() < 1_000_000 || state.evidence.contains_key(&key),
            "store 来源记录超过上限"
        );
        state.evidence.insert(key,serde_json::json!({"root":vm.root,"virtual_page":va&!4095,"page_key":page_key,"store_index":store_index,"record":record,"owner_pid":process.pid,"compressed_address":address,"compressed_size":length,"algorithm":algorithm,"validation":"symbol-driven-synthetic"}));
        if state.pages.len() >= 256 {
            state.pages.pop_first();
        }
        state.pages.insert(key, bytes.clone());
        Ok(bytes)
    }
    pub(super) fn compressed_evidence(&self) -> Result<serde_json::Value> {
        Ok(serde_json::json!(
            self.compressed
                .lock()
                .map_err(|_| anyhow::anyhow!("store evidence 锁失败"))?
                .evidence
                .values()
                .collect::<Vec<_>>()
        ))
    }
}
fn tree_search(vm: &Memory<'_>, mut tree: u64, key: u32, job: &Job) -> Result<u32> {
    let mut seen = HashSet::new();
    for _ in 0..64 {
        job.check()?;
        ensure!(
            vm.kernel(tree) && seen.insert(tree),
            "store B-tree 地址无效或循环"
        );
        let count = vm.number(tree, "_B_TREE", "Elements")?;
        ensure!(count <= 4096, "store B-tree 节点过多");
        let leaf = vm.number(tree, "_B_TREE", "Leaf")? != 0;
        let nodes = add(
            tree,
            vm.isf
                .offset(if leaf { "_B_TREE_LEAF" } else { "_B_TREE" }, "Nodes")?,
        )?;
        let stride = if leaf {
            8
        } else {
            vm.isf.data["user_types"]["_B_TREE_NODE"]["size"]
                .as_u64()
                .context("缺少 store B-tree node 尺寸")?
        };
        ensure!((8..=32).contains(&stride), "store B-tree node 尺寸无效");
        let mut predecessor = None;
        let mut previous = None;
        for i in 0..count {
            job.check()?;
            let node = add(nodes, i * stride)?;
            let current = vm.uint(node, 4)? as u32;
            ensure!(
                previous.is_none_or(|p| p < current),
                "store B-tree key 未排序或重复"
            );
            previous = Some(current);
            if current <= key {
                predecessor = Some((node, current));
            }
        }
        if leaf {
            let (node, current) = predecessor.context("store B-tree 未找到页键")?;
            ensure!(current == key, "store B-tree 没有该页键");
            return Ok(vm.uint(add(node, 4)?, 4)? as u32);
        }
        tree = if let Some((node, _)) = predecessor {
            vm.pointer(add(node, vm.isf.offset("_B_TREE_NODE", "Child")?)?)?
        } else {
            vm.pointer(add(tree, vm.isf.offset("_B_TREE", "LeftChild")?)?)?
        };
    }
    bail!("store B-tree 深度超过上限")
}

#[cfg(test)]
mod tests {
    use super::super::tests::{K, fixture, image, put};
    use super::*;
    use serde_json::json;
    fn setup() -> (Vec<u8>, Isf, paging::Sources) {
        let (mut b, mut isf) = fixture();
        isf.data["base_types"]["u32"] = json!({"size":4});
        let field = |offset, ty: &str| json!({"offset":offset,"type":{"kind":"base","name":ty}});
        let inline = |offset, ty: &str| json!({"offset":offset,"type":{"kind":"struct","name":ty}});
        let pointer = |offset| json!({"offset":offset,"type":{"kind":"pointer"}});
        let mut ty = |name: &str, size, fields: serde_json::Value| {
            isf.data["user_types"][name] = json!({"size":size,"kind":"struct","fields":fields});
        };
        ty(
            "_SM_GLOBALS",
            1024,
            json!({"SmkmStoreMgr":inline(0,"_SMKM_STORE_MGR")}),
        );
        ty(
            "_SMKM_STORE_MGR",
            1024,
            json!({"Smkm":inline(0,"_SMKM"),"KeyToStoreTree":pointer(512)}),
        );
        ty("_SMKM", 256, json!({"StoreMetaDataArray":pointer(0)}));
        ty("_SMKM_STORE_METADATA", 40, json!({"SmkmStore":pointer(0)}));
        ty(
            "_SMKM_STORE",
            1024,
            json!({"StStore":inline(0,"_ST_STORE"),"CompressedRegionPtrArray":pointer(768),"OwnerProcess":pointer(776)}),
        );
        ty(
            "_ST_STORE",
            768,
            json!({"StDataMgr":inline(0,"_ST_DATA_MGR")}),
        );
        ty(
            "_ST_DATA_MGR",
            768,
            json!({"PagesTree":pointer(0),"ChunkMetaData":inline(256,"_SMHP_CHUNK_METADATA"),"RegionSizeMask":field(16,"u32"),"RegionIndexMask":field(20,"u32"),"CompressionAlgorithm":field(24,"u16")}),
        );
        ty(
            "_SMHP_CHUNK_METADATA",
            512,
            json!({"ChunkPtrArray":pointer(0),"BitValue":field(256,"u32"),"PageRecordsPerChunkMask":field(260,"u32"),"PageRecordSize":field(264,"u32"),"ChunkPageHeaderSize":field(272,"u32")}),
        );
        ty(
            "_ST_PAGE_RECORD",
            8,
            json!({"Key":field(0,"u32"),"CompressedSize":field(4,"u16"),"NextKey":field(4,"u32")}),
        );
        ty(
            "_B_TREE",
            4096,
            json!({"Elements":field(0,"u16"),"Leaf":field(3,"u16"),"LeftChild":pointer(8),"Nodes":pointer(16)}),
        );
        ty("_B_TREE_LEAF", 4096, json!({"Nodes":pointer(16)}));
        ty("_B_TREE_NODE", 16, json!({"Child":pointer(8)}));
        let bit = |pos, len| json!({"offset":0,"type":{"kind":"bitfield","bit_position":pos,"bit_length":len,"type":{"kind":"base","name":"u64"}}});
        ty(
            "_MMPTE_SOFTWARE",
            8,
            json!({"Prototype":bit(10,1),"Transition":bit(11,1),"PageFileLow":bit(12,4),"PageFileHigh":bit(32,32),"SwizzleBit":bit(4,1)}),
        );
        isf.data["symbols"]["SmGlobals"] = json!({"address":0x4000});
        b[0x8200..0x8204].copy_from_slice(&18362u32.to_le_bytes());
        put(&mut b, 0x1000, 0x2003); // User VA shares the synthetic leaf table.
        put(&mut b, 0x4018, (1 << 32) | (2 << 12) | 16);
        put(&mut b, 0xc000, K + 0x5000);
        put(&mut b, 0xc200, K + 0x7000);
        put(&mut b, 0xd000, K + 0x6000);
        put(&mut b, 0xe000, K + 0x8000);
        b[0xe010..0xe014].copy_from_slice(&0xfffu32.to_le_bytes());
        b[0xe014..0xe018].copy_from_slice(&12u32.to_le_bytes());
        b[0xe018..0xe01a].copy_from_slice(&3u16.to_le_bytes());
        put(&mut b, 0xe100, K + 0x9000);
        b[0xe200..0xe204].copy_from_slice(&4u32.to_le_bytes());
        b[0xe204..0xe208].copy_from_slice(&15u32.to_le_bytes());
        b[0xe208..0xe20c].copy_from_slice(&8u32.to_le_bytes());
        put(&mut b, 0xe300, K + 0xb000);
        put(&mut b, 0xe308, K + 0x2000);
        for (at, value) in [(0xf000, 0), (0x10000, 16)] {
            b[at..at + 2].copy_from_slice(&1u16.to_le_bytes());
            b[at + 3] = 1;
            b[at + 16..at + 20].copy_from_slice(&0x20000001u32.to_le_bytes());
            b[at + 20..at + 24].copy_from_slice(&(value as u32).to_le_bytes());
        }
        put(&mut b, 0x11000, K + 0xa000);
        b[0x12000..0x12004].copy_from_slice(&0x1000u32.to_le_bytes());
        b[0x12004..0x12006].copy_from_slice(&11u16.to_le_bytes());
        put(&mut b, 0x13008, 0x10000);
        b[0x18000..0x1800b].copy_from_slice(&[0, 0, 0, 0x40, b'z', 7, 0, 15, 255, 0xfc, 0x0f]);
        let mut sources = paging::Sources::open(&Options::default(), &Job::default()).unwrap();
        sources.kernel_context = Some((0x1000, K));
        sources.virtual_indexes.insert(2);
        (b, isf, sources)
    }
    #[test]
    fn reconstructs_symbol_driven_store_page_and_rejects_tree_cycles() {
        let (mut b, isf, sources) = setup();
        let img = image(&b);
        let vm = Memory {
            image: &img,
            root: 0x1000,
            isf: &isf,
            sources: Some(&sources),
        };
        let mut bytes = [0; 32];
        vm.read(K + 0x3010, &mut bytes).unwrap();
        assert_eq!(bytes, [b'z'; 32]);
        assert_eq!(sources.compressed_evidence().unwrap()[0]["owner_pid"], 8);
        assert!(tree_search(&vm, K + 0x7000, 0x20000002, &Job::default()).is_err());
        b[0xf003] = 0;
        put(&mut b, 0xf018, K + 0x7000);
        let img = image(&b);
        let vm = Memory {
            image: &img,
            root: 0x1000,
            isf: &isf,
            sources: None,
        };
        assert!(tree_search(&vm, K + 0x7000, 0x20000001, &Job::default()).is_err());
        assert!(tree_search(&vm, K + 0x7000, 1, &Job::default()).is_err());
    }
}
