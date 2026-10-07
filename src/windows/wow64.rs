//! Stable 32-bit NT user ABI: PEB, loader lists and UNICODE_STRING32.
//! Layout facts: Microsoft NT types and Windows 7–11 x86 PDB layouts.
use super::*;
impl Memory<'_> {
    pub(super) fn unicode32(&self, address: u64) -> Result<String> {
        let length = self.uint(address, 2)?;
        let max = self.uint(add(address, 2)?, 2)?;
        ensure!(
            length <= max && length.is_multiple_of(2) && length <= 65534,
            "UNICODE_STRING32 长度无效"
        );
        let pointer = self.uint(add(address, 4)?, 4)?;
        let mut bytes = vec![0; length as usize];
        if length > 0 {
            ensure!(pointer != 0, "UNICODE_STRING32 空指针");
            self.read(pointer, &mut bytes)?;
        }
        Ok(String::from_utf16_lossy(
            &bytes
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect::<Vec<_>>(),
        ))
    }
}
impl Windows<'_> {
    pub(super) fn wow64_peb(&self, p: &Process) -> Result<Option<u64>> {
        if Architecture::from_isf(self.vm.isf)? == Architecture::X86 {
            return Ok(None);
        }
        let Some(field) = ["WoW64Process", "Wow64Process"]
            .into_iter()
            .find(|f| self.vm.isf.field("_EPROCESS", f).is_ok())
        else {
            return Ok(None);
        };
        let pointer = self.number(p.address, "_EPROCESS", field)?;
        if pointer == 0 {
            return Ok(None);
        }
        let peb = if self.vm.isf.field("_EWOW64PROCESS", "Peb").is_ok() {
            self.number(pointer, "_EWOW64PROCESS", "Peb")?
        } else {
            pointer
        };
        ensure!(
            peb != 0 && peb <= u32::MAX as u64,
            "WOW64 PEB 不是 32 位用户地址"
        );
        Ok(Some(peb))
    }
    pub(super) fn wow64_command(&self, p: &Process, peb: u64) -> Result<String> {
        let vm = self.process_memory(p)?;
        let parameters = vm.uint(add(peb, 16)?, 4)?;
        ensure!(parameters != 0, "WOW64 ProcessParameters 不存在");
        vm.unicode32(add(parameters, 64)?)
    }
    pub(super) fn wow64_dlls(
        &self,
        p: &Process,
        peb: u64,
        job: &Job,
        result: &mut Results,
    ) -> Result<Vec<(u64, u64, String, String)>> {
        let vm = self.process_memory(p)?;
        let ldr = vm.uint(add(peb, 12)?, 4)?;
        ensure!(ldr != 0, "WOW64 loader 不存在");
        let head = add(ldr, 12)?;
        let mut node = vm.uint(head, 4)?;
        let mut previous = head;
        let mut seen = HashSet::new();
        let mut rows = Vec::new();
        while node != head {
            job.check()?;
            let read = (|| -> Result<u64> {
                ensure!(
                    node <= u32::MAX as u64
                        && node.is_multiple_of(4)
                        && seen.insert(node)
                        && seen.len() <= MAX_OBJECTS,
                    "WOW64 DLL 链表无效/循环/超限"
                );
                ensure!(
                    vm.uint(add(node, 4)?, 4)? == previous,
                    "WOW64 DLL 双向链表不一致"
                );
                let base = vm.uint(add(node, 24)?, 4)?;
                let size = vm.uint(add(node, 32)?, 4)?;
                ensure!(
                    base != 0 && size > 0 && base + size <= 0x1_0000_0000,
                    "WOW64 DLL 范围无效"
                );
                let name = vm.unicode32(add(node, 36)?)?;
                rows.push((base, size, name, "wow64".into()));
                vm.uint(node, 4)
            })();
            match read {
                Ok(next) => {
                    previous = node;
                    node = next
                }
                Err(e) => {
                    Self::issue(result, format!("PID {} WOW64 DLL {node:#x}", p.pid), e);
                    return Ok(rows);
                }
            }
        }
        if vm.uint(add(head, 4)?, 4)? != previous {
            Self::issue(result, format!("PID {} WOW64 DLL", p.pid), "链表未闭合");
        }
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{K, fixture, image, put};
    use super::*;
    #[test]
    fn unicode32_command_and_loader_list_use_four_byte_pointers() {
        let (mut b, mut isf) = fixture();
        // Map a low 32-bit user address into the same fixture's physical pages.
        put(&mut b, 0x1000, 0x2003);
        isf.data["user_types"]["_EPROCESS"]["fields"]["WoW64Process"] =
            serde_json::json!({"offset":136,"type":{"kind":"pointer"}});
        isf.data["user_types"]["_EWOW64PROCESS"] =
            serde_json::json!({"size":16,"fields":{"Peb":{"offset":0,"type":{"kind":"pointer"}}}});
        put(&mut b, 0xa088, K + 0x3000);
        put(&mut b, 0xb000, 0x4000);
        b[0xc010..0xc014].copy_from_slice(&0x5000u32.to_le_bytes());
        b[0xd040..0xd044].copy_from_slice(&[6, 0, 6, 0]);
        b[0xd044..0xd048].copy_from_slice(&0x6000u32.to_le_bytes());
        b[0xe000..0xe006].copy_from_slice(&[97, 0, 98, 0, 99, 0]);
        b[0xc00c..0xc010].copy_from_slice(&0x7000u32.to_le_bytes());
        b[0xf00c..0xf010].copy_from_slice(&0x8000u32.to_le_bytes());
        b[0xf010..0xf014].copy_from_slice(&0x8000u32.to_le_bytes());
        b[0x10000..0x10004].copy_from_slice(&0x700cu32.to_le_bytes());
        b[0x10004..0x10008].copy_from_slice(&0x700cu32.to_le_bytes());
        b[0x10018..0x1001c].copy_from_slice(&0x9000u32.to_le_bytes());
        b[0x10020..0x10024].copy_from_slice(&4096u32.to_le_bytes());
        b[0x10024..0x10028].copy_from_slice(&[6, 0, 6, 0]);
        b[0x10028..0x1002c].copy_from_slice(&0x6000u32.to_le_bytes());
        let img = image(&b);
        let engine = Windows {
            vm: Memory::new(&img, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let p = engine.process(K + 0x2000).unwrap();
        let peb = engine.wow64_peb(&p).unwrap().unwrap();
        assert_eq!(peb, 0x4000);
        assert_eq!(engine.wow64_command(&p, peb).unwrap(), "abc");
        let mut result = engine.result(Plugin::WinDlllist);
        let rows = engine
            .wow64_dlls(&p, peb, &Job::default(), &mut result)
            .unwrap();
        assert_eq!(rows, vec![(0x9000, 4096, "abc".into(), "wow64".into())]);
        assert!(result.complete);
    }
}
