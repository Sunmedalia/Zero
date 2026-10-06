//! Microsoft CONTEXT integer/control subsets. Respect ContextFlags, never invent registers.
use super::*;
pub(super) fn parse(
    bytes: &[u8],
    arch: Architecture,
    tid: Option<u32>,
    offset: u64,
) -> Result<ThreadContext> {
    let uint = |at: usize, width: usize| -> Result<u64> {
        let b = bytes.get(at..at + width).context("CONTEXT 截断")?;
        let mut out = [0; 8];
        out[..width].copy_from_slice(b);
        Ok(u64::from_le_bytes(out))
    };
    let flags = uint(if arch == Architecture::X64 { 48 } else { 0 }, 4)?;
    let expected = match arch {
        Architecture::X86 => 0x10000,
        Architecture::X64 => 0x100000,
        Architecture::Arm64 => 0x400000,
        Architecture::Auto => bail!("CONTEXT 缺少 CPU 身份"),
    };
    ensure!(flags & 0x00ff0000 == expected, "CONTEXT 架构标志冲突");
    let mut registers = BTreeMap::new();
    if flags & 1 != 0 {
        let control: &[(&str, usize, usize)] = match arch {
            Architecture::X86 => &[
                ("Ebp", 180, 4),
                ("Eip", 184, 4),
                ("EFlags", 192, 4),
                ("Esp", 196, 4),
            ],
            Architecture::X64 => &[("Rsp", 152, 8), ("Rip", 248, 8), ("EFlags", 68, 4)],
            Architecture::Arm64 => &[
                ("Fp", 240, 8),
                ("Lr", 248, 8),
                ("Sp", 256, 8),
                ("Pc", 264, 8),
                ("Cpsr", 4, 4),
            ],
            _ => unreachable!(),
        };
        for &(name, at, width) in control {
            registers.insert(name.into(), uint(at, width)?);
        }
    }
    if flags & 2 != 0 {
        match arch {
            Architecture::X86 => {
                for (name, at) in [
                    ("Edi", 156),
                    ("Esi", 160),
                    ("Ebx", 164),
                    ("Edx", 168),
                    ("Ecx", 172),
                    ("Eax", 176),
                ] {
                    registers.insert(name.into(), uint(at, 4)?);
                }
            }
            Architecture::X64 => {
                for (name, at) in [
                    ("Rax", 120),
                    ("Rcx", 128),
                    ("Rdx", 136),
                    ("Rbx", 144),
                    ("Rbp", 160),
                    ("Rsi", 168),
                    ("Rdi", 176),
                    ("R8", 184),
                    ("R9", 192),
                    ("R10", 200),
                    ("R11", 208),
                    ("R12", 216),
                    ("R13", 224),
                    ("R14", 232),
                    ("R15", 240),
                ] {
                    registers.insert(name.into(), uint(at, 8)?);
                }
            }
            Architecture::Arm64 => {
                for n in 0..29 {
                    registers.insert(format!("X{n}"), uint(8 + n * 8, 8)?);
                }
            }
            _ => unreachable!(),
        }
    }
    registers.insert("ContextFlags".into(), flags);
    Ok(ThreadContext {
        thread_id: tid,
        file_offset: offset,
        registers,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn contexts_decode_only_captured_groups_and_reject_conflicts() {
        for (arch, size, flags_at, flags, pc_at, pc) in [
            (Architecture::X86, 200, 0, 0x10001u32, 184, 0x1234u64),
            (Architecture::X64, 256, 48, 0x100001, 248, 0x12345678),
            (Architecture::Arm64, 272, 0, 0x400001, 264, 0xabcdef),
        ] {
            let mut b = vec![0; size];
            b[flags_at..flags_at + 4].copy_from_slice(&flags.to_le_bytes());
            let width = arch.pointer_size();
            b[pc_at..pc_at + width].copy_from_slice(&pc.to_le_bytes()[..width]);
            let context = parse(&b, arch, Some(7), 12).unwrap();
            let name = match arch {
                Architecture::X86 => "Eip",
                Architecture::X64 => "Rip",
                _ => "Pc",
            };
            assert_eq!(context.registers[name], pc);
            assert!(
                !context.registers.contains_key("Eax")
                    && !context.registers.contains_key("Rax")
                    && !context.registers.contains_key("X0")
            );
            assert!(parse(&b[..pc_at], arch, None, 0).is_err());
            let other = if arch == Architecture::X64 {
                Architecture::X86
            } else {
                Architecture::X64
            };
            assert!(parse(&b, other, None, 0).is_err());
        }
    }
}
