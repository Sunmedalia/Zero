//! Native BTF (BPF Type Format) to ISF type conversion.
//!
//! Field layouts, base types and enums follow the rules dwarf2json applies to
//! DWARF, so the engine reads a BTF-derived ISF exactly like a debug-ELF one:
//! typedefs resolve to their target except a typedef of a struct/union, which
//! is named (and duplicated) by the typedef, anonymous members are `unnamed_field_N`, bitfields
//! carry byte offset plus `bit_position`, and qualifiers are transparent.
//! Anonymous type names are deterministic content hashes (`unnamed_<16 hex>`);
//! they are opaque and only need to be unique and stable.
use crate::bytes::{Checked as _, le_u16, le_u32};
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

const MAGIC: u16 = 0xeb9f;
const HEADER: usize = 24;
const MAX_TYPES: usize = 1 << 22;
const MAX_DEPTH: usize = 64;
const BTF_INT_SIGNED: u8 = 1;
const BTF_INT_CHAR: u8 = 2;
const BTF_INT_BOOL: u8 = 4;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Int,
    Ptr,
    Array,
    Struct,
    Union,
    Enum,
    Fwd,
    Typedef,
    Volatile,
    Const,
    Restrict,
    Func,
    FuncProto,
    Var,
    Datasec,
    Float,
    DeclTag,
    TypeTag,
    Enum64,
}
impl Kind {
    fn from_raw(raw: u32) -> Result<Self> {
        Ok(match raw {
            1 => Self::Int,
            2 => Self::Ptr,
            3 => Self::Array,
            4 => Self::Struct,
            5 => Self::Union,
            6 => Self::Enum,
            7 => Self::Fwd,
            8 => Self::Typedef,
            9 => Self::Volatile,
            10 => Self::Const,
            11 => Self::Restrict,
            12 => Self::Func,
            13 => Self::FuncProto,
            14 => Self::Var,
            15 => Self::Datasec,
            16 => Self::Float,
            17 => Self::DeclTag,
            18 => Self::TypeTag,
            19 => Self::Enum64,
            _ => bail!("BTF 类型种类未知: {raw}"),
        })
    }
}

struct Member {
    name: u32,
    ty: u32,
    offset: u32,
}
enum Extra {
    None,
    Int { encoding: u8, offset: u8, bits: u8 },
    Array { elem: u32, nelems: u32 },
    Members(Vec<Member>),
    Enum(Vec<(u32, i128)>),
    Datasec(Vec<(u32, u32, u32)>),
}
struct Type {
    kind: Kind,
    name: u32,
    kind_flag: bool,
    /// `size` for sized kinds, the referenced type id otherwise.
    size_or_type: u32,
    extra: Extra,
}

/// Parsed, bounds-checked BTF. Type id 0 is `void` and has no entry.
pub(super) struct Btf {
    strings: Vec<u8>,
    types: Vec<Type>,
}

fn word(bytes: &[u8], at: usize) -> Result<u32> {
    le_u32(bytes, at).context("BTF 数据被截断")
}

impl Btf {
    pub(super) fn parse(data: &[u8], job: &crate::Job) -> Result<Self> {
        job.check()?;
        ensure!(
            le_u16(data, 0) == Some(MAGIC),
            "BTF magic 无效（仅支持小端）"
        );
        ensure!(data.get(2) == Some(&1), "BTF 版本不受支持");
        let header = usize::try_from(word(data, 4)?)?;
        ensure!(header >= HEADER, "BTF 头长度无效");
        let section = |offset: usize, length: usize| -> Result<&[u8]> {
            let start = usize::try_from(word(data, offset)?)?
                .checked_add(header)
                .context("BTF 偏移溢出")?;
            let len = usize::try_from(word(data, length)?)?;
            data.get(start..start.checked_add(len).context("BTF 长度溢出")?)
                .context("BTF 段越界")
        };
        let types = section(8, 12)?;
        let strings = section(16, 20)?.to_vec();
        ensure!(strings.first() == Some(&0), "BTF 字符串表无效");
        let mut out = Vec::new();
        let mut at = 0usize;
        while at < types.len() {
            if out.len() % 4096 == 0 {
                job.check()?;
                job.report(format!("BTF 解析: {} 个类型", out.len()));
            }
            ensure!(out.len() < MAX_TYPES, "BTF 类型数量过多");
            let name = word(types, at)?;
            let info = word(types, at + 4)?;
            let size_or_type = word(types, at + 8)?;
            at += 12;
            let kind = Kind::from_raw((info >> 24) & 0x1f)?;
            let vlen = usize::try_from(info & 0xffff)?;
            let kind_flag = info >> 31 == 1;
            let extra = match kind {
                Kind::Int => {
                    let value = word(types, at)?;
                    at += 4;
                    let [bits, _, offset, encoding] = value.to_le_bytes();
                    Extra::Int {
                        encoding: encoding & 0x0f,
                        offset,
                        bits,
                    }
                }
                Kind::Array => {
                    let elem = word(types, at)?;
                    let nelems = word(types, at + 8)?;
                    at += 12;
                    Extra::Array { elem, nelems }
                }
                Kind::Struct | Kind::Union => {
                    let mut members = Vec::with_capacity(vlen);
                    for i in 0..vlen {
                        if i % 4096 == 0 {
                            job.check()?;
                        }
                        members.push(Member {
                            name: word(types, at)?,
                            ty: word(types, at + 4)?,
                            offset: word(types, at + 8)?,
                        });
                        at += 12;
                    }
                    Extra::Members(members)
                }
                Kind::Enum => {
                    let mut values = Vec::with_capacity(vlen);
                    for i in 0..vlen {
                        if i % 4096 == 0 {
                            job.check()?;
                        }
                        let raw = word(types, at + 4)?;
                        let value = if kind_flag {
                            i128::from(i32::from_le_bytes(raw.to_le_bytes()))
                        } else {
                            i128::from(raw)
                        };
                        values.push((word(types, at)?, value));
                        at += 8;
                    }
                    Extra::Enum(values)
                }
                Kind::Enum64 => {
                    let mut values = Vec::with_capacity(vlen);
                    for i in 0..vlen {
                        if i % 4096 == 0 {
                            job.check()?;
                        }
                        let raw = u64::from(word(types, at + 4)?)
                            | (u64::from(word(types, at + 8)?) << 32);
                        let value = if kind_flag {
                            i128::from(i64::from_le_bytes(raw.to_le_bytes()))
                        } else {
                            i128::from(raw)
                        };
                        values.push((word(types, at)?, value));
                        at += 12;
                    }
                    Extra::Enum(values)
                }
                Kind::FuncProto => {
                    at = at
                        .checked_add(vlen.checked_mul(8).context("BTF 长度溢出")?)
                        .context("BTF 长度溢出")?;
                    Extra::None
                }
                Kind::Var | Kind::DeclTag => {
                    at += 4;
                    Extra::None
                }
                Kind::Datasec => {
                    let mut vars = Vec::with_capacity(vlen);
                    for i in 0..vlen {
                        if i % 4096 == 0 {
                            job.check()?;
                        }
                        vars.push((word(types, at)?, word(types, at + 4)?, word(types, at + 8)?));
                        at += 12;
                    }
                    Extra::Datasec(vars)
                }
                Kind::Ptr
                | Kind::Fwd
                | Kind::Typedef
                | Kind::Volatile
                | Kind::Const
                | Kind::Restrict
                | Kind::Func
                | Kind::Float
                | Kind::TypeTag => Extra::None,
            };
            ensure!(at <= types.len(), "BTF 类型段被截断");
            out.push(Type {
                kind,
                name,
                kind_flag,
                size_or_type,
                extra,
            });
        }
        ensure!(!out.is_empty(), "BTF 不含类型");
        job.check()?;
        Ok(Self {
            strings,
            types: out,
        })
    }

    pub(super) fn len(&self) -> usize {
        self.types.len()
    }

    fn name(&self, offset: u32) -> Result<&str> {
        let start = usize::try_from(offset)?;
        let tail = self.strings.at(start..)?;
        let end = tail
            .iter()
            .position(|b| *b == 0)
            .context("BTF 字符串未终止")?;
        std::str::from_utf8(tail.at(..end)?).context("BTF 字符串不是 UTF-8")
    }

    fn get(&self, id: u32) -> Result<&Type> {
        let index = usize::try_from(id)?
            .checked_sub(1)
            .context("BTF void 没有类型记录")?;
        self.types
            .get(index)
            .with_context(|| format!("BTF 类型 id 越界: {id}"))
    }

    /// Whether `name` is a complete struct or union, i.e. the BTF describes kernel types.
    pub(super) fn has_struct(&self, name: &str) -> bool {
        self.types.iter().any(|t| {
            matches!(t.kind, Kind::Struct | Kind::Union) && self.name(t.name).ok() == Some(name)
        })
    }
}

/// ISF type sections plus the BTF-typed global variables.
pub(super) struct Converted {
    pub base_types: Map<String, Value>,
    pub user_types: Map<String, Value>,
    pub enums: Map<String, Value>,
    /// Variable name -> ISF type, from `DATASEC` entries (normally the per-cpu section).
    pub variables: HashMap<String, Value>,
    /// Names whose BTF definitions disagree; the first definition is kept.
    pub conflicts: Vec<String>,
}

struct Converter<'a> {
    btf: &'a Btf,
    job: &'a crate::Job,
    names: HashMap<u32, String>,
}

fn insert_checked(
    map: &mut Map<String, Value>,
    name: String,
    value: Value,
    conflicts: &mut Vec<String>,
) {
    match map.get(&name) {
        Some(existing) if *existing != value => conflicts.push(name),
        Some(_) => {}
        None => {
            map.insert(name, value);
        }
    }
}

impl Converter<'_> {
    fn descriptor(&mut self, id: u32, depth: usize) -> Result<Value> {
        self.job.check()?;
        ensure!(depth < MAX_DEPTH, "BTF 类型引用过深: {id}");
        if id == 0 {
            return Ok(json!({"kind":"base","name":"void"}));
        }
        let btf = self.btf;
        let t = btf.get(id)?;
        Ok(match t.kind {
            Kind::Int | Kind::Float => json!({"kind":"base","name":btf.name(t.name)?}),
            Kind::Ptr => {
                json!({"kind":"pointer","subtype":self.descriptor(t.size_or_type, depth + 1)?})
            }
            Kind::Array => {
                let Extra::Array { elem, nelems } = t.extra else {
                    bail!("BTF 数组记录无效")
                };
                json!({"kind":"array","count":nelems,"subtype":self.descriptor(elem, depth + 1)?})
            }
            Kind::Struct | Kind::Union => {
                json!({"kind":aggregate(t.kind),"name":self.aggregate_name(id, depth + 1)?})
            }
            Kind::Fwd => json!({
                "kind": if t.kind_flag { "union" } else { "struct" },
                "name": btf.name(t.name)?,
            }),
            Kind::Enum | Kind::Enum64 => {
                json!({"kind":"enum","name":self.enum_name(id)?})
            }
            Kind::Typedef => {
                let target = t.size_or_type;
                match (target != 0).then(|| btf.get(target)).transpose()? {
                    // dwarf2json names every typedef of a struct/union (complete or
                    // declared) by the typedef itself, e.g. `spinlock_t`.
                    Some(inner) if matches!(inner.kind, Kind::Struct | Kind::Union) => {
                        json!({"kind":aggregate(inner.kind),"name":btf.name(t.name)?})
                    }
                    Some(inner) if inner.kind == Kind::Fwd => json!({
                        "kind": if inner.kind_flag { "union" } else { "struct" },
                        "name": btf.name(t.name)?,
                    }),
                    _ => self.descriptor(target, depth + 1)?,
                }
            }
            Kind::Volatile | Kind::Const | Kind::Restrict | Kind::TypeTag => {
                self.descriptor(t.size_or_type, depth + 1)?
            }
            Kind::FuncProto => json!({"kind":"function"}),
            Kind::Func | Kind::Var | Kind::Datasec | Kind::DeclTag => {
                bail!("BTF 类型 {id} 不能作为字段类型")
            }
        })
    }

    fn aggregate_name(&mut self, id: u32, depth: usize) -> Result<String> {
        let t = self.btf.get(id)?;
        if t.name != 0 {
            return Ok(self.btf.name(t.name)?.to_owned());
        }
        if let Some(name) = self.names.get(&id) {
            return Ok(name.clone());
        }
        let canonical = json!({
            "kind": aggregate(t.kind),
            "size": t.size_or_type,
            "fields": self.fields(id, depth + 1)?,
        });
        let name = hashed(&canonical);
        self.names.insert(id, name.clone());
        Ok(name)
    }

    fn enum_name(&mut self, id: u32) -> Result<String> {
        let t = self.btf.get(id)?;
        if t.name != 0 {
            return Ok(self.btf.name(t.name)?.to_owned());
        }
        if let Some(name) = self.names.get(&id) {
            return Ok(name.clone());
        }
        let name =
            hashed(&json!({"kind":"enum","size":t.size_or_type,"constants":self.constants(t)?}));
        self.names.insert(id, name.clone());
        Ok(name)
    }

    fn constants(&self, t: &Type) -> Result<Map<String, Value>> {
        let Extra::Enum(values) = &t.extra else {
            bail!("BTF 枚举记录无效")
        };
        let mut out = Map::new();
        for (name, value) in values {
            self.job.check()?;
            let value = if let Ok(v) = i64::try_from(*value) {
                json!(v)
            } else {
                json!(u64::try_from(*value).context("BTF 枚举值越界")?)
            };
            out.insert(self.btf.name(*name)?.to_owned(), value);
        }
        Ok(out)
    }

    /// Integer behind typedefs and qualifiers, for legacy (non-`kind_flag`) bitfields.
    fn int_of(&self, mut id: u32) -> Result<Option<(u8, u8, u32)>> {
        for _ in 0..MAX_DEPTH {
            if id == 0 {
                return Ok(None);
            }
            let t = self.btf.get(id)?;
            match (t.kind, &t.extra) {
                (Kind::Int, Extra::Int { offset, bits, .. }) => {
                    return Ok(Some((*offset, *bits, t.size_or_type)));
                }
                (
                    Kind::Typedef | Kind::Volatile | Kind::Const | Kind::Restrict | Kind::TypeTag,
                    _,
                ) => {
                    id = t.size_or_type;
                }
                _ => return Ok(None),
            }
        }
        bail!("BTF 类型引用过深: {id}")
    }

    fn fields(&mut self, id: u32, depth: usize) -> Result<Map<String, Value>> {
        self.job.check()?;
        ensure!(depth < MAX_DEPTH, "BTF 匿名结构嵌套过深: {id}");
        let btf = self.btf;
        let t = btf.get(id)?;
        let Extra::Members(members) = &t.extra else {
            bail!("BTF 结构记录无效")
        };
        let mut out = Map::new();
        let mut anonymous = 0usize;
        for member in members {
            self.job.check()?;
            let (mut bit, mut width) = if t.kind_flag {
                (member.offset & 0x00ff_ffff, member.offset >> 24)
            } else {
                (member.offset, 0)
            };
            if !t.kind_flag
                && let Some((offset, bits, size)) = self.int_of(member.ty)?
                && (offset != 0 || u32::from(bits) != size.saturating_mul(8))
            {
                bit = bit
                    .checked_add(u32::from(offset))
                    .context("BTF 位偏移溢出")?;
                width = u32::from(bits);
            }
            let ty = self.descriptor(member.ty, depth + 1)?;
            let mut field = if width != 0 {
                json!({
                    "offset": bit / 8,
                    "type": {"kind":"bitfield","bit_length":width,"bit_position":bit % 8,"type":ty},
                })
            } else {
                ensure!(bit % 8 == 0, "BTF 字段未按字节对齐: 类型 {id}");
                json!({"offset": bit / 8, "type": ty})
            };
            let name = if member.name == 0 {
                let name = format!("unnamed_field_{anonymous:x}");
                anonymous += 1;
                if let Some(object) = field.as_object_mut() {
                    object.insert("anonymous".into(), json!(true));
                }
                name
            } else {
                btf.name(member.name)?.to_owned()
            };
            out.insert(name, field);
        }
        Ok(out)
    }
}

fn aggregate(kind: Kind) -> &'static str {
    if kind == Kind::Union {
        "union"
    } else {
        "struct"
    }
}

fn hashed(canonical: &Value) -> String {
    let digest = Sha256::digest(canonical.to_string().as_bytes());
    let mut name = String::from("unnamed_");
    for byte in digest.iter().take(8) {
        name.push_str(&format!("{byte:02x}"));
    }
    name
}

/// Convert every BTF type into ISF sections. `pointer_size` is the target's pointer width.
pub(super) fn convert(btf: &Btf, pointer_size: u64, job: &crate::Job) -> Result<Converted> {
    let mut converter = Converter {
        btf,
        job,
        names: HashMap::new(),
    };
    let mut base_types = Map::new();
    base_types.insert(
        "void".into(),
        json!({"size":0,"signed":false,"kind":"void","endian":"little"}),
    );
    let mut user_types = Map::new();
    let mut enums = Vec::new();
    let mut variables = HashMap::new();
    let mut duplicate_variables = Vec::new();
    let mut conflicts = Vec::new();
    for (index, t) in btf.types.iter().enumerate() {
        if index % 4096 == 0 {
            job.check()?;
            job.report(format!("BTF 转换: {index}/{} 个类型", btf.len()));
        }
        let id = u32::try_from(index + 1)?;
        match (t.kind, &t.extra) {
            (Kind::Int, Extra::Int { encoding, .. }) => {
                let name = btf.name(t.name)?;
                let size = t.size_or_type;
                let (kind, signed) = if encoding & BTF_INT_BOOL != 0 {
                    // dwarf2json reports DWARF booleans as signed.
                    ("bool", true)
                } else if encoding & BTF_INT_CHAR != 0 || (size == 1 && name.ends_with("char")) {
                    ("char", encoding & BTF_INT_SIGNED != 0)
                } else {
                    ("int", encoding & BTF_INT_SIGNED != 0)
                };
                if !base_types.contains_key(name) {
                    base_types.insert(
                        name.to_owned(),
                        json!({"size":size,"signed":signed,"kind":kind,"endian":"little"}),
                    );
                }
            }
            (Kind::Float, _) => {
                let name = btf.name(t.name)?;
                if !base_types.contains_key(name) {
                    base_types.insert(
                        name.to_owned(),
                        json!({"size":t.size_or_type,"signed":true,"kind":"float","endian":"little"}),
                    );
                }
            }
            (Kind::Ptr, _) if !base_types.contains_key("pointer") => {
                base_types.insert(
                    "pointer".into(),
                    json!({"size":pointer_size,"signed":false,"kind":"int","endian":"little"}),
                );
            }
            (Kind::Struct | Kind::Union, _) => {
                let name = converter.aggregate_name(id, 0)?;
                let value = json!({
                    "size": t.size_or_type,
                    "fields": converter.fields(id, 0)?,
                    "kind": aggregate(t.kind),
                });
                insert_checked(&mut user_types, name, value, &mut conflicts);
            }
            (Kind::Typedef, _) if t.size_or_type != 0 => {
                let inner = btf.get(t.size_or_type)?;
                if matches!(inner.kind, Kind::Struct | Kind::Union) {
                    let value = json!({
                        "size": inner.size_or_type,
                        "fields": converter.fields(t.size_or_type, 0)?,
                        "kind": aggregate(inner.kind),
                    });
                    insert_checked(
                        &mut user_types,
                        btf.name(t.name)?.to_owned(),
                        value,
                        &mut conflicts,
                    );
                }
            }
            (Kind::Enum | Kind::Enum64, _) => {
                let name = converter.enum_name(id)?;
                enums.push((name, t.size_or_type, converter.constants(t)?));
            }
            (Kind::Datasec, Extra::Datasec(vars)) => {
                for (var, _, _) in vars {
                    let v = btf.get(*var)?;
                    ensure!(v.kind == Kind::Var, "BTF DATASEC 引用了非变量类型");
                    let name = btf.name(v.name)?.to_owned();
                    let ty = converter.descriptor(v.size_or_type, 0)?;
                    if variables.insert(name.clone(), ty).is_some() {
                        duplicate_variables.push(name);
                    }
                }
            }
            _ => {}
        }
    }
    for name in duplicate_variables {
        variables.remove(&name);
    }
    if !base_types.contains_key("pointer") {
        base_types.insert(
            "pointer".into(),
            json!({"size":pointer_size,"signed":false,"kind":"int","endian":"little"}),
        );
    }
    // dwarf2json picks the first sorted integer base type of the same size and signedness.
    let mut enum_map = Map::new();
    for (name, size, constants) in enums {
        let signed = constants
            .values()
            .any(|v| v.as_i64().is_some_and(|v| v < 0));
        let base = base_types
            .iter()
            .find(|(_, b)| {
                b["kind"] == "int"
                    && b["size"].as_u64() == Some(u64::from(size))
                    && b["signed"] == signed
            })
            .map_or("void", |(name, _)| name.as_str())
            .to_owned();
        insert_checked(
            &mut enum_map,
            name,
            json!({"size":size,"base":base,"constants":constants}),
            &mut conflicts,
        );
    }
    conflicts.sort();
    conflicts.dedup();
    job.check()?;
    Ok(Converted {
        base_types,
        user_types,
        enums: enum_map,
        variables,
        conflicts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal BTF builder: `types` are raw records, `strings` the string table.
    fn btf(types: &[u8], strings: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC.to_le_bytes());
        out.extend_from_slice(&[1, 0]);
        for value in [
            24u32,
            0,
            types.len() as u32,
            types.len() as u32,
            strings.len() as u32,
        ] {
            out.extend_from_slice(&value.to_le_bytes());
        }
        out.extend_from_slice(types);
        out.extend_from_slice(strings);
        out
    }
    fn record(out: &mut Vec<u8>, words: &[u32]) {
        for word in words {
            out.extend_from_slice(&word.to_le_bytes());
        }
    }
    fn info(kind: u32, vlen: u32, flag: bool) -> u32 {
        (u32::from(flag) << 31) | (kind << 24) | vlen
    }

    #[test]
    fn converts_structs_typedefs_bitfields_anonymous_members_and_enums() {
        // strings: 1 "int", 5 "unsigned int", 18 "list_head", 28 "next", 33 "prev",
        // 38 "task", 43 "flags", 49 "kuid_t", 56 "val", 60 "mode", 65 "A", 67 "B", 69 "e"
        let strings =
            b"\0int\0unsigned int\0list_head\0next\0prev\0task\0flags\0kuid_t\0val\0mode\0A\0B\0e\0";
        let mut t = Vec::new();
        record(&mut t, &[1, info(1, 0, false), 4, (1 << 24) | 32]); // 1 int
        record(&mut t, &[5, info(1, 0, false), 4, 32]); // 2 unsigned int
        record(&mut t, &[18, info(4, 2, false), 16]); // 3 struct list_head
        record(&mut t, &[28, 4, 0, 33, 4, 64]);
        record(&mut t, &[0, info(2, 0, false), 3]); // 4 ptr -> list_head
        record(&mut t, &[0, info(4, 1, false), 4]); // 5 anon struct {val}
        record(&mut t, &[56, 2, 0]);
        record(&mut t, &[49, info(8, 0, false), 5]); // 6 typedef kuid_t -> anon
        record(&mut t, &[0, info(10, 0, false), 6]); // 7 const kuid_t
        record(&mut t, &[69, info(6, 2, true), 4]); // 8 enum e (signed)
        record(&mut t, &[65, 0, 67, u32::MAX]);
        record(&mut t, &[38, info(4, 4, true), 32]); // 9 struct task (kind_flag)
        record(&mut t, &[0, 3, 0]); // anonymous list_head member at 0
        record(&mut t, &[43, 2, (3 << 24) | 130]); // flags: 3 bits at bit 130
        record(&mut t, &[56, 7, 192]); // val: const kuid_t at byte 24
        record(&mut t, &[60, 8, 224]); // mode: enum at byte 28
        let parsed = Btf::parse(&btf(&t, strings), &crate::Job::default()).unwrap();
        let out = convert(&parsed, 8, &crate::Job::default()).unwrap();
        assert!(out.conflicts.is_empty());
        let task = &out.user_types["task"];
        assert_eq!(task["size"], 32);
        assert_eq!(
            task["fields"]["unnamed_field_0"],
            json!({"offset":0,"anonymous":true,"type":{"kind":"struct","name":"list_head"}})
        );
        assert_eq!(
            task["fields"]["flags"],
            json!({"offset":16,"type":{"kind":"bitfield","bit_length":3,"bit_position":2,"type":{"kind":"base","name":"unsigned int"}}})
        );
        assert_eq!(
            task["fields"]["val"]["type"],
            json!({"kind":"struct","name":"kuid_t"})
        );
        assert_eq!(
            task["fields"]["mode"]["type"],
            json!({"kind":"enum","name":"e"})
        );
        assert_eq!(out.user_types["kuid_t"]["fields"]["val"]["offset"], 0);
        assert_eq!(
            out.user_types["list_head"]["fields"]["prev"],
            json!({"offset":8,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"list_head"}}})
        );
        // The anonymous struct is also present under a stable content hash.
        let anonymous: Vec<_> = out
            .user_types
            .keys()
            .filter(|k| k.starts_with("unnamed_"))
            .collect();
        assert_eq!(anonymous.len(), 1);
        assert_eq!(anonymous[0].len(), "unnamed_".len() + 16);
        assert_eq!(
            out.enums["e"],
            json!({"size":4,"base":"int","constants":{"A":0,"B":-1}})
        );
        assert_eq!(out.base_types["int"]["signed"], true);
        assert_eq!(out.base_types["pointer"]["size"], 8);
    }

    #[test]
    fn legacy_int_bitfields_and_per_cpu_variables() {
        // strings: 1 "unsigned int", 14 "s", 16 "a", 18 "var", 22 ".data..percpu"
        let strings = b"\0unsigned int\0s\0a\0var\0.data..percpu\0";
        let mut t = Vec::new();
        record(&mut t, &[1, info(1, 0, false), 4, 32]); // 1 unsigned int
        record(&mut t, &[0, info(1, 0, false), 4, (5 << 16) | 3]); // 2 int:3 at +5
        record(&mut t, &[14, info(4, 1, false), 4]); // 3 struct s
        record(&mut t, &[16, 2, 8]);
        record(&mut t, &[18, info(14, 0, false), 3, 1]); // 4 var s var
        record(&mut t, &[22, info(15, 1, false), 4]); // 5 datasec
        record(&mut t, &[4, 0, 4]);
        let parsed = Btf::parse(&btf(&t, strings), &crate::Job::default()).unwrap();
        let out = convert(&parsed, 8, &crate::Job::default()).unwrap();
        assert_eq!(
            out.user_types["s"]["fields"]["a"],
            json!({"offset":1,"type":{"kind":"bitfield","bit_length":3,"bit_position":5,"type":{"kind":"base","name":""}}})
        );
        assert_eq!(out.variables["var"], json!({"kind":"struct","name":"s"}));
    }

    #[test]
    fn truncated_cyclic_and_foreign_inputs_fail_cleanly() {
        assert!(Btf::parse(b"\x9f\xeb", &crate::Job::default()).is_err());
        assert!(Btf::parse(&[0; 64], &crate::Job::default()).is_err());
        let mut t = Vec::new();
        record(&mut t, &[0, info(4, 1, false), 4]); // 1 struct with truncated member
        assert!(Btf::parse(&btf(&t, b"\0"), &crate::Job::default()).is_err());
        // A const chain that loops never terminates in DWARF terms; BTF must reject it.
        let mut t = Vec::new();
        record(&mut t, &[0, info(10, 0, false), 2]); // 1 const -> 2
        record(&mut t, &[0, info(10, 0, false), 1]); // 2 const -> 1
        record(&mut t, &[1, info(4, 1, false), 8]); // 3 struct s { 1 x }
        record(&mut t, &[1, 1, 0]);
        let parsed = Btf::parse(&btf(&t, b"\0s\0"), &crate::Job::default()).unwrap();
        assert!(convert(&parsed, 8, &crate::Job::default()).is_err());
    }
}

#[cfg(test)]
mod cancellation_tests {
    use super::*;
    #[test]
    fn parser_checks_cancellation_before_inspecting_data() {
        let job = crate::Job::default();
        job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        let error = Btf::parse(&[], &job).err().unwrap();
        assert!(error.to_string().contains("cancelled"));
    }
}
