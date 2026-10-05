//! Exact Windows PDB identities and native PDB -> ISF conversion.
use crate::{
    Job,
    image::Image,
    store,
    symbols::{self, Isf},
};
use anyhow::{Context, Result, bail, ensure};
use pdb::{FallibleIterator, TypeData, TypeIndex};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs,
    path::Path,
};

pub const CONVERTER_VERSION: &str = "pdb-native-3";
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PdbIdentity {
    pub name: String,
    pub guid: String,
    pub age: u32,
}
impl PdbIdentity {
    pub fn key(&self) -> String {
        format!("{}/{}{:X}", self.name, self.guid, self.age)
    }
    pub fn url(&self) -> Result<String> {
        ensure!(
            self.name.ends_with(".pdb")
                && self
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
            "无效 PDB 名称"
        );
        ensure!(
            self.guid.len() == 32 && self.guid.bytes().all(|b| b.is_ascii_hexdigit()),
            "无效 PDB GUID"
        );
        Ok(format!(
            "https://msdl.microsoft.com/download/symbols/{}/{}",
            self.key(),
            self.name
        ))
    }
    pub fn from_key(key: &str) -> Result<Self> {
        let (name, id) = key.split_once('/').context("PDB key 无效")?;
        ensure!(
            id.len() > 32 && id.bytes().all(|b| b.is_ascii_hexdigit()),
            "PDB key 身份不完整或无效"
        );
        let identity = Self {
            name: name.into(),
            guid: id[..32].into(),
            age: u32::from_str_radix(&id[32..], 16)?,
        };
        identity.url()?;
        Ok(identity)
    }
    pub fn from_rsds(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() >= 25 && &bytes[..4] == b"RSDS",
            "无效 CodeView RSDS"
        );
        let name_bytes = &bytes[24..];
        let end = name_bytes
            .iter()
            .position(|b| *b == 0)
            .context("PDB 名称未终止")?;
        let name = std::str::from_utf8(&name_bytes[..end])?
            .rsplit(['\\', '/'])
            .next()
            .context("PDB 名称为空")?
            .to_ascii_lowercase();
        let guid = format!(
            "{:08X}{:04X}{:04X}{}",
            u32::from_le_bytes(bytes[4..8].try_into()?),
            u16::from_le_bytes(bytes[8..10].try_into()?),
            u16::from_le_bytes(bytes[10..12].try_into()?),
            bytes[12..20]
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<String>()
        );
        let identity = Self {
            name,
            guid,
            age: u32::from_le_bytes(bytes[20..24].try_into()?),
        };
        identity.url()?;
        Ok(identity)
    }
    pub fn from_isf(isf: &Isf) -> Result<Self> {
        let p = &isf.data["metadata"]["windows"]["pdb"];
        let identity = Self {
            name: p["database"]
                .as_str()
                .context("Windows ISF 缺少 PDB database")?
                .to_ascii_lowercase(),
            guid: p["GUID"]
                .as_str()
                .context("Windows ISF 缺少 GUID")?
                .replace('-', "")
                .to_ascii_uppercase(),
            age: u32::try_from(p["age"].as_u64().context("Windows ISF 缺少 age")?)?,
        };
        identity.url()?;
        Ok(identity)
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct Candidate {
    pub offset: u64,
    pub pdb: PdbIdentity,
}
pub fn identify(image: &Image, job: &Job) -> Result<Vec<Candidate>> {
    let mut out = Vec::new();
    for offset in image.scan(b"RSDS", job)? {
        job.check()?;
        let mut b = [0; 512];
        if image.read(offset, &mut b).is_ok()
            && let Ok(pdb) = PdbIdentity::from_rsds(&b)
            && matches!(
                pdb.name.as_str(),
                "ntkrnlmp.pdb" | "ntoskrnl.pdb" | "ntkrnlpa.pdb" | "ntkrpamp.pdb"
            )
        {
            out.push(Candidate { offset, pdb });
        }
    }
    ensure!(out.len() <= 1024, "内核 PDB 候选过多");
    Ok(out)
}

pub fn resolve(
    path: &Path,
    image: &Image,
    cache: &Path,
    network: bool,
    job: &Job,
) -> Result<Vec<Isf>> {
    let candidates = image.windows_candidates(job)?;
    ensure!(!candidates.is_empty(), "镜像未发现 Windows 内核 PDB 身份");
    let identities: HashSet<_> = candidates.iter().map(|c| c.pdb.clone()).collect();
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for source in [path.to_path_buf(), cache.join("symbols/isf/windows")] {
        if !source.exists() {
            continue;
        }
        for (label, bytes) in symbols::entries(&source, job)? {
            job.check()?;
            match Isf::parse(&bytes, label.clone()) {
                Ok(isf)
                    if isf.is_windows()
                        && (isf.data["metadata"]["zero"]["converter"].is_null()
                            || isf.data["metadata"]["zero"]["converter"] == CONVERTER_VERSION)
                        && PdbIdentity::from_isf(&isf).is_ok_and(|id| identities.contains(&id))
                        && seen.insert(isf.digest.clone()) =>
                {
                    out.push(isf)
                }
                Ok(_) => {}
                Err(e) => job.report(format!("跳过无效符号 {label}: {e:#}")),
            }
        }
    }
    if out.is_empty() {
        for identity in identities {
            match acquire(&identity, cache, network, job) {
                Ok(isf) => out.push(isf),
                Err(e) => {
                    job.check()?;
                    job.report(format!("{}: {e:#}", identity.key()));
                }
            }
        }
    }
    ensure!(
        !out.is_empty(),
        "没有准确匹配的 Windows ISF；在线模式可原生下载转换 PDB，离线模式需先准备符号"
    );
    out.sort_by(|a, b| a.label.cmp(&b.label));
    Ok(out)
}
pub fn acquire(identity: &PdbIdentity, cache: &Path, network: bool, job: &Job) -> Result<Isf> {
    job.check()?;
    identity.url()?;
    let stem = format!("{}-{}{:X}", identity.name, identity.guid, identity.age);
    let directory = cache.join("symbols/isf/windows");
    let target = directory.join(format!("{stem}.json"));
    if target.is_file()
        && let Ok(isf) = Isf::parse(&fs::read(&target)?, target.display().to_string())
        && PdbIdentity::from_isf(&isf)? == *identity
        && isf.data["metadata"]["zero"]["converter"] == CONVERTER_VERSION
    {
        return Ok(isf);
    }
    let pdb_path = cache.join("symbols/build/pdb").join(format!("{stem}.pdb"));
    let local = fs::read(&pdb_path).ok();
    let had_local = local.is_some();
    let mut bytes = if let Some(bytes) = local {
        bytes
    } else {
        ensure!(network, "离线模式缺少 PDB 缓存: {}", identity.key());
        job.report(format!("下载微软 PDB {}", identity.key()));
        symbols::fetch(&identity.url()?, job)?
    };
    job.report(format!("原生转换 PDB {}", identity.key()));
    let bytes_out = match convert(&bytes, identity, job) {
        Ok(out) => out,
        Err(e) if had_local && network => {
            job.check()?;
            job.report(format!("PDB 缓存无效，重新下载: {e:#}"));
            bytes = symbols::fetch(&identity.url()?, job)?;
            convert(&bytes, identity, job)?
        }
        Err(e) => return Err(e),
    };
    let isf = Isf::parse(&bytes_out, target.display().to_string())?;
    job.check()?;
    store::atomic_write(&pdb_path, &bytes)?;
    store::atomic_write(&target, &bytes_out)?;
    store::atomic_write(
        &target.with_extension("source.json"),
        &serde_json::to_vec_pretty(
            &json!({"url":identity.url()?,"pdb":identity,"pdb_sha256":format!("{:x}",Sha256::digest(&bytes)),"isf_sha256":isf.digest,"converter":CONVERTER_VERSION}),
        )?,
    )?;
    Ok(isf)
}

pub fn convert(bytes: &[u8], identity: &PdbIdentity, job: &Job) -> Result<Vec<u8>> {
    let mut pdb = pdb::PDB::open(std::io::Cursor::new(bytes))?;
    let info = pdb.pdb_information()?;
    let debug = pdb.debug_information()?;
    ensure!(
        debug.machine_type()? == pdb::MachineType::Amd64,
        "仅支持 x64 Windows PDB"
    );
    let image_age = debug.age().unwrap_or(info.age);
    ensure!(
        info.guid.simple().to_string().to_ascii_uppercase() == identity.guid
            && image_age == identity.age,
        "PDB GUID/Age 不匹配: {} / {} (stream age {})",
        info.guid,
        image_age,
        info.age
    );
    let types = pdb.type_information()?;
    let mut finder = types.finder();
    let mut iter = types.iter();
    let mut records = HashMap::new();
    while let Some(item) = iter.next()? {
        job.check()?;
        finder.update(&iter);
        if let Ok(data) = item.parse() {
            records.insert(item.index(), data);
        }
    }
    let mut bases = serde_json::Map::new();
    bases.insert(
        "pointer".into(),
        json!({"size":8,"kind":"int","signed":false,"endian":"little"}),
    );
    bases.insert(
        "void".into(),
        json!({"size":0,"kind":"void","signed":false,"endian":"little"}),
    );
    fn primitive(
        p: pdb::PrimitiveType,
        bases: &mut serde_json::Map<String, Value>,
    ) -> Result<(Value, u64)> {
        use pdb::PrimitiveKind::*;
        if let Some(indirection) = p.indirection {
            ensure!(
                indirection == pdb::Indirection::Near64,
                "不支持的 PDB 指针宽度"
            );
            return Ok((
                json!({"kind":"pointer","subtype":{"kind":"base","name":"void"}}),
                8,
            ));
        }
        let size = match p.kind {
            NoType | Void => 0,
            Char | UChar | RChar | I8 | U8 | Bool8 => 1,
            WChar | RChar16 | Short | UShort | I16 | U16 | Bool16 | F16 => 2,
            RChar32 | Long | ULong | I32 | U32 | Bool32 | F32 | F32PP | HRESULT => 4,
            Quad | UQuad | I64 | U64 | Bool64 | F64 | Complex32 => 8,
            Octa | UOcta | I128 | U128 | F128 | Complex64 => 16,
            F48 => 6,
            F80 => 10,
            Complex80 => 20,
            Complex128 => 32,
            _ => bail!("不支持的 PDB 基本类型 {:?}", p.kind),
        };
        let name = format!("{:?}", p.kind);
        let signed = matches!(
            p.kind,
            Char | I8 | Short | I16 | Long | I32 | Quad | I64 | Octa | I128 | HRESULT
        );
        bases.insert(
            name.clone(),
            json!({"size":size,"kind":"int","signed":signed,"endian":"little"}),
        );
        Ok((json!({"kind":"base","name":name}), size))
    }
    fn type_name(name: &str, index: TypeIndex) -> String {
        if name.is_empty() || name.starts_with('<') {
            format!("__zero_unnamed_{:x}", index.0)
        } else {
            name.into()
        }
    }
    fn ty(
        index: TypeIndex,
        records: &HashMap<TypeIndex, TypeData<'_>>,
        finder: &pdb::TypeFinder<'_>,
        bases: &mut serde_json::Map<String, Value>,
        depth: usize,
    ) -> Result<(Value, u64)> {
        ensure!(depth < 64, "PDB 类型递归过深");
        if index.0 < 0x1000
            && let TypeData::Primitive(p) = finder.find(index)?.parse()?
        {
            return primitive(p, bases);
        }
        match records.get(&index).context("PDB 类型未解析")? {
            TypeData::Class(c) => Ok((
                json!({"kind":"struct","name":type_name(&c.name.to_string(), index)}),
                c.size,
            )),
            TypeData::Union(c) => Ok((
                json!({"kind":"union","name":type_name(&c.name.to_string(), index)}),
                c.size,
            )),
            TypeData::Pointer(p) => {
                ensure!(p.attributes.size() == 8, "不支持非 x64 PDB 指针");
                Ok((
                    json!({"kind":"pointer","subtype":ty(p.underlying_type,records,finder,bases,depth+1).map(|x|x.0).unwrap_or(json!({"kind":"base","name":"void"}))}),
                    8,
                ))
            }
            TypeData::Modifier(m) => ty(m.underlying_type, records, finder, bases, depth + 1),
            TypeData::Array(a) => {
                let (mut sub, mut size) = ty(a.element_type, records, finder, bases, depth + 1)?;
                for &dim in &a.dimensions {
                    ensure!(size > 0 && u64::from(dim) % size == 0, "PDB 数组长度无效");
                    sub = json!({"kind":"array","subtype":sub,"count":u64::from(dim)/size});
                    size = u64::from(dim);
                }
                Ok((sub, size))
            }
            TypeData::Bitfield(b) => {
                let (under, size) = ty(b.underlying_type, records, finder, bases, depth + 1)?;
                Ok((
                    json!({"kind":"bitfield","type":under,"bit_position":b.position,"bit_length":b.length}),
                    size,
                ))
            }
            TypeData::Enumeration(e) => {
                let (_, size) = ty(e.underlying_type, records, finder, bases, depth + 1)?;
                Ok((json!({"kind":"enum","name":e.name.to_string()}), size))
            }
            TypeData::Procedure(_) | TypeData::MemberFunction(_) => {
                Ok((json!({"kind":"base","name":"void"}), 0))
            }
            t => bail!("不支持 PDB 数据类型 {t:?}"),
        }
    }
    fn fields<'a>(
        index: Option<TypeIndex>,
        records: &HashMap<TypeIndex, TypeData<'a>>,
    ) -> Result<Vec<TypeData<'a>>> {
        // Lifetimes are handled by the caller's record map.
        let mut out = Vec::new();
        let mut next = index;
        let mut visited = HashSet::new();
        while let Some(i) = next {
            ensure!(visited.insert(i), "PDB 字段链循环");
            match records.get(&i) {
                Some(TypeData::FieldList(f)) => {
                    out.extend(f.fields.clone());
                    next = f.continuation
                }
                _ => bail!("PDB 字段列表缺失"),
            }
        }
        Ok(out)
    }
    let mut users = BTreeMap::new();
    let mut enums = BTreeMap::new();
    // Resolve forward declarations to their complete definitions before array sizing.
    let mut complete: HashMap<String, TypeData<'_>> = HashMap::new();
    let mut ordered = records.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|(index, _)| index.0);
    for (_, r) in ordered {
        let (name, size) = match r {
            TypeData::Class(c) if !c.properties.forward_reference() => {
                (c.name.to_string().into_owned(), c.size)
            }
            TypeData::Union(c) if !c.properties.forward_reference() => {
                (c.name.to_string().into_owned(), c.size)
            }
            _ => continue,
        };
        if name.is_empty() || name.starts_with('<') {
            continue;
        }
        let previous = complete
            .get(&name)
            .map(|r| match r {
                TypeData::Class(c) => c.size,
                TypeData::Union(c) => c.size,
                _ => 0,
            })
            .unwrap_or(0);
        if !complete.contains_key(&name) || size > previous {
            complete.insert(name, r.clone());
        }
    }
    for r in records.values_mut() {
        match r {
            TypeData::Class(c) if c.properties.forward_reference() => {
                if let Some(full) = complete.get(c.name.to_string().as_ref()) {
                    *r = full.clone()
                }
            }
            TypeData::Union(c) if c.properties.forward_reference() => {
                if let Some(full) = complete.get(c.name.to_string().as_ref()) {
                    *r = full.clone()
                }
            }
            _ => {}
        }
    }
    let mut ordered = records.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|(index, _)| index.0);
    for (record_index, record) in ordered {
        job.check()?;
        let (name, size, index, kind) = match record {
            TypeData::Class(c) if !c.properties.forward_reference() => (
                type_name(&c.name.to_string(), *record_index),
                c.size,
                c.fields,
                "struct",
            ),
            TypeData::Union(c) if !c.properties.forward_reference() => (
                type_name(&c.name.to_string(), *record_index),
                c.size,
                Some(c.fields),
                "union",
            ),
            TypeData::Enumeration(e) if !e.properties.forward_reference() => {
                let (base, size) = ty(e.underlying_type, &records, &finder, &mut bases, 0)?;
                let mut constants = BTreeMap::new();
                for f in fields(Some(e.fields), &records)? {
                    if let TypeData::Enumerate(v) = f {
                        let n: Value = serde_json::from_str(&v.value.to_string())?;
                        constants.insert(v.name.to_string().into_owned(), n);
                    }
                }
                enums.insert(
                    e.name.to_string().into_owned(),
                    json!({"size":size,"base":base["name"],"constants":constants}),
                );
                continue;
            }
            _ => continue,
        };
        // Keep the complete, largest named definition for ISF output; preserve
        // each type index's own size when decoding array dimensions above.
        if users
            .get(&name)
            .and_then(|v: &Value| v["size"].as_u64())
            .is_some_and(|previous| previous >= size)
        {
            continue;
        }
        let mut members = BTreeMap::new();
        for field in fields(index, &records)? {
            if let TypeData::Member(m) = field {
                let (t, _) = ty(m.field_type, &records, &finder, &mut bases, 0)
                    .with_context(|| format!("{name}.{}", m.name))?;
                let n = m.name.to_string().into_owned();
                members.insert(
                    if n.is_empty() {
                        format!("unnamed_field_{}", members.len())
                    } else {
                        n
                    },
                    json!({"offset":m.offset,"type":t}),
                );
            }
        }
        users.insert(name, json!({"kind":kind,"size":size,"fields":members}));
    }
    let map = pdb.address_map()?;
    let table = pdb.global_symbols()?;
    let mut iter = table.iter();
    let mut symbols = BTreeMap::new();
    while let Some(s) = iter.next()? {
        job.check()?;
        let (name, offset) = match s.parse()? {
            pdb::SymbolData::Public(s) => (s.name, s.offset),
            pdb::SymbolData::Data(s) => (s.name, s.offset),
            _ => continue,
        };
        if let Some(rva) = offset.to_rva(&map) {
            symbols.insert(name.to_string().into_owned(), json!({"address":rva.0}));
        }
    }
    serde_json::to_vec(&json!({"metadata":{"format":"6.2.0","producer":{"name":"zero","version":env!("CARGO_PKG_VERSION")},"windows":{"pdb":{"database":identity.name,"GUID":identity.guid,"age":identity.age},"pe":{"machine_type":34404}},"zero":{"converter":CONVERTER_VERSION,"pdb_sha256":format!("{:x}",Sha256::digest(bytes)),"architecture":"x86_64"}},"base_types":bases,"user_types":users,"enums":enums,"symbols":symbols})).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_keys_reject_paths_and_non_ascii_without_panicking() {
        for key in [
            "../x.pdb/00112233445566778899AABBCCDDEEFF1",
            "nt.pdb/短短短短短短短短短短短短",
            "nt.pdb/00112233445566778899AABBCCDDEEFF",
            "nt.pdb/00112233445566778899AABBCCDDEEFFZ",
        ] {
            assert!(PdbIdentity::from_key(key).is_err());
        }
        let key = "ntkrnlmp.pdb/00112233445566778899AABBCCDDEEFFA";
        let identity = PdbIdentity::from_key(key).unwrap();
        assert_eq!(identity.age, 10);
        assert_eq!(identity.key(), key);
        assert!(convert(b"corrupt PDB", &identity, &Job::default()).is_err());
    }
}
