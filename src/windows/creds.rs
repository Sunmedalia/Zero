//! SAM/SECURITY hive 凭证解密：windows.hashdump / lsadump / cachedump。
//! 算法对齐 Volatility 3 的 registry/hashdump.py、lsadump.py、cachedump.py。
use super::crypto;
use super::*;

/// bootkey 片段所在的 Lsa 子键，顺序敏感。
const LSA_BOOTKEY_KEYS: [&str; 4] = ["JD", "Skew1", "GBG", "Data"];
/// vol3 Hashdump.bootkey_perm_table。
const BOOTKEY_PERM: [usize; 16] = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7];
const AQWERTY: &[u8] = b"!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0";
const ANUM: &[u8] = b"0123456789012345678901234567890123456789\0";
const NT_PASSWORD: &[u8] = b"NTPASSWORD\0";
const LM_PASSWORD: &[u8] = b"LMPASSWORD\0";
const EMPTY_LM: &str = "aad3b435b51404eeaad3b435b51404ee";
const EMPTY_NT: &str = "31d6cfe0d16ae931b73c59d7e0c089c0";
/// Vista+ 域缓存凭据（mscash2/DCC2）的默认迭代数。
const DCC2_ITERATIONS: u32 = 10240;
/// (bootkey, LSA 密钥, 是否 Vista+ 布局)：凭证插件共用的密钥组。
type CredKeys = ([u8; 16], Vec<u8>, bool);

fn bytes_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn u32le(data: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        data.get(offset..offset + 4)
            .context("SAM/LSA 数据偏移越界")?
            .try_into()?,
    ))
}
fn u16le(data: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        data.get(offset..offset + 2)
            .context("SAM/LSA 数据偏移越界")?
            .try_into()?,
    ))
}
fn utf16(bytes: &[u8]) -> Result<String> {
    ensure!(bytes.len().is_multiple_of(2), "UTF-16 长度无效");
    Ok(String::from_utf16_lossy(
        &bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect::<Vec<_>>(),
    ))
}

/// 四段 Lsa class 数据（UTF-16LE ASCII hex）→ 置换后的 16 字节 bootkey。
fn bootkey_from_classes(classes: [&[u8]; 4]) -> Result<[u8; 16]> {
    let mut text = String::new();
    for class in classes {
        ensure!(
            class.len().is_multiple_of(2) && !class.is_empty(),
            "bootkey class 长度无效"
        );
        for ch in utf16(class)?.chars() {
            ensure!(ch.is_ascii_hexdigit(), "bootkey class 非十六进制");
            text.push(ch);
        }
    }
    ensure!(text.len() == 32, "bootkey 片段长度无效");
    let mut raw = [0u8; 16];
    for (i, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        raw[i] = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
    }
    let mut out = [0u8; 16];
    for (i, &p) in BOOTKEY_PERM.iter().enumerate() {
        out[i] = raw[p];
    }
    Ok(out)
}

/// SAM `Domains\Account` 的 F 值 → hbootkey（Vista+ AES / XP RC4）。
fn hbootkey_from_f(f: &[u8], bootkey: &[u8; 16]) -> Result<Vec<u8>> {
    ensure!(f.len() >= 0xa8, "SAM F 值截断");
    match f[0] {
        3 => {
            let iv: [u8; 16] = f[0x78..0x88].try_into()?;
            let mut enc = f[0x88..0xa8].to_vec();
            crypto::aes_cbc_decrypt(bootkey, &iv, &mut enc)?;
            Ok(enc[..16].to_vec())
        }
        2 => {
            let mut material = Vec::new();
            material.extend_from_slice(&f[0x70..0x80]);
            material.extend_from_slice(AQWERTY);
            material.extend_from_slice(bootkey);
            material.extend_from_slice(ANUM);
            let key = crypto::md5(&material);
            let mut out = f[0x80..0xa0].to_vec();
            crypto::rc4(&key, &mut out)?;
            Ok(out)
        }
        revision => bail!("未知 SAM 修订版本 {revision}"),
    }
}

/// V 值中的单个哈希段（revision 1 = XP RC4+DES，2 = Vista+ salt-AES+DES）。
/// 未知修订或空密码段返回 `None`，与 vol3 输出空哈希常量的行为一致。
fn sam_hash(
    v: &[u8],
    offset: usize,
    length: usize,
    rid: u32,
    hbootkey: &[u8],
    pwd: &[u8],
    nt: bool,
) -> Result<Option<[u8; 16]>> {
    ensure!(offset + 3 < v.len(), "SAM V 值哈希段越界");
    let revision = v[offset + 2];
    let obf = match (revision, length) {
        (1, 20) => {
            let mut enc = v
                .get(offset + 4..offset + 20)
                .context("SAM V 值哈希段截断")?
                .to_vec();
            let mut material = hbootkey[..16].to_vec();
            material.extend_from_slice(&rid.to_le_bytes());
            material.extend_from_slice(pwd);
            crypto::rc4(&crypto::md5(&material), &mut enc)?;
            enc
        }
        (2, 56) => {
            let (salt, enc_at) = if nt {
                (offset + 8, offset + 24)
            } else {
                (offset + 4, offset + 20)
            };
            let iv: [u8; 16] = v
                .get(salt..salt + 16)
                .context("SAM V 值盐截断")?
                .try_into()?;
            let mut enc = v
                .get(enc_at..enc_at + 32)
                .context("SAM V 值哈希段截断")?
                .to_vec();
            crypto::aes_cbc_decrypt(&hbootkey[..16], &iv, &mut enc)?;
            enc[..16].to_vec()
        }
        _ => return Ok(None),
    };
    ensure!(obf.len() == 16, "SAM 哈希段长度无效");
    let (k1, k2) = crypto::sid_to_key(rid);
    let mut first: [u8; 8] = obf[..8].try_into()?;
    let mut second: [u8; 8] = obf[8..16].try_into()?;
    crypto::des_ecb_decrypt(&k1, &mut first)?;
    crypto::des_ecb_decrypt(&k2, &mut second)?;
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&first);
    out[8..].copy_from_slice(&second);
    Ok(Some(out))
}

struct SamUser {
    rid: u32,
    name: String,
    lm: Option<[u8; 16]>,
    nt: Option<[u8; 16]>,
}

/// SAM `Domains\Account\Users\{RID}` 的 V 值 → 用户名与 LM/NT 哈希。
fn sam_user(v: &[u8], rid: u32, hbootkey: &[u8]) -> Result<SamUser> {
    ensure!(v.len() >= 0xb0, "SAM V 值截断");
    let name_off = u32le(v, 0x0c)? as usize + 0xcc;
    let name_len = u32le(v, 0x10)? as usize;
    let lm_off = u32le(v, 0x9c)? as usize + 0xcc;
    let lm_len = u32le(v, 0xa0)? as usize;
    let nt_off = u32le(v, 0xa8)? as usize + 0xcc;
    let nt_len = u32le(v, 0xac)? as usize;
    ensure!(
        name_off + name_len <= v.len() && lm_off + lm_len <= v.len() && nt_off + nt_len <= v.len(),
        "SAM V 值字段越界"
    );
    Ok(SamUser {
        rid,
        name: utf16(&v[name_off..name_off + name_len])?,
        lm: sam_hash(v, lm_off, lm_len, rid, hbootkey, LM_PASSWORD, false)?,
        nt: sam_hash(v, nt_off, nt_len, rid, hbootkey, NT_PASSWORD, true)?,
    })
}

/// vol3 `Lsadump.decrypt_aes`：SHA256(key ‖ secret[28:60]×1000) 派生 AES-256
/// 密钥，secret[60..] 每 16 字节独立零 IV 解密（末块补零）。
fn lsa_decrypt_blocks(secret: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    ensure!(secret.len() >= 60, "LSA 数据段截断");
    let mut sha = sha2::Sha256::new();
    sha.update(key);
    for _ in 0..1000 {
        sha.update(&secret[28..60]);
    }
    let aeskey = sha.finalize();
    let mut out = Vec::with_capacity(secret.len() - 60);
    let mut block = [0u8; 16];
    for chunk in secret[60..].chunks(16) {
        block[..chunk.len()].copy_from_slice(chunk);
        crypto::aes_cbc_decrypt(&aeskey, &[0; 16], &mut block)?;
        out.extend_from_slice(&block);
    }
    Ok(out)
}

/// SECURITY `Policy\PolEKList` 值 → 32 字节 LSA 密钥（Vista+）。
fn lsa_key_vista(obf: &[u8], bootkey: &[u8; 16]) -> Result<Vec<u8>> {
    let dec = lsa_decrypt_blocks(obf, bootkey)?;
    ensure!(dec.len() >= 100, "LSA 密钥数据截断");
    Ok(dec[68..100].to_vec())
}
/// SECURITY `Policy\PolSecretEncryptionKey` 值 → 16 字节 LSA 密钥（XP）。
fn lsa_key_xp(obf: &[u8], bootkey: &[u8; 16]) -> Result<Vec<u8>> {
    ensure!(obf.len() >= 76, "LSA 密钥数据截断");
    let mut material = bootkey.to_vec();
    for _ in 0..1000 {
        material.extend_from_slice(&obf[60..76]);
    }
    let mut out = obf[12..60].to_vec();
    crypto::rc4(&crypto::md5(&material), &mut out)?;
    ensure!(out.len() >= 0x20, "LSA 密钥截断");
    Ok(out[0x10..0x20].to_vec())
}

/// XP SystemFunction005 风格 DES 链解密 LSA 机密。
fn decrypt_secret_xp(secret: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    ensure!(!secret.is_empty(), "LSA 机密数据为空");
    let mut out = Vec::with_capacity(secret.len());
    let mut j = 0usize;
    for block in secret.chunks(8) {
        let mut buf = [0u8; 8];
        buf[..block.len()].copy_from_slice(block);
        let material: [u8; 7] = key
            .get(j..j + 7)
            .context("LSA 密钥段截断")?
            .try_into()
            .context("LSA 密钥段无效")?;
        crypto::des_ecb_decrypt(&crypto::des_key_from_7(&material), &mut buf)?;
        out.extend_from_slice(&buf);
        j += 7;
        if key.len().saturating_sub(j) < 7 {
            j = key.len() - j;
        }
    }
    ensure!(out.len() >= 12, "LSA 机密数据截断");
    let length = u32le(&out, 0)? as usize;
    ensure!(8 + length <= out.len(), "LSA 机密长度越界");
    Ok(out[8..8 + length].to_vec())
}

struct CacheSlot {
    user: String,
    domain: String,
    domain_name: String,
    hash: [u8; 16],
}

/// `Cache\NNNN` 值头部 → 用户名/域长度、盐与密文位置。
fn cache_header(data: &[u8]) -> Result<(usize, usize, usize, [u8; 16], usize)> {
    ensure!(data.len() >= 96, "缓存凭据条目截断");
    Ok((
        u16le(data, 0)? as usize,
        u16le(data, 2)? as usize,
        u16le(data, 60)? as usize,
        data[64..80].try_into()?,
        96,
    ))
}
/// Vista+：AES-128-CBC(nlkm[16:32], iv=盐) 链式解密（末块补零）。
fn decrypt_cache_vista(enc: &[u8], nlkm: &[u8], salt: &[u8; 16]) -> Result<Vec<u8>> {
    let key = nlkm.get(16..32).context("NL$KM 截断")?;
    let mut data = enc.to_vec();
    data.resize(data.len().div_ceil(16) * 16, 0);
    crypto::aes_cbc_decrypt(key, salt, &mut data)?;
    Ok(data)
}
/// XP：RC4(HMAC-MD5(nlkm, 盐)) 解密。
fn decrypt_cache_xp(enc: &[u8], nlkm: &[u8], salt: &[u8; 16]) -> Result<Vec<u8>> {
    let mut data = enc.to_vec();
    crypto::rc4(&crypto::hmac_md5(nlkm, salt)?, &mut data)?;
    Ok(data)
}
/// 解密后的缓存条目 → 用户名/域/DNS 域与 16 字节 DCC 哈希。
fn cache_fields(
    dec: &[u8],
    uname_len: usize,
    domain_len: usize,
    dn_len: usize,
) -> Result<CacheSlot> {
    ensure!(dec.len() >= 0x10, "缓存凭据数据截断");
    let field = |offset: usize, length: usize| -> Result<String> {
        ensure!(offset + length <= dec.len(), "缓存凭据字段越界");
        utf16(&dec[offset..offset + length])
    };
    let uname_off = 72;
    let domain_off = uname_off + uname_len + 2 * ((uname_len / 2) % 2);
    let dn_off = domain_off + domain_len + 2 * ((domain_len / 2) % 2);
    Ok(CacheSlot {
        user: field(uname_off, uname_len)?,
        domain: field(domain_off, domain_len)?,
        domain_name: field(dn_off, dn_len)?,
        hash: dec[..16].try_into()?,
    })
}
/// hashcat 可直接使用的 DCC 行（2100 模式；XP 为 mscash-v1）。
fn dcc_line(slot: &CacheSlot, vista: bool) -> String {
    let hash = bytes_hex(&slot.hash);
    if vista {
        format!("$DCC2${}#{}#{hash}", DCC2_ITERATIONS, slot.user)
    } else {
        format!("$DCC${}#{hash}", slot.user)
    }
}

impl Windows<'_> {
    /// SYSTEM hive → 置换 bootkey（Lsa 四子键 class 数据）。
    fn bootkey(&self, hive: u64, control_set: &str, job: &Job) -> Result<[u8; 16]> {
        let hhive = self.field(hive, "_CMHIVE", "Hive")?;
        let lsa = self.registry_index(hhive, &format!("{control_set}\\Control\\Lsa"), job)?;
        let mut classes = Vec::new();
        for name in LSA_BOOTKEY_KEYS {
            let child = self.subkey_named(hhive, lsa, name, job)?;
            classes.push(self.key_class(hhive, child)?);
        }
        bootkey_from_classes([&classes[0], &classes[1], &classes[2], &classes[3]])
    }
    /// bootkey + LSA 密钥 + 是否 Vista+ 路径；任一环节失败记诊断返回 `None`。
    fn cred_keys(&self, job: &Job, r: &mut Results) -> Result<Option<CredKeys>> {
        let systems = self.hives_matching(&["system"], job, r)?;
        let securities = self.hives_matching(&["security"], job, r)?;
        if systems.is_empty() || securities.is_empty() {
            Self::issue(r, "SYSTEM/SECURITY", "未找到 SYSTEM 或 SECURITY hive");
            return Ok(None);
        }
        for (system, _) in &systems {
            // 单个 SYSTEM hive 的键遍历损坏降级为诊断，不影响其余 hive。
            let cs = match self.current_control_set(*system, job, r) {
                Ok(cs) => cs,
                Err(e) => {
                    Self::issue(r, hex(*system), e);
                    continue;
                }
            };
            let Some(cs) = cs else {
                continue;
            };
            let bootkey = match self.bootkey(*system, &cs, job) {
                Ok(bootkey) => bootkey,
                Err(e) => {
                    Self::issue(r, hex(*system), e);
                    continue;
                }
            };
            for (security, _) in &securities {
                let read = (|| -> Result<Option<CredKeys>> {
                    let hhive = self.field(*security, "_CMHIVE", "Hive")?;
                    let policy = self.registry_index(hhive, "Policy", job)?;
                    for (name, vista) in [("PolEKList", true), ("PolSecretEncryptionKey", false)] {
                        if let Ok(key) = self.subkey_named(hhive, policy, name, job) {
                            let obf = self.key_first_value(hhive, key, job)?;
                            let lsa_key = if vista {
                                lsa_key_vista(&obf, &bootkey)?
                            } else {
                                lsa_key_xp(&obf, &bootkey)?
                            };
                            return Ok(Some((bootkey, lsa_key, vista)));
                        }
                    }
                    Ok(None)
                })();
                match read {
                    Ok(Some(keys)) => return Ok(Some(keys)),
                    Ok(None) => {
                        Self::issue(r, hex(*security), "SECURITY hive 缺少 LSA 密钥值");
                    }
                    Err(e) => Self::issue(r, hex(*security), e),
                }
            }
        }
        Self::issue(r, "SYSTEM", "无法从任何 SYSTEM hive 读取 bootkey");
        Ok(None)
    }
    /// `Policy\Secrets\{name}\CurrVal` 第一个值解密；键缺失返回 `None`。
    fn lsa_secret(
        &self,
        security: u64,
        name: &str,
        lsa_key: &[u8],
        vista: bool,
        job: &Job,
    ) -> Result<Option<Vec<u8>>> {
        let hhive = self.field(security, "_CMHIVE", "Hive")?;
        let Ok(key) = self.registry_index(hhive, &format!("Policy\\Secrets\\{name}\\CurrVal"), job)
        else {
            return Ok(None);
        };
        let enc = self.key_first_value(hhive, key, job)?;
        if vista {
            Ok(Some(lsa_decrypt_blocks(&enc, lsa_key)?))
        } else {
            ensure!(enc.len() >= 0xc, "LSA 机密截断");
            Ok(Some(decrypt_secret_xp(&enc[0xc..], lsa_key)?))
        }
    }
    /// windows.hashdump：SAM hive 用户 NTLM/LM 哈希。
    pub(super) fn hashdump(&self, job: &Job) -> Result<Results> {
        let mut r = self.result(Plugin::WinHashdump);
        let systems = self.hives_matching(&["system"], job, &mut r)?;
        let sams = self.hives_matching(&["sam"], job, &mut r)?;
        if systems.is_empty() || sams.is_empty() {
            Self::issue(&mut r, "SAM/SYSTEM", "未找到 SAM 或 SYSTEM hive");
            return Ok(r);
        }
        for (system, _) in &systems {
            // 单个 SYSTEM hive 的键遍历损坏降级为诊断，不影响其余 hive。
            let cs = match self.current_control_set(*system, job, &mut r) {
                Ok(cs) => cs,
                Err(e) => {
                    Self::issue(&mut r, hex(*system), e);
                    continue;
                }
            };
            let Some(cs) = cs else {
                continue;
            };
            let bootkey = match self.bootkey(*system, &cs, job) {
                Ok(bootkey) => bootkey,
                Err(e) => {
                    Self::issue(&mut r, hex(*system), e);
                    continue;
                }
            };
            for (sam, _) in &sams {
                let read = (|| -> Result<()> {
                    let hhive = self.field(*sam, "_CMHIVE", "Hive")?;
                    let account = self.registry_index(hhive, "SAM\\Domains\\Account", job)?;
                    let f = self
                        .key_value_bytes(hhive, account, "F", job)?
                        .context("SAM Account 缺少 F 值")?;
                    let hbootkey = hbootkey_from_f(&f, &bootkey)?;
                    let users = self.registry_index(hhive, "SAM\\Domains\\Account\\Users", job)?;
                    let node = self.cell(hhive, users)?;
                    for index in self.subkeys(hhive, &node, job)? {
                        job.check()?;
                        let read = (|| -> Result<()> {
                            let n = self.cell(hhive, index)?;
                            // Users 下的非 RID 子键（如 Names 视图）是正常结构，静默跳过。
                            let Ok(rid) = u32::from_str_radix(&self.key_name(&n)?, 16) else {
                                return Ok(());
                            };
                            let v = self
                                .key_value_bytes(hhive, index, "V", job)?
                                .context("用户键缺少 V 值")?;
                            let user = sam_user(&v, rid, &hbootkey)?;
                            r.rows.push(vec![
                                user.name,
                                user.rid.to_string(),
                                user.lm
                                    .as_ref()
                                    .map(|h| bytes_hex(h))
                                    .unwrap_or_else(|| EMPTY_LM.into()),
                                user.nt
                                    .as_ref()
                                    .map(|h| bytes_hex(h))
                                    .unwrap_or_else(|| EMPTY_NT.into()),
                            ]);
                            Ok(())
                        })();
                        if let Err(e) = read {
                            Self::issue(&mut r, format!("SAM 用户 {index:#x}"), e);
                        }
                    }
                    Ok(())
                })();
                if let Err(e) = read {
                    Self::issue(&mut r, format!("SAM {:#x}", sam), e);
                }
            }
            return Ok(r);
        }
        Self::issue(&mut r, "SYSTEM", "无法从任何 SYSTEM hive 读取 bootkey");
        Ok(r)
    }
    /// windows.lsadump：SECURITY hive LSA 机密。
    pub(super) fn lsadump(&self, job: &Job) -> Result<Results> {
        let mut r = self.result(Plugin::WinLsadump);
        let Some((_bootkey, lsa_key, vista)) = self.cred_keys(job, &mut r)? else {
            return Ok(r);
        };
        let securities = self.hives_matching(&["security"], job, &mut r)?;
        for (security, _) in &securities {
            let read = (|| -> Result<()> {
                let hhive = self.field(*security, "_CMHIVE", "Hive")?;
                let secrets = self.registry_index(hhive, "Policy\\Secrets", job)?;
                let node = self.cell(hhive, secrets)?;
                for index in self.subkeys(hhive, &node, job)? {
                    job.check()?;
                    let read = (|| -> Result<()> {
                        let n = self.cell(hhive, index)?;
                        let name = self.key_name(&n)?;
                        let Some(secret) =
                            self.lsa_secret(*security, &name, &lsa_key, vista, job)?
                        else {
                            return Ok(());
                        };
                        let text = utf16(&secret).unwrap_or_default();
                        let size = secret.len().to_string();
                        let hex_data = secret.iter().map(|b| format!("{b:02x}")).collect();
                        r.rows.push(vec![name, text, hex_data, size]);
                        Ok(())
                    })();
                    if let Err(e) = read {
                        Self::issue(&mut r, format!("LSA 机密 {index:#x}"), e);
                    }
                }
                Ok(())
            })();
            if let Err(e) = read {
                Self::issue(&mut r, format!("SECURITY {:#x}", security), e);
            }
        }
        Ok(r)
    }
    /// windows.cachedump：SECURITY hive 域缓存凭据（DCC）。
    pub(super) fn cachedump(&self, job: &Job) -> Result<Results> {
        let mut r = self.result(Plugin::WinCachedump);
        let Some((_bootkey, lsa_key, vista)) = self.cred_keys(job, &mut r)? else {
            return Ok(r);
        };
        let securities = self.hives_matching(&["security"], job, &mut r)?;
        for (security, _) in &securities {
            let nlkm = match self.lsa_secret(*security, "NL$KM", &lsa_key, vista, job) {
                Ok(Some(nlkm)) => nlkm,
                Ok(None) => {
                    Self::issue(&mut r, hex(*security), "缺少 NL$KM 机密");
                    continue;
                }
                Err(e) => {
                    Self::issue(&mut r, hex(*security), e);
                    continue;
                }
            };
            let read = (|| -> Result<()> {
                let hhive = self.field(*security, "_CMHIVE", "Hive")?;
                let cache = self.registry_index(hhive, "Cache", job)?;
                for (name, data) in self.key_values(hhive, cache, job)? {
                    job.check()?;
                    if name.eq_ignore_ascii_case("NL$Control") || data.is_empty() {
                        continue;
                    }
                    let read = (|| -> Result<()> {
                        let (uname_len, domain_len, dn_len, salt, enc_at) = cache_header(&data)?;
                        // 已被清除的缓存槽位（用户名长度为 0）是正常结构，静默跳过。
                        if uname_len == 0 {
                            return Ok(());
                        }
                        let dec = if vista {
                            decrypt_cache_vista(&data[enc_at..], &nlkm, &salt)?
                        } else {
                            decrypt_cache_xp(&data[enc_at..], &nlkm, &salt)?
                        };
                        let slot = cache_fields(&dec, uname_len, domain_len, dn_len)?;
                        let dcc = dcc_line(&slot, vista);
                        r.rows.push(vec![
                            slot.user,
                            slot.domain,
                            slot.domain_name,
                            if vista {
                                DCC2_ITERATIONS.to_string()
                            } else {
                                "-".into()
                            },
                            dcc,
                        ]);
                        Ok(())
                    })();
                    if let Err(e) = read {
                        Self::issue(&mut r, format!("缓存槽位 {name}"), e);
                    }
                }
                Ok(())
            })();
            if let Err(e) = read {
                Self::issue(&mut r, format!("SECURITY {:#x}", security), e);
            }
        }
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::{BlockEncrypt, KeyInit as _, generic_array::GenericArray};

    fn aes128_cbc_encrypt(key: &[u8; 16], iv: &[u8; 16], data: &mut [u8]) {
        let cipher = aes::Aes128::new(GenericArray::from_slice(key));
        let mut prev = *iv;
        for chunk in data.chunks_exact_mut(16) {
            for (byte, mask) in chunk.iter_mut().zip(prev.iter()) {
                *byte ^= mask;
            }
            cipher.encrypt_block(GenericArray::from_mut_slice(chunk));
            prev = chunk.try_into().unwrap();
        }
    }
    fn aes256_zero_iv_block(key: &[u8; 32], block: &mut [u8; 16]) {
        let cipher = aes::Aes256::new(GenericArray::from_slice(key));
        for (byte, mask) in block.iter_mut().zip([0u8; 16]) {
            *byte ^= mask;
        }
        cipher.encrypt_block(GenericArray::from_mut_slice(block));
    }
    fn des_encrypt(key: &[u8; 8], block: &mut [u8; 8]) {
        des::Des::new(GenericArray::from_slice(key))
            .encrypt_block(GenericArray::from_mut_slice(block));
    }
    fn des_wrap(rid: u32, halves: &mut [[u8; 8]; 2]) {
        let (k1, k2) = crypto::sid_to_key(rid);
        des_encrypt(&k1, &mut halves[0]);
        des_encrypt(&k2, &mut halves[1]);
    }
    fn class(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
    }
    fn put32(v: &mut [u8], offset: usize, value: u32) {
        v[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn bootkey_scramble_permutes_fragments() {
        let classes = [
            class("01234567"),
            class("89abcdef"),
            class("01234567"),
            class("89abcdef"),
        ];
        let bootkey =
            bootkey_from_classes([&classes[0], &classes[1], &classes[2], &classes[3]]).unwrap();
        assert_eq!(bytes_hex(&bootkey), "01ab89456723ab6701cd2389cd45efef");
        assert!(
            bootkey_from_classes([&class("zz"), &classes[1], &classes[2], &classes[3]]).is_err()
        );
        assert!(
            bootkey_from_classes([&class("0123"), &classes[1], &classes[2], &classes[3]]).is_err()
        );
    }

    #[test]
    fn hbootkey_roundtrip_vista_and_xp() {
        let bootkey: [u8; 16] = core::array::from_fn(|i| i as u8);
        let mut f = vec![0u8; 0xa8];
        f[0] = 3;
        f[0x78..0x88].copy_from_slice(&[9u8; 16]);
        let mut plain = [0u8; 32];
        plain[..16].copy_from_slice(&[0x5au8; 16]);
        let iv: [u8; 16] = f[0x78..0x88].try_into().unwrap();
        aes128_cbc_encrypt(&bootkey, &iv, &mut plain);
        f[0x88..0xa8].copy_from_slice(&plain);
        assert_eq!(hbootkey_from_f(&f, &bootkey).unwrap(), vec![0x5au8; 16]);

        let mut f = vec![0u8; 0xa8];
        f[0] = 2;
        f[0x70..0x80].copy_from_slice(&[0xaau8; 16]);
        let mut material = Vec::new();
        material.extend_from_slice(&f[0x70..0x80]);
        material.extend_from_slice(AQWERTY);
        material.extend_from_slice(&bootkey);
        material.extend_from_slice(ANUM);
        let mut enc = [0x55u8; 16].to_vec();
        enc.extend_from_slice(&[7u8; 16]);
        crypto::rc4(&crypto::md5(&material), &mut enc).unwrap();
        f[0x80..0xa0].copy_from_slice(&enc);
        // vol3 keeps the full 32-byte XP hbootkey; only [:16] feeds hash decryption.
        let mut expected = vec![0x55u8; 16];
        expected.extend_from_slice(&[7u8; 16]);
        assert_eq!(hbootkey_from_f(&f, &bootkey).unwrap(), expected);
        let short = vec![0u8; 16];
        assert!(hbootkey_from_f(&short, &bootkey).is_err());
    }

    #[test]
    fn sam_user_decodes_rev1_rev2_and_empty_password() {
        let hbootkey = [3u8; 16];
        let rid = 1000;
        let known: [u8; 16] = core::array::from_fn(|i| 0x10 + i as u8);
        let mut halves = [
            known[..8].try_into().unwrap(),
            known[8..].try_into().unwrap(),
        ];
        des_wrap(rid, &mut halves);
        let des_blob: Vec<u8> = halves.concat();
        // Revision 1 (XP): RC4(MD5(hbootkey ‖ rid ‖ pwdstr)) then DES halves.
        let mut material = hbootkey.to_vec();
        material.extend_from_slice(&rid.to_le_bytes());
        material.extend_from_slice(NT_PASSWORD);
        let mut enc = des_blob.clone();
        crypto::rc4(&crypto::md5(&material), &mut enc).unwrap();
        let mut v = vec![0u8; 0x140];
        put32(&mut v, 0x0c, 0);
        put32(&mut v, 0x10, 8);
        v[0xcc..0xcc + 8].copy_from_slice(
            &"user"
                .encode_utf16()
                .flat_map(|c| c.to_le_bytes())
                .collect::<Vec<_>>(),
        );
        let nt_off = 0x100;
        put32(&mut v, 0xa8, (nt_off - 0xcc) as u32);
        put32(&mut v, 0xac, 20);
        v[nt_off + 2] = 1;
        v[nt_off + 4..nt_off + 20].copy_from_slice(&enc);
        let user = sam_user(&v, rid, &hbootkey).unwrap();
        assert_eq!(user.name, "user");
        assert_eq!(user.nt.unwrap(), known);
        assert!(user.lm.is_none());
        // Revision 2 (Vista+): AES-128-CBC(hbootkey, iv=salt) over a 32-byte
        // block whose first 16 bytes carry the DES halves.
        let salt = [6u8; 16];
        let mut enc = des_blob.clone();
        enc.extend_from_slice(&[0u8; 16]);
        aes128_cbc_encrypt(&hbootkey, &salt, &mut enc);
        let mut v = vec![0u8; 0x160];
        put32(&mut v, 0x0c, 0);
        put32(&mut v, 0x10, 8);
        v[0xcc..0xcc + 8].copy_from_slice(
            &"user"
                .encode_utf16()
                .flat_map(|c| c.to_le_bytes())
                .collect::<Vec<_>>(),
        );
        put32(&mut v, 0xa8, (nt_off - 0xcc) as u32);
        put32(&mut v, 0xac, 56);
        v[nt_off + 2] = 2;
        v[nt_off + 8..nt_off + 24].copy_from_slice(&salt);
        v[nt_off + 24..nt_off + 56].copy_from_slice(&enc);
        let user = sam_user(&v, rid, &hbootkey).unwrap();
        assert_eq!(user.nt.unwrap(), known);
        // Both lengths zero: empty password falls back to the well-known hashes.
        let v = vec![0u8; 0x140];
        let user = sam_user(&v, rid, &hbootkey).unwrap();
        assert!(user.lm.is_none() && user.nt.is_none());
    }

    #[test]
    fn lsa_key_vista_roundtrip() {
        let bootkey = [1u8; 16];
        let known: Vec<u8> = (0xb0u8..0xd0).collect();
        let mut plain = vec![0u8; 128];
        plain[68..100].copy_from_slice(&known);
        let mut obf = vec![0u8; 28];
        obf.extend_from_slice(&[0x33u8; 32]);
        let mut sha = sha2::Sha256::new();
        sha.update(bootkey);
        for _ in 0..1000 {
            sha.update(&obf[28..60]);
        }
        let aeskey: [u8; 32] = sha.finalize().into();
        for block in plain.chunks_exact_mut(16) {
            aes256_zero_iv_block(&aeskey, block.try_into().unwrap());
            let _ = block;
        }
        obf.extend_from_slice(&plain);
        assert_eq!(lsa_key_vista(&obf, &bootkey).unwrap(), known);
    }

    #[test]
    fn lsa_key_xp_and_secret_chain_roundtrip() {
        let bootkey = [2u8; 16];
        let key = [0x77u8; 16];
        let mut material = bootkey.to_vec();
        for _ in 0..1000 {
            material.extend_from_slice(&[0x44u8; 16]);
        }
        let mut out = vec![0u8; 16];
        out.extend_from_slice(&key);
        out.extend_from_slice(&[0u8; 16]);
        crypto::rc4(&crypto::md5(&material), &mut out).unwrap();
        let mut obf = vec![0u8; 12];
        obf.extend_from_slice(&key);
        obf.extend_from_slice(&out[16..]);
        obf.extend_from_slice(&[0x44u8; 16]);
        assert_eq!(lsa_key_xp(&obf, &bootkey).unwrap(), key.to_vec());
        // SystemFunction005 chain over a [len][4B][data] plaintext.
        let secret_data = b"hello-secret!";
        let mut chain: Vec<u8> = (secret_data.len() as u32).to_le_bytes().to_vec();
        chain.extend_from_slice(&[0xaa; 4]);
        chain.extend_from_slice(secret_data);
        chain.resize(chain.len().div_ceil(8) * 8, 0);
        let mut encrypted = Vec::new();
        let mut j = 0usize;
        for block in chain.chunks(8) {
            let mut buf = [0u8; 8];
            buf[..block.len()].copy_from_slice(block);
            let material: [u8; 7] = key.get(j..j + 7).unwrap().try_into().unwrap();
            des_encrypt(&crypto::des_key_from_7(&material), &mut buf);
            encrypted.extend_from_slice(&buf);
            j += 7;
            if key.len().saturating_sub(j) < 7 {
                j = key.len() - j;
            }
        }
        assert_eq!(
            decrypt_secret_xp(&encrypted, &key).unwrap(),
            secret_data.to_vec()
        );
    }

    #[test]
    fn cache_slot_roundtrip_dcc2_and_mscash1() {
        let nlkm = [0x42u8; 32];
        let ch = [7u8; 16];
        let hash = [0x99u8; 16];
        let mut plain = vec![0u8; 96];
        plain[..16].copy_from_slice(&hash);
        let user: Vec<u8> = "alice"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let domain: Vec<u8> = "CORP"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        plain[72..72 + user.len()].copy_from_slice(&user);
        let pad = 2 * ((user.len() / 2) % 2);
        let domain_off = 72 + user.len() + pad;
        plain[domain_off..domain_off + domain.len()].copy_from_slice(&domain);
        let key: [u8; 16] = nlkm[16..32].try_into().unwrap();
        let mut padded = plain.clone();
        padded.resize(96, 0);
        aes128_cbc_encrypt(&key, &ch, &mut padded);
        let mut data = vec![0u8; 96];
        data[0..2].copy_from_slice(&(user.len() as u16).to_le_bytes());
        data[2..4].copy_from_slice(&(domain.len() as u16).to_le_bytes());
        data[64..80].copy_from_slice(&ch);
        data.extend_from_slice(&padded);
        let (uname_len, domain_len, dn_len, salt, enc_at) = cache_header(&data).unwrap();
        let dec = decrypt_cache_vista(&data[enc_at..], &nlkm, &salt).unwrap();
        let slot = cache_fields(&dec, uname_len, domain_len, dn_len).unwrap();
        assert_eq!(slot.user, "alice");
        assert_eq!(slot.domain, "CORP");
        assert_eq!(slot.hash, hash);
        assert_eq!(
            dcc_line(&slot, true),
            format!("$DCC2$10240#alice#{}", bytes_hex(&hash))
        );
        // XP slot: same plaintext under RC4(HMAC-MD5(nlkm, salt)).
        let mut data = vec![0u8; 96];
        data[0..2].copy_from_slice(&(user.len() as u16).to_le_bytes());
        data[2..4].copy_from_slice(&(domain.len() as u16).to_le_bytes());
        data[64..80].copy_from_slice(&ch);
        let mut enc = plain.clone();
        crypto::rc4(&crypto::hmac_md5(&nlkm, &ch).unwrap(), &mut enc).unwrap();
        data.extend_from_slice(&enc);
        let (uname_len, domain_len, dn_len, salt, enc_at) = cache_header(&data).unwrap();
        let dec = decrypt_cache_xp(&data[enc_at..], &nlkm, &salt).unwrap();
        let slot = cache_fields(&dec, uname_len, domain_len, dn_len).unwrap();
        assert_eq!(
            dcc_line(&slot, false),
            format!("$DCC$alice#{}", bytes_hex(&hash))
        );
    }
}
