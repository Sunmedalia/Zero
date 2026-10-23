//! Token privileges, logon sessions and per-user UserAssist execution records.
use super::*;

/// LUID low parts of the well-known privileges, indexed by bit position.
const PRIVILEGES: &[(u32, &str)] = &[
    (2, "SeCreateTokenPrivilege"),
    (3, "SeAssignPrimaryTokenPrivilege"),
    (4, "SeLockMemoryPrivilege"),
    (5, "SeIncreaseQuotaPrivilege"),
    (6, "SeMachineAccountPrivilege"),
    (7, "SeTcbPrivilege"),
    (8, "SeSecurityPrivilege"),
    (9, "SeTakeOwnershipPrivilege"),
    (10, "SeLoadDriverPrivilege"),
    (11, "SeSystemProfilePrivilege"),
    (12, "SeSystemtimePrivilege"),
    (13, "SeProfileSingleProcessPrivilege"),
    (14, "SeIncreaseBasePriorityPrivilege"),
    (15, "SeCreatePagefilePrivilege"),
    (16, "SeCreatePermanentPrivilege"),
    (17, "SeBackupPrivilege"),
    (18, "SeRestorePrivilege"),
    (19, "SeShutdownPrivilege"),
    (20, "SeDebugPrivilege"),
    (21, "SeAuditPrivilege"),
    (22, "SeSystemEnvironmentPrivilege"),
    (23, "SeChangeNotifyPrivilege"),
    (24, "SeRemoteShutdownPrivilege"),
    (25, "SeUndockPrivilege"),
    (26, "SeSyncAgentPrivilege"),
    (27, "SeEnableDelegationPrivilege"),
    (28, "SeManageVolumePrivilege"),
    (29, "SeImpersonatePrivilege"),
    (30, "SeCreateGlobalPrivilege"),
    (31, "SeTrustedCredManAccessPrivilege"),
    (32, "SeRelabelPrivilege"),
    (33, "SeIncreaseWorkingSetPrivilege"),
    (34, "SeTimeZonePrivilege"),
    (35, "SeCreateSymbolicLinkPrivilege"),
    (36, "SeDelegateSessionUserImpersonatePrivilege"),
];
const USERASSIST: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist";

/// UserAssist value names are ROT13 over ASCII letters.
pub(super) fn rot13(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a') + 13) % 26 + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A') + 13) % 26 + b'A') as char,
            _ => c,
        })
        .collect()
}

/// Count, focus count, focus milliseconds and last-run FILETIME of one
/// UserAssist record: 72 bytes since Windows 7, 16 bytes before.
pub(super) fn userassist_record(bytes: &[u8]) -> Option<[String; 4]> {
    let u32_at = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
    match bytes.len() {
        72 => Some([
            u32_at(4).to_string(),
            u32_at(8).to_string(),
            u32_at(12).to_string(),
            filetime(u64::from_le_bytes(bytes[60..68].try_into().unwrap())),
        ]),
        16 => Some([
            // XP starts counting at 5.
            u32_at(4).saturating_sub(5).to_string(),
            String::new(),
            String::new(),
            filetime(u64::from_le_bytes(bytes[8..16].try_into().unwrap())),
        ]),
        _ => None,
    }
}

impl Windows<'_> {
    /// The primary token of a process, with the fast-reference bits removed.
    pub(super) fn token(&self, p: &Process) -> Result<u64> {
        let fast = self.field(p.address, "_EPROCESS", "Token")?;
        let token = if self.vm.isf.field("_EX_FAST_REF", "Object").is_ok() {
            self.number(fast, "_EX_FAST_REF", "Object")?
        } else {
            self.vm.pointer(fast)?
        } & !(self.vm.pointer_size() as u64 * 2 - 1);
        ensure!(self.vm.kernel(token), "无效进程 Token 指针");
        Ok(token)
    }
    /// windows.privileges: present privileges of each process token.
    pub(super) fn privileges(&self, p: &Process, r: &mut Results) -> Result<()> {
        let token = self.token(p)?;
        let read = |field: &str| {
            self.number(token, "_TOKEN", &format!("Privileges.{field}"))
                .with_context(|| {
                    format!("不支持: 缺少 _TOKEN.Privileges.{field}（Vista 之前的令牌布局）")
                })
        };
        let present = read("Present")?;
        let enabled = read("Enabled")?;
        let default = read("EnabledByDefault")?;
        for &(bit, name) in PRIVILEGES {
            let mask = 1u64 << bit;
            if present & mask == 0 {
                continue;
            }
            let mut attributes = vec!["Present"];
            if enabled & mask != 0 {
                attributes.push("Enabled");
            }
            if default & mask != 0 {
                attributes.push("Default");
            }
            r.rows.push(vec![
                p.pid.to_string(),
                p.name.clone(),
                bit.to_string(),
                name.into(),
                attributes.join(","),
            ]);
        }
        Ok(())
    }
    /// windows.sessions: the session each process belongs to.
    pub(super) fn session(&self, p: &Process, r: &mut Results) -> Result<()> {
        let space = self.number(p.address, "_EPROCESS", "Session")?;
        let id = if space == 0 {
            "-".to_string()
        } else {
            ensure!(self.vm.kernel(space), "无效会话空间指针");
            let id = self.number(space, "_MM_SESSION_SPACE", "SessionId")?;
            ensure!(id <= 0xffff, "会话 ID 无效");
            id.to_string()
        };
        r.rows.push(vec![
            id,
            p.pid.to_string(),
            p.name.clone(),
            filetime(p.created),
            if space == 0 {
                String::new()
            } else {
                hex(space)
            },
        ]);
        Ok(())
    }
    /// windows.registry.userassist: decoded Count values of every NTUSER hive.
    pub(super) fn userassist(&self, options: &Options, job: &Job) -> Result<Results> {
        let mut r = self.result(Plugin::WinUserassist);
        let hives = self.registry(Plugin::WinHivelist, &Options::default(), job)?;
        r.complete = hives.complete;
        r.diagnostics = hives.diagnostics;
        for hive in hives.rows {
            job.check()?;
            if !hive[1].to_ascii_lowercase().ends_with("ntuser.dat") {
                continue;
            }
            let address = u64::from_str_radix(hive[0].trim_start_matches("0x"), 16)?;
            if options.hive.is_some_and(|selected| selected != address) {
                continue;
            }
            let Some(root) = self.optional_registry(address, USERASSIST, job, &mut r)? else {
                continue;
            };
            for guid in root.rows.iter().filter(|row| row[2] == "SubKey") {
                let key = format!("{USERASSIST}\\{}\\Count", guid[3]);
                let Some(values) = self.optional_registry(address, &key, job, &mut r)? else {
                    continue;
                };
                for value in values.rows.iter().filter(|row| row[2] == "Value") {
                    job.check()?;
                    let bytes: Option<Vec<u8>> = (0..value[5].len())
                        .step_by(2)
                        .map(|i| u8::from_str_radix(value[5].get(i..i + 2)?, 16).ok())
                        .collect();
                    let Some([count, focus, focus_time, last]) =
                        bytes.as_deref().and_then(userassist_record)
                    else {
                        continue;
                    };
                    r.rows.push(vec![
                        hive[1].clone(),
                        guid[3].clone(),
                        rot13(&value[3]),
                        count,
                        focus,
                        focus_time,
                        last,
                    ]);
                }
            }
        }
        r.kernel_identity["coverage"] = serde_json::json!(
            "NTUSER.DAT hives loaded in memory; paged-out cells are reported as partial"
        );
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rot13_round_trips_and_keeps_non_letters() {
        assert_eq!(
            rot13("{1NP14R77-02R7-4R5Q-O744-2RO1NR5198O7}\\pzq.rkr"),
            "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\cmd.exe"
        );
        assert_eq!(rot13(&rot13("UEME_CTLSESSION")), "UEME_CTLSESSION");
    }

    #[test]
    fn userassist_records_decode_both_layouts_and_reject_others() {
        let mut modern = vec![0u8; 72];
        modern[4..8].copy_from_slice(&7u32.to_le_bytes());
        modern[8..12].copy_from_slice(&3u32.to_le_bytes());
        modern[12..16].copy_from_slice(&1500u32.to_le_bytes());
        modern[60..68].copy_from_slice(&132_000_000_000_000_000u64.to_le_bytes());
        assert_eq!(
            userassist_record(&modern).unwrap(),
            ["7", "3", "1500", "132000000000000000"].map(String::from)
        );
        let mut xp = vec![0u8; 16];
        xp[4..8].copy_from_slice(&6u32.to_le_bytes());
        assert_eq!(userassist_record(&xp).unwrap()[0], "1");
        assert!(userassist_record(&[0; 20]).is_none());
    }
}

#[cfg(test)]
mod process_tests {
    use super::super::tests::{K, fixture, image, put};
    use super::*;
    use serde_json::json;
    fn field(offset: u64, ty: &str) -> serde_json::Value {
        json!({"offset":offset,"type":{"kind":"base","name":ty}})
    }
    fn prepare() -> (Vec<u8>, Isf) {
        let (mut b, mut isf) = fixture();
        isf.data["base_types"]["u32"] = json!({"size":4});
        let eprocess = &mut isf.data["user_types"]["_EPROCESS"]["fields"];
        eprocess["Token"] = field(128, "pointer");
        eprocess["Session"] = field(136, "pointer");
        isf.data["user_types"]["_TOKEN"] = json!({"size":96,"fields":{
            "Privileges":{"offset":64,"type":{"kind":"struct","name":"_SEP_TOKEN_PRIVILEGES"}},
        }});
        isf.data["user_types"]["_SEP_TOKEN_PRIVILEGES"] = json!({"size":24,"fields":{
            "Present":field(0,"u64"),"Enabled":field(8,"u64"),"EnabledByDefault":field(16,"u64"),
        }});
        isf.data["user_types"]["_MM_SESSION_SPACE"] =
            json!({"size":16,"fields":{"SessionId":field(8,"u32")}});
        // System and child share one token; only child has a session.
        for eprocess in [0x9000, 0xa000] {
            put(&mut b, eprocess + 128, K + 0x4000 + 7);
        }
        put(&mut b, 0xc040, 1 << 20 | 1 << 23);
        put(&mut b, 0xc048, 1 << 23);
        put(&mut b, 0xc050, 1 << 23);
        put(&mut b, 0xa000 + 136, K + 0x5000);
        b[0xd008..0xd00c].copy_from_slice(&1u32.to_le_bytes());
        (b, isf)
    }
    fn engine<'a>(img: &'a Image, isf: &'a Isf) -> Windows<'a> {
        Windows {
            vm: Memory::new(img, 0x1000, isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(isf).unwrap(),
        }
    }
    #[test]
    fn privileges_report_present_bits_with_enabled_and_default_attributes() {
        let (b, isf) = prepare();
        let img = image(&b);
        let r = engine(&img, &isf)
            .run(
                Plugin::WinPrivileges,
                &Options {
                    pid: Some(4),
                    ..Default::default()
                },
                &Job::default(),
            )
            .unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(
            r.rows,
            [
                ["4", "System", "20", "SeDebugPrivilege", "Present"],
                [
                    "4",
                    "System",
                    "23",
                    "SeChangeNotifyPrivilege",
                    "Present,Enabled,Default"
                ]
            ]
            .map(|row| row.map(String::from).to_vec())
        );
        // Pre-Vista token layouts are refused per process, not guessed.
        let mut data = isf.data.clone();
        data["user_types"]["_TOKEN"]["fields"]
            .as_object_mut()
            .unwrap()
            .remove("Privileges");
        let isf = Isf::parse(&serde_json::to_vec(&data).unwrap(), "pre-vista.json".into()).unwrap();
        let r = engine(&img, &isf)
            .run(Plugin::WinPrivileges, &Options::default(), &Job::default())
            .unwrap();
        assert!(!r.complete && r.rows.is_empty());
        assert!(r.diagnostics.iter().all(|d| d.contains("不支持")));
    }
    #[test]
    fn sessions_mark_sessionless_processes_and_read_session_ids() {
        let (mut b, isf) = prepare();
        let img = image(&b);
        let r = engine(&img, &isf)
            .run(Plugin::WinSessions, &Options::default(), &Job::default())
            .unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(&r.rows[0][..3], ["-", "4", "System"]);
        assert_eq!(r.rows[0][4], "");
        assert_eq!(&r.rows[1][..3], ["1", "8", "child"]);
        assert_eq!(r.rows[1][4], hex(K + 0x5000));
        // An implausible session ID keeps the other process.
        b[0xd008..0xd00c].copy_from_slice(&0x10000u32.to_le_bytes());
        let img = image(&b);
        let r = engine(&img, &isf)
            .run(Plugin::WinSessions, &Options::default(), &Job::default())
            .unwrap();
        assert!(!r.complete);
        assert_eq!(r.rows.len(), 1);
    }
}
