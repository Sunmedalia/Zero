use super::*;
use crate::{image::Image, symbols::Isf};
use serde_json::{Value, json};
use std::io::Write;
fn put(b: &mut [u8], at: usize, n: u64) {
    b[at..at + 8].copy_from_slice(&n.to_le_bytes());
}
pub(crate) fn fixture() -> (Vec<u8>, Isf) {
    let mut b = vec![0; 0x40000];
    // Identity kernel mapping, independent user page table with two noncontiguous pages.
    put(&mut b, 0x1000, 0x2003);
    put(&mut b, 0x2000, 0x3003);
    put(&mut b, 0x3000, 0x83);
    put(&mut b, 0x4000, 0x5003);
    put(&mut b, 0x5000, 0x6003);
    put(&mut b, 0x6008, 0x7003);
    put(&mut b, 0x7000, 0x20003);
    put(&mut b, 0x7008, 0x25003);
    let mut types = serde_json::Map::new();
    for (name, fields) in [
        ("list_head", vec!["next", "prev"]),
        (
            "task_struct",
            vec![
                "tasks",
                "pid",
                "tgid",
                "real_parent",
                "comm",
                "mm",
                "files",
                "fs",
            ],
        ),
        (
            "mm_struct",
            vec![
                "pgd",
                "arg_start",
                "arg_end",
                "env_start",
                "env_end",
                "mmap",
            ],
        ),
        (
            "vm_area_struct",
            vec![
                "vm_next", "vm_start", "vm_end", "vm_flags", "vm_pgoff", "vm_file",
            ],
        ),
        ("files_struct", vec!["fdt"]),
        ("fdtable", vec!["max_fds", "fd"]),
        ("file", vec!["f_path", "unused"]),
        ("path", vec!["mnt", "dentry"]),
        ("fs_struct", vec!["root", "unused"]),
        ("vfsmount", vec!["mnt_root", "mnt_parent", "mnt_mountpoint"]),
        ("dentry", vec!["d_parent", "d_name", "unused", "d_inode"]),
        ("qstr", vec!["len", "name"]),
        ("inode", vec!["i_mode", "i_ino"]),
        (
            "socket_alloc",
            vec!["socket", "unused", "vfs_inode", "unused2"],
        ),
        ("socket", vec!["sk", "state"]),
        ("sock", vec!["__sk_common", "sk_type", "sk_protocol"]),
        (
            "sock_common",
            vec!["skc_family", "skc_state", "skc_rcv_saddr", "skc_daddr"],
        ),
        (
            "inet_sock",
            vec![
                "unused",
                "unused2",
                "unused3",
                "unused4",
                "inet_sport",
                "inet_dport",
                "pinet6",
            ],
        ),
        (
            "ipv6_pinfo",
            vec!["rcv_saddr", "unused", "daddr", "unused2"],
        ),
        (
            "unix_sock",
            vec!["unused", "unused2", "unused3", "unused4", "addr", "peer"],
        ),
        ("unix_address", vec!["len", "name"]),
        ("sockaddr_un", vec!["sun_family", "sun_path"]),
    ] {
        let fields: serde_json::Map<String, Value> = fields
            .iter()
            .enumerate()
            .map(|(i, f)| {
                (
                    f.to_string(),
                    json!({"offset": i*8,"type":{"kind":"base","name":"u64"}}),
                )
            })
            .collect();
        types.insert(name.into(), json!({"size":128,"fields":fields}));
    }
    let mut data = json!({"user_types":types,"base_types":{"pointer":{"size":8},"u64":{"size":8},"u32":{"size":4},"char":{"size":1}},"symbols":{"init_task":{"address":0x9000}},"enums":{"state":{"size":4}}});
    for (s, f, ty) in [
        (
            "task_struct",
            "tasks",
            json!({"kind":"struct","name":"list_head"}),
        ),
        (
            "task_struct",
            "comm",
            json!({"kind":"array","count":8,"subtype":{"kind":"base","name":"char"}}),
        ),
        ("file", "f_path", json!({"kind":"struct","name":"path"})),
        ("fs_struct", "root", json!({"kind":"struct","name":"path"})),
        ("dentry", "d_name", json!({"kind":"struct","name":"qstr"})),
        (
            "sock",
            "__sk_common",
            json!({"kind":"struct","name":"sock_common"}),
        ),
        (
            "sock",
            "sk_type",
            json!({"kind":"bitfield","bit_position":3,"bit_length":16,"type":{"kind":"base","name":"u32"}}),
        ),
        (
            "sock",
            "sk_protocol",
            json!({"kind":"bitfield","bit_position":0,"bit_length":8,"type":{"kind":"base","name":"u32"}}),
        ),
        ("socket", "state", json!({"kind":"enum","name":"state"})),
        (
            "unix_address",
            "name",
            json!({"kind":"array","count":0,"subtype":{"kind":"struct","name":"sockaddr_un"}}),
        ),
    ] {
        data["user_types"][s]["fields"][f]["type"] = ty;
    }
    data["user_types"]["sock"]["fields"]["sk_type"]["offset"] = json!(32);
    data["user_types"]["sock"]["fields"]["sk_protocol"]["offset"] = json!(40);
    data["user_types"]["unix_sock"]["fields"]["addr"]["offset"] = json!(48);
    data["user_types"]["unix_sock"]["fields"]["peer"]["offset"] = json!(56);
    data["user_types"]["inet_sock"]["fields"]["inet_sport"]["offset"] = json!(48);
    data["user_types"]["inet_sock"]["fields"]["inet_dport"]["offset"] = json!(56);
    data["user_types"]["inet_sock"]["fields"]["pinet6"]["offset"] = json!(64);
    for name in ["list_head", "path", "qstr"] {
        data["user_types"][name]["size"] = json!(16);
    }
    data["user_types"]["sock"]["fields"]["sk_socket"] =
        json!({"offset":72,"type":{"kind":"pointer"}});
    // Closed task list: PID 1 followed by a kernel thread.
    put(&mut b, 0x9000, 0xa000);
    put(&mut b, 0x9008, 0xa100);
    put(&mut b, 0xa000, 0xa100);
    put(&mut b, 0xa008, 0x9000);
    put(&mut b, 0xa100, 0x9000);
    put(&mut b, 0xa108, 0xa000);
    for (at, pid) in [(0xa000, 1), (0xa100, 2)] {
        put(&mut b, at + 8 * 2, pid);
        put(&mut b, at + 8 * 3, pid);
        put(&mut b, at + 8 * 4, 0x9000);
    }
    // tasks takes 16 bytes; shift the remaining members beyond it.
    for f in ["pid", "tgid", "real_parent", "comm", "mm", "files", "fs"] {
        let offset = data["user_types"]["task_struct"]["fields"][f]["offset"]
            .as_u64()
            .unwrap();
        data["user_types"]["task_struct"]["fields"][f]["offset"] = json!(offset + 8);
    }
    b[0xa028..0xa02c].copy_from_slice(b"init");
    b[0xa128..0xa12b].copy_from_slice(b"kth");
    put(&mut b, 0xa030, 0xb000);
    put(&mut b, 0xa040, 0xc000);
    put(&mut b, 0xb000, 0x4000);
    put(&mut b, 0xb008, 0x200ffe);
    put(&mut b, 0xb010, 0x201008);
    b[0x20ffe..0x21000].copy_from_slice(b"a\0");
    b[0x25000..0x25008].copy_from_slice(b"b=c\0d\0\0\0");
    let isf = Isf {
        slide: std::sync::atomic::AtomicU64::new(0),
        data,
        label: "fixture".into(),
        digest: "fixture".into(),
        banner: b"Linux version fixture\0".to_vec(),
        locations: vec![],
        layouts: Default::default(),
    };
    (b, isf)
}
pub(crate) fn image(b: &[u8]) -> Image {
    let mut f = tempfile::tempfile().unwrap();
    f.write_all(b).unwrap();
    Image::from_file(f, "test".into()).unwrap()
}
pub(crate) fn engine<'a>(image: &'a Image, isf: &'a Isf) -> Linux<'a> {
    Linux {
        vm: VirtualMemory::new(image, 0x1000),
        isf,
    }
}
#[test]
fn process_regions_and_failures() {
    let (mut b, mut isf) = fixture();
    let job = Job::default();
    let i = image(&b);
    let linux = engine(&i, &isf);
    assert_eq!(
        linux.user_region(0xb000, "arg", &job).unwrap(),
        b"a\0b=c\0d\0\0\0"
    );
    let r = linux.run(Plugin::Psaux, &job).unwrap();
    assert!(r.complete, "{:?}", r.diagnostics);
    assert_eq!(r.rows[0][2], "a b=c d  ");
    assert_eq!(r.rows[1][3], "KernelThread");
    put(&mut b, 0xb018, 0x200ffe);
    put(&mut b, 0xb020, 0x201008);
    let i = image(&b);
    let r = engine(&i, &isf).run(Plugin::Envars, &job).unwrap();
    assert_eq!(r.rows[1], vec!["1", "init", "b", "c"]);
    put(&mut b, 0xb018, 0x201000);
    put(&mut b, 0xb020, 0x201008);
    b[0x25000..0x25008].copy_from_slice(b"K=a=b\0\0\0");
    let i = image(&b);
    let r = engine(&i, &isf).run(Plugin::Envars, &job).unwrap();
    assert_eq!(r.rows[0][3], "a=b");
    put(&mut b, 0xb018, 0);
    put(&mut b, 0xb020, 0);
    let i = image(&b);
    assert!(
        engine(&i, &isf)
            .run(Plugin::Envars, &job)
            .unwrap()
            .rows
            .is_empty()
    );
    put(&mut b, 0xb010, 0x400000);
    let i = image(&b);
    let r = engine(&i, &isf).run(Plugin::Psaux, &job).unwrap();
    assert!(!r.complete);
    assert_eq!(r.rows.len(), 1);
    assert!(r.diagnostics[0].contains("1 MiB"));
    put(&mut b, 0xb010, 0x201008);
    put(&mut b, 0x7008, 0);
    let i = image(&b);
    let r = engine(&i, &isf).run(Plugin::Psaux, &job).unwrap();
    assert!(!r.complete);
    assert!(r.diagnostics[0].contains("缺页"));
    isf.data["user_types"]["mm_struct"]["fields"]
        .as_object_mut()
        .unwrap()
        .remove("pgd");
    isf.invalidate_layouts();
    assert!(
        engine(&i, &isf)
            .run(Plugin::Psaux, &job)
            .unwrap_err()
            .to_string()
            .contains("不支持")
    );
}
#[test]
fn nested_enum_bitfield_flexible_array() {
    let (mut b, mut isf) = fixture();
    put(&mut b, 0xd008, 10);
    put(&mut b, 0xd120, 5 << 3);
    let i = image(&b);
    let linux = engine(&i, &isf);
    assert_eq!(linux.number(0xd000, "socket", "state").unwrap(), 10);
    assert_eq!(linux.number(0xd100, "sock", "sk_type").unwrap(), 5);
    assert_eq!(isf.offset("file", "f_path.dentry").unwrap(), 8);
    assert_eq!(isf.size("unix_address", "name").unwrap(), 0);
    isf.data["user_types"]["unix_address"]["fields"]["name"]["offset"] = json!(128);
    isf.invalidate_layouts();
    assert_eq!(isf.offset("unix_address", "name").unwrap(), 128);
    isf.data["user_types"]["unix_address"]["fields"]["name"]["type"]["count"] = json!(1);
    isf.invalidate_layouts();
    assert!(isf.offset("unix_address", "name").is_err());
}
#[test]
fn vma_permissions_cycle_and_limits() {
    let (mut b, isf) = fixture();
    let job = Job::default();
    put(&mut b, 0xb028, 0xd000);
    put(&mut b, 0xd000, 0xd000);
    put(&mut b, 0xd008, 0x200000);
    put(&mut b, 0xd010, 0x201000);
    put(&mut b, 0xd018, 15);
    put(&mut b, 0xd020, 3);
    let i = image(&b);
    let r = engine(&i, &isf).run(Plugin::Maps, &job).unwrap();
    assert!(!r.complete);
    assert!(r.diagnostics[0].contains("循环"));
    assert_eq!(&r.rows[0][4..], &["rwxs", "12288", "[anonymous]"]);
    put(&mut b, 0xd000, 0);
    let i = image(&b);
    assert!(engine(&i, &isf).run(Plugin::Maps, &job).unwrap().complete);
    assert_eq!(permissions(0), "---p");
}
pub(crate) fn path_fixture(b: &mut [u8]) {
    // Process root /root. File resides inside a child mount at /root/mnt/file.
    put(b, 0xc000, 0xc100);
    put(b, 0xc008, 0xc200);
    put(b, 0xc100, 0xc200);
    put(b, 0xc108, 0xc100);
    put(b, 0xc300, 0xc400);
    put(b, 0xc308, 0xc100);
    put(b, 0xc310, 0xc500);
    put(b, 0xc600, 0xc300);
    put(b, 0xc608, 0xc700);
    put(b, 0xc700, 0xc400);
    put(b, 0xc708, 4);
    put(b, 0xc710, 0xc800);
    b[0xc800..0xc805].copy_from_slice(b"file\0");
    put(b, 0xc500, 0xc200);
    put(b, 0xc508, 3);
    put(b, 0xc510, 0xc900);
    b[0xc900..0xc904].copy_from_slice(b"mnt\0");
    put(b, 0xc718, 0xca00);
    put(b, 0xca00, 0x8000);
    put(b, 0xca08, 42);
}
#[test]
fn mount_root_fd_holes_and_duplicate_references() {
    let (mut b, isf) = fixture();
    path_fixture(&mut b);
    let job = Job::default();
    put(&mut b, 0xa038, 0xcb00);
    put(&mut b, 0xcb00, 0xcc00);
    put(&mut b, 0xcc00, 3);
    put(&mut b, 0xcc08, 0xcd00);
    put(&mut b, 0xcd00, 0xc600);
    put(&mut b, 0xcd10, 0xc600);
    let i = image(&b);
    let linux = engine(&i, &isf);
    assert_eq!(linux.file_path(0xa000, 0xc600, &job).unwrap(), "/mnt/file");
    let r = linux.run(Plugin::Lsof, &job).unwrap();
    assert!(r.complete, "{:?}", r.diagnostics);
    assert_eq!(r.rows.len(), 2);
    assert_eq!(r.rows[1][2], "2");
    assert_eq!(r.rows[0][5], "/mnt/file");
    put(&mut b, 0xc500, 0xc500);
    let i = image(&b);
    let r = engine(&i, &isf).run(Plugin::Lsof, &job).unwrap();
    assert!(!r.complete);
    assert_eq!(r.diagnostics.len(), 2);
    assert_eq!(r.rows.len(), 2);
}
fn netscan_fixture() -> (Vec<u8>, Isf) {
    let (mut b, mut isf) = fixture();
    path_fixture(&mut b);
    put(&mut b, 0xa038, 0xcb00);
    put(&mut b, 0xa138, 0xcb00); // Shared socket ownership must survive deduplication.
    put(&mut b, 0xcb00, 0xcc00);
    put(&mut b, 0xcc00, 3);
    put(&mut b, 0xcc08, 0xcd00);
    put(&mut b, 0xcd00, 0xc600);
    put(&mut b, 0xcd10, 0xc600); // Hole at FD 1, repeated socket at FD 2.
    put(&mut b, 0xc718, 0xd010);
    put(&mut b, 0xd010, 0xc000);
    put(&mut b, 0xd000, 0xd100);
    put(&mut b, 0xd100, 2);
    put(&mut b, 0xd108, 1);
    put(&mut b, 0xd120, 1 << 3);
    put(&mut b, 0xd128, 6);
    b[0xd110..0xd114].copy_from_slice(&[127, 0, 0, 1]);
    b[0xd118..0xd11c].copy_from_slice(&[192, 0, 2, 1]);
    b[0xd130..0xd132].copy_from_slice(&8080u16.to_be_bytes());
    b[0xd138..0xd13a].copy_from_slice(&443u16.to_be_bytes());
    // netscan must not depend on Unix socket or inode-number symbol coverage.
    for ty in ["unix_sock", "unix_address", "sockaddr_un"] {
        isf.data["user_types"].as_object_mut().unwrap().remove(ty);
    }
    isf.data["user_types"]["inode"]["fields"]
        .as_object_mut()
        .unwrap()
        .remove("i_ino");
    isf.data["user_types"]["sock"]["fields"]
        .as_object_mut()
        .unwrap()
        .remove("sk_socket");
    (b, isf)
}
#[test]
fn netscan_deduplicates_per_owner_filters_non_internet_and_preserves_partial_results() {
    let (mut b, isf) = netscan_fixture();
    let job = Job::default();
    let i = image(&b);
    let r = engine(&i, &isf).run(Plugin::Netscan, &job).unwrap();
    assert!(r.complete, "{:?}", r.diagnostics);
    assert_eq!(r.rows.len(), 2);
    assert_ne!(r.rows[0][0], r.rows[1][0]);
    assert_eq!(
        &r.rows[0][2..],
        &[
            "TCPv4",
            "127.0.0.1:8080",
            "192.0.2.1:443",
            "ESTABLISHED",
            "0x000000000000d000"
        ]
    );
    assert_eq!(r.columns, Plugin::Netscan.descriptor().columns);
    for (protocol, state, expected_protocol, expected_state) in
        [(17, 7, "UDPv4", "UDP"), (6, 10, "TCPv4", "LISTEN")]
    {
        put(&mut b, 0xd128, protocol);
        put(&mut b, 0xd108, state);
        let i = image(&b);
        let r = engine(&i, &isf).run(Plugin::Netscan, &job).unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(r.rows.len(), 2);
        assert_eq!(r.rows[0][2], expected_protocol);
        assert_eq!(r.rows[0][5], expected_state);
    }
    put(&mut b, 0xd108, 1);
    // Distinct sockets with identical endpoints remain distinct.
    b.copy_within(0xd000..0xd200, 0xe000);
    put(&mut b, 0xe000, 0xe100);
    put(&mut b, 0xc620, 0xc300);
    put(&mut b, 0xc628, 0xc740);
    put(&mut b, 0xc758, 0xe010);
    put(&mut b, 0xcd08, 0xc620);
    let i = image(&b);
    let r = engine(&i, &isf).run(Plugin::Netscan, &job).unwrap();
    assert!(r.complete, "{:?}", r.diagnostics);
    assert_eq!(r.rows.len(), 4);
    for (family, protocol) in [(1, 0), (16, 0), (2, 1)] {
        put(&mut b, 0xe100, family);
        put(&mut b, 0xe128, protocol);
        // Invalid Unix data must never be decoded by netscan.
        put(&mut b, 0xe130, 0x300000);
        let i = image(&b);
        let r = engine(&i, &isf).run(Plugin::Netscan, &job).unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(r.rows.len(), 2);
    }
    put(&mut b, 0xcd08, 0x300000); // Missing file page is a partial result.
    let i = image(&b);
    let r = engine(&i, &isf).run(Plugin::Netscan, &job).unwrap();
    assert!(!r.complete);
    assert_eq!(r.rows.len(), 2);
    assert_eq!(r.diagnostics.len(), 2);
    assert!(r.diagnostics.iter().all(|d| d.contains("FD 1")));
}
#[test]
fn netscan_ipv6_udp_and_modern_endpoint_layouts() {
    for modern in [false, true] {
        for (protocol, expected) in [(6, "TCPv6"), (17, "UDPv6")] {
            let (mut b, mut isf) = netscan_fixture();
            put(&mut b, 0xd100, 10);
            put(&mut b, 0xd128, protocol);
            if modern {
                let fields = isf.data["user_types"]["sock_common"]["fields"]
                    .as_object_mut()
                    .unwrap();
                fields.insert("skc_v6_rcv_saddr".into(), json!({"offset": 80, "type": {"kind": "array", "count": 16, "subtype": {"kind": "base", "name": "char"}}}));
                fields.insert("skc_v6_daddr".into(), json!({"offset": 96, "type": {"kind": "array", "count": 16, "subtype": {"kind": "base", "name": "char"}}}));
                fields.insert(
                    "skc_dport".into(),
                    json!({"offset": 56, "type": {"kind": "base", "name": "u64"}}),
                );
                isf.data["user_types"]["inet_sock"]["fields"]
                    .as_object_mut()
                    .unwrap()
                    .remove("inet_dport");
                b[0xd150..0xd160].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
                b[0xd160..0xd170].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
            } else {
                put(&mut b, 0xd140, 0xe000);
                b[0xe000..0xe010].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
                b[0xe010..0xe020].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
            }
            let i = image(&b);
            let r = engine(&i, &isf)
                .run(Plugin::Netscan, &Job::default())
                .unwrap();
            assert!(r.complete, "{:?}", r.diagnostics);
            assert_eq!(r.rows.len(), 2);
            assert_eq!(&r.rows[0][2..5], &[expected, "[::1]:8080", "[::1]:443"]);
            assert_eq!(
                r.rows[0][5],
                if protocol == 6 { "ESTABLISHED" } else { "UDP" }
            );
        }
    }
}
#[test]
fn ipv4_ipv6_tcp_udp_unix_and_unsupported() {
    let (mut b, isf) = fixture();
    let sk = 0xd100;
    put(&mut b, 0xd000, sk); // socket begins 16 bytes before inode
    put(&mut b, 0xd100, 2);
    put(&mut b, 0xd108, 10);
    b[0xd110..0xd114].copy_from_slice(&[127, 0, 0, 1]);
    b[0xd118..0xd11c].copy_from_slice(&[192, 0, 2, 1]);
    put(&mut b, 0xd120, 1 << 3);
    put(&mut b, 0xd128, 6);
    b[0xd130..0xd132].copy_from_slice(&8080u16.to_be_bytes());
    b[0xd138..0xd13a].copy_from_slice(&443u16.to_be_bytes());
    let i = image(&b);
    let row = engine(&i, &isf).socket(0xd010).unwrap();
    assert_eq!(
        &row[..6],
        &[
            "IPv4",
            "STREAM",
            "TCP",
            "127.0.0.1:8080",
            "192.0.2.1:443",
            "LISTEN"
        ]
    );
    put(&mut b, 0xd128, 17);
    let i = image(&b);
    assert_eq!(engine(&i, &isf).socket(0xd010).unwrap()[5], "UDP");
    put(&mut b, 0xd100, 10);
    put(&mut b, 0xd140, 0xe000);
    b[0xe000..0xe010].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
    b[0xe010..0xe020].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
    let i = image(&b);
    let row = engine(&i, &isf).socket(0xd010).unwrap();
    assert_eq!(row[3], "[::1]:8080");
    assert_eq!(row[4], "[::1]:443");
    put(&mut b, 0xd100, 1);
    put(&mut b, 0xd130, 0xe100);
    put(&mut b, 0xe100, 12); // sun_path offset 8, len 12
    b[0xe110..0xe114].copy_from_slice(b"abc\0");
    let i = image(&b);
    assert_eq!(engine(&i, &isf).socket(0xd010).unwrap()[3], "abc");
    b[0xe110..0xe114].copy_from_slice(b"\0ab\0");
    let i = image(&b);
    assert_eq!(engine(&i, &isf).socket(0xd010).unwrap()[3], "@ab\0");
    put(&mut b, 0xd138, 0xe200);
    put(&mut b, 0xe248, 0xe300);
    let i = image(&b);
    assert_eq!(
        engine(&i, &isf).socket(0xd010).unwrap()[4],
        "0x000000000000e300"
    );
    put(&mut b, 0xd130, 0);
    let i = image(&b);
    assert_eq!(engine(&i, &isf).socket(0xd010).unwrap()[3], "[unnamed]");
    put(&mut b, 0xd100, 16);
    let i = image(&b);
    assert_eq!(
        engine(&i, &isf).socket(0xd010).unwrap()[5],
        "UnsupportedFamily"
    );
}
#[test]
fn traversal_limits_cancel_and_identity_failure() {
    let (mut b, isf) = fixture();
    let job = Job::default();
    put(&mut b, 0xa038, 0xcb00);
    put(&mut b, 0xcb00, 0xcc00);
    put(&mut b, 0xcc00, 4);
    put(&mut b, 0xcc08, 0xcd00);
    put(&mut b, 0xb028, 0xd000);
    for node in [0xd000, 0xd100, 0xd200, 0xd300] {
        put(&mut b, node, node as u64 + 0x100);
        put(&mut b, node + 8, 0x200000);
        put(&mut b, node + 16, 0x201000);
    }
    let i = image(&b);
    let linux = engine(&i, &isf);
    let mut result = linux.run(Plugin::Pslist, &job).unwrap();
    result.rows.clear();
    let prefix = vec!["1".into(), "init".into()];
    assert!(
        linux
            .files_bounded(0xa000, prefix.clone(), Plugin::Lsof, &mut result, &job, 3)
            .unwrap_err()
            .to_string()
            .contains("上限")
    );
    assert!(
        linux
            .maps_bounded(0xa000, prefix, &mut result, &job, 3)
            .unwrap_err()
            .to_string()
            .contains("上限")
    );
    assert_eq!(result.rows.len(), 3);
    job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(linux.run(Plugin::Psaux, &job).is_err());
    put(&mut b, 0xa010, u64::MAX);
    let i = image(&b);
    let r = engine(&i, &isf)
        .run(Plugin::Psaux, &Job::default())
        .unwrap();
    assert!(!r.complete);
    assert_eq!(r.rows[0][0], "2");
}
#[test]
fn path_depth_limit_and_name_bounds() {
    let (mut b, isf) = fixture();
    path_fixture(&mut b);
    let job = Job::default();
    put(&mut b, 0xc608, 0x10000);
    b[0x3f000..0x3f002].copy_from_slice(b"x\0");
    for n in 0..1024 {
        let d = 0x10000 + n * 64;
        put(&mut b, d, (d + 64) as u64);
        put(&mut b, d + 8, 1);
        put(&mut b, d + 16, 0x3f000);
    }
    let i = image(&b);
    assert!(
        engine(&i, &isf)
            .file_path(0xa000, 0xc600, &job)
            .unwrap_err()
            .to_string()
            .contains("1024")
    );
    put(&mut b, 0x10008, 256);
    let i = image(&b);
    assert!(
        engine(&i, &isf)
            .file_path(0xa000, 0xc600, &job)
            .unwrap_err()
            .to_string()
            .contains("长度")
    );
}
