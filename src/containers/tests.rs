use super::*;
use crate::{Job, image::Image};
use std::{fs, io::Write};

fn build_elf64_core(
    segments: &[(u64, &[u8])],
    qemu_cr3: Option<(u64, u64)>,
    vmcoreinfo: Option<&str>,
) -> Vec<u8> {
    let mut notes = Vec::new();
    let push_note = |buf: &mut Vec<u8>, name: &[u8], n_type: u32, desc: &[u8]| {
        buf.extend_from_slice(&(name.len() as u32).to_le_bytes());
        buf.extend_from_slice(&(desc.len() as u32).to_le_bytes());
        buf.extend_from_slice(&n_type.to_le_bytes());
        buf.extend_from_slice(name);
        while !buf.len().is_multiple_of(4) {
            buf.push(0);
        }
        buf.extend_from_slice(desc);
        while !buf.len().is_multiple_of(4) {
            buf.push(0);
        }
    };
    if let Some((rip, cr3)) = qemu_cr3 {
        let mut cpu = vec![0u8; 432];
        cpu[0..4].copy_from_slice(&432u32.to_le_bytes()); // size
        cpu[4..8].copy_from_slice(&1u32.to_le_bytes()); // version
        cpu[8 + 6 * 8..8 + 7 * 8].copy_from_slice(&0xffff_8880_0000_1234u64.to_le_bytes()); // rsp
        cpu[136..144].copy_from_slice(&rip.to_le_bytes());
        cpu[392..400].copy_from_slice(&0x8005_0033u64.to_le_bytes()); // cr0
        cpu[416..424].copy_from_slice(&cr3.to_le_bytes()); // cr3
        cpu[424..432].copy_from_slice(&0x0000_06f0u64.to_le_bytes()); // cr4
        push_note(&mut notes, b"QEMU\0", 0, &cpu);
    }
    if let Some(info) = vmcoreinfo {
        push_note(&mut notes, b"VMCOREINFO\0", 0, info.as_bytes());
    }

    let phnum = segments.len() + usize::from(!notes.is_empty());
    let phoff = 64u64;
    let phentsize = 56u16;
    let data_start = phoff + (phnum * usize::from(phentsize)) as u64;

    let mut out = vec![0u8; data_start as usize];
    out[0..4].copy_from_slice(b"\x7fELF");
    out[4] = 2; // ELF64
    out[5] = 1; // LE
    out[6] = 1; // EV_CURRENT
    out[16..18].copy_from_slice(&4u16.to_le_bytes()); // ET_CORE
    out[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    out[20..24].copy_from_slice(&1u32.to_le_bytes());
    out[32..40].copy_from_slice(&phoff.to_le_bytes());
    out[52..54].copy_from_slice(&64u16.to_le_bytes());
    out[54..56].copy_from_slice(&phentsize.to_le_bytes());
    out[56..58].copy_from_slice(&(phnum as u16).to_le_bytes());

    let mut ph_idx = 0usize;
    let mut write_ph = |out: &mut [u8], p_type: u32, offset: u64, paddr: u64, filesz: u64| {
        let base = phoff as usize + ph_idx * usize::from(phentsize);
        out[base..base + 4].copy_from_slice(&p_type.to_le_bytes());
        out[base + 8..base + 16].copy_from_slice(&offset.to_le_bytes());
        out[base + 24..base + 32].copy_from_slice(&paddr.to_le_bytes());
        out[base + 32..base + 40].copy_from_slice(&filesz.to_le_bytes());
        out[base + 40..base + 48].copy_from_slice(&filesz.to_le_bytes());
        ph_idx += 1;
    };

    if !notes.is_empty() {
        let note_off = out.len() as u64;
        out.extend_from_slice(&notes);
        write_ph(&mut out, 4, note_off, 0, notes.len() as u64);
    }
    for &(paddr, data) in segments {
        let seg_off = out.len() as u64;
        out.extend_from_slice(data);
        write_ph(&mut out, 1, seg_off, paddr, data.len() as u64);
    }
    out
}

fn push_vmware_tag(buf: &mut Vec<u8>, name: &str, indices: &[u32], value: &[u8]) {
    let flags = ((indices.len() as u8) << 6) | (value.len() as u8);
    buf.push(flags);
    buf.push(name.len() as u8);
    buf.extend_from_slice(name.as_bytes());
    for &idx in indices {
        buf.extend_from_slice(&idx.to_le_bytes());
    }
    buf.extend_from_slice(value);
}

fn push_vmware_block_tag_64(buf: &mut Vec<u8>, name: &str, indices: &[u32], payload: &[u8]) {
    let flags = ((indices.len() as u8) << 6) | 0x3f;
    buf.push(flags);
    buf.push(name.len() as u8);
    buf.extend_from_slice(name.as_bytes());
    for &idx in indices {
        buf.extend_from_slice(&idx.to_le_bytes());
    }
    buf.extend_from_slice(&(payload.len() as u64).to_le_bytes()); // disk_size
    buf.extend_from_slice(&(payload.len() as u64).to_le_bytes()); // mem_size
    buf.extend_from_slice(&0u16.to_le_bytes()); // pad_size
    buf.extend_from_slice(payload);
}

fn build_vmware_checkpoint(
    regions: &[(u64, u64, u64)],
    embedded_mem: Option<&[u8]>,
    vcpu_cr3: u64,
    vcpu_rip: u64,
) -> Vec<u8> {
    let mut mem_group = Vec::new();
    push_vmware_tag(
        &mut mem_group,
        "regionsCount",
        &[],
        &(regions.len() as u32).to_le_bytes(),
    );
    for (i, &(ppn, page_num, size_pages)) in regions.iter().enumerate() {
        let idx = i as u32;
        push_vmware_tag(&mut mem_group, "regionPPN", &[idx], &ppn.to_le_bytes());
        push_vmware_tag(
            &mut mem_group,
            "regionPageNum",
            &[idx],
            &page_num.to_le_bytes(),
        );
        push_vmware_tag(
            &mut mem_group,
            "regionSize",
            &[idx],
            &size_pages.to_le_bytes(),
        );
    }
    if let Some(mem) = embedded_mem {
        push_vmware_block_tag_64(&mut mem_group, "Memory", &[0, 0], mem);
    }
    mem_group.extend_from_slice(&[0, 0]);

    let mut cpu_group = Vec::new();
    push_vmware_tag(&mut cpu_group, "cr", &[0, 3], &vcpu_cr3.to_le_bytes());
    push_vmware_tag(&mut cpu_group, "rip", &[0], &vcpu_rip.to_le_bytes());
    cpu_group.extend_from_slice(&[0, 0]);

    let dir_size = 2 * 80;
    let mem_off = (12 + dir_size) as u64;
    let cpu_off = mem_off + mem_group.len() as u64;

    let mut out = Vec::new();
    out.extend_from_slice(&0xbed2_bed2u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&2u32.to_le_bytes());

    for (name, off, sz) in [
        ("memory", mem_off, mem_group.len() as u64),
        ("cpu", cpu_off, cpu_group.len() as u64),
    ] {
        let mut entry = [0u8; 80];
        entry[..name.len()].copy_from_slice(name.as_bytes());
        entry[64..72].copy_from_slice(&off.to_le_bytes());
        entry[72..80].copy_from_slice(&sz.to_le_bytes());
        out.extend_from_slice(&entry);
    }
    out.extend_from_slice(&mem_group);
    out.extend_from_slice(&cpu_group);
    out
}

fn push_avml_range(out: &mut Vec<u8>, start: u64, data: &[u8], compressed: bool) {
    let end_inclusive = start + data.len() as u64 - 1;
    out.extend_from_slice(&avml::AVML_MAGIC.to_le_bytes());
    out.extend_from_slice(&2u32.to_le_bytes());
    out.extend_from_slice(&start.to_le_bytes());
    out.extend_from_slice(&end_inclusive.to_le_bytes());
    out.extend_from_slice(&[0u8; 8]);
    out.extend_from_slice(&snappy::encode_framed(data, compressed));
}

fn push_lime_range(out: &mut Vec<u8>, start: u64, data: &[u8]) {
    let end_inclusive = start + data.len() as u64 - 1;
    out.extend_from_slice(&avml::LIME_MAGIC.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&start.to_le_bytes());
    out.extend_from_slice(&end_inclusive.to_le_bytes());
    out.extend_from_slice(&[0u8; 8]);
    out.extend_from_slice(data);
}

#[test]
fn qemu_elf64_core_dump_reads_segments_and_notes() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let cache = dir.path().join("cache");
    fs::create_dir_all(&cache)?;

    let mut seg0 = vec![0u8; 8192];
    let banner = b"Linux version 6.8.0-qemu-test (gcc)\0";
    seg0[0x200..0x200 + banner.len()].copy_from_slice(banner);
    let mut seg1 = vec![0x5au8; 4096];
    seg1[0x10..0x18].copy_from_slice(b"KVM_HIGH");

    let elf = build_elf64_core(
        &[(0x0, &seg0), (0x10_0000, &seg1)],
        Some((0xffff_ffff_8100_1234, 0x001a_2000)),
        Some("OSRELEASE=6.8.0-qemu-test\nPAGESIZE=4096\n"),
    );
    let path = dir.path().join("guest.elf");
    fs::write(&path, &elf)?;

    let job = Job::default();
    let img = Image::open(&path, &cache, &job)?;
    assert_eq!(img.format, "ELF Core (QEMU/KVM)");
    assert_eq!(img.segments.len(), 2);

    let mut got = [0u8; 8];
    img.read(0x10_0010, &mut got)?;
    assert_eq!(&got, b"KVM_HIGH");
    assert!(img.read(0x4000, &mut got).is_err());

    let banners = img.banners(&job)?;
    assert_eq!(banners.len(), 1);
    assert_eq!(banners[0].0, 0x200);
    assert_eq!(banners[0].1, banner);

    let vm = img.vm_metadata.as_ref().expect("vm_metadata");
    assert_eq!(vm.architecture.as_deref(), Some("x86_64"));
    assert_eq!(vm.vcpus.len(), 1);
    assert_eq!(vm.vcpus[0].rip, Some(0xffff_ffff_8100_1234));
    assert_eq!(vm.vcpus[0].cr3, Some(0x001a_2000));
    assert_eq!(vm.cr3_hints(), vec![0x001a_2000]);
    assert!(
        vm.vmcoreinfo
            .as_deref()
            .unwrap()
            .contains("OSRELEASE=6.8.0")
    );
    Ok(())
}

#[test]
fn vmware_vmem_and_vmsn_companion_and_embedded_snapshots() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let cache = dir.path().join("cache");
    fs::create_dir_all(&cache)?;

    // Two 4 KiB pages in backing store: page 0 -> GPA 0x0, page 1 -> GPA 0x100000 (PCI hole)
    let mut backing = vec![0u8; 8192];
    let banner = b"Linux version 6.6.0-vmware (clang)\0";
    backing[0x100..0x100 + banner.len()].copy_from_slice(banner);
    backing[4096 + 0x40..4096 + 0x48].copy_from_slice(b"VMW_HIGH");

    // 1. Companion pair: guest.vmem + guest.vmsn
    let vmem_path = dir.path().join("guest.vmem");
    let vmsn_path = dir.path().join("guest.vmsn");
    fs::write(&vmem_path, &backing)?;
    let vmsn = build_vmware_checkpoint(
        &[(0, 0, 1), (0x100, 1, 1)],
        None,
        0x002b_4000,
        0xffff_f800_0123_4567,
    );
    fs::write(&vmsn_path, &vmsn)?;

    let job = Job::default();
    for open_path in [&vmem_path, &vmsn_path] {
        let img = Image::open(open_path, &cache, &job)?;
        assert_eq!(img.format, "VMware (.vmem+.vmsn)");
        assert_eq!(img.segments.len(), 2);
        let mut high = [0u8; 8];
        img.read(0x10_0040, &mut high)?;
        assert_eq!(&high, b"VMW_HIGH");
        assert!(img.read(0x2000, &mut high).is_err());
        let banners = img.banners(&job)?;
        assert_eq!(banners.len(), 1);
        assert_eq!(banners[0].0, 0x100);
        let vm = img.vm_metadata.as_ref().expect("vm_metadata");
        assert_eq!(vm.cr3_hints(), vec![0x002b_4000]);
        assert_eq!(vm.vcpus[0].rip, Some(0xffff_f800_0123_4567));
        // Identification cache reuse
        let reopened = Image::open_identified(open_path, &cache, &job)?;
        assert_eq!(reopened.format, "VMware (.vmem+.vmsn)");
        assert_eq!(reopened.banners(&job)?, banners);
    }

    // 2. Standalone embedded snapshot (.vmss)
    let vmss_path = dir.path().join("embedded.vmss");
    let vmss = build_vmware_checkpoint(
        &[(0, 0, 1), (0x200, 1, 1)],
        Some(&backing),
        0x003c_0000,
        0x401000,
    );
    fs::write(&vmss_path, &vmss)?;
    let img = Image::open(&vmss_path, &cache, &job)?;
    assert_eq!(img.format, "VMware Snapshot");
    let mut high = [0u8; 8];
    img.read(0x20_0040, &mut high)?;
    assert_eq!(&high, b"VMW_HIGH");
    assert_eq!(
        img.vm_metadata.as_ref().unwrap().cr3_hints(),
        vec![0x003c_0000]
    );

    // 3. Standalone .vmsn with no embedded memory and no .vmem fails explicitly
    let orphan = dir.path().join("orphan.vmsn");
    fs::write(&orphan, &vmsn)?;
    assert!(Image::open(&orphan, &cache, &job).is_err());
    Ok(())
}

#[test]
fn avml_snappy_v2_multi_chunk_and_mixed_lime_reads_and_scans() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let cache = dir.path().join("cache");
    fs::create_dir_all(&cache)?;

    // Range 0: 70 KiB (spans 2 Snappy 64 KiB framed chunks) compressed at 0x1000
    let mut range0: Vec<u8> = (0..70_000).map(|i| (i * 17 % 251) as u8).collect();
    let banner = b"Linux version 6.1.0-avml-snappy (gcc)\0";
    // Place banner straddling the 64 KiB chunk boundary!
    range0[65_530..65_530 + banner.len()].copy_from_slice(banner);

    // Range 1: uncompressed Snappy chunk at 0x40000
    let range1 = vec![0xab; 4096];
    // Range 2: standard LiME v1 range mixed in the same file at 0x80000
    let mut range2 = vec![0xcd; 4096];
    range2[16..24].copy_from_slice(b"LIME_MIX");

    let mut avml_bytes = Vec::new();
    push_avml_range(&mut avml_bytes, 0x1000, &range0, true);
    push_avml_range(&mut avml_bytes, 0x4_0000, &range1, false);
    push_lime_range(&mut avml_bytes, 0x8_0000, &range2);

    let path = dir.path().join("capture.avml");
    fs::write(&path, &avml_bytes)?;

    let job = Job::default();
    let img = Image::open(&path, &cache, &job)?;
    assert_eq!(img.format, "AVML");
    assert_eq!(img.segments.len(), 3);

    // Cross-chunk read
    let mut out = vec![0u8; banner.len()];
    img.read(0x1000 + 65_530, &mut out)?;
    assert_eq!(out, banner);

    // Uncompressed Snappy chunk read
    let mut u = [0u8; 16];
    img.read(0x4_0000, &mut u)?;
    assert_eq!(u, [0xab; 16]);

    // Mixed LiME v1 range read
    let mut m = [0u8; 8];
    img.read(0x8_0010, &mut m)?;
    assert_eq!(&m, b"LIME_MIX");

    // Hole returns error
    assert!(img.read(0x3_0000, &mut m).is_err());

    // Banner scan works across chunk boundary
    let banners = img.banners(&job)?;
    assert_eq!(banners.len(), 1);
    assert_eq!(banners[0].0, 0x1000 + 65_530);
    assert_eq!(banners[0].1, banner);
    Ok(())
}

#[test]
fn zstd_and_xz_compressed_images_auto_detect_and_reuse_cache() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let cache = dir.path().join("cache");
    fs::create_dir_all(&cache)?;

    let mut raw = vec![0u8; 16_384];
    let banner = b"Linux version 6.8.0-compressed (gcc)\0";
    raw[0x400..0x400 + banner.len()].copy_from_slice(banner);
    let elf = build_elf64_core(&[(0x1000, &raw)], Some((0x1234, 0x5000)), None);

    // 1. Zstandard (.zst) wrapping an ELF Core dump
    let zst_path = dir.path().join("guest.elf.zst");
    {
        let mut enc = zstd::stream::write::Encoder::new(fs::File::create(&zst_path)?, 1)?;
        enc.write_all(&elf)?;
        enc.finish()?;
    }

    // 2. XZ (.xz) wrapping a RAW image
    let xz_path = dir.path().join("memory.raw.xz");
    {
        let mut enc = xz2::write::XzEncoder::new(fs::File::create(&xz_path)?, 1);
        enc.write_all(&raw)?;
        enc.finish()?;
    }

    let job = Job::default();
    let img_zst = Image::open(&zst_path, &cache, &job)?;
    assert_eq!(img_zst.format, "ELF Core (QEMU/KVM)");
    assert_eq!(img_zst.banners(&job)?.len(), 1);
    assert_eq!(img_zst.banners(&job)?[0].0, 0x1400);
    let reopened_zst = Image::open_identified(&zst_path, &cache, &job)?;
    assert_eq!(reopened_zst.format, "ELF Core (QEMU/KVM)");

    let img_xz = Image::open(&xz_path, &cache, &job)?;
    assert_eq!(img_xz.format, "RAW");
    assert_eq!(img_xz.banners(&job)?.len(), 1);
    assert_eq!(img_xz.banners(&job)?[0].0, 0x400);
    let reopened_xz = Image::open_identified(&xz_path, &cache, &job)?;
    assert_eq!(reopened_xz.format, "RAW");
    Ok(())
}

#[test]
fn vmware_companion_edit_changes_image_digest() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let cache = dir.path().join("cache");
    fs::create_dir_all(&cache)?;

    let vmem_path = dir.path().join("guest.vmem");
    let vmsn_path = dir.path().join("guest.vmsn");
    fs::write(&vmem_path, vec![0xabu8; 8192])?;
    fs::write(
        &vmsn_path,
        build_vmware_checkpoint(&[(0x1, 0, 2)], None, 0x2000, 0x1000),
    )?;

    let job = Job::default();
    let first = Image::open(&vmem_path, &cache, &job)?;
    assert_eq!(first.format, "VMware (.vmem+.vmsn)");
    let first_digest = first.digest.clone();
    drop(first);

    // Changing the companion checkpoint layout must produce a distinct image digest.
    fs::write(
        &vmsn_path,
        build_vmware_checkpoint(&[(0x4, 0, 2)], None, 0x3000, 0x1000),
    )?;
    let second = Image::open(&vmem_path, &cache, &job)?;
    assert_ne!(first_digest, second.digest);
    Ok(())
}
