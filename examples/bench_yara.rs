//! Benchmark YARA physical and virtual region scanning performance,
//! plus physical scan I/O (`image.read`) vs rule-matching (`scanner.scan`) breakdown.
use anyhow::{Result, ensure};
use std::{
    io::Write,
    path::PathBuf,
    time::{Duration, Instant},
};
use zero_tui::{
    Job,
    image::{Image, Segment},
    yara::{YaraSpec, scan_physical, scan_region_sparse_with_scanner, scan_region_with_scanner},
};

const PAGE_SIZE: usize = 4096;
const PAGE: u64 = PAGE_SIZE as u64;
const CHUNK: usize = 16 * 1024 * 1024;
const OVERLAP: usize = 4096;
const ROUNDS: usize = 5;

fn median_ms(samples: &mut [Duration]) -> f64 {
    samples.sort();
    let mid = samples.len() / 2;
    samples.get(mid).copied().unwrap_or_default().as_secs_f64() * 1000.0
}

fn bench<F>(name: &str, mut f: F) -> Result<f64>
where
    F: FnMut() -> Result<usize>,
{
    // Warmup
    let warmup_hits = f()?;
    let mut times = Vec::with_capacity(ROUNDS);
    for _ in 0..ROUNDS {
        let start = Instant::now();
        let hits = f()?;
        let elapsed = start.elapsed();
        ensure!(hits == warmup_hits, "benchmark hit count drifted");
        times.push(elapsed);
    }
    let med = median_ms(&mut times);
    let min = times.first().copied().unwrap_or_default().as_secs_f64() * 1000.0;
    let max = times.last().copied().unwrap_or_default().as_secs_f64() * 1000.0;
    println!(
        "{name:<42} median={med:8.2} ms  min={min:8.2} ms  max={max:8.2} ms  hits={warmup_hits}"
    );
    Ok(med)
}

fn realistic_rules() -> &'static str {
    r#"
rule c2_beacon_markers {
    strings:
        $a1 = "ReflectiveLoader" ascii
        $a2 = "beacon.dll" wide
        $h1 = { 4D 5A 90 00 03 00 ?? ?? 04 00 00 00 FF FF }
    condition:
        any of them
}

rule linux_rootkit_strings {
    strings:
        $s1 = "diamorphine_init" ascii
        $s2 = "reptile_hide" ascii
        $s3 = "/dev/shm/.hidden_payload" ascii
        $h1 = { 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 40 10 }
    condition:
        any of them
}

rule credential_dump_tools {
    strings:
        $m1 = "sekurlsa::logonpasswords" ascii nocase
        $m2 = "lsadump::sam" ascii nocase
        $m3 = "kerberos::golden" wide
    condition:
        any of them
}

rule shellcode_stubs {
    strings:
        $x1 = { FC 48 83 E4 F0 E8 C0 00 00 00 41 51 41 50 }
        $x2 = { 65 48 8B 04 25 60 00 00 00 48 8B 40 18 }
        $x3 = { 31 C0 50 68 2F 2F 73 68 68 2F 62 69 6E }
    condition:
        any of them
}

rule suspicious_urls {
    strings:
        $u1 = /https?:\/\/[a-z0-9\.-]{6,32}\/stage[0-9]{1,3}\/payload\.bin/
        $u2 = /powershell(\.exe)?\s+-[eE][nN][cC]\s+[A-Za-z0-9+\/]{16,}/
    condition:
        any of them
}

rule webshell_markers {
    strings:
        $w1 = "eval(base64_decode($_POST[" ascii
        $w2 = "Runtime.getRuntime().exec(request.getParameter" ascii
        $w3 = "System.Diagnostics.Process.Start" wide
    condition:
        any of them
}

rule crypto_wallet_stealer {
    strings:
        $c1 = "wallet.dat" ascii
        $c2 = "electrum_seed_phrase" ascii
        $c3 = { 62 31 05 00 09 00 00 00 00 20 00 00 00 09 }
    condition:
        2 of them
}

rule elf_implant_pack {
    strings:
        $e1 = "UPX!" ascii
        $e2 = "SLIVER_IMPLANT_V2" ascii
        $e3 = "MYTHIC_POSEIDON_AGENT" ascii
    condition:
        $e2 or $e3 or ($e1 and #e1 > 4)
}
"#
}

fn heavy_rules_source() -> String {
    let mut src = String::from(realistic_rules());
    for i in 0..48 {
        src.push_str(&format!(
            r#"
rule synthetic_heavy_{i:02} {{
    strings:
        $a = "IMPLANT_FAMILY_{i:02}_MARKER" ascii
        $b = "C2_PROFILE_{i:02}_CONFIG" wide
        $h = {{ 55 48 89 E5 48 83 EC {:02X} ?? ?? 48 8B 45 F8 }}
        $r = /agent_{i:02}_[a-f0-9]{{8,16}}_beacon/
    condition:
        any of them
}}
"#,
            (i * 4 + 16) & 0xff
        ));
    }
    src
}

fn high_hit_rules() -> &'static str {
    r#"
rule high_hit_alpha {
    strings:
        $a = "HIT_ALPHA_01" ascii
        $b = "HIT_BETA_02" ascii
    condition:
        any of them
}

rule high_hit_gamma {
    strings:
        $g = { DE AD BE EF 13 37 }
    condition:
        $g
}
"#
}

fn build_synthetic_image(
    segments_count: usize,
    seg_bytes: usize,
    hole_bytes: u64,
    pattern_stride: Option<usize>,
) -> Result<Image> {
    let mut file = tempfile::tempfile()?;
    // Deterministic non-zero background block (1 MiB) so nothing is trivially zero-filled.
    let mut block = vec![0u8; 1024 * 1024];
    let mut state = 0x1234_5678_9abc_def0u64;
    for byte in &mut block {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = (state & 0xff) as u8;
    }

    let mut segments = Vec::with_capacity(segments_count);
    let mut phys = 0x10_0000u64;
    let mut file_offset = 0u64;
    for seg_idx in 0..segments_count {
        let mut written = 0usize;
        while written < seg_bytes {
            let chunk_len = (seg_bytes - written).min(block.len());
            let mut slice = block.get(..chunk_len).unwrap_or_default().to_vec();
            if let Some(stride) = pattern_stride {
                let mut pos = 0usize;
                while pos + 64 < slice.len() {
                    slice[pos..pos + 12].copy_from_slice(b"HIT_ALPHA_01");
                    slice[pos + 24..pos + 35].copy_from_slice(b"HIT_BETA_02");
                    slice[pos + 48..pos + 54]
                        .copy_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x13, 0x37]);
                    pos += stride;
                }
            } else if written.is_multiple_of(16 * 1024 * 1024) {
                // Plant a few realistic hits, including near chunk boundary.
                slice[128..144].copy_from_slice(b"ReflectiveLoader");
                slice[4090..4106].copy_from_slice(b"diamorphine_init");
                let tail = slice.len().saturating_sub(24);
                slice[tail..tail + 17].copy_from_slice(b"SLIVER_IMPLANT_V2");
            }
            file.write_all(&slice)?;
            written += chunk_len;
        }
        segments.push(Segment {
            start: phys,
            end: phys + seg_bytes as u64,
            file_offset,
        });
        file_offset += seg_bytes as u64;
        phys += seg_bytes as u64
            + if seg_idx + 1 < segments_count {
                hole_bytes
            } else {
                0
            };
    }
    file.flush()?;
    let mut image = Image::from_file(file, format!("bench-{segments_count}x{seg_bytes}"))?;
    image.segments = segments;
    Ok(image)
}

fn measure_io_vs_scan(label: &str, image: &Image, spec: &YaraSpec) -> Result<()> {
    let YaraSpec::Rules(ref _compiled) = *spec else {
        return Ok(());
    };
    let mut read_samples = Vec::with_capacity(ROUNDS);
    let mut scan_samples = Vec::with_capacity(ROUNDS);
    let mut total_bytes = 0u64;

    // Warmup + timed rounds
    for round in 0..=ROUNDS {
        let mut read_time = Duration::ZERO;
        let mut scan_time = Duration::ZERO;
        let mut buf = vec![0u8; CHUNK + OVERLAP];
        let mut valid_len = 0usize;
        let mut previous_end = None;
        let mut scanner = match spec {
            YaraSpec::Rules(_) => spec.scanner(),
            YaraSpec::Pattern(_) => return Ok(()),
        };
        let mut bytes_this_round = 0u64;

        // Extract raw yara_x::Scanner by timing via a fresh scanner on the same chunks.
        // We time image.read and scan_buffer-equivalent scan separately.
        let _ = &mut scanner;
        // Use a dedicated yara_x::Scanner via YaraSpec::from_rules_source? No, measure directly
        // by timing image.read into buf, and timing scan_physical vs read-only pass!
        // Even better: time image.read into buf directly per chunk, and measure full scan_physical.
        for segment in &image.segments {
            if previous_end != Some(segment.start) && valid_len > 0 {
                let t0 = Instant::now();
                let _ = &buf[..valid_len];
                scan_time += t0.elapsed();
                valid_len = 0;
            }
            let mut pos = segment.start;
            while pos < segment.end {
                let want = (CHUNK + OVERLAP).saturating_sub(valid_len).max(1);
                let count = usize::try_from((segment.end - pos).min(want as u64))?;
                let t0 = Instant::now();
                image.read(pos, &mut buf[valid_len..valid_len + count])?;
                read_time += t0.elapsed();
                bytes_this_round += count as u64;
                pos += count as u64;
                valid_len += count;
                if valid_len >= CHUNK + OVERLAP {
                    buf.copy_within(CHUNK..valid_len, 0);
                    valid_len -= CHUNK;
                }
            }
            previous_end = Some(segment.end);
        }
        let t_full = Instant::now();
        let res = scan_physical(image, spec, &Job::default())?;
        let full_time = t_full.elapsed();
        let _ = res.hits.len();
        scan_time = full_time.saturating_sub(read_time);

        if round > 0 {
            read_samples.push(read_time);
            scan_samples.push(scan_time);
            total_bytes = bytes_this_round;
        }
    }

    let read_ms = median_ms(&mut read_samples);
    let scan_ms = median_ms(&mut scan_samples);
    let total_ms = read_ms + scan_ms;
    let read_pct = if total_ms > 0.0 {
        100.0 * read_ms / total_ms
    } else {
        0.0
    };
    let scan_pct = if total_ms > 0.0 {
        100.0 * scan_ms / total_ms
    } else {
        0.0
    };
    let mib = total_bytes as f64 / (1024.0 * 1024.0);
    println!(
        "[Item 5 breakdown] {label} ({mib:.1} MiB): image.read={read_ms:7.2} ms ({read_pct:4.1}%) | scan+overhead={scan_ms:7.2} ms ({scan_pct:4.1}%) | total={total_ms:7.2} ms"
    );
    Ok(())
}

fn main() -> Result<()> {
    let job = Job::default();
    let realistic = YaraSpec::from_rules_source(realistic_rules())?;
    let heavy = YaraSpec::from_rules_source(&heavy_rules_source())?;
    let high_hit = YaraSpec::from_rules_source(high_hit_rules())?;

    println!("=== Building synthetic fixtures ===");
    // 1. 256 MiB multi-segment physical image (4 x 64 MiB with 4 MiB holes)
    let large_img = build_synthetic_image(4, 64 * 1024 * 1024, 4 * 1024 * 1024, None)?;
    // 2. 64 MiB high-hit physical image (~48k hits across 3 patterns)
    let high_hit_img = build_synthetic_image(1, 64 * 1024 * 1024, 0, Some(4096))?;
    // 3. 64 MiB VMA buffer in memory
    let vma_bytes = 64 * 1024 * 1024usize;
    let mut vma_mem = vec![0x41u8; vma_bytes];
    for off in (0..vma_bytes).step_by(256 * 1024) {
        if off + 32 < vma_bytes {
            vma_mem[off..off + 16].copy_from_slice(b"ReflectiveLoader");
        }
    }
    // Cross-page hit at page 10 boundary
    vma_mem[10 * PAGE_SIZE - 5..10 * PAGE_SIZE + 11].copy_from_slice(b"ReflectiveLoader");

    println!("\n=== YARA Scan Benchmarks (ROUNDS={ROUNDS}, median) ===");

    bench("1a. physical 256MiB (4 segs, 8 rules)", || {
        let s = scan_physical(&large_img, &realistic, &job)?;
        Ok(s.hits.len())
    })?;

    bench("1b. physical 256MiB (4 segs, 56 rules)", || {
        let s = scan_physical(&large_img, &heavy, &job)?;
        Ok(s.hits.len())
    })?;

    bench("2.  physical 64MiB high-hit (~48k hits)", || {
        let s = scan_physical(&high_hit_img, &high_hit, &job)?;
        Ok(s.hits.len())
    })?;

    // 3a. Dense VMA 64 MiB (simulating vm.read with arbitrary slice length)
    bench("3a. VMA dense 64MiB (8 rules)", || {
        let mut scanner = realistic.scanner();
        let mut budget = 256 * 1024 * 1024u64;
        let s = scan_region_with_scanner(
            &mut scanner,
            0,
            vma_bytes as u64,
            &mut budget,
            100_000,
            &job,
            |at, out| {
                let start = usize::try_from(at)?;
                let end = start + out.len();
                ensure!(end <= vma_mem.len(), "oob");
                out.copy_from_slice(&vma_mem[start..end]);
                Ok(())
            },
        )?;
        Ok(s.hits.len())
    })?;

    // 3b. Sparse VMA 64 MiB (periodic 4-page holes every 256 pages + single-page holes)
    let is_absent = |page_idx: u64| -> bool {
        let m = page_idx % 256;
        (120..124).contains(&m) || m == 200
    };
    bench("3b. VMA sparse 64MiB (holes+skip_absent)", || {
        let mut scanner = realistic.scanner();
        let mut budget = 256 * 1024 * 1024u64;
        let s = scan_region_sparse_with_scanner(
            &mut scanner,
            0,
            vma_bytes as u64,
            &mut budget,
            100_000,
            &job,
            |at, out| {
                let mut cur = at;
                let mut dst = out;
                while !dst.is_empty() {
                    let page_idx = cur / PAGE;
                    ensure!(!is_absent(page_idx), "absent page");
                    let step = dst.len().min(PAGE_SIZE - (cur as usize % PAGE_SIZE));
                    let s_off = usize::try_from(cur)?;
                    dst[..step].copy_from_slice(&vma_mem[s_off..s_off + step]);
                    cur += step as u64;
                    dst = &mut dst[step..];
                }
                Ok(())
            },
            |at, end| {
                let page_idx = at / PAGE;
                if (120..124).contains(&(page_idx % 256)) {
                    let base_block = page_idx - (page_idx % 256);
                    Some(((base_block + 124) * PAGE).min(end))
                } else {
                    None
                }
            },
        )?;
        Ok(s.hits.len())
    })?;

    // 3c. Many small VMAs (512 x 64 KiB = 32 MiB) reusing one scanner
    bench("3c. VMA 512x64KiB (reused scanner)", || {
        let mut scanner = realistic.scanner();
        let mut budget = 256 * 1024 * 1024u64;
        let mut total_hits = 0usize;
        for i in 0..512u64 {
            let start = i * 64 * 1024;
            let end = start + 64 * 1024;
            let s = scan_region_with_scanner(
                &mut scanner,
                start,
                end,
                &mut budget,
                100_000,
                &job,
                |at, out| {
                    let s_off = usize::try_from(at)?;
                    out.copy_from_slice(&vma_mem[s_off..s_off + out.len()]);
                    Ok(())
                },
            )?;
            total_hits += s.hits.len();
        }
        Ok(total_hits)
    })?;

    println!("\n=== Item 5: Physical Scan I/O vs Scan Breakdown ===");
    measure_io_vs_scan("256MiB 4-seg (8 rules)", &large_img, &realistic)?;
    measure_io_vs_scan("256MiB 4-seg (56 rules)", &large_img, &heavy)?;
    measure_io_vs_scan("64MiB high-hit (3 rules)", &high_hit_img, &high_hit)?;

    if let Ok(path) = std::env::var("ZERO_TEST_IMAGE")
        && !path.is_empty()
    {
        let p = PathBuf::from(&path);
        if p.exists() {
            println!("\n=== Real Sample ({path}) ===");
            let cache = tempfile::tempdir()?;
            let img = Image::open(&p, cache.path(), &job)?;
            bench("real sample (8 rules)", || {
                let s = scan_physical(&img, &realistic, &job)?;
                Ok(s.hits.len())
            })?;
            measure_io_vs_scan("real sample (8 rules)", &img, &realistic)?;
        }
    } else {
        println!("\n(ZERO_TEST_IMAGE not set; skipping real sample benchmark)");
    }

    Ok(())
}
