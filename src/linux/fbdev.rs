//! fbdev registration, geometry and explicit bounded framebuffer exports.
use super::*;
use crate::{
    dump::DumpOptions,
    framebuffer::{Channel, Layout},
};

struct Frame {
    object: u64,
    address: u64,
    id: String,
    width: u32,
    height: u32,
    stride: u64,
    bpp: u32,
    size: u64,
    state: u64,
    grayscale: u64,
}
impl Linux<'_> {
    fn framebuffer(&self, object: u64) -> Result<Frame> {
        let number = |field: &str| self.number(object, "fb_info", field);
        ensure!(
            self.isf.size("fb_info", "fix.id")? <= 256,
            "framebuffer ID 超过读取上限"
        );
        let id = self.string(object, "fb_info", "fix.id")?;
        let width = number("var.xres_virtual")?.try_into()?;
        let height: u32 = number("var.yres_virtual")?.try_into()?;
        let stride = number("fix.line_length")?;
        Ok(Frame {
            object,
            address: number("screen_base")?,
            id,
            width,
            height,
            stride,
            bpp: number("var.bits_per_pixel")?.try_into()?,
            size: stride
                .checked_mul(u64::from(height))
                .context("framebuffer 长度溢出")?,
            state: number("state")?,
            grayscale: number("var.grayscale")?,
        })
    }
    fn framebuffer_layout(&self, fb: &Frame) -> Result<Layout> {
        let mut channels = [Channel::default(); 4];
        for (channel, name) in channels.iter_mut().zip(["red", "green", "blue", "transp"]) {
            let field = |member| self.number(fb.object, "fb_info", &format!("var.{name}.{member}"));
            *channel = Channel {
                offset: field("offset")?.try_into()?,
                length: field("length")?.try_into()?,
                msb_right: field("msb_right")? != 0,
            };
        }
        let layout = Layout {
            width: fb.width,
            height: fb.height,
            stride: fb.stride,
            bits_per_pixel: fb.bpp,
            channels,
        };
        layout.validate(fb.address)?;
        Ok(layout)
    }
    fn dump_framebuffer(
        &self,
        fb: &Frame,
        options: &DumpOptions,
        job: &Job,
    ) -> Result<(String, serde_json::Value)> {
        ensure!(fb.address != 0 && fb.size > 0, "framebuffer 地址或长度为零");
        ensure!(
            fb.size <= crate::dump::MAX_DUMP_BYTES,
            "framebuffer 超过 256 MiB 上限"
        );
        fb.address
            .checked_add(fb.size)
            .context("framebuffer 地址溢出")?;
        // FOURCC buffers retain every captured byte instead of inventing RGB pixels.
        let png = fb.grayscale <= 1;
        let layout = png.then(|| self.framebuffer_layout(fb)).transpose()?;
        let id: String = if fb.id.is_empty() {
            "N-A".into()
        } else {
            fb.id
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || "._-".contains(c) {
                        c
                    } else {
                        '_'
                    }
                })
                .collect()
        };
        let filename = format!(
            "{id}_{}x{}_{}bpp.{}",
            fb.width,
            fb.height,
            fb.bpp,
            if png { "png" } else { "raw" }
        );
        let target = options.directory.join(&filename);
        let mut source_bytes = 0;
        let (bytes, digest) = crate::dump::write_stream_artifact(&target, job, |out| {
            if let Some(layout) = &layout {
                source_bytes =
                    crate::framebuffer::write_png(fb.address, layout, out, job, |at, buf| {
                        self.vm.read(at, buf)
                    })?;
            } else {
                let mut buffer = vec![0; 65536];
                while source_bytes < fb.size {
                    job.check()?;
                    let len = (fb.size - source_bytes).min(buffer.len() as u64) as usize;
                    self.vm
                        .read(fb.address + source_bytes, &mut buffer[..len])?;
                    out.write_all(&buffer[..len])?;
                    source_bytes += len as u64;
                }
            }
            Ok(())
        })?;
        Ok((
            filename,
            serde_json::json!({"path":target,"bytes":bytes,"sha256":digest,"format":if png {"PNG RGBA8"} else {"RAW FOURCC"},"source_bytes":source_bytes,"stride_respected":true,"channel_values":"unscaled, saturated at 255; missing alpha=255","channels":layout.as_ref().map(|l| l.channels.map(|c|serde_json::json!({"offset":c.offset,"length":c.length,"msb_right":c.msb_right})))}),
        ))
    }
    pub(crate) fn fbdev(&self, dump: Option<&DumpOptions>, job: &Job) -> Result<Results> {
        job.check()?;
        if let Some(options) = dump {
            options.validate(Plugin::Fbdev)?;
        }
        let mut result = self.result(Plugin::Fbdev);
        let registered = (|| -> Result<(u64, usize)> {
            let count = self.vm.uint(self.isf.address("num_registered_fb")?, 4)?;
            ensure!(
                count <= 32,
                "num_registered_fb {count} 超过 fbdev 32 个设备上限或为负"
            );
            if count == 0 {
                return Ok((0, 0));
            }
            Ok((self.isf.address("registered_fb")?, count as usize))
        })();
        let (array, count) = match registered {
            Ok(value) => value,
            Err(error) => {
                job.check()?;
                partial(
                    &mut result,
                    "fbdev 注册表不可用（未编入内核或布局不支持）",
                    error,
                );
                return Ok(result);
            }
        };
        if let Some(options) = dump {
            crate::dump::directory(&options.directory)?;
        }
        let width = self.isf.data["base_types"]["pointer"]["size"]
            .as_u64()
            .unwrap_or(8);
        ensure!(matches!(width, 4 | 8), "无效指针宽度");
        let mut reports = Vec::new();
        let mut selected = 0;
        let mut seen = HashSet::new();
        for i in 0..count {
            job.check()?;
            let parsed = (|| -> Result<Option<Frame>> {
                let object = self
                    .vm
                    .uint(add(array, i as u64 * width)?, width as usize)?;
                ensure!(object != 0, "registered_fb[{i}] 为空；注册数量与数组不一致");
                if dump
                    .and_then(|o| o.start)
                    .is_some_and(|start| start != object)
                {
                    return Ok(None);
                }
                ensure!(
                    seen.insert(object),
                    "registered_fb[{i}] 重复 fb_info {object:#x}"
                );
                self.framebuffer(object).map(Some)
            })();
            let fb = match parsed {
                Ok(Some(fb)) => fb,
                Ok(None) => continue,
                Err(error) => {
                    job.check()?;
                    partial(&mut result, format!("registered_fb[{i}]"), error);
                    continue;
                }
            };
            selected += 1;
            let device = (|| -> Result<String> {
                let dev = self.number(fb.object, "fb_info", "dev")?;
                ensure!(dev != 0, "fb_info.dev 为空");
                let name = self.number(dev, "device", "kobj.name")?;
                ensure!(name != 0, "device.kobj.name 为空");
                user_string(&self.vm, name, 256, job)
            })();
            let device = match device {
                Ok(name) => name,
                Err(error) => {
                    job.check()?;
                    partial(
                        &mut result,
                        format!("fb_info {:#x} 设备名称", fb.object),
                        error,
                    );
                    "N/A".into()
                }
            };
            let mut filename = "Disabled".into();
            let mut artifact = serde_json::Value::Null;
            if let Some(options) = dump {
                match self.dump_framebuffer(&fb, options, job) {
                    Ok((name, proof)) => {
                        filename = name;
                        artifact = proof;
                    }
                    Err(error) => {
                        job.check()?;
                        partial(&mut result, format!("fb_info {:#x} 导出", fb.object), error);
                        filename = "N/A".into();
                    }
                }
            }
            reports.push(serde_json::json!({"index":i,"fb_info":hex(fb.object),"address":hex(fb.address),"width":fb.width,"height":fb.height,"line_length":fb.stride,"size":fb.size,"bits_per_pixel":fb.bpp,"grayscale_or_fourcc":fb.grayscale,"artifact":artifact}));
            result.rows.push(vec![
                hex(fb.address),
                device,
                if fb.id.is_empty() {
                    "N/A".into()
                } else {
                    fb.id
                },
                fb.size.to_string(),
                format!("{}x{}", fb.width, fb.height),
                fb.bpp.to_string(),
                if fb.state == 0 {
                    "RUNNING"
                } else {
                    "SUSPENDED"
                }
                .into(),
                filename,
            ]);
        }
        if let Some(start) = dump.and_then(|o| o.start)
            && selected == 0
        {
            partial(
                &mut result,
                "framebuffer 选择",
                anyhow::anyhow!("未找到 fb_info {start:#x}；不会推断未注册对象"),
            );
        }
        if !result.kernel_identity.is_object() {
            result.kernel_identity = serde_json::json!({});
        }
        result.kernel_identity["fbdev"] = serde_json::json!({"registered_count":count,"registration_scope":"first num_registered_fb slots, matching pinned reference","dump_requested":dump.is_some(),"selected_fb_info":dump.and_then(|o|o.start).map(hex),"frames":reports,"max_devices":32,"max_artifact_bytes":crate::dump::MAX_DUMP_BYTES,"png_pixel_model":"little-endian packed bitfields, unscaled channels; respects stride; not palette/FOURCC conversion"});
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{engine, image};
    use super::*;
    use serde_json::json;
    fn put(b: &mut [u8], at: usize, value: u64, size: usize) {
        b[at..at + size].copy_from_slice(&value.to_le_bytes()[..size]);
    }
    fn fixture() -> (Vec<u8>, Isf) {
        let (mut bytes, mut isf) = super::super::tests::fixture();
        isf.data["base_types"]["u32"] = json!({"size":4});
        let field = |offset, name| json!({"offset":offset,"type":{"kind":"base","name":name}});
        let structure =
            |offset, name| json!({"offset":offset,"type":{"kind":"struct","name":name}});
        let pointer = |offset| json!({"offset":offset,"type":{"kind":"pointer"}});
        isf.data["symbols"]["num_registered_fb"] = json!({"address":0x30000});
        isf.data["symbols"]["registered_fb"] = json!({"address":0x30008});
        isf.data["user_types"]["fb_info"] = json!({"size":120,"fields":{
            "fix":structure(0,"fb_fix_screeninfo"),"var":structure(32,"fb_var_screeninfo"),
            "screen_base":pointer(96),"state":field(104,"u32"),"dev":pointer(112)}});
        isf.data["user_types"]["fb_fix_screeninfo"] = json!({"size":24,"fields":{
            "id":{"offset":0,"type":{"kind":"array","count":16,"subtype":{"kind":"base","name":"char"}}},"line_length":field(16,"u32")}});
        isf.data["user_types"]["fb_var_screeninfo"] = json!({"size":64,"fields":{
            "xres_virtual":field(0,"u32"),"yres_virtual":field(4,"u32"),"bits_per_pixel":field(8,"u32"),"grayscale":field(12,"u32"),
            "red":structure(16,"fb_bitfield"),"green":structure(28,"fb_bitfield"),"blue":structure(40,"fb_bitfield"),"transp":structure(52,"fb_bitfield")}});
        isf.data["user_types"]["fb_bitfield"] = json!({"size":12,"fields":{"offset":field(0,"u32"),"length":field(4,"u32"),"msb_right":field(8,"u32")}});
        isf.data["user_types"]["device"] =
            json!({"size":8,"fields":{"kobj":structure(0,"kobject")}});
        isf.data["user_types"]["kobject"] = json!({"size":8,"fields":{"name":pointer(0)}});
        put(&mut bytes, 0x30000, 2, 4);
        for (i, object, pixels, dev, name) in [
            (0, 0x31000, 0x32000, 0x34000, 0x34200),
            (1, 0x31100, 0x33000, 0x34100, 0x34300),
        ] {
            bytes[object..object + 120].fill(0);
            let id = if i == 0 {
                b"test".as_slice()
            } else {
                b"fourcc".as_slice()
            };
            bytes[object..object + id.len()].copy_from_slice(id);
            put(&mut bytes, 0x30008 + i * 8, object as u64, 8);
            for (offset, value) in [
                (16, if i == 0 { 6 } else { 8 }),
                (32, 2),
                (36, 2),
                (40, 16),
                (44, if i == 0 { 0 } else { 0x3231564e }),
                (48, 11),
                (52, 5),
                (60, 5),
                (64, 6),
                (72, 0),
                (76, 5),
                (104, i as u64),
            ] {
                put(&mut bytes, object + offset, value, 4);
            }
            put(&mut bytes, object + 96, pixels as u64, 8);
            put(&mut bytes, object + 112, dev as u64, 8);
            put(&mut bytes, dev, name as u64, 8);
            bytes[name..name + 5].copy_from_slice(b"fbdev");
            bytes[name + 5] = 0;
        }
        bytes[0x32000..0x3200c].copy_from_slice(&[
            0, 0xf8, 0xe0, 7, 0xaa, 0xbb, 0x1f, 0, 0xff, 0xff, 0xcc, 0xdd,
        ]);
        bytes[0x33000..0x33010].copy_from_slice(b"raw-fourcc-bytes");
        (bytes, isf)
    }
    #[test]
    fn eight_fields_optional_exports_strided_png_raw_hashes_and_no_clobber() {
        let (bytes, isf) = fixture();
        let image = image(&bytes);
        let linux = engine(&image, &isf);
        let job = Job::default();
        let result = linux.fbdev(None, &job).unwrap();
        assert!(result.complete, "{:?}", result.diagnostics);
        assert_eq!(
            result.rows[0],
            [
                "0x0000000000032000",
                "fbdev",
                "test",
                "12",
                "2x2",
                "16",
                "RUNNING",
                "Disabled"
            ]
        );
        assert_eq!(result.rows[1][6], "SUSPENDED");
        let dir = tempfile::tempdir().unwrap();
        let options = DumpOptions {
            pid: 0,
            directory: dir.path().into(),
            start: None,
            end: None,
        };
        let result = linux.fbdev(Some(&options), &job).unwrap();
        assert!(result.complete, "{:?}", result.diagnostics);
        let png = std::fs::read(dir.path().join("test_2x2_16bpp.png")).unwrap();
        assert!(png.starts_with(b"\x89PNG\r\n\x1a\n"));
        assert_eq!(
            std::fs::read(dir.path().join("fourcc_2x2_16bpp.raw")).unwrap(),
            b"raw-fourcc-bytes"
        );
        use sha2::{Digest, Sha256};
        for frame in result.kernel_identity["fbdev"]["frames"]
            .as_array()
            .unwrap()
        {
            let a = &frame["artifact"];
            let data = std::fs::read(a["path"].as_str().unwrap()).unwrap();
            assert_eq!(a["sha256"], format!("{:x}", Sha256::digest(&data)));
            assert_eq!(a["bytes"], data.len());
        }
        let again = linux.fbdev(Some(&options), &job).unwrap();
        assert!(!again.complete);
        assert!(again.rows.iter().all(|r| r[7] == "N/A"));
        assert_eq!(
            std::fs::read(dir.path().join("test_2x2_16bpp.png")).unwrap(),
            png
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
    }
    #[test]
    fn holes_bad_devices_and_selection_preserve_independent_frames_without_zero_filling() {
        let (mut bytes, isf) = fixture();
        put(&mut bytes, 0x31060, 0x3fffc, 8);
        put(&mut bytes, 0x31070, 0, 8);
        let image = image(&bytes);
        let linux = engine(&image, &isf);
        let dir = tempfile::tempdir().unwrap();
        let mut options = DumpOptions {
            pid: 0,
            directory: dir.path().into(),
            start: None,
            end: None,
        };
        let job = Job::default();
        let result = linux.fbdev(Some(&options), &job).unwrap();
        assert!(!result.complete);
        assert_eq!(result.rows.len(), 2);
        assert_eq!(result.rows[0][1], "N/A");
        assert_eq!(result.rows[0][7], "N/A");
        assert_ne!(result.rows[1][7], "N/A");
        assert!(!dir.path().join("test_2x2_16bpp.png").exists());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        options.start = Some(0xdead);
        let result = linux.fbdev(Some(&options), &job).unwrap();
        assert!(!result.complete);
        assert!(result.rows.is_empty());
        options.start = Some(0x31000);
        let result = linux.fbdev(Some(&options), &job).unwrap();
        assert_eq!(result.rows.len(), 1);
        job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(linux.fbdev(None, &job).is_err());
    }
    #[test]
    fn absent_registry_negative_count_and_null_slots_are_not_complete_empty_results() {
        let (mut bytes, mut isf) = fixture();
        put(&mut bytes, 0x30000, u32::MAX as u64, 4);
        let img = image(&bytes);
        assert!(
            !engine(&img, &isf)
                .fbdev(None, &Job::default())
                .unwrap()
                .complete
        );
        put(&mut bytes, 0x30000, 2, 4);
        put(&mut bytes, 0x30008, 0, 8);
        let img = image(&bytes);
        let result = engine(&img, &isf).fbdev(None, &Job::default()).unwrap();
        assert!(!result.complete);
        assert_eq!(result.rows.len(), 1);
        isf.data["symbols"]
            .as_object_mut()
            .unwrap()
            .remove("num_registered_fb");
        assert!(
            !engine(&img, &isf)
                .fbdev(None, &Job::default())
                .unwrap()
                .complete
        );
        let (mut bytes, isf) = fixture();
        put(&mut bytes, 0x30000, 0, 4);
        let img = image(&bytes);
        let result = engine(&img, &isf).fbdev(None, &Job::default()).unwrap();
        assert!(result.complete);
        assert!(result.rows.is_empty());
    }
    #[test]
    #[ignore = "requires pinned Volatility and a test-only Python with Pillow"]
    fn native_pixels_and_raw_match_reference_functions_and_padding_difference_is_preserved() {
        let python = std::env::var("ZERO_REFERENCE_PYTHON").expect("set ZERO_REFERENCE_PYTHON");
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let output = tempfile::tempdir().unwrap();
        let mut cases = Vec::new();
        for variant in ["rgb565", "padded-rgb565", "rgba8", "wide64"] {
            let (mut bytes, isf) = fixture();
            if variant == "rgb565" {
                put(&mut bytes, 0x31010, 4, 4);
                bytes[0x32000..0x32008].copy_from_slice(&[0, 0xf8, 0xe0, 7, 0x1f, 0, 0xff, 0xff]);
            } else if variant == "rgba8" || variant == "wide64" {
                let bits = if variant == "rgba8" { 8 } else { 16 };
                put(&mut bytes, 0x31010, bits, 4);
                put(&mut bytes, 0x31028, bits * 4, 4);
                for i in 0..4 {
                    put(&mut bytes, 0x31030 + i * 12, i as u64 * bits, 4);
                    put(&mut bytes, 0x31034 + i * 12, bits, 4);
                    put(&mut bytes, 0x31038 + i * 12, u64::from(i == 2), 4);
                }
                for i in 0..bits as usize * 4 {
                    bytes[0x32000 + i] = (i * 37 + 11) as u8;
                }
            }
            let image = image(&bytes);
            let linux = engine(&image, &isf);
            let dir = output.path().join(variant);
            std::fs::create_dir(&dir).unwrap();
            let result = linux
                .fbdev(
                    Some(&DumpOptions {
                        pid: 0,
                        directory: dir.clone(),
                        start: None,
                        end: None,
                    }),
                    &Job::default(),
                )
                .unwrap();
            assert!(result.complete, "{:?}", result.diagnostics);
            let fb = linux.framebuffer(0x31000).unwrap();
            let layout = linux.framebuffer_layout(&fb).unwrap();
            let raw = dir.join("source.bin");
            std::fs::write(&raw, &bytes[0x32000..0x32000 + fb.size as usize]).unwrap();
            cases.push(json!({"id":variant,"format":"PNG","raw":raw,"native":dir.join(&result.rows[0][7]),"width":fb.width,"height":fb.height,"stride":fb.stride,"bpp":fb.bpp,"channels":layout.channels.map(|c| (c.offset,c.length,c.msb_right)),"expect_equal":variant!="padded-rgb565"}));
            let raw = dir.join("fourcc-source.bin");
            std::fs::write(&raw, &bytes[0x33000..0x33010]).unwrap();
            cases.push(json!({"id":format!("{variant}/fourcc"),"format":"RAW","raw":raw,"native":dir.join(&result.rows[1][7]),"width":2,"height":2,"stride":8,"bpp":16,"channels":vec![(0,0,false);4],"expect_equal":true}));
        }
        let manifest = output.path().join("cases.json");
        std::fs::write(&manifest, serde_json::to_vec(&cases).unwrap()).unwrap();
        let run = std::process::Command::new(python)
            .arg(root.join("tests/reference/parity/fbdev_pixels.py"))
            .arg(root.join("target/reference/volatility3"))
            .arg(manifest)
            .output()
            .unwrap();
        assert!(
            run.status.success(),
            "{}",
            String::from_utf8_lossy(&run.stderr)
        );
        println!("{}", String::from_utf8_lossy(&run.stdout));
    }
}
