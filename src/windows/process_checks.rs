//! Process image provenance (ghosting / delete-pending images) and job
//! object membership.
use super::*;

impl Windows<'_> {
    /// windows.processghosting: processes whose image file object is
    /// delete-pending or backs no section, as process ghosting leaves it.
    pub(super) fn processghosting(&self, p: &Process, r: &mut Results) -> Result<()> {
        let file = self.number(p.address, "_EPROCESS", "ImageFilePointer")?;
        if file == 0 {
            // System, Registry and MemCompression have no image file.
            return Ok(());
        }
        ensure!(self.vm.kernel(file), "无效 ImageFilePointer");
        // A stale pointer can land on reused pool; require a File object.
        if let Ok(body) = self.vm.isf.offset("_OBJECT_HEADER", "Body") {
            let header = file.checked_sub(body).context("对象头下溢")?;
            let kind = self.object_type(header, &self.object_header_layout())?;
            ensure!(
                kind == "File",
                "ImageFilePointer 指向 {kind} 对象，不是 File"
            );
        }
        let pending = self.number(file, "_FILE_OBJECT", "DeletePending")? != 0;
        let pointers = self.number(file, "_FILE_OBJECT", "SectionObjectPointer")?;
        let (data, image) = if pointers == 0 {
            (0, 0)
        } else {
            (
                self.number(pointers, "_SECTION_OBJECT_POINTERS", "DataSectionObject")?,
                self.number(pointers, "_SECTION_OBJECT_POINTERS", "ImageSectionObject")?,
            )
        };
        let mut reasons = Vec::new();
        if pending {
            reasons.push("DeletePending");
        }
        if data == 0 && image == 0 {
            reasons.push("NoSectionObjects");
        }
        if reasons.is_empty() {
            return Ok(());
        }
        let path = self
            .field(file, "_FILE_OBJECT", "FileName")
            .and_then(|name| self.vm.unicode(name))
            .unwrap_or_default();
        r.rows.push(vec![
            p.pid.to_string(),
            p.name.clone(),
            hex(file),
            pending.to_string(),
            hex(data),
            hex(image),
            path,
            reasons.join(","),
        ]);
        Ok(())
    }
    /// windows.joblinks: the job object each process belongs to.
    pub(super) fn joblink(&self, p: &Process, r: &mut Results) -> Result<()> {
        let job = self.number(p.address, "_EPROCESS", "Job")?;
        if job == 0 {
            return Ok(());
        }
        ensure!(self.vm.kernel(job), "无效 Job 指针");
        let session = if self.vm.isf.field("_EJOB", "SessionId").is_ok() {
            self.number(job, "_EJOB", "SessionId")?.to_string()
        } else {
            String::new()
        };
        r.rows.push(vec![
            hex(job),
            session,
            self.number(job, "_EJOB", "ActiveProcesses")?.to_string(),
            self.number(job, "_EJOB", "TotalProcesses")?.to_string(),
            p.pid.to_string(),
            p.name.clone(),
        ]);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{K, fixture, image, put};
    use super::*;
    use serde_json::json;
    fn field(offset: u64, ty: &str) -> serde_json::Value {
        json!({"offset":offset,"type":{"kind":"base","name":ty}})
    }
    fn prepare() -> (Vec<u8>, Isf) {
        let (b, mut isf) = fixture();
        isf.data["base_types"]["u32"] = json!({"size":4});
        isf.data["base_types"]["u8"] = json!({"size":1});
        let eprocess = &mut isf.data["user_types"]["_EPROCESS"]["fields"];
        eprocess["ImageFilePointer"] = field(144, "pointer");
        eprocess["Job"] = field(152, "pointer");
        isf.data["user_types"]["_FILE_OBJECT"] = json!({"size":64,"fields":{
            "DeletePending":field(8,"u8"),"SectionObjectPointer":field(16,"pointer"),
            "FileName":{"offset":24,"type":{"kind":"struct","name":"_UNICODE_STRING"}},
        }});
        isf.data["user_types"]["_SECTION_OBJECT_POINTERS"] = json!({"size":24,"fields":{
            "DataSectionObject":field(0,"pointer"),"ImageSectionObject":field(8,"pointer"),
        }});
        isf.data["user_types"]["_EJOB"] = json!({"size":32,"fields":{
            "ActiveProcesses":field(0,"u32"),"TotalProcesses":field(4,"u32"),"SessionId":field(8,"u32"),
        }});
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
    fn ghosted_images_are_flagged_and_normal_images_skipped() {
        let (mut b, isf) = prepare();
        // System (K+0x1000) has no image; child (K+0x2000) maps a delete-
        // pending file object at K+0x4000 that backs no sections.
        put(&mut b, 0xa000 + 144, K + 0x4000);
        b[0xc008] = 1;
        put(&mut b, 0xc010, K + 0x4100);
        let img = image(&b);
        let r = engine(&img, &isf)
            .run(
                Plugin::WinProcessghosting,
                &Options::default(),
                &Job::default(),
            )
            .unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(r.rows.len(), 1);
        assert_eq!(&r.rows[0][..4], ["8", "child", &hex(K + 0x4000), "true"]);
        assert_eq!(r.rows[0][7], "DeletePending,NoSectionObjects");
        // A normal image (not pending, image section present) is not reported.
        b[0xc008] = 0;
        put(&mut b, 0xc108, K + 0x5000);
        let img = image(&b);
        let r = engine(&img, &isf)
            .run(
                Plugin::WinProcessghosting,
                &Options::default(),
                &Job::default(),
            )
            .unwrap();
        assert!(r.rows.is_empty());
    }
    #[test]
    fn job_members_report_counts_and_session() {
        let (mut b, isf) = prepare();
        put(&mut b, 0xa000 + 152, K + 0x6000);
        b[0xe000..0xe004].copy_from_slice(&1u32.to_le_bytes());
        b[0xe004..0xe008].copy_from_slice(&3u32.to_le_bytes());
        b[0xe008..0xe00c].copy_from_slice(&2u32.to_le_bytes());
        let img = image(&b);
        let r = engine(&img, &isf)
            .run(Plugin::WinJoblinks, &Options::default(), &Job::default())
            .unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(
            r.rows,
            [[
                hex(K + 0x6000),
                "2".into(),
                "1".into(),
                "3".into(),
                "8".into(),
                "child".into()
            ]
            .to_vec()]
        );
    }
}
