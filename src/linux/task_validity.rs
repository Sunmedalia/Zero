//! Pinned task_struct validity and directional list selection for standard plugins.
use super::*;

fn reference_comm(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .take_while(|ch| !matches!(ch, '\0' | '\u{fffd}'))
        .collect()
}

impl Linux<'_> {
    fn task_span_readable(&self, address: u64, size: u64) -> Result<bool> {
        ensure!(size <= 1024 * 1024, "任务目标结构超过读取上限");
        Ok(self
            .vm
            .read(address, &mut vec![0; size.max(1) as usize])
            .is_ok())
    }

    fn task_pointer(&self, task: u64, field: &str) -> Result<(u64, bool)> {
        let value = self.number(task, "task_struct", field)?;
        if value == 0 {
            return Ok((0, false));
        }
        let ty = &self.isf.field("task_struct", field)?["type"];
        ensure!(ty["kind"] == "pointer", "task_struct.{field} 不是指针");
        let size = self.isf.type_size(&ty["subtype"])?;
        Ok((value, self.task_span_readable(value, size)?))
    }

    fn task_id_negative(&self, task: u64, field: &str) -> Result<bool> {
        let value = self.number(task, "task_struct", field)?;
        let ty = &self.isf.field("task_struct", field)?["type"];
        let signed = ty["kind"] == "base"
            && ty["name"]
                .as_str()
                .is_some_and(|name| self.isf.data["base_types"][name]["signed"] == true);
        let size = self.isf.size("task_struct", field)?;
        ensure!(matches!(size, 1 | 2 | 4 | 8), "任务 ID 宽度无效");
        Ok(signed && value & (1 << (size * 8 - 1)) != 0)
    }

    pub(super) fn reference_task_valid(&self, task: u64) -> Result<bool> {
        let size = self.isf.data["user_types"]["task_struct"]["size"]
            .as_u64()
            .context("task_struct 缺少大小")?;
        if !self.task_span_readable(task, size)?
            || self.task_id_negative(task, "pid")?
            || self.task_id_negative(task, "tgid")?
        {
            return Ok(false);
        }
        for field in ["signal", "nsproxy", "real_parent"] {
            if self.isf.field("task_struct", field).is_ok() && !self.task_pointer(task, field)?.1 {
                return Ok(false);
            }
        }
        if self.isf.field("task_struct", "active_mm").is_ok() {
            let (active, readable) = self.task_pointer(task, "active_mm")?;
            if active != 0 && !readable {
                return Ok(false);
            }
        }
        let (mm, readable) = self.task_pointer(task, "mm")?;
        if mm != 0 && (!readable || mm != self.number(task, "task_struct", "active_mm")?) {
            return Ok(false);
        }
        Ok(true)
    }

    pub(super) fn reference_process_rows(&self, plugin: Plugin, job: &Job) -> Result<Results> {
        let offset = self.isf.offset("task_struct", "tasks")?;
        let head = self.field_address(self.isf.address("init_task")?, "task_struct", "tasks")?;
        let link_size = self.isf.data["user_types"]["list_head"]["size"]
            .as_u64()
            .context("list_head 缺少大小")?;
        let mut result = self.result(plugin);
        let mut seen = HashSet::new();
        for direction in ["next", "prev"] {
            job.check()?;
            if !self.task_span_readable(head, 1)? {
                continue;
            }
            let mut link = self.number(head, "list_head", direction)?;
            if link == 0 || !self.task_span_readable(link, link_size)? {
                continue;
            }
            let mut direction_seen = HashSet::from([head]);
            while !direction_seen.contains(&link) {
                job.check()?;
                ensure!(direction_seen.len() <= LIMIT, "任务链表达到遍历上限");
                let Some(task) = link.checked_sub(offset) else {
                    break;
                };
                if !self.task_span_readable(task, 1)? {
                    break;
                }
                if seen.insert(task) && self.reference_task_valid(task)? {
                    let size = self.isf.size("task_struct", "comm")?;
                    ensure!((1..=256).contains(&size), "任务名称超过读取上限");
                    let mut name = vec![0; size];
                    self.vm
                        .read(self.field_address(task, "task_struct", "comm")?, &mut name)?;
                    result.rows.push(vec![
                        self.number(task, "task_struct", "pid")?.to_string(),
                        self.number(task, "task_struct", "tgid")?.to_string(),
                        "0".into(),
                        reference_comm(&name),
                        hex(task),
                    ]);
                }
                direction_seen.insert(link);
                let next = self.number(link, "list_head", direction)?;
                if next == 0 || !self.task_span_readable(next, link_size)? {
                    break;
                }
                link = next;
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::tests::{engine, fixture, image};
    use serde_json::{Value, json};

    fn materialize(case: &Value) -> (Image, Isf) {
        let (mut bytes, mut isf) = fixture();
        bytes.truncate(0x20000);
        let width = case["pointer_width"].as_u64().unwrap();
        isf.data["base_types"]["pointer"]["size"] = json!(width);
        isf.data["base_types"]["i32"] = json!({"size":4,"signed":true});
        isf.data["base_types"]["u32"]["signed"] = json!(false);
        isf.data["user_types"]["task_struct"] = json!({"size":256,"fields":{}});
        for (name, size) in [("signal_struct", 32), ("nsproxy", 24), ("mm_struct", 128)] {
            isf.data["user_types"][name] = json!({"size":size,"fields":{}});
        }
        for (name, offset, target) in [
            ("real_parent", 24, "task_struct"),
            ("signal", 32, "signal_struct"),
            ("nsproxy", 40, "nsproxy"),
            ("active_mm", 48, "mm_struct"),
            ("mm", 56, "mm_struct"),
        ] {
            isf.data["user_types"]["task_struct"]["fields"][name] = json!({"offset":offset,"type":{"kind":"pointer","subtype":{"kind":"struct","name":target}}});
        }
        for (field, offset) in [("pid", 16), ("tgid", 20)] {
            isf.data["user_types"]["task_struct"]["fields"][field] = json!({"offset":offset,"type":{"kind":"base","name":if case["signed"]==false {"u32"} else {"i32"}}});
        }
        isf.data["user_types"]["task_struct"]["fields"]["comm"] = json!({"offset":64,"type":{"kind":"array","count":16,"subtype":{"kind":"base","name":"char"}}});
        isf.data["user_types"]["task_struct"]["fields"]["tasks"] = json!({"offset":case["task_offset"].as_u64().unwrap_or(80),"type":{"kind":"struct","name":"list_head"}});
        for name in case["omit"].as_array().into_iter().flatten() {
            isf.data["user_types"]["task_struct"]["fields"]
                .as_object_mut()
                .unwrap()
                .remove(name.as_str().unwrap());
        }
        for write in case["writes"].as_array().unwrap() {
            let at = write[0].as_u64().unwrap() as usize;
            for (index, pair) in write[1]
                .as_str()
                .unwrap()
                .as_bytes()
                .chunks_exact(2)
                .enumerate()
            {
                bytes[at + index] =
                    u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
            }
        }
        isf.invalidate_layouts();
        let mut image = image(&bytes);
        if let Some(holes) = case["holes"].as_array() {
            image.segments.clear();
            let mut start = 0;
            for hole in holes {
                let end = hole[0].as_u64().unwrap();
                if end > start {
                    image.segments.push(crate::image::Segment {
                        start,
                        end,
                        file_offset: start,
                    });
                }
                start = hole[1].as_u64().unwrap();
            }
            if start < bytes.len() as u64 {
                image.segments.push(crate::image::Segment {
                    start,
                    end: bytes.len() as u64,
                    file_offset: start,
                });
            }
        }
        (image, isf)
    }

    #[test]
    fn complete_task_validity_matches_fixed_extension() {
        let vectors: Value = serde_json::from_str(include_str!(
            "../../tests/reference/parity/fixtures/task-validity.json"
        ))
        .unwrap();
        for case in vectors["validity"].as_array().unwrap() {
            let (image, isf) = materialize(case);
            let actual = engine(&image, &isf).reference_task_valid(0xa000);
            if case.get("error").is_some() {
                assert!(actual.is_err(), "{}", case["id"]);
            } else {
                assert_eq!(
                    actual.unwrap(),
                    case["expected"].as_bool().unwrap(),
                    "{} width {}",
                    case["id"],
                    case["pointer_width"]
                );
            }
        }
    }

    #[test]
    fn selected_task_order_and_names_match_fixed_iterators() {
        let vectors: Value = serde_json::from_str(include_str!(
            "../../tests/reference/parity/fixtures/task-validity.json"
        ))
        .unwrap();
        for case in vectors["walks"].as_array().unwrap() {
            let (image, isf) = materialize(case);
            let linux = engine(&image, &isf);
            let actual = linux.reference_process_rows(Plugin::Pslist, &Job::default());
            if case.get("error").is_some() {
                assert!(actual.is_err(), "{}", case["id"]);
                continue;
            }
            let actual = actual.unwrap();
            assert!(actual.complete, "{}", case["id"]);
            let pids: HashSet<_> = case["pids"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|p| p.as_u64().unwrap())
                .collect();
            let rows: Vec<_> = actual
                .rows
                .iter()
                .filter(|row| pids.is_empty() || pids.contains(&row[0].parse::<u64>().unwrap()))
                .map(|row| {
                    json!([
                        u64::from_str_radix(&row[4][2..], 16).unwrap(),
                        row[0].parse::<u64>().unwrap(),
                        row[1].parse::<u64>().unwrap(),
                        row[3]
                    ])
                })
                .collect();
            assert_eq!(json!(rows), case["expected"], "{}", case["id"]);
            if case["id"] == "task-tail-hole" {
                let legacy = linux.process_list(Plugin::Pslist, &Job::default()).unwrap();
                assert!(legacy.rows.iter().any(|row| row[4] == hex(0xa000)));
            }
            let job = Job::default();
            job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
            assert!(linux.reference_process_rows(Plugin::Pslist, &job).is_err());
        }
    }
}
