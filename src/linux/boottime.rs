//! Kernel boot timestamps and the time namespace view used by Boottime.
use super::*;

impl Linux<'_> {
    fn time_field_type<'b>(&'b self, ty: &str, field: &str) -> Result<&'b str> {
        self.isf.field(ty, field)?["type"]["name"]
            .as_str()
            .context("时间字段缺少类型名")
    }

    fn signed_time_field(&self, at: u64, ty: &str, field: &str) -> Result<i128> {
        let layout = self.isf.layout(ty, field)?;
        ensure!(matches!(layout.size, 1 | 2 | 4 | 8), "时间字段宽度无效");
        let value = self.number(at, ty, field)?;
        let shift = 64 - layout.size * 8;
        Ok(((value << shift) as i64 >> shift) as i128)
    }

    fn timespec_nanos(&self, at: u64, ty: &str) -> Result<i128> {
        Ok(self.signed_time_field(at, ty, "tv_sec")? * 1_000_000_000
            + self.signed_time_field(at, ty, "tv_nsec")?)
    }

    fn symbol_time_type(&self, name: &str, fallback: &str) -> String {
        self.isf.data["symbols"][name]["type"]["name"]
            .as_str()
            .unwrap_or(fallback)
            .to_owned()
    }

    pub(super) fn root_boot_time_nanos(&self) -> Result<i128> {
        if self.isf.data["symbols"].get("tk_core").is_some() {
            let core = self.isf.address("tk_core")?;
            let core_type = self.symbol_time_type("tk_core", "tk_core");
            let keeper = self.field_address(core, &core_type, "timekeeper")?;
            let keeper_type = self.time_field_type(&core_type, "timekeeper")?;
            let ktime = |field| -> Result<i128> {
                let ty = self.time_field_type(keeper_type, field)?;
                if self.isf.field(ty, "tv64").is_ok() {
                    self.signed_time_field(
                        self.field_address(keeper, keeper_type, field)?,
                        ty,
                        "tv64",
                    )
                } else {
                    self.signed_time_field(keeper, keeper_type, field)
                }
            };
            return Ok(ktime("offs_real")? - ktime("offs_boot")?);
        }
        if self.isf.data["symbols"].get("timekeeper").is_some()
            && self.isf.field("timekeeper", "wall_to_monotonic").is_ok()
        {
            let keeper = self.isf.address("timekeeper")?;
            let read = |field| {
                self.timespec_nanos(
                    self.field_address(keeper, "timekeeper", field)?,
                    self.time_field_type("timekeeper", field)?,
                )
            };
            return Ok(-(read("wall_to_monotonic")? + read("total_sleep_time")?));
        }
        let wall = self
            .isf
            .address("wall_to_monotonic")
            .context("不支持: 缺少内核启动时间符号")?;
        let mut total = self.timespec_nanos(
            wall,
            &self.symbol_time_type("wall_to_monotonic", "timespec"),
        )?;
        if self.isf.data["symbols"].get("total_sleep_time").is_some() {
            let at = self.isf.address("total_sleep_time")?;
            let ty = self.symbol_time_type("total_sleep_time", "timespec");
            total += if ty == "timespec" {
                self.timespec_nanos(at, &ty)?
            } else {
                let size = self.isf.data["base_types"][&ty]["size"]
                    .as_u64()
                    .context("total_sleep_time 缺少标量宽度")?;
                self.vm.uint(at, usize::try_from(size)?)? as i128 * 1_000_000_000
            };
        }
        Ok(-total)
    }

    fn task_time_namespace(&self, task: u64) -> Result<Option<u64>> {
        if self.isf.field("task_struct", "nsproxy").is_err()
            || self.isf.field("nsproxy", "time_ns").is_err()
        {
            return Ok(None);
        }
        let proxy = self.number(task, "task_struct", "nsproxy")?;
        let namespace = self.number(proxy, "nsproxy", "time_ns")?;
        Ok((namespace != 0).then_some(namespace))
    }

    pub(super) fn namespace_boottimes(&self, job: &Job) -> Result<Results> {
        let (result, tasks) = self.tasks(Plugin::LinuxBoottime, job)?;
        self.namespace_boottimes_tasks(job, result, tasks)
    }
    fn namespace_boottimes_tasks(
        &self,
        job: &Job,
        mut result: Results,
        tasks: Vec<Task>,
    ) -> Result<Results> {
        let mut seen = HashSet::new();
        let mut timeline = Vec::new();
        for task in tasks {
            job.check()?;
            let namespace = self.task_time_namespace(task.address)?;
            let id = namespace
                .map(|at| -> Result<u64> {
                    let ns = self.field_address(at, "time_namespace", "ns")?;
                    self.number(ns, "ns_common", "inum")
                })
                .transpose()?;
            if !seen.insert(id) {
                continue;
            }
            let mut nanos = self.root_boot_time_nanos()?;
            if self.isf.data["symbols"].get("tk_core").is_some() {
                nanos = reference_ktime_nanos(nanos);
            }
            if let Some(at) = namespace
                && self.isf.field("time_namespace", "offsets").is_ok()
            {
                let offsets = self.field_address(at, "time_namespace", "offsets")?;
                let ty = self.time_field_type("time_namespace", "offsets")?;
                nanos -= self.timespec_nanos(
                    self.field_address(offsets, ty, "boottime")?,
                    self.time_field_type(ty, "boottime")?,
                )?;
            }
            let timestamp = boot_datetime(nanos).unwrap_or_else(|| "N/A".into());
            timeline.push(serde_json::json!({
                "description": format!("System boot time for time namespace {}",
                    id.map_or_else(|| "None".into(), |value| value.to_string())),
                "event_type": "CREATED",
                "timestamp": timestamp,
            }));
            result.rows.push(vec![
                id.filter(|id| *id != 0)
                    .map_or_else(|| "N/A".into(), |id| id.to_string()),
                timestamp,
            ]);
        }
        result.kernel_identity["boottime_timeline"] = serde_json::json!(timeline);
        Ok(result)
    }
}

/// Timespec64Concrete.new_from_nsec divides by the floating-point NSEC_PER_SEC.
/// Match its integer-to-float conversion and CPython's float divmod sequence.
fn reference_ktime_nanos(nanos: i128) -> i128 {
    if nanos == 0 {
        return 0;
    }
    let value = if nanos < 0 { -nanos - 1 } else { nanos } as f64;
    let remainder = value % 1_000_000_000.0;
    let div = (value - remainder) / 1_000_000_000.0;
    let mut quotient = div.floor();
    if div - quotient > 0.5 {
        quotient += 1.0;
    }
    let positive = quotient as i128 * 1_000_000_000 + remainder as i128;
    if nanos < 0 { -positive - 1 } else { positive }
}

/// Match datetime.fromtimestamp on the reference's floating-point timespec sum.
fn boot_datetime(nanos: i128) -> Option<String> {
    let time = nanos.div_euclid(1_000_000_000) as f64
        + nanos.rem_euclid(1_000_000_000) as f64 / 1_000_000_000.0;
    if time <= 0.0 || !time.is_finite() {
        return None;
    }
    let mut seconds = time.floor() as i64;
    let mut micros = ((time - time.floor()) * 1_000_000.0).round_ties_even() as i64;
    if micros == 1_000_000 {
        seconds = seconds.checked_add(1)?;
        micros = 0;
    }
    if !(0..=253_402_300_799).contains(&seconds) {
        return None;
    }
    let date = crate::report::utc(seconds).replace(' ', "T");
    let date = date.strip_suffix("TUTC")?;
    Some(if micros == 0 {
        format!("{date}+00:00")
    } else {
        format!("{date}.{micros:06}+00:00")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::tests::{engine, fixture, image};
    use serde_json::{Value, json};

    fn put(bytes: &mut [u8], at: u64, value: i128) {
        bytes[at as usize..at as usize + 8].copy_from_slice(&(value as u64).to_le_bytes());
    }
    fn fields(data: &mut Value, name: &str, entries: &[(&str, u64, &str)]) {
        data["user_types"][name] = json!({"size":0,"fields":{}});
        let mut size = 0;
        for &(field, offset, ty) in entries {
            let field_size = data["base_types"][ty]["size"]
                .as_u64()
                .or_else(|| data["user_types"][ty]["size"].as_u64())
                .unwrap();
            size = size.max(offset + field_size);
            let kind = if matches!(ty, "i64" | "u64") {
                "base"
            } else {
                "struct"
            };
            data["user_types"][name]["fields"][field] =
                json!({"offset":offset,"type":{"kind":kind,"name":ty}});
        }
        data["user_types"][name]["size"] = json!(size);
    }
    fn timespec(bytes: &mut [u8], at: u64, nanos: i128) {
        put(bytes, at, nanos.div_euclid(1_000_000_000));
        put(bytes, at + 8, nanos.rem_euclid(1_000_000_000));
    }

    #[test]
    fn timekeeping_and_namespace_rows_match_pinned_methods() {
        let vectors: Value = serde_json::from_str(include_str!(
            "../../tests/reference/parity/fixtures/boottime.json"
        ))
        .unwrap();
        for case in vectors["cases"].as_array().unwrap() {
            let (mut bytes, mut isf) = fixture();
            isf.data["base_types"]["i64"] = json!({"size":8,"signed":true});
            fields(
                &mut isf.data,
                "timespec",
                &[("tv_sec", 0, "i64"), ("tv_nsec", 8, "i64")],
            );
            let root = case["root"].as_str().unwrap().parse::<i128>().unwrap();
            let kind = case["kind"].as_str().unwrap();
            let symbol = |data: &mut Value, name: &str, address, ty: &str| {
                data["symbols"][name] =
                    json!({"address":address,"type":{"kind":"struct","name":ty}});
            };
            match kind {
                "modern" | "wrapped" => {
                    let ty = if kind == "wrapped" { "ktime_t" } else { "i64" };
                    fields(&mut isf.data, "ktime_t", &[("tv64", 0, "i64")]);
                    fields(
                        &mut isf.data,
                        "timekeeper",
                        &[("offs_real", 0, ty), ("offs_boot", 8, ty)],
                    );
                    fields(
                        &mut isf.data,
                        "exact_anonymous_core",
                        &[("timekeeper", 8, "timekeeper")],
                    );
                    symbol(&mut isf.data, "tk_core", 0x10000, "exact_anonymous_core");
                    put(&mut bytes, 0x10008, root + 123_000_000_000);
                    put(&mut bytes, 0x10010, 123_000_000_000);
                }
                "global-timekeeper" => {
                    fields(
                        &mut isf.data,
                        "timekeeper",
                        &[
                            ("wall_to_monotonic", 0, "timespec"),
                            ("total_sleep_time", 16, "timespec"),
                        ],
                    );
                    symbol(&mut isf.data, "timekeeper", 0x10000, "timekeeper");
                    timespec(&mut bytes, 0x10000, -root - 10_000_000_000);
                    timespec(&mut bytes, 0x10010, 10_000_000_000);
                }
                "wall-timespec" | "wall-scalar" | "wall-only" => {
                    let sleep = if kind == "wall-only" {
                        0
                    } else {
                        10_000_000_000
                    };
                    symbol(&mut isf.data, "wall_to_monotonic", 0x10000, "timespec");
                    timespec(&mut bytes, 0x10000, -root - sleep);
                    if kind == "wall-timespec" {
                        symbol(&mut isf.data, "total_sleep_time", 0x10020, "timespec");
                        timespec(&mut bytes, 0x10020, sleep);
                    } else if kind == "wall-scalar" {
                        symbol(&mut isf.data, "total_sleep_time", 0x10020, "u64");
                        put(&mut bytes, 0x10020, 10);
                    }
                }
                "unsupported" => (),
                _ => panic!("unknown fixture kind"),
            }
            isf.data["user_types"]["task_struct"]["fields"]["nsproxy"] =
                json!({"offset":112,"type":{"kind":"pointer"}});
            fields(&mut isf.data, "nsproxy", &[("time_ns", 0, "u64")]);
            match case["namespace_layout"].as_str() {
                Some("no-proxy") => {
                    isf.data["user_types"]["task_struct"]["fields"]
                        .as_object_mut()
                        .unwrap()
                        .remove("nsproxy");
                }
                Some("no-time") => fields(&mut isf.data, "nsproxy", &[]),
                _ => (),
            }
            fields(&mut isf.data, "ns_common", &[("inum", 0, "u64")]);
            fields(
                &mut isf.data,
                "timens_offsets",
                &[("boottime", 0, "timespec")],
            );
            fields(&mut isf.data, "time_namespace", &[("ns", 0, "ns_common")]);
            let tasks = case["tasks"].as_array().unwrap();
            let head = 0x9000;
            put(
                &mut bytes,
                head,
                if tasks.is_empty() {
                    head as i128
                } else {
                    0xa000
                },
            );
            put(
                &mut bytes,
                head + 8,
                if tasks.is_empty() {
                    head as i128
                } else {
                    0xa000 + (tasks.len() as i128 - 1) * 0x100
                },
            );
            for (index, namespace) in tasks.iter().enumerate() {
                let at = 0xa000 + index as u64 * 0x100;
                put(
                    &mut bytes,
                    at,
                    if index + 1 == tasks.len() {
                        head
                    } else {
                        at + 0x100
                    } as i128,
                );
                put(
                    &mut bytes,
                    at + 8,
                    if index == 0 { head } else { at - 0x100 } as i128,
                );
                put(&mut bytes, at + 16, index as i128 + 1);
                put(&mut bytes, at + 24, index as i128 + 1);
                put(&mut bytes, at + 32, head as i128);
                let comm = at + isf.offset("task_struct", "comm").unwrap();
                bytes[comm as usize..comm as usize + 8].copy_from_slice(b"task\0\0\0\0");
                let proxy = 0x11000 + index as u64 * 0x100;
                let ns = 0x12000 + index as u64 * 0x100;
                put(&mut bytes, at + 112, proxy as i128);
                put(
                    &mut bytes,
                    proxy,
                    if namespace.is_null() { 0 } else { ns as i128 },
                );
                if !namespace.is_null() {
                    put(&mut bytes, ns, namespace["id"].as_i64().unwrap() as i128);
                    if let Some(offset) = namespace["offset"].as_array() {
                        fields(
                            &mut isf.data,
                            "time_namespace",
                            &[("ns", 0, "ns_common"), ("offsets", 16, "timens_offsets")],
                        );
                        fields(
                            &mut isf.data,
                            "timens_offsets",
                            &[("boottime", 0, "timespec")],
                        );
                        put(&mut bytes, ns + 16, offset[0].as_i64().unwrap() as i128);
                        put(&mut bytes, ns + 24, offset[1].as_i64().unwrap() as i128);
                    }
                }
            }
            if let Some(member) = case["missing_member"].as_str() {
                let ty = match member {
                    "timekeeper" => "exact_anonymous_core",
                    "total_sleep_time" => "timekeeper",
                    "boottime" => "timens_offsets",
                    _ => panic!("unknown missing field"),
                };
                isf.data["user_types"][ty]["fields"]
                    .as_object_mut()
                    .unwrap()
                    .remove(member);
            }
            let image = image(&bytes);
            let linux = engine(&image, &isf);
            let (result, tasks) = linux
                .adapter_tasks(Plugin::LinuxBoottime, &Job::default())
                .unwrap();
            let result = linux.namespace_boottimes_tasks(&Job::default(), result, tasks);
            if case.get("error").is_some() {
                assert!(result.is_err(), "{}", case["id"]);
            } else {
                let result = result.unwrap();
                assert!(result.complete, "{} {:?}", case["id"], result.diagnostics);
                assert_eq!(json!(result.rows), case["expected"], "{}", case["id"]);
                assert_eq!(
                    result.kernel_identity["boottime_timeline"], case["timeline"],
                    "{}",
                    case["id"]
                );
            }
        }
    }

    #[test]
    fn timekeeping_32_bit_fields_preserve_signed_seconds_and_unsigned_sleep() {
        for scalar_sleep in [false, true] {
            let (mut bytes, mut isf) = fixture();
            isf.data["base_types"]["i32"] = json!({"size":4,"signed":true});
            isf.data["user_types"]["timespec"] = json!({"size":8,"fields":{
                "tv_sec":{"offset":0,"type":{"kind":"base","name":"i32"}},
                "tv_nsec":{"offset":4,"type":{"kind":"base","name":"i32"}}
            }});
            isf.data["symbols"]["wall_to_monotonic"] =
                json!({"address":0x10000,"type":{"name":"timespec"}});
            let write = |bytes: &mut [u8], at: usize, value: u32| {
                bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
            };
            write(&mut bytes, 0x10000, (-1_700_000_010i32) as u32);
            write(&mut bytes, 0x10004, 123_456_789);
            if scalar_sleep {
                isf.data["symbols"]["total_sleep_time"] =
                    json!({"address":0x10020,"type":{"name":"u32"}});
                write(&mut bytes, 0x10020, 10);
            } else {
                isf.data["symbols"]["total_sleep_time"] =
                    json!({"address":0x10020,"type":{"name":"timespec"}});
                write(&mut bytes, 0x10020, 10);
                write(&mut bytes, 0x10024, 0);
            }
            let image = image(&bytes);
            let linux = engine(&image, &isf);
            assert_eq!(
                linux.root_boot_time_nanos().unwrap(),
                1_699_999_999_876_543_211
            );
        }
    }
}
