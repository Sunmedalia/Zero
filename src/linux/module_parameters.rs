//! Kernel module load arguments, decoded through the pinned parameter getters.
use super::*;

const INTEGER_GETTERS: &[(&str, &str)] = &[
    ("param_get_invbool", "int"),
    ("param_get_bool", "int"),
    ("param_get_int", "int"),
    ("param_get_ulong", "long unsigned int"),
    ("param_get_ullong", "long long unsigned int"),
    ("param_get_long", "long int"),
    ("param_get_uint", "unsigned int"),
    ("param_get_ushort", "short unsigned int"),
    ("param_get_short", "short int"),
    ("param_get_byte", "char"),
];

impl Linux<'_> {
    fn parameter_string(&self, at: u64, count: u64) -> Result<String> {
        ensure!((1..=4096).contains(&count), "模块参数字符串超出读取上限");
        let mut bytes = Vec::new();
        while bytes.len() < usize::try_from(count)? {
            let address = add(at, bytes.len() as u64)?;
            let length = usize::try_from(4096 - (address & 4095))?
                .min(usize::try_from(count)? - bytes.len());
            let mut page = vec![0; length];
            if let Err(error) = self.vm.read(address, &mut page) {
                if bytes.is_empty() {
                    return Err(error);
                }
                break;
            }
            bytes.extend(page);
        }
        let decoded = String::from_utf8_lossy(&bytes);
        Ok(decoded
            .split(['\0', '\u{fffd}'])
            .next()
            .unwrap_or_default()
            .to_owned())
    }

    fn parameter_value(&self, param: u64, depth: usize, job: &Job) -> Result<Option<String>> {
        job.check()?;
        ensure!(depth < 32, "模块参数数组递归达到上限");
        let getter = (|| -> Result<u64> {
            if self.isf.has_field("kernel_param", "get") {
                self.number(param, "kernel_param", "get")
            } else {
                self.number(
                    self.number(param, "kernel_param", "ops")?,
                    "kernel_param_ops",
                    "get",
                )
            }
        })();
        let Ok(getter) = getter else { return Ok(None) };
        if getter == 0 {
            return Ok(None);
        }
        let matches = |name| self.isf.address(name).ok() == Some(getter);
        if matches("param_array_get") {
            let array = self.number(param, "kernel_param", "arr")?;
            let num = self.number(array, "kparam_array", "num")?;
            let count = if num == 0 {
                self.number(array, "kparam_array", "max")?
            } else {
                let width = self.isf.data["base_types"]["unsigned int"]["size"]
                    .as_u64()
                    .context("unsigned int 宽度缺失")?;
                self.vm.uint(num, usize::try_from(width)?)?
            };
            if count == 0 || count > 32 {
                return Ok(None);
            }
            let elem = self.number(array, "kparam_array", "elem")?;
            let stride = self.number(array, "kparam_array", "elemsize")?;
            let mut values = Vec::new();
            for i in 0..count {
                let at = add(elem, stride.checked_mul(i).context("参数数组偏移溢出")?)?;
                values.push(
                    self.parameter_value(at, depth + 1, job)?
                        .unwrap_or_else(|| "None".into()),
                );
            }
            return Ok(Some(values.join(",")));
        }
        if matches("param_get_string") || matches("param_get_charp") {
            let read = (|| -> Result<String> {
                let at = self.number(param, "kernel_param", "str")?;
                let count = if matches("param_get_string") {
                    self.number(at, "kparam_string", "maxlen")?
                } else {
                    256
                };
                self.parameter_string(at, count)
            })();
            return Ok(read.ok());
        }
        // Later aliases overwrite earlier handler types in the reference map.
        if let Some(&(_, ty)) = INTEGER_GETTERS.iter().rev().find(|(name, _)| matches(name)) {
            let read = (|| -> Result<String> {
                let at = self.number(param, "kernel_param", "arg")?;
                let size = self.isf.data["base_types"][ty]["size"]
                    .as_u64()
                    .context("模块参数整数宽度缺失")?;
                let raw = self.vm.uint(at, usize::try_from(size)?)?;
                if matches("param_get_bool") || matches("param_get_invbool") {
                    return Ok(if (raw != 0) != matches("param_get_invbool") {
                        "Y"
                    } else {
                        "N"
                    }
                    .into());
                }
                if self.isf.data["base_types"][ty]["signed"] == true {
                    let shift = 64 - size * 8;
                    Ok(((raw << shift) as i64 >> shift).to_string())
                } else {
                    Ok(raw.to_string())
                }
            })();
            return Ok(read.ok());
        }
        Ok(None)
    }

    pub(super) fn module_load_arguments(&self, module: u64, job: &Job) -> Result<String> {
        if !self.isf.has_field("module", "kp") {
            return Ok(String::new());
        }
        let count = self.number(module, "module", "num_kp")?;
        if count == 0 || count > 128 {
            return Ok(String::new());
        }
        let base = self.number(module, "module", "kp")?;
        let size = self.isf.data["user_types"]["kernel_param"]["size"]
            .as_u64()
            .context("kernel_param size 缺失")?;
        ensure!((1..=4096).contains(&size), "kernel_param size 无效");
        let mut values = Vec::new();
        for index in 0..count {
            job.check()?;
            let param = add(base, index * size)?;
            let name = self
                .number(param, "kernel_param", "name")
                .and_then(|at| self.parameter_string(at, 32));
            let Ok(name) = name else { continue };
            let value = self
                .parameter_value(param, 0, job)?
                .unwrap_or_else(|| "None".into());
            values.push(format!("{name}={value}"));
        }
        Ok(values.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    #[test]
    fn parameter_arrays_getter_faults_and_strings_match_pinned_methods() {
        let vectors: Value = serde_json::from_str(include_str!(
            "../../tests/reference/parity/fixtures/module-parameters.json"
        ))
        .unwrap();
        for case in vectors["arrays"].as_array().unwrap() {
            let (mut bytes, mut isf) = crate::linux::tests::fixture();
            isf.data["base_types"]["int"] = json!({"size":4,"signed":true});
            isf.data["base_types"]["unsigned int"] = json!({"size":4,"signed":false});
            isf.data["symbols"]["param_array_get"] = json!({"address":0x16000});
            isf.data["symbols"]["param_get_int"] = json!({"address":0x15020});
            isf.data["user_types"]["kernel_param"] = json!({"size":16,"fields":{
                "get":{"offset":0,"type":{"kind":"pointer"}},
                "arg":{"offset":8,"type":{"kind":"pointer"}},
                "arr":{"offset":8,"type":{"kind":"pointer"}}
            }});
            isf.data["user_types"]["kparam_array"] = json!({"size":32,"fields":{
                "num":{"offset":0,"type":{"kind":"pointer"}},
                "max":{"offset":8,"type":{"kind":"base","name":"u64"}},
                "elem":{"offset":16,"type":{"kind":"pointer"}},
                "elemsize":{"offset":24,"type":{"kind":"base","name":"u64"}}
            }});
            let count = case["count"].as_u64().unwrap();
            for (at, value) in [
                (0x11000, 0x16000u64),
                (0x11008, 0x14000),
                (0x14000, if count == 0 { 0 } else { 0x14100 }),
                (0x14008, count),
                (0x14010, 0x13000),
                (0x14018, 16),
                (0x14100, count),
                (0x13000, 0x15020),
                (0x13008, 0x12000),
                (0x12000, 7),
            ] {
                bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
            }
            let image = crate::linux::tests::image(&bytes);
            let linux = crate::linux::tests::engine(&image, &isf);
            assert_eq!(
                serde_json::to_value(linux.parameter_value(0x11000, 0, &Job::default()).unwrap())
                    .unwrap(),
                case["expected"]
            );
        }
        for case in vectors["array_faults"].as_array().unwrap() {
            let (mut bytes, mut isf) = crate::linux::tests::fixture();
            isf.data["symbols"]["param_array_get"] = json!({"address":0x16000});
            isf.data["user_types"]["kernel_param"] = json!({"size":16,"fields":{
                "get":{"offset":0,"type":{"kind":"pointer"}},
                "arr":{"offset":8,"type":{"kind":"pointer"}}
            }});
            isf.data["user_types"]["kparam_array"] = json!({"size":16,"fields":{
                "num":{"offset":0,"type":{"kind":"pointer"}},
                "max":{"offset":8,"type":{"kind":"base","name":"u64"}}
            }});
            bytes[0x11000..0x11008].copy_from_slice(&0x16000u64.to_le_bytes());
            let array = if case["field"] == "num" {
                0x40000u64
            } else {
                0x3fff8u64
            };
            bytes[0x11008..0x11010].copy_from_slice(&array.to_le_bytes());
            let image = crate::linux::tests::image(&bytes);
            let error = crate::linux::tests::engine(&image, &isf)
                .parameter_value(0x11000, 0, &Job::default())
                .unwrap_err();
            assert!(!error.to_string().contains("ISF 字段越界"));
            assert_eq!(case["error"], "InvalidAddressException");
        }
        for case in vectors["getter_faults"].as_array().unwrap() {
            let (mut bytes, mut isf) = crate::linux::tests::fixture();
            let at = if case["id"] == "direct" {
                isf.data["user_types"]["kernel_param"] =
                    json!({"size":8,"fields":{"get":{"offset":0,"type":{"kind":"pointer"}}}});
                0x40000
            } else {
                isf.data["user_types"]["kernel_param"] =
                    json!({"size":8,"fields":{"ops":{"offset":0,"type":{"kind":"pointer"}}}});
                isf.data["user_types"]["kernel_param_ops"] =
                    json!({"size":8,"fields":{"get":{"offset":0,"type":{"kind":"pointer"}}}});
                bytes[0x11000..0x11008].copy_from_slice(&0x40000u64.to_le_bytes());
                0x11000
            };
            let image = crate::linux::tests::image(&bytes);
            assert_eq!(
                serde_json::to_value(
                    crate::linux::tests::engine(&image, &isf)
                        .parameter_value(at, 0, &Job::default())
                        .unwrap()
                )
                .unwrap(),
                case["expected"]
            );
        }
        for case in vectors["strings"].as_array().unwrap() {
            let (mut bytes, isf) = crate::linux::tests::fixture();
            let input = case["hex"].as_str().unwrap();
            let data: Vec<u8> = (0..input.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&input[i..i + 2], 16).unwrap())
                .collect();
            bytes[0x12000..0x12000 + data.len()].copy_from_slice(&data);
            let image = crate::linux::tests::image(&bytes);
            assert_eq!(
                crate::linux::tests::engine(&image, &isf)
                    .parameter_string(0x12000, data.len().max(1) as u64)
                    .unwrap(),
                case["expected"].as_str().unwrap()
            );
        }
    }

    #[test]
    fn parameter_scalars_match_pinned_methods() {
        let vectors: Value = serde_json::from_str(include_str!(
            "../../tests/reference/parity/fixtures/module-parameters.json"
        ))
        .unwrap();
        for case in vectors["cases"].as_array().unwrap() {
            let (mut bytes, mut isf) = crate::linux::tests::fixture();
            for (name, address) in vectors["handlers"].as_object().unwrap() {
                isf.data["symbols"][name] = json!({"address":address});
            }
            let ty = case["type"].as_str().unwrap();
            isf.data["base_types"][ty] = json!({"size":case["size"],"signed":case["signed"]});
            isf.data["user_types"]["kernel_param"] = json!({"size":16,"fields":{
                "get":{"offset":0,"type":{"kind":"pointer"}},
                "arg":{"offset":8,"type":{"kind":"pointer"}}
            }});
            bytes[0x11000..0x11008]
                .copy_from_slice(&case["getter"].as_u64().unwrap().to_le_bytes());
            let at: u64 = if case["fault"] == true {
                0x40000
            } else {
                0x12000
            };
            bytes[0x11008..0x11010].copy_from_slice(&at.to_le_bytes());
            let raw = case["value"]
                .as_i64()
                .map(|n| n as u64)
                .or_else(|| case["value"].as_u64())
                .unwrap();
            bytes[0x12000..0x12008].copy_from_slice(&raw.to_le_bytes());
            let image = crate::linux::tests::image(&bytes);
            let linux = crate::linux::tests::engine(&image, &isf);
            assert_eq!(
                serde_json::to_value(linux.parameter_value(0x11000, 0, &Job::default()).unwrap())
                    .unwrap(),
                case["expected"],
                "{}",
                case["id"]
            );
        }
    }
}
