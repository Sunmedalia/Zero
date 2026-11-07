//! Verified image-generation checkpoints; an index alone never proves success.
use super::*;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::Write,
};

#[derive(Serialize, Deserialize)]
struct Index {
    generator: String,
    engine: String,
    image_sha256: String,
    isf_sha256: String,
    source_sha256: String,
}

pub(super) fn build_path(image: &Image, cache: &Path) -> PathBuf {
    // Hash even caller-supplied identities: none of them may become path components.
    let key = if hex_digest(&image.digest) {
        image.digest.clone()
    } else {
        format!("{:x}", Sha256::digest(image.digest.as_bytes()))
    };
    cache.join("symbols/build/image").join(key).join(GENERATOR)
}

fn digest(path: &Path, job: &Job) -> Result<String> {
    crate::image::digest_reader(File::open(path)?, job)
}

fn hex_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn unchanged(image: &Image, stamp: &str) -> Result<()> {
    image.ensure_unchanged()?;
    ensure!(
        image.stamp()? == stamp,
        "镜像在符号生成期间发生变化；请重新打开镜像"
    );
    Ok(())
}

pub(super) fn reuse(
    image: &Image,
    cache: &Path,
    build: &Path,
    stamp: &str,
    job: &Job,
) -> Result<Option<PathBuf>> {
    let index_path = build.join("index.json");
    if !index_path.exists() {
        return Ok(None);
    }
    job.report("校验镜像符号生成缓存");
    let result = (|| -> Result<PathBuf> {
        let record: Index = serde_json::from_value(
            super::super::stages::read_json(&index_path).context("生成索引损坏")?,
        )?;
        ensure!(
            record.generator == GENERATOR
                && record.engine == crate::ENGINE_VERSION
                && record.image_sha256 == image.digest,
            "生成索引版本或镜像不匹配"
        );
        ensure!(
            hex_digest(&record.isf_sha256) && hex_digest(&record.source_sha256),
            "生成索引摘要无效"
        );
        let path = cache
            .join("symbols/isf")
            .join(format!("{}.json.xz", record.isf_sha256));
        let source_path = path.with_extension("source.json");
        ensure!(
            digest(&source_path, job)? == record.source_sha256,
            "来源记录摘要不匹配"
        );
        let source = super::super::stages::read_json(&source_path).context("来源记录损坏")?;
        ensure!(
            source.key("source") == "image"
                && source.key("generator") == GENERATOR
                && source.key("image_sha256").as_str() == Some(image.digest.as_str()),
            "来源记录不匹配"
        );
        let bytes = crate::symbols::decode(File::open(&path)?, "cached.json.xz", job)?;
        job.check()?;
        let mut isf = Isf::parse(&bytes, path.display().to_string())?;
        ensure!(isf.digest == record.isf_sha256, "符号文件摘要不匹配");
        let zero = isf.data.key("metadata").key("zero");
        ensure!(
            zero.key("source") == "image"
                && zero.key("generator") == GENERATOR
                && zero.key("image_sha256").as_str() == Some(image.digest.as_str()),
            "ISF 来源不匹配"
        );
        ensure!(
            source.key("metadata") == isf.data.key("metadata"),
            "ISF 与来源元数据不匹配"
        );
        let expected = source
            .key("provenance")
            .key("page_table")
            .key("slide")
            .as_str()
            .and_then(|s| s.strip_prefix("0x"))
            .and_then(|s| u64::from_str_radix(s, 16).ok())
            .context("来源缺少页表重定位")?;
        let (_, slide) = validate(image, &mut isf, Some(expected), job)?;
        if let Some(offset) = isf
            .data
            .key("metadata")
            .key("zero")
            .key("kaslr_offset")
            .as_u64()
        {
            ensure!(slide == offset, "缓存 KASLR 偏移不匹配");
        }
        unchanged(image, stamp)?;
        job.check()?;
        Ok(path)
    })();
    match result {
        Ok(path) => {
            job.report("复用已验证的镜像生成符号（跳过 kallsyms 解码与 BTF 转换）");
            Ok(Some(path))
        }
        Err(error) => {
            job.check()?;
            unchanged(image, stamp)?;
            job.report(format!("镜像生成缓存不可用，重新生成: {error:#}"));
            Ok(None)
        }
    }
}

/// Serialize with cancellation checks without requiring a second JSON-sized buffer.
pub(super) fn json_bytes(data: &Value, job: &Job) -> Result<Vec<u8>> {
    struct Writer<'a> {
        bytes: Vec<u8>,
        remaining: usize,
        job: &'a Job,
    }
    impl Write for Writer<'_> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.remaining == 0 {
                self.job.check().map_err(std::io::Error::other)?;
                self.remaining = 65536;
            }
            let length = bytes.len().min(self.remaining);
            if self.bytes.len().saturating_add(length) > 256 * 1024 * 1024 {
                return Err(std::io::Error::other("ISF 超过 256 MiB 限制"));
            }
            self.bytes
                .extend_from_slice(bytes.get(..length).unwrap_or_default());
            self.remaining -= length;
            Ok(length)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    job.check()?;
    let mut writer = Writer {
        bytes: Vec::new(),
        remaining: 0,
        job,
    };
    serde_json::to_writer(&mut writer, data)?;
    job.check()?;
    Ok(writer.bytes)
}

pub(super) fn publish(
    image: &Image,
    stamp: &str,
    path: &Path,
    bytes: &[u8],
    source: &Value,
    job: &Job,
) -> Result<()> {
    unchanged(image, stamp)?;
    let lock = path.with_extension("lock");
    let _lock = super::super::stages::artifact_lock(&lock, "符号产物正在保存", job)?;
    let sidecar = path.with_extension("source.json");
    // Keep existing verified bytes and provenance; repair incomplete/corrupt cache files.
    let existing = if path.exists() {
        let decoded = crate::symbols::decode(File::open(path)?, "existing.json.xz", job);
        job.check()?;
        decoded.is_ok_and(|existing| existing == bytes)
    } else {
        false
    };
    let source_valid = super::super::stages::read_json(&sidecar).is_some_and(|s| {
        s.key("source") == "image"
            && s.key("generator") == GENERATOR
            && s.key("image_sha256").as_str() == Some(image.digest.as_str())
            && s.key("metadata") == source.key("metadata")
            && s.key("provenance").key("page_table") == source.key("provenance").key("page_table")
    });
    let mut created_source = false;
    let result = (|| {
        if !source_valid {
            let was_present = sidecar.exists();
            store::atomic_stream(&sidecar, job, |writer| {
                serde_json::to_writer_pretty(writer, source)?;
                unchanged(image, stamp)
            })?;
            created_source = !was_present;
        }
        if !existing {
            job.report("压缩并保存镜像生成符号");
            store::atomic_stream(path, job, |writer| {
                let mut encoder = xz2::write::XzEncoder::new(writer, 6);
                for chunk in bytes.chunks(65536) {
                    job.check()?;
                    encoder.write_all(chunk)?;
                }
                job.check()?;
                encoder.finish()?;
                unchanged(image, stamp)
            })?;
        }
        unchanged(image, stamp)?;
        job.check()?;
        Ok(())
    })();
    if result.is_err() && created_source {
        let _ = fs::remove_file(&sidecar);
    }
    // Lock files are stable synchronization objects; cache clearing removes them.
    result
}

pub(super) fn index(
    image: &Image,
    stamp: &str,
    build: &Path,
    path: &Path,
    job: &Job,
) -> Result<()> {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .and_then(|s| s.strip_suffix(".json.xz"))
        .context("ISF 文件名无效")?;
    ensure!(hex_digest(name), "ISF 摘要无效");
    let record = Index {
        generator: GENERATOR.into(),
        engine: crate::ENGINE_VERSION.into(),
        image_sha256: image.digest.clone(),
        isf_sha256: name.into(),
        source_sha256: digest(&path.with_extension("source.json"), job)?,
    };
    store::atomic_stream(&build.join("index.json"), job, |writer| {
        serde_json::to_writer_pretty(writer, &record)?;
        unchanged(image, stamp)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_serialization_preserves_bytes_and_honors_cancellation() {
        let data = json!({"test": "x".repeat(150000), "items": [1, 2, 3]});
        let job = Job::default();
        assert_eq!(
            json_bytes(&data, &job).unwrap(),
            serde_json::to_vec(&data).unwrap()
        );
        job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(
            json_bytes(&data, &job)
                .unwrap_err()
                .to_string()
                .contains("cancelled")
        );
    }

    #[test]
    fn failed_publication_removes_new_sidecar_but_preserves_existing_records() {
        let dir = tempfile::tempdir().unwrap();
        let file = tempfile::tempfile().unwrap();
        file.set_len(4096).unwrap();
        let image = Image::from_file(file, "fixture".into()).unwrap();
        let stamp = image.stamp().unwrap();
        let target = dir.path().join("blocked.json.xz");
        fs::create_dir(&target).unwrap();
        let source = json!({"source":"image", "generator":GENERATOR, "image_sha256":"fixture"});
        let sidecar = target.with_extension("source.json");
        // A directory cannot be atomically replaced by a regular ISF file.
        assert!(publish(&image, &stamp, &target, b"isf", &source, &Job::default()).is_err());
        assert!(!sidecar.exists());
        assert!(target.is_dir());
    }
}
