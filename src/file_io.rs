use std::{fs::File, io, path::Path};

#[cfg(unix)]
pub(crate) use std::os::unix::fs::FileExt as ReadAt;

#[cfg(windows)]
pub(crate) trait ReadAt {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()>;
}

#[cfg(windows)]
impl ReadAt for File {
    fn read_exact_at(&self, mut buf: &mut [u8], mut offset: u64) -> io::Result<()> {
        use std::os::windows::fs::FileExt;
        while !buf.is_empty() {
            // Windows updates the cursor, but every image read supplies its own offset.
            match self.seek_read(buf, offset) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(count) => {
                    buf = buf.get_mut(count..).ok_or(io::ErrorKind::InvalidData)?;
                    offset = offset
                        .checked_add(count as u64)
                        .ok_or(io::ErrorKind::InvalidInput)?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct FileStamp {
    volume: u64,
    id: u128,
    pub(crate) len: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl std::fmt::Display for FileStamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}:{}:{}:{}:{}:{}",
            self.volume,
            self.id,
            self.len,
            self.modified.0,
            self.modified.1,
            self.changed.0,
            self.changed.1
        )
    }
}

#[cfg(unix)]
pub(crate) fn metadata_stamp(metadata: &std::fs::Metadata) -> FileStamp {
    use std::os::unix::fs::MetadataExt;
    FileStamp {
        volume: metadata.dev(),
        id: metadata.ino().into(),
        len: metadata.len(),
        modified: (metadata.mtime(), metadata.mtime_nsec()),
        changed: (metadata.ctime(), metadata.ctime_nsec()),
    }
}

#[cfg(unix)]
pub(crate) fn file_stamp(file: &File) -> io::Result<FileStamp> {
    Ok(metadata_stamp(&file.metadata()?))
}

#[cfg(unix)]
pub(crate) fn path_stamp(path: &Path) -> io::Result<FileStamp> {
    Ok(metadata_stamp(&std::fs::metadata(path)?))
}

#[cfg(windows)]
pub(crate) fn path_stamp(path: &Path) -> io::Result<FileStamp> {
    path_stamp_with(path, true)
}

#[cfg(windows)]
pub(crate) fn symlink_stamp(path: &Path) -> io::Result<FileStamp> {
    path_stamp_with(path, false)
}

#[cfg(windows)]
fn path_stamp_with(path: &Path, follow: bool) -> io::Result<FileStamp> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
    };
    let mut flags = FILE_FLAG_BACKUP_SEMANTICS;
    if !follow {
        flags |= FILE_FLAG_OPEN_REPARSE_POINT;
    }
    let file = File::options()
        .access_mode(FILE_READ_ATTRIBUTES)
        .custom_flags(flags)
        .open(path)?;
    file_stamp(&file)
}

#[cfg(windows)]
pub(crate) fn file_stamp(file: &File) -> io::Result<FileStamp> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_BASIC_INFO, FILE_ID_INFO, FileBasicInfo, FileIdInfo,
        GetFileInformationByHandle, GetFileInformationByHandleEx,
    };

    let basic_info_size = u32::try_from(size_of::<FILE_BASIC_INFO>()).map_err(io::Error::other)?;
    let file_id_size = u32::try_from(size_of::<FILE_ID_INFO>()).map_err(io::Error::other)?;
    let handle = file.as_raw_handle();
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    let mut times = FILE_BASIC_INFO::default();
    let mut id = FILE_ID_INFO::default();
    // The handle is borrowed for these synchronous queries and the output
    // buffers have the size and layout of the requested Windows structures.
    let (volume, id) = unsafe {
        if GetFileInformationByHandle(handle, &mut info) == 0
            || GetFileInformationByHandleEx(
                handle,
                FileBasicInfo,
                (&raw mut times).cast(),
                basic_info_size,
            ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        if GetFileInformationByHandleEx(handle, FileIdInfo, (&raw mut id).cast(), file_id_size) == 0
        {
            // Some filesystems only expose the legacy 64-bit identifier.
            let legacy = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
            (info.dwVolumeSerialNumber.into(), legacy.into())
        } else {
            (
                id.VolumeSerialNumber,
                u128::from_le_bytes(id.FileId.Identifier),
            )
        }
    };
    let timestamp = |ticks: i64| (ticks / 10_000_000, (ticks % 10_000_000) * 100);
    Ok(FileStamp {
        volume,
        id,
        len: (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow),
        modified: timestamp(times.LastWriteTime),
        changed: timestamp(times.ChangeTime),
    })
}

#[cfg(all(windows, test))]
mod tests {
    use super::*;

    #[test]
    fn positional_reads_share_a_handle_and_detect_eof() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("image");
        std::fs::write(&path, [vec![b'a'; 4096], vec![b'b'; 4096]].concat())?;
        let file = File::open(&path)?;
        std::thread::scope(|scope| {
            for (offset, byte) in [(0, b'a'), (4096, b'b')] {
                let file = &file;
                scope.spawn(move || {
                    for _ in 0..32 {
                        let mut buf = [0; 4096];
                        file.read_exact_at(&mut buf, offset).unwrap();
                        assert_eq!(buf, [byte; 4096]);
                    }
                });
            }
        });
        let error = file.read_exact_at(&mut [0; 2], 8191).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        Ok(())
    }

    #[test]
    fn a_same_size_replacement_has_a_different_file_stamp() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let first = dir.path().join("first");
        let second = dir.path().join("second");
        std::fs::write(&first, b"a")?;
        std::fs::write(&second, b"b")?;
        let file = File::open(&first)?;
        let stamp = file_stamp(&file)?;
        assert_eq!(stamp, path_stamp(&first)?);
        drop(file);
        std::fs::rename(&second, &first)?;
        assert_ne!(stamp, path_stamp(&first)?);
        Ok(())
    }
}
