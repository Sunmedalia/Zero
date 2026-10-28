//! Bounded packed-pixel conversion and streaming RGBA PNG output.
//!
//! Channels retain the fbdev reference's unscaled integer values (saturated at
//! 255); absent alpha is opaque. Row padding is respected, not rendered.
use crate::Job;
use anyhow::{Context, Result, ensure};
use flate2::{Compression, write::ZlibEncoder};
use std::io::Write;

const MAX_SOURCE: u64 = 256 * 1024 * 1024;
const MAX_PIXELS: u64 = 16 * 1024 * 1024;
const CHUNK: usize = 65536;

#[derive(Clone, Copy, Debug, Default)]
pub struct Channel {
    pub offset: u32,
    pub length: u32,
    pub msb_right: bool,
}
#[derive(Clone, Debug)]
pub struct Layout {
    pub width: u32,
    pub height: u32,
    pub stride: u64,
    pub bits_per_pixel: u32,
    /// Red, green, blue, alpha, in that order.
    pub channels: [Channel; 4],
}
impl Layout {
    /// Validate before any source reads or output writes, including address overflow.
    pub fn validate(&self, base: u64) -> Result<u64> {
        ensure!(self.width > 0 && self.height > 0, "像素尺寸不能为零");
        ensure!(
            matches!(self.bits_per_pixel, 8 | 16 | 24 | 32 | 40 | 48 | 56 | 64),
            "仅支持 8..64 位字节对齐的 packed pixel"
        );
        let pixels = u64::from(self.width) * u64::from(self.height);
        ensure!(pixels <= MAX_PIXELS, "图像超过 16 Mi 像素上限");
        let row = u64::from(self.width) * u64::from(self.bits_per_pixel / 8);
        ensure!(self.stride >= row, "像素行超过 line_length");
        let size = self
            .stride
            .checked_mul(u64::from(self.height))
            .context("像素缓冲长度溢出")?;
        ensure!(size <= MAX_SOURCE, "像素缓冲超过 256 MiB 上限");
        base.checked_add(size).context("像素缓冲地址溢出")?;
        for channel in self.channels {
            ensure!(
                channel.length == 0
                    || channel
                        .offset
                        .checked_add(channel.length)
                        .is_some_and(|end| end <= self.bits_per_pixel),
                "颜色位域超出像素"
            );
        }
        Ok(size)
    }
}
fn channel_value(pixel: u64, channel: Channel, absent: u8) -> u8 {
    if channel.length == 0 {
        return absent;
    }
    let mask = if channel.length == 64 {
        u64::MAX
    } else {
        (1u64 << channel.length) - 1
    };
    let mut value = (pixel >> channel.offset) & mask;
    if channel.msb_right {
        value = value.reverse_bits() >> (64 - channel.length);
    }
    value.min(255) as u8
}
const fn crc_table() -> [u32; 256] {
    let mut table = [0; 256];
    let mut i = 0;
    while i < 256 {
        let mut value = i as u32;
        let mut bit = 0;
        while bit < 8 {
            value = if value & 1 != 0 {
                (value >> 1) ^ 0xedb8_8320
            } else {
                value >> 1
            };
            bit += 1;
        }
        table[i] = value;
        i += 1;
    }
    table
}
const CRC: [u32; 256] = crc_table();
fn chunk(output: &mut dyn Write, kind: &[u8; 4], bytes: &[u8]) -> std::io::Result<()> {
    debug_assert!(bytes.len() <= CHUNK);
    output.write_all(&(bytes.len() as u32).to_be_bytes())?;
    output.write_all(kind)?;
    output.write_all(bytes)?;
    let mut crc = u32::MAX;
    for &byte in kind.iter().chain(bytes) {
        crc = (crc >> 8) ^ CRC[((crc ^ u32::from(byte)) & 255) as usize];
    }
    output.write_all(&(!crc).to_be_bytes())
}
struct Idat<'a> {
    output: &'a mut dyn Write,
    pending: Vec<u8>,
    job: &'a Job,
}
impl Idat<'_> {
    fn emit(&mut self) -> std::io::Result<()> {
        self.job.check().map_err(std::io::Error::other)?;
        if !self.pending.is_empty() {
            chunk(self.output, b"IDAT", &self.pending)?;
            self.pending.clear();
        }
        Ok(())
    }
}
impl Write for Idat<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.job.check().map_err(std::io::Error::other)?;
        let len = bytes.len().min(CHUNK - self.pending.len());
        self.pending.extend_from_slice(&bytes[..len]);
        if self.pending.len() == CHUNK {
            self.emit()?;
        }
        Ok(len)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.emit()
    }
}
/// Encode one selected packed framebuffer. The caller publishes the output atomically.
/// Reads one pixel row at a time and never invents pixels for missing source bytes.
/// Returns the number of source bytes actually read, excluding stride padding.
pub fn write_png(
    base: u64,
    layout: &Layout,
    output: &mut dyn Write,
    job: &Job,
    mut read: impl FnMut(u64, &mut [u8]) -> Result<()>,
) -> Result<u64> {
    job.check()?;
    layout.validate(base)?;
    output.write_all(b"\x89PNG\r\n\x1a\n")?;
    let mut header = Vec::with_capacity(13);
    header.extend_from_slice(&layout.width.to_be_bytes());
    header.extend_from_slice(&layout.height.to_be_bytes());
    header.extend_from_slice(&[8, 6, 0, 0, 0]);
    chunk(output, b"IHDR", &header)?;
    let mut idat = Idat {
        output,
        pending: Vec::with_capacity(CHUNK),
        job,
    };
    let mut encoder = ZlibEncoder::new(&mut idat, Compression::default());
    let bytes_per_pixel = (layout.bits_per_pixel / 8) as usize;
    let mut row = vec![0; layout.width as usize * bytes_per_pixel];
    let mut rgba = vec![0; 1 + layout.width as usize * 4]; // filter 0, then RGBA
    let mut bytes_read = 0;
    for y in 0..layout.height {
        job.check()?;
        read(base + u64::from(y) * layout.stride, &mut row)?;
        bytes_read += row.len() as u64;
        for (x, source) in row.chunks_exact(bytes_per_pixel).enumerate() {
            if x % 4096 == 0 {
                job.check()?;
            }
            let mut raw = [0; 8];
            raw[..bytes_per_pixel].copy_from_slice(source);
            let pixel = u64::from_le_bytes(raw);
            for (i, channel) in layout.channels.iter().copied().enumerate() {
                rgba[1 + x * 4 + i] = channel_value(pixel, channel, if i == 3 { 255 } else { 0 });
            }
        }
        encoder.write_all(&rgba)?;
    }
    encoder.finish()?;
    idat.emit()?;
    job.check()?;
    chunk(idat.output, b"IEND", &[])?;
    Ok(bytes_read)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    fn rgb565() -> Layout {
        Layout {
            width: 2,
            height: 2,
            stride: 6,
            bits_per_pixel: 16,
            channels: [
                Channel {
                    offset: 11,
                    length: 5,
                    msb_right: false,
                },
                Channel {
                    offset: 5,
                    length: 6,
                    msb_right: false,
                },
                Channel {
                    offset: 0,
                    length: 5,
                    msb_right: true,
                },
                Channel::default(),
            ],
        }
    }
    #[test]
    fn packed_pixels_use_stride_reverse_bits_and_unscaled_channels() {
        let raw = [
            0x01, 0xf8, 0xe0, 0x07, 0xaa, 0xbb, 0xff, 0xff, 0x00, 0x00, 0xcc, 0xdd,
        ];
        let mut output = Vec::new();
        let mut reads = Vec::new();
        let bytes = write_png(
            0x1000,
            &rgb565(),
            &mut output,
            &Job::default(),
            |at, dst| {
                reads.push((at, dst.len()));
                let offset = (at - 0x1000) as usize;
                dst.copy_from_slice(&raw[offset..offset + dst.len()]);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(bytes, 8);
        assert_eq!(reads, [(0x1000, 4), (0x1006, 4)]);
        assert_eq!(&output[..8], b"\x89PNG\r\n\x1a\n");
        // Known CRC of the fixed 2x2 RGBA IHDR, independently generated with zlib.
        assert_eq!(&output[29..33], &[0x72, 0xb6, 0x0d, 0x24]);
        let mut compressed = Vec::new();
        let mut offset = 8;
        while offset < output.len() {
            let len = u32::from_be_bytes(output[offset..offset + 4].try_into().unwrap()) as usize;
            if &output[offset + 4..offset + 8] == b"IDAT" {
                compressed.extend_from_slice(&output[offset + 8..offset + 8 + len]);
            }
            offset += 12 + len;
        }
        let mut pixels = Vec::new();
        flate2::read::ZlibDecoder::new(compressed.as_slice())
            .read_to_end(&mut pixels)
            .unwrap();
        assert_eq!(
            pixels,
            [
                0, 31, 0, 16, 255, 0, 63, 0, 255, 0, 31, 63, 31, 255, 0, 0, 0, 255
            ]
        );
        assert_eq!(&output[output.len() - 12..], b"\0\0\0\0IEND\xaeB`\x82");
    }
    #[test]
    fn validation_precedes_io_and_holes_or_cancellation_abort_atomic_publication() {
        let mut layout = rgb565();
        layout.stride = 1;
        let mut output = Vec::new();
        assert!(
            write_png(0, &layout, &mut output, &Job::default(), |_, _| panic!(
                "read invalid layout"
            ))
            .is_err()
        );
        assert!(output.is_empty());
        let mut layout = rgb565();
        layout.channels[0].length = 64;
        assert!(layout.validate(0).is_err());
        assert!(rgb565().validate(u64::MAX - 1).is_err());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frame.png");
        std::fs::write(&path, b"old").unwrap();
        let job = Job::default();
        let result = crate::store::atomic_stream(&path, &job, |out| {
            write_png(0, &rgb565(), out, &job, |_, _| anyhow::bail!("source hole")).map(|_| ())
        });
        assert!(result.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"old");
        job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(
            write_png(0, &rgb565(), &mut output, &job, |_, _| panic!(
                "read cancelled job"
            ))
            .is_err()
        );
    }

    #[test]
    fn multiple_idat_chunks_preserve_incompressible_rows_and_cancel_during_conversion() {
        let layout = Layout {
            width: 400,
            height: 200,
            stride: 1600,
            bits_per_pixel: 32,
            channels: std::array::from_fn(|i| Channel {
                offset: i as u32 * 8,
                length: 8,
                msb_right: false,
            }),
        };
        let mut state = 0x12345678u32;
        let raw: Vec<u8> = (0..320000)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect();
        let mut output = Vec::new();
        write_png(0, &layout, &mut output, &Job::default(), |at, out| {
            out.copy_from_slice(&raw[at as usize..at as usize + out.len()]);
            Ok(())
        })
        .unwrap();
        let mut compressed = Vec::new();
        let mut offset = 8;
        let mut idats = 0;
        while offset < output.len() {
            let len = u32::from_be_bytes(output[offset..offset + 4].try_into().unwrap()) as usize;
            assert!(len <= CHUNK);
            if &output[offset + 4..offset + 8] == b"IDAT" {
                idats += 1;
                compressed.extend_from_slice(&output[offset + 8..offset + 8 + len]);
            }
            offset += len + 12;
        }
        assert!(idats > 1);
        let mut pixels = Vec::new();
        flate2::read::ZlibDecoder::new(compressed.as_slice())
            .read_to_end(&mut pixels)
            .unwrap();
        assert_eq!(pixels.len(), 200 * 1601);
        for (expected, actual) in raw.chunks_exact(1600).zip(pixels.chunks_exact(1601)) {
            assert_eq!(actual[0], 0);
            assert_eq!(&actual[1..], expected);
        }
        let job = Job::default();
        let mut reads = 0;
        assert!(
            write_png(0, &layout, &mut Vec::new(), &job, |_, out| {
                reads += 1;
                out.fill(0);
                job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                Ok(())
            })
            .is_err()
        );
        assert_eq!(reads, 1);
        let wide = Channel {
            offset: 0,
            length: 64,
            msb_right: true,
        };
        assert_eq!(channel_value(1, wide, 0), 255);
        assert_eq!(channel_value(1 << 63, wide, 0), 1);
    }
}
