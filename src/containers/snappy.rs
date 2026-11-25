//! Pure-Rust Snappy raw block and framing format decoder with masked CRC-32C.
//!
//! References:
//! - Google Snappy format description (`format_description.txt`)
//! - Google Snappy framing format (`framing_format.txt`)
use crate::bytes::Checked as _;
use anyhow::{Context, Result, bail, ensure};

/// Maximum uncompressed size of a single Snappy framed chunk (64 KiB per spec).
pub const MAX_FRAMED_CHUNK_UNCOMPRESSED: usize = 65_536;

/// Snappy stream identifier chunk payload.
pub const STREAM_IDENTIFIER: &[u8; 6] = b"sNaPpY";

/// Compute Castagnoli CRC-32C (reflected polynomial 0x82f63b78).
pub fn crc32c(bytes: &[u8]) -> u32 {
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    let table = TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, slot) in t.iter_mut().enumerate() {
            let mut crc = u32::try_from(i).unwrap_or(0);
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ 0x82f6_3b78
                } else {
                    crc >> 1
                };
            }
            *slot = crc;
        }
        t
    });
    let mut crc = !0u32;
    for &byte in bytes {
        let [low, ..] = crc.to_le_bytes();
        let idx = usize::from(low ^ byte);
        crc = (crc >> 8) ^ table.get(idx).copied().unwrap_or(0);
    }
    !crc
}

/// Mask a CRC-32C checksum as defined by the Snappy framing format.
pub fn mask_crc32c(crc: u32) -> u32 {
    crc.rotate_right(15).wrapping_add(0xa282_ead8)
}

/// Read the uncompressed length varint from the front of a raw Snappy block.
/// Returns `(uncompressed_len, bytes_consumed)`.
pub fn read_uncompressed_len(input: &[u8]) -> Result<(usize, usize)> {
    let mut value = 0u32;
    for (i, &byte) in input.iter().take(5).enumerate() {
        let shift = u32::try_from(i * 7)?;
        if i == 4 && byte > 0x0f {
            bail!("Snappy varint 溢出");
        }
        value |= u32::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok((usize::try_from(value)?, i + 1));
        }
    }
    bail!("Snappy varint 截断")
}

/// Decompress a raw Snappy block, enforcing an upper bound on output size.
pub fn decompress_raw(input: &[u8], max_output: usize) -> Result<Vec<u8>> {
    let (expected_len, mut pos) = read_uncompressed_len(input)?;
    ensure!(
        expected_len <= max_output,
        "Snappy 解压长度 {expected_len} 超过上限 {max_output}"
    );
    let mut out = Vec::with_capacity(expected_len);
    while pos < input.len() {
        let tag = *input.at(pos)?;
        pos += 1;
        match tag & 0x03 {
            // Literal
            0 => {
                let len_minus_1 = usize::from(tag >> 2);
                let lit_len = if len_minus_1 < 60 {
                    len_minus_1 + 1
                } else {
                    let extra = len_minus_1 - 59;
                    let raw = input
                        .get(pos..pos + extra)
                        .context("Snappy 字面量长度截断")?;
                    pos += extra;
                    let mut n = 0usize;
                    for (i, &b) in raw.iter().enumerate() {
                        n |= usize::from(b) << (i * 8);
                    }
                    n.checked_add(1).context("Snappy 字面量长度溢出")?
                };
                let lit = input
                    .get(pos..pos.checked_add(lit_len).context("Snappy 字面量偏移溢出")?)
                    .context("Snappy 字面量数据截断")?;
                pos += lit_len;
                ensure!(
                    out.len()
                        .checked_add(lit_len)
                        .is_some_and(|n| n <= expected_len),
                    "Snappy 字面量超出声明解压长度"
                );
                out.extend_from_slice(lit);
            }
            // Copy with 1-byte offset
            1 => {
                let len = usize::from((tag >> 2) & 0x07) + 4;
                let low = usize::from(*input.get(pos).context("Snappy copy1 偏移截断")?);
                pos += 1;
                let offset = (usize::from(tag >> 5) << 8) | low;
                copy_back(&mut out, offset, len, expected_len)?;
            }
            // Copy with 2-byte offset
            2 => {
                let len = usize::from(tag >> 2) + 1;
                let b0 = usize::from(*input.get(pos).context("Snappy copy2 偏移截断")?);
                let b1 = usize::from(*input.get(pos + 1).context("Snappy copy2 偏移截断")?);
                pos += 2;
                let offset = b0 | (b1 << 8);
                copy_back(&mut out, offset, len, expected_len)?;
            }
            // Copy with 4-byte offset
            _ => {
                let len = usize::from(tag >> 2) + 1;
                let bytes = input.get(pos..pos + 4).context("Snappy copy4 偏移截断")?;
                pos += 4;
                let offset = usize::try_from(u32::from_le_bytes(
                    bytes
                        .first_chunk()
                        .copied()
                        .context("Snappy copy4 长度无效")?,
                ))?;
                copy_back(&mut out, offset, len, expected_len)?;
            }
        }
    }
    ensure!(
        out.len() == expected_len,
        "Snappy 解压长度不匹配：声明 {expected_len}，实际 {}",
        out.len()
    );
    Ok(out)
}

fn copy_back(out: &mut Vec<u8>, offset: usize, len: usize, expected_len: usize) -> Result<()> {
    ensure!(
        offset > 0 && offset <= out.len(),
        "Snappy 回溯偏移 {offset} 无效（当前输出 {} 字节）",
        out.len()
    );
    ensure!(
        out.len()
            .checked_add(len)
            .is_some_and(|n| n <= expected_len),
        "Snappy 复制超出声明解压长度"
    );
    let start = out.len() - offset;
    if offset >= len {
        out.extend_from_within(start..start + len);
    } else {
        for i in 0..len {
            let byte = *out.at(start + i)?;
            out.push(byte);
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn encode_raw_literals(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut n = data.len() as u32;
    loop {
        let mut byte = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if n == 0 {
            break;
        }
    }
    if !data.is_empty() {
        let len_m1 = data.len() - 1;
        if len_m1 < 60 {
            out.push((len_m1 as u8) << 2);
        } else if len_m1 <= 0xff {
            out.push(60 << 2);
            out.push(len_m1 as u8);
        } else {
            out.push(61 << 2);
            out.extend_from_slice(&(len_m1 as u16).to_le_bytes());
        }
        out.extend_from_slice(data);
    }
    out
}

#[cfg(test)]
pub(crate) fn encode_framed(data: &[u8], compressed: bool) -> Vec<u8> {
    let mut out = Vec::new();
    // Stream identifier chunk
    out.push(0xff);
    out.extend_from_slice(&[6, 0, 0]);
    out.extend_from_slice(STREAM_IDENTIFIER);
    for chunk in data.chunks(MAX_FRAMED_CHUNK_UNCOMPRESSED) {
        let crc = mask_crc32c(crc32c(chunk));
        if compressed {
            let payload = encode_raw_literals(chunk);
            let len = (4 + payload.len()) as u32;
            out.push(0x00);
            out.extend_from_slice(&len.to_le_bytes()[..3]);
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&payload);
        } else {
            let len = (4 + chunk.len()) as u32;
            out.push(0x01);
            out.extend_from_slice(&len.to_le_bytes()[..3]);
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(chunk);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_snappy_decodes_literals_and_overlapping_copies() {
        // Decompresses to "abcdabcdabcd!" (13 bytes):
        // varint 13, literal "abcd" (len=4 -> tag=(3<<2)=0x0c), copy1 len=8 offset=4 ->
        // tag = 1 | ((8-4)<<2) | (0<<5) = 0x11, offset=4, literal "!" (tag=0x00, b'!')
        let encoded = [13u8, 0x0c, b'a', b'b', b'c', b'd', 0x11, 4, 0x00, b'!'];
        let decoded = decompress_raw(&encoded, 64).unwrap();
        assert_eq!(decoded, b"abcdabcdabcd!");
    }

    #[test]
    fn crc32c_matches_standard_test_vector() {
        // RFC 3720 / Castagnoli check value for "123456789" is 0xe3069283.
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
    }

    #[test]
    fn raw_snappy_rejects_corrupt_offset_and_oversize() {
        // Copy offset 0 is invalid
        let bad = [4u8, 0x01, 0x00];
        assert!(decompress_raw(&bad, 64).is_err());
        // Declared length exceeds max_output
        let oversize = [100u8, 0x00, b'a'];
        assert!(decompress_raw(&oversize, 16).is_err());
    }
}
