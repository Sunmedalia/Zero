//! Bounded native Microsoft XPRESS codecs. Plain LZ77 follows MS-XCA §2.4.4.
use anyhow::{Context, Result, ensure};
pub(super) fn decompress(format: u16, input: &[u8], size: usize) -> Result<Vec<u8>> {
    ensure!(
        (1..=65536).contains(&size) && input.len() <= 65536,
        "XPRESS 块大小越界"
    );
    let output = match format {
        3 => plain(input, size)?,
        4 => xpress_huffman::decompress(input, size)
            .map_err(|e| anyhow::anyhow!("XPRESS Huffman: {e:?}"))?,
        _ => anyhow::bail!("未知压缩算法 {format}"),
    };
    ensure!(
        output.len() == size,
        "解压长度不匹配: {} / {size}",
        output.len()
    );
    Ok(output)
}
fn take(input: &[u8], at: &mut usize, n: usize) -> Result<u32> {
    let end = at.checked_add(n).context("XPRESS 输入溢出")?;
    let mut b = [0; 4];
    b[..n].copy_from_slice(input.get(*at..end).context("XPRESS 输入截断")?);
    *at = end;
    Ok(u32::from_le_bytes(b))
}
fn plain(input: &[u8], size: usize) -> Result<Vec<u8>> {
    let mut output = Vec::with_capacity(size);
    let mut at = 0;
    let mut flags = 0;
    let mut bits = 0;
    let mut half = None;
    while output.len() < size {
        if bits == 0 {
            flags = take(input, &mut at, 4)?;
            bits = 32;
        }
        bits -= 1;
        if flags & (1 << bits) == 0 {
            output.push(take(input, &mut at, 1)? as u8);
            continue;
        }
        let token = take(input, &mut at, 2)?;
        let distance = (token / 8 + 1) as usize;
        let mut length = token % 8;
        if length == 7 {
            length = if let Some(previous) = half.take() {
                u32::from(*input.get(previous).context("XPRESS nibble 截断")?) / 16
            } else {
                let previous = at;
                let byte = take(input, &mut at, 1)?;
                half = Some(previous);
                byte % 16
            };
            if length == 15 {
                length = take(input, &mut at, 1)?;
                if length == 255 {
                    length = take(input, &mut at, 2)?;
                    if length == 0 {
                        length = take(input, &mut at, 4)?;
                    }
                    ensure!(length >= 22, "XPRESS 扩展长度无效");
                    length -= 22;
                }
                length = length.checked_add(15).context("XPRESS 长度溢出")?;
            }
            length = length.checked_add(7).context("XPRESS 长度溢出")?;
        }
        let length = length.checked_add(3).context("XPRESS 长度溢出")? as usize;
        ensure!(
            distance <= output.len() && output.len().checked_add(length).is_some_and(|n| n <= size),
            "XPRESS 匹配越界"
        );
        for _ in 0..length {
            output.push(output[output.len() - distance]);
        }
    }
    Ok(output)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn plain_literals_overlap_and_extended_lengths() {
        assert_eq!(decompress(3, &[0, 0, 0, 0, b'a', b'b'], 2).unwrap(), b"ab");
        assert_eq!(
            decompress(3, &[0, 0, 0, 0x40, b'a', 2, 0], 6).unwrap(),
            b"aaaaaa"
        );
        assert!(decompress(3, &[0, 0, 0, 0x80, 0, 0], 3).is_err());
        let data = [0, 0, 0, 0x40, b'x', 7, 0, 15, 255, 0xfc, 0x0f];
        assert_eq!(decompress(3, &data, 4096).unwrap(), vec![b'x'; 4096]);
        for n in 0..data.len() {
            assert!(decompress(3, &data[..n], 4096).is_err());
        }
        assert!(decompress(4, &[0; 256], 4096).is_err());
        assert!(decompress(3, &data, 65537).is_err());
    }
}
