//! Bounds-checked integers from untrusted image bytes. `None` means truncated input.
#![cfg_attr(not(test), deny(clippy::indexing_slicing))]
fn array<const N: usize>(bytes: &[u8], at: usize) -> Option<[u8; N]> {
    bytes.get(at..at.checked_add(N)?)?.first_chunk().copied()
}
pub(crate) fn le_u16(bytes: &[u8], at: usize) -> Option<u16> {
    array(bytes, at).map(u16::from_le_bytes)
}
pub(crate) fn le_u32(bytes: &[u8], at: usize) -> Option<u32> {
    array(bytes, at).map(u32::from_le_bytes)
}
pub(crate) fn le_u64(bytes: &[u8], at: usize) -> Option<u64> {
    array(bytes, at).map(u64::from_le_bytes)
}
/// Little-endian integer of up to eight bytes; `None` for a longer slice.
pub(crate) fn le_uint(bytes: &[u8]) -> Option<u64> {
    let mut value = [0; 8];
    value.get_mut(..bytes.len())?.copy_from_slice(bytes);
    Some(u64::from_le_bytes(value))
}
/// Low half of a 64-bit value, for fields whose high bits are deliberately discarded.
pub(crate) fn low_u32(value: u64) -> u32 {
    let [a, b, c, d, ..] = value.to_le_bytes();
    u32::from_le_bytes([a, b, c, d])
}
/// Terminal cell counts. Anything wider than a screen saturates instead of wrapping.
pub(crate) trait Cells {
    fn cells(self) -> u16;
}
impl Cells for usize {
    fn cells(self) -> u16 {
        u16::try_from(self).unwrap_or(u16::MAX)
    }
}
/// Whole part of a float. The only float-to-integer cast: `as` saturates and maps NaN
/// to zero, and `try_from` does not exist for floats.
#[allow(clippy::cast_possible_truncation)]
pub(crate) fn float_to_i128(value: f64) -> i128 {
    value as i128
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cells_and_floats_saturate() {
        assert_eq!(70_000usize.cells(), u16::MAX);
        assert_eq!(7usize.cells(), 7);
        assert_eq!(float_to_i128(f64::NAN), 0);
        assert_eq!(float_to_i128(-1.9), -1);
        assert_eq!(float_to_i128(f64::INFINITY), i128::MAX);
    }
    #[test]
    fn variable_width_reads_stop_at_eight_bytes() {
        assert_eq!(le_uint(&[1, 2, 3]), Some(0x03_0201));
        assert_eq!(le_uint(&[]), Some(0));
        assert_eq!(le_uint(&[0; 9]), None);
    }
    #[test]
    fn low_half_discards_only_the_high_bits() {
        assert_eq!(low_u32(0x1234_5678_9abc_def0), 0x9abc_def0);
    }
    #[test]
    fn reads_little_endian_values_in_bounds() {
        let bytes = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        assert_eq!(le_u16(&bytes, 7), Some(0x0908));
        assert_eq!(le_u32(&bytes, 1), Some(0x0504_0302));
        assert_eq!(le_u64(&bytes, 1), Some(0x0908_0706_0504_0302));
    }
    #[test]
    fn out_of_bounds_reads_are_none_even_at_the_address_limit() {
        let bytes = [0; 4];
        assert_eq!(le_u32(&bytes, 1), None);
        assert_eq!(le_u16(&bytes, 4), None);
        assert_eq!(le_u64(&bytes, 0), None);
        assert_eq!(le_u32(&bytes, usize::MAX), None);
        assert_eq!(le_u16(&bytes, usize::MAX - 1), None);
    }
}
