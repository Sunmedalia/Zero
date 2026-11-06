//! Bounds-checked integers from untrusted image bytes. `None` means truncated input.
use std::slice::SliceIndex;
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
/// Bytes before the first NUL, or all of them when there is none.
pub(crate) fn c_str(bytes: &[u8]) -> &[u8] {
    bytes.split(|b| *b == 0).next().unwrap_or(bytes)
}
/// `c_str` decoded as lossy UTF-8.
pub(crate) fn c_str_lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(c_str(bytes)).into_owned()
}
/// Little-endian UTF-16 code units; an odd trailing byte is dropped.
pub(crate) fn utf16_units(bytes: &[u8]) -> Vec<u16> {
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|unit| u16::from_le_bytes(*unit))
        .collect()
}
/// Lossy little-endian UTF-16; an odd trailing byte is dropped.
pub(crate) fn utf16_lossy(bytes: &[u8]) -> String {
    String::from_utf16_lossy(&utf16_units(bytes))
}
/// Lossy little-endian UTF-16 where an odd trailing byte, a truncated code
/// unit, shows as U+FFFD instead of disappearing.
pub(crate) fn utf16_lossy_marked(bytes: &[u8]) -> String {
    let mut units = utf16_units(bytes);
    if !bytes.len().is_multiple_of(2) {
        units.push(0xfffd);
    }
    String::from_utf16_lossy(&units)
}
/// Low half of a 64-bit value, for fields whose high bits are deliberately discarded.
pub(crate) fn low_u32(value: u64) -> u32 {
    let [a, b, c, d, ..] = value.to_le_bytes();
    u32::from_le_bytes([a, b, c, d])
}
/// Checked slice and string access. An out-of-range index becomes an error naming the
/// source line, so corrupt input fails visibly instead of panicking or reading as empty.
pub(crate) trait Checked {
    #[track_caller]
    fn at<I: SliceIndex<Self>>(&self, index: I) -> anyhow::Result<&I::Output>;
    #[track_caller]
    fn at_mut<I: SliceIndex<Self>>(&mut self, index: I) -> anyhow::Result<&mut I::Output>;
}
#[cold]
#[track_caller]
fn out_of_range() -> anyhow::Error {
    anyhow::anyhow!("索引越界: {}", std::panic::Location::caller())
}
macro_rules! checked {
    ($($type:ty, [$($generic:ident)?]);*) => {$(
        impl<$($generic)?> Checked for $type {
            #[inline]
            #[track_caller]
            fn at<I: SliceIndex<Self>>(&self, index: I) -> anyhow::Result<&I::Output> {
                match self.get(index) {
                    Some(value) => Ok(value),
                    None => Err(out_of_range()),
                }
            }
            #[inline]
            #[track_caller]
            fn at_mut<I: SliceIndex<Self>>(&mut self, index: I) -> anyhow::Result<&mut I::Output> {
                match self.get_mut(index) {
                    Some(value) => Ok(value),
                    None => Err(out_of_range()),
                }
            }
        }
    )*};
}
checked!([T], [T]; str, []);
/// Checked map lookup; a missing key is an error, as it would be a panic through `Index`.
pub(crate) trait MapAt<K, V> {
    #[track_caller]
    fn at<Q: Ord + ?Sized>(&self, key: &Q) -> anyhow::Result<&V>
    where
        K: std::borrow::Borrow<Q> + Ord;
}
impl<K, V> MapAt<K, V> for std::collections::BTreeMap<K, V> {
    #[inline]
    #[track_caller]
    fn at<Q: Ord + ?Sized>(&self, key: &Q) -> anyhow::Result<&V>
    where
        K: std::borrow::Borrow<Q> + Ord,
    {
        match self.get(key) {
            Some(value) => Ok(value),
            None => Err(out_of_range()),
        }
    }
}
/// `serde_json` access without the `Index` operators. `key` keeps their read behavior, a
/// missing key is `Null`; `key_mut` reports a non-object instead of panicking.
pub(crate) trait JsonKey {
    fn key<I: serde_json::value::Index>(&self, key: I) -> &serde_json::Value;
    fn key_mut(&mut self, key: impl AsRef<str>) -> anyhow::Result<&mut serde_json::Value>;
}
impl JsonKey for serde_json::Value {
    fn key<I: serde_json::value::Index>(&self, key: I) -> &serde_json::Value {
        self.get(key).unwrap_or(&serde_json::Value::Null)
    }
    fn key_mut(&mut self, key: impl AsRef<str>) -> anyhow::Result<&mut serde_json::Value> {
        if self.is_null() {
            *self = serde_json::Value::Object(serde_json::Map::new());
        }
        let object = self
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("JSON 值不是对象: {}", key.as_ref()))?;
        Ok(object
            .entry(key.as_ref())
            .or_insert(serde_json::Value::Null))
    }
}
/// Result-table cell; a short row reads as empty, like the columns it does not have.
pub(crate) trait Row {
    fn cell(&self, column: usize) -> &str;
}
impl Row for [String] {
    fn cell(&self, column: usize) -> &str {
        self.get(column).map_or("", String::as_str)
    }
}
/// Layout regions; a missing one is an empty rectangle that draws nothing.
pub(crate) trait Regions {
    fn rect(&self, index: usize) -> ratatui::layout::Rect;
}
impl Regions for [ratatui::layout::Rect] {
    fn rect(&self, index: usize) -> ratatui::layout::Rect {
        self.get(index).copied().unwrap_or_default()
    }
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
    #[test]
    fn c_strings_stop_at_the_first_nul_or_take_everything() {
        use super::{c_str, c_str_lossy};
        assert_eq!(c_str(b"init\0junk"), b"init");
        assert_eq!(c_str(b"no-nul"), b"no-nul");
        assert_eq!(c_str(b"\0x"), b"");
        assert_eq!(c_str(b""), b"");
        assert_eq!(c_str_lossy(b"a\xffb\0c"), "a\u{fffd}b");
    }
    #[test]
    fn utf16_helpers_drop_or_mark_a_truncated_unit() {
        use super::{utf16_lossy, utf16_lossy_marked, utf16_units};
        assert_eq!(utf16_units(b"a\0b\0c"), vec![0x61, 0x62]);
        assert_eq!(utf16_lossy(b"a\0b\0c"), "ab");
        assert_eq!(utf16_lossy_marked(b"a\0b\0c"), "ab\u{fffd}");
        assert_eq!(utf16_lossy_marked(b"a\0"), "a");
        // An unpaired surrogate stays one replacement character.
        assert_eq!(utf16_lossy(&[0x00, 0xd8, 0x41, 0x00]), "\u{fffd}A");
        assert_eq!(utf16_lossy(&[]), "");
    }
    use super::*;
    #[test]
    fn checked_access_reports_the_caller() {
        let bytes = [1u8, 2, 3];
        assert_eq!(bytes.at(1).ok(), Some(&2));
        assert_eq!(bytes.at(1..).ok(), Some(&[2u8, 3][..]));
        let error = bytes.at(3).err().map(|e| e.to_string()).unwrap_or_default();
        assert!(error.contains("src/bytes.rs"), "{error}");
        assert!("ab".at(5..).is_err());
        assert!("中".at(1..).is_err());
        let mut values = vec![0u8; 2];
        *values.at_mut(1).map_err(|e| e.to_string()).unwrap() = 9;
        assert_eq!(values, [0, 9]);
        assert!(values.at_mut(2).is_err());
    }
    #[test]
    fn json_keys_match_index_reads_and_report_bad_writes() {
        let mut value = serde_json::json!({"a": {"b": 1}, "list": [7]});
        assert_eq!(value.key("a").key("b"), &value["a"]["b"]);
        assert!(value.key("missing").key("deeper").is_null());
        assert_eq!(value.key("list").key(0), &serde_json::json!(7));
        assert!(value.key("list").key(9).is_null());
        let mut empty = serde_json::Value::Null;
        *empty.key_mut("x").map_err(|e| e.to_string()).unwrap() = 1.into();
        assert_eq!(empty, serde_json::json!({"x": 1}));
        assert!(value.key_mut("a").is_ok());
        let mut number = serde_json::json!(1);
        assert!(number.key_mut("x").is_err());
    }
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
