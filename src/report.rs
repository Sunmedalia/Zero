//! Formatting and diagnostics shared by every analysis engine.
use crate::store::Results;
use std::fmt::Display;

/// Fixed-width kernel address as rendered in every result column.
pub(crate) fn hex(value: u64) -> String {
    format!("{value:#018x}")
}
/// Mark a result partial and record why; `error` keeps its full context chain.
pub(crate) fn partial(result: &mut Results, context: impl Display, error: anyhow::Error) {
    result.complete = false;
    result.diagnostics.push(format!("{context}: {error:#}"));
}

/// `YYYY-MM-DD HH:MM:SS UTC` for Unix seconds, without a time-zone database.
pub(crate) fn utc(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let time = seconds.rem_euclid(86_400);
    // Howard Hinnant's civil-from-days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        time / 3600,
        time % 3600 / 60,
        time % 60
    )
}

#[cfg(test)]
mod utc_tests {
    #[test]
    fn utc_formats_epoch_leap_days_and_pre_epoch() {
        assert_eq!(super::utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(super::utc(951_782_400), "2000-02-29 00:00:00 UTC");
        assert_eq!(super::utc(1_700_000_000), "2023-11-14 22:13:20 UTC");
        assert_eq!(super::utc(-1), "1969-12-31 23:59:59 UTC");
    }
}
