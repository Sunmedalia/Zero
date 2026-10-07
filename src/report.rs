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
