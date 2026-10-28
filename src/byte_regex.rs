//! Bounded PCRE2 byte regular expressions. Compiled code is immutable; match
//! data and contexts are owned per call and never shared with a worker.
use crate::Job;
use anyhow::{Context, Result, bail, ensure};
use pcre2_sys::*;
use std::{
    ops::Range,
    ptr::{self, NonNull},
};
pub const MATCH_LIMIT: u32 = 100_000;
pub const DEPTH_LIMIT: u32 = 1_000;
pub const HEAP_KIB: u32 = 8_192;
pub const WORK_LIMIT: u64 = 10_000_000;
// pcre2-sys does not expose callouts. The block is deliberately opaque: this
// callback uses only its own boxed state and never dereferences the C block.
unsafe extern "C" {
    fn pcre2_set_callout_8(
        context: *mut pcre2_match_context_8,
        callback: Option<
            unsafe extern "C" fn(*mut std::ffi::c_void, *mut std::ffi::c_void) -> std::ffi::c_int,
        >,
        data: *mut std::ffi::c_void,
    ) -> std::ffi::c_int;
}
struct CalloutState {
    remaining: u64,
    cancel: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}
unsafe extern "C" fn callout(
    _block: *mut std::ffi::c_void,
    data: *mut std::ffi::c_void,
) -> std::ffi::c_int {
    // Registered only with a live, exclusively owned Box<CalloutState>. PCRE2
    // invokes callbacks synchronously on this matcher's thread. No unwinding,
    // allocations or user callbacks cross this ABI boundary.
    let state = unsafe { &mut *data.cast::<CalloutState>() };
    if state.remaining == 0
        || state
            .cancel
            .as_ref()
            .is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed))
    {
        return PCRE2_ERROR_CALLOUT;
    }
    state.remaining -= 1;
    0
}

pub struct ByteRegex {
    code: NonNull<pcre2_code_8>,
}
impl Drop for ByteRegex {
    fn drop(&mut self) {
        unsafe { pcre2_code_free_8(self.code.as_ptr()) }
    }
}
fn error(code: i32) -> String {
    let mut bytes = [0u8; 256];
    // PCRE2 writes at most the supplied length, returning bytes excluding NUL.
    let n = unsafe { pcre2_get_error_message_8(code, bytes.as_mut_ptr(), bytes.len()) };
    if n < 0 {
        format!("PCRE2 error {code}")
    } else {
        String::from_utf8_lossy(&bytes[..n as usize]).into_owned()
    }
}
/// Control verbs are PCRE-specific, but escaped parentheses and character
/// classes containing '(' and '*' are ordinary Python byte patterns.
fn reject_control_verbs(pattern: &str) -> Result<()> {
    let bytes = pattern.as_bytes();
    let mut index = 0;
    let mut class = false;
    let mut first = false;
    let mut negate = false;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => {
                index += 2;
                first = false;
                continue;
            }
            b'[' if !class => {
                class = true;
                first = true;
                negate = true;
            }
            b'^' if class && first && negate => {
                negate = false;
            }
            b']' if class && !first => {
                class = false;
            }
            b'(' if !class && bytes.get(index + 1) == Some(&b'*') => {
                anyhow::bail!("不支持 PCRE 专用控制动词；请输入字节正则")
            }
            _ => {
                first = false;
            }
        }
        index += 1;
    }
    Ok(())
}
impl ByteRegex {
    pub fn compile(pattern: &str, dotall: bool) -> Result<Self> {
        ensure!(pattern.len() <= 4096, "正则模式超过 4096 字节");
        reject_control_verbs(pattern)?;
        // Python bytes \Z is strict end-of-subject; PCRE2 spells it \z.
        let mut source = Vec::new();
        let mut bytes = pattern.bytes();
        while let Some(byte) = bytes.next() {
            source.push(byte);
            if byte == b'\\'
                && let Some(next) = bytes.next()
            {
                source.push(if next == b'Z' { b'z' } else { next });
            }
        }
        let length = source.len();
        // Keep a real byte allocated even for an empty pattern, while passing
        // the explicit byte length (embedded NULs remain valid pattern data).
        source.push(0);
        let mut code = 0;
        let mut offset = 0;
        let options = PCRE2_NEVER_UTF
            | PCRE2_NEVER_UCP
            | PCRE2_AUTO_CALLOUT
            | if dotall { PCRE2_DOTALL } else { 0 };
        // Source stays alive for compilation; PCRE2 owns the resulting code.
        let compiled = unsafe {
            pcre2_compile_8(
                source.as_ptr(),
                length,
                options,
                &mut code,
                &mut offset,
                ptr::null_mut(),
            )
        };
        let code = NonNull::new(compiled)
            .with_context(|| format!("正则编译失败 @ {offset}: {}", error(code)))?;
        Ok(Self { code })
    }
    pub fn for_each(
        &self,
        subject: &[u8],
        job: &Job,
        mut visit: impl FnMut(Range<usize>) -> Result<bool>,
    ) -> Result<()> {
        let mut matcher = Matcher::new(self, Some(job))?;
        let mut start = 0;
        let mut after_empty = false;
        loop {
            job.check()?;
            let options = if after_empty {
                PCRE2_NOTEMPTY_ATSTART | PCRE2_ANCHORED
            } else {
                0
            };
            match matcher.find(subject, start, options)? {
                Some(found) => {
                    after_empty = found.is_empty();
                    start = found.end;
                    if !visit(found)? {
                        break;
                    }
                }
                None if after_empty && start < subject.len() => {
                    start += 1;
                    after_empty = false;
                }
                None => break,
            }
        }
        job.check()
    }
    pub fn anchored(&self, subject: &[u8], job: &Job) -> Result<Option<Range<usize>>> {
        Matcher::new(self, Some(job))?.find(subject, 0, PCRE2_ANCHORED)
    }
}
struct MatchData(NonNull<pcre2_match_data_8>);
impl Drop for MatchData {
    fn drop(&mut self) {
        unsafe { pcre2_match_data_free_8(self.0.as_ptr()) }
    }
}
struct MatchContext(NonNull<pcre2_match_context_8>);
impl Drop for MatchContext {
    fn drop(&mut self) {
        unsafe { pcre2_match_context_free_8(self.0.as_ptr()) }
    }
}
struct Matcher<'a> {
    regex: &'a ByteRegex,
    data: MatchData,
    context: MatchContext,
    callout: Box<CalloutState>,
}
impl<'a> Matcher<'a> {
    fn new(regex: &'a ByteRegex, job: Option<&Job>) -> Result<Self> {
        // Allocations use PCRE2's default allocator. RAII frees the first one if
        // any later allocation or configuration fails.
        let data = MatchData(
            NonNull::new(unsafe {
                pcre2_match_data_create_from_pattern_8(regex.code.as_ptr(), ptr::null_mut())
            })
            .context("正则 match data 分配失败")?,
        );
        let context = MatchContext(
            NonNull::new(unsafe { pcre2_match_context_create_8(ptr::null_mut()) })
                .context("正则 context 分配失败")?,
        );
        unsafe {
            ensure!(
                pcre2_set_match_limit_8(context.0.as_ptr(), MATCH_LIMIT) == 0,
                "正则 match limit 设置失败"
            );
            ensure!(
                pcre2_set_depth_limit_8(context.0.as_ptr(), DEPTH_LIMIT) == 0,
                "正则 depth limit 设置失败"
            );
            ensure!(
                pcre2_set_heap_limit_8(context.0.as_ptr(), HEAP_KIB) == 0,
                "正则 heap limit 设置失败"
            );
        }
        let mut callout_state = Box::new(CalloutState {
            remaining: WORK_LIMIT,
            cancel: job.map(|j| std::sync::Arc::clone(&j.cancel)),
        });
        // Moving the Box into Matcher does not move its allocation. It remains
        // alive until after the match context is freed, including error paths.
        unsafe {
            ensure!(
                pcre2_set_callout_8(
                    context.0.as_ptr(),
                    Some(callout),
                    (&mut *callout_state as *mut CalloutState).cast()
                ) == 0,
                "正则 callout 设置失败"
            );
        }
        Ok(Self {
            regex,
            data,
            context,
            callout: callout_state,
        })
    }
    fn find(&mut self, subject: &[u8], start: usize, options: u32) -> Result<Option<Range<usize>>> {
        ensure!(start <= subject.len(), "正则起始位置越界");
        // PCRE2 receives valid buffers for the duration of the call. Each owned
        // match data/context is used by only this matcher; JIT is not enabled.
        let result = unsafe {
            pcre2_match_8(
                self.regex.code.as_ptr(),
                if subject.is_empty() {
                    c"".as_ptr().cast::<u8>()
                } else {
                    subject.as_ptr()
                },
                subject.len(),
                start,
                options,
                self.data.0.as_ptr(),
                self.context.0.as_ptr(),
            )
        };
        if result == PCRE2_ERROR_NOMATCH {
            return Ok(None);
        }
        if result < 0 {
            ensure!(
                !self
                    .callout
                    .cancel
                    .as_ref()
                    .is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed)),
                "任务已取消 / cancelled"
            );
            ensure!(
                self.callout.remaining > 0,
                "正则执行工作计数达到 {WORK_LIMIT} 上限"
            );
            bail!("正则执行失败/资源上限: {}", error(result));
        }
        ensure!(result > 0, "正则 capture vector 不足");
        let vector = unsafe { pcre2_get_ovector_pointer_8(self.data.0.as_ptr()) };
        ensure!(!vector.is_null(), "正则返回空 vector");
        // A successful match has at least one pair, allocated from this pattern.
        let (start, end) = unsafe { (*vector, *vector.add(1)) };
        ensure!(start <= end && end <= subject.len(), "正则匹配范围越界");
        Ok(Some(start..end))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn matches(pattern: &str, bytes: &[u8], dotall: bool) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        ByteRegex::compile(pattern, dotall)
            .unwrap()
            .for_each(bytes, &Job::default(), |r| {
                out.push((r.start, r.end));
                Ok(true)
            })
            .unwrap();
        out
    }
    #[test]
    fn byte_dotall_backreferences_lookarounds_and_python_end_anchor() {
        assert_eq!(
            matches(r"(?<=A)([\xff])\1(?=Z)", b"A\xff\xffZ", true),
            [(1, 3)]
        );
        assert_eq!(matches("a.b", b"a\nb", true), [(0, 3)]);
        assert_eq!(matches("[(*]", b"(*", true), [(0, 1), (1, 2)]);
        assert_eq!(matches(r"\(+", b"((", true), [(0, 2)]);
        assert!(matches("a.b", b"a\nb", false).is_empty());
        assert!(matches(r"a\Z", b"a\n", true).is_empty());
        assert_eq!(matches(r"a$", b"a\n", true), [(0, 1)]);
        assert_eq!(matches(r"(?P<x>ab)(?P=x)", b"abab", true), [(0, 4)]);
    }
    #[test]
    fn empty_matches_allow_nonempty_alternatives_at_the_same_position() {
        assert_eq!(matches("", b"a", true), [(0, 0), (1, 1)]);
        assert_eq!(matches("|a", b"a", true), [(0, 0), (0, 1), (1, 1)]);
        assert_eq!(matches("a*", b"ab", true), [(0, 1), (1, 1), (2, 2)]);
        assert_eq!(
            matches(r"\b", b"ab cd", true),
            [(0, 0), (2, 2), (3, 3), (5, 5)]
        );
    }
    #[test]
    fn foreign_callout_aborts_inside_native_matching_on_work_limit_or_cancellation() {
        let regex = ByteRegex::compile("a+", true).unwrap();
        let mut matcher = Matcher::new(&regex, None).unwrap();
        matcher.callout.remaining = 0;
        assert!(
            matcher
                .find(b"aaa", 0, 0)
                .unwrap_err()
                .to_string()
                .contains("工作计数")
        );
        let job = Job::default();
        let mut matcher = Matcher::new(&regex, Some(&job)).unwrap();
        job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(
            matcher
                .find(b"aaa", 0, 0)
                .unwrap_err()
                .to_string()
                .contains("cancelled")
        );
    }
    #[test]
    fn invalid_patterns_resource_limits_and_cancellation_are_explicit() {
        for pattern in ["(", "(*UTF)a", "(*ACCEPT)", "[^^](*ACCEPT)"] {
            assert!(ByteRegex::compile(pattern, true).is_err());
        }
        let regex = ByteRegex::compile("^(a+)+$", true).unwrap();
        let mut subject = vec![b'a'; 200];
        subject.push(b'!');
        assert!(
            regex
                .for_each(&subject, &Job::default(), |_| Ok(true))
                .is_err()
        );
        let job = Job::default();
        job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(regex.for_each(b"aaa", &job, |_| Ok(true)).is_err());
    }
}
