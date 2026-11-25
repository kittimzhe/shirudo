// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The log: each message to syslog under LOG_AUTHPRIV, as `shirudo` with
//! its pid, and normally to stderr, at the priority of err(), warn(),
//! info() or audit(). The stderr copy is omitted when it is the systemd
//! journal stream and syslog is available. A fuzz build makes each line
//! and drops it.

use core::ffi::c_int;
use std::ffi::CString;
use std::os::fd::AsFd;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::sys::libc::{F_OK, access, env, errno, fputs, openlog, set_errno, stderr, syslog};
use crate::util::io::stat_fd;

const LOG_PID: c_int = 0x01;
const LOG_NDELAY: c_int = 0x08;
const LOG_AUTHPRIV: c_int = 10 << 3;
/// The most an escaped message of 8192 bytes takes, with its NUL.
const OUT_MAX: usize = 4 * 8192 + 1;
static TO_STDERR: AtomicBool = AtomicBool::new(true);

fn decimal(raw: &[u8]) -> Option<u64> {
    if raw.is_empty() {
        return None;
    }
    raw.iter().try_fold(0u64, |value, &c| {
        if !c.is_ascii_digit() {
            return None;
        }
        value.checked_mul(10)?.checked_add(u64::from(c - b'0'))
    })
}

/// Whether a JOURNAL_STREAM value names the file at `dev` and `ino`.
fn stream_is(stream: Option<&[u8]>, dev: u64, ino: u64) -> bool {
    let Some(stream) = stream else {
        return false;
    };
    let Some(colon) = stream.iter().position(|&c| c == b':') else {
        return false;
    };

    decimal(&stream[..colon]) == Some(dev) && decimal(&stream[colon + 1..]) == Some(ino)
}

/*
 * systemd connects a service's standard error to the journal and names
 * that stream in JOURNAL_STREAM. A message sent to syslog and written
 * there too is in the journal twice. Without /dev/log syslog drops the
 * message, so the copy on standard error stays then.
 */
fn stderr_repeats_syslog() -> bool {
    let err_stream = std::io::stderr();
    let Ok(st) = stat_fd(err_stream.as_fd()) else {
        return false;
    };
    let dev = libc::makedev(st.stx_dev_major, st.stx_dev_minor);

    stream_is(
        env(c"JOURNAL_STREAM").map(|stream| stream.to_bytes()),
        dev,
        st.stx_ino,
    ) &&
    // SAFETY: a static C string and an existence check.
    unsafe { access(c"/dev/log".as_ptr(), F_OK) } == 0
}

/// Opens syslog for the messages to come.
pub(crate) fn init() {
    // SAFETY: a static name, which syslog keeps.
    unsafe { openlog(c"shirudo".as_ptr(), LOG_PID | LOG_NDELAY, LOG_AUTHPRIV) };
    TO_STDERR.store(!stderr_repeats_syslog(), Ordering::Relaxed);
}

/// `msg` up to its NUL as a line that forges no record and drives no
/// terminal, in at most `cap` bytes with a NUL: printable ASCII kept, a
/// backslash doubled, any other byte a backslash and three octal digits.
/// A message carries text from outside, a registry's error body or a
/// name from a package, and with it escape sequences or line breaks.
pub(crate) fn escape(msg: &[u8], cap: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(msg.len().min(cap));
    for &c in msg.iter().take_while(|&&c| c != 0) {
        if out.len() + 5 > cap {
            break;
        }
        match c {
            b'\\' => out.extend_from_slice(b"\\\\"),
            0x20..0x7f => out.push(c),
            _ => out.extend_from_slice(&[
                b'\\',
                b'0' + (c >> 6),
                b'0' + ((c >> 3) & 7),
                b'0' + (c & 7),
            ]),
        }
    }
    out
}

/// Logs `msg` at syslog priority `priority`, escaped, and leaves errno
/// as it found it: a caller reports a failure and then returns -errno,
/// and syslog and stdio may change it on the way, as without /dev/log in
/// an early initrd.
pub(crate) fn emit(priority: c_int, msg: &[u8]) {
    let saved = errno();
    let line = CString::new(escape(msg, OUT_MAX)).unwrap_or_default();
    if cfg!(shirudo_fuzz) {
        set_errno(saved);
        return;
    }
    // The line and its newline in one fputs(): stderr is unbuffered, so
    // that is one write(), which a write from another thread or process
    // sharing the stream cannot split.
    let out = CString::new([line.as_bytes(), b"\n"].concat()).unwrap_or_default();
    // SAFETY: a "%s" format with a C string.
    unsafe { syslog(priority, c"%s".as_ptr(), line.as_ptr()) };
    if TO_STDERR.load(Ordering::Relaxed) {
        // SAFETY: a C string, and the C library's stderr.
        unsafe { fputs(out.as_ptr(), stderr) };
    }
    set_errno(saved);
}

/// The syslog priorities a message is logged at.
const LOG_ERR: c_int = 3;
const LOG_WARNING: c_int = 4;
const LOG_NOTICE: c_int = 5;
const LOG_INFO: c_int = 6;

/// A failure.
pub(crate) fn err(msg: &[u8]) {
    emit(LOG_ERR, msg);
}

/// What a command goes on without.
pub(crate) fn warn(msg: &[u8]) {
    emit(LOG_WARNING, msg);
}

/// What a command did.
pub(crate) fn info(msg: &[u8]) {
    emit(LOG_INFO, msg);
}

/// What changed the trust state, for the audit trail.
pub(crate) fn audit(msg: &[u8]) {
    emit(LOG_NOTICE, msg);
}

#[cfg(test)]
mod tests {
    use super::stream_is;

    #[test]
    fn stream_names_its_file() {
        assert!(stream_is(Some(b"8:1234"), 8, 1234));
        assert!(stream_is(Some(b"0:0"), 0, 0));
        assert!(stream_is(Some(b"18446744073709551615:1"), u64::MAX, 1));
    }

    #[test]
    fn stream_of_another_file() {
        assert!(!stream_is(Some(b"8:1234"), 8, 1235));
        assert!(!stream_is(Some(b"8:1234"), 9, 1234));
        assert!(!stream_is(Some(b"1234:8"), 8, 1234));
    }

    #[test]
    fn stream_that_is_no_pair_of_numbers() {
        for stream in [
            None,
            Some(&b""[..]),
            Some(&b":"[..]),
            Some(&b"8"[..]),
            Some(&b"8:"[..]),
            Some(&b":1234"[..]),
            Some(&b"8:1234 "[..]),
            Some(&b" 8:1234"[..]),
            Some(&b"8:1234:5"[..]),
            Some(&b"0x8:1234"[..]),
            Some(&b"-8:1234"[..]),
            Some(&b"18446744073709551616:1"[..]),
        ] {
            assert!(!stream_is(stream, 0, 0));
        }
    }
}
