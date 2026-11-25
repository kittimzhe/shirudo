// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The identity init froze into the kernel this boot, read back from the
//! map it pinned in the private bpffs, and whether the boot enforces.

use core::ffi::{CStr, c_int};

use crate::errno::{EINVAL, ENOSYS, EPROTO};
use crate::sys::identity::Identity;
use crate::sys::libc::{close, errno, prctl};
use crate::util::bpf_info::{Info, MAP_INFO_SIZE, MAP_VALUE_SIZE};
use crate::util::bpf_sys::{bpf_map_lookup_elem, bpf_obj_get};

/// IDENTITY_PIN of util/paths.h.
pub(crate) const IDENTITY_PIN: &CStr = c"/run/shirudo/bpffs/identity";
/// PR_GET_ENFORCEMENT and PR_ENFORCING_ERR of include/shirudo/enforcement.h.
const PR_GET_ENFORCEMENT: c_int = 0x5352_0001;
const PR_ENFORCING_ERR: c_int = 1002;
/// Whether a 16-byte kernel BPF object name is the complete expected
/// name, or the kernel's 15-byte truncation of it.
pub(crate) fn guard_name_matches(name: &[u8], expected: &CStr) -> bool {
    let Some(name) = name.get(..16) else {
        return false;
    };
    let Some(len) = name.iter().position(|&c| c == 0) else {
        return false;
    };
    let expected = expected.to_bytes();
    let expected_len = expected.len().min(15);

    len == expected_len && name[..len] == expected[..expected_len]
}

/// Whether this boot enforces, as the kernel's prctl answers: 1, 0 for a
/// kernel that does not know the question, or -errno.
pub(crate) fn enforcement_active() -> c_int {
    // SAFETY: a query that takes no pointer.
    if unsafe { prctl(PR_GET_ENFORCEMENT, 0, 0, 0, 0) } >= 0 {
        return -EPROTO;
    }
    match errno() {
        PR_ENFORCING_ERR => 1,
        EINVAL | ENOSYS => 0,
        e => -e,
    }
}

/// The identity init populated, froze and pinned this boot into `out`,
/// which is zeroed first: 0, -ENOENT before init, -EPROTO for a map of
/// another shape, or another -errno.
pub(crate) fn read(out: &mut Identity) -> c_int {
    *out = Identity::zeroed();
    // SAFETY: a C string.
    let fd = unsafe { bpf_obj_get(IDENTITY_PIN.as_ptr()) };
    if fd < 0 {
        return -errno();
    }
    let ret = lookup(fd, out);
    // SAFETY: the pin opened above.
    unsafe { close(fd) };
    ret
}

fn lookup(fd: c_int, out: &mut Identity) -> c_int {
    let mut info = Info::<MAP_INFO_SIZE>::new();
    if let Err(err) = info.read(fd) {
        return err;
    }
    if info.u32_at(MAP_VALUE_SIZE) as usize != size_of::<Identity>() {
        return -EPROTO;
    }
    let zero = 0u32;
    // SAFETY: the map, a key of its size, and room for a value of its
    // size, checked above.
    if unsafe {
        bpf_map_lookup_elem(
            fd,
            (&raw const zero).cast(),
            core::ptr::from_mut(out).cast(),
        )
    } != 0
    {
        return -errno();
    }
    0
}

#[cfg(test)]
mod tests {
    use super::guard_name_matches;

    fn kernel_name(raw: &[u8]) -> [u8; 16] {
        let mut name = [0u8; 16];
        name[..raw.len()].copy_from_slice(raw);
        name
    }

    #[test]
    fn kernel_name_is_the_start_of_a_long_one() {
        let name = kernel_name(b"shirudo_bpffs_s");

        assert!(guard_name_matches(&name, c"shirudo_bpffs_sb"));
        assert!(guard_name_matches(&name, c"shirudo_bpffs_s"));
        assert!(guard_name_matches(&name, c"shirudo_bpffs_s_and_more"));
        assert!(!guard_name_matches(&name, c"shirudo_bpffs_"));
        assert!(!guard_name_matches(&name, c"shirudo_bpffs_x"));
        assert!(!guard_name_matches(&name, c""));
    }

    #[test]
    fn short_name_is_the_whole_one() {
        let name = kernel_name(b"shirudo_tasks");

        assert!(guard_name_matches(&name, c"shirudo_tasks"));
        assert!(!guard_name_matches(&name, c"shirudo_task"));
        assert!(!guard_name_matches(&name, c"shirudo_tasks_"));
        assert!(!guard_name_matches(&name, c"shirudo_task_policy"));
        assert!(!guard_name_matches(&name, c"SHIRUDO_TASKS"));
    }

    #[test]
    fn unterminated_name_matches_nothing() {
        let name = [b'x'; 16];

        assert!(!guard_name_matches(&name, c"xxxxxxxxxxxxxxx"));
        assert!(!guard_name_matches(&name, c"xxxxxxxxxxxxxxxx"));
        assert!(guard_name_matches(&[0; 16], c""));
        assert!(!guard_name_matches(&[0; 16], c"x"));
    }
}
