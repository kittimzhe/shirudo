// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The Java agents a target runs: sealed jars of loaded Java upatches,
//! and the environment.d file that names them to future JVMs.

use core::ffi::c_int;
use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

use crate::errno::{E2BIG, EFBIG, EINVAL, EIO, ENAMETOOLONG, ENOENT, EPERM, ESTALE};
use crate::sys::libc::PATH_MAX;
use crate::util::io;
use crate::util::seal;
use crate::util::upatch::{self, FILE_MAX, TYPE_JAVA, Upatch};
use crate::util::upatch_pins::PAYLOAD_HASH_LEN;

pub(crate) const JAVA_DIR: &[u8] = b"/run/shirudo-java";
const JAVA_DIR_ENTRY: &[u8] = b"/run/shirudo-java/.";
const JAVA_ENV_DIR: &[u8] = b"/run/environment.d";
const JAVA_ENV_PATH: &CStr = c"/run/environment.d/shirudo.conf";
const UPATCHES_DIR: &[u8] = b"/var/lib/shirudo/upatches";
const JAVA_OPTIONS_MAX: usize = 64 * 1024;

// A Java 8 agent with an empty premain. A user manager started before an
// unload keeps naming the jar, and a missing or non-agent jar would keep
// a later JVM from starting.
const PLACEHOLDER: &[u8] = b"\x50\x4b\x03\x04\x14\x00\x00\x00\x00\x00\x00\x00\x21\x00\x6d\x6f\x09\xd7\x3a\x00\x00\x00\x3a\x00\x00\x00\x14\x00\x00\x00\x4d\x45\x54\x41\x2d\x49\x4e\x46\x2f\x4d\x41\x4e\x49\x46\x45\x53\x54\x2e\x4d\x46\x4d\x61\x6e\x69\x66\x65\x73\x74\x2d\x56\x65\x72\x73\x69\x6f\x6e\x3a\x20\x31\x2e\x30\x0d\x0a\x50\x72\x65\x6d\x61\x69\x6e\x2d\x43\x6c\x61\x73\x73\x3a\x20\x73\x68\x69\x72\x75\x64\x6f\x2e\x55\x6e\x6c\x6f\x61\x64\x65\x64\x0d\x0a\x0d\x0a\x50\x4b\x03\x04\x14\x00\x00\x00\x00\x00\x00\x00\x21\x00\xbc\xe2\x68\x5c\xc0\x00\x00\x00\xc0\x00\x00\x00\x16\x00\x00\x00\x73\x68\x69\x72\x75\x64\x6f\x2f\x55\x6e\x6c\x6f\x61\x64\x65\x64\x2e\x63\x6c\x61\x73\x73\xca\xfe\xba\xbe\x00\x00\x00\x34\x00\x0c\x0a\x00\x02\x00\x03\x07\x00\x04\x0c\x00\x05\x00\x06\x01\x00\x10\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x4f\x62\x6a\x65\x63\x74\x01\x00\x06\x3c\x69\x6e\x69\x74\x3e\x01\x00\x03\x28\x29\x56\x07\x00\x08\x01\x00\x10\x73\x68\x69\x72\x75\x64\x6f\x2f\x55\x6e\x6c\x6f\x61\x64\x65\x64\x01\x00\x04\x43\x6f\x64\x65\x01\x00\x07\x70\x72\x65\x6d\x61\x69\x6e\x01\x00\x15\x28\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x53\x74\x72\x69\x6e\x67\x3b\x29\x56\x00\x31\x00\x07\x00\x02\x00\x00\x00\x00\x00\x02\x00\x01\x00\x05\x00\x06\x00\x01\x00\x09\x00\x00\x00\x11\x00\x01\x00\x01\x00\x00\x00\x05\x2a\xb7\x00\x01\xb1\x00\x00\x00\x00\x00\x09\x00\x0a\x00\x0b\x00\x01\x00\x09\x00\x00\x00\x0d\x00\x00\x00\x01\x00\x00\x00\x01\xb1\x00\x00\x00\x00\x00\x00\x50\x4b\x01\x02\x14\x03\x14\x00\x00\x00\x00\x00\x00\x00\x21\x00\x6d\x6f\x09\xd7\x3a\x00\x00\x00\x3a\x00\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa4\x01\x00\x00\x00\x00\x4d\x45\x54\x41\x2d\x49\x4e\x46\x2f\x4d\x41\x4e\x49\x46\x45\x53\x54\x2e\x4d\x46\x50\x4b\x01\x02\x14\x03\x14\x00\x00\x00\x00\x00\x00\x00\x21\x00\xbc\xe2\x68\x5c\xc0\x00\x00\x00\xc0\x00\x00\x00\x16\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa4\x01\x6c\x00\x00\x00\x73\x68\x69\x72\x75\x64\x6f\x2f\x55\x6e\x6c\x6f\x61\x64\x65\x64\x2e\x63\x6c\x61\x73\x73\x50\x4b\x05\x06\x00\x00\x00\x00\x02\x00\x02\x00\x86\x00\x00\x00\x60\x01\x00\x00\x00\x00";

fn io_errno(e: &std::io::Error) -> c_int {
    -e.raw_os_error().unwrap_or(EIO)
}

fn path_of(parts: &[&[u8]]) -> Result<CString, c_int> {
    let path = parts.concat();
    if path.len() >= PATH_MAX {
        return Err(-ENAMETOOLONG);
    }
    CString::new(path).map_err(|_| -EINVAL)
}

pub(crate) fn agent_path(name: &[u8]) -> Result<CString, c_int> {
    path_of(&[JAVA_DIR, b"/", name, b".jar"])
}

fn archive_path(name: &[u8]) -> Result<CString, c_int> {
    path_of(&[UPATCHES_DIR, b"/", name, b".upatch"])
}

fn set_mode(path: &[u8], mode: u32) -> Result<(), c_int> {
    std::fs::set_permissions(
        OsStr::from_bytes(path),
        std::fs::Permissions::from_mode(mode),
    )
    .map_err(|e| io_errno(&e))
}

fn dir_check() -> Result<(), c_int> {
    let st = std::fs::symlink_metadata(OsStr::from_bytes(JAVA_DIR)).map_err(|e| io_errno(&e))?;
    if !st.file_type().is_dir()
        || st.uid() != 0
        || st.mode() & 0o022 != 0
        || !seal::parent_labeled(JAVA_DIR_ENTRY)
    {
        return Err(-EPERM);
    }
    Ok(())
}

/// Prepare the sealed directory that holds installed Java agents.
pub(crate) fn dir_prepare() -> Result<(), c_int> {
    let made = match std::fs::DirBuilder::new()
        .mode(0o755)
        .create(OsStr::from_bytes(JAVA_DIR))
    {
        Ok(()) => true,
        Err(e) if e.raw_os_error() == Some(crate::errno::EEXIST) => return dir_check(),
        Err(e) => return Err(io_errno(&e)),
    };
    debug_assert!(made);
    let path = CString::new(JAVA_DIR).map_err(|_| -EINVAL)?;
    let prepared = set_mode(JAVA_DIR, 0o755).and_then(|()| seal::label(&path));
    if let Err(err) = prepared {
        let _ = std::fs::remove_dir(OsStr::from_bytes(JAVA_DIR));
        return Err(err);
    }
    Ok(())
}

/// Install the signed jar of a Java upatch under `name`.
pub(crate) fn install(name: &[u8], jar: &[u8]) -> Result<(), c_int> {
    let path = agent_path(name)?;
    dir_prepare()?;
    seal::write_file_mode(path.to_bytes(), jar, 0o644)
}

fn jar_installed(name: &[u8], jar: &[u8]) -> Result<bool, c_int> {
    let path = agent_path(name)?;
    let fd = match seal::open_read(path.to_bytes()) {
        Ok(fd) => fd,
        Err(err) if err == -ENOENT => return Ok(false),
        Err(err) => return Err(err),
    };
    let file = File::from(fd);
    let have = io::read_whole(file.as_fd(), FILE_MAX)?;
    Ok(have == jar)
}

/// Replace an installed agent with the harmless placeholder, leaving
/// paths inherited by an older user manager valid.
pub(crate) fn retire(name: &[u8]) -> Result<(), c_int> {
    let path = agent_path(name)?;
    match std::fs::metadata(OsStr::from_bytes(path.to_bytes())) {
        Ok(_) => {}
        Err(e) if e.raw_os_error() == Some(ENOENT) => return Ok(()),
        Err(e) => return Err(io_errno(&e)),
    }
    if jar_installed(name, PLACEHOLDER)? {
        return Ok(());
    }
    seal::write_file_mode(path.to_bytes(), PLACEHOLDER, 0o644)
}

fn archive_open(name: &[u8]) -> Result<Upatch<'static>, c_int> {
    let path = archive_path(name)?;
    let file = File::from(seal::open_read(path.to_bytes())?);
    Upatch::read(&file)
}

fn archived_java(name: &[u8]) -> Result<Option<Upatch<'static>>, c_int> {
    match archive_open(name) {
        Ok(u) if u.hdr.ty == TYPE_JAVA && !u.is_unload() => Ok(Some(u)),
        Ok(_) => Ok(None),
        Err(err) if [-ENOENT, -EPERM, -EINVAL, -EFBIG].contains(&err) => Ok(None),
        Err(err) => Err(err),
    }
}

/// The digest of the archived Java load when its signed jar is the one
/// installed under `name`.
pub(crate) fn payload(name: &[u8]) -> Result<[u8; PAYLOAD_HASH_LEN], c_int> {
    let u = archived_java(name)?.ok_or(-ENOENT)?;
    let jar = u.signed_jar().ok_or(-ENOENT)?;
    if !jar_installed(name, jar)? {
        return Err(-ESTALE);
    }
    Ok(u.hdr.payload_sha256)
}

pub(crate) fn loaded(name: &[u8]) -> bool {
    payload(name).is_ok()
}

fn jar_files() -> Result<Vec<Vec<u8>>, c_int> {
    match io::dir_names(JAVA_DIR, |name| name.ends_with(b".jar")) {
        Ok(names) => Ok(names),
        Err(err) if err == -ENOENT => Ok(Vec::new()),
        Err(err) => Err(err),
    }
}

fn jar_name(file: &[u8]) -> &[u8] {
    &file[..file.len() - b".jar".len()]
}

/// Call `cb` for each installed, archive-backed Java agent in bytewise
/// name order.
pub(crate) fn each_loaded(cb: &mut dyn FnMut(&[u8], &[u8; PAYLOAD_HASH_LEN]) -> c_int) -> c_int {
    let files = match jar_files() {
        Ok(files) => files,
        Err(err) => return err,
    };
    for file in files {
        let name = jar_name(&file);
        if !upatch::name_valid(Some(name)) {
            continue;
        }
        let Ok(payload) = payload(name) else {
            continue;
        };
        let ret = cb(name, &payload);
        if ret != 0 {
            return ret;
        }
    }
    0
}

/// An installed Java agent's name.
type Named<'a> = &'a mut dyn FnMut(&[u8]) -> c_int;

/// Count jars that are neither the placeholder nor backed by a matching
/// Java archive. When present, `cb` runs for each one in name order.
pub(crate) fn unbacked(mut cb: Option<Named<'_>>) -> c_int {
    let files = match jar_files() {
        Ok(files) => files,
        Err(err) => return err,
    };
    let mut count = 0;
    for file in files {
        let name = jar_name(&file);
        if !upatch::name_valid(Some(name)) {
            continue;
        }
        match jar_installed(name, PLACEHOLDER) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(err) => return err,
        }
        if loaded(name) {
            continue;
        }
        count += 1;
        if let Some(f) = cb.as_deref_mut() {
            let ret = f(name);
            if ret != 0 {
                return ret;
            }
        }
    }
    count
}

fn tool_options(names: &[Vec<u8>], cap: usize) -> Result<Vec<u8>, c_int> {
    let mut out = b"JAVA_TOOL_OPTIONS=\"${JAVA_TOOL_OPTIONS:+$JAVA_TOOL_OPTIONS }".to_vec();
    for (i, name) in names.iter().enumerate() {
        if i != 0 {
            out.push(b' ');
        }
        out.extend_from_slice(b"-javaagent:");
        out.extend_from_slice(JAVA_DIR);
        out.push(b'/');
        out.extend_from_slice(name);
        out.extend_from_slice(b".jar");
    }
    out.extend_from_slice(b"\"\n");
    if out.len() >= cap {
        return Err(-E2BIG);
    }
    Ok(out)
}

fn options_current(want: &[u8]) -> bool {
    io::read(JAVA_ENV_PATH, JAVA_OPTIONS_MAX).is_ok_and(|have| have == want)
}

fn env_dir_prepare() -> Result<(), c_int> {
    match std::fs::DirBuilder::new()
        .mode(0o755)
        .create(OsStr::from_bytes(JAVA_ENV_DIR))
    {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(crate::errno::EEXIST) => {}
        Err(e) => return Err(io_errno(&e)),
    }
    set_mode(JAVA_ENV_DIR, 0o755)
}

fn write_options(names: &[Vec<u8>]) -> Result<(), c_int> {
    if names.is_empty() {
        return match std::fs::remove_file(OsStr::from_bytes(JAVA_ENV_PATH.to_bytes())) {
            Ok(()) => Ok(()),
            Err(e) if e.raw_os_error() == Some(ENOENT) => Ok(()),
            Err(e) => Err(io_errno(&e)),
        };
    }
    let want = tool_options(names, JAVA_OPTIONS_MAX)?;
    if options_current(&want) {
        return Ok(());
    }
    env_dir_prepare()?;
    seal::write_file_mode(JAVA_ENV_PATH.to_bytes(), &want, 0o644)
}

/// Bring installed jars and JAVA_TOOL_OPTIONS in line with the sealed
/// archive set. Passing archive errors keep the jar named, so a measured
/// agent is never silently removed.
pub(crate) fn sync() -> Result<(), c_int> {
    let files = jar_files()?;
    let mut names = Vec::new();
    let mut jar_err = 0;
    for file in files {
        let name = jar_name(&file);
        let archived = if upatch::name_valid(Some(name)) {
            archived_java(name)
        } else {
            Ok(None)
        };
        match archived {
            Ok(Some(_)) => names.push(name.to_vec()),
            Err(err) => {
                names.push(name.to_vec());
                if jar_err == 0 {
                    jar_err = err;
                }
            }
            Ok(None) => {
                if let Err(err) = retire(name)
                    && jar_err == 0
                {
                    jar_err = err;
                }
            }
        }
    }
    let written = write_options(&names);
    if jar_err != 0 { Err(jar_err) } else { written }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_paths_are_exact_and_bounded() {
        assert_eq!(
            agent_path(b"watch").unwrap().to_bytes(),
            b"/run/shirudo-java/watch.jar"
        );
        assert_eq!(
            agent_path(&vec![b'a'; PATH_MAX]).unwrap_err(),
            -ENAMETOOLONG
        );
    }

    #[test]
    fn options_name_agents_in_order() {
        let names = vec![b"alpha".to_vec(), b"omega".to_vec()];
        assert_eq!(
            tool_options(&names, JAVA_OPTIONS_MAX).unwrap(),
            b"JAVA_TOOL_OPTIONS=\"${JAVA_TOOL_OPTIONS:+$JAVA_TOOL_OPTIONS }-javaagent:/run/shirudo-java/alpha.jar -javaagent:/run/shirudo-java/omega.jar\"\n"
        );
    }

    #[test]
    fn options_need_room_for_a_nul() {
        let names = vec![b"agent".to_vec()];
        let options = tool_options(&names, JAVA_OPTIONS_MAX).unwrap();
        assert_eq!(tool_options(&names, options.len()).unwrap_err(), -E2BIG);
        assert_eq!(tool_options(&names, options.len() + 1).unwrap(), options);
        assert_eq!(tool_options(&names, 4).unwrap_err(), -E2BIG);
    }

    #[test]
    fn one_agent_has_no_leading_separator() {
        let names = vec![b"agent".to_vec()];
        assert_eq!(
            tool_options(&names, JAVA_OPTIONS_MAX).unwrap(),
            b"JAVA_TOOL_OPTIONS=\"${JAVA_TOOL_OPTIONS:+$JAVA_TOOL_OPTIONS }-javaagent:/run/shirudo-java/agent.jar\"\n"
        );
    }

    #[test]
    fn agent_without_archive_is_not_loaded() {
        assert!(!loaded(b"shirudo-unit-no-such-upatch"));
    }
}
