use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::filesystem::{FilesystemMount, FilesystemProfile};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RuntimeFile {
    pub(super) source: PathBuf,
    pub(super) target: PathBuf,
}

/// Find the command, its script or ELF interpreter, its ELF shared libraries,
/// and the same requirements for the trusted supervisor. This reads ELF data
/// directly and never runs the authorized executable on the host.
pub(super) fn runtime_files(
    executable: &Path,
    supervisor: &Path,
    profile: &FilesystemProfile,
) -> Result<Vec<RuntimeFile>, String> {
    let mut files = BTreeMap::<PathBuf, PathBuf>::new();
    let mut inspected = BTreeSet::<PathBuf>::new();
    let mut pending = VecDeque::from([executable.to_path_buf(), supervisor.to_path_buf()]);
    let default_library_dirs = library_directories();
    let cache = linker_cache();

    while let Some(path) = pending.pop_front() {
        if !inspected.insert(path.clone()) {
            continue;
        }
        let bytes = fs::read(&path).map_err(|error| {
            format!(
                "failed to inspect runtime file '{}': {error}",
                path.display()
            )
        })?;
        if bytes.starts_with(b"#!") {
            let interpreter = parse_shebang(&bytes)
                .map_err(|details| format!("invalid shebang in '{}': {details}", path.display()))?;
            ensure_runtime_interpreter(&interpreter, profile, &default_library_dirs)?;
            insert_runtime_file(&mut files, path.clone(), path.clone())?;
            pending.push_back(interpreter);
            continue;
        }
        if !bytes.starts_with(b"\x7fELF") {
            return Err(format!(
                "runtime file '{}' is neither an ELF executable nor a script with a shebang",
                path.display()
            ));
        }

        let elf = parse_elf(&bytes).map_err(|details| {
            format!("cannot inspect ELF file '{}': {details}", path.display())
        })?;
        insert_runtime_file(&mut files, path.clone(), path.clone())?;
        if let Some(interpreter) = elf.interpreter {
            ensure_runtime_interpreter(&interpreter, profile, &default_library_dirs)?;
            pending.push_back(interpreter);
        }
        let mut search_dirs = Vec::new();
        search_dirs.extend(
            elf.search_dirs
                .iter()
                .map(|entry| expand_origin(entry, &path)),
        );
        search_dirs.retain(|directory| profile_exposes_path(profile, directory));
        search_dirs.extend(default_library_dirs.iter().cloned());
        for needed in elf.needed {
            let dependency = if needed.contains('/') {
                let path = PathBuf::from(&needed);
                if path.is_absolute()
                    && path.is_file()
                    && (trusted_library_path(&path, &default_library_dirs)
                        || profile_exposes_path(profile, &path))
                {
                    path
                } else {
                    return Err(format!(
                        "ELF dependency '{needed}' for '{}' is not an available absolute file",
                        path.display()
                    ));
                }
            } else {
                resolve_library(
                    &needed,
                    &search_dirs,
                    &cache,
                    &default_library_dirs,
                    profile,
                )
                .ok_or_else(|| {
                    format!(
                        "ELF dependency '{needed}' for '{}' is unavailable in the trusted runtime or selected environment",
                        path.display()
                    )
                })?
            };
            pending.push_back(dependency);
        }
    }

    Ok(files
        .into_iter()
        .map(|(target, source)| RuntimeFile { source, target })
        .collect())
}

fn insert_runtime_file(
    files: &mut BTreeMap<PathBuf, PathBuf>,
    target: PathBuf,
    source: PathBuf,
) -> Result<(), String> {
    if !target.is_absolute() || !source.is_absolute() {
        return Err("runtime files must use absolute paths".to_string());
    }
    if let Some(existing) = files.insert(target.clone(), source.clone())
        && existing != source
    {
        return Err(format!(
            "runtime path '{}' maps to conflicting files",
            target.display()
        ));
    }
    Ok(())
}

fn parse_shebang(bytes: &[u8]) -> Result<PathBuf, String> {
    let line_end = bytes
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(bytes.len())
        .min(4096);
    let line = std::str::from_utf8(&bytes[2..line_end])
        .map_err(|_| "interpreter path is not valid UTF-8".to_string())?;
    let interpreter = line.split_ascii_whitespace().next().unwrap_or_default();
    if interpreter.is_empty() || !interpreter.starts_with('/') {
        return Err("interpreter path must be absolute".to_string());
    }
    Ok(PathBuf::from(interpreter))
}

#[derive(Debug)]
struct ElfInfo {
    interpreter: Option<PathBuf>,
    needed: Vec<String>,
    search_dirs: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
struct Segment {
    kind: u32,
    offset: u64,
    virtual_address: u64,
    file_size: u64,
}

fn parse_elf(bytes: &[u8]) -> Result<ElfInfo, String> {
    if bytes.len() < 16 || !bytes.starts_with(b"\x7fELF") {
        return Err("invalid ELF header".to_string());
    }
    let class = bytes[4];
    let little_endian = match bytes[5] {
        1 => true,
        2 => false,
        _ => return Err("unsupported ELF byte order".to_string()),
    };
    let (is_64, phoff_offset, phentsize_offset, phnum_offset) = match class {
        1 => (false, 28, 42, 44),
        2 => (true, 32, 54, 56),
        _ => return Err("unsupported ELF class".to_string()),
    };
    let phoff = read_uint(
        bytes,
        phoff_offset,
        if is_64 { 8 } else { 4 },
        little_endian,
    )?;
    let phentsize = read_uint(bytes, phentsize_offset, 2, little_endian)? as usize;
    let phnum = read_uint(bytes, phnum_offset, 2, little_endian)? as usize;
    if phentsize == 0 || phnum > 4096 {
        return Err("invalid program header table".to_string());
    }
    let mut segments = Vec::with_capacity(phnum);
    for index in 0..phnum {
        let offset = usize::try_from(phoff)
            .ok()
            .and_then(|base| base.checked_add(index.checked_mul(phentsize)?))
            .ok_or_else(|| "program header offset overflow".to_string())?;
        if offset
            .checked_add(phentsize)
            .is_none_or(|end| end > bytes.len())
        {
            return Err("program header extends beyond the ELF file".to_string());
        }
        let kind = read_uint(bytes, offset, 4, little_endian)? as u32;
        let (file_offset, virtual_address, file_size) = if is_64 {
            (
                read_uint(bytes, offset + 8, 8, little_endian)?,
                read_uint(bytes, offset + 16, 8, little_endian)?,
                read_uint(bytes, offset + 32, 8, little_endian)?,
            )
        } else {
            (
                read_uint(bytes, offset + 4, 4, little_endian)?,
                read_uint(bytes, offset + 8, 4, little_endian)?,
                read_uint(bytes, offset + 16, 4, little_endian)?,
            )
        };
        segments.push(Segment {
            kind,
            offset: file_offset,
            virtual_address,
            file_size,
        });
    }

    let mut interpreter = None;
    let mut dynamic = None;
    for segment in &segments {
        match segment.kind {
            2 => dynamic = Some(*segment),
            3 => {
                let start = usize::try_from(segment.offset)
                    .map_err(|_| "interpreter offset overflow".to_string())?;
                let size = usize::try_from(segment.file_size)
                    .map_err(|_| "interpreter size overflow".to_string())?;
                let data = bytes
                    .get(start..start.saturating_add(size))
                    .ok_or_else(|| "interpreter extends beyond the ELF file".to_string())?;
                let end = data
                    .iter()
                    .position(|byte| *byte == 0)
                    .unwrap_or(data.len());
                let value = std::str::from_utf8(&data[..end])
                    .map_err(|_| "interpreter path is not valid UTF-8".to_string())?;
                if !value.is_empty() {
                    interpreter = Some(PathBuf::from(value));
                }
            }
            _ => {}
        }
    }

    let Some(dynamic) = dynamic else {
        return Ok(ElfInfo {
            interpreter,
            needed: Vec::new(),
            search_dirs: Vec::new(),
        });
    };
    let entry_size = if is_64 { 16 } else { 8 };
    let start =
        usize::try_from(dynamic.offset).map_err(|_| "dynamic offset overflow".to_string())?;
    let size =
        usize::try_from(dynamic.file_size).map_err(|_| "dynamic size overflow".to_string())?;
    let data = bytes
        .get(start..start.saturating_add(size))
        .ok_or_else(|| "dynamic table extends beyond the ELF file".to_string())?;
    let mut strtab_address = None;
    let mut strtab_size = None;
    let mut string_entries = Vec::new();
    for entry in data.chunks_exact(entry_size) {
        let tag = read_uint(entry, 0, if is_64 { 8 } else { 4 }, little_endian)? as i64;
        let value = read_uint(
            entry,
            if is_64 { 8 } else { 4 },
            if is_64 { 8 } else { 4 },
            little_endian,
        )?;
        match tag {
            0 => break,
            1 | 15 | 29 => string_entries.push((tag, value)),
            5 => strtab_address = Some(value),
            10 => strtab_size = Some(value),
            _ => {}
        }
    }
    let mut needed = Vec::new();
    let mut search_dirs = Vec::new();
    if !string_entries.is_empty() {
        let address = strtab_address.ok_or_else(|| "missing ELF string table".to_string())?;
        let string_table_offset = segments
            .iter()
            .filter(|segment| segment.kind == 1)
            .find_map(|segment| {
                let end = segment.virtual_address.checked_add(segment.file_size)?;
                (address >= segment.virtual_address && address < end)
                    .then(|| {
                        segment
                            .offset
                            .checked_add(address - segment.virtual_address)
                    })
                    .flatten()
            })
            .ok_or_else(|| "ELF string table is outside loadable segments".to_string())?;
        let offset = usize::try_from(string_table_offset)
            .map_err(|_| "ELF string table offset overflow".to_string())?;
        let available = bytes
            .get(offset..)
            .ok_or_else(|| "ELF string table extends beyond the file".to_string())?;
        let table_size = strtab_size
            .and_then(|size| usize::try_from(size).ok())
            .unwrap_or(available.len())
            .min(available.len());
        let table = &available[..table_size];
        for (tag, value) in string_entries {
            let index =
                usize::try_from(value).map_err(|_| "ELF string offset overflow".to_string())?;
            let tail = table
                .get(index..)
                .ok_or_else(|| "ELF string offset is outside the string table".to_string())?;
            let end = tail
                .iter()
                .position(|byte| *byte == 0)
                .ok_or_else(|| "unterminated ELF string".to_string())?;
            let value = std::str::from_utf8(&tail[..end])
                .map_err(|_| "ELF string is not valid UTF-8".to_string())?;
            if tag == 1 {
                needed.push(value.to_string());
            } else {
                search_dirs.extend(
                    value
                        .split(':')
                        .filter(|entry| !entry.is_empty())
                        .map(str::to_string),
                );
            }
        }
    }

    Ok(ElfInfo {
        interpreter,
        needed,
        search_dirs,
    })
}

fn read_uint(
    bytes: &[u8],
    offset: usize,
    width: usize,
    little_endian: bool,
) -> Result<u64, String> {
    let value = bytes
        .get(offset..offset.saturating_add(width))
        .ok_or_else(|| "truncated ELF structure".to_string())?;
    let mut result = 0u64;
    if little_endian {
        for (index, byte) in value.iter().enumerate() {
            result |= u64::from(*byte) << (index * 8);
        }
    } else {
        for byte in value {
            result = result
                .checked_shl(8)
                .ok_or_else(|| "ELF integer overflow".to_string())?
                | u64::from(*byte);
        }
    }
    Ok(result)
}

fn expand_origin(value: &str, binary: &Path) -> PathBuf {
    let origin = binary.parent().unwrap_or_else(|| Path::new("/"));
    PathBuf::from(
        value
            .replace("${ORIGIN}", &origin.to_string_lossy())
            .replace("$ORIGIN", &origin.to_string_lossy()),
    )
}

fn ensure_runtime_interpreter(
    interpreter: &Path,
    profile: &FilesystemProfile,
    trusted_dirs: &[PathBuf],
) -> Result<(), String> {
    if trusted_interpreter_path(interpreter, trusted_dirs)
        || profile_exposes_path(profile, interpreter)
    {
        Ok(())
    } else {
        Err(format!(
            "interpreter '{}' is outside the trusted runtime and selected filesystem profile",
            interpreter.display()
        ))
    }
}

fn profile_exposes_path(profile: &FilesystemProfile, path: &Path) -> bool {
    let Ok(path) = fs::canonicalize(path) else {
        return false;
    };
    profile.mounts.iter().any(|mount| {
        let FilesystemMount::Bind { source, .. } = mount else {
            return false;
        };
        fs::canonicalize(source).is_ok_and(|source| path.starts_with(source))
    })
}

fn trusted_library_path(path: &Path, trusted_dirs: &[PathBuf]) -> bool {
    trusted_dirs
        .iter()
        .any(|directory| path.starts_with(directory))
}

fn trusted_interpreter_path(path: &Path, library_dirs: &[PathBuf]) -> bool {
    trusted_library_path(path, library_dirs)
        || ["/bin", "/usr/bin", "/sbin", "/usr/sbin"]
            .into_iter()
            .map(Path::new)
            .any(|directory| path.starts_with(directory))
}

fn library_directories() -> Vec<PathBuf> {
    let mut directories = vec![
        "/lib".into(),
        "/lib64".into(),
        "/usr/lib".into(),
        "/usr/lib64".into(),
        "/lib/x86_64-linux-gnu".into(),
        "/usr/lib/x86_64-linux-gnu".into(),
        "/lib/aarch64-linux-gnu".into(),
        "/usr/lib/aarch64-linux-gnu".into(),
    ];
    for config in [Path::new("/etc/ld.so.conf"), Path::new("/etc/ld.so.conf.d")] {
        if config.is_file() {
            if let Ok(contents) = fs::read_to_string(config) {
                directories.extend(
                    contents
                        .lines()
                        .map(str::trim)
                        .filter(|line| line.starts_with('/') && Path::new(line).is_dir())
                        .map(PathBuf::from),
                );
            }
        } else if config.is_dir()
            && let Ok(entries) = fs::read_dir(config)
        {
            for entry in entries.flatten() {
                if let Ok(contents) = fs::read_to_string(entry.path()) {
                    directories.extend(
                        contents
                            .lines()
                            .map(str::trim)
                            .filter(|line| line.starts_with('/') && Path::new(line).is_dir())
                            .map(PathBuf::from),
                    );
                }
            }
        }
    }
    directories.sort();
    directories.dedup();
    directories
}

fn linker_cache() -> BTreeMap<String, Vec<PathBuf>> {
    let executable = ["/sbin/ldconfig", "/usr/sbin/ldconfig"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.is_file());
    let Some(executable) = executable else {
        return BTreeMap::new();
    };
    let Ok(output) = Command::new(executable).arg("-p").env_clear().output() else {
        return BTreeMap::new();
    };
    let mut result = BTreeMap::<String, Vec<PathBuf>>::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let Some((name, location)) = line.split_once("=>") else {
            continue;
        };
        let name = name.split_ascii_whitespace().next().unwrap_or_default();
        let location = location.trim();
        if !name.is_empty() && Path::new(location).is_absolute() {
            result
                .entry(name.to_string())
                .or_default()
                .push(PathBuf::from(location));
        }
    }
    result
}

fn resolve_library(
    name: &str,
    search_dirs: &[PathBuf],
    cache: &BTreeMap<String, Vec<PathBuf>>,
    trusted_dirs: &[PathBuf],
    profile: &FilesystemProfile,
) -> Option<PathBuf> {
    for directory in search_dirs {
        let candidate = directory.join(name);
        if candidate.is_file()
            && (trusted_library_path(&candidate, trusted_dirs)
                || profile_exposes_path(profile, &candidate))
        {
            return Some(candidate);
        }
    }
    cache.get(name).and_then(|paths| {
        paths
            .iter()
            .find(|path| path.is_file() && trusted_library_path(path, trusted_dirs))
            .cloned()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovers_a_real_elf_runtime_and_script_interpreter() {
        let profile = FilesystemProfile {
            name: "minimal".to_string(),
            mounts: Vec::new(),
        };
        let runtime = runtime_files(Path::new("/usr/bin/true"), Path::new("/bin/sh"), &profile)
            .expect("system commands have inspectable runtimes");
        assert!(
            runtime
                .iter()
                .any(|file| file.target == Path::new("/usr/bin/true"))
        );
        assert!(
            runtime
                .iter()
                .any(|file| file.target == Path::new("/bin/sh"))
        );
        assert!(
            runtime
                .iter()
                .any(|file| file.target.to_string_lossy().contains("libc.so"))
        );
    }

    #[test]
    fn parses_absolute_shebang_interpreters() {
        assert_eq!(
            parse_shebang(b"#!/bin/sh -e\necho ok\n").unwrap(),
            PathBuf::from("/bin/sh")
        );
        assert!(parse_shebang(b"#!/usr/bin/env python\n").is_ok());
        assert!(parse_shebang(b"#!python\n").is_err());
    }
}
