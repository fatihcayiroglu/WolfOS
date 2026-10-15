//! Build an actual standalone x86-64 ELF application for the isolated
//! Ring3 QEMU test, never for the normal kernel flavor.
//!
//! Uses GNU binutils from the CI toolchain. The checked independent ELF is
//! embedded as a file blob by include_bytes!(OUT_DIR), NOT as hand-copied
//! machine opcodes inside the kernel. All ELF headers and segment bytes
//! are checked again by the real WolfOS ELF preflight at runtime.
use std::{env, fs, path::PathBuf, process::Command};

fn checked(program: &str, args: &[&str]) {
    let status = Command::new(program).args(args).status()
        .unwrap_or_else(|e| panic!("unable to invoke {program}: {e}"));
    assert!(status.success(), "{program} returned {status}");
}
fn nm_symbol(output: &str, name: &str) -> u64 {
    let matches: Vec<u64> = output.lines().filter_map(|line| {
        let pieces: Vec<&str> = line.split_whitespace().collect();
        if pieces.len() == 3 && pieces[2] == name {
            u64::from_str_radix(pieces[0], 16).ok()
        } else { None }
    }).collect();
    assert_eq!(matches.len(), 1, "missing or ambiguous ELF symbol {name}");
    matches[0]
}

fn main() {
    println!("cargo:rerun-if-changed=user/hello.S");
    println!("cargo:rerun-if-changed=user/hello.ld");
    if env::var_os("CARGO_FEATURE_USER_ELF_RUN_SMOKE").is_none()
        && env::var_os("CARGO_FEATURE_USER_PROCESS_SMOKE").is_none()
        && env::var_os("CARGO_FEATURE_USER_RAMFS_SMOKE").is_none()
        && env::var_os("CARGO_FEATURE_USER_VFS_SMOKE").is_none()
        && env::var_os("CARGO_FEATURE_USER_FILE_IO_SMOKE").is_none() {
        return;
    }
    let path = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    fs::create_dir_all(&path).expect("make OUT_DIR");
    let obj = path.join("wolfos-user-hello.o");
    let elf = path.join("wolfos-user-hello.elf");
    if env::var_os("CARGO_FEATURE_USER_FILE_IO_SMOKE").is_some() {
        checked("as", &["--64", "--defsym", "WOLFOS_FILE_IO=1",
            "-o", obj.to_str().unwrap(), "user/hello.S"]);
    } else {
        checked("as", &["--64", "-o", obj.to_str().unwrap(), "user/hello.S"]);
    }
    checked("ld", &["-m", "elf_x86_64", "-nostdlib", "-static",
        "-T", "user/hello.ld", "-o", elf.to_str().unwrap(),
        obj.to_str().unwrap()]);
    let out = Command::new("nm").arg("-n").arg(&elf)
        .output().expect("nm missing");
    assert!(out.status.success(), "nm ELF symbol scan failed");
    let output = String::from_utf8(out.stdout).expect("bad nm output");
    let symbols = [
        ("_start", "ENTRY"), ("_after_id", "AFTER_ID"),
        ("_after_add", "AFTER_ADD"),
        ("_after_putc", "AFTER_PUTC"),
        ("_after_exit", "AFTER_EXIT"),
        ("hello_text", "HELLO_TEXT"),
        ("hello_end", "HELLO_END"),
        ("fixture_magic", "FIXTURE_MAGIC"),
        ("uninitialized", "BSS_START"),
    ];
    let mut generated = String::new();
    let file_symbols = [
        ("_after_file_open", "AFTER_FILE_OPEN"),
        ("_after_file_read", "AFTER_FILE_READ"),
        ("_after_file_bad_read", "AFTER_FILE_BAD_READ"),
        ("_after_file_close", "AFTER_FILE_CLOSE"),
        ("_after_file_bad_open", "AFTER_FILE_BAD_OPEN"),
        ("file_path", "FILE_PATH"),
        ("file_path_end", "FILE_PATH_END"),
    ];
    for (symbol, var) in symbols.iter().copied().chain(
        file_symbols.iter().copied()
            .filter(|_| env::var_os("CARGO_FEATURE_USER_FILE_IO_SMOKE").is_some())
    ) {
        let value = nm_symbol(&output, symbol);
        generated += &format!("pub const {var}: u64 = {value:#x};\n");
    }
    fs::write(path.join("wolfos_elf_symbols.rs"), generated)
        .expect("cannot persist checked independent ELF symbol addresses");
    assert!(fs::metadata(&elf).unwrap().len() < 32768,
        "unexpectedly large user executable");
}
