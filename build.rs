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
    println!("cargo:rerun-if-changed=user/yield.S");
    if env::var_os("CARGO_FEATURE_P2_RING3_YIELD_SMOKE").is_some()
        || env::var_os("CARGO_FEATURE_P2_RING3_IRQ_READY_SMOKE").is_some()
        || env::var_os("CARGO_FEATURE_P2_RING3_TIMER_OBSERVE_SMOKE").is_some() || env::var_os("CARGO_FEATURE_P2_RING3_TIMER_PREEMPT_SMOKE").is_some() {
        println!("cargo:rerun-if-changed=user/hello.ld");
        let path=PathBuf::from(env::var_os("OUT_DIR").unwrap());
        fs::create_dir_all(&path).expect("make yield OUT_DIR");
        let mut symbols=String::new();
        for pid in [1usize,2] {
            let obj=path.join(format!("wolfos-yield-{pid}.o"));
            let elf=path.join(format!("wolfos-yield-{pid}.elf"));
            let def=format!("WOLFOS_PID={pid}");
            if env::var_os("CARGO_FEATURE_P2_RING3_TIMER_OBSERVE_SMOKE").is_some() || env::var_os("CARGO_FEATURE_P2_RING3_TIMER_PREEMPT_SMOKE").is_some() {
                checked("as",&["--64","--defsym",&def,
                    "--defsym","WOLFOS_TIMER_IRQ_PROBE=1","-o",
                    obj.to_str().unwrap(),"user/yield.S"]);
            } else {
                checked("as",&["--64","--defsym",&def,"-o",
                    obj.to_str().unwrap(),"user/yield.S"]);
            }
            checked("ld",&["-m","elf_x86_64","-nostdlib","-static",
                "-T","user/hello.ld","-o",elf.to_str().unwrap(),
                obj.to_str().unwrap()]);
            let out=Command::new("nm").arg("-n").arg(&elf)
                .output().expect("missing nm for yield ELF");
            assert!(out.status.success(),"yield nm failed");
            let map=String::from_utf8(out.stdout).expect("yield nm not utf8");
            for (name,suffix) in [
                ("_start","ENTRY"),("_yield_return","AFTER_YIELD"),
                ("_exit_return","AFTER_EXIT"),("progress","PROGRESS"),
            ] {
                let addr=nm_symbol(&map,name);
                symbols+=&format!("pub const PID{pid}_{suffix}: u64 = {addr:#x};\n");
            }
            if env::var_os("CARGO_FEATURE_P2_RING3_TIMER_OBSERVE_SMOKE").is_some() || env::var_os("CARGO_FEATURE_P2_RING3_TIMER_PREEMPT_SMOKE").is_some(){
                for (name,suffix) in [("_busy_begin","BUSY_BEGIN"),("_busy_end","BUSY_END")] {
                    let addr=nm_symbol(&map,name);
                    symbols+=&format!("pub const PID{pid}_{suffix}: u64 = {addr:#x};\n");
                }
            }
            assert!(fs::metadata(&elf).unwrap().len()<32768,
                "unexpectedly large second ELF");
        }
        fs::write(path.join("wolfos_yield_symbols.rs"),symbols)
            .expect("write separately linked ELF symbol table");
        return;
    }
    println!("cargo:rerun-if-changed=user/hello.S");
    println!("cargo:rerun-if-changed=user/hello.ld");
    if env::var_os("CARGO_FEATURE_USER_ELF_RUN_SMOKE").is_none()
        && env::var_os("CARGO_FEATURE_USER_PROCESS_SMOKE").is_none()
        && env::var_os("CARGO_FEATURE_USER_RAMFS_SMOKE").is_none()
        && env::var_os("CARGO_FEATURE_USER_VFS_SMOKE").is_none()
        && env::var_os("CARGO_FEATURE_USER_COPY_SMOKE").is_none()
        && env::var_os("CARGO_FEATURE_USER_FILE_IO_SMOKE").is_none() {
        return;
    }
    let path = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    fs::create_dir_all(&path).expect("make OUT_DIR");
    let obj = path.join("wolfos-user-hello.o");
    let elf = path.join("wolfos-user-hello.elf");
    if env::var_os("CARGO_FEATURE_USER_FILE_IO_SMOKE").is_some() {
        checked("as", &["--64", "--defsym", "WOLFOS_FILE_IO_SMOKE=1",
            "-o", obj.to_str().unwrap(), "user/hello.S"]);
    } else if env::var_os("CARGO_FEATURE_USER_COPY_SMOKE").is_some() {
        checked("as", &["--64", "--defsym", "WOLFOS_USERCOPY_SMOKE=1",
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
    let mut symbols = vec![
        ("_start", "ENTRY"), ("_after_id", "AFTER_ID"),
        ("_after_add", "AFTER_ADD"),
        ("_after_write", "AFTER_WRITE"),
        ("_after_putc", "AFTER_PUTC"),
        ("_after_exit", "AFTER_EXIT"),
        ("hello_text", "HELLO_TEXT"),
        ("hello_end", "HELLO_END"),
        ("fixture_magic", "FIXTURE_MAGIC"),
        ("uninitialized", "BSS_START"),
    ];
    if env::var_os("CARGO_FEATURE_USER_FILE_IO_SMOKE").is_some() {
        symbols.extend_from_slice(&[
            ("_after_file_bad_open", "FILE_BAD_OPEN"),
            ("_after_file_open", "FILE_OPEN"),
            ("_after_file_bad_read", "FILE_BAD_READ"),
            ("_after_file_read", "FILE_READ"),
            ("_after_file_eof", "FILE_EOF"),
            ("_after_file_close", "FILE_CLOSE"),
            ("_after_file_stale_close", "FILE_STALE_CLOSE"),
            ("file_path", "FILE_PATH"),
            ("file_path_end", "FILE_PATH_END"),
        ]);
    }
    let mut generated = String::new();
    for (symbol, var) in symbols {
        let value = nm_symbol(&output, symbol);
        generated += &format!("pub const {var}: u64 = {value:#x};\n");
    }
    fs::write(path.join("wolfos_elf_symbols.rs"), generated)
        .expect("cannot persist checked independent ELF symbol addresses");
    assert!(fs::metadata(&elf).unwrap().len() < 32768,
        "unexpectedly large user executable");
}
