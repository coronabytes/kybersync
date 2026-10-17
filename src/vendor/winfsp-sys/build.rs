//! Patched for cryptnx: uses the pre-generated x64 bindings shipped in
//! `src/bindings.rs` instead of running bindgen, so no libclang/LLVM is
//! required to build. Layout assertions inside the bindings guarantee the
//! structs match the target at compile time.
use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let project_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();

    if target_os != "windows" {
        panic!("WinFSP is only supported on Windows.");
    }
    if (target_arch.as_str(), target_env.as_str()) != ("x86_64", "msvc") {
        panic!("vendored winfsp-sys only ships bindings for x86_64-pc-windows-msvc");
    }

    println!(
        "cargo:rustc-link-search={}",
        project_dir.join("winfsp/lib").to_string_lossy()
    );
    println!("cargo:rustc-link-lib=dylib=delayimp");
    println!("cargo:rustc-link-lib=dylib=winfsp-x64");
    println!("cargo:rustc-link-arg=/DELAYLOAD:winfsp-x64.dll");

    fs::copy(
        project_dir.join("src/bindings.rs"),
        out_dir.join("bindings.rs"),
    )
    .expect("copy pre-generated bindings");
    println!("cargo:rerun-if-changed=src/bindings.rs");
    println!("cargo:rerun-if-changed=build.rs");
}
