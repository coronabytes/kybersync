use std::path::PathBuf;
use std::process::Command;

fn main() {
    #[cfg(windows)]
    winfsp::build::winfsp_link_delayload();
    // ML-KEM / ML-DSA keep large matrices on the stack; the default 1 MiB
    // main thread is too small for the UI thread, which unwraps keys.
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        println!("cargo:rustc-link-arg-bins=/STACK:16777216");
    }
    println!("cargo:rustc-env=KYBERSYNC_VERSION={}", version());
}

/// The version shown in the app: the nearest git tag (`v0.0.2`), with the
/// commits since it and a `-dirty` suffix when the tree has changes, as
/// `git describe` prints it. Falls back to the Cargo version when the build
/// does not run inside a git checkout.
fn version() -> String {
    let git = |args: &[&str]| {
        let out = Command::new("git").args(args).output().ok()?;
        out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
    };
    // Re-run when the checked-out commit or the tags change. In a worktree
    // HEAD lives in the worktree's own git dir, tags in the common one.
    for (dir, files) in [("--git-dir", &["HEAD"][..]), ("--git-common-dir", &["packed-refs", "refs/tags"][..])] {
        if let Some(d) = git(&["rev-parse", dir]) {
            for f in files {
                println!("cargo:rerun-if-changed={}", PathBuf::from(&d).join(f).display());
            }
        }
    }
    match git(&["describe", "--tags", "--always", "--dirty"]) {
        Some(v) => v.strip_prefix('v').unwrap_or(&v).to_string(),
        None => std::env::var("CARGO_PKG_VERSION").unwrap_or_default(),
    }
}
