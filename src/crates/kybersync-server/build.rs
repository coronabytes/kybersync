use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rustc-env=KYBERSYNC_VERSION={}", version());
}

/// The version the server reports and compares against releases: the
/// `KYBERSYNC_VERSION` variable when the build sets it (the Docker image is
/// built from a source copy without `.git`, so the release workflow passes
/// the tag through), else the nearest git tag as `git describe` prints it,
/// else `unknown` (the workspace version in Cargo.toml is not kept up to
/// date, so it would claim an old release). An unknown version is never
/// compared against releases.
fn version() -> String {
    println!("cargo:rerun-if-env-changed=KYBERSYNC_VERSION");
    if let Ok(v) = std::env::var("KYBERSYNC_VERSION")
        && !v.trim().is_empty()
    {
        let v = v.trim();
        return v.strip_prefix('v').unwrap_or(v).to_string();
    }
    let git = |args: &[&str]| {
        let out = Command::new("git").args(args).output().ok()?;
        out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
    };
    for (dir, files) in [("--git-dir", &["HEAD"][..]), ("--git-common-dir", &["packed-refs", "refs/tags"][..])] {
        if let Some(d) = git(&["rev-parse", dir]) {
            for f in files {
                println!("cargo:rerun-if-changed={}", PathBuf::from(&d).join(f).display());
            }
        }
    }
    match git(&["describe", "--tags", "--always", "--dirty"]) {
        Some(v) => v.strip_prefix('v').unwrap_or(&v).to_string(),
        None => "unknown".into(),
    }
}
