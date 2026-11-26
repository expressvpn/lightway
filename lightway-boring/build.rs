use std::path::Path;

/// Find the resolved version of `package` in the nearest `Cargo.lock`
fn locked_version(manifest_dir: &Path, package: &str) -> Option<String> {
    let lockfile = manifest_dir
        .ancestors()
        .map(|p| p.join("Cargo.lock"))
        .find(|p| p.exists())?;
    println!("cargo:rerun-if-changed={}", lockfile.display());

    let contents = std::fs::read_to_string(lockfile).ok()?;
    let name = format!("name = \"{package}\"");
    let mut lines = contents.lines();
    lines.find(|l| l.trim() == name)?;
    let version = lines.next()?.trim().strip_prefix("version = \"")?;
    Some(version.strip_suffix('"')?.to_owned())
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // Record the resolved `boring` version for `build_info()`. When this crate
    // is a git dependency the nearest lockfile is lightway's own.
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set");
    let boring_version =
        locked_version(Path::new(&manifest_dir), "boring").unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=LIGHTWAY_BORING_BORING_VERSION={boring_version}");

    // Record crate version and enabled features for `build_info()`
    built::write_built_file().expect("Failed to write build information");
}
