fn main() {
    // Record crate version and enabled features for `build_info()`
    built::write_built_file().expect("Failed to write build information");
}
