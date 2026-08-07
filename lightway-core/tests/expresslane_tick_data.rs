//! Integration test for ExpresslaneTickData public API.
//! This must compile as an external crate to ensure pub-ness is verifiable
//! — a bare `use` in lib.rs makes this test fail to compile, catching the
//! regression the whole task exists to prevent.

use lightway_core::ExpresslaneTickData;

#[test]
fn tick_data_is_publicly_nameable_and_debuggable() {
    fn assert_traits<T: std::fmt::Debug + Clone>() {}
    assert_traits::<ExpresslaneTickData>();
}
