pub mod connection;
pub mod packet_codec;

pub fn get_test_timeout() -> u64 {
    if cfg!(target_arch = "riscv64") {
        5000
    } else {
        2000
    }
}
