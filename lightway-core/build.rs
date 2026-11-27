fn main() {
    cfg_aliases::cfg_aliases! {
        wolfssl: { feature = "wolfssl" },
        boringssl: { feature = "boringssl" },
        // UDP_GRO and TUN TCP coalescing
        gro: { any(target_os = "linux", target_os = "android") },
    }
}
