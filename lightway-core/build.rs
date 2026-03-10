fn main() {
    cfg_aliases::cfg_aliases! {
        wolfssl: { feature = "wolfssl" },
        boringssl: { feature = "boringssl" },
    }
}
