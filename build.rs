fn main() {
    #[cfg(target_os = "windows")]
    static_vcruntime::metabuild();
}
