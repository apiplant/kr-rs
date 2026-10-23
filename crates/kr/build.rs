// Fully static, no libc, no C runtime: kr-rt provides _start and mem* symbols.
fn main() {
    for arg in ["-nostartfiles", "-nostdlib", "-static", "-Wl,--gc-sections", "-Wl,--build-id=none"] {
        println!("cargo:rustc-link-arg-bins={arg}");
    }
}
