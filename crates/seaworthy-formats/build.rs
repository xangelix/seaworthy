//! seaworthy-formats' build script: stamps the compile-time target triple
//! into `SEAWORTHY_FORMATS_TARGET_TRIPLE` for `TARGET_TRIPLE`.

fn main() {
    // `TARGET_TRIPLE` (the `{target}` placeholder of the update helper's
    // package URL, and the target every signed manifest must name) is the
    // compile-time target triple. Cargo always sets TARGET for build
    // scripts; were it missing, a loud build error (`cargo::error`), never
    // a panic. TARGET is fixed per target directory, so nothing but this
    // file needs to rerun it.
    println!("cargo::rerun-if-changed=build.rs");
    match std::env::var("TARGET") {
        Ok(target) => println!("cargo::rustc-env=SEAWORTHY_FORMATS_TARGET_TRIPLE={target}"),
        Err(e) => println!("cargo::error=seaworthy-formats: TARGET is unusable ({e})"),
    }
}
