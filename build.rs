// SPDX-License-Identifier: GPL-2.0
use libbpf_cargo::SkeletonBuilder;
use std::env;
use std::path::PathBuf;

const SRC: &str = "src/bpf/rsched.bpf.c";

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
    SkeletonBuilder::new()
        .source(SRC)
        .build_and_generate(out.join("rsched.skel.rs"))
        .unwrap();
    println!("cargo:rerun-if-changed={}", SRC);
}
