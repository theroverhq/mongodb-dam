use libbpf_cargo::SkeletonBuilder;
use std::{env, path::PathBuf};

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let bpf_dir = manifest.join("../../bpf");
    let source = bpf_dir.join("observer.bpf.c");
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("observer.skel.rs");
    SkeletonBuilder::new()
        .source(&source)
        .clang_args([format!("-I{}", bpf_dir.display())])
        .build_and_generate(&output)
        .expect("building MongoDB DAM eBPF programs");
    println!("cargo:rerun-if-changed={}", source.display());
    println!(
        "cargo:rerun-if-changed={}",
        bpf_dir.join("vmlinux_min.h").display()
    );
}
