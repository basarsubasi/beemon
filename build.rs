// Build script for beemon single binary.
//
// Compiles both architecture-specific BPF C programs (x86_64 and arm64)
// via clang into <OUT_DIR>/beemon_{x86,arm64}.o for embedding.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, Context, Result};

const BPF_HELPER_INCLUDE_DIR: &str = "kernelspace";

fn main() -> Result<()> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    println!("cargo:rerun-if-changed=kernelspace/x86_64/beemon.bpf.c");
    println!("cargo:rerun-if-changed=kernelspace/arm64/beemon.bpf.c");
    println!("cargo:rerun-if-changed=kernelspace/bpf/");
    println!("cargo:rerun-if-changed=Cargo.toml");

    compile_bpf(&manifest_dir, &out_dir)
}

fn compile_bpf(manifest_dir: &Path, out_dir: &Path) -> Result<()> {
    let clang = env::var("CLANG").unwrap_or_else(|_| "clang".to_string());
    let incdir = manifest_dir.join(BPF_HELPER_INCLUDE_DIR);

    let arches: &[(&str, &str, &str)] = &[
        ("x86", "x86", "kernelspace/x86_64/beemon.bpf.c"),
        ("arm64", "arm64", "kernelspace/arm64/beemon.bpf.c"),
    ];

    for (suffix, arch_target, src) in arches {
        let src = manifest_dir.join(src);
        let obj = out_dir.join(format!("beemon_{suffix}.o"));
        let target_arch = format!("__TARGET_ARCH_{arch_target}");
        let status = Command::new(&clang)
            .arg("-O2")
            .arg("-g")
            .arg("-Wall")
            .arg("-target")
            .arg("bpf")
            .arg("-D")
            .arg(&target_arch)
            .arg(format!("-I{}", incdir.display()))
            .arg("-c")
            .arg(&src)
            .arg("-o")
            .arg(&obj)
            .status()
            .with_context(|| format!("failed to spawn clang ({})", clang))?;
        if !status.success() {
            return Err(anyhow!(
                "clang failed compiling {} ({:?})",
                src.display(),
                status
            ));
        }
    }
    Ok(())
}
