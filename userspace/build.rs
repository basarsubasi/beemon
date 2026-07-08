// Build script for the beemon userspace daemon.
//
// Responsibilities:
//   1. Compile both architecture-specific BPF C programs (x86_64 and arm64)
//      via clang into <OUT_DIR>/beemon_{x86,arm64}.o so they can be embedded
//      into the binary with `include_bytes!`.
//   2. Run tonic-build on a preprocessed copy of beemon.proto. The daemon
//      doesn't depend on google.api.http annotations (the BFF is the gateway)
//      or buf protovalidate (only the gateway uses validation), so we strip
//      those imports/options before invoking the codegen, so we don't need
//      the googleapis or bufvalidate well-known protos at build time.
//
// Required tooling: `clang` and `protoc` available on PATH.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, Context, Result};

/// The BPF source files `#include <bpf/bpf_helpers.h>` etc., so the include
/// dir must be the *parent* of the `bpf/` directory holding the headers
/// (i.e. `kernelspace/` itself), not the `bpf/` directory.
const BPF_HELPER_INCLUDE_DIR: &str = "../kernelspace";

fn main() -> Result<()> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    println!("cargo:rerun-if-changed=../protobuf/api/v1/beemon.proto");
    println!("cargo:rerun-if-changed=../kernelspace/x86_64/beemon.bpf.c");
    println!("cargo:rerun-if-changed=../kernelspace/arm64/beemon.bpf.c");
    println!("cargo:rerun-if-changed=../kernelspace/bpf/");
    println!("cargo:rerun-if-changed=Cargo.toml");

    compile_bpf(&manifest_dir, &out_dir)?;
    compile_proto(&manifest_dir, &out_dir)?;
    Ok(())
}

fn compile_bpf(manifest_dir: &Path, out_dir: &Path) -> Result<()> {
    let clang = env::var("CLANG").unwrap_or_else(|_| "clang".to_string());
    let incdir = manifest_dir.join(BPF_HELPER_INCLUDE_DIR);

    // (object suffix, __TARGET_ARCH_* suffix, source path)
    let arches: &[(&str, &str, &str)] = &[
        ("x86",  "x86",  "../kernelspace/x86_64/beemon.bpf.c"),
        ("arm64", "arm64", "../kernelspace/arm64/beemon.bpf.c"),
    ];

    for (suffix, arch_target, src) in arches {
        let src = manifest_dir.join(src);
        let obj = out_dir.join(format!("beemon_{suffix}.o"));
        let target_arch = format!("__TARGET_ARCH_{arch_target}");
        let status = Command::new(&clang)
            .arg("-O2")
            .arg("-g")
            .arg("-Wall")
            .arg("-target").arg("bpf")
            .arg("-D").arg(&target_arch)
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
                src.display(), status
            ));
        }
    }
    Ok(())
}

fn compile_proto(manifest_dir: &Path, out_dir: &Path) -> Result<()> {
    let proto_src = manifest_dir.join("../protobuf/api/v1/beemon.proto");
    let stripped = out_dir.join("beemon_stripped.proto");

    let raw = fs::read_to_string(&proto_src)
        .with_context(|| format!("read proto {}", proto_src.display()))?;

    let stripped_text = strip_gateway_and_validate(&raw);
    fs::write(&stripped, stripped_text)
        .with_context(|| format!("write preprocessed proto to {}", stripped.display()))?;

    // Run prost/tonic codegen. Skip unknown imports/options defensively.
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(false)
        .build_transport(true)
        .compile_protos(
            &[stripped.as_path()],
            &[manifest_dir.join("../protobuf/api/v1").as_path(), std::path::Path::new(&out_dir)],
        )
        .map_err(|e| anyhow!("tonic-prost-build failed: {e}"))
        .context("Proto compilation failed")?;
    Ok(())
}

// Minimal proto preprocessor used only to remove dependencies the daemon
// does not need, so the build cannot fail over missing googleapis/bufvalidate
// well-known protos.
fn strip_gateway_and_validate(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut in_http_option = false;
    let mut brace_depth = 0i32;
    for line in src.lines() {
        let trimmed = line.trim();

        if in_http_option {
            if let Some(b) = trimmed.rfind('}') {
                if brace_depth > 0 {
                    let _ = b; // close brace counted below
                }
                brace_depth -= trimmed.matches('}').count() as i32;
                brace_depth += trimmed.matches('{').count() as i32;
                if brace_depth <= 0 {
                    in_http_option = false;
                    brace_depth = 0;
                }
            }
            continue;
        }

        if trimmed.starts_with("import \"google/api/annotations.proto\";")
            || trimmed.starts_with("import \"google/annotations.proto\";")
            || trimmed.starts_with("import \"buf/validate/validate.proto\";")
        {
            continue;
        }

        if trimmed.starts_with("option (google.api.http) = {") {
            in_http_option = true;
            brace_depth = trimmed.matches('{').count() as i32 - trimmed.matches('}').count() as i32;
            if brace_depth <= 0 {
                in_http_option = false;
            }
            continue;
        }

        let line = strip_field_options(line.to_string());
        out.push_str(&line);
        out.push('\n');
    }
    out
}

fn strip_field_options(mut line: String) -> String {
    // Handles `[(buf.validate.field).uint32.gt = 0]` annotations inside field definitions.
    const NEEDLE: &str = "[(buf.validate.field).";
    while let Some(start) = line.find(NEEDLE) {
        if let Some(close) = line[start..].find(']') {
            let end = start + close + 1;
            let comma_at = if line[..start].ends_with(", ") { start - 2 } else { start };
            line.replace_range(comma_at..end, "");
        } else {
            break;
        }
    }
    line
}