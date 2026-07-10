use std::env;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};

fn main() -> Result<()> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);

    println!("cargo:rerun-if-changed=../protobuf/api/v1/beemon.proto");

    let proto_src = manifest_dir.join("../protobuf/api/v1/beemon.proto");
    let stripped = out_dir.join("beemon_stripped.proto");

    let raw = fs::read_to_string(&proto_src)
        .with_context(|| format!("read proto {}", proto_src.display()))?;

    let stripped_text = strip_gateway_and_validate(&raw);
    fs::write(&stripped, stripped_text)
        .with_context(|| format!("write preprocessed proto to {}", stripped.display()))?;

    let proto_path = stripped.as_path();
    let proto_include = manifest_dir.join("../protobuf/api/v1");

    let mut config = prost_build::Config::new();
    let fds_path = out_dir.join("beemon.v1.fds");
    config.file_descriptor_set_path(&fds_path);

    tonic_prost_build::configure()
        .build_server(false)
        .build_client(true)
        .build_transport(true)
        .compile_with_config(config, &[proto_path], &[proto_include.as_path(), &out_dir])
        .context("tonic proto compilation failed")?;

    let fds = fs::read(&fds_path).context("read file descriptor set")?;
    let mut builder = pbjson_build::Builder::new();
    builder.register_descriptors(&fds).unwrap();
    builder
        .build(&[".beemon.v1"])
        .context("pbjson codegen failed")?;

    Ok(())
}

fn strip_gateway_and_validate(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut in_http_option = false;
    let mut brace_depth = 0i32;
    for line in src.lines() {
        let trimmed = line.trim();

        if in_http_option {
            if let Some(b) = trimmed.rfind('}') {
                if brace_depth > 0 {
                    let _ = b;
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
