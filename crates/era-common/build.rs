use std::io::Result;

fn main() -> Result<()> {
    prost_build::compile_protos(
        &["proto/era_common.proto", "proto/test_evolution.proto"],
        &["proto/"],
    )?;
    Ok(())
}
