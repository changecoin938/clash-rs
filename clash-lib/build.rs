fn main() -> std::io::Result<()> {
    println!("cargo::rustc-check-cfg=cfg(docker_test)");
    println!("cargo:rerun-if-env-changed=CLASH_DOCKER_TEST");
    if let Some("1" | "true") = option_env!("CLASH_DOCKER_TEST") {
        println!("cargo::rustc-cfg=docker_test");
    }

    if std::env::var_os("PROTOC").is_none() {
        if let Ok(protoc_path) = protoc_bin_vendored::protoc_bin_path() {
            unsafe {
                std::env::set_var("PROTOC", protoc_path);
            }
        }
    }

    println!("cargo:rerun-if-changed=src/common/geodata/geodata.proto");
    prost_build::Config::new()
        .type_attribute(".", "#[allow(dead_code)]")
        .compile_protos(
        &["src/common/geodata/geodata.proto"],
        &["src/common/geodata"],
    )
}
