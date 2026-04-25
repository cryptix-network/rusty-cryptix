fn main() {
    println!("cargo:rerun-if-changed=proto/cryptixwalletd.proto");

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile(&["proto/cryptixwalletd.proto"], &["proto"])
        .expect("failed to compile cryptixwalletd.proto");
}
