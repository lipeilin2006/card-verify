fn main() {
    println!("cargo:rerun-if-env-changed=VMP_SDK_DIR");
    if std::env::var("CARGO_FEATURE_VMP").is_err() {
        return;
    }
    let dir = std::env::var("VMP_SDK_DIR")
        .unwrap_or_else(|_| r"D:\VMProtect Professional\Lib\Windows".to_owned());
    println!("cargo:rustc-link-search=native={dir}");
    println!("cargo:rustc-link-lib=dylib=VMProtectSDK64");
}
