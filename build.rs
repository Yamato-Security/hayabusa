use std::{env, io};

fn main() -> io::Result<()> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.toml");

    // Build scripts run on the host, so check the target OS for cross-compilation.
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return Ok(());
    }

    // Read the version and descriptive metadata from Cargo.toml.
    let mut resource = winresource::WindowsResource::new();
    // English (US) version strings; this does not change the application language.
    resource.set_language(0x0409);

    if !env::var("CARGO_PKG_VERSION_PRE")
        .unwrap_or_default()
        .is_empty()
    {
        const VS_FF_PRERELEASE: u64 = 0x0000_0002;
        resource.set_version_info(winresource::VersionInfo::FILEFLAGS, VS_FF_PRERELEASE);
    }

    // Fail the build if the resource compiler cannot embed the metadata.
    resource.compile()
}
