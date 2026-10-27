//!
//! XmlSec Bindings Generation
//!

use std::path::PathBuf;

/// Include paths and `-D` defines needed to compile against the xmlsec headers.
struct XmlSec {
    includes: Vec<PathBuf>,
    defines: Vec<String>,
}

fn main() {
    let xmlsec = find_xmlsec();

    generate_bindings(&xmlsec);
}

/// Vendored xmlsec is used with the `vendored` feature, and by default on Windows
/// (prebuilt xmlsec libraries there are often unusable). Setting `XMLSEC1_NO_VENDOR`
/// on Windows links against xmlsec installed with vcpkg instead.
fn find_xmlsec() -> XmlSec {
    println!("cargo:rerun-if-env-changed=XMLSEC1_NO_VENDOR");

    #[cfg(any(feature = "vendored", target_os = "windows"))]
    if cfg!(feature = "vendored") || std::env::var_os("XMLSEC1_NO_VENDOR").is_none() {
        return find_vendored_xmlsec();
    }

    find_system_xmlsec()
}

/// Builds the bundled xmlsec1 sources from the `xmlsec1-src` crate.
#[cfg(any(feature = "vendored", target_os = "windows"))]
fn find_vendored_xmlsec() -> XmlSec {
    let artifacts = xmlsec1_src::Build::new().build();
    artifacts.print_cargo_metadata();

    let defines = artifacts
        .defines()
        .iter()
        .map(|(name, value)| match value {
            Some(v) => format!("-D{name}={v}"),
            None => format!("-D{name}"),
        })
        .collect();

    XmlSec {
        includes: vec![artifacts.include_dir().to_path_buf()],
        defines,
    }
}

/// Links against a system installed xmlsec1 (OpenSSL backend).
#[cfg(not(target_os = "windows"))]
fn find_system_xmlsec() -> XmlSec {
    let lib = pkg_config::Config::new()
        .cargo_metadata(false)
        .probe("xmlsec1-openssl")
        .expect("xmlsec1-openssl not found");

    // Default system dirs are searched by the linker anyway. Passing them explicitly
    // (e.g. `/usr/lib` from Homebrew's libxslt.pc on macOS) would place them before
    // other dirs and link the system libxml2 instead of the one xmlsec was built against.
    for path in lib
        .link_paths
        .iter()
        .filter(|p| !["/usr/lib", "/lib"].iter().any(|sys| p.as_path() == std::path::Path::new(sys)))
    {
        println!("cargo:rustc-link-search=native={}", path.display());
    }
    for name in &lib.libs {
        println!("cargo:rustc-link-lib={name}");
    }

    let defines = lib
        .defines
        .iter()
        .map(|(name, value)| match value {
            Some(v) => format!("-D{name}={v}"),
            None => format!("-D{name}"),
        })
        .collect();

    XmlSec {
        includes: lib.include_paths,
        defines,
    }
}

/// Links against xmlsec1 installed with vcpkg.
#[cfg(target_os = "windows")]
fn find_system_xmlsec() -> XmlSec {
    let lib = vcpkg::find_package("xmlsec").expect("xmlsec not found via vcpkg");

    XmlSec {
        includes: lib.include_paths,
        defines: vec!["-DXMLSEC_CRYPTO_OPENSSL=1".to_string()],
    }
}

fn generate_bindings(xmlsec: &XmlSec) {
    let path_bindings = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("bindings.rs");

    let includes = xmlsec
        .includes
        .iter()
        .chain(find_libxml().iter())
        .chain(find_openssl().iter())
        .map(|inc| format!("-I{}", inc.display()))
        .collect::<Vec<_>>();

    let bindings = bindgen::Builder::default()
        .header("bindings.h")
        .clang_args(&xmlsec.defines)
        .clang_args(includes)
        .allowlist_var(r#"(\w*xmlSec\w*)"#)
        .allowlist_type(r#"(\w*xmlSec\w*)"#)
        .allowlist_function(r#"(\w*xmlSec\w*)"#)
        .blocklist_file(".*libxml/[^/]*.h")
        .generate_comments(true)
        .generate()
        .expect("Unable to generate bindings")
        .to_string();

    // RIPEMD160 is optional in xmlsec (XMLSEC_NO_RIPEMD160), e.g. Homebrew builds without it.
    println!("cargo:rustc-check-cfg=cfg(xmlsec_ripemd160)");
    if bindings.contains("xmlSecOpenSSLTransformRipemd160GetKlass") {
        println!("cargo:rustc-cfg=xmlsec_ripemd160");
    }

    std::fs::write(path_bindings, bindings).expect("Couldn't write bindings!");
}

/// libxml2 include paths; linking is done by the `libxml` crate.
#[cfg(not(target_os = "windows"))]
fn find_libxml() -> Vec<PathBuf> {
    pkg_config::Config::new()
        .cargo_metadata(false)
        .probe("libxml-2.0")
        .expect("libxml2 not found")
        .include_paths
}

/// libxml2 include paths; linking is done by the `libxml` crate.
#[cfg(target_os = "windows")]
fn find_libxml() -> Vec<PathBuf> {
    vcpkg::Config::new()
        .cargo_metadata(false)
        .find_package("libxml2")
        .expect("libxml2 not found via vcpkg")
        .include_paths
        .into_iter()
        .flat_map(|p| [p.join("libxml2"), p])
        .collect()
}

/// OpenSSL include paths as reported by `openssl-sys`.
fn find_openssl() -> Vec<PathBuf> {
    std::env::var_os("DEP_OPENSSL_INCLUDE")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default()
}
