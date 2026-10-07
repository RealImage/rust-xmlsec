//!
//! Central XmlSec1 Context
//!
use log::RecordBuilder;

use crate::bindings;

use once_cell::sync::Lazy;
use std::ffi::CStr;
use std::ffi::c_char;
use std::ffi::c_int;
use std::ptr::null;
use std::sync::Mutex;

/// Callback invoked for an XML security diagnostic.
pub type ErrorCallback =
    Box<dyn Fn(Option<&str>, Option<&str>, XmlSecErrorReason, Option<&str>) + Send>;

static XMLSEC: Lazy<Mutex<Option<XmlSecContext>>> = Lazy::new(|| Mutex::new(None));

/// XmlSec Error Reason
#[derive(Debug, Copy, Clone, PartialEq)]
#[allow(missing_docs)]
pub enum XmlSecErrorReason {
    NoError,
    Unknown,
    XmlSecFailed,
    MallocFailed,
    StrdupFailed,
    CryptoFailed,
    XmlFailed,
    XsltFailed,
    IoFailed,
    Disabled,
    NotImplemented,
    InvalidConfig,
    InvalidSize,
    InvalidData,
    InvalidResult,
    InvalidType,
    InvalidOperation,
    InvalidStatus,
    InvalidFormat,
    DataNotMatch,
    InvalidVersion,
    InvalidNode,
    InvalidNodeContent,
    InvalidNodeAttribute,
    MissingNodeAttribute,
    NodeAlreadyPresent,
    UnexpectedNode,
    NodeNotFound,
    InvalidTransform,
    InvalidTransformKey,
    InvalidUriType,
    TransformSameDocumentRequired,
    TransformDisabled,
    InvalidAlgorithm,
    InvalidKeyData,
    KeyDataNotFound,
    KeyDataAlreadyExist,
    InvalidKeyDataSize,
    KeyNotFound,
    KeyDataDisabled,
    MaxRetrievalsLevel,
    MaxRetrievalTypeMismatch,
    MaxEncKeyLevel,
    CertVerifyFailed,
    CertNotFound,
    CertRevoked,
    CertIssuerFailed,
    CertNotYetValid,
    CertHasExpired,
    CrlVerifyFailed,
    CrlNotYetValid,
    CrlHasExpired,
    DsigNoReferences,
    DsigInvalidReference,
    Assertion,
    CastImpossible,
}

// create From<i32> for XmlSecErrorReason
impl From<i32> for XmlSecErrorReason {
    fn from(reason: i32) -> Self {
        match reason {
            0 => XmlSecErrorReason::NoError,
            1 => XmlSecErrorReason::XmlSecFailed,
            2 => XmlSecErrorReason::MallocFailed,
            3 => XmlSecErrorReason::StrdupFailed,
            4 => XmlSecErrorReason::CryptoFailed,
            5 => XmlSecErrorReason::XmlFailed,
            6 => XmlSecErrorReason::XsltFailed,
            7 => XmlSecErrorReason::IoFailed,
            8 => XmlSecErrorReason::Disabled,
            9 => XmlSecErrorReason::NotImplemented,
            10 => XmlSecErrorReason::InvalidConfig,
            11 => XmlSecErrorReason::InvalidSize,
            12 => XmlSecErrorReason::InvalidData,
            13 => XmlSecErrorReason::InvalidResult,
            14 => XmlSecErrorReason::InvalidType,
            15 => XmlSecErrorReason::InvalidOperation,
            16 => XmlSecErrorReason::InvalidStatus,
            17 => XmlSecErrorReason::InvalidFormat,
            18 => XmlSecErrorReason::DataNotMatch,
            19 => XmlSecErrorReason::InvalidVersion,
            21 => XmlSecErrorReason::InvalidNode,
            22 => XmlSecErrorReason::InvalidNodeContent,
            23 => XmlSecErrorReason::InvalidNodeAttribute,
            25 => XmlSecErrorReason::MissingNodeAttribute,
            26 => XmlSecErrorReason::NodeAlreadyPresent,
            27 => XmlSecErrorReason::UnexpectedNode,
            28 => XmlSecErrorReason::NodeNotFound,
            31 => XmlSecErrorReason::InvalidTransform,
            32 => XmlSecErrorReason::InvalidTransformKey,
            33 => XmlSecErrorReason::InvalidUriType,
            34 => XmlSecErrorReason::TransformSameDocumentRequired,
            35 => XmlSecErrorReason::TransformDisabled,
            36 => XmlSecErrorReason::InvalidAlgorithm,
            41 => XmlSecErrorReason::InvalidKeyData,
            42 => XmlSecErrorReason::KeyDataNotFound,
            43 => XmlSecErrorReason::KeyDataAlreadyExist,
            44 => XmlSecErrorReason::InvalidKeyDataSize,
            45 => XmlSecErrorReason::KeyNotFound,
            46 => XmlSecErrorReason::KeyDataDisabled,
            51 => XmlSecErrorReason::MaxRetrievalsLevel,
            52 => XmlSecErrorReason::MaxRetrievalTypeMismatch,
            61 => XmlSecErrorReason::MaxEncKeyLevel,
            71 => XmlSecErrorReason::CertVerifyFailed,
            72 => XmlSecErrorReason::CertNotFound,
            73 => XmlSecErrorReason::CertRevoked,
            74 => XmlSecErrorReason::CertIssuerFailed,
            75 => XmlSecErrorReason::CertNotYetValid,
            76 => XmlSecErrorReason::CertHasExpired,
            77 => XmlSecErrorReason::CrlVerifyFailed,
            78 => XmlSecErrorReason::CrlNotYetValid,
            79 => XmlSecErrorReason::CrlHasExpired,
            81 => XmlSecErrorReason::DsigNoReferences,
            82 => XmlSecErrorReason::DsigInvalidReference,
            100 => XmlSecErrorReason::Assertion,
            101 => XmlSecErrorReason::CastImpossible,
            _ => XmlSecErrorReason::Unknown,
        }
    }
}

/// Set the error callback
pub fn set_error_callback(cb: Option<ErrorCallback>) {
    guarantee_xmlsec_init();
    XMLSEC
        .lock()
        .expect("Unable to lock global xmlsec initalization wrapper")
        .as_mut()
        .expect("xmlsec not initalized")
        .error_callback = cb;
}

unsafe extern "C" fn error_callback(
    file: *const c_char,
    line: c_int,
    func: *const c_char,
    error_object: *const c_char,
    error_subject: *const c_char,
    reason: c_int,
    msg: *const c_char,
) {
    let error_msg = {
        let mut i = 0;
        loop {
            let error_msg = unsafe { bindings::xmlSecErrorsGetMsg(i) };
            if error_msg.is_null() {
                break error_msg;
            }
            if unsafe { bindings::xmlSecErrorsGetCode(i) } == reason {
                break error_msg;
            }
            i += 1;
        }
    };

    if let Some(cb) = XMLSEC
        .lock()
        .expect("Unable to lock global xmlsec initalization wrapper")
        .as_ref()
        .expect("xmlsec not initalized")
        .error_callback
        .as_ref()
    {
        cb(
            ptr_to_str(error_object),
            ptr_to_str(error_subject),
            reason.into(),
            ptr_to_str(msg),
        );
    }

    log::logger().log(
        &RecordBuilder::new()
            .args(format_args!(
                "func={}:obj={}:subj={}:error={}:{}:{}",
                ptr_to_str(func).unwrap_or("unknown"),
                ptr_to_str(error_object).unwrap_or("unknown"),
                ptr_to_str(error_subject).unwrap_or("unknown"),
                reason,
                ptr_to_str(error_msg).unwrap_or(""),
                ptr_to_str(msg).unwrap_or("unknown"),
            ))
            .level(log::Level::Error)
            .module_path_static(Some("xmlsec"))
            .target("libxmlsec1")
            .file(Some(ptr_to_str(file).unwrap_or("unknown")))
            .line(Some(line as u32))
            .build(),
    );
}

fn ptr_to_str<'a>(file: *const c_char) -> Option<&'a str> {
    if file.is_null() {
        None
    } else {
        let file_str = unsafe { CStr::from_ptr(file as *const c_char) };
        file_str.to_str().ok()
    }
}

pub fn guarantee_xmlsec_init() {
    let mut inner = XMLSEC
        .lock()
        .expect("Unable to lock global xmlsec initalization wrapper");

    let ver = unsafe { *openssl_sys::OpenSSL_version(0) };
    if ver < 1 {
        panic!("OpenSSL version 1.0.0 or higher is required");
    }

    if inner.is_none() {
        *inner = Some(XmlSecContext::new());
        unsafe {
            bindings::xmlSecErrorsSetCallback(Some(error_callback));
        }
    }
}

/// XmlSec Global Context
///
/// This object initializes the underlying xmlsec global state and cleans it
/// up once gone out of scope. It is checked by all objects in the library that
/// require the context to be initialized. See [`globals`][globals].
///
/// [globals]: globals
struct XmlSecContext {
    error_callback: Option<ErrorCallback>,
}

impl XmlSecContext {
    /// Runs xmlsec initialization and returns instance of itself.
    pub fn new() -> Self {
        init_xmlsec();
        init_crypto_app();
        init_crypto();

        Self {
            error_callback: None,
        }
    }
}

impl Drop for XmlSecContext {
    fn drop(&mut self) {
        cleanup_crypto();
        cleanup_crypto_app();
        cleanup_xmlsec();
    }
}

/// Init xmlsec library
fn init_xmlsec() {
    let rc = unsafe { bindings::xmlSecInit() };

    if rc < 0 {
        panic!("XmlSec failed initialization");
    }
}

/// Load default crypto engine if we are supporting dynamic loading for
/// xmlsec-crypto libraries. Use the crypto library name ("openssl",
/// "nss", etc.) to load corresponding xmlsec-crypto library.
fn init_crypto_app() {
    // if bindings::XMLSEC_CRYPTO_DYNAMIC_LOADING
    // {
    //     let rc = unsafe { bindings::xmlSecCryptoDLLoadLibrary(0) };

    //     if rc < 0 {
    //         panic!("XmlSec failed while loading default crypto backend. \
    //                 Make sure that you have it installed and check shread libraries path");
    //     }
    // }

    let rc = unsafe { bindings::xmlSecOpenSSLAppInit(null()) };

    if rc < 0 {
        panic!("XmlSec failed to init crypto backend")
    }
}

/// Init xmlsec-crypto library
fn init_crypto() {
    let rc = unsafe { bindings::xmlSecOpenSSLInit() };

    if rc < 0 {
        panic!(
            "XmlSec failed while loading default crypto backend. \
               Make sure that you have it installed and check shread libraries path"
        );
    }
}

/// Shutdown xmlsec-crypto library
fn cleanup_crypto() {
    unsafe { bindings::xmlSecOpenSSLShutdown() };
}

/// Shutdown crypto library
fn cleanup_crypto_app() {
    unsafe { bindings::xmlSecOpenSSLAppShutdown() };
}

/// Shutdown xmlsec library
fn cleanup_xmlsec() {
    unsafe { bindings::xmlSecShutdown() };
}
