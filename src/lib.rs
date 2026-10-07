//!
//! Bindings for XmlSec1
//!
//! Modules reflect the header names of the bound xmlsec1 library
//!
#![deny(missing_docs)]
#![deny(clippy::all)]
#![allow(clippy::new_without_default)] // simply do not agree with this

// imports

#[doc(hidden)]
pub use libxml::tree::document::Document as XmlDocument;
#[doc(hidden)]
pub use libxml::tree::node::Node as XmlNode;
#[doc(hidden)]
pub use libxml::xpath::Context as XmlXPathContext;

// internals
pub mod bindings;

mod crypto;
mod error;
mod exts;
mod keys;
mod nodeset;
mod templates;
mod transforms;
mod xmldsig;
mod xmlenc;
mod xmlkeysmngr;
mod xmlsec;

// exports
pub use self::exts::XmlSecDocumentExt;

pub use self::xmlsec::set_error_callback;
pub use self::xmlsec::XmlSecErrorReason;

pub use self::keys::XmlSecKey;
pub use self::keys::XmlSecKeyDataType;
pub use self::keys::XmlSecKeyFormat;

pub use self::error::XmlSecError;
pub use self::error::XmlSecResult;

pub use self::crypto::XmlSecSignatureMethod;

pub use self::nodeset::XmlSecNodeSet;

pub use self::xmldsig::{
    XmlSecReferenceVerification, XmlSecSignatureContext, XmlSecSignatureVerification,
};
pub use self::xmlenc::XmlSecEncryptionContext;
pub use self::xmlenc::XmlSecEncryptionContextMode;
pub use self::xmlkeysmngr::XmlSecKeysMngr;

pub use self::templates::ReferenceSignatureBuilder;
pub use self::templates::TemplateBuilder as XmlSecTemplateBuilder;
pub use self::templates::X509Builder;
pub use self::templates::XmlDocumentTemplateBuilder as XmlSecDocumentTemplateBuilder;
pub use self::templates::XmlDocumentTemplating as XmlSecDocumentTemplating;

pub use self::transforms::XmlSecCanonicalizationMethod;
pub use self::transforms::XmlSecTransform;
pub use self::transforms::XmlSecTransformCtx;
pub use self::transforms::XmlSecTransformOperation;

// export preambles
pub mod template {
    //! Namespace for preamble pertaining all things signature template creation.

    pub mod preamble {
        //! Preamble of all things signature template creation.
        pub use crate::XmlSecCanonicalizationMethod;
        pub use crate::XmlSecDocumentTemplating;
        pub use crate::XmlSecSignatureMethod;
        pub use crate::XmlSecTemplateBuilder;
        pub use crate::XmlSecTransformOperation;
    }
}
