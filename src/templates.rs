//!
//! Wrapper for DSIG Nodes Templating
//!

use libxml::tree::Node;
use openssl::x509::X509;

use crate::bindings;

use crate::XmlDocument;

use crate::XmlSecCanonicalizationMethod;
use crate::XmlSecSignatureMethod;

use crate::XmlSecError;
use crate::XmlSecResult;

use std::ffi::CString;
use std::os::raw::c_uchar;
use std::ptr::null;

/// Declaration of a template building API for other specific trait extensions
/// on foreign XML objects.
pub trait TemplateBuilder {
    /// Sets canonicalization method. See: [`XmlSecCanonicalizationMethod`][c14n].
    ///
    /// [c14n]: ./transforms/enum.XmlSecCanonicalizationMethod.html
    fn canonicalization(self, c14n: XmlSecCanonicalizationMethod) -> Self;

    /// Sets cryptographic signature method. See: [`XmlSecSignatureMethod`][sig].
    ///
    /// [sig]: ./crypto/openssl/enum.XmlSecSignatureMethod.html
    fn signature(self, sig: XmlSecSignatureMethod) -> Self;

    /// Sets cryptographic digest for `<dsig:Reference/>. See: [`XmlSecSignatureMethod`][sig].
    ///
    /// [sig]: ./crypto/openssl/enum.XmlSecSignatureMethod.html
    fn reference_signature(self, sig: XmlSecSignatureMethod) -> Self;

    /// Sets signature subject node URI
    fn uri(self, uri: &str) -> Self;

    /// the namespace prefix for the signature element (e.g. "dsig")
    fn ns_prefix(self, ns_prefix: &str) -> Self;

    /// Adds <ds:KeyName> to key information node
    fn keyname(self, add: bool) -> Self;

    /// Adds <ds:KeyValue> to key information node
    fn keyvalue(self, add: bool) -> Self;

    /// Adds <ds:X509Data> to key information node
    fn x509data(self, add: bool) -> Self;

    /// Builds the actual template and returns
    fn done(self) -> XmlSecResult<()>;
}

/// Trait extension aimed at a concrete implementation for [`XmlDocument`][xmldoc]
///
/// [xmldoc]: http://kwarc.github.io/rust-libxml/libxml/tree/document/struct.Document.html
pub trait XmlDocumentTemplating<'d> {
    /// Return a template builder over current XmlDocument.
    fn template(&'d self) -> XmlDocumentTemplateBuilder<'d>;
}

/// Concrete template builder for [`XmlDocument`][xmldoc]
///
/// [xmldoc]: http://kwarc.github.io/rust-libxml/libxml/tree/document/struct.Document.html
pub struct XmlDocumentTemplateBuilder<'d> {
    doc: &'d XmlDocument,
    c14n: XmlSecCanonicalizationMethod,

    sig: XmlSecSignatureMethod,
    refsig: XmlSecSignatureMethod,

    ns_prefix: Option<String>,
    parent_node: Option<Node>,
}

pub struct SignatureNode<'a> {
    doc: &'a XmlDocument,
    node: *mut libxml::bindings::xmlNode,
}

/// Build a reference signature node
pub struct ReferenceSignatureBuilder<'a> {
    signature_node: &'a SignatureNode<'a>,
    sig: XmlSecSignatureMethod,
    uri: Option<CString>,
    with_enveloped: bool,
    canonicalization: Option<XmlSecCanonicalizationMethod>,
}

/// Build a key information node
pub struct KeyInfoBuilder<'a> {
    signature_node: &'a SignatureNode<'a>,
    keyname: bool,
    keyvalue: bool,
    x509data: bool,
}

/// Build a KeyInfi/X509 data node
pub struct X509Builder<'a> {
    signature_node: &'a SignatureNode<'a>,
}

impl<'a> X509Builder<'a> {
    /// Creates a new X509 data builder over a given signature node
    pub fn new(signature_node: &'a SignatureNode<'a>) -> Self {
        Self { signature_node }
    }

    /// Adds a new X509 data node to the signature node
    pub fn add_node(self, cert: &X509) {
        let keyinfo =
            unsafe { bindings::xmlSecTmplSignatureEnsureKeyInfo(self.signature_node.node, null()) };

        if keyinfo.is_null() {
            panic!("Failed to ensure key info");
        }

        let x509data = unsafe { bindings::xmlSecTmplKeyInfoAddX509Data(keyinfo) };

        if x509data.is_null() {
            panic!("Failed to add X509 data node");
        }

        let x509ser = unsafe { bindings::xmlSecTmplX509DataAddIssuerSerial(x509data) };

        if x509ser.is_null() {
            panic!("Failed to add X509 issuer serial nodel");
        }

        let issuer_string = cert
            .issuer_name()
            .entries()
            .map(|entry| {
                format!(
                    "{}={}",
                    entry.object().nid().short_name().unwrap(),
                    entry.data().as_utf8().unwrap()
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let issuer_string = CString::new(issuer_string).unwrap();
        unsafe {
            bindings::xmlSecTmplX509IssuerSerialAddIssuerName(
                x509ser,
                issuer_string.as_ptr().cast(),
            );
        }

        let serial_number = cert
            .serial_number()
            .to_bn()
            .unwrap()
            .to_dec_str()
            .unwrap()
            .to_string();
        let serial_number = CString::new(serial_number).unwrap();
        unsafe {
            bindings::xmlSecTmplX509IssuerSerialAddSerialNumber(
                x509ser,
                serial_number.as_ptr().cast(),
            );
        }

        let x509cert = unsafe { bindings::xmlSecTmplX509DataAddCertificate(x509data) };

        if x509cert.is_null() {
            panic!("Failed to add X509 certificate node");
        }

        let cert_string = cert.to_der().unwrap();

        unsafe {
            let buf = bindings::xmlSecBufferCreate(cert_string.len());
            bindings::xmlSecBufferSetData(
                buf,
                cert_string.as_ptr() as *const c_uchar,
                cert_string.len(),
            );
            bindings::xmlSecBufferBase64NodeContentWrite(buf, x509cert, 64);
            bindings::xmlSecBufferDestroy(buf)
        }
    }
}

impl<'a> KeyInfoBuilder<'a> {
    fn new(signature_node: &'a SignatureNode<'a>) -> Self {
        Self {
            signature_node,
            keyname: false,
            keyvalue: false,
            x509data: false,
        }
    }

    pub fn keyname(mut self, keyname: bool) -> Self {
        self.keyname = keyname;
        self
    }

    pub fn keyvalue(mut self, keyvalue: bool) -> Self {
        self.keyvalue = keyvalue;
        self
    }

    pub fn x509data(mut self, x509data: bool) -> Self {
        self.x509data = x509data;
        self
    }

    pub fn add_node(self) {
        let keyinfo =
            unsafe { bindings::xmlSecTmplSignatureEnsureKeyInfo(self.signature_node.node, null()) };

        if keyinfo.is_null() {
            panic!("Failed to ensure key info");
        }

        if self.keyname {
            let keyname = unsafe { bindings::xmlSecTmplKeyInfoAddKeyName(keyinfo, null()) };

            if keyname.is_null() {
                panic!("Failed to add key name");
            }
        }

        if self.keyvalue {
            let keyvalue = unsafe { bindings::xmlSecTmplKeyInfoAddKeyValue(keyinfo) };

            if keyvalue.is_null() {
                panic!("Failed to add key value");
            }
        }

        if self.x509data {
            let x509data = unsafe { bindings::xmlSecTmplKeyInfoAddX509Data(keyinfo) };

            if x509data.is_null() {
                panic!("Failed to add key value");
            }
        }
    }
}

impl<'a> ReferenceSignatureBuilder<'a> {
    /// Creates a new reference signature builder over a given signature node
    pub fn new(signature_node: &'a SignatureNode<'a>) -> Self {
        Self {
            signature_node,
            sig: XmlSecSignatureMethod::Sha1,
            uri: None,
            with_enveloped: true,
            canonicalization: None,
        }
    }

    /// Sets cryptographic digest for `<dsig:Reference/>`. See: [`XmlSecSignatureMethod`][sig].
    pub fn signature(mut self, sig: XmlSecSignatureMethod) -> Self {
        self.sig = sig;
        self
    }

    /// Sets signature subject node URI
    pub fn uri(mut self, uri: &str) -> Self {
        self.uri = Some(CString::new(uri).unwrap());
        self
    }

    /// Adds a reference signature node to the signature node
    pub fn with_enveloped(mut self, with_enveloped: bool) -> Self {
        self.with_enveloped = with_enveloped;
        self
    }

    /// Canonicalize the reference after the optional enveloped transform.
    pub fn canonicalization(mut self, method: XmlSecCanonicalizationMethod) -> Self {
        self.canonicalization = Some(method);
        self
    }

    /// Adds a new reference signature node to the signature node
    pub fn add_node(self) {
        let curi = self.uri.as_ref().map_or(null(), |uri| uri.as_ptr().cast());
        let reference = unsafe {
            bindings::xmlSecTmplSignatureAddReference(
                self.signature_node.node,
                self.sig.to_method(),
                null(),
                curi,
                null(),
            )
        };

        if reference.is_null() {
            panic!("Failed to add enveloped transform to reference");
        }

        if self.with_enveloped {
            let envelope = unsafe {
                bindings::xmlSecTmplReferenceAddTransform(
                    reference,
                    bindings::xmlSecTransformEnvelopedGetKlass(),
                )
            };

            if envelope.is_null() {
                panic!("Failed to add enveloped transform")
            }
        }
        if let Some(method) = self.canonicalization {
            // SAFETY: the reference belongs to the live signature document;
            // xmlsec copies the transform configuration into that document.
            let transform =
                unsafe { bindings::xmlSecTmplReferenceAddTransform(reference, method.to_method()) };
            assert!(
                !transform.is_null(),
                "Failed to add canonicalization transform"
            );
        }
    }
}

impl<'d> XmlDocumentTemplating<'d> for XmlDocument {
    fn template(&'d self) -> XmlDocumentTemplateBuilder<'d> {
        crate::xmlsec::guarantee_xmlsec_init();

        XmlDocumentTemplateBuilder::new(self)
    }
}

impl<'a> XmlDocumentTemplateBuilder<'a> {
    /// Creates a new template builder over a given document
    pub fn new(doc: &'a XmlDocument) -> Self {
        Self {
            doc,
            c14n: XmlSecCanonicalizationMethod::ExclusiveC14N,

            sig: XmlSecSignatureMethod::RsaSha1,
            refsig: XmlSecSignatureMethod::Sha1,

            ns_prefix: None,
            parent_node: None,
        }
    }

    /// Builds the actual template and returns
    pub fn build(self) -> XmlSecResult<SignatureNode<'a>> {
        let docptr = self.doc.doc_ptr() as *mut libxml::bindings::xmlDoc;
        let ns_prefix = self.ns_prefix.map(|prefix| CString::new(prefix).unwrap());
        let c_ns_prefix = ns_prefix
            .as_ref()
            .map_or(null(), |prefix| prefix.as_ptr().cast());

        let node = unsafe {
            bindings::xmlSecTmplSignatureCreateNsPref(
                docptr,
                self.c14n.to_method(),
                self.sig.to_method(),
                null(),
                c_ns_prefix,
            )
        };

        let rootptr = if let Some(parent) = self.parent_node {
            parent.node_ptr() as *mut libxml::bindings::xmlNode
        } else if let Some(root) = self.doc.get_root_element() {
            root.node_ptr() as *mut libxml::bindings::xmlNode
        } else {
            return Err(XmlSecError::RootNotFound);
        };

        unsafe { libxml::bindings::xmlAddChild(rootptr, node) };

        Ok(SignatureNode {
            doc: self.doc,
            node,
        })
    }

    /// Sets canonicalization method. See: [`XmlSecCanonicalizationMethod`][c14n].
    ///
    /// [c14n]: ./transforms/enum.XmlSecCanonicalizationMethod.html
    pub fn canonicalization(mut self, c14n: XmlSecCanonicalizationMethod) -> Self {
        self.c14n = c14n;
        self
    }

    /// Sets cryptographic signature method. See: [`XmlSecSignatureMethod`][sig].
    ///
    /// [sig]: ./crypto/openssl/enum.XmlSecSignatureMethod.html
    pub fn signature(mut self, sig: XmlSecSignatureMethod) -> Self {
        self.sig = sig;
        self
    }

    /// the namespace prefix for the signature element (e.g. "dsig")
    pub fn ns_prefix(mut self, ns_prefix: &str) -> Self {
        self.ns_prefix = Some(ns_prefix.to_owned());
        self
    }

    /// use this node instead of root to add the signature node
    pub fn parent_node(mut self, parent_node: Node) -> Self {
        self.parent_node = Some(parent_node);
        self
    }
}

impl<'a> SignatureNode<'a> {
    fn keyname(&self, _add: bool) {
        // let keyinfo = unsafe { bindings::xmlSecTmplSignatureEnsureKeyInfo(signature, null()) };

        // if keyinfo.is_null() {
        //     panic!("Failed to ensure key info");
        // }

        // if self.options.keyname {
        //     let keyname = unsafe { bindings::xmlSecTmplKeyInfoAddKeyName(keyinfo, null()) };

        //     if keyname.is_null() {
        //         panic!("Failed to add key name");
        //     }
        // }

        // if self.options.keyvalue {
        //     let keyvalue = unsafe { bindings::xmlSecTmplKeyInfoAddKeyValue(keyinfo) };

        //     if keyvalue.is_null() {
        //         panic!("Failed to add key value");
        //     }
        // }

        // if self.options.x509data {
        //     let x509data = unsafe { bindings::xmlSecTmplKeyInfoAddX509Data(keyinfo) };

        //     if x509data.is_null() {
        //         panic!("Failed to add key value");
        //     }
        // }
    }
}
