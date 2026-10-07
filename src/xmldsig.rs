//!
//! Wrapper for XmlSec Signature Context
//!

use libxml::bindings::xmlChar;

use crate::bindings;

use crate::XmlSecError;
use crate::XmlSecKey;
use crate::XmlSecResult;

use crate::XmlDocument;
use crate::XmlNode;
use crate::XmlSecSignatureMethod;
use crate::xmlkeysmngr::XmlSecKeysMngr;

use std::ffi::c_char;
use std::mem::forget;
use std::ptr::null_mut;

/// Digest verification result for one SignedInfo reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmlSecReferenceVerification {
    /// URI exactly as supplied by the Reference, or None when absent.
    pub uri: Option<String>,
    /// Whether the reference digest matches.
    pub valid: bool,
}

/// Cryptographic verification with independent reference and signature results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmlSecSignatureVerification {
    /// Overall xmlsec verification outcome. Only this field means acceptance.
    pub verified: bool,
    /// Whether SignatureValue matches canonicalized SignedInfo.
    pub signature_valid: bool,
    /// Every SignedInfo reference, in document order.
    pub references: Vec<XmlSecReferenceVerification>,
}

/// Signature signing/veryfying context
pub struct XmlSecSignatureContext {
    ctx: *mut bindings::xmlSecDSigCtx,
    key_mngr: Option<XmlSecKeysMngr>,
}

impl XmlSecSignatureContext {
    /// Builds a context, ensuring xmlsec is initialized.
    pub fn new() -> Self {
        crate::xmlsec::guarantee_xmlsec_init();

        let ctx = unsafe { bindings::xmlSecDSigCtxCreate(null_mut()) };

        if ctx.is_null() {
            panic!("Failed to create dsig context");
        }

        Self {
            ctx,
            key_mngr: None,
        }
    }

    /// Builds a context, ensuring xmlsec is initialized.
    pub fn with_keys_manager(keys_mngr: XmlSecKeysMngr) -> Self {
        crate::xmlsec::guarantee_xmlsec_init();

        let ctx = unsafe { bindings::xmlSecDSigCtxCreate(keys_mngr.as_ptr()) };

        if ctx.is_null() {
            panic!("Failed to create dsig context");
        }

        Self {
            ctx,
            key_mngr: Some(keys_mngr),
        }
    }

    /// Sets the key to use for signature or verification. In case a key had
    /// already been set, the latter one gets released in the optional return.
    pub fn insert_key(&mut self, key: XmlSecKey) -> Option<XmlSecKey> {
        let mut old = None;

        unsafe {
            if !(*self.ctx).signKey.is_null() {
                old = Some(XmlSecKey::from_ptr((*self.ctx).signKey));
            }

            (*self.ctx).signKey = XmlSecKey::leak(key);
        }

        old
    }

    /// Releases a currently set key returning `Some(key)` or None otherwise.
    pub fn release_key(&mut self) -> Option<XmlSecKey> {
        unsafe {
            if (*self.ctx).signKey.is_null() {
                None
            } else {
                let key = XmlSecKey::from_ptr((*self.ctx).signKey);

                (*self.ctx).signKey = null_mut();

                Some(key)
            }
        }
    }

    /// UNTESTED
    pub fn sign_node(&self, node: &XmlNode) -> XmlSecResult<()> {
        self.key_is_set()?;

        let node = node.node_ptr() as libxml::bindings::xmlNodePtr;

        self.sign_node_raw(node)
    }

    /// Takes a [`XmlDocument`][xmldoc] and attempts to sign it. For this to work it has to have a properly structured
    /// `<dsig:Signature>` node within, and a XmlSecKey must have been previously set with [`insert_key`][inskey].
    ///
    /// # Errors
    ///
    /// If key has not been previously set or document is malformed.
    ///
    /// [xmldoc]: http://kwarc.github.io/rust-libxml/libxml/tree/document/struct.Document.html
    /// [inskey]: struct.XmlSecSignatureContext.html#method.insert_key
    pub fn sign_document(&self, doc: &XmlDocument) -> XmlSecResult<()> {
        self.key_is_set()?;

        let root = find_root(doc)?;
        let sig = find_signode(root)?;

        self.sign_node_raw(sig)
    }

    /// UNTESTED
    pub fn verify_node(&self, node: &XmlNode) -> XmlSecResult<bool> {
        self.key_is_set()?;

        let node = node.node_ptr() as libxml::bindings::xmlNodePtr;

        self.verify_node_raw(node)
    }

    /// Takes a [`XmlDocument`][xmldoc] and attempts to verify its signature. For this to work it has to have a properly
    /// structured and signed `<dsig:Signature>` node within, and a XmlSecKey must have been previously set with
    /// [`insert_key`][inskey].
    ///
    /// # Errors
    ///
    /// If key has not been previously set or document is malformed.
    ///
    /// [xmldoc]: http://kwarc.github.io/rust-libxml/libxml/tree/document/struct.Document.html
    /// [inskey]: struct.XmlSecSignatureContext.html#method.insert_key
    pub fn verify_document(&self, doc: &XmlDocument) -> XmlSecResult<bool> {
        self.key_is_set()?;

        let root = find_root(doc)?;
        let sig = find_signode(root)?;

        self.verify_node_raw(sig)
    }

    /// Verify every SignedInfo reference and SignatureValue independently.
    ///
    /// Unlike the ordinary verifier's early return on a bad digest, this method
    /// completes the remaining checks so callers can diagnose multiple failures.
    /// Call on a fresh context with a key or manager installed. Detailed diagnostics
    /// for manifest failures are unsupported and return an error.
    /// Processing errors remain errors, never partial verification success.
    pub fn verify_document_detailed(
        &mut self,
        doc: &XmlDocument,
    ) -> XmlSecResult<XmlSecSignatureVerification> {
        let verified = self.verify_document(doc)?;
        let signature = find_root(doc)?;
        // SAFETY: self owns the initialized context and doc keeps every node
        // alive. All new reference contexts are added to the parent's owned
        // list before processing, or explicitly destroyed on insertion failure.
        // Strings/results are copied out before the parent context is dropped.
        unsafe {
            let ctx = self.ctx;
            if !verified && bindings::xmlSecPtrListGetSize(&mut (*ctx).manifestReferences) != 0 {
                return Err("Detailed verification does not support manifests".into());
            }
            let signed_info = bindings::xmlSecFindChild(
                signature,
                &bindings::xmlSecNodeSignedInfo as *const xmlChar,
                &bindings::xmlSecDSigNs as *const xmlChar,
            );
            if signed_info.is_null()
                || (*ctx).signMethod.is_null()
                || (*ctx).signValueNode.is_null()
            {
                return Err(XmlSecError::NodeNotFound);
            }
            let list = &mut (*ctx).signedInfoReferences;
            let processed = bindings::xmlSecPtrListGetSize(list);
            let mut node = bindings::xmlSecFindChild(
                signed_info,
                &bindings::xmlSecNodeReference as *const xmlChar,
                &bindings::xmlSecDSigNs as *const xmlChar,
            );
            let mut index = 0;
            while !node.is_null() {
                if bindings::xmlSecCheckNodeName(
                    node,
                    &bindings::xmlSecNodeReference as *const xmlChar,
                    &bindings::xmlSecDSigNs as *const xmlChar,
                ) == 0
                {
                    return Err(XmlSecError::VerifyError);
                }
                if index >= processed {
                    let reference = bindings::xmlSecDSigReferenceCtxCreate(
                        ctx,
                        bindings::xmlSecDSigReferenceOrigin_xmlSecDSigReferenceOriginSignedInfo,
                    );
                    if reference.is_null() {
                        return Err(XmlSecError::VerifyError);
                    }
                    if bindings::xmlSecPtrListAdd(list, reference.cast()) < 0 {
                        bindings::xmlSecDSigReferenceCtxDestroy(reference);
                        return Err(XmlSecError::VerifyError);
                    }
                    if bindings::xmlSecDSigReferenceCtxProcessNode(reference, node) < 0 {
                        return Err(XmlSecError::VerifyError);
                    }
                }
                index += 1;
                node = bindings::xmlSecGetNextElementNode((*node).next);
            }
            if (*ctx).failureReason
                == bindings::xmlSecDSigFailureReason_xmlSecDSigFailureReasonReference
            {
                // xmlsec prepared the C14N/signature transform chain before it
                // checked references, but stopped before executing it. Finish
                // exactly that chain (including algorithm-specific parameters).
                let nodeset =
                    bindings::xmlSecNodeSetGetChildren((*signed_info).doc, signed_info, 1, 0);
                if nodeset.is_null() {
                    return Err(XmlSecError::VerifyError);
                }
                let result =
                    bindings::xmlSecTransformCtxXmlExecute(&mut (*ctx).transformCtx, nodeset);
                bindings::xmlSecNodeSetDestroy(nodeset);
                if result < 0
                    || bindings::xmlSecTransformVerifyNodeContent(
                        (*ctx).signMethod,
                        (*ctx).signValueNode,
                        &mut (*ctx).transformCtx,
                    ) < 0
                {
                    return Err(XmlSecError::VerifyError);
                }
            }
            let signature_valid = (*(*ctx).signMethod).status
                == bindings::xmlSecTransformStatus_xmlSecTransformStatusOk;
            let mut references = Vec::with_capacity(index);
            for index in 0..bindings::xmlSecPtrListGetSize(list) {
                let reference = bindings::xmlSecPtrListGetItem(list, index)
                    .cast::<bindings::xmlSecDSigReferenceCtx>();
                if reference.is_null() {
                    return Err(XmlSecError::VerifyError);
                }
                let valid = match (*reference).status {
                    bindings::xmlSecDSigStatus_xmlSecDSigStatusSucceeded => true,
                    bindings::xmlSecDSigStatus_xmlSecDSigStatusInvalid => false,
                    _ => return Err(XmlSecError::VerifyError),
                };
                let uri = if (*reference).uri.is_null() {
                    None
                } else {
                    Some(
                        std::ffi::CStr::from_ptr((*reference).uri.cast())
                            .to_string_lossy()
                            .into_owned(),
                    )
                };
                references.push(XmlSecReferenceVerification { uri, valid });
            }
            Ok(XmlSecSignatureVerification {
                verified,
                signature_valid,
                references,
            })
        }
    }

    /// Sets the verification time to be used for the signature verification.
    pub fn set_verification_time(&mut self, time: i64) {
        unsafe {
            (*self.ctx).keyInfoReadCtx.certsVerificationTime = time;
        }
    }

    /// # Safety
    ///
    /// Returns a raw pointer to the underlying xmlsec signature context. Beware that it is still managed by this
    /// wrapping object and will be deallocated once `self` gets dropped.
    pub unsafe fn as_ptr(&self) -> *mut bindings::xmlSecDSigCtx {
        self.ctx
    }

    /// # Safety
    ///
    /// Returns a raw pointer to the underlying xmlsec signature context. Beware that it will be forgotten by this
    /// wrapping object and *must* be deallocated manually by the callee.
    pub unsafe fn into_ptr(self) -> *mut bindings::xmlSecDSigCtx {
        let ctx = self.ctx; // keep a copy of the pointer

        forget(self); // release our copy of the pointer without deallocating it

        ctx // return the only remaining copy
    }

    /// Gets the signature method used in the context.
    pub fn signature_method(&self) -> Option<XmlSecSignatureMethod> {
        // SAFETY: self owns ctx, but xmlsec sets signMethod only after parsing
        // SignedInfo. An unused or unsuccessfully parsed context has no method.
        unsafe {
            let transform = (*self.ctx).signMethod;
            if transform.is_null() {
                return None;
            }
            let signmethod = (*transform).id;

            if signmethod.is_null() {
                None
            } else {
                XmlSecSignatureMethod::from_method(signmethod)
            }
        }
    }

    /// Gets the signature method name used in the context.
    pub fn signature_method_name(&self) -> Option<String> {
        // SAFETY: self owns ctx, but xmlsec sets signMethod only after parsing
        // SignedInfo. An unused or unsuccessfully parsed context has no method.
        unsafe {
            let transform = (*self.ctx).signMethod;
            if transform.is_null() {
                return None;
            }
            let signmethod = (*transform).id;

            if signmethod.is_null() {
                None
            } else {
                let name = (*signmethod).name;

                if name.is_null() {
                    None
                } else {
                    let name = std::ffi::CStr::from_ptr(name as *const c_char);
                    Some(name.to_string_lossy().into_owned())
                }
            }
        }
    }
}

impl XmlSecSignatureContext {
    fn key_is_set(&self) -> XmlSecResult<()> {
        unsafe {
            if !(*self.ctx).signKey.is_null() || self.key_mngr.is_some() {
                Ok(())
            } else {
                Err(XmlSecError::KeyNotLoaded)
            }
        }
    }

    fn sign_node_raw(&self, node: *mut libxml::bindings::xmlNode) -> XmlSecResult<()> {
        let rc = unsafe { bindings::xmlSecDSigCtxSign(self.ctx, node) };

        if rc < 0 {
            Err(XmlSecError::SigningError)
        } else {
            Ok(())
        }
    }

    fn verify_node_raw(&self, node: *mut libxml::bindings::xmlNode) -> XmlSecResult<bool> {
        let rc = unsafe { bindings::xmlSecDSigCtxVerify(self.ctx, node) };

        if rc < 0 {
            return Err(XmlSecError::VerifyError);
        }

        match unsafe { (*self.ctx).status } {
            bindings::xmlSecDSigStatus_xmlSecDSigStatusUnknown => Ok(false),
            bindings::xmlSecDSigStatus_xmlSecDSigStatusSucceeded => Ok(true),
            bindings::xmlSecDSigStatus_xmlSecDSigStatusInvalid => Ok(false),

            _ => panic!("Failed to interprete xmlSecDSigStatus code"),
        }
    }
}

impl Drop for XmlSecSignatureContext {
    fn drop(&mut self) {
        unsafe {
            bindings::xmlSecDSigCtxDestroy(self.ctx);
        };
    }
}

fn find_root(doc: &XmlDocument) -> XmlSecResult<*mut libxml::bindings::xmlNode> {
    if let Some(root) = doc.get_root_element() {
        let rawroot = root.node_ptr() as *mut libxml::bindings::xmlNode;
        let signode = find_signode(rawroot)?;

        Ok(signode)
    } else {
        Err(XmlSecError::RootNotFound)
    }
}

fn find_signode(
    tree: *mut libxml::bindings::xmlNode,
) -> XmlSecResult<*mut libxml::bindings::xmlNode> {
    let signode = unsafe {
        bindings::xmlSecFindNode(
            tree,
            &bindings::xmlSecNodeSignature as *const xmlChar,
            &bindings::xmlSecDSigNs as *const xmlChar,
        )
    };

    if signode.is_null() {
        return Err(XmlSecError::NodeNotFound);
    }

    Ok(signode)
}
