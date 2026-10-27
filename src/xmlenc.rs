//!
//! Wrapper for XmlSec Signature Context
//!

use crate::bindings;

use crate::XmlSecError;
use crate::XmlSecKey;
use crate::XmlSecResult;

use crate::xmlkeysmngr::XmlSecKeysMngr;
use crate::XmlNode;

use std::ptr::null_mut;

/// Signature signing/veryfying context
pub struct XmlSecEncryptionContext {
    ctx: *mut bindings::xmlSecEncCtx,
    key_mngr: Option<XmlSecKeysMngr>,
}

impl XmlSecEncryptionContext {
    /// Builds a context, ensuring xmlsec is initialized.
    pub fn new() -> Self {
        crate::xmlsec::guarantee_xmlsec_init();

        let ctx = unsafe { bindings::xmlSecEncCtxCreate(null_mut()) };

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

        let ctx = unsafe { bindings::xmlSecEncCtxCreate(keys_mngr.as_ptr()) };

        if ctx.is_null() {
            panic!("Failed to create dsig context");
        }

        Self {
            ctx,
            key_mngr: Some(keys_mngr),
        }
    }

    /// Set encryption/descryption key
    pub fn set_key(&mut self, key: XmlSecKey) -> &mut Self {
        unsafe {
            if !(*self.ctx).encKey.is_null() {
                std::mem::drop(XmlSecKey::from_ptr((*self.ctx).encKey));
            }

            (*self.ctx).encKey = XmlSecKey::leak(key);
        }

        self
    }

    /// Set encryption context mode, default: XmlSecEncryptionContextMode::Data
    pub fn set_mode(&mut self, mode: XmlSecEncryptionContextMode) -> &mut Self {
        match mode {
            XmlSecEncryptionContextMode::Key => unsafe {
                (*self.ctx).mode = bindings::xmlSecEncCtxMode_xmlSecEncCtxModeEncryptedKey;
            },
            _ => unsafe {
                (*self.ctx).mode = bindings::xmlSecEncCtxMode_xmlSecEncCtxModeEncryptedData;
            },
        };
        self
    }

    /// decrypt node
    pub fn decrypt(&mut self, node: &XmlNode) -> XmlSecResult<&[u8]> {
        let node = node.node_ptr() as libxml::bindings::xmlNodePtr;

        let result = unsafe { bindings::xmlSecEncCtxDecrypt(self.ctx, node) };

        if result < 0 {
            return Err(XmlSecError::SigningError);
        }

        unsafe {
            let s = bindings::xmlSecBufferGetSize((*self.ctx).result);
            let p = bindings::xmlSecBufferGetData((*self.ctx).result);

            if p.is_null() || s == 0 {
                return Err(XmlSecError::SigningError);
            }

            let buf = std::slice::from_raw_parts(p, s);

            Ok(buf)
        }
    }
}

#[allow(missing_docs)]
pub enum XmlSecEncryptionContextMode {
    Data,
    Key,
}

impl Drop for XmlSecEncryptionContext {
    fn drop(&mut self) {
        unsafe {
            bindings::xmlSecEncCtxDestroy(self.ctx);
        };
    }
}
