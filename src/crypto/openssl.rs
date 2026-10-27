//!
//! Wrapping for OpenSSL Crypto Backend Implementation for XmlSec Crypto Interface
//!
use crate::bindings;

/// Supported digesting and signing methods as specified by the XML standard.
#[allow(missing_docs)]
pub enum XmlSecSignatureMethod {
    Aes128Cbc,
    Aes192Cbc,
    Aes256Cbc,
    KWAes128,
    KWAes192,
    KWAes256,
    Des3Cbc,
    KWDes3,
    DsaSha1,
    DsaSha256,
    EcdsaSha1,
    EcdsaSha224,
    EcdsaSha256,
    EcdsaSha384,
    EcdsaSha512,
    #[cfg(xmlsec_ripemd160)]
    HmacRipemd160,
    HmacSha1,
    HmacSha224,
    HmacSha256,
    HmacSha384,
    HmacSha512,
    #[cfg(xmlsec_ripemd160)]
    Ripemd160,
    #[cfg(xmlsec_ripemd160)]
    RsaRipemd160,
    RsaSha1,
    RsaSha224,
    RsaSha256,
    RsaSha384,
    RsaSha512,
    RsaPkcs1,
    RsaOaep,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl XmlSecSignatureMethod {
    /// Returns the resource pointer for the corresponding digesting/signing resource
    pub fn to_method(&self) -> bindings::xmlSecTransformId
    {
        match self
        {
            Self::Aes128Cbc     => unsafe { bindings::xmlSecOpenSSLTransformAes128CbcGetKlass() },
            Self::Aes192Cbc     => unsafe { bindings::xmlSecOpenSSLTransformAes192CbcGetKlass() },
            Self::Aes256Cbc     => unsafe { bindings::xmlSecOpenSSLTransformAes256CbcGetKlass() },
            Self::KWAes128      => unsafe { bindings::xmlSecOpenSSLTransformKWAes128GetKlass() },
            Self::KWAes192      => unsafe { bindings::xmlSecOpenSSLTransformKWAes192GetKlass() },
            Self::KWAes256      => unsafe { bindings::xmlSecOpenSSLTransformKWAes256GetKlass() },
            Self::Des3Cbc       => unsafe { bindings::xmlSecOpenSSLTransformDes3CbcGetKlass() },
            Self::KWDes3        => unsafe { bindings::xmlSecOpenSSLTransformKWDes3GetKlass() },
            Self::DsaSha1       => unsafe { bindings::xmlSecOpenSSLTransformDsaSha1GetKlass() },
            Self::DsaSha256     => unsafe { bindings::xmlSecOpenSSLTransformDsaSha256GetKlass() },
            Self::EcdsaSha1     => unsafe { bindings::xmlSecOpenSSLTransformEcdsaSha1GetKlass() },
            Self::EcdsaSha224   => unsafe { bindings::xmlSecOpenSSLTransformEcdsaSha224GetKlass() },
            Self::EcdsaSha256   => unsafe { bindings::xmlSecOpenSSLTransformEcdsaSha256GetKlass() },
            Self::EcdsaSha384   => unsafe { bindings::xmlSecOpenSSLTransformEcdsaSha384GetKlass() },
            Self::EcdsaSha512   => unsafe { bindings::xmlSecOpenSSLTransformEcdsaSha512GetKlass() },
            #[cfg(xmlsec_ripemd160)]
            Self::HmacRipemd160 => unsafe { bindings::xmlSecOpenSSLTransformHmacRipemd160GetKlass() },
            Self::HmacSha1      => unsafe { bindings::xmlSecOpenSSLTransformHmacSha1GetKlass() },
            Self::HmacSha224    => unsafe { bindings::xmlSecOpenSSLTransformHmacSha224GetKlass() },
            Self::HmacSha256    => unsafe { bindings::xmlSecOpenSSLTransformHmacSha256GetKlass() },
            Self::HmacSha384    => unsafe { bindings::xmlSecOpenSSLTransformHmacSha384GetKlass() },
            Self::HmacSha512    => unsafe { bindings::xmlSecOpenSSLTransformHmacSha512GetKlass() },
            #[cfg(xmlsec_ripemd160)]
            Self::Ripemd160     => unsafe { bindings::xmlSecOpenSSLTransformRipemd160GetKlass() },
            #[cfg(xmlsec_ripemd160)]
            Self::RsaRipemd160  => unsafe { bindings::xmlSecOpenSSLTransformRsaRipemd160GetKlass() },
            Self::RsaSha1       => unsafe { bindings::xmlSecOpenSSLTransformRsaSha1GetKlass() },
            Self::RsaSha224     => unsafe { bindings::xmlSecOpenSSLTransformRsaSha224GetKlass() },
            Self::RsaSha256     => unsafe { bindings::xmlSecOpenSSLTransformRsaSha256GetKlass() },
            Self::RsaSha384     => unsafe { bindings::xmlSecOpenSSLTransformRsaSha384GetKlass() },
            Self::RsaSha512     => unsafe { bindings::xmlSecOpenSSLTransformRsaSha512GetKlass() },
            Self::RsaPkcs1      => unsafe { bindings::xmlSecOpenSSLTransformRsaPkcs1GetKlass() },
            Self::RsaOaep       => unsafe { bindings::xmlSecOpenSSLTransformRsaOaepGetKlass() },
            Self::Sha1          => unsafe { bindings::xmlSecOpenSSLTransformSha1GetKlass() },
            Self::Sha224        => unsafe { bindings::xmlSecOpenSSLTransformSha224GetKlass() },
            Self::Sha256        => unsafe { bindings::xmlSecOpenSSLTransformSha256GetKlass() },
            Self::Sha384        => unsafe { bindings::xmlSecOpenSSLTransformSha384GetKlass() },
            Self::Sha512        => unsafe { bindings::xmlSecOpenSSLTransformSha512GetKlass() },
        }
    }

    pub(crate) fn from_method(method: bindings::xmlSecTransformId) -> Option<Self> {
        match method {
            _ if method == unsafe { bindings::xmlSecOpenSSLTransformAes128CbcGetKlass() } => {
                Some(Self::Aes128Cbc)
            }
            _ if method == unsafe { bindings::xmlSecOpenSSLTransformAes192CbcGetKlass() } => {
                Some(Self::Aes192Cbc)
            }
            _ if method == unsafe { bindings::xmlSecOpenSSLTransformAes256CbcGetKlass() } => {
                Some(Self::Aes256Cbc)
            }
            // _ if method == unsafe { bindings::xmlSecOpenSSLTransformAes128GcmGetKlass() } => {
            //     Some(Self::Aes128Gcm)
            // }
            // _ if method == unsafe { bindings::xmlSecOpenSSLTransformAes192GcmGetKlass() } => {
            //     Some(Self::Aes192Gcm)
            // }
            // _ if method == unsafe { bindings::xmlSecOpenSSLTransformAes256GcmGetKlass() } => {
            //     Some(Self::Aes256Gcm)
            // }
            _ if method == unsafe { bindings::xmlSecOpenSSLTransformKWAes128GetKlass() } => {
                Some(Self::KWAes128)
            }
            _ if method == unsafe { bindings::xmlSecOpenSSLTransformKWAes192GetKlass() } => {
                Some(Self::KWAes192)
            }
            _ if method == unsafe { bindings::xmlSecOpenSSLTransformKWAes256GetKlass() } => {
                Some(Self::KWAes256)
            }
            _ if method == unsafe { bindings::xmlSecOpenSSLTransformDes3CbcGetKlass() } => {
                Some(Self::Des3Cbc)
            }
            _ if method == unsafe { bindings::xmlSecOpenSSLTransformKWDes3GetKlass() } => {
                Some(Self::KWDes3)
            }
            _ if method == unsafe { bindings::xmlSecOpenSSLTransformDsaSha1GetKlass() } => {
                Some(Self::DsaSha1)
            }
            _ if method == unsafe { bindings::xmlSecOpenSSLTransformDsaSha256GetKlass() } => {
                Some(Self::DsaSha256)
            }
            _ if method == unsafe { bindings::xmlSecOpenSSLTransformEcdsaSha1GetKlass() } => {
                Some(Self::EcdsaSha1)
            }
            _ if method == unsafe { bindings::xmlSecOpenSSLTransformEcdsaSha224GetKlass() } => {
                Some(Self::EcdsaSha224)
            }
            _ if method == unsafe { bindings::xmlSecOpenSSLTransformEcdsaSha256GetKlass() } => {
                Some(Self::EcdsaSha256)
            }
            _ if method == unsafe { bindings::xmlSecOpenSSLTransformEcdsaSha384GetKlass() } => {
                Some(Self::EcdsaSha384)
            }
            _ if method == unsafe { bindings::xmlSecOpenSSLTransformEcdsaSha512GetKlass() } => {
                Some(Self::EcdsaSha512)
            }
            // _ if method == unsafe { bindings::xmlSecOpenSSLTransformHmacMd5GetKlass() } => {
            //     Some(Self::HmacMd5)
            // }
            #[cfg(xmlsec_ripemd160)]
            _ if method == unsafe { bindings::xmlSecOpenSSLTransformHmacRipemd160GetKlass() } => {
                Some(Self::HmacRipemd160)
            }
            _ if method == unsafe { bindings::xmlSecOpenSSLTransformHmacSha1GetKlass() } => {
                Some(Self::HmacSha1)
            }
            _ if method == unsafe { bindings::xmlSecOpenSSLTransformHmacSha224GetKlass() } => {
                Some(Self::HmacSha224)
            }
            _ if method == unsafe { bindings::xmlSecOpenSSLTransformHmacSha256GetKlass() } => {
                Some(Self::HmacSha256)
            }
            _ if method == unsafe { bindings::xmlSecOpenSSLTransformHmacSha384GetKlass() } => {
                Some(Self::HmacSha384)
            }
            _ if method == unsafe { bindings::xmlSecOpenSSLTransformHmacSha512GetKlass() } => {
                Some(Self::HmacSha512)
            }
            // _ if method == unsafe { bindings::xmlSecOpenSSLTransformMd5GetKlass() } => {
            //     Some(Self::Md5)
            // }
            #[cfg(xmlsec_ripemd160)]
            _ if method == unsafe { bindings::xmlSecOpenSSLTransformRipemd160GetKlass() } => {
                Some(Self::Ripemd160)
            }
            // _ if method == unsafe { bindings::xmlSecOpenSSLTransformRsaMd5GetKlass() } => {
            //     Some(Self::RsaMd5)
            // }
            #[cfg(xmlsec_ripemd160)]
            _ if method == unsafe { bindings::xmlSecOpenSSLTransformRsaRipemd160GetKlass() } => {
                Some(Self::RsaRipemd160)
            }
            _ if method == unsafe { bindings::xmlSecOpenSSLTransformRsaSha1GetKlass() } => {
                Some(Self::RsaSha1)
            }
            _ if method == unsafe { bindings::xmlSecOpenSSLTransformRsaSha224GetKlass() } => {
                Some(Self::RsaSha224)
            }
            _ if method == unsafe { bindings::xmlSecOpenSSLTransformRsaSha256GetKlass() } => {
                Some(Self::RsaSha256)
            }
            _ if method == unsafe { bindings::xmlSecOpenSSLTransformRsaSha384GetKlass() } => {
                Some(Self::RsaSha384)
            }
            _ if method == unsafe { bindings::xmlSecOpenSSLTransformRsaSha512GetKlass() } => {
                Some(Self::RsaSha512)
            }
            _ if method == unsafe { bindings::xmlSecOpenSSLTransformRsaPkcs1GetKlass() } => {
                Some(Self::RsaPkcs1)
            }
            _ if method == unsafe { bindings::xmlSecOpenSSLTransformRsaOaepGetKlass() } => {
                Some(Self::RsaOaep)
            }
            _ if method == unsafe { bindings::xmlSecOpenSSLTransformSha1GetKlass() } => {
                Some(Self::Sha1)
            }
            _ if method == unsafe { bindings::xmlSecOpenSSLTransformSha224GetKlass() } => {
                Some(Self::Sha224)
            }
            _ if method == unsafe { bindings::xmlSecOpenSSLTransformSha256GetKlass() } => {
                Some(Self::Sha256)
            }
            _ if method == unsafe { bindings::xmlSecOpenSSLTransformSha384GetKlass() } => {
                Some(Self::Sha384)
            }
            _ if method == unsafe { bindings::xmlSecOpenSSLTransformSha512GetKlass() } => {
                Some(Self::Sha512)
            }
            _ => None,
        }
    }
}
