//!
//! Bindgen generated bindings
//!
#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(improper_ctypes)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::redundant_static_lifetimes)]

use libxml::bindings::xmlChar;
use libxml::bindings::xmlDocPtr;
use libxml::bindings::xmlExternalEntityLoader;
use libxml::bindings::xmlNodePtr;
use libxml::bindings::xmlNodeSetPtr;
use libxml::bindings::xmlOutputBufferPtr;
use libxml::bindings::xmlParserInputBufferPtr;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
