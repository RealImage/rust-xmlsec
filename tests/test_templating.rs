//!
//! Testing of Template Creation
//!
use xmlsec::ReferenceSignatureBuilder;
use xmlsec::XmlSecCanonicalizationMethod;
use xmlsec::XmlSecDocumentTemplateBuilder;
use xmlsec::XmlSecDocumentTemplating;
use xmlsec::XmlSecSignatureMethod;
use xmlsec::XmlSecTemplateBuilder;

use libxml::parser::Parser as XmlParser;

#[test]
fn test_template_creation() {
    // load document
    let parser = XmlParser::default();

    let doc = parser
        .parse_file("tests/resources/sign2-doc.xml")
        .expect("Could not load template document");

    // add signature node structure
    let signature_node = doc
        .template()
        .canonicalization(XmlSecCanonicalizationMethod::ExclusiveC14N)
        .signature(XmlSecSignatureMethod::RsaSha1)
        // .keyname(true)
        // .keyvalue(true)
        // .x509data(true)
        // .uri("ReferencedID")
        // .done()
        .build()
        .expect("Failed to build and attach signature");

    ReferenceSignatureBuilder::new(&signature_node)
        .uri("ReferencedID")
        .add_node();

    // compare template results
    let reference =
        String::from_utf8(include_bytes!("./resources/sign2-tmpl.xml").to_vec()).unwrap();

    assert_eq!(doc.to_string(), reference);
}

#[test]
fn test_template_creation_with_ns_prefix() {
    // load document
    let parser = XmlParser::default();

    let doc = parser
        .parse_file("tests/resources/sign2-doc.xml")
        .expect("Could not load template document");

    // add signature node structure
    let sign_node = XmlSecDocumentTemplateBuilder::new(&doc)
        .canonicalization(XmlSecCanonicalizationMethod::ExclusiveC14N)
        .signature(XmlSecSignatureMethod::RsaSha1)
        .ns_prefix("dsig")
        .build()
        .expect("Failed to build and attach signature");

    ReferenceSignatureBuilder::new(&sign_node)
        .uri("ReferencedID")
        .add_node();

    // compare template results
    let reference =
        String::from_utf8(include_bytes!("./resources/sign2-tmpl-ns-prefix-dsig.xml").to_vec())
            .unwrap();

    assert_eq!(doc.to_string(), reference);
}

#[test]
fn reference_canonicalization_follows_the_enveloped_transform() {
    let doc = XmlParser::default().parse_string("<root/>").unwrap();
    let signature = XmlSecDocumentTemplateBuilder::new(&doc)
        .canonicalization(XmlSecCanonicalizationMethod::InclusiveC14NWithComments)
        .signature(XmlSecSignatureMethod::RsaSha256)
        .build()
        .unwrap();
    ReferenceSignatureBuilder::new(&signature)
        .signature(XmlSecSignatureMethod::Sha256)
        .uri("")
        .with_enveloped(true)
        .canonicalization(XmlSecCanonicalizationMethod::InclusiveC14NWithComments)
        .add_node();
    let xpath = libxml::xpath::Context::new(&doc).unwrap();
    xpath
        .register_namespace("ds", "http://www.w3.org/2000/09/xmldsig#")
        .unwrap();
    let nodes = xpath
        .evaluate("//ds:Reference/ds:Transforms/ds:Transform")
        .unwrap()
        .get_nodes_as_vec();
    let algorithms: Vec<_> = nodes
        .iter()
        .map(|n| n.get_property("Algorithm").unwrap())
        .collect();
    assert_eq!(
        algorithms,
        [
            "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
        ]
    );
}
