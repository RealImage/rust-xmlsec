use libxml::parser::Parser;
use xmlsec::{
    ReferenceSignatureBuilder, XmlSecCanonicalizationMethod, XmlSecDocumentExt,
    XmlSecDocumentTemplateBuilder, XmlSecKey, XmlSecKeyFormat, XmlSecSignatureContext,
    XmlSecSignatureMethod,
};

fn key() -> XmlSecKey {
    XmlSecKey::from_memory(
        include_bytes!("resources/key.pem"),
        XmlSecKeyFormat::Pem,
        None,
    )
    .unwrap()
}
fn signed() -> String {
    let doc = Parser::default()
        .parse_string("<root><Data Id=\"a\">one</Data><Data Id=\"b\">two</Data></root>")
        .unwrap();
    doc.specify_idattr("//Data", "Id", None).unwrap();
    let signature = XmlSecDocumentTemplateBuilder::new(&doc)
        .signature(XmlSecSignatureMethod::RsaSha256)
        .ns_prefix("ds")
        .build()
        .unwrap();
    for uri in ["#a", "#b"] {
        ReferenceSignatureBuilder::new(&signature)
            .signature(XmlSecSignatureMethod::Sha256)
            .uri(uri)
            .canonicalization(XmlSecCanonicalizationMethod::InclusiveC14N)
            .add_node();
    }
    let mut ctx = XmlSecSignatureContext::new();
    ctx.insert_key(key());
    ctx.sign_document(&doc).unwrap();
    doc.to_string()
}

#[test]
fn report_checks_all_references_and_signed_info_independently() {
    let xml = signed();
    for (bad_references, signature_bad) in
        (0u8..4).flat_map(|mask| [false, true].map(|bad| (mask, bad)))
    {
        let doc = Parser::default().parse_string(&xml).unwrap();
        doc.specify_idattr("//Data", "Id", None).unwrap();
        let root = doc.get_root_element().unwrap();
        {
            for (index, mut data) in root
                .get_child_elements()
                .into_iter()
                .filter(|node| node.get_name() == "Data")
                .enumerate()
            {
                if bad_references & (1 << index) != 0 {
                    data.set_content("changed").unwrap();
                }
            }
        }
        if signature_bad {
            let sig = root
                .get_child_elements()
                .into_iter()
                .find(|node| node.get_name() == "Signature")
                .unwrap();
            let mut value = sig
                .get_child_elements()
                .into_iter()
                .find(|node| node.get_name() == "SignatureValue")
                .unwrap();
            let mut text = value.get_content();
            text.replace_range(..1, if text.starts_with('A') { "B" } else { "A" });
            value.set_content(&text).unwrap();
        }
        let before = doc.to_string();
        let mut ctx = XmlSecSignatureContext::new();
        ctx.insert_key(key());
        let report = ctx.verify_document_detailed(&doc).unwrap();
        assert_eq!(report.verified, bad_references == 0 && !signature_bad);
        assert_eq!(report.signature_valid, !signature_bad);
        assert_eq!(report.references.len(), 2);
        for (index, reference) in report.references.iter().enumerate() {
            assert_eq!(reference.uri.as_deref(), Some(["#a", "#b"][index]));
            assert_eq!(reference.valid, bad_references & (1 << index) == 0);
        }
        let mut ordinary = XmlSecSignatureContext::new();
        ordinary.insert_key(key());
        assert_eq!(ordinary.verify_document(&doc).unwrap(), report.verified);
        assert_eq!(
            doc.to_string(),
            before,
            "verification must not mutate signed XML"
        );
    }
}

#[test]
fn fresh_context_methods_are_absent() {
    let context = XmlSecSignatureContext::new();
    assert!(context.signature_method().is_none());
    assert!(context.signature_method_name().is_none());
}

#[test]
fn malformed_signature_returns_an_error_without_a_signature_method() {
    let doc = Parser::default()
        .parse_string(
            "<root><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"/></root>",
        )
        .unwrap();
    let mut context = XmlSecSignatureContext::new();
    context.insert_key(key());
    assert!(context.verify_document_detailed(&doc).is_err());
    assert!(context.signature_method().is_none());
    assert!(context.signature_method_name().is_none());
}
