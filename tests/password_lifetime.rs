use openssl::{pkey::PKey, rsa::Rsa, symm::Cipher};
use xmlsec::{XmlSecKey, XmlSecKeyDataType, XmlSecKeyFormat};

#[test]
fn password_remains_alive_during_memory_and_file_key_loads() {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let password = "xmlsec-regression-password";
    let pem = key
        .private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), password.as_bytes())
        .unwrap();
    assert!(XmlSecKey::from_memory(&pem, XmlSecKeyFormat::Pem, Some(password)).is_ok());
    assert!(
        XmlSecKey::from_memory(&pem, XmlSecKeyFormat::Pem, Some("incorrect-password")).is_err()
    );
    let path = std::env::temp_dir().join(format!("xmlsec-password-{}.pem", std::process::id()));
    std::fs::write(&path, pem).unwrap();
    let result = XmlSecKey::from_file(
        path.to_str().unwrap(),
        XmlSecKeyDataType::Private,
        XmlSecKeyFormat::Pem,
        Some(password),
    );
    let wrong_password = XmlSecKey::from_file(
        path.to_str().unwrap(),
        XmlSecKeyDataType::Private,
        XmlSecKeyFormat::Pem,
        Some("incorrect-password"),
    );
    std::fs::remove_file(path).unwrap();
    assert!(wrong_password.is_err());
    assert!(result.is_ok());
}
