use crown::{
    asn1::{der::Reader, oid},
    error::CryptoError,
    pkcs7::ContentInfo,
    pkcs12::{Bag, Pfx, SafeBag},
    x509::{
        algorithm::AlgorithmIdentifier,
        attribute::parse_attributes,
        pbe::{LegacyPbe, Pbes2},
    },
};
use zeroize::Zeroizing;

use crate::{certificate, certificate_file, keystore::KeystoreEntry};

const MAX_ITERATIONS: u32 = 1_000_000;
const MAX_SALT_SIZE: usize = 64;
const TRUSTED_KEY_USAGE: &[u64] = &[2, 16, 840, 1, 113894, 746875, 1, 1];

pub struct Store(Pfx);

#[derive(Debug)]
pub enum VerifyError {
    Password,
    Invalid(&'static str),
}

pub struct Verified {
    pub entries: Vec<KeystoreEntry>,
    pub incomplete: bool,
}

pub fn parse(data: &[u8]) -> Result<Store, &'static str> {
    let pfx = Pfx::parse(data).map_err(|_| "invalid PKCS12 structure")?;
    if pfx.version != 3 {
        return Err("unsupported PKCS12 version");
    }
    let mac = pfx.mac.as_ref().ok_or("PKCS12 integrity MAC is missing")?;
    if mac.iterations == 0 || mac.iterations > MAX_ITERATIONS || mac.salt.len() > MAX_SALT_SIZE {
        return Err("PKCS12 MAC iteration count is unsupported");
    }
    Ok(Store(pfx))
}

impl Store {
    pub fn verify(&self, password: &str) -> Result<Verified, VerifyError> {
        let mut password_bytes = password.as_bytes();
        let mut mac_result = self.0.verify_mac(password_bytes);
        // Java also accepts a NUL character as the encoding of an empty password.
        if password.is_empty() && mac_result == Err(CryptoError::AuthenticationFailed) {
            mac_result = self.0.verify_mac(b"\0");
            if mac_result.is_ok() {
                password_bytes = b"\0";
            }
        }
        mac_result.map_err(|error| {
            if error == CryptoError::AuthenticationFailed {
                VerifyError::Password
            } else {
                VerifyError::Invalid("unsupported or invalid PKCS12 integrity MAC")
            }
        })?;

        let safe = self
            .0
            .authenticated_safe()
            .map_err(|_| VerifyError::Invalid("invalid PKCS12 content"))?;
        let mut reader = Reader::new(&safe);
        let mut sequence = reader
            .read_sequence()
            .map_err(|_| VerifyError::Invalid("invalid PKCS12 content"))?;
        let mut bags = Vec::new();
        let mut incomplete = false;
        while !sequence.is_empty() {
            let info = match ContentInfo::parse_reader(&mut sequence) {
                Ok(info) => info,
                Err(_) => {
                    incomplete = true;
                    break;
                }
            };
            let content = if info.content_type.matches(oid::OID_PKCS7_DATA) {
                Reader::new(&info.content)
                    .read_octet_string_owned()
                    .map(Zeroizing::new)
                    .ok()
            } else if info.content_type.matches(oid::OID_PKCS7_ENCRYPTED_DATA) {
                decrypt_safe(&info.content, password_bytes)
                    .ok()
                    .map(Zeroizing::new)
            } else {
                None
            };
            if let Some(content) = content {
                let mut reader = Reader::new(&content);
                if let Ok(mut sequence) = reader.read_sequence() {
                    while !sequence.is_empty() {
                        match sequence.read_raw_tlv() {
                            Ok(raw) => match parse_metadata_bag(raw) {
                                Ok(Some(bag)) => bags.push(bag),
                                Ok(None) | Err(_) => incomplete = true,
                            },
                            Err(_) => {
                                incomplete = true;
                                break;
                            }
                        }
                    }
                } else {
                    incomplete = true;
                }
            } else {
                incomplete = true;
            }
        }

        let pool: Vec<_> = bags
            .iter()
            .filter_map(|bag| bag.certificate_der.as_deref())
            .collect();
        let mut entries = Vec::new();
        let mut unnamed_keys = 0;
        for bag in &bags {
            if matches!(bag.bag, Bag::ShroudedKey(_)) {
                // Java and OpenSSL give the key and its end-entity certificate
                // the same local key ID.
                let leaf = bag
                    .local_key_id()
                    .and_then(|id| {
                        bags.iter().find(|other| {
                            other.certificate_der.is_some()
                                && other.local_key_id().as_ref() == Some(&id)
                        })
                    })
                    .and_then(|bag| bag.certificate_der.as_deref());
                // OpenSSL only stores a friendly name when given one.
                let alias = bag
                    .friendly_name()
                    .or_else(|| leaf.and_then(certificate_file::subject_name))
                    .unwrap_or_else(|| {
                        unnamed_keys += 1;
                        format!("Private key {unnamed_keys}")
                    });
                let (certificates, chain_warning) = leaf.map_or_else(
                    || (vec![], None),
                    |leaf| certificate::details::chain(leaf, &pool),
                );
                entries.push(KeystoreEntry {
                    alias,
                    kind: "Private key",
                    certificate: leaf.and_then(certificate::summarize),
                    certificates,
                    chain_warning,
                    document: None,
                });
            }
        }
        let mut unnamed_certificates = 0;
        for bag in &bags {
            match &bag.bag {
                Bag::Secret { .. } => {
                    if let Some(alias) = bag.friendly_name() {
                        entries.push(KeystoreEntry {
                            alias,
                            kind: "Secret key",
                            certificate: None,
                            certificates: vec![],
                            chain_warning: None,
                            document: None,
                        });
                    } else {
                        incomplete = true;
                    }
                }
                _ if bag.certificate_der.is_some() => {
                    let der = bag.certificate_der.as_deref().unwrap();
                    // Java identifies trusted entries with its trustedKeyUsage
                    // attribute. Other tools store plain certificates, which
                    // are listed unless they belong to a key's chain.
                    if !bag
                        .attributes
                        .iter()
                        .any(|attr| attr.oid.matches(TRUSTED_KEY_USAGE))
                    {
                        if entries.iter().any(|entry| {
                            entry.kind == "Private key"
                                && entry.certificates.iter().any(|stored| stored == der)
                        }) {
                            continue;
                        }
                        let alias = bag
                            .friendly_name()
                            .or_else(|| certificate_file::subject_name(der))
                            .unwrap_or_else(|| {
                                unnamed_certificates += 1;
                                format!("Certificate {unnamed_certificates}")
                            });
                        let (certificates, chain_warning) = certificate::details::chain(der, &pool);
                        entries.push(KeystoreEntry {
                            alias,
                            kind: certificate_file::KIND,
                            certificate: certificate::summarize(der),
                            certificates,
                            chain_warning,
                            document: None,
                        });
                        continue;
                    }
                    if let Some(alias) = bag.friendly_name() {
                        if !entries
                            .iter()
                            .any(|entry| entry.alias.eq_ignore_ascii_case(&alias))
                        {
                            let (certificates, chain_warning) =
                                certificate::details::chain(der, &pool);
                            entries.push(KeystoreEntry {
                                alias,
                                kind: "Trusted certificate",
                                certificate: certificate::summarize(der),
                                certificates,
                                chain_warning,
                                document: None,
                            });
                        }
                    } else {
                        incomplete = true;
                    }
                }
                Bag::ShroudedKey(_) => {}
                _ => incomplete = true,
            }
        }
        entries.sort_by(|a, b| a.alias.cmp(&b.alias));
        Ok(Verified {
            entries,
            incomplete,
        })
    }
}

struct MetadataBag {
    metadata: SafeBag,
    certificate_der: Option<Vec<u8>>,
}

impl std::ops::Deref for MetadataBag {
    type Target = SafeBag;
    fn deref(&self) -> &Self::Target {
        &self.metadata
    }
}

fn parse_metadata_bag(raw: &[u8]) -> Result<Option<MetadataBag>, CryptoError> {
    let mut reader = Reader::new(raw);
    let mut bag = reader.read_sequence()?;
    let id = bag.read_oid()?;
    // Crown parses plaintext keyBag contents; Java PKCS12 uses shrouded key bags.
    if id.matches(oid::OID_PKCS12_KEY_BAG) || id.matches(oid::OID_PKCS12_SAFE_CONTENTS_BAG) {
        return Ok(None);
    }
    // Keep original DER and bag attributes even when a certificate or its
    // public-key algorithm cannot be decoded by crown. Keys stay opaque.
    if id.matches(oid::OID_PKCS12_CERT_BAG) {
        let mut value = bag.read_explicit(0)?;
        let mut cert_bag = value.read_sequence()?;
        if !cert_bag.read_oid()?.matches(oid::OID_X509_CERTIFICATE) {
            return Ok(None);
        }
        let mut cert_value = cert_bag.read_explicit(0)?;
        let certificate_der = cert_value.read_octet_string_owned()?;
        cert_value.expect_end()?;
        cert_bag.expect_end()?;
        value.expect_end()?;
        let attributes = if bag.is_empty() {
            vec![]
        } else {
            parse_attributes(&mut bag)?
        };
        bag.expect_end()?;
        reader.expect_end()?;
        return Ok(Some(MetadataBag {
            metadata: SafeBag {
                bag: Bag::Other {
                    oid: id,
                    value: vec![],
                },
                attributes,
            },
            certificate_der: Some(certificate_der),
        }));
    }
    let mut reader = Reader::new(raw);
    let bag = SafeBag::parse(&mut reader)?;
    reader.expect_end()?;
    Ok(Some(MetadataBag {
        metadata: bag,
        certificate_der: None,
    }))
}

fn decrypt_safe(content: &[u8], password: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut reader = Reader::new(content);
    let mut sequence = reader.read_sequence()?;
    let _version = sequence.read_integer()?;
    let mut info = sequence.read_sequence()?;
    let _content_type = info.read_oid()?;
    let algorithm = AlgorithmIdentifier::parse(&mut info)?;
    let ciphertext = info.read_implicit(0, false)?;
    if algorithm.oid.matches(oid::OID_PBES2) {
        let pbe = Pbes2::parse(&algorithm)?;
        if pbe.iterations == 0 || pbe.iterations > MAX_ITERATIONS || pbe.salt.len() > MAX_SALT_SIZE
        {
            return Err(CryptoError::InvalidRound(pbe.iterations as usize));
        }
        pbe.decrypt(ciphertext, password)
    } else {
        let pbe = LegacyPbe::parse(&algorithm)?;
        if pbe.iterations == 0 || pbe.iterations > MAX_ITERATIONS || pbe.salt.len() > MAX_SALT_SIZE
        {
            return Err(CryptoError::InvalidRound(pbe.iterations as usize));
        }
        pbe.decrypt(ciphertext, password)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{fixture_certificate_der, fixture_summary};
    use crown::{
        asn1::{der, oid::ObjectIdentifier},
        pkcs12::SafeBag,
        rng::Rng,
        x509::{
            Certificate,
            algorithm::AlgorithmIdentifier,
            attribute::{friendly_name, local_key_id},
            keys::EncryptedPrivateKeyInfo,
        },
    };

    const MODERN: &[u8] = include_bytes!("../tests/fixtures/trusted-cert.p12");
    const LEGACY: &[u8] = include_bytes!("../tests/fixtures/trusted-cert-legacy.p12");
    const UNICODE_ALIAS: &[u8] = include_bytes!("../tests/fixtures/unicode-alias.p12");
    const EMPTY_PASSWORD: &[u8] = include_bytes!("../tests/fixtures/empty-password.p12");
    const NUL_PASSWORD: &[u8] = include_bytes!("../tests/fixtures/nul-password.p12");
    const OPENSSL: &[u8] = include_bytes!("../tests/fixtures/openssl-cert.p12");
    const OPENSSL_LEGACY: &[u8] = include_bytes!("../tests/fixtures/openssl-cert-legacy.p12");

    struct TestRng(u8);
    impl Rng for TestRng {
        fn fill_bytes(&mut self, bytes: &mut [u8]) {
            for byte in bytes {
                self.0 = self.0.wrapping_add(1);
                *byte = self.0;
            }
        }
    }

    fn synthetic(bags: Vec<SafeBag>) -> Vec<u8> {
        Pfx::build(bags, b"changeit", 100, &mut TestRng(0))
            .unwrap()
            .encode()
    }

    #[test]
    fn reads_java_truststores_with_modern_and_legacy_crypto() {
        for data in [MODERN, LEGACY] {
            let store = parse(data).unwrap();
            assert!(matches!(store.verify("wrong"), Err(VerifyError::Password)));
            let verified = store.verify("changeit").unwrap();
            assert_eq!(
                verified.entries,
                vec![KeystoreEntry {
                    alias: "root-cert".into(),
                    kind: "Trusted certificate",
                    certificate: Some(fixture_summary()),
                    certificates: vec![fixture_certificate_der().to_vec()],
                    chain_warning: None,
                    document: None,
                }]
            );
            assert!(!verified.incomplete);
        }
    }

    #[test]
    fn reads_openssl_certificate_stores_without_java_attributes() {
        for data in [OPENSSL, OPENSSL_LEGACY] {
            let store = parse(data).unwrap();
            assert!(matches!(store.verify("wrong"), Err(VerifyError::Password)));
            let verified = store.verify("changeit").unwrap();
            assert_eq!(
                verified.entries,
                vec![KeystoreEntry {
                    alias: "JKS TUI test fixture".into(),
                    kind: certificate_file::KIND,
                    certificate: Some(fixture_summary()),
                    certificates: vec![fixture_certificate_der().to_vec()],
                    chain_warning: None,
                    document: None,
                }]
            );
            assert!(!verified.incomplete);
        }
    }

    #[test]
    fn reads_a_java_unicode_alias() {
        let verified = parse(UNICODE_ALIAS).unwrap().verify("changeit").unwrap();
        assert_eq!(verified.entries[0].alias, "certificate-😀");
        assert!(!verified.incomplete);
    }

    #[test]
    fn lists_keys_without_decrypting_them_and_warns_about_unknown_bags() {
        let key = SafeBag {
            bag: Bag::ShroudedKey(EncryptedPrivateKeyInfo {
                algorithm: AlgorithmIdentifier::with_null(
                    ObjectIdentifier::new(oid::OID_PBES2).unwrap(),
                ),
                encrypted_data: vec![1, 2, 3],
            }),
            attributes: vec![friendly_name("private"), local_key_id(&[1])],
        };
        let secret = SafeBag {
            bag: Bag::Secret {
                oid: ObjectIdentifier::new(oid::OID_PKCS12_SECRET_BAG).unwrap(),
                value: der::octet_string(&[1, 2, 3]),
            },
            attributes: vec![friendly_name("secret")],
        };
        let unknown = SafeBag {
            bag: Bag::Other {
                oid: ObjectIdentifier::new(&[1, 2, 3, 4]).unwrap(),
                value: der::null(),
            },
            attributes: vec![friendly_name("other")],
        };
        let plaintext_key = SafeBag {
            bag: Bag::Other {
                oid: ObjectIdentifier::new(oid::OID_PKCS12_KEY_BAG).unwrap(),
                value: der::octet_string(&[1, 2, 3]),
            },
            attributes: vec![friendly_name("plaintext")],
        };
        let data = synthetic(vec![key, secret, unknown, plaintext_key]);
        let verified = parse(&data).unwrap().verify("changeit").unwrap();
        assert_eq!(
            verified.entries,
            vec![
                KeystoreEntry {
                    alias: "private".into(),
                    kind: "Private key",
                    certificate: None,
                    certificates: vec![],
                    chain_warning: None,
                    document: None,
                },
                KeystoreEntry {
                    alias: "secret".into(),
                    kind: "Secret key",
                    certificate: None,
                    certificates: vec![],
                    chain_warning: None,
                    document: None,
                },
            ]
        );
        assert!(verified.incomplete);
    }

    #[test]
    fn summarizes_the_certificate_sharing_a_private_key_id() {
        let key = |alias, id: &[u8]| SafeBag {
            bag: Bag::ShroudedKey(EncryptedPrivateKeyInfo {
                algorithm: AlgorithmIdentifier::with_null(
                    ObjectIdentifier::new(oid::OID_PBES2).unwrap(),
                ),
                encrypted_data: vec![1, 2, 3],
            }),
            attributes: vec![friendly_name(alias), local_key_id(id)],
        };
        let certificate = SafeBag {
            bag: Bag::Cert(Certificate::parse(fixture_certificate_der()).unwrap()),
            attributes: vec![friendly_name("matched"), local_key_id(&[2])],
        };
        let data = synthetic(vec![
            key("matched", &[2]),
            key("unmatched", &[3]),
            certificate,
        ]);
        let verified = parse(&data).unwrap().verify("changeit").unwrap();
        assert_eq!(verified.entries[0].alias, "matched");
        assert_eq!(verified.entries[0].certificate, Some(fixture_summary()));
        assert_eq!(verified.entries[1].alias, "unmatched");
        assert_eq!(verified.entries[1].certificate, None);
        assert!(!verified.incomplete);
    }

    #[test]
    fn malformed_bag_does_not_hide_later_entries_in_a_verified_store() {
        let secret = |alias| SafeBag {
            bag: Bag::Secret {
                oid: ObjectIdentifier::new(oid::OID_PKCS12_SECRET_BAG).unwrap(),
                value: der::octet_string(&[1]),
            },
            attributes: vec![friendly_name(alias)],
        };
        let malformed = SafeBag {
            bag: Bag::Other {
                oid: ObjectIdentifier::new(oid::OID_PKCS12_CERT_BAG).unwrap(),
                value: der::null(),
            },
            attributes: vec![],
        };
        let data = synthetic(vec![secret("first"), malformed, secret("last")]);
        let verified = parse(&data).unwrap().verify("changeit").unwrap();
        assert_eq!(verified.entries.len(), 2);
        assert_eq!(verified.entries[0].alias, "first");
        assert_eq!(verified.entries[1].alias, "last");
        assert!(verified.incomplete);
    }

    #[test]
    fn rejects_missing_or_failed_mac() {
        let mut pfx = Pfx::parse(MODERN).unwrap();
        pfx.mac = None;
        assert!(parse(&pfx.encode()).is_err());
        let mut pfx = Pfx::parse(MODERN).unwrap();
        pfx.mac.as_mut().unwrap().digest[0] ^= 1;
        assert!(matches!(
            parse(&pfx.encode()).unwrap().verify("changeit"),
            Err(VerifyError::Password)
        ));
    }

    #[test]
    fn rejects_excessive_mac_work_before_prompting() {
        let mut pfx = Pfx::parse(MODERN).unwrap();
        pfx.mac.as_mut().unwrap().iterations = MAX_ITERATIONS + 1;
        assert!(parse(&pfx.encode()).is_err());
    }

    #[test]
    fn opens_empty_password_stores_without_a_prompt() {
        for password in [b"".as_slice(), b"\0".as_slice()] {
            let data = Pfx::build(vec![], password, 100, &mut TestRng(0))
                .unwrap()
                .encode();
            let verified = parse(&data).unwrap().verify("").unwrap();
            assert!(verified.entries.is_empty());
            assert!(!verified.incomplete);
        }
    }

    #[test]
    fn opens_java_empty_and_nul_password_stores_with_an_empty_password() {
        // Java's empty-password store only opens through the NUL fallback.
        assert!(parse(EMPTY_PASSWORD).unwrap().0.verify_mac(b"").is_err());
        for data in [EMPTY_PASSWORD, NUL_PASSWORD] {
            let store = parse(data).unwrap();
            assert!(matches!(
                store.verify("changeit"),
                Err(VerifyError::Password)
            ));
            let verified = store.verify("").unwrap();
            assert_eq!(
                verified.entries,
                vec![KeystoreEntry {
                    alias: "root-cert".into(),
                    kind: "Trusted certificate",
                    certificate: Some(fixture_summary()),
                    certificates: vec![fixture_certificate_der().to_vec()],
                    chain_warning: None,
                    document: None,
                }]
            );
            assert!(!verified.incomplete);
        }
    }
    fn raw_certificate(der: &[u8], attributes: Vec<crown::x509::attribute::Attribute>) -> SafeBag {
        SafeBag {
            bag: Bag::Other {
                oid: ObjectIdentifier::new(oid::OID_PKCS12_CERT_BAG).unwrap(),
                value: der::sequence(
                    &[
                        der::oid(&ObjectIdentifier::new(oid::OID_X509_CERTIFICATE).unwrap()),
                        der::explicit(0, &der::octet_string(der)),
                    ]
                    .concat(),
                ),
            },
            attributes,
        }
    }

    #[test]
    fn retains_exact_certificates_and_builds_key_chains_from_unnamed_ca_bags() {
        use crate::test_support::metadata_certificate;
        let leaf = metadata_certificate("leaf", "intermediate", &[0, 0, 1], &[]);
        let intermediate = metadata_certificate("intermediate", "root", &[2], &[]);
        let root = metadata_certificate("root", "root", &[3], &[]);
        let unrelated = metadata_certificate("other", "other", &[4], &[]);
        let key = SafeBag {
            bag: Bag::ShroudedKey(EncryptedPrivateKeyInfo {
                algorithm: AlgorithmIdentifier::with_null(
                    ObjectIdentifier::new(oid::OID_PBES2).unwrap(),
                ),
                encrypted_data: vec![1, 2, 3],
            }),
            attributes: vec![friendly_name("key"), local_key_id(&[1])],
        };
        let data = synthetic(vec![
            key,
            raw_certificate(&root, vec![]),
            raw_certificate(&unrelated, vec![]),
            raw_certificate(&leaf, vec![local_key_id(&[1])]),
            raw_certificate(&intermediate, vec![]),
            raw_certificate(&root, vec![]),
        ]);
        let verified = parse(&data).unwrap().verify("changeit").unwrap();
        assert!(!verified.incomplete);
        // Chain members are not listed again, but an unrelated certificate is.
        assert_eq!(verified.entries.len(), 2);
        assert_eq!(verified.entries[0].certificates, [leaf, intermediate, root]);
        assert_eq!(verified.entries[0].chain_warning, None);
        assert_eq!(verified.entries[1].alias, "other");
        assert_eq!(verified.entries[1].kind, certificate_file::KIND);
        assert_eq!(verified.entries[1].certificates, [unrelated]);
    }

    #[test]
    fn names_unnamed_keys_and_lists_plain_certificates_like_openssl_writes_them() {
        use crate::test_support::metadata_certificate;
        let leaf = metadata_certificate("leaf", "ca", &[1], &[]);
        let ca = metadata_certificate("ca", "ca", &[2], &[]);
        let loose = metadata_certificate("loose", "loose", &[3], &[]);
        let key = |id: &[u8]| SafeBag {
            bag: Bag::ShroudedKey(EncryptedPrivateKeyInfo {
                algorithm: AlgorithmIdentifier::with_null(
                    ObjectIdentifier::new(oid::OID_PBES2).unwrap(),
                ),
                encrypted_data: vec![1, 2, 3],
            }),
            attributes: vec![local_key_id(id)],
        };
        let data = synthetic(vec![
            key(&[1]),
            key(&[9]),
            raw_certificate(&leaf, vec![local_key_id(&[1])]),
            raw_certificate(&ca, vec![]),
            raw_certificate(&loose, vec![friendly_name("named")]),
            raw_certificate(b"unreadable", vec![]),
        ]);
        let verified = parse(&data).unwrap().verify("changeit").unwrap();
        assert!(!verified.incomplete);
        let listed: Vec<_> = verified
            .entries
            .iter()
            .map(|entry| (entry.alias.as_str(), entry.kind, entry.certificates.len()))
            .collect();
        assert_eq!(
            listed,
            [
                ("Certificate 1", certificate_file::KIND, 1),
                ("Private key 1", "Private key", 0),
                ("leaf", "Private key", 2),
                ("named", certificate_file::KIND, 1),
            ]
        );
    }

    #[test]
    fn malformed_and_negative_serial_certificates_remain_inspectable() {
        use crate::test_support::metadata_certificate;
        use crown::x509::attribute::Attribute;
        let negative = metadata_certificate("negative", "negative", &[0xff], &[]);
        let trusted = |name| {
            vec![
                friendly_name(name),
                Attribute::new(
                    ObjectIdentifier::new(TRUSTED_KEY_USAGE).unwrap(),
                    vec![der::oid(
                        &ObjectIdentifier::new(&[2, 5, 29, 37, 0]).unwrap(),
                    )],
                ),
            ]
        };
        let data = synthetic(vec![
            raw_certificate(b"unreadable", trusted("malformed")),
            raw_certificate(&negative, trusted("negative")),
        ]);
        let verified = parse(&data).unwrap().verify("changeit").unwrap();
        assert!(!verified.incomplete);
        assert_eq!(verified.entries.len(), 2);
        assert_eq!(verified.entries[0].certificates, [b"unreadable".to_vec()]);
        assert!(verified.entries[0].certificate.is_none());
        assert_eq!(verified.entries[1].certificates, [negative]);
        assert_eq!(
            certificate::details::Details::parse(&verified.entries[1].certificates[0])
                .unwrap()
                .serial_decimal,
            "-1"
        );
    }
}
