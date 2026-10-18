use crown::{
    asn1::{der::Reader, oid},
    error::CryptoError,
    pkcs7::ContentInfo,
    pkcs12::{Bag, Pfx, SafeBag},
    x509::{
        algorithm::AlgorithmIdentifier,
        pbe::{LegacyPbe, Pbes2},
    },
};
use zeroize::Zeroizing;

use crate::keystore::KeystoreEntry;

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

        let mut keys = Vec::new();
        for bag in &bags {
            if matches!(bag.bag, Bag::ShroudedKey(_)) {
                if let Some(alias) = bag.friendly_name() {
                    keys.push(alias);
                } else {
                    incomplete = true;
                }
            }
        }
        let mut entries: Vec<KeystoreEntry> = keys
            .into_iter()
            .map(|alias| KeystoreEntry {
                alias,
                kind: "Private key",
            })
            .collect();
        for bag in &bags {
            match &bag.bag {
                Bag::Secret { .. } => {
                    if let Some(alias) = bag.friendly_name() {
                        entries.push(KeystoreEntry {
                            alias,
                            kind: "Secret key",
                        });
                    } else {
                        incomplete = true;
                    }
                }
                Bag::Cert(_) => {
                    // Java identifies trusted entries with its trustedKeyUsage attribute.
                    if !bag
                        .attributes
                        .iter()
                        .any(|attr| attr.oid.matches(TRUSTED_KEY_USAGE))
                    {
                        continue;
                    }
                    if let Some(alias) = bag.friendly_name() {
                        if !entries
                            .iter()
                            .any(|entry| entry.alias.eq_ignore_ascii_case(&alias))
                        {
                            entries.push(KeystoreEntry {
                                alias,
                                kind: "Trusted certificate",
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

fn parse_metadata_bag(raw: &[u8]) -> Result<Option<SafeBag>, CryptoError> {
    let mut reader = Reader::new(raw);
    let mut bag = reader.read_sequence()?;
    let id = bag.read_oid()?;
    // Crown parses plaintext keyBag contents; Java PKCS12 uses shrouded key bags.
    if id.matches(oid::OID_PKCS12_KEY_BAG) || id.matches(oid::OID_PKCS12_SAFE_CONTENTS_BAG) {
        return Ok(None);
    }
    let mut reader = Reader::new(raw);
    let bag = SafeBag::parse(&mut reader)?;
    reader.expect_end()?;
    Ok(Some(bag))
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
    use crown::{
        asn1::{der, oid::ObjectIdentifier},
        pkcs12::SafeBag,
        rng::Rng,
        x509::{
            algorithm::AlgorithmIdentifier,
            attribute::{friendly_name, local_key_id},
            keys::EncryptedPrivateKeyInfo,
        },
    };

    const MODERN: &[u8] = include_bytes!("../tests/fixtures/trusted-cert.p12");
    const LEGACY: &[u8] = include_bytes!("../tests/fixtures/trusted-cert-legacy.p12");
    const UNICODE_ALIAS: &[u8] = include_bytes!("../tests/fixtures/unicode-alias.p12");

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
                    kind: "Trusted certificate"
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
                    kind: "Private key"
                },
                KeystoreEntry {
                    alias: "secret".into(),
                    kind: "Secret key"
                },
            ]
        );
        assert!(verified.incomplete);
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
}
