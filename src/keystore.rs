use std::io::Cursor;

use jks::{
    KeyStore, KeyStoreError, KeyStoreOptions,
    common::{MAGIC, VERSION_01, VERSION_02},
    decoder::Decoder,
};

#[derive(Debug, PartialEq, Eq)]
pub struct KeystoreEntry {
    pub alias: String,
    pub kind: &'static str,
}

pub fn load_entries(data: &[u8], password: &[u8]) -> jks::Result<Vec<KeystoreEntry>> {
    let mut reader = Cursor::new(data);
    let mut decoder = Decoder::new(&mut reader);
    if decoder.read_u32()? != MAGIC {
        return Err(KeyStoreError::InvalidMagic);
    }
    // The crate only checks the version while reading certificates, so check it
    // here as well to reject unsupported versions of empty keystores.
    let version = decoder.read_u32()?;
    if !matches!(version, VERSION_01 | VERSION_02) {
        return Err(KeyStoreError::UnknownVersion(version));
    }

    reader.set_position(0);
    let mut keystore = KeyStore::with_options(KeyStoreOptions {
        ordered_aliases: true,
        case_exact_aliases: true,
        ..Default::default()
    });
    let result = keystore.load(&mut reader, password);
    // A digest mismatch means the structure was parsed, but the password or
    // integrity is wrong. Never expose the crate's partially loaded entries.
    if (result.is_ok() || matches!(result, Err(KeyStoreError::InvalidDigest)))
        && reader.position() != data.len() as u64
    {
        return Err(KeyStoreError::Other("trailing data after keystore".into()));
    }
    result?;

    Ok(keystore
        .aliases()
        .into_iter()
        .map(|alias| {
            let kind = if keystore.is_private_key_entry(&alias) {
                "Private key"
            } else {
                "Trusted certificate"
            };
            KeystoreEntry { alias, kind }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{KEYTOOL_JKS, empty_keystore, mixed_keystore};

    #[test]
    fn reads_a_java_generated_keystore() {
        assert_eq!(
            load_entries(KEYTOOL_JKS, b"changeit").unwrap(),
            [KeystoreEntry {
                alias: "root-cert".into(),
                kind: "Trusted certificate",
            }]
        );
    }

    #[test]
    fn lists_both_entry_types_in_alias_order_without_the_key_password() {
        assert_eq!(
            load_entries(&mixed_keystore(), b"changeit").unwrap(),
            [
                KeystoreEntry {
                    alias: "root-cert".into(),
                    kind: "Trusted certificate",
                },
                KeystoreEntry {
                    alias: "server-key".into(),
                    kind: "Private key",
                },
            ]
        );
    }

    #[test]
    fn rejects_non_jks_and_truncated_files() {
        for data in [
            &b"not a keystore"[..],
            &b"\x30\x82PKCS12"[..],
            &KEYTOOL_JKS[..0],
            &KEYTOOL_JKS[..4],
            &KEYTOOL_JKS[..12],
            &KEYTOOL_JKS[..KEYTOOL_JKS.len() - 1],
        ] {
            let error = load_entries(data, b"changeit").unwrap_err();
            assert!(!matches!(error, KeyStoreError::InvalidDigest));
        }
    }

    #[test]
    fn rejects_wrong_password_and_corrupt_digest_without_returning_entries() {
        assert!(matches!(
            load_entries(KEYTOOL_JKS, b"wrong-password"),
            Err(KeyStoreError::InvalidDigest)
        ));
        let mut data = KEYTOOL_JKS.to_vec();
        *data.last_mut().unwrap() ^= 1;
        assert!(matches!(
            load_entries(&data, b"changeit"),
            Err(KeyStoreError::InvalidDigest)
        ));
    }

    #[test]
    fn rejects_unsupported_versions_even_without_entries() {
        let mut data = empty_keystore();
        data[4..8].copy_from_slice(&3_u32.to_be_bytes());
        assert!(matches!(
            load_entries(&data, b""),
            Err(KeyStoreError::UnknownVersion(3))
        ));
    }

    #[test]
    fn rejects_trailing_data_before_requesting_a_password() {
        let mut data = KEYTOOL_JKS.to_vec();
        data.push(0);
        for password in [&b""[..], &b"changeit"[..]] {
            let error = load_entries(&data, password).unwrap_err();
            assert!(error.to_string().contains("trailing data"));
        }
    }

    #[test]
    fn supports_empty_keystores() {
        assert!(load_entries(&empty_keystore(), b"").unwrap().is_empty());
    }

    #[test]
    fn preserves_alias_case_when_identifying_entry_types() {
        let mut keystore = KeyStore::with_options(KeyStoreOptions {
            case_exact_aliases: true,
            ..Default::default()
        });
        keystore
            .load(mixed_keystore().as_slice(), b"changeit")
            .unwrap();
        let entry = keystore
            .get_private_key_entry("server-key", b"keypass")
            .unwrap();
        keystore.delete_entry("server-key");
        keystore
            .set_private_key_entry("MixedCase", entry, b"keypass")
            .unwrap();
        let mut data = Vec::new();
        keystore.store(&mut data, b"changeit").unwrap();
        let entries = load_entries(&data, b"changeit").unwrap();
        assert_eq!(entries[0].alias, "MixedCase");
        assert_eq!(entries[0].kind, "Private key");
    }
}
