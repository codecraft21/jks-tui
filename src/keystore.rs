use std::{collections::BTreeMap, io};

use jks::{
    KeyStoreError,
    common::{MAGIC, PRIVATE_KEY_TAG, TRUSTED_CERT_TAG, VERSION_01, VERSION_02, WHITENER_MESSAGE},
    decoder::Decoder,
};

#[derive(Debug, PartialEq, Eq)]
pub struct KeystoreEntry {
    pub alias: String,
    pub kind: &'static str,
}

pub fn load_entries(data: &[u8], password: &str) -> jks::Result<Vec<KeystoreEntry>> {
    let body_len = data.len().checked_sub(20).ok_or_else(truncated)?;
    let (body, mut digest) = data.split_at(body_len);
    let mut reader = Reader { remaining: body };
    if reader.u32()? != MAGIC {
        return Err(KeyStoreError::InvalidMagic);
    }
    let version = reader.u32()?;
    if !matches!(version, VERSION_01 | VERSION_02) {
        return Err(KeyStoreError::UnknownVersion(version));
    }

    // Even the smallest v1 entry needs a tag, alias length, timestamp and
    // certificate length. Never reserve memory from an untrusted count.
    let count = reader.count(18)?;
    let mut entries = BTreeMap::new();
    for _ in 0..count {
        let tag = reader.u32()?;
        let alias = reader.string()?;
        reader.take(8)?; // Creation timestamp; listing does not need it.
        let kind = match tag {
            PRIVATE_KEY_TAG => {
                reader.payload()?; // Encrypted key bytes remain opaque.
                let cert_count = reader.count(if version == VERSION_01 { 4 } else { 6 })?;
                for _ in 0..cert_count {
                    reader.certificate(version)?;
                }
                "Private key"
            }
            TRUSTED_CERT_TAG => {
                reader.certificate(version)?;
                "Trusted certificate"
            }
            _ => return Err(KeyStoreError::UnknownEntryTag(tag)),
        };
        entries.insert(alias, kind);
    }
    if !reader.remaining.is_empty() {
        return Err(KeyStoreError::Other("trailing data after keystore".into()));
    }

    // Use only the crate's fixed-size digest verifier, not its allocating
    // entry decoder. Java hashes password UTF-16 code units in big-endian order.
    let mut verifier = Decoder::new(&mut digest);
    for unit in password.encode_utf16() {
        let mut bytes = unit.to_be_bytes();
        verifier.update_digest(&bytes);
        jks::zeroing(&mut bytes);
    }
    verifier.update_digest(WHITENER_MESSAGE);
    verifier.update_digest(body);
    verifier.verify_digest()?;

    Ok(entries
        .into_iter()
        .map(|(alias, kind)| KeystoreEntry { alias, kind })
        .collect())
}

fn truncated() -> KeyStoreError {
    io::Error::new(io::ErrorKind::UnexpectedEof, "truncated JKS data").into()
}

struct Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> jks::Result<&'a [u8]> {
        if len > self.remaining.len() {
            return Err(truncated());
        }
        let (bytes, remaining) = self.remaining.split_at(len);
        self.remaining = remaining;
        Ok(bytes)
    }

    fn u32(&mut self) -> jks::Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn count(&mut self, minimum_size: usize) -> jks::Result<u32> {
        let count = self.u32()?;
        if u64::from(count) > (self.remaining.len() / minimum_size) as u64 {
            return Err(truncated());
        }
        Ok(count)
    }

    fn payload(&mut self) -> jks::Result<()> {
        let len = self.u32()? as usize;
        self.take(len)?;
        Ok(())
    }

    fn certificate(&mut self, version: u32) -> jks::Result<()> {
        if version == VERSION_02 {
            self.string()?;
        }
        self.payload()
    }

    fn string(&mut self) -> jks::Result<String> {
        let len = u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as usize;
        let mut bytes = self.take(len)?;
        // Java's DataInput.readUTF encodes UTF-16 units: NUL uses C0 80 and
        // supplementary characters use two three-byte surrogate sequences.
        let invalid = || KeyStoreError::Other("invalid modified UTF-8 in JKS string".into());
        let mut units = Vec::new();
        while let Some((&first, rest)) = bytes.split_first() {
            bytes = rest;
            let unit = match first {
                0x00..=0x7f => u16::from(first),
                0xc0..=0xef => {
                    let continuations = if first < 0xe0 { 1 } else { 2 };
                    if bytes.len() < continuations {
                        return Err(invalid());
                    }
                    let mut unit = u16::from(first & (0x7f >> (continuations + 1)));
                    for &byte in &bytes[..continuations] {
                        if byte & 0xc0 != 0x80 {
                            return Err(invalid());
                        }
                        unit = (unit << 6) | u16::from(byte & 0x3f);
                    }
                    bytes = &bytes[continuations..];
                    unit
                }
                _ => return Err(invalid()),
            };
            units.push(unit);
        }
        String::from_utf16(&units).map_err(|_| invalid())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{
        KEYTOOL_JKS, UNICODE_ALIAS_JKS, UNICODE_PASSWORD_JKS, empty_keystore, mixed_keystore,
    };
    use jks::{KeyStore, KeyStoreOptions};

    #[test]
    fn verifies_java_passwords_with_accented_and_supplementary_characters() {
        assert_eq!(
            load_entries(UNICODE_PASSWORD_JKS, "pässwörd-😀").unwrap(),
            load_entries(KEYTOOL_JKS, "changeit").unwrap()
        );
        for password in ["", "pässwörd", "pässwörd-😁"] {
            assert!(matches!(
                load_entries(UNICODE_PASSWORD_JKS, password),
                Err(KeyStoreError::InvalidDigest)
            ));
        }
    }

    #[test]
    fn reads_java_aliases_with_supplementary_characters() {
        assert_eq!(
            load_entries(UNICODE_ALIAS_JKS, "changeit").unwrap(),
            [KeystoreEntry {
                alias: "certificate-😀".into(),
                kind: "Trusted certificate",
            }]
        );
    }

    #[test]
    fn rejects_every_truncated_prefix_before_requesting_a_password() {
        let mixed = mixed_keystore();
        for data in [KEYTOOL_JKS, UNICODE_ALIAS_JKS, mixed.as_slice()] {
            for end in 0..data.len() {
                let error = load_entries(&data[..end], "").unwrap_err();
                assert!(!matches!(error, KeyStoreError::InvalidDigest));
            }
        }
    }

    #[test]
    fn rejects_unbounded_lengths_and_counts_without_allocating_payloads() {
        let mut data = mixed_keystore();
        // Locate the serialized fields in a valid store, then overwrite each
        // length/count with its maximum value. Include the original crashing
        // private-key chain count and lengths in trusted and chain certificates.
        let body_len = data.len() - 20;
        let mut reader = Reader {
            remaining: &data[..body_len],
        };
        reader.take(8).unwrap();
        let mut u32_offsets = vec![8]; // Entry count.
        let mut u16_offsets = Vec::new();
        let count = reader.u32().unwrap();
        for _ in 0..count {
            let tag = reader.u32().unwrap();
            u16_offsets.push(body_len - reader.remaining.len());
            reader.string().unwrap();
            reader.take(8).unwrap();
            let cert_count = if tag == PRIVATE_KEY_TAG {
                u32_offsets.push(body_len - reader.remaining.len());
                reader.payload().unwrap();
                u32_offsets.push(body_len - reader.remaining.len());
                reader.u32().unwrap()
            } else {
                1
            };
            for _ in 0..cert_count {
                u16_offsets.push(body_len - reader.remaining.len());
                reader.string().unwrap();
                u32_offsets.push(body_len - reader.remaining.len());
                reader.payload().unwrap();
            }
        }
        for (offset, replacement) in u32_offsets
            .into_iter()
            .map(|offset| (offset, u32::MAX.to_be_bytes().to_vec()))
            .chain(
                u16_offsets
                    .into_iter()
                    .map(|offset| (offset, u16::MAX.to_be_bytes().to_vec())),
            )
        {
            let original = data[offset..offset + replacement.len()].to_vec();
            data[offset..offset + replacement.len()].copy_from_slice(&replacement);
            for password in ["", "changeit"] {
                let error = load_entries(&data, password).unwrap_err();
                assert!(!matches!(error, KeyStoreError::InvalidDigest));
            }
            data[offset..offset + original.len()].copy_from_slice(&original);
        }
    }

    #[test]
    fn decodes_modified_utf8_and_rejects_malformed_strings() {
        let mut reader = Reader {
            remaining: b"\x00\x0ea\xc0\x80\xc3\xa9\xe4\xb8\xad\xed\xa0\xbd\xed\xb8\x80",
        };
        assert_eq!(reader.string().unwrap(), "a\0é中😀");
        assert!(reader.remaining.is_empty());
        for bytes in [
            &b"\x00\x01\x80"[..],             // Unexpected continuation.
            &b"\x00\x01\xc0"[..],             // Missing continuation.
            &b"\x00\x02\xc0A"[..],            // Invalid continuation.
            &b"\x00\x02\xe0\x80"[..],         // Truncated three-byte sequence.
            &b"\x00\x03\xed\xa0\xbd"[..],     // Unpaired surrogate.
            &b"\x00\x04\xf0\x9f\x98\x80"[..], // Standard UTF-8 is not modified UTF-8.
        ] {
            assert!(Reader { remaining: bytes }.string().is_err());
        }
    }

    #[test]
    fn supports_v1_entries_without_certificate_type_fields() {
        let mut data = Vec::new();
        let mut encoder = jks::encoder::Encoder::new(&mut data);
        encoder.update_digest(WHITENER_MESSAGE); // Empty test password.
        encoder.write_u32(MAGIC).unwrap();
        encoder.write_u32(VERSION_01).unwrap();
        encoder.write_u32(2).unwrap();
        for (tag, alias) in [(PRIVATE_KEY_TAG, "key"), (TRUSTED_CERT_TAG, "cert")] {
            encoder.write_u32(tag).unwrap();
            encoder.write_string(alias).unwrap();
            encoder.write_u64(0).unwrap();
            if tag == PRIVATE_KEY_TAG {
                encoder.write_u32(0).unwrap(); // No actual key material.
                encoder.write_u32(1).unwrap(); // One certificate in the chain.
            }
            encoder.write_u32(1).unwrap();
            encoder.write_bytes(&[0]).unwrap(); // Opaque synthetic certificate.
        }
        encoder.write_digest().unwrap();
        assert_eq!(
            load_entries(&data, "").unwrap(),
            [
                KeystoreEntry {
                    alias: "cert".into(),
                    kind: "Trusted certificate"
                },
                KeystoreEntry {
                    alias: "key".into(),
                    kind: "Private key"
                },
            ]
        );
    }

    #[test]
    fn reads_a_java_generated_keystore() {
        assert_eq!(
            load_entries(KEYTOOL_JKS, "changeit").unwrap(),
            [KeystoreEntry {
                alias: "root-cert".into(),
                kind: "Trusted certificate",
            }]
        );
    }

    #[test]
    fn lists_both_entry_types_in_alias_order_without_the_key_password() {
        assert_eq!(
            load_entries(&mixed_keystore(), "changeit").unwrap(),
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
            let error = load_entries(data, "changeit").unwrap_err();
            assert!(!matches!(error, KeyStoreError::InvalidDigest));
        }
    }

    #[test]
    fn rejects_wrong_password_and_corrupt_digest_without_returning_entries() {
        assert!(matches!(
            load_entries(KEYTOOL_JKS, "wrong-password"),
            Err(KeyStoreError::InvalidDigest)
        ));
        let mut data = KEYTOOL_JKS.to_vec();
        *data.last_mut().unwrap() ^= 1;
        assert!(matches!(
            load_entries(&data, "changeit"),
            Err(KeyStoreError::InvalidDigest)
        ));
    }

    #[test]
    fn rejects_unsupported_versions_even_without_entries() {
        let mut data = empty_keystore();
        data[4..8].copy_from_slice(&3_u32.to_be_bytes());
        assert!(matches!(
            load_entries(&data, ""),
            Err(KeyStoreError::UnknownVersion(3))
        ));
    }

    #[test]
    fn rejects_trailing_data_before_requesting_a_password() {
        let mut data = KEYTOOL_JKS.to_vec();
        data.push(0);
        for password in ["", "changeit"] {
            let error = load_entries(&data, password).unwrap_err();
            assert!(error.to_string().contains("trailing data"));
        }
    }

    #[test]
    fn supports_empty_keystores() {
        assert!(load_entries(&empty_keystore(), "").unwrap().is_empty());
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
        let entries = load_entries(&data, "changeit").unwrap();
        assert_eq!(entries[0].alias, "MixedCase");
        assert_eq!(entries[0].kind, "Private key");
    }
}
