use std::io;

use jks::{
    KeyStoreError,
    common::{MAGIC, PRIVATE_KEY_TAG, TRUSTED_CERT_TAG, VERSION_01, VERSION_02, WHITENER_MESSAGE},
    decoder::Decoder,
};
use zeroize::Zeroize;

#[derive(Debug, PartialEq, Eq)]
pub struct KeystoreEntry {
    pub alias: String,
    pub kind: &'static str,
}

/// A structurally valid keystore whose integrity digest has not been checked.
/// Parse once, then call `verify` for each password attempt. Entries are only
/// reachable through a successful `verify`.
pub struct Keystore {
    data: Vec<u8>,
    body_len: usize,
    entries: Vec<KeystoreEntry>,
}

const DIGEST_LEN: usize = 20;
/// The only certificate type standard Java providers can load from a JKS file.
const CERTIFICATE_TYPE: &str = "X.509";

pub fn parse(mut data: Vec<u8>) -> jks::Result<Keystore> {
    // Check the magic first so short or empty non-JKS files are reported as
    // such rather than as truncated keystores.
    if data.get(..4) != Some(&MAGIC.to_be_bytes()[..]) {
        return Err(KeyStoreError::InvalidMagic);
    }
    let mut reader = Reader {
        remaining: &data[4..],
    };
    let version = reader.u32()?;
    if !matches!(version, VERSION_01 | VERSION_02) {
        return Err(KeyStoreError::UnknownVersion(version));
    }

    // Even the smallest v1 entry needs a tag, alias length, timestamp and
    // certificate length. Never reserve memory from an untrusted count.
    let count = reader.count(18)?;
    let mut entries = Vec::new();
    for _ in 0..count {
        let tag = reader.u32()?;
        let alias = reader.string()?;
        reader.take(8)?; // Creation timestamp; listing does not need it.
        let kind = match tag {
            PRIVATE_KEY_TAG => {
                // Encrypted key bytes remain opaque. Like Java, accept any
                // length (even empty) and a key entry without a chain.
                reader.payload()?;
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
        entries.push(KeystoreEntry { alias, kind });
    }
    let body_len = data.len() - reader.remaining.len();
    reader.take(DIGEST_LEN)?;
    // Like Java's JavaKeyStore, ignore anything after the digest, and do not
    // keep it in memory while waiting for a password.
    data.truncate(body_len + DIGEST_LEN);
    data.shrink_to_fit();

    // Keep duplicate aliases visible instead of letting one entry hide another.
    entries.sort_by(|a, b| a.alias.cmp(&b.alias));
    Ok(Keystore {
        data,
        body_len,
        entries,
    })
}

impl Keystore {
    /// Returns the entries if the password matches the integrity digest, or
    /// the keystore back for another attempt if it does not.
    pub fn verify(self, password: &str) -> Result<Vec<KeystoreEntry>, Self> {
        let (body, mut digest) = self.data.split_at(self.body_len);
        // Use only the crate's fixed-size digest verifier, not its allocating
        // entry decoder. `parse` guarantees exactly DIGEST_LEN digest bytes, so
        // the only possible failure is a mismatch.
        let mut verifier = Decoder::new(&mut digest);
        hash_password(password, |bytes| verifier.update_digest(bytes));
        verifier.update_digest(body);
        match verifier.verify_digest() {
            Ok(()) => Ok(self.entries),
            Err(_) => Err(self),
        }
    }
}

/// Feeds the digest prefix Java uses: the password's UTF-16 code units in
/// big-endian order, then the whitener.
fn hash_password(password: &str, mut update: impl FnMut(&[u8])) {
    for unit in password.encode_utf16() {
        let mut bytes = unit.to_be_bytes();
        update(&bytes);
        bytes.zeroize();
    }
    update(WHITENER_MESSAGE);
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

    fn payload(&mut self) -> jks::Result<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    fn certificate(&mut self, version: u32) -> jks::Result<()> {
        // Java resolves the type with CertificateFactory (case-insensitively),
        // and standard providers only support X.509. Version 1 implies X.509.
        if version == VERSION_02 && !self.string()?.eq_ignore_ascii_case(CERTIFICATE_TYPE) {
            return Err(KeyStoreError::Other(
                "unsupported certificate type in JKS data".into(),
            ));
        }
        // Java fails to load a keystore whose certificate encoding is empty.
        if self.payload()?.is_empty() {
            return Err(KeyStoreError::Other("empty certificate in JKS data".into()));
        }
        Ok(())
    }

    fn string(&mut self) -> jks::Result<String> {
        let len = u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as usize;
        let mut bytes = self.take(len)?;
        // Java's DataInput.readUTF encodes UTF-16 units: NUL uses C0 80 and
        // supplementary characters use two three-byte surrogate sequences.
        let invalid = || KeyStoreError::Other("invalid modified UTF-8 in JKS string".into());
        let mut units = Vec::with_capacity(bytes.len());
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
        // Java strings may hold unpaired surrogates. Show each as a \uXXXX
        // escape so aliases that differ only in them stay distinguishable.
        Ok(char::decode_utf16(units)
            .map(|unit| match unit {
                Ok(ch) => ch.to_string(),
                Err(error) => format!("\\u{:04X}", error.unpaired_surrogate()),
            })
            .collect())
    }
}

#[cfg(test)]
pub fn load_entries(data: &[u8], password: &str) -> jks::Result<Vec<KeystoreEntry>> {
    parse(data.to_vec())?
        .verify(password)
        .map_err(|_| KeyStoreError::InvalidDigest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{
        KEYTOOL_JKS, UNICODE_ALIAS_JKS, UNICODE_PASSWORD_JKS, empty_keystore, mixed_keystore,
    };
    use jks::{KeyStore, KeyStoreOptions, encoder::Encoder};

    /// Writes a keystore field by field, recording where each length or count
    /// lives so tests can corrupt them without re-implementing the parser.
    #[derive(Default)]
    struct Builder {
        body: Vec<u8>,
        u32_fields: Vec<usize>,
        u16_fields: Vec<usize>,
    }

    impl Builder {
        fn new(version: u32, count: u32) -> Self {
            let mut builder = Self::default();
            builder.u32(MAGIC);
            builder.u32(version);
            builder.u32_field(count);
            builder
        }

        fn u32(&mut self, value: u32) {
            self.body.extend_from_slice(&value.to_be_bytes());
        }

        fn u32_field(&mut self, value: u32) {
            self.u32_fields.push(self.body.len());
            self.u32(value);
        }

        fn raw_string(&mut self, bytes: &[u8]) {
            self.u16_fields.push(self.body.len());
            self.body
                .extend_from_slice(&u16::try_from(bytes.len()).unwrap().to_be_bytes());
            self.body.extend_from_slice(bytes);
        }

        fn payload(&mut self, bytes: &[u8]) {
            self.u32_field(bytes.len().try_into().unwrap());
            self.body.extend_from_slice(bytes);
        }

        fn certificate(&mut self, version: u32) {
            if version == VERSION_02 {
                self.raw_string(CERTIFICATE_TYPE.as_bytes());
            }
            self.payload(b"opaque synthetic certificate");
        }

        /// Writes the tag, alias and creation timestamp every entry starts with.
        fn entry_header(&mut self, tag: u32, alias: &[u8]) {
            self.u32(tag);
            self.raw_string(alias);
            self.body.extend_from_slice(&0_u64.to_be_bytes());
        }

        fn entry(&mut self, tag: u32, alias: &[u8], version: u32, certificates: u32) {
            self.entry_header(tag, alias);
            if tag == PRIVATE_KEY_TAG {
                self.payload(b"synthetic test payload, not a private key");
                self.u32_field(certificates);
            }
            for _ in 0..certificates {
                self.certificate(version);
            }
        }

        fn finish(&self, password: &str) -> Vec<u8> {
            let mut data = Vec::new();
            let mut encoder = Encoder::new(&mut data);
            hash_password(password, |bytes| encoder.update_digest(bytes));
            encoder.write_bytes(&self.body).unwrap();
            encoder.write_digest().unwrap();
            data
        }
    }

    fn key(alias: &str) -> KeystoreEntry {
        KeystoreEntry {
            alias: alias.into(),
            kind: "Private key",
        }
    }

    fn cert(alias: &str) -> KeystoreEntry {
        KeystoreEntry {
            alias: alias.into(),
            kind: "Trusted certificate",
        }
    }

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
    fn a_parsed_keystore_can_be_verified_repeatedly() {
        let mut keystore = parse(KEYTOOL_JKS.to_vec()).unwrap();
        for _ in 0..2 {
            keystore = keystore.verify("wrong").err().unwrap();
        }
        assert_eq!(
            keystore.verify("changeit").ok().unwrap(),
            [cert("root-cert")]
        );
    }

    #[test]
    fn reads_java_aliases_with_supplementary_characters() {
        assert_eq!(
            load_entries(UNICODE_ALIAS_JKS, "changeit").unwrap(),
            [cert("certificate-😀")]
        );
    }

    #[test]
    fn lists_aliases_with_unpaired_surrogates_that_java_accepts() {
        let mut builder = Builder::new(VERSION_02, 2);
        builder.entry(TRUSTED_CERT_TAG, b"a\xed\xb0\x80", VERSION_02, 1);
        builder.entry(TRUSTED_CERT_TAG, b"a\xed\xa0\xbd", VERSION_02, 1);
        assert_eq!(
            load_entries(&builder.finish(""), "").unwrap(),
            [cert("a\\uD83D"), cert("a\\uDC00")]
        );
    }

    #[test]
    fn duplicate_aliases_do_not_hide_entries() {
        let mut builder = Builder::new(VERSION_02, 3);
        builder.entry(PRIVATE_KEY_TAG, b"a", VERSION_02, 1);
        builder.entry(TRUSTED_CERT_TAG, b"b", VERSION_02, 1);
        builder.entry(TRUSTED_CERT_TAG, b"a", VERSION_02, 1);
        assert_eq!(
            load_entries(&builder.finish(""), "").unwrap(),
            [key("a"), cert("a"), cert("b")]
        );
    }

    #[test]
    fn accepts_empty_key_material_like_java() {
        let mut data = Builder::new(VERSION_02, 1);
        data.entry_header(PRIVATE_KEY_TAG, b"key");
        data.payload(b"");
        data.u32_field(1);
        data.certificate(VERSION_02);
        assert_eq!(load_entries(&data.finish(""), "").unwrap(), [key("key")]);
    }

    #[test]
    fn rejects_certificates_java_cannot_load() {
        for (version, cert_type, encoding, message) in [
            (VERSION_01, None, &b""[..], "empty certificate"),
            (
                VERSION_02,
                Some(&b"x.509"[..]),
                &b""[..],
                "empty certificate",
            ),
            (
                VERSION_02,
                Some(&b"FOO"[..]),
                &b"cert"[..],
                "unsupported certificate type",
            ),
            (
                VERSION_02,
                Some(&b""[..]),
                &b"cert"[..],
                "unsupported certificate type",
            ),
            (
                VERSION_02,
                Some(&b"\xc0"[..]),
                &b"cert"[..],
                "invalid modified UTF-8",
            ),
        ] {
            let mut data = Builder::new(version, 1);
            data.entry_header(TRUSTED_CERT_TAG, b"cert");
            if let Some(cert_type) = cert_type {
                data.raw_string(cert_type);
            }
            data.payload(encoding);
            let error = parse(data.finish("")).err().unwrap();
            assert!(error.to_string().contains(message), "{error}");
        }
    }

    #[test]
    fn drops_trailing_data_from_memory() {
        let mut data = KEYTOOL_JKS.to_vec();
        data.resize(KEYTOOL_JKS.len() + 4096, 0);
        let keystore = parse(data).unwrap();
        assert_eq!(keystore.data, KEYTOOL_JKS);
        assert!(keystore.data.capacity() < KEYTOOL_JKS.len() + 4096);
    }

    #[test]
    fn lists_private_keys_without_a_certificate_chain() {
        let mut builder = Builder::new(VERSION_02, 1);
        builder.entry(PRIVATE_KEY_TAG, b"key", VERSION_02, 0);
        assert_eq!(load_entries(&builder.finish(""), "").unwrap(), [key("key")]);
    }

    #[test]
    fn rejects_every_truncated_prefix_before_requesting_a_password() {
        let mixed = mixed_keystore();
        for data in [KEYTOOL_JKS, UNICODE_ALIAS_JKS, mixed.as_slice()] {
            for end in 0..data.len() {
                assert!(parse(data[..end].to_vec()).is_err());
            }
        }
    }

    #[test]
    fn rejects_unbounded_lengths_and_counts_without_allocating_payloads() {
        let mut builder = Builder::new(VERSION_02, 2);
        builder.entry(PRIVATE_KEY_TAG, b"key", VERSION_02, 2);
        builder.entry(TRUSTED_CERT_TAG, b"cert", VERSION_02, 1);
        let mut data = builder.finish("changeit");
        assert_eq!(load_entries(&data, "changeit").unwrap().len(), 2);
        // Every length and count in both entry types, including the original
        // crashing private-key chain count, is overwritten with its maximum.
        let fields = builder
            .u32_fields
            .iter()
            .map(|&offset| (offset, &[0xff; 4][..]))
            .chain(
                builder
                    .u16_fields
                    .iter()
                    .map(|&offset| (offset, &[0xff; 2][..])),
            );
        assert_eq!(fields.clone().count(), 11);
        for (offset, replacement) in fields {
            let range = offset..offset + replacement.len();
            let original = data[range.clone()].to_vec();
            data[range.clone()].copy_from_slice(replacement);
            assert!(parse(data.clone()).is_err(), "field at {offset}");
            data[range].copy_from_slice(&original);
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
            &b"\x00\x04\xf0\x9f\x98\x80"[..], // Standard UTF-8 is not modified UTF-8.
        ] {
            assert!(Reader { remaining: bytes }.string().is_err());
        }
    }

    #[test]
    fn supports_v1_entries_without_certificate_type_fields() {
        let mut builder = Builder::new(VERSION_01, 2);
        builder.entry(PRIVATE_KEY_TAG, b"key", VERSION_01, 1);
        builder.entry(TRUSTED_CERT_TAG, b"cert", VERSION_01, 1);
        assert_eq!(
            load_entries(&builder.finish(""), "").unwrap(),
            [cert("cert"), key("key")]
        );
    }

    #[test]
    fn reads_a_java_generated_keystore() {
        assert_eq!(
            load_entries(KEYTOOL_JKS, "changeit").unwrap(),
            [cert("root-cert")]
        );
    }

    #[test]
    fn lists_both_entry_types_in_alias_order_without_the_key_password() {
        assert_eq!(
            load_entries(&mixed_keystore(), "changeit").unwrap(),
            [cert("root-cert"), key("server-key")]
        );
    }

    #[test]
    fn reports_short_and_empty_non_jks_files_as_invalid_magic() {
        for data in [
            &b""[..],
            &b"PK"[..],
            &b"not a keystore"[..],
            &b"\x30\x82PKCS12"[..],
        ] {
            assert!(matches!(
                parse(data.to_vec()),
                Err(KeyStoreError::InvalidMagic)
            ));
        }
    }

    #[test]
    fn rejects_truncated_files() {
        for end in [4, 12, KEYTOOL_JKS.len() - 1] {
            let error = parse(KEYTOOL_JKS[..end].to_vec()).err().unwrap();
            assert!(error.to_string().contains("truncated"));
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
        assert!(matches!(parse(data), Err(KeyStoreError::UnknownVersion(3))));
    }

    #[test]
    fn ignores_trailing_data_after_the_digest_like_java() {
        let mut data = KEYTOOL_JKS.to_vec();
        data.extend_from_slice(b"\0trailing");
        assert_eq!(
            load_entries(&data, "changeit").unwrap(),
            [cert("root-cert")]
        );
        assert!(matches!(
            load_entries(&data, ""),
            Err(KeyStoreError::InvalidDigest)
        ));
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
