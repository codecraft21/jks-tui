use std::fmt;

use sha1::{Digest, Sha1};
use zeroize::Zeroize;

use crate::{
    certificate::{self, Summary},
    java_serialization,
};

pub(crate) const MAGIC: u32 = 0xfeed_feed;
/// JCEKS shares the JKS layout and digest, and adds secret-key entries.
pub(crate) const JCEKS_MAGIC: u32 = 0xcece_cece;
pub(crate) const VERSION_01: u32 = 1;
pub(crate) const VERSION_02: u32 = 2;
pub(crate) const PRIVATE_KEY_TAG: u32 = 1;
pub(crate) const TRUSTED_CERT_TAG: u32 = 2;
pub(crate) const SECRET_KEY_TAG: u32 = 3;
/// The class Java seals JCEKS secret keys in.
const SEALED_KEY_CLASS: &[u8] = b"com.sun.crypto.provider.SealedObjectForKeyProtector";
/// Java appends this to the password before hashing the keystore body.
const WHITENER_MESSAGE: &[u8] = b"Mighty Aphrodite";

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidMagic,
    UnknownVersion(u32),
    UnknownEntryTag(u32),
    Truncated,
    Invalid(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => f.write_str("not a JKS or JCEKS file (bad magic number)"),
            Self::UnknownVersion(version) => write!(f, "unsupported keystore version {version}"),
            Self::UnknownEntryTag(tag) => write!(f, "unknown entry tag {tag}"),
            Self::Truncated => f.write_str("truncated keystore data"),
            Self::Invalid(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug, PartialEq, Eq)]
pub struct KeystoreEntry {
    pub alias: String,
    pub kind: &'static str,
    /// The entry's certificate, or the first of a private key's chain.
    pub certificate: Option<Summary>,
    /// Original DER in leaf-first stored order, including unreadable certificates.
    pub certificates: Vec<Vec<u8>>,
    pub chain_warning: Option<&'static str>,
}

/// A structurally valid keystore whose integrity digest has not been checked.
/// Parse once, then call `verify` for each password attempt. Entries are only
/// reachable through a successful `verify`.
pub struct Keystore {
    data: Vec<u8>,
    body_len: usize,
    entries: Vec<KeystoreEntry>,
}

pub(crate) const DIGEST_LEN: usize = 20;
/// The only certificate type standard Java providers can load from a JKS file.
pub(crate) const CERTIFICATE_TYPE: &str = "X.509";

/// Whether the data starts with the JKS or JCEKS magic number.
pub fn has_magic(data: &[u8]) -> bool {
    data.starts_with(&MAGIC.to_be_bytes()) || is_jceks(data)
}

pub fn is_jceks(data: &[u8]) -> bool {
    data.starts_with(&JCEKS_MAGIC.to_be_bytes())
}

pub fn parse(mut data: Vec<u8>) -> Result<Keystore, Error> {
    // Check the magic first so short or empty non-JKS files are reported as
    // such rather than as truncated keystores.
    if !has_magic(&data) {
        return Err(Error::InvalidMagic);
    }
    let jceks = is_jceks(&data);
    let mut reader = Reader {
        remaining: &data[4..],
    };
    let version = reader.u32()?;
    if !matches!(version, VERSION_01 | VERSION_02) {
        return Err(Error::UnknownVersion(version));
    }

    // Even the smallest v1 entry needs a tag, alias length, timestamp and
    // certificate length. Never reserve memory from an untrusted count.
    let count = reader.count(18)?;
    let mut entries = Vec::new();
    for _ in 0..count {
        let tag = reader.u32()?;
        let alias = reader.string()?;
        reader.take(8)?; // Creation timestamp; listing does not need it.
        let mut certificates = Vec::new();
        let (kind, certificate) = match tag {
            PRIVATE_KEY_TAG => {
                // Encrypted key bytes remain opaque. Like Java, accept any
                // length (even empty) and a key entry without a chain.
                reader.payload()?;
                let cert_count = reader.count(if version == VERSION_01 { 4 } else { 6 })?;
                let mut leaf = None;
                for index in 0..cert_count {
                    let encoding = reader.certificate(version)?;
                    certificates.push(encoding.to_vec());
                    if index == 0 {
                        leaf = certificate::summarize(encoding);
                    }
                }
                ("Private key", leaf)
            }
            TRUSTED_CERT_TAG => {
                let encoding = reader.certificate(version)?;
                certificates.push(encoding.to_vec());
                ("Trusted certificate", certificate::summarize(encoding))
            }
            SECRET_KEY_TAG if jceks => {
                // Java writes the sealed key as a serialized object with no
                // length, so its layout is walked to find the next entry.
                let (class, rest) = java_serialization::skip_object(reader.remaining).map_err(
                    |error| match error {
                        java_serialization::Error::Truncated => Error::Truncated,
                        _ => Error::Invalid("unsupported secret key encoding in JCEKS data"),
                    },
                )?;
                if class != SEALED_KEY_CLASS {
                    return Err(Error::Invalid("unsupported secret key type in JCEKS data"));
                }
                reader.remaining = rest;
                ("Secret key", None)
            }
            _ => return Err(Error::UnknownEntryTag(tag)),
        };
        entries.push(KeystoreEntry {
            alias,
            kind,
            certificate,
            certificates,
            chain_warning: None,
        });
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
        let (body, digest) = self.data.split_at(self.body_len);
        if digest_of(password, body)[..] == *digest {
            Ok(self.entries)
        } else {
            Err(self)
        }
    }
}

/// The integrity digest Java stores after the keystore body.
pub(crate) fn digest_of(password: &str, body: &[u8]) -> [u8; DIGEST_LEN] {
    let mut hasher = Sha1::new();
    hash_password(password, |bytes| hasher.update(bytes));
    hasher.update(body);
    hasher.finalize().into()
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

struct Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        if len > self.remaining.len() {
            return Err(Error::Truncated);
        }
        let (bytes, remaining) = self.remaining.split_at(len);
        self.remaining = remaining;
        Ok(bytes)
    }

    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn count(&mut self, minimum_size: usize) -> Result<u32, Error> {
        let count = self.u32()?;
        if u64::from(count) > (self.remaining.len() / minimum_size) as u64 {
            return Err(Error::Truncated);
        }
        Ok(count)
    }

    fn payload(&mut self) -> Result<&'a [u8], Error> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    fn certificate(&mut self, version: u32) -> Result<&'a [u8], Error> {
        // Java resolves the type with CertificateFactory (case-insensitively),
        // and standard providers only support X.509. Version 1 implies X.509.
        if version == VERSION_02 && !self.string()?.eq_ignore_ascii_case(CERTIFICATE_TYPE) {
            return Err(Error::Invalid(
                "unsupported certificate type in keystore data",
            ));
        }
        // Java fails to load a keystore whose certificate encoding is empty.
        let encoding = self.payload()?;
        if encoding.is_empty() {
            return Err(Error::Invalid("empty certificate in keystore data"));
        }
        Ok(encoding)
    }

    fn string(&mut self) -> Result<String, Error> {
        let len = u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as usize;
        let mut bytes = self.take(len)?;
        // Java's DataInput.readUTF encodes UTF-16 units: NUL uses C0 80 and
        // supplementary characters use two three-byte surrogate sequences.
        let invalid = || Error::Invalid("invalid modified UTF-8 in keystore string");
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
/// Parses valid test data and returns its entries, or `None` if the password
/// does not match the digest.
pub fn load_entries(data: &[u8], password: &str) -> Option<Vec<KeystoreEntry>> {
    parse(data.to_vec()).unwrap().verify(password).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{
        Builder, KEYTOOL_JCEKS, KEYTOOL_JKS, UNICODE_ALIAS_JKS, UNICODE_PASSWORD_JKS,
        empty_keystore, fixture_certificate_der, fixture_summary, mixed_keystore,
    };
    fn key(alias: &str) -> KeystoreEntry {
        KeystoreEntry {
            alias: alias.into(),
            kind: "Private key",
            certificate: None,
            certificates: vec![b"opaque synthetic certificate".to_vec()],
            chain_warning: None,
        }
    }

    fn cert(alias: &str) -> KeystoreEntry {
        KeystoreEntry {
            alias: alias.into(),
            kind: "Trusted certificate",
            certificate: None,
            certificates: vec![b"opaque synthetic certificate".to_vec()],
            chain_warning: None,
        }
    }

    fn fixture_cert(alias: &str) -> KeystoreEntry {
        KeystoreEntry {
            certificate: Some(fixture_summary()),
            certificates: vec![fixture_certificate_der().to_vec()],
            ..cert(alias)
        }
    }

    #[test]
    fn summarizes_the_first_certificate_of_a_private_key_chain() {
        let mut data = Builder::new(VERSION_02, 1);
        data.entry_header(PRIVATE_KEY_TAG, b"key");
        data.payload(b"synthetic test payload, not a private key");
        data.u32_field(2);
        data.raw_string(CERTIFICATE_TYPE.as_bytes());
        data.payload(fixture_certificate_der());
        data.certificate(VERSION_02);
        assert_eq!(
            load_entries(&data.finish(""), "").unwrap(),
            [KeystoreEntry {
                certificate: Some(fixture_summary()),
                certificates: vec![
                    fixture_certificate_der().to_vec(),
                    b"opaque synthetic certificate".to_vec()
                ],
                ..key("key")
            }]
        );
    }

    #[test]
    fn verifies_java_passwords_with_accented_and_supplementary_characters() {
        assert_eq!(
            load_entries(UNICODE_PASSWORD_JKS, "pässwörd-😀").unwrap(),
            load_entries(KEYTOOL_JKS, "changeit").unwrap()
        );
        for password in ["", "pässwörd", "pässwörd-😁"] {
            assert!(load_entries(UNICODE_PASSWORD_JKS, password).is_none());
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
            [fixture_cert("root-cert")]
        );
    }

    #[test]
    fn reads_java_aliases_with_supplementary_characters() {
        assert_eq!(
            load_entries(UNICODE_ALIAS_JKS, "changeit").unwrap(),
            [fixture_cert("certificate-😀")]
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
        assert_eq!(
            load_entries(&builder.finish(""), "").unwrap(),
            [KeystoreEntry {
                certificates: vec![],
                ..key("key")
            }]
        );
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
            [fixture_cert("root-cert")]
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
            &b"\xce\xce\xce"[..],
        ] {
            assert!(matches!(parse(data.to_vec()), Err(Error::InvalidMagic)));
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
        assert!(load_entries(KEYTOOL_JKS, "wrong-password").is_none());
        let mut data = KEYTOOL_JKS.to_vec();
        *data.last_mut().unwrap() ^= 1;
        assert!(load_entries(&data, "changeit").is_none());
    }

    #[test]
    fn rejects_unsupported_versions_even_without_entries() {
        let mut data = empty_keystore();
        data[4..8].copy_from_slice(&3_u32.to_be_bytes());
        assert!(matches!(parse(data), Err(Error::UnknownVersion(3))));
    }

    #[test]
    fn ignores_trailing_data_after_the_digest_like_java() {
        let mut data = KEYTOOL_JKS.to_vec();
        data.extend_from_slice(b"\0trailing");
        assert_eq!(
            load_entries(&data, "changeit").unwrap(),
            [fixture_cert("root-cert")]
        );
        assert!(load_entries(&data, "").is_none());
    }

    #[test]
    fn reads_a_java_generated_jceks_keystore() {
        assert!(is_jceks(KEYTOOL_JCEKS));
        assert!(load_entries(KEYTOOL_JCEKS, "wrong").is_none());
        assert_eq!(
            load_entries(KEYTOOL_JCEKS, "changeit").unwrap(),
            [fixture_cert("root-cert")]
        );
    }

    fn secret(alias: &str) -> KeystoreEntry {
        KeystoreEntry {
            alias: alias.into(),
            kind: "Secret key",
            certificate: None,
            certificates: vec![],
            chain_warning: None,
        }
    }

    #[test]
    fn lists_jceks_secret_keys_alongside_other_entries() {
        for version in [VERSION_01, VERSION_02] {
            let mut builder = Builder::jceks(version, 4);
            builder.entry(SECRET_KEY_TAG, b"aes", version, 0);
            builder.entry(PRIVATE_KEY_TAG, b"key", version, 1);
            builder.entry(SECRET_KEY_TAG, b"hmac", version, 0);
            builder.entry(TRUSTED_CERT_TAG, b"cert", version, 1);
            assert_eq!(
                load_entries(&builder.finish("changeit"), "changeit").unwrap(),
                [secret("aes"), cert("cert"), secret("hmac"), key("key")]
            );
        }
    }

    #[test]
    fn secret_keys_are_jceks_only_and_must_be_sealed_keys() {
        let mut builder = Builder::new(VERSION_02, 1);
        builder.entry(SECRET_KEY_TAG, b"aes", VERSION_02, 0);
        assert_eq!(
            parse(builder.finish("")).err(),
            Some(Error::UnknownEntryTag(SECRET_KEY_TAG))
        );
        let mut builder = Builder::jceks(VERSION_02, 1);
        builder.entry(SECRET_KEY_TAG, b"aes", VERSION_02, 0);
        let data = builder.finish("");
        let class = data
            .windows(SEALED_KEY_CLASS.len())
            .position(|window| window == SEALED_KEY_CLASS)
            .unwrap();
        let mut renamed = data.clone();
        renamed[class] = b'x';
        let error = parse(renamed).err().unwrap();
        assert!(error.to_string().contains("secret key type"), "{error}");
        for end in 0..data.len() {
            assert!(parse(data[..end].to_vec()).is_err(), "prefix {end}");
        }
    }

    #[test]
    fn supports_empty_keystores() {
        assert!(load_entries(&empty_keystore(), "").unwrap().is_empty());
    }

    #[test]
    fn preserves_alias_case_when_identifying_entry_types() {
        let mut builder = Builder::new(VERSION_02, 1);
        builder.entry(PRIVATE_KEY_TAG, b"MixedCase", VERSION_02, 1);
        assert_eq!(
            load_entries(&builder.finish("changeit"), "changeit").unwrap(),
            [key("MixedCase")]
        );
    }
}
