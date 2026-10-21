use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};

use crown::asn1::Asn1Time;

use crate::certificate::Summary;
use crate::keystore::{
    CERTIFICATE_TYPE, MAGIC, PRIVATE_KEY_TAG, TRUSTED_CERT_TAG, VERSION_02, digest_of,
};

pub const KEYTOOL_JKS: &[u8] = include_bytes!("../tests/fixtures/trusted-cert.jks");
pub const UNICODE_PASSWORD_JKS: &[u8] = include_bytes!("../tests/fixtures/unicode-password.jks");
pub const UNICODE_ALIAS_JKS: &[u8] = include_bytes!("../tests/fixtures/unicode-alias.jks");

/// The DER certificate stored in `KEYTOOL_JKS` under the alias `root-cert`.
pub fn fixture_certificate_der() -> &'static [u8] {
    // Header, tag, alias, timestamp and the "X.509" type precede its length.
    let offset = 12 + 4 + 2 + "root-cert".len() + 8 + 2 + CERTIFICATE_TYPE.len();
    let len = u32::from_be_bytes(KEYTOOL_JKS[offset..offset + 4].try_into().unwrap()) as usize;
    &KEYTOOL_JKS[offset + 4..offset + 4 + len]
}

/// What the entry list shows for the fixture certificate.
pub fn fixture_summary() -> Summary {
    Summary {
        algorithm: "EC".into(),
        key_size: Some(256),
        not_after: Asn1Time::new(2036, 10, 9, 19, 48, 29, true).unwrap(),
    }
}

pub struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    pub fn new() -> Self {
        static NEXT_ID: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "keystore-tui-test-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Writes a keystore field by field, recording where each length or count
/// lives so tests can corrupt them without re-implementing the parser.
#[derive(Default)]
pub struct Builder {
    body: Vec<u8>,
    pub u32_fields: Vec<usize>,
    pub u16_fields: Vec<usize>,
}

impl Builder {
    pub fn new(version: u32, count: u32) -> Self {
        let mut builder = Self::default();
        builder.u32(MAGIC);
        builder.u32(version);
        builder.u32_field(count);
        builder
    }

    fn u32(&mut self, value: u32) {
        self.body.extend_from_slice(&value.to_be_bytes());
    }

    pub fn u32_field(&mut self, value: u32) {
        self.u32_fields.push(self.body.len());
        self.u32(value);
    }

    pub fn raw_string(&mut self, bytes: &[u8]) {
        self.u16_fields.push(self.body.len());
        self.body
            .extend_from_slice(&u16::try_from(bytes.len()).unwrap().to_be_bytes());
        self.body.extend_from_slice(bytes);
    }

    pub fn payload(&mut self, bytes: &[u8]) {
        self.u32_field(bytes.len().try_into().unwrap());
        self.body.extend_from_slice(bytes);
    }

    pub fn certificate(&mut self, version: u32) {
        if version == VERSION_02 {
            self.raw_string(CERTIFICATE_TYPE.as_bytes());
        }
        self.payload(b"opaque synthetic certificate");
    }

    /// Writes the tag, alias and creation timestamp every entry starts with.
    pub fn entry_header(&mut self, tag: u32, alias: &[u8]) {
        self.u32(tag);
        self.raw_string(alias);
        self.body.extend_from_slice(&0_u64.to_be_bytes());
    }

    pub fn entry(&mut self, tag: u32, alias: &[u8], version: u32, certificates: u32) {
        self.entry_header(tag, alias);
        if tag == PRIVATE_KEY_TAG {
            // Entry listing treats encrypted key bytes as opaque. Do not
            // store an actual private key in the test source or fixtures.
            self.payload(b"synthetic test payload, not a private key");
            self.u32_field(certificates);
        }
        for _ in 0..certificates {
            self.certificate(version);
        }
    }

    pub fn finish(&self, password: &str) -> Vec<u8> {
        let mut data = self.body.clone();
        data.extend_from_slice(&digest_of(password, &self.body));
        data
    }
}

pub fn empty_keystore() -> Vec<u8> {
    Builder::new(VERSION_02, 0).finish("")
}

pub fn mixed_keystore() -> Vec<u8> {
    let mut builder = Builder::new(VERSION_02, 2);
    builder.entry(TRUSTED_CERT_TAG, b"root-cert", VERSION_02, 1);
    builder.entry(PRIVATE_KEY_TAG, b"server-key", VERSION_02, 1);
    builder.finish("changeit")
}

/// Builds display-only certificates using the generated fixture's public SPKI.
/// Signatures remain synthetic; no private key is needed or stored.
pub fn metadata_certificate(
    subject: &str,
    issuer: &str,
    serial: &[u8],
    extensions: &[Vec<u8>],
) -> Vec<u8> {
    use crown::{
        asn1::{Reader, der},
        x509::name::Name,
    };
    let mut certificate = Reader::new(fixture_certificate_der())
        .read_sequence()
        .unwrap();
    let mut tbs = certificate.read_sequence().unwrap();
    tbs.read_raw_tlv().unwrap(); // Version.
    tbs.read_raw_tlv().unwrap(); // Serial.
    let signature = tbs.read_raw_tlv().unwrap();
    tbs.read_raw_tlv().unwrap(); // Issuer.
    let validity = tbs.read_raw_tlv().unwrap();
    tbs.read_raw_tlv().unwrap(); // Subject.
    let spki = tbs.read_raw_tlv().unwrap();
    let mut body = [
        der::explicit(0, &der::integer_i64(2)),
        der::tlv(der::INTEGER, serial),
        signature.to_vec(),
        Name::from_common_name(issuer).encode(),
        validity.to_vec(),
        Name::from_common_name(subject).encode(),
        spki.to_vec(),
    ]
    .concat();
    if !extensions.is_empty() {
        body.extend(der::explicit(3, &der::sequence(&extensions.concat())));
    }
    der::sequence(
        &[
            der::sequence(&body),
            signature.to_vec(),
            der::bit_string(0, &[1, 2, 3]),
        ]
        .concat(),
    )
}
