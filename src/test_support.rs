use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
    time::SystemTime,
};

use jks::{KeyStore, KeyStoreOptions, PrivateKeyEntry};

pub const KEYTOOL_JKS: &[u8] = include_bytes!("../tests/fixtures/trusted-cert.jks");
pub const UNICODE_PASSWORD_JKS: &[u8] = include_bytes!("../tests/fixtures/unicode-password.jks");
pub const UNICODE_ALIAS_JKS: &[u8] = include_bytes!("../tests/fixtures/unicode-alias.jks");

pub struct TestDirectory {
    pub path: PathBuf,
}

impl TestDirectory {
    pub fn new() -> Self {
        static NEXT_ID: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "jks-tui-test-{}-{}",
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

pub fn empty_keystore() -> Vec<u8> {
    let keystore = KeyStore::with_options(KeyStoreOptions {
        min_password_len: 0,
        ..Default::default()
    });
    let mut data = Vec::new();
    keystore.store(&mut data, b"").unwrap();
    data
}

pub fn mixed_keystore() -> Vec<u8> {
    let mut keystore = KeyStore::new();
    keystore.load(KEYTOOL_JKS, b"changeit").unwrap();
    let certificate = keystore
        .get_trusted_certificate_entry("root-cert")
        .unwrap()
        .certificate;
    keystore
        .set_private_key_entry(
            "server-key",
            PrivateKeyEntry {
                creation_time: SystemTime::UNIX_EPOCH,
                // Entry listing treats encrypted key bytes as opaque. Do not
                // store an actual private key in the test source or fixture.
                private_key: b"synthetic test payload, not a private key".to_vec(),
                certificate_chain: vec![certificate],
            },
            b"keypass",
        )
        .unwrap();
    let mut data = Vec::new();
    keystore.store(&mut data, b"changeit").unwrap();
    data
}
