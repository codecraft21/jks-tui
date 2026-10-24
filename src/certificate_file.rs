//! Standalone certificate files: PEM or DER certificates, PKCS#7 bundles, and
//! PKCS#10 certificate requests. Each certificate or request becomes one
//! entry; a certificate's chain is assembled from the other certificates in
//! the same file by matching issuer and subject names.
use crown::{
    asn1::{Reader, der, oid, pem},
    error::CryptoError,
    pkcs7::ContentInfo,
    x509::name::Name,
};

use crate::{
    certificate::{self, details::Details},
    certificate_request,
    keystore::{Content, KeystoreEntry, Kind},
};

/// File name extensions offered by the file browser alongside keystores.
pub const EXTENSIONS: &[&str] = &["pem", "crt", "cer", "der", "p7b", "p7c", "csr", "p10"];

pub struct CertificateFile {
    /// In file order.
    pub entries: Vec<KeystoreEntry>,
    /// Whether PEM blocks other than certificates and requests, such as
    /// private keys, were ignored.
    pub skipped: bool,
}

/// A certificate or request in file order, as exact DER.
enum Item {
    Certificate(Vec<u8>),
    Request(Vec<u8>),
}

pub fn is_pem(data: &[u8]) -> bool {
    data.windows(11).any(|window| window == b"-----BEGIN ")
}

pub fn has_extension(path: &std::path::Path) -> bool {
    path.extension().is_some_and(|extension| {
        EXTENSIONS
            .iter()
            .any(|known| extension.eq_ignore_ascii_case(known))
    })
}

pub fn parse(data: &[u8]) -> Result<CertificateFile, &'static str> {
    let mut items = Vec::new();
    let mut skipped = false;
    if is_pem(data) {
        let text = std::str::from_utf8(data).map_err(|_| "PEM file is not valid UTF-8 text")?;
        for block in pem::parse(text).map_err(|_| "malformed PEM block")? {
            match block.label.as_str() {
                "CERTIFICATE" | "X509 CERTIFICATE" => items.push(Item::Certificate(block.data)),
                // OpenSSL appends trust settings after the certificate.
                "TRUSTED CERTIFICATE" => items.push(Item::Certificate(
                    Reader::new(&block.data)
                        .read_raw_tlv()
                        .map_err(|_| "malformed trusted certificate")?
                        .to_vec(),
                )),
                // Java's keytool writes the older "NEW" label.
                "CERTIFICATE REQUEST" | "NEW CERTIFICATE REQUEST" => {
                    items.push(Item::Request(block.data))
                }
                "PKCS7" | "CMS" => items.extend(
                    pkcs7_certificates(&block.data)?
                        .into_iter()
                        .map(Item::Certificate),
                ),
                _ => skipped = true,
            }
        }
    } else if let Some(item) = single_der_item(data) {
        items.push(item);
    } else {
        items = pkcs7_certificates(data)?
            .into_iter()
            .map(Item::Certificate)
            .collect();
    }
    if items.is_empty() {
        return Err("the file contains no certificates or certificate requests");
    }
    Ok(CertificateFile {
        entries: entries(&items),
        skipped,
    })
}

/// A certificate or request that is exactly one DER element.
fn single_der_item(data: &[u8]) -> Option<Item> {
    let tlv = Reader::new(data).read_raw_tlv().ok()?;
    if tlv.len() != data.len() {
        None
    } else if certificate::summarize(data).is_some() {
        Some(Item::Certificate(data.to_vec()))
    } else if certificate_request::summarize(data).is_some() {
        Some(Item::Request(data.to_vec()))
    } else {
        None
    }
}

/// The X.509 certificates of a PKCS#7 SignedData, as exact DER.
fn pkcs7_certificates(data: &[u8]) -> Result<Vec<Vec<u8>>, &'static str> {
    let info = ContentInfo::parse(data)
        .map_err(|_| "not a certificate, certificate request, or PKCS#7 file")?;
    if !info.content_type.matches(oid::OID_PKCS7_SIGNED_DATA) {
        return Err("PKCS#7 content is not signed data");
    }
    let malformed = |_: CryptoError| "malformed PKCS#7 signed data";
    let mut reader = Reader::new(&info.content);
    let mut signed = reader.read_sequence().map_err(malformed)?;
    signed.read_raw_tlv().map_err(malformed)?; // Version.
    signed.read_raw_tlv().map_err(malformed)?; // Digest algorithms.
    signed.read_raw_tlv().map_err(malformed)?; // Encapsulated content.
    let mut certificates = Vec::new();
    if !signed.is_empty()
        && signed.peek_tag().map_err(malformed)? == der::Tag::context_constructed(0)
    {
        let mut set = signed.read_implicit_constructed(0).map_err(malformed)?;
        while !set.is_empty() {
            let raw = set.read_raw_tlv().map_err(malformed)?;
            // Attribute certificates use other tags and are not listed.
            if Reader::new(raw).peek_tag().map_err(malformed)? == der::SEQUENCE {
                certificates.push(raw.to_vec());
            }
        }
    }
    Ok(certificates)
}

/// Comparable issuer and subject names, used to link chains.
fn names(der: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut tbs = Reader::new(der)
        .read_sequence()
        .ok()?
        .read_sequence()
        .ok()?;
    if tbs.peek_tag().ok()? == der::Tag::context_constructed(0) {
        tbs.read_raw_tlv().ok()?; // Version.
    }
    tbs.read_raw_tlv().ok()?; // Serial number.
    tbs.read_raw_tlv().ok()?; // Signature algorithm.
    let issuer = tbs.read_raw_tlv().ok()?;
    tbs.read_raw_tlv().ok()?; // Validity.
    Some((name_key(issuer), name_key(tbs.read_raw_tlv().ok()?)))
}

/// The decoded name ignoring case, so the same name matches across string
/// encodings; the raw DER when it cannot be decoded.
fn name_key(raw: &[u8]) -> Vec<u8> {
    Name::parse(&mut Reader::new(raw)).map_or_else(
        |_| raw.to_vec(),
        |name| name.to_string().to_lowercase().into_bytes(),
    )
}

fn entries(items: &[Item]) -> Vec<KeystoreEntry> {
    // Requests have no issuer and are never part of a chain.
    let names: Vec<_> = items
        .iter()
        .map(|item| match item {
            Item::Certificate(der) => names(der),
            Item::Request(_) => None,
        })
        .collect();
    let der = |index: usize| match &items[index] {
        Item::Certificate(der) | Item::Request(der) => der,
    };
    (0..items.len())
        .map(|index| {
            if let Item::Request(request) = &items[index] {
                return KeystoreEntry {
                    alias: certificate_request::subject_name(request)
                        .unwrap_or_else(|| format!("Certificate request {}", index + 1)),
                    certificate: certificate_request::summarize(request),
                    content: Content::Request(request.clone()),
                    chain_warning: None,
                };
            }
            // Follow issuers through the file, stopping at a self-issued
            // certificate, a missing issuer, or a certificate already used.
            let mut chain = vec![index];
            while let Some((issuer, subject)) = &names[chain[chain.len() - 1]]
                && issuer != subject
                && let Some(next) = (0..names.len()).find(|candidate| {
                    !chain.contains(candidate)
                        && names[*candidate]
                            .as_ref()
                            .is_some_and(|(_, subject)| subject == issuer)
                })
            {
                chain.push(next);
            }
            KeystoreEntry {
                alias: alias(index, der(index)),
                certificate: certificate::summarize(der(index)),
                content: Content::Certificates {
                    kind: Kind::Certificate,
                    certificates: chain.iter().map(|&i| der(i).clone()).collect(),
                },
                chain_warning: None,
            }
        })
        .collect()
}

/// The subject name, else the file position.
fn alias(index: usize, der: &[u8]) -> String {
    subject_name(der).unwrap_or_else(|| format!("Certificate {}", index + 1))
}

/// The subject common name, else the whole subject, if either is non-empty.
pub fn subject_name(der: &[u8]) -> Option<String> {
    Details::parse(der)
        .ok()
        .and_then(|info| certificate::name_alias(&info.subject))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{fixture_certificate_der, metadata_certificate};

    fn signed_data(certificates: &[Vec<u8>]) -> Vec<u8> {
        let content = der::sequence(
            &[
                der::integer_i64(1),
                der::set(&[]),
                der::sequence(&der::oid(
                    &oid::ObjectIdentifier::new(oid::OID_PKCS7_DATA).unwrap(),
                )),
                der::implicit(0, true, &certificates.concat()),
                der::set(&[]),
            ]
            .concat(),
        );
        ContentInfo {
            content_type: oid::ObjectIdentifier::new(oid::OID_PKCS7_SIGNED_DATA).unwrap(),
            content,
        }
        .encode()
    }

    fn aliases(file: &CertificateFile) -> Vec<&str> {
        file.entries
            .iter()
            .map(|entry| entry.alias.as_str())
            .collect()
    }

    #[test]
    fn reads_a_der_certificate() {
        let file = parse(fixture_certificate_der()).unwrap();
        assert_eq!(file.entries.len(), 1);
        assert!(!file.skipped);
        let entry = &file.entries[0];
        assert_eq!(entry.kind(), "Certificate");
        assert_eq!(entry.certificates(), [fixture_certificate_der()]);
        assert!(entry.certificate.is_some());
    }

    #[test]
    fn pem_bundles_keep_file_order_link_chains_and_skip_other_blocks() {
        let root = metadata_certificate("root", "root", &[1], &[]);
        let intermediate = metadata_certificate("intermediate", "root", &[2], &[]);
        let leaf = metadata_certificate("leaf", "intermediate", &[3], &[]);
        let text = [
            pem::encode("CERTIFICATE", &leaf),
            "comment between blocks\n".into(),
            pem::encode("PRIVATE KEY", b"synthetic, not a key"),
            pem::encode("CERTIFICATE", &root),
            pem::encode("CERTIFICATE", &intermediate),
        ]
        .concat();
        let file = parse(text.as_bytes()).unwrap();
        assert!(file.skipped);
        assert_eq!(aliases(&file), ["leaf", "root", "intermediate"]);
        assert_eq!(
            file.entries[0].certificates(),
            [leaf, intermediate.clone(), root.clone()]
        );
        assert_eq!(file.entries[1].certificates(), std::slice::from_ref(&root));
        assert_eq!(file.entries[2].certificates(), [intermediate, root]);
    }

    #[test]
    fn issuer_cycles_and_unreadable_certificates_do_not_loop() {
        let a = metadata_certificate("a", "b", &[1], &[]);
        let b = metadata_certificate("b", "a", &[2], &[]);
        let text = [
            pem::encode("CERTIFICATE", &a),
            pem::encode("CERTIFICATE", &b),
            pem::encode("CERTIFICATE", b"unreadable"),
        ]
        .concat();
        let file = parse(text.as_bytes()).unwrap();
        assert_eq!(aliases(&file), ["a", "b", "Certificate 3"]);
        assert_eq!(file.entries[0].certificates(), [a.clone(), b.clone()]);
        assert_eq!(file.entries[1].certificates(), [b, a]);
        assert_eq!(file.entries[2].certificates(), [b"unreadable".to_vec()]);
        assert!(file.entries[2].certificate.is_none());
    }

    #[test]
    fn reads_der_and_pem_pkcs7_bundles() {
        let root = metadata_certificate("root", "root", &[1], &[]);
        let leaf = metadata_certificate("leaf", "root", &[2], &[]);
        let bundle = signed_data(&[leaf.clone(), root.clone()]);
        for data in [bundle.clone(), pem::encode("PKCS7", &bundle).into_bytes()] {
            let file = parse(&data).unwrap();
            assert_eq!(aliases(&file), ["leaf", "root"]);
            assert_eq!(file.entries[0].certificates(), [leaf.clone(), root.clone()]);
        }
    }

    #[test]
    fn requests_are_listed_in_file_order_outside_chains() {
        use crate::test_support::{KEYTOOL_REQUEST, OPENSSL_REQUEST_DER, ed25519_request};
        let root = metadata_certificate("root", "root", &[1], &[]);
        let request = ed25519_request("root", &[]);
        let unnamed = ed25519_request("", &[]);
        let text = [
            pem::encode("CERTIFICATE REQUEST", &request),
            pem::encode("CERTIFICATE", &root),
            pem::encode("NEW CERTIFICATE REQUEST", &unnamed),
        ]
        .concat();
        let file = parse(text.as_bytes()).unwrap();
        assert!(!file.skipped);
        assert_eq!(aliases(&file), ["root", "root", "Certificate request 3"]);
        let kinds: Vec<_> = file.entries.iter().map(KeystoreEntry::kind).collect();
        assert_eq!(
            kinds,
            [
                certificate_request::KIND,
                "Certificate",
                certificate_request::KIND
            ]
        );
        assert_eq!(file.entries[0].content, Content::Request(request.clone()));
        assert_eq!(
            file.entries[0].certificate.as_ref().unwrap().algorithm,
            "Ed25519"
        );
        assert_eq!(file.entries[1].certificates(), [root]);

        let keytool = parse(KEYTOOL_REQUEST).unwrap();
        assert_eq!(aliases(&keytool), ["CSR TUI test fixture"]);
        let openssl = parse(OPENSSL_REQUEST_DER).unwrap();
        assert_eq!(aliases(&openssl), ["OpenSSL CSR fixture"]);
        assert_eq!(
            openssl.entries[0].content,
            Content::Request(OPENSSL_REQUEST_DER.to_vec())
        );
    }

    #[test]
    fn rejects_files_without_certificates() {
        assert!(parse(&signed_data(&[])).is_err());
        assert!(parse(pem::encode("PRIVATE KEY", b"synthetic").as_bytes()).is_err());
        assert!(parse(b"-----BEGIN CERTIFICATE-----\nnot base64!\n").is_err());
        assert!(parse(b"\x30\x03\x02\x01\x01").is_err());
        let mut trailing = fixture_certificate_der().to_vec();
        trailing.push(0);
        assert!(parse(&trailing).is_err());
    }
}
