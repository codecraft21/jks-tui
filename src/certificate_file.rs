//! Standalone certificate files: PEM or DER certificates, PKCS#7 bundles,
//! certificate requests, and revocation lists. Each becomes one entry; chains
//! are assembled from the certificates in the same file by matching issuer and
//! subject names.
use crown::{
    asn1::{Reader, der, oid, pem},
    error::CryptoError,
    pkcs7::ContentInfo,
    x509::name::Name,
};

use crate::{
    certificate::{self, details::Details, request::Request, revocation::RevocationList},
    keystore::{Document, KeystoreEntry},
};

/// File name extensions offered by the file browser alongside keystores.
pub const EXTENSIONS: &[&str] = &[
    "pem", "crt", "cer", "der", "p7b", "p7c", "csr", "p10", "crl",
];
pub const KIND: &str = "Certificate";
pub const REQUEST_KIND: &str = "Certificate request";
pub const REVOCATION_LIST_KIND: &str = "Revocation list";

pub struct CertificateFile {
    /// In file order.
    pub entries: Vec<KeystoreEntry>,
    /// Whether PEM blocks of other kinds, such as private keys, were ignored.
    pub skipped: bool,
}

/// One DER object of the file. `None` is a certificate.
type Item = (Option<Document>, Vec<u8>);

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
                "CERTIFICATE" | "X509 CERTIFICATE" => items.push((None, block.data)),
                // OpenSSL appends trust settings after the certificate.
                "TRUSTED CERTIFICATE" => items.push((
                    None,
                    Reader::new(&block.data)
                        .read_raw_tlv()
                        .map_err(|_| "malformed trusted certificate")?
                        .to_vec(),
                )),
                "CERTIFICATE REQUEST" | "NEW CERTIFICATE REQUEST" => {
                    items.push((Some(Document::Request), block.data));
                }
                "X509 CRL" => items.push((Some(Document::RevocationList), block.data)),
                "PKCS7" | "CMS" => items.extend(pkcs7_items(&block.data)?),
                _ => skipped = true,
            }
        }
    } else if let Some(document) = der_kind(data) {
        items.push((document, data.to_vec()));
    } else {
        items = pkcs7_items(data)?;
    }
    if items.is_empty() {
        return Err("the file contains no certificates, requests, or revocation lists");
    }
    Ok(CertificateFile {
        entries: entries(&items),
        skipped,
    })
}

/// What a single, complete DER element reads as, if it is a certificate
/// (`Some(None)`), a request, or a revocation list.
fn der_kind(data: &[u8]) -> Option<Option<Document>> {
    if !Reader::new(data)
        .read_raw_tlv()
        .is_ok_and(|tlv| tlv.len() == data.len())
    {
        None
    } else if certificate::summarize(data).is_some() {
        Some(None)
    } else if Request::parse(data).is_ok() {
        Some(Some(Document::Request))
    } else if RevocationList::parse(data).is_ok() {
        Some(Some(Document::RevocationList))
    } else {
        None
    }
}

/// The X.509 certificates and revocation lists of a PKCS#7 SignedData, as
/// exact DER, certificates first.
fn pkcs7_items(data: &[u8]) -> Result<Vec<Item>, &'static str> {
    let info = ContentInfo::parse(data).map_err(|_| "not a certificate or PKCS#7 file")?;
    if !info.content_type.matches(oid::OID_PKCS7_SIGNED_DATA) {
        return Err("PKCS#7 content is not signed data");
    }
    let malformed = |_: CryptoError| "malformed PKCS#7 signed data";
    let mut reader = Reader::new(&info.content);
    let mut signed = reader.read_sequence().map_err(malformed)?;
    signed.read_raw_tlv().map_err(malformed)?; // Version.
    signed.read_raw_tlv().map_err(malformed)?; // Digest algorithms.
    signed.read_raw_tlv().map_err(malformed)?; // Encapsulated content.
    let mut items = Vec::new();
    for (number, document) in [(0, None), (1, Some(Document::RevocationList))] {
        if !signed.is_empty()
            && signed.peek_tag().map_err(malformed)? == der::Tag::context_constructed(number)
        {
            let mut set = signed
                .read_implicit_constructed(number)
                .map_err(malformed)?;
            while !set.is_empty() {
                let raw = set.read_raw_tlv().map_err(malformed)?;
                // Attribute certificates and other revocation formats use
                // other tags and are not listed.
                if Reader::new(raw).peek_tag().map_err(malformed)? == der::SEQUENCE {
                    items.push((document, raw.to_vec()));
                }
            }
        }
    }
    Ok(items)
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
    // Only certificates take part in chains.
    let names: Vec<_> = items
        .iter()
        .map(|(document, der)| document.is_none().then(|| names(der)).flatten())
        .collect();
    let chain = |first: usize| {
        // Follow issuers through the file, stopping at a self-issued
        // certificate, a missing issuer, or a certificate already used.
        let mut chain = vec![first];
        while let Some((issuer, subject)) = &names[chain[chain.len() - 1]]
            && issuer != subject
            && let Some(next) = issuer_of(&names, issuer, &chain)
        {
            chain.push(next);
        }
        chain
    };
    items
        .iter()
        .enumerate()
        .map(|(index, (document, der))| {
            let (kind, certificate, members) = match document {
                None => (KIND, certificate::summarize(der), chain(index)),
                Some(Document::Request) => (
                    REQUEST_KIND,
                    Request::parse(der).ok().map(|request| request.summary()),
                    vec![index],
                ),
                Some(Document::RevocationList) => {
                    let list = RevocationList::parse(der).ok();
                    let issuer = list
                        .as_ref()
                        .map(|list| name_key(&list.issuer.encode()))
                        .and_then(|issuer| issuer_of(&names, &issuer, &[]));
                    let mut members = vec![index];
                    members.extend(issuer.map(chain).unwrap_or_default());
                    (
                        REVOCATION_LIST_KIND,
                        list.map(|list| list.summary()),
                        members,
                    )
                }
            };
            KeystoreEntry {
                alias: alias(index, *document, der),
                kind,
                certificate,
                certificates: members.iter().map(|&i| items[i].1.clone()).collect(),
                chain_warning: None,
                document: *document,
            }
        })
        .collect()
}

/// The first certificate, not already in `chain`, whose subject is `issuer`.
fn issuer_of(
    names: &[Option<(Vec<u8>, Vec<u8>)>],
    issuer: &[u8],
    chain: &[usize],
) -> Option<usize> {
    (0..names.len()).find(|candidate| {
        !chain.contains(candidate)
            && names[*candidate]
                .as_ref()
                .is_some_and(|(_, subject)| subject == issuer)
    })
}

/// The subject name (a revocation list's issuer name), else the file position.
fn alias(index: usize, document: Option<Document>, der: &[u8]) -> String {
    let (name, fallback) = match document {
        None => (subject_name(der), "Certificate"),
        Some(Document::Request) => (
            Request::parse(der)
                .ok()
                .and_then(|request| display_name(&request.subject)),
            "Request",
        ),
        Some(Document::RevocationList) => (
            RevocationList::parse(der)
                .ok()
                .and_then(|list| display_name(&list.issuer)),
            "Revocation list",
        ),
    };
    name.unwrap_or_else(|| format!("{fallback} {}", index + 1))
}

/// The subject common name, else the whole subject, if either is non-empty.
pub fn subject_name(der: &[u8]) -> Option<String> {
    Details::parse(der)
        .ok()
        .and_then(|info| display_name(&info.subject))
}

/// The common name, else the whole name, if either is non-empty.
fn display_name(name: &Name) -> Option<String> {
    name.common_name()
        .or_else(|| Some(name.to_string()))
        .filter(|name| !name.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{
        ed25519_request, ed25519_revocation_list, fixture_certificate_der, metadata_certificate,
    };

    fn signed_data(certificates: &[Vec<u8>]) -> Vec<u8> {
        signed_data_with_lists(certificates, &[])
    }

    fn signed_data_with_lists(certificates: &[Vec<u8>], lists: &[Vec<u8>]) -> Vec<u8> {
        let content = der::sequence(
            &[
                der::integer_i64(1),
                der::set(&[]),
                der::sequence(&der::oid(
                    &oid::ObjectIdentifier::new(oid::OID_PKCS7_DATA).unwrap(),
                )),
                der::implicit(0, true, &certificates.concat()),
                der::implicit(1, true, &lists.concat()),
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
        assert_eq!(entry.kind, KIND);
        assert_eq!(entry.certificates, [fixture_certificate_der()]);
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
            file.entries[0].certificates,
            [leaf, intermediate.clone(), root.clone()]
        );
        assert_eq!(file.entries[1].certificates, std::slice::from_ref(&root));
        assert_eq!(file.entries[2].certificates, [intermediate, root]);
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
        assert_eq!(file.entries[0].certificates, [a.clone(), b.clone()]);
        assert_eq!(file.entries[1].certificates, [b, a]);
        assert_eq!(file.entries[2].certificates, [b"unreadable".to_vec()]);
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
            assert_eq!(file.entries[0].certificates, [leaf.clone(), root.clone()]);
        }
    }

    #[test]
    fn requests_and_revocation_lists_are_entries_in_file_order() {
        let root = metadata_certificate("root", "root", &[1], &[]);
        let intermediate = metadata_certificate("intermediate", "root", &[2], &[]);
        let request = ed25519_request("web", &[], 5);
        let list = ed25519_revocation_list("intermediate", None, &[], &[], 1);
        let orphan = ed25519_revocation_list("elsewhere", None, &[], &[], 1);
        let text = [
            pem::encode("NEW CERTIFICATE REQUEST", &request),
            pem::encode("X509 CRL", &list),
            pem::encode("CERTIFICATE", &intermediate),
            pem::encode("X509 CRL", &orphan),
            pem::encode("CERTIFICATE", &root),
            pem::encode("CERTIFICATE REQUEST", b"unreadable"),
        ]
        .concat();
        let file = parse(text.as_bytes()).unwrap();
        assert!(!file.skipped);
        assert_eq!(
            aliases(&file),
            [
                "web",
                "intermediate",
                "intermediate",
                "elsewhere",
                "root",
                "Request 6"
            ]
        );
        let kinds: Vec<_> = file
            .entries
            .iter()
            .map(|entry| (entry.kind, entry.document))
            .collect();
        assert_eq!(
            kinds,
            [
                (REQUEST_KIND, Some(Document::Request)),
                (REVOCATION_LIST_KIND, Some(Document::RevocationList)),
                (KIND, None),
                (REVOCATION_LIST_KIND, Some(Document::RevocationList)),
                (KIND, None),
                (REQUEST_KIND, Some(Document::Request)),
            ]
        );
        assert_eq!(file.entries[0].certificates, [request]);
        assert_eq!(
            file.entries[0].certificate.as_ref().unwrap().subject,
            "CN=web"
        );
        // A list is followed by its issuer's chain from the same file.
        assert_eq!(
            file.entries[1].certificates,
            [list, intermediate.clone(), root.clone()]
        );
        assert_eq!(file.entries[2].certificates, [intermediate, root]);
        assert_eq!(file.entries[3].certificates, [orphan]);
        assert!(file.entries[5].certificate.is_none());
    }

    #[test]
    fn reads_openssl_requests_and_revocation_lists() {
        use crate::{
            certificate::signature::{self, Signature},
            test_support::{OPENSSL_CA_CRL, OPENSSL_REQUEST},
        };
        let file = parse(OPENSSL_REQUEST).unwrap();
        let entry = &file.entries[0];
        assert_eq!(
            (entry.alias.as_str(), entry.kind),
            ("keystore-tui test request", REQUEST_KIND)
        );
        let summary = entry.certificate.as_ref().unwrap();
        assert_eq!(
            (summary.algorithm.as_str(), summary.key_size),
            ("RSA", Some(2048))
        );
        let request = Request::parse(&entry.certificates[0]).unwrap();
        assert_eq!(request.signature_algorithm, "SHA-256 with RSA");
        assert_eq!(request.extensions[0].lines, ["DNS: request.example.test"]);
        assert_eq!(
            signature::verify_request(&entry.certificates[0]),
            Signature::Verified
        );

        let file = parse(OPENSSL_CA_CRL).unwrap();
        assert_eq!(
            aliases(&file),
            ["keystore-tui test CA", "keystore-tui test CA"]
        );
        let list_entry = &file.entries[1];
        assert_eq!(list_entry.kind, REVOCATION_LIST_KIND);
        assert_eq!(list_entry.certificates[1], file.entries[0].certificates[0]);
        assert_eq!(
            signature::verify_revocation_list(
                &list_entry.certificates[0],
                &list_entry.certificates[1]
            ),
            Signature::Verified
        );
        let list = RevocationList::parse(&list_entry.certificates[0]).unwrap();
        assert_eq!(list.version, 2);
        assert_eq!(list.signature_algorithm, "SHA-256 with ECDSA");
        assert_eq!(list.extensions[0].title(), "CRL Number (2.5.29.20)");
        assert_eq!(list.extensions[0].lines, ["4096"]);
        assert_eq!(list.revoked.len(), 1);
        assert_eq!(list.revoked[0].serial_hex, "0x0A");
        assert_eq!(list.revoked[0].extensions[0].lines, ["Key Compromise"]);
    }

    #[test]
    fn reads_der_requests_lists_and_pkcs7_lists() {
        let request = ed25519_request("web", &[], 5);
        let list = ed25519_revocation_list("root", None, &[], &[], 1);
        assert_eq!(parse(&request).unwrap().entries[0].kind, REQUEST_KIND);
        assert_eq!(parse(&list).unwrap().entries[0].kind, REVOCATION_LIST_KIND);
        let root = metadata_certificate("root", "root", &[1], &[]);
        let bundle =
            signed_data_with_lists(std::slice::from_ref(&root), std::slice::from_ref(&list));
        let file = parse(&bundle).unwrap();
        assert_eq!(aliases(&file), ["root", "root"]);
        assert_eq!(file.entries[1].certificates, [list, root]);
        assert!(parse(&signed_data_with_lists(&[], &[])).is_err());
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
