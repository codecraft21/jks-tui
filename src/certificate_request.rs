//! PKCS#10 certificate requests (CSRs), read for display only. A request has
//! no issuer or validity, and nothing in it is trusted.
use crown::{
    asn1::{Reader, der, oid::ObjectIdentifier},
    error::{CryptoError, CryptoResult},
    x509::{algorithm::AlgorithmIdentifier, name::Name},
};

use crate::certificate::{
    Summary,
    details::signature_name,
    extensions::{Extension, hex, printable},
    name_alias, public_key, security, subject_text,
};

pub const KIND: &str = "Certificate request";

const OID_EXTENSION_REQUEST: &[u64] = &[1, 2, 840, 113549, 1, 9, 14];
/// Microsoft's older attribute for requested extensions, with the same value.
const OID_MS_EXTENSION_REQUEST: &[u64] = &[1, 3, 6, 1, 4, 1, 311, 2, 1, 14];
const OID_CHALLENGE_PASSWORD: &[u64] = &[1, 2, 840, 113549, 1, 9, 7];
const OID_UNSTRUCTURED_NAME: &[u64] = &[1, 2, 840, 113549, 1, 9, 2];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub version: i64,
    pub subject: Name,
    pub signature_algorithm: String,
    /// The requested extensions, in request order.
    pub extensions: Vec<Extension>,
    /// Every other attribute, as a title and display lines.
    pub attributes: Vec<(String, Vec<String>)>,
}

impl Request {
    pub fn parse(encoding: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(encoding);
        let mut request = reader.read_sequence()?;
        reader.expect_end()?;
        let mut info = request.read_sequence()?;
        let version = info
            .read_integer_i64()?
            .checked_add(1)
            .ok_or(CryptoError::StrError("invalid request version"))?;
        let subject = Name::parse(&mut info)?;
        info.read_sequence()?; // SPKI: summarize() tolerates algorithms crown cannot decode.
        let mut parsed = Self {
            version,
            subject,
            signature_algorithm: String::new(),
            extensions: Vec::new(),
            attributes: Vec::new(),
        };
        // PKCS#10 requires the attribute set, but some tools omit it when empty.
        if !info.is_empty() {
            let mut attributes = info.read_implicit_constructed(0)?;
            while !attributes.is_empty() {
                parsed.add_attribute(attributes.read_raw_tlv()?);
            }
        }
        info.expect_end()?;
        parsed.signature_algorithm = signature_name(&AlgorithmIdentifier::parse(&mut request)?.oid);
        request.read_bit_string()?;
        request.expect_end()?;
        Ok(parsed)
    }

    /// A malformed attribute is described, not fatal to the other fields.
    fn add_attribute(&mut self, encoding: &[u8]) {
        let Ok((oid, values)) = attribute_fields(encoding) else {
            let oid = Reader::new(encoding)
                .read_sequence()
                .and_then(|mut attribute| attribute.read_oid());
            // A challenge password stays hidden even when it is malformed.
            self.attributes.push(match oid {
                Ok(oid) if oid.matches(OID_CHALLENGE_PASSWORD) => (
                    format!("Challenge Password ({oid})"),
                    vec!["Could not decode; value not shown.".into()],
                ),
                _ => (
                    "Malformed attribute".into(),
                    vec![format!("Could not decode; encoding: {}", hex(encoding))],
                ),
            });
            return;
        };
        if oid.matches(OID_EXTENSION_REQUEST) || oid.matches(OID_MS_EXTENSION_REQUEST) {
            for value in values {
                match extensions(value) {
                    Ok(extensions) => self.extensions.extend(extensions),
                    Err(_) => self.attributes.push((
                        format!("Extension Request ({oid})"),
                        vec![format!("Could not decode; value: {}", hex(value))],
                    )),
                }
            }
        } else if oid.matches(OID_CHALLENGE_PASSWORD) {
            // It is a secret shared with the CA, so it is never displayed.
            self.attributes.push((
                format!("Challenge Password ({oid})"),
                vec!["Present; not shown.".into()],
            ));
        } else if oid.matches(OID_UNSTRUCTURED_NAME) {
            let lines = values.iter().map(|value| string_or_hex(value)).collect();
            self.attributes
                .push((format!("Unstructured Name ({oid})"), lines));
        } else {
            let lines = values
                .iter()
                .map(|value| format!("Value: {}", hex(value)))
                .collect();
            self.attributes.push((oid.to_dotted_string(), lines));
        }
    }
}

/// An attribute's type and its values, each as its whole encoding.
fn attribute_fields(encoding: &[u8]) -> CryptoResult<(ObjectIdentifier, Vec<&[u8]>)> {
    let mut reader = Reader::new(encoding);
    let mut attribute = reader.read_sequence()?;
    reader.expect_end()?;
    let oid = attribute.read_oid()?;
    let mut set = attribute.read_set()?;
    attribute.expect_end()?;
    let mut values = Vec::new();
    while !set.is_empty() {
        values.push(set.read_raw_tlv()?);
    }
    Ok((oid, values))
}

/// The extensions in an extension request value.
fn extensions(value: &[u8]) -> CryptoResult<Vec<Extension>> {
    let mut reader = Reader::new(value);
    let mut sequence = reader.read_sequence()?;
    reader.expect_end()?;
    let mut extensions = Vec::new();
    while !sequence.is_empty() {
        extensions.push(Extension::parse(sequence.read_raw_tlv()?));
    }
    Ok(extensions)
}

fn string_or_hex(value: &[u8]) -> String {
    Reader::new(value)
        .read_tlv()
        .and_then(|(tag, content)| der::decode_string(tag, content))
        .map_or_else(
            |_| format!("Value: {}", hex(value)),
            |text| printable(&text),
        )
}

/// Reads only the fields the entry list shows. A request has no expiry, and
/// only its key size is checked: the hash it is signed with does not carry
/// into the certificate it asks for.
pub fn summarize(encoding: &[u8]) -> Option<Summary> {
    let mut info = Reader::new(encoding)
        .read_sequence()
        .ok()?
        .read_sequence()
        .ok()?;
    info.read_raw_tlv().ok()?; // Version.
    let subject = info.read_raw_tlv().ok()?;
    let (algorithm, key_size) = public_key(info.read_raw_tlv().ok()?)?;
    Some(Summary {
        subject: subject_text(subject),
        weaknesses: security::key_weakness(&algorithm, key_size)
            .into_iter()
            .collect(),
        algorithm,
        key_size,
        not_after: None,
    })
}

/// The subject common name, else the whole subject, if either is non-empty.
pub fn subject_name(encoding: &[u8]) -> Option<String> {
    Request::parse(encoding)
        .ok()
        .and_then(|request| name_alias(&request.subject))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        certificate::signature::{Signature, verify_request},
        test_support::{KEYTOOL_REQUEST, OPENSSL_REQUEST_DER, ed25519_request},
    };
    use crown::asn1::pem;

    fn attribute(oid: &[u64], values: &[Vec<u8>]) -> Vec<u8> {
        der::sequence(
            &[
                der::oid(&ObjectIdentifier::new(oid).unwrap()),
                der::set(&values.concat()),
            ]
            .concat(),
        )
    }

    fn keytool_request() -> Vec<u8> {
        let text = std::str::from_utf8(KEYTOOL_REQUEST).unwrap();
        pem::parse(text).unwrap().remove(0).data
    }

    #[test]
    fn reads_a_keytool_request() {
        let der = keytool_request();
        let request = Request::parse(&der).unwrap();
        assert_eq!(request.version, 1);
        assert_eq!(
            request.subject.to_string(),
            "O=keystore-tui,CN=CSR TUI test fixture"
        );
        assert_eq!(request.signature_algorithm, "SHA-384 with ECDSA");
        let titles: Vec<_> = request.extensions.iter().map(Extension::title).collect();
        assert_eq!(
            titles,
            [
                "Subject Key Identifier (2.5.29.14)",
                "Subject Alternative Name (2.5.29.17)",
                "Extended Key Usage (2.5.29.37)",
            ]
        );
        assert_eq!(
            request.extensions[1].lines,
            ["DNS: csr.example.test", "IP: 192.0.2.1"]
        );
        assert!(request.attributes.is_empty());
        assert_eq!(verify_request(&der), Signature::Verified);
        let summary = summarize(&der).unwrap();
        assert_eq!(
            (summary.algorithm.as_str(), summary.key_size),
            ("EC", Some(256))
        );
        assert_eq!(summary.expiry_text(), "-");
        assert!(!summary.is_expired(i64::MAX));
        assert!(summary.weaknesses.is_empty());
        assert_eq!(subject_name(&der).as_deref(), Some("CSR TUI test fixture"));
    }

    #[test]
    fn reads_an_openssl_request() {
        let request = Request::parse(OPENSSL_REQUEST_DER).unwrap();
        assert_eq!(request.signature_algorithm, "SHA-256 with RSA");
        assert_eq!(request.extensions[0].lines, ["DNS: openssl.example.test"]);
        assert_eq!(verify_request(OPENSSL_REQUEST_DER), Signature::Verified);
        let summary = summarize(OPENSSL_REQUEST_DER).unwrap();
        assert_eq!(
            (summary.algorithm.as_str(), summary.key_size),
            ("RSA", Some(2048))
        );
    }

    #[test]
    fn describes_attributes_without_showing_challenge_passwords() {
        let utf8 = der::utf8_string("device\u{1b}[31m");
        let der = ed25519_request(
            "device",
            &[
                attribute(OID_CHALLENGE_PASSWORD, &[der::utf8_string("synthetic")]),
                attribute(OID_UNSTRUCTURED_NAME, &[utf8]),
                attribute(&[1, 2, 3], &[der::null()]),
                attribute(OID_EXTENSION_REQUEST, &[der::null()]),
                der::sequence(&der::null()),
                // A value outside the SET, so the attribute is malformed.
                der::sequence(
                    &[
                        der::oid(&ObjectIdentifier::new(OID_CHALLENGE_PASSWORD).unwrap()),
                        der::utf8_string("synthetic"),
                    ]
                    .concat(),
                ),
            ],
        );
        let request = Request::parse(&der).unwrap();
        let shown = format!("{:?}", request.attributes);
        assert!(!shown.contains("synthetic"));
        assert_eq!(
            request.attributes,
            [
                (
                    "Challenge Password (1.2.840.113549.1.9.7)".into(),
                    vec!["Present; not shown.".into()]
                ),
                (
                    "Unstructured Name (1.2.840.113549.1.9.2)".into(),
                    vec!["device\\u{1b}[31m".into()]
                ),
                ("1.2.3".into(), vec!["Value: 05:00".into()]),
                (
                    "Extension Request (1.2.840.113549.1.9.14)".into(),
                    vec!["Could not decode; value: 05:00".into()]
                ),
                (
                    "Malformed attribute".into(),
                    vec!["Could not decode; encoding: 30:02:05:00".into()]
                ),
                (
                    "Challenge Password (1.2.840.113549.1.9.7)".into(),
                    vec!["Could not decode; value not shown.".into()]
                ),
            ]
        );
        assert!(request.extensions.is_empty());
        assert_eq!(verify_request(&der), Signature::Verified);
    }

    #[test]
    fn flags_short_keys_but_not_signature_hashes() {
        let mut modulus = vec![0x80];
        modulus.resize(128, 0);
        let rsa_key = der::sequence(&[der::integer(&modulus), der::integer(&[1, 0, 1])].concat());
        let spki = der::sequence(
            &[
                der::algorithm_identifier(
                    &ObjectIdentifier::new(&[1, 2, 840, 113549, 1, 1, 1]).unwrap(),
                    Some(&der::null()),
                ),
                der::bit_string(0, &rsa_key),
            ]
            .concat(),
        );
        let info = der::sequence(
            &[
                der::integer_i64(0),
                Name::from_common_name("weak").encode(),
                spki,
            ]
            .concat(),
        );
        let sha1_rsa = der::algorithm_identifier(
            &ObjectIdentifier::new(&[1, 2, 840, 113549, 1, 1, 5]).unwrap(),
            Some(&der::null()),
        );
        // Without the attribute set, as some tools write it.
        let der = der::sequence(&[info, sha1_rsa, der::bit_string(0, &[1])].concat());
        assert_eq!(
            Request::parse(&der).unwrap().signature_algorithm,
            "SHA-1 with RSA"
        );
        assert_eq!(
            summarize(&der).unwrap().weaknesses,
            [security::Weakness::ShortKey {
                algorithm: "RSA".into(),
                bits: 1024,
                minimum: 2048,
            }]
        );
    }

    #[test]
    fn altered_requests_fail_their_signature_check() {
        let der = ed25519_request("device", &[]);
        let at = der.windows(6).position(|w| w == b"device").unwrap();
        let mut altered = der.clone();
        altered[at] = b'D';
        assert_eq!(
            verify_request(&altered),
            Signature::Failed("the signature does not match")
        );
        assert_eq!(
            verify_request(b"junk"),
            Signature::Unchecked("the request could not be decoded")
        );
    }

    #[test]
    fn malformed_and_truncated_requests_are_rejected() {
        let der = keytool_request();
        for end in 0..der.len() {
            assert!(Request::parse(&der[..end]).is_err(), "prefix {end}");
        }
        let mut trailing = der.clone();
        trailing.push(0);
        assert!(Request::parse(&trailing).is_err());
        assert!(Request::parse(crate::test_support::fixture_certificate_der()).is_err());
    }
}
