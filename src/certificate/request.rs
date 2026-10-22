//! Display-only PKCS#10 certificate request fields. The self-signature is
//! checked separately, by `signature::verify_request`.
use crown::{
    asn1::{Reader, der, oid::ObjectIdentifier},
    error::{CryptoError, CryptoResult},
    x509::{algorithm::AlgorithmIdentifier, name::Name},
};

use super::{
    Summary,
    details::signature_name,
    extensions::{Extension, hex, printable},
    security,
};

const OID_CHALLENGE_PASSWORD: &[u64] = &[1, 2, 840, 113549, 1, 9, 7];
const OID_UNSTRUCTURED_NAME: &[u64] = &[1, 2, 840, 113549, 1, 9, 2];
const OID_EXTENSION_REQUEST: &[u64] = &[1, 2, 840, 113549, 1, 9, 14];
/// Microsoft's older form of the extension request, with the same value.
const OID_MS_EXTENSION_REQUEST: &[u64] = &[1, 3, 6, 1, 4, 1, 311, 2, 1, 14];

/// A request attribute other than requested extensions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    /// For example `Challenge Password (1.2.840.113549.1.9.7)`.
    pub title: String,
    pub lines: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub version: i64,
    pub subject: Name,
    pub algorithm: String,
    pub key_size: Option<u32>,
    pub signature_algorithm: String,
    signature_oid: ObjectIdentifier,
    /// In request order.
    pub attributes: Vec<Attribute>,
    /// The extensions requested for the certificate, in request order.
    pub extensions: Vec<Extension>,
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
        // Keys crown cannot decode are still described by OID.
        let (algorithm, key_size) = super::public_key(info.read_raw_tlv()?)
            .ok_or(CryptoError::StrError("invalid request public key"))?;
        let mut attributes = Vec::new();
        let mut extensions = Vec::new();
        // The attributes are required, but some tools leave them out when empty.
        if !info.is_empty() {
            let mut set = info.read_implicit_constructed(0)?;
            while !set.is_empty() {
                let mut attribute = set.read_sequence()?;
                let id = attribute.read_oid()?;
                let mut values = Vec::new();
                let mut set = attribute.read_set()?;
                attribute.expect_end()?;
                while !set.is_empty() {
                    values.push(set.read_raw_tlv()?);
                }
                if (id.matches(OID_EXTENSION_REQUEST) || id.matches(OID_MS_EXTENSION_REQUEST))
                    && let Ok(requested) = requested_extensions(&values)
                {
                    extensions.extend(requested);
                } else {
                    attributes.push(describe(&id, &values));
                }
            }
        }
        info.expect_end()?;
        let signature_oid = AlgorithmIdentifier::parse(&mut request)?.oid;
        request.read_bit_string()?;
        request.expect_end()?;
        Ok(Self {
            version,
            subject,
            algorithm,
            key_size,
            signature_algorithm: signature_name(&signature_oid),
            signature_oid,
            attributes,
            extensions,
        })
    }

    /// The entry-list fields. A request is signed with its own key, so only
    /// the key size can make it weak.
    pub fn summary(&self) -> Summary {
        Summary {
            subject: self.subject.to_string(),
            algorithm: self.algorithm.clone(),
            key_size: self.key_size,
            not_after: None,
            expiry_warning: false,
            weaknesses: security::weaknesses(
                &self.algorithm,
                self.key_size,
                &self.signature_oid,
                true,
            ),
        }
    }
}

/// The one value of an extension request: a SEQUENCE of extensions.
fn requested_extensions(values: &[&[u8]]) -> CryptoResult<Vec<Extension>> {
    let [value] = values else {
        return Err(CryptoError::StrError("invalid extension request"));
    };
    let mut reader = Reader::new(value);
    let mut sequence = reader.read_sequence()?;
    reader.expect_end()?;
    let mut extensions = Vec::new();
    while !sequence.is_empty() {
        extensions.push(Extension::parse(sequence.read_raw_tlv()?));
    }
    Ok(extensions)
}

fn describe(id: &ObjectIdentifier, values: &[&[u8]]) -> Attribute {
    let name = [
        (OID_CHALLENGE_PASSWORD, "Challenge Password"),
        (OID_UNSTRUCTURED_NAME, "Unstructured Name"),
        (OID_EXTENSION_REQUEST, "Extension Request"),
        (OID_MS_EXTENSION_REQUEST, "Extension Request"),
    ]
    .into_iter()
    .find_map(|(arcs, name)| id.matches(arcs).then_some(name));
    let lines = if id.matches(OID_CHALLENGE_PASSWORD) {
        // A shared secret for the CA, so it is never displayed.
        vec!["Present; not shown".into()]
    } else {
        values
            .iter()
            .map(|value| match text(value) {
                Some(text) if name.is_some() => text,
                _ if name.is_some() => format!("Could not decode; value: {}", hex(value)),
                _ => format!("Value: {}", hex(value)),
            })
            .collect()
    };
    Attribute {
        title: name.map_or_else(|| id.to_dotted_string(), |name| format!("{name} ({id})")),
        lines,
    }
}

/// A single string element, made safe for the terminal.
fn text(value: &[u8]) -> Option<String> {
    let mut reader = Reader::new(value);
    let (tag, content) = reader.read_tlv().ok()?;
    reader.expect_end().ok()?;
    der::decode_string(tag, content)
        .ok()
        .map(|text| printable(&text))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ed25519_request;

    fn attribute(arcs: &[u64], values: &[Vec<u8>]) -> Vec<u8> {
        der::sequence(
            &[
                der::oid(&ObjectIdentifier::new(arcs).unwrap()),
                der::set(&values.concat()),
            ]
            .concat(),
        )
    }

    #[test]
    fn reads_subject_key_attributes_and_requested_extensions() {
        let san = der::sequence(
            &[
                der::oid(&ObjectIdentifier::new(&[2, 5, 29, 17]).unwrap()),
                der::octet_string(&der::sequence(&der::implicit(2, false, b"example.test"))),
            ]
            .concat(),
        );
        let attributes = [
            attribute(OID_CHALLENGE_PASSWORD, &[der::utf8_string("synthetic")]),
            attribute(OID_UNSTRUCTURED_NAME, &[der::utf8_string("line\u{1b}[2J")]),
            attribute(OID_EXTENSION_REQUEST, &[der::sequence(&san)]),
            attribute(&[1, 2, 3], &[der::integer_i64(5)]),
        ];
        let request = Request::parse(&ed25519_request("web", &attributes, 7)).unwrap();
        assert_eq!(request.version, 1);
        assert_eq!(request.subject.to_string(), "CN=web");
        assert_eq!(
            (request.algorithm.as_str(), request.key_size),
            ("Ed25519", Some(255))
        );
        assert_eq!(request.signature_algorithm, "Ed25519");
        let shown: Vec<_> = request
            .attributes
            .iter()
            .map(|attribute| (attribute.title.as_str(), attribute.lines.join("|")))
            .collect();
        assert_eq!(
            shown,
            [
                (
                    "Challenge Password (1.2.840.113549.1.9.7)",
                    "Present; not shown".into()
                ),
                (
                    "Unstructured Name (1.2.840.113549.1.9.2)",
                    "line\\u{1b}[2J".into()
                ),
                ("1.2.3", "Value: 02:01:05".into()),
            ]
        );
        assert_eq!(request.extensions.len(), 1);
        assert_eq!(request.extensions[0].lines, ["DNS: example.test"]);
        let summary = request.summary();
        assert_eq!(summary.subject, "CN=web");
        assert_eq!(summary.not_after, None);
        assert!(summary.weaknesses.is_empty());
    }

    #[test]
    fn requests_without_attributes_and_malformed_requests() {
        let request = Request::parse(&ed25519_request("bare", &[], 7)).unwrap();
        assert!(request.attributes.is_empty() && request.extensions.is_empty());
        let encoding = ed25519_request("web", &[], 7);
        for end in 0..encoding.len() {
            assert!(Request::parse(&encoding[..end]).is_err());
        }
        assert!(Request::parse(crate::test_support::fixture_certificate_der()).is_err());
        let broken = attribute(OID_EXTENSION_REQUEST, &[der::null()]);
        let request = Request::parse(&ed25519_request("web", &[broken], 7)).unwrap();
        assert_eq!(
            request.attributes[0].lines,
            ["Could not decode; value: 05:00"]
        );
    }
}
