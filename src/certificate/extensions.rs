//! Display text for X.509 v3 extensions. Values are decoded for reading only;
//! nothing here affects trust, and undecodable values fall back to hex.
use std::net::{Ipv4Addr, Ipv6Addr};

use crown::{
    asn1::{
        Reader,
        der::{self, Tag},
        oid::ObjectIdentifier,
    },
    error::{CryptoError, CryptoResult},
    x509::name::Name,
};

use super::details::serial_text;

pub const OID_SUBJECT_KEY_ID: &[u64] = &[2, 5, 29, 14];
pub const OID_AUTHORITY_KEY_ID: &[u64] = &[2, 5, 29, 35];

type Decoder = fn(&[u8]) -> CryptoResult<Vec<String>>;

const KNOWN: &[(&[u64], &str, Decoder)] = &[
    (OID_SUBJECT_KEY_ID, "Subject Key Identifier", subject_key_id),
    (&[2, 5, 29, 15], "Key Usage", key_usage),
    (
        &[2, 5, 29, 17],
        "Subject Alternative Name",
        alternative_names,
    ),
    (
        &[2, 5, 29, 18],
        "Issuer Alternative Name",
        alternative_names,
    ),
    (&[2, 5, 29, 19], "Basic Constraints", basic_constraints),
    (
        &[2, 5, 29, 31],
        "CRL Distribution Points",
        crl_distribution_points,
    ),
    (
        &[2, 5, 29, 32],
        "Certificate Policies",
        certificate_policies,
    ),
    (
        OID_AUTHORITY_KEY_ID,
        "Authority Key Identifier",
        authority_key_id,
    ),
    (&[2, 5, 29, 37], "Extended Key Usage", extended_key_usage),
    (
        &[1, 3, 6, 1, 5, 5, 7, 1, 1],
        "Authority Information Access",
        authority_information_access,
    ),
];

const KEY_USAGES: [&str; 9] = [
    "Digital Signature",
    "Non Repudiation",
    "Key Encipherment",
    "Data Encipherment",
    "Key Agreement",
    "Certificate Sign",
    "CRL Sign",
    "Encipher Only",
    "Decipher Only",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    /// `None` when the extension's own structure could not be read.
    pub oid: Option<ObjectIdentifier>,
    pub critical: bool,
    /// The extension's OCTET STRING content (or its whole encoding when malformed).
    pub value: Vec<u8>,
    /// Display lines; a decoding failure yields a note and the value in hex.
    pub lines: Vec<String>,
}

impl Extension {
    /// Never fails: a malformed or unrecognized extension is described in hex.
    pub fn parse(encoding: &[u8]) -> Self {
        let Ok((oid, critical, value)) = fields(encoding) else {
            return Self {
                oid: None,
                critical: false,
                value: encoding.to_vec(),
                lines: vec![format!("Could not decode; encoding: {}", hex(encoding))],
            };
        };
        let lines = match KNOWN.iter().find(|(arcs, _, _)| oid.matches(arcs)) {
            Some((_, _, decode)) => match decode(value) {
                Ok(lines) if lines.is_empty() => vec!["None".into()],
                Ok(lines) => lines,
                Err(_) => vec![format!("Could not decode; value: {}", hex(value))],
            },
            None => vec![format!("Value: {}", hex(value))],
        };
        Self {
            oid: Some(oid),
            critical,
            value: value.to_vec(),
            lines,
        }
    }

    /// For example `Key Usage (2.5.29.15) [critical]`.
    pub fn title(&self) -> String {
        let mut title = match &self.oid {
            None => "Malformed extension".into(),
            Some(oid) => match KNOWN.iter().find(|(arcs, _, _)| oid.matches(arcs)) {
                Some((_, name, _)) => format!("{name} ({oid})"),
                None => oid.to_dotted_string(),
            },
        };
        if self.critical {
            title.push_str(" [critical]");
        }
        title
    }
}

fn fields(encoding: &[u8]) -> CryptoResult<(ObjectIdentifier, bool, &[u8])> {
    let mut extension = single_sequence(encoding)?;
    let oid = extension.read_oid()?;
    let critical = if extension.peek_tag()? == der::BOOLEAN {
        extension.read_boolean()?
    } else {
        false
    };
    let value = extension.read_octet_string()?;
    extension.expect_end()?;
    Ok((oid, critical, value))
}

/// Colon-separated uppercase hex, as used for fingerprints.
pub fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "(empty)".into();
    }
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn single_sequence(value: &[u8]) -> CryptoResult<Reader<'_>> {
    let mut reader = Reader::new(value);
    let sequence = reader.read_sequence()?;
    reader.expect_end()?;
    Ok(sequence)
}

fn invalid() -> CryptoError {
    CryptoError::StrError("invalid extension value")
}

/// Certificate strings could otherwise move the cursor or restyle the terminal.
pub(crate) fn printable(text: &str) -> String {
    text.chars()
        .map(|ch| {
            if ch.is_control() {
                ch.escape_unicode().to_string()
            } else {
                ch.to_string()
            }
        })
        .collect()
}

fn ia5(content: &[u8]) -> CryptoResult<String> {
    Ok(printable(&der::decode_string(der::IA5_STRING, content)?))
}

fn general_name(tag: Tag, content: &[u8]) -> CryptoResult<String> {
    Ok(if tag == Tag::context(1) {
        format!("Email: {}", ia5(content)?)
    } else if tag == Tag::context(2) {
        format!("DNS: {}", ia5(content)?)
    } else if tag == Tag::context(6) {
        format!("URI: {}", ia5(content)?)
    } else if tag == Tag::context(7) {
        let address = if let Ok(bytes) = <[u8; 4]>::try_from(content) {
            Ipv4Addr::from(bytes).to_string()
        } else if let Ok(bytes) = <[u8; 16]>::try_from(content) {
            Ipv6Addr::from(bytes).to_string()
        } else {
            hex(content)
        };
        format!("IP: {address}")
    } else if tag == Tag::context_constructed(4) {
        let mut reader = Reader::new(content);
        let name = Name::parse(&mut reader)?;
        reader.expect_end()?;
        format!("Directory name: {}", printable(&name.to_string()))
    } else if tag == Tag::context(8) {
        format!(
            "Registered ID: {}",
            ObjectIdentifier::from_der_content(content)?
        )
    } else {
        let label = match tag.number {
            0 => "Other name",
            3 => "X.400 address",
            5 => "EDI party name",
            _ => "Name",
        };
        format!("{label} [{}]: {}", tag.number, hex(content))
    })
}

fn general_names(content: &[u8]) -> CryptoResult<Vec<String>> {
    let mut names = Reader::new(content);
    let mut lines = Vec::new();
    while !names.is_empty() {
        let (tag, content) = names.read_tlv()?;
        lines.push(general_name(tag, content)?);
    }
    Ok(lines)
}

fn alternative_names(value: &[u8]) -> CryptoResult<Vec<String>> {
    let mut reader = Reader::new(value);
    let content = reader.read_expected(der::SEQUENCE)?;
    reader.expect_end()?;
    general_names(content)
}

fn subject_key_id(value: &[u8]) -> CryptoResult<Vec<String>> {
    let mut reader = Reader::new(value);
    let id = reader.read_octet_string()?;
    reader.expect_end()?;
    Ok(vec![hex(id)])
}

fn authority_key_id(value: &[u8]) -> CryptoResult<Vec<String>> {
    let mut sequence = single_sequence(value)?;
    let mut lines = Vec::new();
    while !sequence.is_empty() {
        let (tag, content) = sequence.read_tlv()?;
        if tag == Tag::context(0) {
            lines.push(format!("Key ID: {}", hex(content)));
        } else if tag == Tag::context_constructed(1) {
            lines.extend(
                general_names(content)?
                    .into_iter()
                    .map(|name| format!("Issuer: {name}")),
            );
        } else if tag == Tag::context(2) && !content.is_empty() {
            lines.push(format!("Serial: {}", serial_text(content, true)));
        } else {
            return Err(invalid());
        }
    }
    Ok(lines)
}

fn key_usage(value: &[u8]) -> CryptoResult<Vec<String>> {
    let mut reader = Reader::new(value);
    let (unused, bits) = reader.read_bit_string()?;
    reader.expect_end()?;
    let names: Vec<String> = (0..bits.len() * 8 - usize::from(unused))
        .filter(|bit| bits[bit / 8] & (0x80 >> (bit % 8)) != 0)
        .map(|bit| {
            KEY_USAGES
                .get(bit)
                .map_or_else(|| format!("Bit {bit}"), |name| (*name).into())
        })
        .collect();
    Ok(if names.is_empty() {
        Vec::new()
    } else {
        vec![names.join(", ")]
    })
}

fn extended_key_usage(value: &[u8]) -> CryptoResult<Vec<String>> {
    let mut sequence = single_sequence(value)?;
    let mut lines = Vec::new();
    while !sequence.is_empty() {
        let id = sequence.read_oid()?;
        lines.push(match id.arcs() {
            [1, 3, 6, 1, 5, 5, 7, 3, 1] => "serverAuth".into(),
            [1, 3, 6, 1, 5, 5, 7, 3, 2] => "clientAuth".into(),
            [1, 3, 6, 1, 5, 5, 7, 3, 3] => "codeSigning".into(),
            [1, 3, 6, 1, 5, 5, 7, 3, 4] => "emailProtection".into(),
            [1, 3, 6, 1, 5, 5, 7, 3, 8] => "timeStamping".into(),
            [1, 3, 6, 1, 5, 5, 7, 3, 9] => "OCSPSigning".into(),
            [2, 5, 29, 37, 0] => "anyExtendedKeyUsage".into(),
            _ => id.to_dotted_string(),
        });
    }
    Ok(lines)
}

fn basic_constraints(value: &[u8]) -> CryptoResult<Vec<String>> {
    let mut sequence = single_sequence(value)?;
    let ca = if !sequence.is_empty() && sequence.peek_tag()? == der::BOOLEAN {
        sequence.read_boolean()?
    } else {
        false
    };
    let path_length = if sequence.is_empty() {
        None
    } else {
        Some(sequence.read_integer_i64()?)
    };
    sequence.expect_end()?;
    let mut line = format!("CA: {ca}");
    match path_length {
        Some(length) if length < 0 => return Err(invalid()),
        Some(length) => line.push_str(&format!(", path length: {length}")),
        None if ca => line.push_str(", path length: unlimited"),
        None => {}
    }
    Ok(vec![line])
}

fn crl_distribution_points(value: &[u8]) -> CryptoResult<Vec<String>> {
    let mut points = single_sequence(value)?;
    let mut lines = Vec::new();
    while !points.is_empty() {
        let mut point = points.read_sequence()?;
        while !point.is_empty() {
            let (tag, content) = point.read_tlv()?;
            if tag == Tag::context_constructed(0) {
                let mut name = Reader::new(content);
                let (tag, content) = name.read_tlv()?;
                name.expect_end()?;
                if tag == Tag::context_constructed(0) {
                    lines.extend(general_names(content)?);
                } else if tag == Tag::context_constructed(1) {
                    lines.push(format!("Relative name: {}", hex(content)));
                } else {
                    return Err(invalid());
                }
            } else if tag == Tag::context(1) {
                lines.push(format!("Reasons: {}", hex(content)));
            } else if tag == Tag::context_constructed(2) {
                lines.extend(
                    general_names(content)?
                        .into_iter()
                        .map(|name| format!("CRL issuer: {name}")),
                );
            } else {
                return Err(invalid());
            }
        }
    }
    Ok(lines)
}

fn authority_information_access(value: &[u8]) -> CryptoResult<Vec<String>> {
    let mut descriptions = single_sequence(value)?;
    let mut lines = Vec::new();
    while !descriptions.is_empty() {
        let mut description = descriptions.read_sequence()?;
        let method = description.read_oid()?;
        let (tag, content) = description.read_tlv()?;
        description.expect_end()?;
        let method = match method.arcs() {
            [1, 3, 6, 1, 5, 5, 7, 48, 1] => "OCSP".into(),
            [1, 3, 6, 1, 5, 5, 7, 48, 2] => "CA Issuers".into(),
            _ => method.to_dotted_string(),
        };
        lines.push(format!("{method}: {}", general_name(tag, content)?));
    }
    Ok(lines)
}

fn certificate_policies(value: &[u8]) -> CryptoResult<Vec<String>> {
    let mut policies = single_sequence(value)?;
    let mut lines = Vec::new();
    while !policies.is_empty() {
        let mut policy = policies.read_sequence()?;
        let id = policy.read_oid()?;
        if !policy.is_empty() {
            policy.read_sequence()?; // Qualifiers (CPS pointers, user notices).
        }
        policy.expect_end()?;
        let name = match id.arcs() {
            [2, 5, 29, 32, 0] => Some("anyPolicy"),
            [2, 23, 140, 1, 1] => Some("Extended Validation"),
            [2, 23, 140, 1, 2, 1] => Some("Domain Validated"),
            [2, 23, 140, 1, 2, 2] => Some("Organization Validated"),
            [2, 23, 140, 1, 2, 3] => Some("Individual Validated"),
            _ => None,
        };
        lines.push(match name {
            Some(name) => format!("Policy: {id} ({name})"),
            None => format!("Policy: {id}"),
        });
    }
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extension(oid: &[u64], value: &[u8]) -> Vec<u8> {
        der::sequence(
            &[
                der::oid(&ObjectIdentifier::new(oid).unwrap()),
                der::octet_string(value),
            ]
            .concat(),
        )
    }

    fn oid(arcs: &[u64]) -> Vec<u8> {
        der::oid(&ObjectIdentifier::new(arcs).unwrap())
    }

    fn ia5(tag: u32, text: &str) -> Vec<u8> {
        der::implicit(tag, false, text.as_bytes())
    }

    /// Every strict prefix of a valid value must fall back to hex, not panic.
    fn assert_truncations_fail(decode: Decoder, value: &[u8]) {
        for end in 0..value.len() {
            assert!(decode(&value[..end]).is_err(), "prefix {end}");
        }
        assert!(decode(&[value, &[0]].concat()).is_err(), "trailing data");
    }

    #[test]
    fn critical_flag_and_title_use_known_names() {
        let value = der::sequence(&der::boolean(true));
        let critical = der::sequence(
            &[
                oid(&[2, 5, 29, 19]),
                der::boolean(true),
                der::octet_string(&value),
            ]
            .concat(),
        );
        let parsed = Extension::parse(&critical);
        assert!(parsed.critical);
        assert_eq!(parsed.title(), "Basic Constraints (2.5.29.19) [critical]");
        assert_eq!(parsed.lines, ["CA: true, path length: unlimited"]);
        let plain = Extension::parse(&extension(&[2, 5, 29, 19], &value));
        assert!(!plain.critical);
        assert_eq!(plain.title(), "Basic Constraints (2.5.29.19)");
    }

    #[test]
    fn unknown_extensions_show_oid_and_hex() {
        let parsed = Extension::parse(&extension(&[1, 2, 3, 4], &[0xde, 0xad]));
        assert_eq!(parsed.title(), "1.2.3.4");
        assert_eq!(parsed.lines, ["Value: DE:AD"]);
    }

    #[test]
    fn undecodable_values_show_note_and_hex() {
        let parsed = Extension::parse(&extension(&[2, 5, 29, 15], &[0x01, 0x02]));
        assert_eq!(parsed.title(), "Key Usage (2.5.29.15)");
        assert_eq!(parsed.lines, ["Could not decode; value: 01:02"]);
        let malformed = der::sequence(&der::octet_string(&[1]));
        let parsed = Extension::parse(&malformed);
        assert_eq!(parsed.oid, None);
        assert_eq!(parsed.title(), "Malformed extension");
        assert!(parsed.lines[0].starts_with("Could not decode; encoding: 30:"));
    }

    #[test]
    fn subject_alternative_names() {
        let directory = der::explicit(4, &Name::from_common_name("dir").encode());
        let value = der::sequence(
            &[
                ia5(2, "example.test"),
                der::implicit(7, false, &[192, 0, 2, 1]),
                der::implicit(
                    7,
                    false,
                    &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                ),
                der::implicit(7, false, &[1, 2, 3]),
                ia5(1, "user@example.test"),
                ia5(6, "https://example.test/"),
                directory,
                der::implicit(8, false, &oid(&[1, 2, 3])[2..]),
                der::implicit(0, true, &[0xaa]),
                ia5(2, "evil\x1b[2J"),
            ]
            .concat(),
        );
        assert_eq!(
            alternative_names(&value).unwrap(),
            [
                "DNS: example.test",
                "IP: 192.0.2.1",
                "IP: 2001:db8::1",
                "IP: 01:02:03",
                "Email: user@example.test",
                "URI: https://example.test/",
                "Directory name: CN=dir",
                "Registered ID: 1.2.3",
                "Other name [0]: AA",
                "DNS: evil\\u{1b}[2J",
            ]
        );
        assert_truncations_fail(alternative_names, &value);
        assert!(alternative_names(&der::sequence(&ia5(2, "é"))).is_err());
    }

    #[test]
    fn key_usage_names_set_bits() {
        // digitalSignature, keyCertSign, cRLSign, decipherOnly (bit 8).
        let value = der::bit_string(7, &[0x86, 0x80]);
        assert_eq!(
            key_usage(&value).unwrap(),
            ["Digital Signature, Certificate Sign, CRL Sign, Decipher Only"]
        );
        assert_eq!(
            key_usage(&der::bit_string(0, &[0, 0x40])).unwrap(),
            ["Bit 9"]
        );
        assert!(key_usage(&der::bit_string(0, &[])).unwrap().is_empty());
        assert_truncations_fail(key_usage, &value);
        assert!(key_usage(&[3, 2, 8, 0]).is_err()); // More than 7 unused bits.
    }

    #[test]
    fn extended_key_usage_names_well_known_purposes() {
        let value = der::sequence(
            &[1, 2, 3, 4, 8, 9]
                .into_iter()
                .map(|n| oid(&[1, 3, 6, 1, 5, 5, 7, 3, n]))
                .chain([oid(&[1, 2, 3, 4])])
                .collect::<Vec<_>>()
                .concat(),
        );
        assert_eq!(
            extended_key_usage(&value).unwrap(),
            [
                "serverAuth",
                "clientAuth",
                "codeSigning",
                "emailProtection",
                "timeStamping",
                "OCSPSigning",
                "1.2.3.4",
            ]
        );
        assert_truncations_fail(extended_key_usage, &value);
        assert!(extended_key_usage(&der::sequence(&der::null())).is_err());
    }

    #[test]
    fn basic_constraints_ca_and_path_length() {
        let ca = der::sequence(&[der::boolean(true), der::integer_i64(2)].concat());
        assert_eq!(
            basic_constraints(&ca).unwrap(),
            ["CA: true, path length: 2"]
        );
        assert_eq!(
            basic_constraints(&der::sequence(&[])).unwrap(),
            ["CA: false"]
        );
        assert_truncations_fail(basic_constraints, &ca);
        let negative = der::sequence(&[der::boolean(true), der::integer_i64(-1)].concat());
        assert!(basic_constraints(&negative).is_err());
    }

    #[test]
    fn key_identifiers() {
        let ski = der::octet_string(&[0x76, 0x3e]);
        assert_eq!(subject_key_id(&ski).unwrap(), ["76:3E"]);
        assert_truncations_fail(subject_key_id, &ski);

        let issuer = der::explicit(4, &Name::from_common_name("ca").encode());
        let aki = der::sequence(
            &[
                der::implicit(0, false, &[7, 8]),
                der::implicit(1, true, &issuer),
                der::implicit(2, false, &[0x01, 0x00]),
            ]
            .concat(),
        );
        assert_eq!(
            authority_key_id(&aki).unwrap(),
            [
                "Key ID: 07:08",
                "Issuer: Directory name: CN=ca",
                "Serial: 0x0100"
            ]
        );
        assert_truncations_fail(authority_key_id, &aki);
        assert!(authority_key_id(&der::sequence(&der::implicit(2, false, &[]))).is_err());
        assert!(authority_key_id(&der::sequence(&der::null())).is_err());
    }

    #[test]
    fn crl_distribution_point_uris() {
        let full_name = der::implicit(0, true, &ia5(6, "http://crl.example.test/ca.crl"));
        let value = der::sequence(
            &[
                der::sequence(&der::explicit(0, &full_name)),
                der::sequence(
                    &[
                        der::explicit(0, &der::implicit(1, true, &[0xaa])),
                        der::implicit(1, false, &[0x06, 0x40]),
                        der::implicit(2, true, &ia5(2, "issuer.test")),
                    ]
                    .concat(),
                ),
            ]
            .concat(),
        );
        assert_eq!(
            crl_distribution_points(&value).unwrap(),
            [
                "URI: http://crl.example.test/ca.crl",
                "Relative name: AA",
                "Reasons: 06:40",
                "CRL issuer: DNS: issuer.test",
            ]
        );
        assert_truncations_fail(crl_distribution_points, &value);
    }

    #[test]
    fn authority_information_access_methods() {
        let description = |method: u64, uri: &str| {
            der::sequence(&[oid(&[1, 3, 6, 1, 5, 5, 7, 48, method]), ia5(6, uri)].concat())
        };
        let value = der::sequence(
            &[
                description(1, "http://ocsp.example.test"),
                description(2, "http://ca.example.test/ca.cer"),
                description(5, "http://other.example.test"),
            ]
            .concat(),
        );
        assert_eq!(
            authority_information_access(&value).unwrap(),
            [
                "OCSP: URI: http://ocsp.example.test",
                "CA Issuers: URI: http://ca.example.test/ca.cer",
                "1.3.6.1.5.5.7.48.5: URI: http://other.example.test",
            ]
        );
        assert_truncations_fail(authority_information_access, &value);
    }

    #[test]
    fn certificate_policy_identifiers() {
        let qualifiers = der::sequence(&der::sequence(&oid(&[1, 3, 6, 1, 5, 5, 7, 2, 1])));
        let value = der::sequence(
            &[
                der::sequence(&[oid(&[2, 23, 140, 1, 2, 1]), qualifiers].concat()),
                der::sequence(&oid(&[1, 2, 3, 4])),
            ]
            .concat(),
        );
        assert_eq!(
            certificate_policies(&value).unwrap(),
            [
                "Policy: 2.23.140.1.2.1 (Domain Validated)",
                "Policy: 1.2.3.4"
            ]
        );
        assert_truncations_fail(certificate_policies, &value);
    }
}
