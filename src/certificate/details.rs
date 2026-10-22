//! Display-only certificate metadata. Public keys and signatures are never verified here.
use crown::{
    asn1::{Asn1Time, Reader, der, oid::ObjectIdentifier},
    error::{CryptoError, CryptoResult},
    x509::{algorithm::AlgorithmIdentifier, name::Name},
};

use super::extensions::{self, Extension, OID_AUTHORITY_KEY_ID, OID_SUBJECT_KEY_ID};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Details {
    pub version: i64,
    pub subject: Name,
    pub issuer: Name,
    pub serial_hex: String,
    pub serial_decimal: String,
    pub not_before: Asn1Time,
    pub not_after: Asn1Time,
    pub signature_algorithm: String,
    /// In certificate order; empty when the certificate has none.
    pub extensions: Vec<Extension>,
    subject_key_id: Option<Vec<u8>>,
    authority_key_id: Option<Vec<u8>>,
    authority_serial: Option<Vec<u8>>,
    authority_issuers: Vec<Name>,
}

impl Details {
    pub fn parse(encoding: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(encoding);
        let mut certificate = reader.read_sequence()?;
        reader.expect_end()?;
        let mut tbs = certificate.read_sequence()?;
        let version = if tbs.peek_tag()? == der::Tag::context_constructed(0) {
            tbs.read_explicit(0)?
                .read_integer_i64()?
                .checked_add(1)
                .ok_or(CryptoError::StrError("invalid certificate version"))?
        } else {
            1
        };
        let serial = tbs.read_expected(der::INTEGER)?.to_vec();
        if serial.is_empty() {
            return Err(CryptoError::StrError("empty certificate serial"));
        }
        AlgorithmIdentifier::parse(&mut tbs)?;
        let issuer = Name::parse(&mut tbs)?;
        let mut validity = tbs.read_sequence()?;
        let not_before = validity.read_time()?;
        let not_after = validity.read_time()?;
        validity.expect_end()?;
        let subject = Name::parse(&mut tbs)?;
        tbs.read_sequence()?; // SPKI: summarize() tolerates algorithms crown cannot decode.
        let mut details = Self {
            version,
            subject,
            issuer,
            serial_hex: serial_text(&serial, true),
            serial_decimal: serial_text(&serial, false),
            not_before,
            not_after,
            signature_algorithm: signature_name(&AlgorithmIdentifier::parse(&mut certificate)?.oid),
            extensions: Vec::new(),
            subject_key_id: None,
            authority_key_id: None,
            authority_serial: None,
            authority_issuers: Vec::new(),
        };
        certificate.read_bit_string()?;
        certificate.expect_end()?;
        while !tbs.is_empty() {
            if tbs.peek_tag()? == der::Tag::context_constructed(3) {
                let mut explicit = tbs.read_explicit(3)?;
                let mut extensions = explicit.read_sequence()?;
                while !extensions.is_empty() {
                    // A malformed extension is described, not fatal to the other details.
                    let extension = Extension::parse(extensions.read_raw_tlv()?);
                    // Optional linking hints must not make otherwise readable details disappear.
                    if let Some(id) = &extension.oid {
                        if id.matches(OID_SUBJECT_KEY_ID) {
                            details.subject_key_id = Reader::new(&extension.value)
                                .read_octet_string()
                                .ok()
                                .map(Vec::from);
                        } else if id.matches(OID_AUTHORITY_KEY_ID) {
                            let _ = details.read_authority(&extension.value);
                        }
                    }
                    details.extensions.push(extension);
                }
            } else {
                tbs.read_raw_tlv()?; // Optional issuer/subject unique identifiers.
            }
        }
        Ok(details)
    }

    fn read_authority(&mut self, value: &[u8]) -> CryptoResult<()> {
        let mut sequence = Reader::new(value).read_sequence()?;
        while !sequence.is_empty() {
            let (tag, value) = sequence.read_tlv()?;
            if tag == der::Tag::context(0) {
                self.authority_key_id = Some(value.to_vec());
            } else if tag == der::Tag::context(2) {
                self.authority_serial = Some(value.to_vec());
            } else if tag == der::Tag::context_constructed(1) {
                let mut names = Reader::new(value);
                while !names.is_empty() {
                    if names.peek_tag()? == der::Tag::context_constructed(4) {
                        self.authority_issuers
                            .push(Name::parse(&mut names.read_explicit(4)?)?);
                    } else {
                        names.read_raw_tlv()?;
                    }
                }
            }
        }
        Ok(())
    }
}

pub fn time_text(time: &Asn1Time) -> String {
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        time.year, time.month, time.day, time.hour, time.minute, time.second
    )
}

pub fn fingerprint(encoding: &[u8], sha1: bool) -> String {
    if sha1 {
        extensions::hex(&crown::hash::sha1::sum(encoding))
    } else {
        extensions::hex(&crown::hash::sha256::sum256(encoding))
    }
}

/// INTEGER content is signed two's complement and is not limited to machine integers.
pub(super) fn serial_text(bytes: &[u8], hex: bool) -> String {
    let negative = bytes.first().is_some_and(|byte| byte & 0x80 != 0);
    let mut magnitude = bytes.to_vec();
    if negative {
        let mut carry = 1u16;
        for byte in magnitude.iter_mut().rev() {
            let value = u16::from(!*byte) + carry;
            *byte = value as u8;
            carry = value >> 8;
        }
    }
    let first = magnitude
        .iter()
        .position(|&byte| byte != 0)
        .unwrap_or(magnitude.len().saturating_sub(1));
    let magnitude = &magnitude[first..];
    let sign = if negative { "-" } else { "" };
    if hex {
        return format!(
            "{sign}0x{}",
            magnitude
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<String>()
        );
    }
    let mut digits = vec![0u16]; // Little-endian decimal digits.
    for &byte in magnitude {
        let mut carry = u16::from(byte);
        for digit in &mut digits {
            let value = *digit * 256 + carry;
            *digit = value % 10;
            carry = value / 10;
        }
        while carry != 0 {
            digits.push(carry % 10);
            carry /= 10;
        }
    }
    format!(
        "{sign}{}",
        digits
            .iter()
            .rev()
            .map(|digit| char::from(b'0' + *digit as u8))
            .collect::<String>()
    )
}

pub(super) fn signature_name(id: &ObjectIdentifier) -> String {
    let names: &[(&[u64], &str)] = &[
        (&[1, 2, 840, 113549, 1, 1, 2], "MD2 with RSA"),
        (&[1, 2, 840, 113549, 1, 1, 4], "MD5 with RSA"),
        (&[1, 2, 840, 113549, 1, 1, 5], "SHA-1 with RSA"),
        (&[1, 3, 14, 3, 2, 29], "SHA-1 with RSA"),
        (&[1, 2, 840, 113549, 1, 1, 11], "SHA-256 with RSA"),
        (&[1, 2, 840, 113549, 1, 1, 12], "SHA-384 with RSA"),
        (&[1, 2, 840, 113549, 1, 1, 13], "SHA-512 with RSA"),
        (&[1, 2, 840, 113549, 1, 1, 10], "RSASSA-PSS"),
        (&[1, 2, 840, 10045, 4, 1], "SHA-1 with ECDSA"),
        (&[1, 2, 840, 10045, 4, 3, 2], "SHA-256 with ECDSA"),
        (&[1, 2, 840, 10045, 4, 3, 3], "SHA-384 with ECDSA"),
        (&[1, 2, 840, 10045, 4, 3, 4], "SHA-512 with ECDSA"),
        (&[1, 2, 840, 10040, 4, 3], "SHA-1 with DSA"),
        (&[2, 16, 840, 1, 101, 3, 4, 3, 2], "SHA-256 with DSA"),
        (&[1, 3, 101, 112], "Ed25519"),
        (&[1, 3, 101, 113], "Ed448"),
        (&[2, 16, 840, 1, 101, 3, 4, 3, 17], "ML-DSA-44"),
        (&[2, 16, 840, 1, 101, 3, 4, 3, 18], "ML-DSA-65"),
        (&[2, 16, 840, 1, 101, 3, 4, 3, 19], "ML-DSA-87"),
    ];
    names
        .iter()
        .find_map(|(oid, name)| id.matches(oid).then(|| name.to_string()))
        .unwrap_or_else(|| id.to_dotted_string())
}

/// Build a descriptive, leaf-first chain, never guessing between issuer candidates.
pub fn chain(leaf: &[u8], pool: &[&[u8]]) -> (Vec<Vec<u8>>, Option<&'static str>) {
    let mut chain = vec![leaf.to_vec()];
    let metadata: Vec<_> = pool.iter().map(|der| Details::parse(der).ok()).collect();
    loop {
        let Some(current) = chain.last().and_then(|der| Details::parse(der).ok()) else {
            return (
                chain,
                Some("Certificate could not be decoded; issuer is unavailable."),
            );
        };
        if current.subject == current.issuer {
            return (chain, None);
        }
        let mut candidates: Vec<&[u8]> = Vec::new();
        for (der, info) in pool.iter().zip(&metadata) {
            let Some(info) = info else {
                continue;
            };
            if info.subject != current.issuer {
                continue;
            }
            if let (Some(authority), Some(subject)) =
                (&current.authority_key_id, &info.subject_key_id)
                && authority != subject
            {
                continue;
            }
            if let Some(serial) = &current.authority_serial
                && serial_text(serial, true) != info.serial_hex
            {
                continue;
            }
            if !current.authority_issuers.is_empty()
                && !current.authority_issuers.contains(&info.issuer)
            {
                continue;
            }
            if !candidates.contains(der) {
                candidates.push(der);
            }
        }
        if candidates.len() > 1 {
            return (chain, Some("Issuer could not be determined uniquely."));
        }
        let Some(issuer) = candidates.first() else {
            return (
                chain,
                Some("Issuer certificate is not stored or could not be decoded."),
            );
        };
        if chain.iter().any(|der| der.as_slice() == *issuer) {
            return (chain, Some("Certificate chain contains a cycle."));
        }
        chain.push(issuer.to_vec());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{fixture_certificate_der, metadata_certificate};

    fn extension(oid: &[u64], value: &[u8]) -> Vec<u8> {
        der::sequence(
            &[
                der::oid(&ObjectIdentifier::new(oid).unwrap()),
                der::octet_string(value),
            ]
            .concat(),
        )
    }

    #[test]
    fn reads_all_metadata_and_utc_dates() {
        let info = Details::parse(fixture_certificate_der()).unwrap();
        assert_eq!(info.version, 3);
        assert!(!info.subject.to_string().is_empty());
        assert_eq!(info.subject, info.issuer);
        assert_eq!(time_text(&info.not_after), "2036-10-09 19:48:29 UTC");
        assert_eq!(info.signature_algorithm, "SHA-384 with ECDSA");
        assert!(info.serial_hex.starts_with("0x"));
        assert!(info.serial_decimal.chars().all(|ch| ch.is_ascii_digit()));
    }

    #[test]
    fn lists_extensions_and_survives_undecodable_ones() {
        let fixture = Details::parse(fixture_certificate_der()).unwrap();
        assert_eq!(fixture.extensions.len(), 1);
        assert_eq!(
            fixture.extensions[0].title(),
            "Subject Key Identifier (2.5.29.14)"
        );
        let none = Details::parse(&metadata_certificate("leaf", "issuer", &[1], &[])).unwrap();
        assert!(none.extensions.is_empty());

        let ski = extension(&[2, 5, 29, 14], &der::octet_string(&[7]));
        let broken_key_usage = extension(&[2, 5, 29, 15], &[0xff]);
        let malformed = der::sequence(&der::null());
        let unknown = extension(&[1, 2, 3], &[0xab]);
        let info = Details::parse(&metadata_certificate(
            "leaf",
            "issuer",
            &[1],
            &[ski, broken_key_usage, malformed, unknown],
        ))
        .unwrap();
        let shown: Vec<_> = info
            .extensions
            .iter()
            .map(|extension| (extension.title(), extension.lines.join("|")))
            .collect();
        assert_eq!(
            shown,
            [
                ("Subject Key Identifier (2.5.29.14)".into(), "07".into()),
                (
                    "Key Usage (2.5.29.15)".into(),
                    "Could not decode; value: FF".into()
                ),
                (
                    "Malformed extension".into(),
                    "Could not decode; encoding: 30:02:05:00".into()
                ),
                ("1.2.3".into(), "Value: AB".into()),
            ]
        );
        assert_eq!(info.subject_key_id.as_deref(), Some(&[7][..]));
    }

    #[test]
    fn signed_serials_do_not_overflow_and_ignore_sign_padding() {
        for (serial, hex, decimal) in [
            (vec![0], "0x00", "0"),
            (vec![0, 0x80], "0x80", "128"),
            (vec![0, 0, 1], "0x01", "1"),
            (vec![0xff], "-0x01", "-1"),
            (vec![0x80], "-0x80", "-128"),
            (vec![0xff, 0], "-0x0100", "-256"),
            (
                vec![1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                "0x0100000000000000000000000000000000",
                "340282366920938463463374607431768211456",
            ),
        ] {
            let info =
                Details::parse(&metadata_certificate("leaf", "issuer", &serial, &[])).unwrap();
            assert_eq!(info.serial_hex, hex);
            assert_eq!(info.serial_decimal, decimal);
        }
    }

    #[test]
    fn fingerprints_hash_original_bytes() {
        assert_eq!(
            fingerprint(b"abc", false),
            "BA:78:16:BF:8F:01:CF:EA:41:41:40:DE:5D:AE:22:23:B0:03:61:A3:96:17:7A:9C:B4:10:FF:61:F2:00:15:AD"
        );
        assert_eq!(
            fingerprint(b"abc", true),
            "A9:99:3E:36:47:06:81:6A:BA:3E:25:71:78:50:C2:6C:9C:D0:D8:9D"
        );
    }

    #[test]
    fn unknown_signature_and_key_algorithms_still_show_metadata() {
        let unknown =
            der::algorithm_identifier(&ObjectIdentifier::new(&[1, 2, 3, 4]).unwrap(), None);
        let original = metadata_certificate("leaf", "issuer", &[0xff], &[]);
        let mut certificate = Reader::new(&original).read_sequence().unwrap();
        let mut tbs = certificate.read_sequence().unwrap();
        let mut fields = Vec::new();
        while !tbs.is_empty() {
            fields.push(tbs.read_raw_tlv().unwrap().to_vec());
        }
        fields[2] = unknown.clone();
        fields[6] = der::sequence(&[unknown.clone(), der::bit_string(0, &[0; 8])].concat());
        let encoding = der::sequence(
            &[
                der::sequence(&fields.concat()),
                unknown,
                der::bit_string(0, &[1]),
            ]
            .concat(),
        );
        let info = Details::parse(&encoding).unwrap();
        assert_eq!(info.signature_algorithm, "1.2.3.4");
        assert_eq!(info.serial_decimal, "-1");
        assert_eq!(
            crate::certificate::summarize(&encoding).unwrap().algorithm,
            "1.2.3.4"
        );
    }

    #[test]
    fn malformed_and_truncated_certificates_are_recoverable() {
        let encoding = fixture_certificate_der();
        for end in 0..encoding.len() {
            assert!(Details::parse(&encoding[..end]).is_err());
        }
        assert!(Details::parse(b"not a certificate").is_err());
    }

    #[test]
    fn links_available_chain_and_excludes_duplicates_and_unrelated_certificates() {
        let leaf = metadata_certificate("leaf", "intermediate", &[1], &[]);
        let intermediate = metadata_certificate("intermediate", "root", &[2], &[]);
        let root = metadata_certificate("root", "root", &[3], &[]);
        let unrelated = metadata_certificate("other", "other", &[4], &[]);
        let (certificates, warning) =
            chain(&leaf, &[&root, &unrelated, &intermediate, &root, &leaf]);
        assert_eq!(certificates, [leaf, intermediate, root]);
        assert_eq!(warning, None);
    }

    #[test]
    fn explains_missing_ambiguous_cyclic_and_unreadable_issuers() {
        let leaf = metadata_certificate("leaf", "issuer", &[1], &[]);
        let issuer = metadata_certificate("issuer", "issuer", &[2], &[]);
        let other_issuer = metadata_certificate("issuer", "issuer", &[3], &[]);
        assert!(chain(&leaf, &[]).1.unwrap().contains("not stored"));
        assert!(
            chain(&leaf, &[b"unreadable"])
                .1
                .unwrap()
                .contains("not stored")
        );
        assert!(
            chain(&leaf, &[&issuer, &other_issuer])
                .1
                .unwrap()
                .contains("uniquely")
        );
        let cyclic_issuer = metadata_certificate("issuer", "leaf", &[2], &[]);
        assert!(
            chain(&leaf, &[&leaf, &cyclic_issuer])
                .1
                .unwrap()
                .contains("cycle")
        );
        assert!(chain(b"unreadable", &[]).1.unwrap().contains("decoded"));
    }

    #[test]
    fn authority_key_and_serial_identifiers_disambiguate_issuers() {
        let ski = |id: u8| extension(&[2, 5, 29, 14], &der::octet_string(&[id]));
        let aki =
            der::sequence(&[der::implicit(0, false, &[7]), der::implicit(2, false, &[2])].concat());
        let leaf =
            metadata_certificate("leaf", "issuer", &[1], &[extension(&[2, 5, 29, 35], &aki)]);
        let issuer = metadata_certificate("issuer", "issuer", &[2], &[ski(7)]);
        let wrong_id = metadata_certificate("issuer", "issuer", &[2], &[ski(8)]);
        let wrong_serial = metadata_certificate("issuer", "issuer", &[3], &[ski(7)]);
        let (certificates, warning) = chain(&leaf, &[&wrong_id, &wrong_serial, &issuer]);
        assert_eq!(certificates, [leaf, issuer]);
        assert_eq!(warning, None);
    }
}
