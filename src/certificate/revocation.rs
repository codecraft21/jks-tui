//! Display-only X.509 revocation list fields. The signature is checked
//! separately, by `signature::verify_revocation_list`.
use crown::{
    asn1::{Asn1Time, Reader, der, oid::ObjectIdentifier},
    error::{CryptoError, CryptoResult},
    x509::{algorithm::AlgorithmIdentifier, name::Name},
};

use super::{
    Summary,
    details::{serial_text, signature_name},
    extensions::Extension,
    security,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokedCertificate {
    pub serial_hex: String,
    pub serial_decimal: String,
    pub revocation_date: Asn1Time,
    /// Entry extensions, such as the reason code, in list order.
    pub extensions: Vec<Extension>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationList {
    pub version: i64,
    pub issuer: Name,
    pub this_update: Asn1Time,
    pub next_update: Option<Asn1Time>,
    pub signature_algorithm: String,
    signature_oid: ObjectIdentifier,
    /// In list order.
    pub extensions: Vec<Extension>,
    /// In list order.
    pub revoked: Vec<RevokedCertificate>,
}

impl RevocationList {
    pub fn parse(encoding: &[u8]) -> CryptoResult<Self> {
        let mut reader = Reader::new(encoding);
        let mut list = reader.read_sequence()?;
        reader.expect_end()?;
        let mut tbs = list.read_sequence()?;
        let version = if tbs.peek_tag()? == der::INTEGER {
            tbs.read_integer_i64()?
                .checked_add(1)
                .ok_or(CryptoError::StrError("invalid revocation list version"))?
        } else {
            1
        };
        AlgorithmIdentifier::parse(&mut tbs)?;
        let issuer = Name::parse(&mut tbs)?;
        let this_update = tbs.read_time()?;
        let next_update = if !tbs.is_empty()
            && [der::UTC_TIME, der::GENERALIZED_TIME].contains(&tbs.peek_tag()?)
        {
            Some(tbs.read_time()?)
        } else {
            None
        };
        let mut revoked = Vec::new();
        if !tbs.is_empty() && tbs.peek_tag()? == der::SEQUENCE {
            let mut entries = tbs.read_sequence()?;
            while !entries.is_empty() {
                revoked.push(revoked_certificate(&mut entries.read_sequence()?)?);
            }
        }
        let mut extensions = Vec::new();
        if !tbs.is_empty() {
            let mut explicit = tbs.read_explicit(0)?;
            extensions = extension_list(&mut explicit)?;
            explicit.expect_end()?;
        }
        tbs.expect_end()?;
        let signature_oid = AlgorithmIdentifier::parse(&mut list)?.oid;
        list.read_bit_string()?;
        list.expect_end()?;
        Ok(Self {
            version,
            issuer,
            this_update,
            next_update,
            signature_algorithm: signature_name(&signature_oid),
            signature_oid,
            extensions,
            revoked,
        })
    }

    /// The entry-list fields: the issuer as the subject, and the next update
    /// as the expiry. Only the signature algorithm can make a list weak.
    pub fn summary(&self) -> Summary {
        Summary {
            subject: self.issuer.to_string(),
            algorithm: "-".into(),
            key_size: None,
            not_after: self.next_update,
            expiry_warning: false,
            weaknesses: security::weaknesses("-", None, &self.signature_oid, false),
        }
    }
}

fn revoked_certificate(entry: &mut Reader<'_>) -> CryptoResult<RevokedCertificate> {
    let serial = entry.read_expected(der::INTEGER)?;
    if serial.is_empty() {
        return Err(CryptoError::StrError("empty revoked serial"));
    }
    let revocation_date = entry.read_time()?;
    let extensions = if entry.is_empty() {
        Vec::new()
    } else {
        extension_list(entry)?
    };
    entry.expect_end()?;
    Ok(RevokedCertificate {
        serial_hex: serial_text(serial, true),
        serial_decimal: serial_text(serial, false),
        revocation_date,
        extensions,
    })
}

/// A SEQUENCE of extensions. A malformed extension is described, not fatal.
fn extension_list(reader: &mut Reader<'_>) -> CryptoResult<Vec<Extension>> {
    let mut sequence = reader.read_sequence()?;
    let mut extensions = Vec::new();
    while !sequence.is_empty() {
        extensions.push(Extension::parse(sequence.read_raw_tlv()?));
    }
    Ok(extensions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        certificate::{details::time_text, security::Weakness},
        test_support::{ed25519_revocation_list, revoked_certificate},
    };

    fn extension(arcs: &[u64], value: &[u8]) -> Vec<u8> {
        der::sequence(
            &[
                der::oid(&ObjectIdentifier::new(arcs).unwrap()),
                der::octet_string(value),
            ]
            .concat(),
        )
    }

    #[test]
    fn reads_fields_extensions_and_revoked_certificates() {
        let reason = extension(&[2, 5, 29, 21], &der::tlv(der::Tag::universal(10), &[1]));
        let number = extension(&[2, 5, 29, 20], &der::integer_i64(42));
        let encoding = ed25519_revocation_list(
            "ca",
            Some(1_900_000_000),
            &[
                revoked_certificate(&[0x0a], &[reason]),
                revoked_certificate(&[0xff], &[]),
            ],
            &[number],
            1,
        );
        let list = RevocationList::parse(&encoding).unwrap();
        assert_eq!(list.version, 2);
        assert_eq!(list.issuer.to_string(), "CN=ca");
        assert_eq!(time_text(&list.this_update), "2024-01-01 00:00:00 UTC");
        assert_eq!(list.next_update.unwrap().to_unix(), 1_900_000_000);
        assert_eq!(list.signature_algorithm, "Ed25519");
        assert_eq!(list.extensions[0].title(), "CRL Number (2.5.29.20)");
        assert_eq!(list.extensions[0].lines, ["42"]);
        let revoked: Vec<_> = list
            .revoked
            .iter()
            .map(|entry| (entry.serial_hex.as_str(), entry.serial_decimal.as_str()))
            .collect();
        assert_eq!(revoked, [("0x0A", "10"), ("-0x01", "-1")]);
        assert_eq!(list.revoked[0].extensions[0].lines, ["Key Compromise"]);
        assert!(list.revoked[1].extensions.is_empty());
        let summary = list.summary();
        assert_eq!(summary.subject, "CN=ca");
        assert_eq!(summary.not_after, list.next_update);
        assert!(!summary.expiry_warning);
        assert!(summary.weaknesses.is_empty());
    }

    #[test]
    fn optional_fields_may_be_absent() {
        let v2 = ed25519_revocation_list("ca", None, &[], &[], 1);
        let list = RevocationList::parse(&v2).unwrap();
        assert_eq!(list.next_update, None);
        assert!(list.revoked.is_empty() && list.extensions.is_empty());
        // Version 1 lists have no version field.
        let mut reader = Reader::new(&v2).read_sequence().unwrap();
        let mut tbs = reader.read_sequence().unwrap();
        tbs.read_raw_tlv().unwrap();
        let mut fields = Vec::new();
        while !tbs.is_empty() {
            fields.extend(tbs.read_raw_tlv().unwrap());
        }
        let rest = [
            reader.read_raw_tlv().unwrap(),
            reader.read_raw_tlv().unwrap(),
        ]
        .concat();
        let v1 = der::sequence(&[der::sequence(&fields), rest].concat());
        assert_eq!(RevocationList::parse(&v1).unwrap().version, 1);
    }

    #[test]
    fn weak_signatures_and_malformed_lists() {
        let encoding =
            ed25519_revocation_list("ca", None, &[revoked_certificate(&[1], &[])], &[], 1);
        for end in 0..encoding.len() {
            assert!(RevocationList::parse(&encoding[..end]).is_err());
        }
        assert!(RevocationList::parse(crate::test_support::fixture_certificate_der()).is_err());
        let sha1 = RevocationList {
            signature_oid: ObjectIdentifier::new(&[1, 2, 840, 113549, 1, 1, 5]).unwrap(),
            ..RevocationList::parse(&encoding).unwrap()
        };
        assert_eq!(
            sha1.summary().weaknesses,
            [Weakness::WeakSignature("SHA-1")]
        );
    }
}
