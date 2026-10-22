pub mod details;
pub mod extensions;
pub mod request;
pub mod revocation;
pub mod security;
pub mod signature;

use crown::{
    asn1::{Asn1Time, Reader, der::Class, oid},
    x509::name::Name,
};

/// The subject, public key and expiry of an X.509 certificate, or the
/// equivalent fields of a request or revocation list, for display only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    /// The subject distinguished name (a revocation list's issuer), or empty
    /// when it cannot be decoded.
    pub subject: String,
    /// `-` when there is no public key.
    pub algorithm: String,
    /// `None` when the size is unknown or not meaningful for the algorithm.
    pub key_size: Option<u32>,
    /// A revocation list's next update; `None` for a request.
    pub not_after: Option<Asn1Time>,
    /// Whether an approaching `not_after` is highlighted. Revocation lists are
    /// reissued shortly before their next update, so only staleness is shown.
    pub expiry_warning: bool,
    /// Weak key or signature choices, in that order; empty when none are found.
    pub weaknesses: Vec<security::Weakness>,
}

impl Summary {
    pub fn key_size_text(&self) -> String {
        self.key_size
            .map_or_else(|| "-".into(), |bits| format!("{bits} bits"))
    }

    pub fn expiry_text(&self) -> String {
        self.not_after.map_or_else(
            || "-".into(),
            |time| format!("{:04}-{:02}-{:02}", time.year, time.month, time.day),
        )
    }

    pub fn is_expired(&self, now: i64) -> bool {
        self.not_after.is_some_and(|time| time.to_unix() < now)
    }
}

const OID_RSASSA_PSS: &[u64] = &[1, 2, 840, 113549, 1, 1, 10];
const OID_SECP224R1: &[u64] = &[1, 3, 132, 0, 33];
const OID_ML_DSA_44: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 17];
const OID_ML_DSA_65: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 18];
const OID_ML_DSA_87: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 19];

/// Reads only the fields the entry list shows. Returns `None` for anything
/// that is not a well-formed certificate, so unusual certificates still list.
pub fn summarize(der: &[u8]) -> Option<Summary> {
    let mut reader = Reader::new(der);
    let mut tbs = reader.read_sequence().ok()?.read_sequence().ok()?;
    let tag = tbs.peek_tag().ok()?;
    if tag.class == Class::ContextSpecific && tag.number == 0 {
        tbs.read_raw_tlv().ok()?; // Version.
    }
    tbs.read_raw_tlv().ok()?; // Serial number, possibly negative.
    let signature = tbs.read_sequence().ok()?.read_oid().ok()?;
    let issuer = tbs.read_raw_tlv().ok()?;
    let mut validity = tbs.read_sequence().ok()?;
    validity.read_time().ok()?;
    let not_after = validity.read_time().ok()?;
    let subject = tbs.read_raw_tlv().ok()?;
    let (name, key_size) = public_key(tbs.read_raw_tlv().ok()?)?;
    let weaknesses = security::weaknesses(&name, key_size, &signature, issuer == subject);
    Some(Summary {
        // Unusual names must not hide the entry, so decode failures leave it empty.
        subject: Name::parse(&mut Reader::new(subject))
            .map(|name| name.to_string())
            .unwrap_or_default(),
        algorithm: name,
        key_size,
        not_after: Some(not_after),
        expiry_warning: true,
        weaknesses,
    })
}

/// The algorithm name and key size of a SubjectPublicKeyInfo. An algorithm
/// crown cannot decode is named by its OID.
pub fn public_key(spki: &[u8]) -> Option<(String, Option<u32>)> {
    let mut spki = Reader::new(spki).read_sequence().ok()?;
    let mut algorithm = spki.read_sequence().ok()?;
    let id = algorithm.read_oid().ok()?;
    let key = spki.read_bit_string_bytes().ok()?;
    Some(
        if id.matches(oid::OID_RSA_ENCRYPTION) || id.matches(OID_RSASSA_PSS) {
            let name = if id.matches(OID_RSASSA_PSS) {
                "RSASSA-PSS"
            } else {
                "RSA"
            };
            let modulus = Reader::new(key)
                .read_sequence()
                .and_then(|mut key| key.read_integer())
                .ok();
            (name.into(), modulus.and_then(bit_length))
        } else if id.matches(oid::OID_EC_PUBLIC_KEY) {
            let curve = algorithm.read_oid().ok();
            let size = curve.and_then(|curve| {
                [
                    (oid::OID_SECP256R1, 256),
                    (oid::OID_SECP384R1, 384),
                    (oid::OID_SECP521R1, 521),
                    (oid::OID_SECP256K1, 256),
                    (OID_SECP224R1, 224),
                ]
                .into_iter()
                .find_map(|(arcs, size)| curve.matches(arcs).then_some(size))
            });
            ("EC".into(), size)
        } else if id.matches(oid::OID_DSA) {
            let prime = algorithm
                .read_sequence()
                .and_then(|mut parameters| parameters.read_integer())
                .ok();
            ("DSA".into(), prime.and_then(bit_length))
        } else {
            [
                (oid::OID_ED25519, "Ed25519", Some(255)),
                (oid::OID_ED448, "Ed448", Some(448)),
                (oid::OID_X25519, "X25519", Some(255)),
                (oid::OID_X448, "X448", Some(448)),
                (OID_ML_DSA_44, "ML-DSA-44", None),
                (OID_ML_DSA_65, "ML-DSA-65", None),
                (OID_ML_DSA_87, "ML-DSA-87", None),
            ]
            .into_iter()
            .find(|(arcs, _, _)| id.matches(arcs))
            .map_or_else(
                || (id.to_dotted_string(), None),
                |(_, name, size)| (name.into(), size),
            )
        },
    )
}

fn bit_length(magnitude: &[u8]) -> Option<u32> {
    let first = magnitude.first()?;
    Some((magnitude.len() as u32 - 1) * 8 + (8 - first.leading_zeros()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crown::asn1::{der, oid::ObjectIdentifier};

    fn certificate(algorithm: Vec<u8>, key: &[u8], not_after: &Asn1Time) -> Vec<u8> {
        let not_before = Asn1Time::new(2020, 1, 1, 0, 0, 0, true).unwrap();
        let name = der::sequence(&[]);
        let signature = der::sequence(&der::oid(
            &ObjectIdentifier::new(oid::OID_ECDSA_WITH_SHA256).unwrap(),
        ));
        let tbs = [
            der::explicit(0, &der::integer_i64(2)),
            der::tlv(der::INTEGER, &[0xff]), // Negative serial, as some CAs issue.
            signature.clone(),
            name.clone(),
            der::sequence(&[der::time(&not_before), der::time(not_after)].concat()),
            name,
            der::sequence(&[algorithm, der::bit_string(0, key)].concat()),
        ]
        .concat();
        der::sequence(
            &[
                der::sequence(&tbs),
                signature,
                der::bit_string(0, &[1, 2, 3]),
            ]
            .concat(),
        )
    }

    fn algorithm(arcs: &[u64], parameters: Option<&[u8]>) -> Vec<u8> {
        der::algorithm_identifier(&ObjectIdentifier::new(arcs).unwrap(), parameters)
    }

    #[test]
    fn summarizes_common_public_key_algorithms() {
        let expiry = Asn1Time::new(2051, 2, 3, 4, 5, 6, false).unwrap();
        let mut modulus = vec![0x80];
        modulus.resize(256, 0);
        let rsa_key = der::sequence(&[der::integer(&modulus), der::integer(&[1, 0, 1])].concat());
        let curve = der::oid(&ObjectIdentifier::new(oid::OID_SECP384R1).unwrap());
        let dsa_parameters = der::sequence(
            &[
                der::integer(&[0x7f; 128]),
                der::integer(&[1]),
                der::integer(&[2]),
            ]
            .concat(),
        );
        for (algorithm, key, name, size) in [
            (
                algorithm(oid::OID_RSA_ENCRYPTION, Some(&der::null())),
                rsa_key.as_slice(),
                "RSA",
                Some(2048),
            ),
            (
                algorithm(oid::OID_EC_PUBLIC_KEY, Some(&curve)),
                &[4][..],
                "EC",
                Some(384),
            ),
            (
                algorithm(oid::OID_DSA, Some(&dsa_parameters)),
                &[2, 1, 1][..],
                "DSA",
                Some(1023),
            ),
            (
                algorithm(oid::OID_ED25519, None),
                &[0; 32][..],
                "Ed25519",
                Some(255),
            ),
            (
                algorithm(OID_ML_DSA_65, None),
                &[0; 4][..],
                "ML-DSA-65",
                None,
            ),
            (algorithm(&[1, 2, 3, 4], None), &[0][..], "1.2.3.4", None),
        ] {
            let summary = summarize(&certificate(algorithm, key, &expiry)).unwrap();
            assert_eq!(summary.algorithm, name);
            assert_eq!(summary.key_size, size, "{name}");
            assert_eq!(summary.expiry_text(), "2051-02-03");
        }
    }

    #[test]
    fn reports_short_keys_as_weaknesses() {
        let expiry = Asn1Time::new(2051, 2, 3, 4, 5, 6, false).unwrap();
        let mut modulus = vec![0x80];
        modulus.resize(128, 0);
        let rsa_key = der::sequence(&[der::integer(&modulus), der::integer(&[1, 0, 1])].concat());
        let summary = summarize(&certificate(
            algorithm(oid::OID_RSA_ENCRYPTION, Some(&der::null())),
            &rsa_key,
            &expiry,
        ))
        .unwrap();
        assert_eq!(
            summary.weaknesses,
            [security::Weakness::ShortKey {
                algorithm: "RSA".into(),
                bits: 1024,
                minimum: 2048,
            }]
        );
    }

    #[test]
    fn reports_expiry_relative_to_now() {
        let expiry = Asn1Time::new(2030, 1, 1, 0, 0, 0, true).unwrap();
        let summary = summarize(&certificate(
            algorithm(oid::OID_ED25519, None),
            &[0; 32],
            &expiry,
        ))
        .unwrap();
        assert!(!summary.is_expired(expiry.to_unix() - 1));
        assert!(summary.is_expired(expiry.to_unix() + 1));
    }

    #[test]
    fn ignores_data_that_is_not_a_certificate() {
        let der = certificate(
            algorithm(oid::OID_ED25519, None),
            &[0; 32],
            &Asn1Time::new(2030, 1, 1, 0, 0, 0, true).unwrap(),
        );
        assert!(summarize(b"opaque synthetic certificate").is_none());
        for end in 0..der.len() {
            assert!(summarize(&der[..end]).is_none(), "prefix {end}");
        }
    }
}
