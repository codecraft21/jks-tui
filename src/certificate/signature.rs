//! Checks a certificate's signature against the public key of the certificate
//! stored as its issuer. This is offline and makes no trust decisions: names,
//! validity, constraints, and revocation are not checked.
use crown::{
    asn1::{Reader, der::Class},
    error::CryptoError,
    x509::{AlgorithmIdentifier, SignatureAlgorithm, keys::PublicKey, keys::SubjectPublicKeyInfo},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signature {
    Verified,
    /// Why the signature does not verify.
    Failed(&'static str),
    /// Why the signature could not be checked.
    Unchecked(&'static str),
}

/// The signed bytes, the signature algorithm (from inside and outside the
/// signed part), and the signature value.
struct Signed<'a> {
    tbs: &'a [u8],
    inner_algorithm: &'a [u8],
    outer_algorithm: &'a [u8],
    value: &'a [u8],
}

fn signed(der: &[u8]) -> Option<Signed<'_>> {
    let mut reader = Reader::new(der);
    let mut certificate = reader.read_sequence().ok()?;
    let tbs = certificate.read_raw_tlv().ok()?;
    let outer_algorithm = certificate.read_raw_tlv().ok()?;
    let value = certificate.read_bit_string_bytes().ok()?;
    let mut fields = Reader::new(tbs).read_sequence().ok()?;
    skip_version(&mut fields)?;
    fields.read_raw_tlv().ok()?; // Serial number.
    let inner_algorithm = fields.read_raw_tlv().ok()?;
    Some(Signed {
        tbs,
        inner_algorithm,
        outer_algorithm,
        value,
    })
}

fn subject_public_key_info(der: &[u8]) -> Option<&[u8]> {
    let mut fields = Reader::new(der)
        .read_sequence()
        .ok()?
        .read_sequence()
        .ok()?;
    skip_version(&mut fields)?;
    for _ in [
        "serial number",
        "signature",
        "issuer",
        "validity",
        "subject",
    ] {
        fields.read_raw_tlv().ok()?;
    }
    fields.read_raw_tlv().ok()
}

fn skip_version(fields: &mut Reader<'_>) -> Option<()> {
    let tag = fields.peek_tag().ok()?;
    if tag.class == Class::ContextSpecific && tag.number == 0 {
        fields.read_raw_tlv().ok()?;
    }
    Some(())
}

/// Whether a key of this type can make signatures with this algorithm.
fn compatible(algorithm: &SignatureAlgorithm, key: &PublicKey) -> bool {
    matches!(
        (algorithm, key),
        (
            SignatureAlgorithm::RsaPkcs1v15(_) | SignatureAlgorithm::RsaPss { .. },
            PublicKey::Rsa(_)
        ) | (SignatureAlgorithm::Ecdsa(_), PublicKey::Ec { .. })
            | (SignatureAlgorithm::Ed25519, PublicKey::Ed25519(_))
            | (SignatureAlgorithm::Ed448, PublicKey::Ed448(_))
            | (SignatureAlgorithm::Sm2, PublicKey::Sm2(_))
            | (SignatureAlgorithm::Dsa(_), PublicKey::Dsa { .. })
            | (SignatureAlgorithm::MlDsa(_), PublicKey::MlDsa(_))
            | (SignatureAlgorithm::SlhDsa(_), PublicKey::SlhDsa(_))
    )
}

/// Checks `certificate`'s signature with the public key in `issuer`. Pass the
/// same certificate twice to check a self-signed certificate.
pub fn verify(certificate: &[u8], issuer: &[u8]) -> Signature {
    let Some(signed) = signed(certificate) else {
        return Signature::Unchecked("the certificate could not be decoded");
    };
    let Ok(identifier) = AlgorithmIdentifier::parse(&mut Reader::new(signed.outer_algorithm))
    else {
        return Signature::Unchecked("the signature algorithm could not be decoded");
    };
    let Ok(algorithm) = SignatureAlgorithm::from_identifier(&identifier) else {
        return Signature::Unchecked("the signature algorithm is not supported");
    };
    let Some(spki) = subject_public_key_info(issuer) else {
        return Signature::Unchecked("the issuer certificate could not be decoded");
    };
    let key = match SubjectPublicKeyInfo::parse(spki) {
        Ok(spki) => spki.public_key,
        Err(CryptoError::UnsupportedOperation(_)) => {
            return Signature::Unchecked("the issuer's key type is not supported");
        }
        Err(_) => return Signature::Unchecked("the issuer's public key could not be decoded"),
    };
    if signed.inner_algorithm != signed.outer_algorithm {
        return Signature::Failed("the signature algorithm differs inside the certificate");
    }
    if !compatible(&algorithm, &key) {
        return Signature::Failed("the issuer's key type cannot make this signature");
    }
    match algorithm.verify(&key, signed.tbs, signed.value) {
        Ok(true) => Signature::Verified,
        Ok(false) | Err(_) => Signature::Failed("the issuer's public key did not make it"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{ed25519_certificate, fixture_certificate_der, metadata_certificate};
    use crown::asn1::{der, oid::ObjectIdentifier};

    #[test]
    fn verifies_signatures_made_by_the_issuer_key() {
        let root = ed25519_certificate("root", "root", 1, 1);
        let leaf = ed25519_certificate("leaf", "root", 2, 1);
        assert_eq!(verify(&root, &root), Signature::Verified);
        assert_eq!(verify(&leaf, &root), Signature::Verified);
        // The keytool fixture is a self-signed ECDSA P-256 certificate.
        let fixture = fixture_certificate_der();
        assert_eq!(verify(fixture, fixture), Signature::Verified);
    }

    #[test]
    fn reports_wrong_issuers_and_altered_certificates() {
        let root = ed25519_certificate("root", "root", 1, 1);
        let other = ed25519_certificate("other", "other", 3, 3);
        let leaf = ed25519_certificate("leaf", "root", 2, 1);
        let failed = Signature::Failed("the issuer's public key did not make it");
        assert_eq!(verify(&leaf, &other), failed);
        let mut altered = leaf.clone();
        let last = altered.len() - 1;
        altered[last] ^= 1;
        assert_eq!(verify(&altered, &root), failed);
        let subject = leaf.windows(4).position(|w| w == b"leaf").unwrap();
        let mut renamed = leaf.clone();
        renamed[subject] = b'L';
        assert_eq!(verify(&renamed, &root), failed);
        assert_eq!(
            verify(&leaf, fixture_certificate_der()),
            Signature::Failed("the issuer's key type cannot make this signature")
        );
        // Placeholder signature bytes in a well-formed ECDSA certificate.
        let placeholder = metadata_certificate("leaf", "root", &[1], &[]);
        assert_eq!(verify(&placeholder, fixture_certificate_der()), failed);
    }

    fn oid(arcs: &[u64]) -> Vec<u8> {
        der::sequence(&der::oid(&ObjectIdentifier::new(arcs).unwrap()))
    }

    /// Replaces the `n`th Ed25519 algorithm identifier: the signature inside
    /// the signed part, the public key, or the signature outside it.
    fn replace_algorithm(certificate: &[u8], n: usize, arcs: &[u64]) -> Vec<u8> {
        let ed25519 = oid(&[1, 3, 101, 112]);
        let at = (0..certificate.len())
            .filter(|&i| certificate[i..].starts_with(&ed25519))
            .nth(n)
            .unwrap();
        let mut changed = certificate.to_vec();
        changed.splice(at..at + ed25519.len(), oid(arcs));
        changed
    }

    #[test]
    fn rejects_a_signature_algorithm_that_differs_inside_the_certificate() {
        let root = ed25519_certificate("root", "root", 1, 1);
        let leaf = ed25519_certificate("leaf", "root", 2, 1);
        let ed448 = [1, 3, 101, 113];
        assert_eq!(
            verify(&replace_algorithm(&leaf, 2, &ed448), &root),
            Signature::Failed("the signature algorithm differs inside the certificate")
        );
    }

    #[test]
    fn leaves_unsupported_or_undecodable_input_unchecked() {
        let root = ed25519_certificate("root", "root", 1, 1);
        let leaf = ed25519_certificate("leaf", "root", 2, 1);
        let unknown = [1, 2, 3, 4];
        for (certificate, issuer, reason) in [
            (
                b"junk".to_vec(),
                root.clone(),
                "the certificate could not be decoded",
            ),
            (
                replace_algorithm(&leaf, 2, &unknown),
                root.clone(),
                "the signature algorithm is not supported",
            ),
            (
                leaf.clone(),
                b"junk".to_vec(),
                "the issuer certificate could not be decoded",
            ),
            (
                leaf.clone(),
                replace_algorithm(&root, 1, &unknown),
                "the issuer's key type is not supported",
            ),
        ] {
            assert_eq!(verify(&certificate, &issuer), Signature::Unchecked(reason));
        }
    }
}
