//! Checks a certificate's signature against the public key of the certificate
//! stored as its issuer. This is offline and makes no trust decisions: names,
//! validity, constraints, and revocation are not checked.
use crown::{
    asn1::{
        Reader,
        der::{self, Class},
    },
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

/// The signed bytes, the signature algorithm (from outside the signed part,
/// and from inside it when it repeats it there), and the signature value.
struct Signed<'a> {
    tbs: &'a [u8],
    inner_algorithm: Option<&'a [u8]>,
    outer_algorithm: &'a [u8],
    value: &'a [u8],
}

/// Splits `SEQUENCE { signed part, algorithm, BIT STRING }`, the outer layout
/// of certificates, revocation lists, and requests.
fn signed(der: &[u8]) -> Option<Signed<'_>> {
    let mut outer = Reader::new(der).read_sequence().ok()?;
    let tbs = outer.read_raw_tlv().ok()?;
    let outer_algorithm = outer.read_raw_tlv().ok()?;
    let value = outer.read_bit_string_bytes().ok()?;
    Some(Signed {
        tbs,
        inner_algorithm: None,
        outer_algorithm,
        value,
    })
}

fn signed_certificate(der: &[u8]) -> Option<Signed<'_>> {
    let signed = signed(der)?;
    let mut fields = Reader::new(signed.tbs).read_sequence().ok()?;
    skip_version(&mut fields)?;
    fields.read_raw_tlv().ok()?; // Serial number.
    Some(Signed {
        inner_algorithm: Some(fields.read_raw_tlv().ok()?),
        ..signed
    })
}

fn signed_revocation_list(der: &[u8]) -> Option<Signed<'_>> {
    let signed = signed(der)?;
    let mut fields = Reader::new(signed.tbs).read_sequence().ok()?;
    if fields.peek_tag().ok()? == der::INTEGER {
        fields.read_raw_tlv().ok()?; // Version.
    }
    Some(Signed {
        inner_algorithm: Some(fields.read_raw_tlv().ok()?),
        ..signed
    })
}

/// A request's signed parts and its own SubjectPublicKeyInfo.
fn signed_request(der: &[u8]) -> Option<(Signed<'_>, &[u8])> {
    let signed = signed(der)?;
    let mut fields = Reader::new(signed.tbs).read_sequence().ok()?;
    fields.read_raw_tlv().ok()?; // Version.
    fields.read_raw_tlv().ok()?; // Subject.
    let spki = fields.read_raw_tlv().ok()?;
    Some((signed, spki))
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

/// Why a signature does not verify, or could not be checked, worded for
/// whose key checks it.
struct Reasons {
    no_key: &'static str,
    unsupported_key: &'static str,
    undecodable_key: &'static str,
    incompatible_key: &'static str,
    mismatch: &'static str,
}

const ISSUER: Reasons = Reasons {
    no_key: "the issuer certificate could not be decoded",
    unsupported_key: "the issuer's key type is not supported",
    undecodable_key: "the issuer's public key could not be decoded",
    incompatible_key: "the issuer's key type cannot make this signature",
    mismatch: "the issuer's public key did not make it",
};

const REQUESTER: Reasons = Reasons {
    no_key: "the request could not be decoded",
    unsupported_key: "the request's key type is not supported",
    undecodable_key: "the request's public key could not be decoded",
    incompatible_key: "the request's key type cannot make this signature",
    mismatch: "the request's public key did not make it",
};

/// Checks `certificate`'s signature with the public key in `issuer`. Pass the
/// same certificate twice to check a self-signed certificate.
pub fn verify(certificate: &[u8], issuer: &[u8]) -> Signature {
    let Some(signed) = signed_certificate(certificate) else {
        return Signature::Unchecked("the certificate could not be decoded");
    };
    check(&signed, subject_public_key_info(issuer), &ISSUER)
}

/// Checks a revocation list's signature with the public key in `issuer`.
pub fn verify_revocation_list(list: &[u8], issuer: &[u8]) -> Signature {
    let Some(signed) = signed_revocation_list(list) else {
        return Signature::Unchecked("the revocation list could not be decoded");
    };
    check(&signed, subject_public_key_info(issuer), &ISSUER)
}

/// Checks a request's signature with its own public key, which shows that
/// the requester holds the matching private key.
pub fn verify_request(request: &[u8]) -> Signature {
    let Some((signed, spki)) = signed_request(request) else {
        return Signature::Unchecked("the request could not be decoded");
    };
    check(&signed, Some(spki), &REQUESTER)
}

fn check(signed: &Signed<'_>, spki: Option<&[u8]>, reasons: &Reasons) -> Signature {
    let Ok(identifier) = AlgorithmIdentifier::parse(&mut Reader::new(signed.outer_algorithm))
    else {
        return Signature::Unchecked("the signature algorithm could not be decoded");
    };
    let Ok(algorithm) = SignatureAlgorithm::from_identifier(&identifier) else {
        return Signature::Unchecked("the signature algorithm is not supported");
    };
    let Some(spki) = spki else {
        return Signature::Unchecked(reasons.no_key);
    };
    let key = match SubjectPublicKeyInfo::parse(spki) {
        Ok(spki) => spki.public_key,
        Err(CryptoError::UnsupportedOperation(_)) => {
            return Signature::Unchecked(reasons.unsupported_key);
        }
        Err(_) => return Signature::Unchecked(reasons.undecodable_key),
    };
    if signed
        .inner_algorithm
        .is_some_and(|inner| inner != signed.outer_algorithm)
    {
        return Signature::Failed(
            "the signature algorithm differs from the one in the signed part",
        );
    }
    if !compatible(&algorithm, &key) {
        return Signature::Failed(reasons.incompatible_key);
    }
    match algorithm.verify(&key, signed.tbs, signed.value) {
        Ok(true) => Signature::Verified,
        Ok(false) | Err(_) => Signature::Failed(reasons.mismatch),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{
        ed25519_certificate, ed25519_request, ed25519_revocation_list, fixture_certificate_der,
        metadata_certificate,
    };
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

    #[test]
    fn checks_requests_with_their_own_key() {
        let request = ed25519_request("web", &[], 5);
        assert_eq!(verify_request(&request), Signature::Verified);
        let subject = request.windows(3).position(|w| w == b"web").unwrap();
        let mut altered = request.clone();
        altered[subject] = b'W';
        assert_eq!(
            verify_request(&altered),
            Signature::Failed("the request's public key did not make it")
        );
        assert_eq!(
            verify_request(b"junk"),
            Signature::Unchecked("the request could not be decoded")
        );
        assert_eq!(
            verify_request(&replace_algorithm(&request, 0, &[1, 2, 3, 4])),
            Signature::Unchecked("the request's key type is not supported")
        );
    }

    #[test]
    fn checks_revocation_lists_with_the_issuer_key() {
        let root = ed25519_certificate("root", "root", 1, 1);
        let other = ed25519_certificate("other", "other", 3, 3);
        let list = ed25519_revocation_list("root", None, &[], &[], 1);
        assert_eq!(verify_revocation_list(&list, &root), Signature::Verified);
        assert_eq!(
            verify_revocation_list(&list, &other),
            Signature::Failed("the issuer's public key did not make it")
        );
        assert_eq!(
            verify_revocation_list(&replace_algorithm(&list, 1, &[1, 3, 101, 113]), &root),
            Signature::Failed("the signature algorithm differs from the one in the signed part")
        );
        assert_eq!(
            verify_revocation_list(b"junk", &root),
            Signature::Unchecked("the revocation list could not be decoded")
        );
        // A version 1 list has no version field before its algorithm.
        let mut outer = Reader::new(&list).read_sequence().unwrap();
        let mut tbs = outer.read_sequence().unwrap();
        tbs.read_raw_tlv().unwrap();
        let mut fields = Vec::new();
        while !tbs.is_empty() {
            fields.extend(tbs.read_raw_tlv().unwrap());
        }
        let tbs = der::sequence(&fields);
        let signature = crown::ed25519::sign(&[1; 32], &tbs);
        let algorithm = outer.read_raw_tlv().unwrap();
        let v1 = der::sequence(&[&tbs[..], algorithm, &der::bit_string(0, &signature)].concat());
        assert_eq!(verify_revocation_list(&v1, &root), Signature::Verified);
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
            Signature::Failed("the signature algorithm differs from the one in the signed part")
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
