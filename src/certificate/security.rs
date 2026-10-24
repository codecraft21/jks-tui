//! Weak-cryptography checks for the entry list and detail view. They flag
//! short public keys and weak signature hashes; they do not verify anything.
use std::fmt;

use crown::asn1::oid::ObjectIdentifier;

/// RSA and DSA keys shorter than this are flagged, following NIST SP 800-131A.
pub const MINIMUM_RSA_DSA_BITS: u32 = 2048;
/// EC curves smaller than this are flagged.
pub const MINIMUM_EC_BITS: u32 = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Weakness {
    ShortKey {
        algorithm: String,
        bits: u32,
        minimum: u32,
    },
    /// The signature's hash function, such as `SHA-1`.
    WeakSignature(&'static str),
}

impl fmt::Display for Weakness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShortKey {
                algorithm,
                bits,
                minimum,
            } => write!(
                f,
                "{bits}-bit {algorithm} key is shorter than the recommended {minimum} bits"
            ),
            Self::WeakSignature(hash) => write!(f, "signed with {hash}, which is no longer secure"),
        }
    }
}

const WEAK_SIGNATURES: &[(&[u64], &str)] = &[
    (&[1, 2, 840, 113549, 1, 1, 2], "MD2"),
    (&[1, 2, 840, 113549, 1, 1, 4], "MD5"),
    (&[1, 2, 840, 113549, 1, 1, 5], "SHA-1"),
    (&[1, 3, 14, 3, 2, 29], "SHA-1"),
    (&[1, 2, 840, 10045, 4, 1], "SHA-1"),
    (&[1, 2, 840, 10040, 4, 3], "SHA-1"),
];

/// The weaknesses of a certificate's key and signature. A self-signed
/// certificate's signature is not checked: trust in a root comes from where
/// it is stored, not from its signature.
pub fn weaknesses(
    algorithm: &str,
    key_size: Option<u32>,
    signature: &ObjectIdentifier,
    self_signed: bool,
) -> Vec<Weakness> {
    let mut found: Vec<_> = key_weakness(algorithm, key_size).into_iter().collect();
    if !self_signed
        && let Some((_, hash)) = WEAK_SIGNATURES
            .iter()
            .find(|(arcs, _)| signature.matches(arcs))
    {
        found.push(Weakness::WeakSignature(hash));
    }
    found
}

/// Whether a key of this algorithm and size is too short.
pub fn key_weakness(algorithm: &str, key_size: Option<u32>) -> Option<Weakness> {
    let minimum = match algorithm {
        "RSA" | "RSASSA-PSS" | "DSA" => MINIMUM_RSA_DSA_BITS,
        "EC" => MINIMUM_EC_BITS,
        _ => return None,
    };
    let bits = key_size.filter(|&bits| bits < minimum)?;
    Some(Weakness::ShortKey {
        algorithm: algorithm.into(),
        bits,
        minimum,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oid(arcs: &[u64]) -> ObjectIdentifier {
        ObjectIdentifier::new(arcs).unwrap()
    }

    #[test]
    fn flags_keys_below_the_minimum_size() {
        let sha256_rsa = oid(&[1, 2, 840, 113549, 1, 1, 11]);
        for (algorithm, bits, weak) in [
            ("RSA", Some(1024), true),
            ("RSA", Some(2047), true),
            ("RSA", Some(2048), false),
            ("RSASSA-PSS", Some(1024), true),
            ("DSA", Some(1024), true),
            ("DSA", Some(3072), false),
            ("EC", Some(224), true),
            ("EC", Some(256), false),
            ("EC", None, false),
            ("Ed25519", Some(255), false),
            ("1.2.3.4", Some(8), false),
        ] {
            let found = weaknesses(algorithm, bits, &sha256_rsa, false);
            assert_eq!(!found.is_empty(), weak, "{algorithm} {bits:?}");
        }
        assert_eq!(
            weaknesses("RSA", Some(1024), &sha256_rsa, true)[0].to_string(),
            "1024-bit RSA key is shorter than the recommended 2048 bits"
        );
    }

    #[test]
    fn flags_md5_and_sha1_signatures_except_on_self_signed_certificates() {
        for (arcs, hash) in WEAK_SIGNATURES {
            let found = weaknesses("EC", Some(256), &oid(arcs), false);
            assert_eq!(found, [Weakness::WeakSignature(hash)]);
            assert!(weaknesses("EC", Some(256), &oid(arcs), true).is_empty());
        }
        assert_eq!(
            Weakness::WeakSignature("SHA-1").to_string(),
            "signed with SHA-1, which is no longer secure"
        );
        for arcs in [&[1, 2, 840, 10045, 4, 3, 2][..], &[1, 3, 101, 112]] {
            assert!(weaknesses("EC", Some(256), &oid(arcs), false).is_empty());
        }
    }
}
