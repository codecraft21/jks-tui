//! Filtering, sorting, and expiry classification for the main entry list.
use crate::{certificate::Summary, keystore::KeystoreEntry};

/// Certificates expiring within this many seconds are highlighted as a warning.
pub const EXPIRY_WARNING_SECONDS: i64 = 30 * 24 * 60 * 60;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SortOrder {
    /// The loaded order: by alias, with duplicate aliases kept in stored order.
    #[default]
    Alias,
    /// Soonest expiry first; entries without an expiry date last.
    Expiry,
}

impl SortOrder {
    pub fn next(self) -> Self {
        match self {
            Self::Alias => Self::Expiry,
            Self::Expiry => Self::Alias,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Alias => "alias",
            Self::Expiry => "expiry",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpiryStatus {
    Valid,
    /// Not yet expired, but expiring within `EXPIRY_WARNING_SECONDS`.
    ExpiringSoon,
    Expired,
}

pub fn expiry_status(summary: &Summary, now: i64) -> ExpiryStatus {
    if summary.is_expired(now) {
        ExpiryStatus::Expired
    } else if summary.expiry_warning
        && summary
            .not_after
            .is_some_and(|time| time.to_unix() <= now.saturating_add(EXPIRY_WARNING_SECONDS))
    {
        ExpiryStatus::ExpiringSoon
    } else {
        ExpiryStatus::Valid
    }
}

/// Case-insensitive substring match against the alias and certificate subject.
/// `needle` must already be lowercase; an empty needle matches everything.
fn matches(entry: &KeystoreEntry, needle: &str) -> bool {
    needle.is_empty()
        || entry.alias.to_lowercase().contains(needle)
        || entry
            .certificate
            .as_ref()
            .is_some_and(|summary| summary.subject.to_lowercase().contains(needle))
}

/// Indices into `entries` of the entries to show, in display order.
pub fn visible_entries(entries: &[KeystoreEntry], filter: &str, order: SortOrder) -> Vec<usize> {
    let needle = filter.to_lowercase();
    let mut visible: Vec<usize> = entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| matches(entry, &needle))
        .map(|(index, _)| index)
        .collect();
    if order == SortOrder::Expiry {
        // Stable, so equal expiry dates keep their alias order.
        visible.sort_by_key(|&index| {
            entries[index]
                .certificate
                .as_ref()
                .and_then(|summary| summary.not_after)
                .map_or((true, 0), |time| (false, time.to_unix()))
        });
    }
    visible
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::fixture_summary;
    use crown::asn1::Asn1Time;

    fn entry(alias: &str, expiry: Option<(i32, u8, u8)>) -> KeystoreEntry {
        KeystoreEntry {
            alias: alias.into(),
            kind: "Trusted certificate",
            certificate: expiry.map(|(year, month, day)| Summary {
                not_after: Some(Asn1Time::new(year, month, day, 0, 0, 0, true).unwrap()),
                ..fixture_summary()
            }),
            certificates: vec![],
            chain_warning: None,
            document: None,
        }
    }

    fn aliases(entries: &[KeystoreEntry], visible: &[usize]) -> Vec<String> {
        visible
            .iter()
            .map(|&index| entries[index].alias.clone())
            .collect()
    }

    #[test]
    fn filters_case_insensitively_by_alias_and_subject() {
        let entries = [
            entry("Server-Key", Some((2030, 1, 1))),
            entry("root-cert", Some((2031, 1, 1))),
            entry("secret", None),
        ];
        for (filter, expected) in [
            ("", vec!["Server-Key", "root-cert", "secret"]),
            ("SERVER", vec!["Server-Key"]),
            ("r-k", vec!["Server-Key"]),
            ("test fixture", vec!["Server-Key", "root-cert"]),
            ("cn=jks", vec!["Server-Key", "root-cert"]),
            ("missing", vec![]),
        ] {
            let visible = visible_entries(&entries, filter, SortOrder::Alias);
            assert_eq!(aliases(&entries, &visible), expected, "{filter}");
        }
    }

    #[test]
    fn expiry_sort_puts_soonest_first_and_undated_entries_last() {
        let entries = [
            entry("a-late", Some((2040, 1, 1))),
            entry("b-none", None),
            entry("dup", Some((2030, 1, 1))),
            entry("dup", Some((2020, 1, 1))),
            entry("e-same", Some((2030, 1, 1))),
            entry("f-none", None),
        ];
        assert_eq!(
            visible_entries(&entries, "", SortOrder::Alias),
            [0, 1, 2, 3, 4, 5]
        );
        assert_eq!(
            visible_entries(&entries, "", SortOrder::Expiry),
            [3, 2, 4, 0, 1, 5]
        );
        assert_eq!(visible_entries(&entries, "DUP", SortOrder::Expiry), [3, 2]);
        assert_eq!(visible_entries(&entries, "-n", SortOrder::Expiry), [1, 5]);
        assert_eq!(SortOrder::Alias.next(), SortOrder::Expiry);
        assert_eq!(SortOrder::Expiry.next(), SortOrder::Alias);
    }

    #[test]
    fn classifies_expiry_with_a_thirty_day_warning_window() {
        let summary = fixture_summary();
        let expiry = summary.not_after.unwrap().to_unix();
        for (now, status) in [
            (expiry - EXPIRY_WARNING_SECONDS - 1, ExpiryStatus::Valid),
            (expiry - EXPIRY_WARNING_SECONDS, ExpiryStatus::ExpiringSoon),
            (expiry, ExpiryStatus::ExpiringSoon),
            (expiry + 1, ExpiryStatus::Expired),
            (i64::MAX, ExpiryStatus::Expired),
            (i64::MIN, ExpiryStatus::Valid),
        ] {
            assert_eq!(expiry_status(&summary, now), status, "{now}");
        }
        let list = Summary {
            expiry_warning: false,
            ..summary.clone()
        };
        assert_eq!(expiry_status(&list, expiry), ExpiryStatus::Valid);
        assert_eq!(expiry_status(&list, expiry + 1), ExpiryStatus::Expired);
        let request = Summary {
            not_after: None,
            ..summary
        };
        assert_eq!(expiry_status(&request, i64::MAX), ExpiryStatus::Valid);
        assert_eq!(request.expiry_text(), "-");
    }
}
