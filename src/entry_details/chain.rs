//! A stored chain in the detail view: the hierarchy and each certificate's details.
use ratatui::{
    style::Stylize,
    text::{Line, Span, Text},
    widgets::Row,
};

use super::{
    extensions_text, fingerprint_text, hierarchy_row, public_key_text, signature_line,
    weakness_lines,
};
use crate::certificate::{
    self, Summary,
    details::{Details, time_text},
    signature::{self, Signature},
};

/// A stored chain, with each certificate decoded and its signature checked once.
pub(super) struct ChainView {
    /// Original DER in leaf-first stored order.
    pub(super) certificates: Vec<Vec<u8>>,
    chain_warning: Option<&'static str>,
    pub(super) metadata: Vec<Option<Details>>,
    summaries: Vec<Option<Summary>>,
    /// Each certificate's signature checked with the next stored certificate,
    /// or with its own key when it is the last and self-issued. `None` when
    /// the issuer is not stored.
    pub(super) signatures: Vec<Option<Signature>>,
}

impl ChainView {
    pub(super) fn new(certificates: &[Vec<u8>], chain_warning: Option<&'static str>) -> Self {
        let metadata: Vec<_> = certificates
            .iter()
            .map(|der| Details::parse(der).ok())
            .collect();
        let signatures = (0..certificates.len())
            .map(|index| {
                let issuer = if index + 1 < certificates.len() {
                    index + 1
                } else if metadata[index]
                    .as_ref()
                    .is_some_and(|info| info.issuer == info.subject)
                {
                    index
                } else {
                    return None;
                };
                Some(signature::verify(
                    &certificates[index],
                    &certificates[issuer],
                ))
            })
            .collect();
        Self {
            certificates: certificates.to_vec(),
            chain_warning,
            metadata,
            summaries: certificates
                .iter()
                .map(|der| certificate::summarize(der))
                .collect(),
            signatures,
        }
    }

    /// The hierarchy, root first, indented by depth.
    pub(super) fn hierarchy_rows(&self) -> Vec<Row<'static>> {
        self.metadata
            .iter()
            .enumerate()
            .rev()
            .enumerate()
            .map(|(depth, (index, info))| {
                let label = info
                    .as_ref()
                    .map(|info| info.subject.to_string())
                    .filter(|name| !name.is_empty())
                    .unwrap_or_else(|| {
                        format!("Certificate {} (unreadable or unnamed)", index + 1)
                    });
                let weak = self.summaries[index]
                    .as_ref()
                    .is_some_and(|summary| !summary.weaknesses.is_empty());
                let indent = "  ".repeat(depth.min(8));
                hierarchy_row(format!("{indent}{label}"), weak, self.signatures[index])
            })
            .collect()
    }

    /// The detail text after the alias and type: any chain warning, then the
    /// certificate at `index`, if one is selected.
    pub(super) fn text(
        &self,
        mut text: String,
        index: Option<usize>,
        now: i64,
        sha1: bool,
    ) -> Text<'static> {
        if let Some(warning) = self.chain_warning {
            text.push_str(&format!("{warning}\n\n"));
        }
        let Some(index) = index else {
            text.push_str("No certificate is stored with this entry.");
            return Text::from(text);
        };
        let mut lines = Vec::new();
        if let Some(info) = &self.metadata[index] {
            let summary = self.summaries[index].as_ref();
            text.push_str(&format!(
                "Version: {}\n\nSubject: {}\n\nIssuer: {}\n\nSerial Number (hex): {}\n\nSerial Number (dec): {}\n\nValid From: {}\n\n",
                info.version, info.subject, info.issuer, info.serial_hex, info.serial_decimal,
                time_text(&info.not_before),
            ));
            lines.extend(Text::from(text).lines);
            let expiry = Span::raw(time_text(&info.not_after));
            lines.push(Line::from(vec![
                Span::raw("Valid Until: "),
                if info.not_after.to_unix() < now {
                    expiry.red()
                } else {
                    expiry
                },
            ]));
            lines.extend(
                Text::from(format!(
                    "\nPublic Key: {}\n\nSignature Algorithm: {}\n",
                    public_key_text(summary),
                    info.signature_algorithm,
                ))
                .lines,
            );
            lines.extend(weakness_lines(summary));
            lines.push(self.signature_line(index));
            text = "\n".into();
        } else {
            text.push_str("Certificate could not be decoded.\n\n");
        }
        text.push_str(&fingerprint_text(&self.certificates[index], sha1));
        if let Some(info) = &self.metadata[index] {
            text.push_str(&extensions_text("Extensions", &info.extensions));
        }
        text.push_str(
            "Stored certificates only; signatures are checked within the chain, trust is not verified.",
        );
        if self.chain_warning.is_none()
            && self
                .metadata
                .last()
                .and_then(Option::as_ref)
                .is_some_and(|info| info.issuer != info.subject)
        {
            text.push_str("\nIssuer certificate is not stored in this chain.");
        }
        lines.extend(Text::from(text).lines);
        Text::from(lines)
    }

    /// The signature check of the certificate at `index`, naming the key it used.
    fn signature_line(&self, index: usize) -> Line<'static> {
        let Some(result) = self.signatures[index] else {
            return Line::from("Signature: not checked (the issuer certificate is not stored).");
        };
        let key = if index + 1 == self.metadata.len() {
            "its own public key (self-signed)".to_string()
        } else {
            let issuer = self.metadata[index + 1]
                .as_ref()
                .map(|info| info.subject.to_string())
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| format!("certificate {}", index + 2));
            format!("the public key of {issuer}")
        };
        signature_line(result, &key)
    }
}
