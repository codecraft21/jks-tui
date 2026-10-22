//! Detail text for certificate requests and revocation lists.
use ratatui::{
    style::Stylize,
    text::{Line, Span, Text},
};

use crate::{
    certificate::{
        Summary, details::time_text, extensions::Extension, request::Request,
        revocation::RevocationList,
    },
    keystore,
};

/// Revoked certificates beyond this many are counted but not listed, so the
/// details stay within the scrollable length.
pub const MAX_REVOKED_SHOWN: usize = 5000;

pub enum Document {
    /// `None` when it cannot be decoded.
    Request(Option<Request>),
    RevocationList(Option<RevocationList>),
}

impl Document {
    pub fn parse(kind: keystore::Document, der: &[u8]) -> Self {
        match kind {
            keystore::Document::Request => Self::Request(Request::parse(der).ok()),
            keystore::Document::RevocationList => {
                Self::RevocationList(RevocationList::parse(der).ok())
            }
        }
    }

    /// For example `Request`, as it starts the hierarchy label.
    pub fn noun(&self) -> &'static str {
        match self {
            Self::Request(_) => "Request",
            Self::RevocationList(_) => "Revocation list",
        }
    }

    /// The PEM label exports use.
    pub fn pem_label(&self) -> &'static str {
        match self {
            Self::Request(_) => "CERTIFICATE REQUEST",
            Self::RevocationList(_) => "X509 CRL",
        }
    }

    /// The export prompt's name for it.
    pub fn export_label(&self) -> &'static str {
        match self {
            Self::Request(_) => "request",
            Self::RevocationList(_) => "revocation list",
        }
    }

    pub fn summary(&self) -> Option<Summary> {
        match self {
            Self::Request(request) => request.as_ref().map(Request::summary),
            Self::RevocationList(list) => list.as_ref().map(RevocationList::summary),
        }
    }

    /// The subject (a revocation list's issuer), when it can be decoded.
    pub fn name(&self) -> Option<String> {
        match self {
            Self::Request(request) => request.as_ref().map(|request| request.subject.to_string()),
            Self::RevocationList(list) => list.as_ref().map(|list| list.issuer.to_string()),
        }
        .filter(|name| !name.is_empty())
    }

    /// The fields up to the signature algorithm, and the sections that follow
    /// the fingerprint; `None` when the document cannot be decoded.
    pub fn fields(&self, now: i64) -> Option<(Vec<Line<'static>>, String)> {
        match self {
            Self::Request(request) => request.as_ref().map(request_fields),
            Self::RevocationList(list) => list.as_ref().map(|list| list_fields(list, now)),
        }
    }
}

fn request_fields(request: &Request) -> (Vec<Line<'static>>, String) {
    let public_key = match request.key_size {
        Some(bits) => format!("{} {bits} bits", request.algorithm),
        None => format!("{} -", request.algorithm),
    };
    let lines = Text::from(format!(
        "Version: {}\n\nSubject: {}\n\nPublic Key: {public_key}\n\nSignature Algorithm: {}",
        request.version, request.subject, request.signature_algorithm,
    ))
    .lines;
    let mut sections = String::from("Attributes:");
    if request.attributes.is_empty() {
        sections.push_str(" None\n");
    } else {
        sections.push('\n');
        for attribute in &request.attributes {
            sections.push_str(&format!("  {}\n", attribute.title));
            for line in &attribute.lines {
                sections.push_str(&format!("    {line}\n"));
            }
        }
    }
    sections.push('\n');
    sections.push_str(&extensions_text(
        "Requested Extensions:",
        &request.extensions,
    ));
    (lines, sections)
}

fn list_fields(list: &RevocationList, now: i64) -> (Vec<Line<'static>>, String) {
    let mut lines = Text::from(format!(
        "Version: {}\n\nIssuer: {}\n\nThis Update: {}\n",
        list.version,
        list.issuer,
        time_text(&list.this_update),
    ))
    .lines;
    lines.push(match list.next_update {
        Some(next) if next.to_unix() < now => Line::from(vec![
            Span::raw("Next Update: "),
            Span::raw(time_text(&next)).red(),
        ]),
        Some(next) => Line::from(format!("Next Update: {}", time_text(&next))),
        None => Line::from("Next Update: None"),
    });
    lines.extend(
        Text::from(format!(
            "\nSignature Algorithm: {}",
            list.signature_algorithm
        ))
        .lines,
    );
    let mut sections = extensions_text("Extensions:", &list.extensions);
    if list.revoked.is_empty() {
        sections.push_str("Revoked Certificates: None\n\n");
    } else {
        sections.push_str(&format!("Revoked Certificates: {}\n", list.revoked.len()));
        for entry in list.revoked.iter().take(MAX_REVOKED_SHOWN) {
            sections.push_str(&format!(
                "  Serial Number: {} ({})\n    Revoked: {}\n",
                entry.serial_hex,
                entry.serial_decimal,
                time_text(&entry.revocation_date),
            ));
            for extension in &entry.extensions {
                sections.push_str(&format!("    {}\n", extension.title()));
                for line in &extension.lines {
                    sections.push_str(&format!("      {line}\n"));
                }
            }
        }
        if let Some(hidden) = list.revoked.len().checked_sub(MAX_REVOKED_SHOWN)
            && hidden > 0
        {
            sections.push_str(&format!("  {hidden} more are not listed.\n"));
        }
        sections.push('\n');
    }
    (lines, sections)
}

/// A titled, indented section; each extension's title is followed by its
/// decoded values.
pub fn extensions_text(title: &str, extensions: &[Extension]) -> String {
    if extensions.is_empty() {
        return format!("{title} None\n\n");
    }
    let mut text = format!("{title}\n");
    for extension in extensions {
        text.push_str(&format!("  {}\n", extension.title()));
        for line in &extension.lines {
            text.push_str(&format!("    {line}\n"));
        }
    }
    text.push('\n');
    text
}
