//! Full-screen, read-only entry inspection, independent of the entry table state.
use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use ratatui::{
    Frame,
    crossterm::event::{KeyCode, KeyEvent},
    layout::{Constraint, Layout},
    style::{Color, Style, Stylize},
    text::{Line, Span, Text},
    widgets::{Block, Paragraph, Row, Table, TableState, Wrap},
};

use crate::{
    certificate::{
        self, Summary,
        details::{Details, fingerprint, time_text},
        signature::{self, Signature},
    },
    export::{self, ExportPrompt, Outcome, Scope},
    keystore::KeystoreEntry,
};

mod document;

use document::{Document, extensions_text};

/// The certificate fields up to the signature algorithm.
fn certificate_fields(info: &Details, summary: Option<&Summary>, now: i64) -> Vec<Line<'static>> {
    let public_key = summary.map_or_else(
        || "Unavailable".into(),
        |summary| format!("{} {}", summary.algorithm, summary.key_size_text()),
    );
    let mut lines = Text::from(format!(
        "Version: {}\n\nSubject: {}\n\nIssuer: {}\n\nSerial Number (hex): {}\n\nSerial Number (dec): {}\n\nValid From: {}\n",
        info.version, info.subject, info.issuer, info.serial_hex, info.serial_decimal,
        time_text(&info.not_before),
    ))
    .lines;
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
            "\nPublic Key: {public_key}\n\nSignature Algorithm: {}",
            info.signature_algorithm,
        ))
        .lines,
    );
    lines
}

pub struct EntryDetails {
    pub entry: usize,
    hierarchy: TableState,
    /// Certificate fields; `None` for a document and unreadable certificates.
    metadata: Vec<Option<Details>>,
    /// The entry-list fields of each hierarchy member.
    summaries: Vec<Option<Summary>>,
    /// The request or revocation list that is the first hierarchy member.
    document: Option<Document>,
    /// Each certificate's signature checked with the next stored certificate,
    /// or with its own key when it is the last and self-issued. A request is
    /// checked with its own key. `None` when the issuer is not stored.
    signatures: Vec<Option<Signature>>,
    details_focused: bool,
    sha1: bool,
    scroll: u16,
    page: u16,
    max_scroll: u16,
    /// Where exports are suggested and relative export names are resolved.
    directory: PathBuf,
    export: Option<ExportPrompt>,
    /// The last export result, and whether it failed.
    message: Option<(String, bool)>,
}

impl EntryDetails {
    pub fn new(entry: usize, data: &KeystoreEntry, directory: PathBuf) -> Self {
        let certificates = &data.certificates;
        let document = data
            .document
            .zip(certificates.first())
            .map(|(kind, der)| Document::parse(kind, der));
        let metadata: Vec<_> = certificates
            .iter()
            .enumerate()
            .map(|(index, der)| {
                (index > 0 || document.is_none())
                    .then(|| Details::parse(der).ok())
                    .flatten()
            })
            .collect();
        let summaries = certificates
            .iter()
            .enumerate()
            .map(|(index, der)| match &document {
                Some(document) if index == 0 => document.summary(),
                _ => certificate::summarize(der),
            })
            .collect();
        let signatures = (0..certificates.len())
            .map(|index| {
                match &document {
                    Some(Document::Request(_)) if index == 0 => {
                        return Some(signature::verify_request(&certificates[0]));
                    }
                    Some(Document::RevocationList(_)) if index == 0 => {
                        return certificates.get(1).map(|issuer| {
                            signature::verify_revocation_list(&certificates[0], issuer)
                        });
                    }
                    _ => {}
                }
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
            entry,
            hierarchy: TableState::default().with_selected(certificates.len().checked_sub(1)),
            metadata,
            summaries,
            document,
            signatures,
            details_focused: false,
            sha1: false,
            scroll: 0,
            page: 1,
            max_scroll: 0,
            directory,
            export: None,
            message: None,
        }
    }

    /// Whether keys are typed into an export file name instead of acting as shortcuts.
    pub fn exporting(&self) -> bool {
        self.export.is_some()
    }

    /// Handles a key press; returns `true` when the view should close.
    pub fn handle_event(&mut self, key: KeyEvent, entry: &KeystoreEntry) -> bool {
        if let Some(prompt) = &mut self.export {
            match prompt.handle_key(key) {
                Outcome::Editing => self.message = None,
                Outcome::Cancelled => {
                    self.export = None;
                    self.message = None;
                }
                Outcome::Save(path) => {
                    let label = prompt.label;
                    let members: Vec<_> = match prompt.scope {
                        Scope::Certificate => self.selected_certificate().into_iter().collect(),
                        Scope::Chain => (0..entry.certificates.len()).collect(),
                    };
                    let items: Vec<_> = members
                        .into_iter()
                        .map(|index| (self.pem_label(index), &entry.certificates[index][..]))
                        .collect();
                    match export::save(&path, &items) {
                        Ok(()) => {
                            self.export = None;
                            self.message =
                                Some((format!("Saved {label} to '{}'.", path.display()), false));
                        }
                        // Keep the prompt open so the name can be corrected.
                        Err(error) => self.message = Some((error, true)),
                    }
                }
            }
            return false;
        }
        self.message = None;
        match key.code {
            KeyCode::Esc => return true,
            KeyCode::Char('x') | KeyCode::Char('X') if self.selected_certificate().is_some() => {
                let (scope, label) = if key.code == KeyCode::Char('X') {
                    (Scope::Chain, "chain")
                } else {
                    match &self.document {
                        Some(document) if self.selected_certificate() == Some(0) => {
                            (Scope::Certificate, document.export_label())
                        }
                        _ => (Scope::Certificate, "certificate"),
                    }
                };
                self.export = Some(ExportPrompt::new(
                    scope,
                    label,
                    &self.directory,
                    &entry.alias,
                ));
            }
            code => self.handle_key(code),
        }
        false
    }

    /// The PEM label of a hierarchy member.
    fn pem_label(&self, index: usize) -> &'static str {
        match &self.document {
            Some(document) if index == 0 => document.pem_label(),
            _ => "CERTIFICATE",
        }
    }

    /// The `metadata` and stored-certificate index selected in the hierarchy.
    fn selected_certificate(&self) -> Option<usize> {
        self.hierarchy
            .selected()
            .map(|i| self.metadata.len() - 1 - i)
    }

    pub fn handle_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Tab | KeyCode::BackTab => self.details_focused = !self.details_focused,
            KeyCode::Char('f') => self.sha1 = !self.sha1,
            KeyCode::PageDown => {
                self.scroll = self.scroll.saturating_add(self.page).min(self.max_scroll)
            }
            KeyCode::PageUp => self.scroll = self.scroll.saturating_sub(self.page),
            KeyCode::Home => self.scroll = 0,
            KeyCode::End => self.scroll = self.max_scroll,
            KeyCode::Down | KeyCode::Char('j') => {
                if self.details_focused {
                    self.scroll = self.scroll.saturating_add(1).min(self.max_scroll);
                } else if let Some(index) = self.hierarchy.selected() {
                    self.select((index + 1).min(self.metadata.len().saturating_sub(1)));
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if self.details_focused {
                    self.scroll = self.scroll.saturating_sub(1);
                } else if let Some(index) = self.hierarchy.selected() {
                    self.select(index.saturating_sub(1));
                }
            }
            _ => {}
        }
    }

    fn select(&mut self, index: usize) {
        if self.hierarchy.selected() != Some(index) {
            self.hierarchy.select(Some(index));
            self.scroll = 0;
        }
    }

    fn text(&self, entry: &KeystoreEntry, now: i64) -> Text<'static> {
        let mut text = format!("Alias: {}\nType: {}\n\n", entry.alias, entry.kind);
        if let Some(warning) = entry.chain_warning {
            text.push_str(&format!("{warning}\n\n"));
        }
        let Some(index) = self.selected_certificate() else {
            text.push_str("No certificate is stored with this entry.");
            return Text::from(text);
        };
        let mut lines = Text::from(text).lines;
        let summary = self.summaries[index].as_ref();
        let (fields, noun) = match &self.document {
            Some(document) if index == 0 => (document.fields(now), document.noun()),
            _ => (
                self.metadata[index].as_ref().map(|info| {
                    (
                        certificate_fields(info, summary, now),
                        extensions_text("Extensions:", &info.extensions),
                    )
                }),
                "Certificate",
            ),
        };
        let mut text = String::new();
        let sections = if let Some((fields, sections)) = fields {
            lines.extend(fields);
            for weakness in summary.iter().flat_map(|summary| &summary.weaknesses) {
                lines.push(Line::from(format!("Weak: {weakness}.")).yellow());
            }
            lines.push(self.signature_line(index));
            text.push('\n');
            sections
        } else {
            text.push_str(&format!("{noun} could not be decoded.\n\n"));
            String::new()
        };
        text.push_str(&format!(
            "Fingerprint ({}): {}\n\n",
            if self.sha1 { "SHA-1" } else { "SHA-256" },
            fingerprint(&entry.certificates[index], self.sha1)
        ));
        text.push_str(&sections);
        text.push_str(match &self.document {
            Some(Document::Request(_)) => {
                "Only the request's signature is checked; nothing it claims is verified."
            }
            _ => "Stored certificates only; signatures are checked within the chain, trust is not verified.",
        });
        if entry.chain_warning.is_none()
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

    /// The selected certificate's signature check, naming the key it used.
    fn signature_line(&self, index: usize) -> Line<'static> {
        let Some(result) = self.signatures[index] else {
            return Line::from("Signature: not checked (the issuer certificate is not stored).");
        };
        let key = if index == 0 && matches!(self.document, Some(Document::Request(_))) {
            "its own public key (proof of possession)".to_string()
        } else if index + 1 == self.metadata.len() {
            "its own public key (self-signed)".to_string()
        } else {
            let issuer = self.metadata[index + 1]
                .as_ref()
                .map(|info| info.subject.to_string())
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| format!("certificate {}", index + 2));
            format!("the public key of {issuer}")
        };
        match result {
            Signature::Verified => Line::from(format!("Signature: verified with {key}.")).green(),
            Signature::Failed(reason) => {
                Line::from(format!("Signature: does not verify with {key}: {reason}.")).red()
            }
            Signature::Unchecked(reason) => {
                Line::from(format!("Signature: not checked ({reason})."))
            }
        }
    }

    pub fn draw(&mut self, frame: &mut Frame, entry: &KeystoreEntry) {
        let area = frame.area();
        let shortcuts = "Tab Focus | ↑/↓ j/k Navigate | PgUp/PgDn Home/End Scroll\nf SHA-256/SHA-1 | x Export certificate | X Export chain | Esc Back | q / Ctrl+C Quit";
        let minimum = Paragraph::new(shortcuts)
            .wrap(Wrap { trim: false })
            .line_count(area.width);
        if area.width < 20 || usize::from(area.height) < minimum.saturating_add(10) {
            frame.render_widget(
                Paragraph::new("Resize terminal for entry details. Esc Back | q / Ctrl+C Quit")
                    .wrap(Wrap { trim: false }),
                area,
            );
            return;
        }
        let footer = self.footer(shortcuts);
        let footer_height = u16::try_from(footer.line_count(area.width))
            .unwrap_or(u16::MAX)
            .min(area.height / 2);
        let [header, content, footer_area] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(footer_height),
        ])
        .areas(area);
        frame.render_widget(
            Paragraph::new(format!("{} — {}", entry.alias, entry.kind))
                .blue()
                .bold(),
            header,
        );
        let tree_height = (content.height / 3)
            .min(
                u16::try_from(self.metadata.len())
                    .unwrap_or(u16::MAX)
                    .saturating_add(2),
            )
            .max(3);
        let [hierarchy, details] =
            Layout::vertical([Constraint::Length(tree_height), Constraint::Min(3)]).areas(content);
        let focused = |focus| if focus { Color::Blue } else { Color::Reset };
        let tree_block = Block::bordered()
            .title(if self.details_focused {
                " Certificate hierarchy "
            } else {
                " Certificate hierarchy [focused] "
            })
            .border_style(Style::default().fg(focused(!self.details_focused)));
        if self.metadata.is_empty() {
            frame.render_widget(
                Paragraph::new("No certificate").block(tree_block),
                hierarchy,
            );
        } else {
            let rows =
                self.metadata
                    .iter()
                    .enumerate()
                    .rev()
                    .enumerate()
                    .map(|(depth, (index, info))| {
                        let label = match &self.document {
                            Some(document) if index == 0 => document.name().map_or_else(
                                || format!("{} (unreadable or unnamed)", document.noun()),
                                |name| format!("{}: {name}", document.noun()),
                            ),
                            _ => info
                                .as_ref()
                                .map(|info| info.subject.to_string())
                                .filter(|name| !name.is_empty())
                                .unwrap_or_else(|| {
                                    format!("Certificate {} (unreadable or unnamed)", index + 1)
                                }),
                        };
                        let weak = self.summaries[index]
                            .as_ref()
                            .is_some_and(|summary| !summary.weaknesses.is_empty());
                        let indent = "  ".repeat(depth.min(8));
                        let mut spans = vec![Span::raw(format!("{indent}{label}"))];
                        if weak {
                            spans.extend([Span::raw(" "), Span::raw("[weak]").yellow()]);
                        }
                        spans.push(Span::raw(" "));
                        spans.push(match self.signatures[index] {
                            Some(Signature::Verified) => Span::raw("[verified]").green(),
                            Some(Signature::Failed(_)) => Span::raw("[bad signature]").red(),
                            Some(Signature::Unchecked(_)) | None => Span::raw("[unchecked]"),
                        });
                        Row::new([Line::from(spans)])
                    });
            let table = Table::new(rows, [Constraint::Min(0)])
                .block(tree_block)
                .highlight_symbol("> ")
                .row_highlight_style(
                    Style::default()
                        .fg(Color::Rgb(0, 0, 0))
                        .bg(Color::Rgb(175, 255, 255))
                        .bold(),
                );
            frame.render_stateful_widget(table, hierarchy, &mut self.hierarchy);
        }
        let block = Block::bordered()
            .title(if self.details_focused {
                " Certificate details [focused] "
            } else {
                " Certificate details "
            })
            .border_style(Style::default().fg(focused(self.details_focused)));
        let inner = block.inner(details);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs() as i64);
        let paragraph = Paragraph::new(self.text(entry, now)).wrap(Wrap { trim: false });
        self.page = inner.height.max(1);
        self.max_scroll = u16::try_from(
            paragraph
                .line_count(inner.width)
                .saturating_sub(usize::from(inner.height)),
        )
        .unwrap_or(u16::MAX);
        self.scroll = self.scroll.min(self.max_scroll);
        frame.render_widget(paragraph.scroll((self.scroll, 0)).block(block), details);
        frame.render_widget(footer, footer_area);
    }

    /// The export result, then either the export name being typed or the shortcuts.
    fn footer(&self, shortcuts: &'static str) -> Paragraph<'static> {
        let mut lines = Vec::new();
        if let Some((message, failed)) = &self.message {
            let color = if *failed { Color::Red } else { Color::Green };
            lines.push(Line::from(message.clone()).fg(color));
        }
        if let Some(prompt) = &self.export {
            lines.push(Line::from(vec![
                Span::raw(format!("Save {} to: ", prompt.label)).bold(),
                Span::raw(format!("{}_", prompt.path)),
            ]));
            lines.push(Line::from(
                "A .der name saves DER, any other PEM | Enter Save | Ctrl+U Clear | Esc Cancel | Ctrl+C Quit",
            ));
        } else {
            lines.extend(Text::from(shortcuts).lines);
        }
        Paragraph::new(lines).wrap(Wrap { trim: false })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{keystore, test_support::metadata_certificate};
    use crown::asn1::{der, oid::ObjectIdentifier};
    use ratatui::{Terminal, backend::TestBackend};

    fn entry(certificates: Vec<Vec<u8>>) -> KeystoreEntry {
        KeystoreEntry {
            alias: "test-entry".into(),
            kind: "Private key",
            certificate: None,
            certificates,
            chain_warning: None,
            document: None,
        }
    }

    fn draw(details: &mut EntryDetails, entry: &KeystoreEntry, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| details.draw(frame, entry)).unwrap();
        terminal
            .backend()
            .buffer()
            .content
            .chunks(usize::from(width.max(1)))
            .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn only_expired_valid_until_timestamps_render_red() {
        let data = entry(vec![metadata_certificate("leaf", "root", &[1], &[])]);
        let view = EntryDetails::new(0, &data, PathBuf::new());
        let info = view.metadata[0].as_ref().unwrap();
        let expiry = info.not_after.to_unix();
        let timestamp = time_text(&info.not_after);
        for now in [expiry - 1, expiry, expiry + 1] {
            let mut terminal = Terminal::new(TestBackend::new(100, 50)).unwrap();
            terminal
                .draw(|frame| {
                    frame.render_widget(
                        Paragraph::new(view.text(&data, now)).wrap(Wrap { trim: false }),
                        frame.area(),
                    );
                })
                .unwrap();
            let red: String = terminal
                .backend()
                .buffer()
                .content
                .iter()
                .filter(|cell| cell.fg == Color::Red)
                .map(|cell| cell.symbol())
                .collect();
            assert_eq!(red, if now > expiry { &timestamp } else { "" });
        }
    }

    #[test]
    fn starts_at_leaf_and_switching_certificates_resets_scroll_but_keeps_hash() {
        let data = entry(vec![
            metadata_certificate("leaf", "root", &[1], &[]),
            metadata_certificate("root", "root", &[2], &[]),
        ]);
        let mut view = EntryDetails::new(0, &data, PathBuf::new());
        let screen = draw(&mut view, &data, 100, 50);
        assert!(screen.find("CN=root").unwrap() < screen.find("CN=leaf").unwrap());
        assert!(view.text(&data, 0).to_string().contains("Subject: CN=leaf"));
        assert!(!view.details_focused);
        view.handle_key(KeyCode::Char('f'));
        view.handle_key(KeyCode::End);
        view.handle_key(KeyCode::Up);
        assert_eq!(view.scroll, 0);
        assert!(view.text(&data, 0).to_string().contains("Subject: CN=root"));
        assert!(
            view.text(&data, 0)
                .to_string()
                .contains("Fingerprint (SHA-1)")
        );
        view.handle_key(KeyCode::Char('j'));
        assert!(view.text(&data, 0).to_string().contains("Subject: CN=leaf"));
    }

    #[test]
    fn wrapped_values_remain_accessible_with_scrolling_and_resizing() {
        let long_name = format!("{}THE-END", "long-name-界".repeat(30));
        let data = entry(vec![metadata_certificate(&long_name, "root", &[1], &[])]);
        let mut view = EntryDetails::new(0, &data, PathBuf::new());
        assert!(!draw(&mut view, &data, 40, 24).contains("THE-END"));
        view.handle_key(KeyCode::Tab);
        assert!(view.details_focused);
        let mut seen = String::new();
        for _ in 0..view.max_scroll + 1 {
            seen.push_str(&draw(&mut view, &data, 40, 24));
            view.handle_key(KeyCode::Char('j'));
        }
        assert!(seen.contains("THE-END"));
        assert!(seen.contains("Signature Algorithm:"));
        assert!(seen.contains("Fingerprint (SHA-256):"));
        assert!(seen.contains("verified."));
        assert!(view.scroll > 0);
        view.handle_key(KeyCode::Home);
        assert_eq!(view.scroll, 0);
        view.handle_key(KeyCode::PageDown);
        assert!(view.scroll > 0);
        view.handle_key(KeyCode::PageUp);
        assert_eq!(view.scroll, 0);
        view.handle_key(KeyCode::End);
        assert_eq!(view.scroll, view.max_scroll);
        draw(&mut view, &data, 160, 100);
        assert_eq!(view.scroll, 0);
    }

    #[test]
    fn extensions_section_follows_fields_and_marks_critical() {
        let critical_ca = der::sequence(
            &[
                der::oid(&ObjectIdentifier::new(&[2, 5, 29, 19]).unwrap()),
                der::boolean(true),
                der::octet_string(&der::sequence(&der::boolean(true))),
            ]
            .concat(),
        );
        let data = entry(vec![
            metadata_certificate("leaf", "root", &[1], &[critical_ca]),
            metadata_certificate("root", "root", &[2], &[]),
        ]);
        let mut view = EntryDetails::new(0, &data, PathBuf::new());
        let text = view.text(&data, 0).to_string();
        let fingerprint = text.find("Fingerprint (SHA-256)").unwrap();
        let section = text.find("Extensions:\n  Basic Constraints (2.5.29.19) [critical]\n    CA: true, path length: unlimited\n").unwrap();
        assert!(fingerprint < section);
        assert!(section < text.find("trust is not verified").unwrap());
        view.handle_key(KeyCode::Up);
        assert!(view.text(&data, 0).to_string().contains("Extensions: None"));
    }

    #[test]
    fn unreadable_certificates_do_not_hide_other_members() {
        let data = entry(vec![
            b"unreadable".to_vec(),
            metadata_certificate("root", "root", &[2], &[]),
        ]);
        let mut view = EntryDetails::new(0, &data, PathBuf::new());
        let screen = draw(&mut view, &data, 100, 30);
        assert!(screen.contains("Certificate 1"));
        assert!(screen.contains("Certificate could not be decoded"));
        assert!(screen.contains("Fingerprint (SHA-256)"));
        view.handle_key(KeyCode::Up);
        assert!(draw(&mut view, &data, 100, 50).contains("Subject: CN=root"));
    }

    #[test]
    fn hierarchy_marks_each_signature_check() {
        use crate::test_support::ed25519_certificate;
        let data = entry(vec![
            ed25519_certificate("leaf", "intermediate", 3, 2),
            ed25519_certificate("intermediate", "root", 2, 9),
            ed25519_certificate("root", "root", 1, 1),
        ]);
        let mut view = EntryDetails::new(0, &data, PathBuf::new());
        let screen = draw(&mut view, &data, 100, 50);
        assert!(screen.contains("CN=root [verified]"));
        assert!(screen.contains("CN=intermediate [bad signature]"));
        assert!(screen.contains("CN=leaf [verified]"));
        let line = |view: &EntryDetails| {
            let text = view.text(&data, 0).to_string();
            text.lines()
                .find(|line| line.starts_with("Signature: "))
                .unwrap()
                .to_string()
        };
        assert_eq!(
            line(&view),
            "Signature: verified with the public key of CN=intermediate."
        );
        view.handle_key(KeyCode::Up);
        assert_eq!(
            line(&view),
            "Signature: does not verify with the public key of CN=root: the issuer's public key did not make it."
        );
        view.handle_key(KeyCode::Up);
        assert_eq!(
            line(&view),
            "Signature: verified with its own public key (self-signed)."
        );

        let lone = entry(vec![ed25519_certificate("leaf", "missing", 3, 2)]);
        let mut view = EntryDetails::new(0, &lone, PathBuf::new());
        assert!(draw(&mut view, &lone, 100, 50).contains("CN=leaf [unchecked]"));
        assert!(
            view.text(&lone, 0)
                .to_string()
                .contains("Signature: not checked (the issuer certificate is not stored).")
        );
        let unreadable = entry(vec![b"unreadable".to_vec(), data.certificates[2].clone()]);
        let view = EntryDetails::new(0, &unreadable, PathBuf::new());
        assert_eq!(
            view.signatures[0],
            Some(Signature::Unchecked("the certificate could not be decoded"))
        );
    }

    #[test]
    fn long_hierarchy_scrolls_and_tiny_terminals_do_not_panic() {
        let certificates = (0..30)
            .map(|i| metadata_certificate(&format!("certificate-{i}"), "issuer", &[1], &[]))
            .collect();
        let data = entry(certificates);
        let mut view = EntryDetails::new(0, &data, PathBuf::new());
        assert!(draw(&mut view, &data, 80, 24).contains("CN=certificate-0"));
        for _ in 0..29 {
            view.handle_key(KeyCode::Up);
        }
        assert!(draw(&mut view, &data, 80, 24).contains("CN=certificate-29"));
        for (width, height) in [(0, 0), (1, 1), (10, 5), (30, 10), (20, 30)] {
            draw(&mut view, &data, width, height);
        }
        assert!(draw(&mut view, &data, 40, 8).contains("Resize terminal"));
    }

    fn document_entry(document: keystore::Document, certificates: Vec<Vec<u8>>) -> KeystoreEntry {
        KeystoreEntry {
            document: Some(document),
            ..entry(certificates)
        }
    }

    #[test]
    fn requests_show_attributes_requested_extensions_and_their_own_signature() {
        use crate::test_support::ed25519_request;
        let challenge = der::sequence(
            &[
                der::oid(&ObjectIdentifier::new(&[1, 2, 840, 113549, 1, 9, 7]).unwrap()),
                der::set(&der::utf8_string("synthetic-challenge")),
            ]
            .concat(),
        );
        let san = der::sequence(
            &[
                der::oid(&ObjectIdentifier::new(&[2, 5, 29, 17]).unwrap()),
                der::octet_string(&der::sequence(&der::implicit(2, false, b"example.test"))),
            ]
            .concat(),
        );
        let request_extensions = der::sequence(
            &[
                der::oid(&ObjectIdentifier::new(&[1, 2, 840, 113549, 1, 9, 14]).unwrap()),
                der::set(&der::sequence(&san)),
            ]
            .concat(),
        );
        let data = document_entry(
            keystore::Document::Request,
            vec![ed25519_request("web", &[challenge, request_extensions], 5)],
        );
        let mut view = EntryDetails::new(0, &data, PathBuf::new());
        assert!(draw(&mut view, &data, 100, 50).contains("Request: CN=web [verified]"));
        let text = view.text(&data, 0).to_string();
        for expected in [
            "Subject: CN=web\n\nPublic Key: Ed25519 255 bits\n\nSignature Algorithm: Ed25519\nSignature: verified with its own public key (proof of possession).\n\nFingerprint (SHA-256): ",
            "Attributes:\n  Challenge Password (1.2.840.113549.1.9.7)\n    Present; not shown\n\n",
            "Requested Extensions:\n  Subject Alternative Name (2.5.29.17)\n    DNS: example.test\n\n",
            "Only the request's signature is checked",
        ] {
            assert!(text.contains(expected), "{expected}");
        }
        assert!(!text.contains("synthetic-challenge"));
        assert!(!text.contains("Issuer"));

        let unreadable = document_entry(keystore::Document::Request, vec![b"junk".to_vec()]);
        let mut view = EntryDetails::new(0, &unreadable, PathBuf::new());
        let screen = draw(&mut view, &unreadable, 100, 50);
        assert!(screen.contains("Request (unreadable or unnamed) [unchecked]"));
        assert!(screen.contains("Request could not be decoded."));
    }

    #[test]
    fn revocation_lists_show_entries_staleness_and_the_issuer_signature() {
        use crate::test_support::{
            ed25519_certificate, ed25519_revocation_list, revoked_certificate,
        };
        let reason = der::sequence(
            &[
                der::oid(&ObjectIdentifier::new(&[2, 5, 29, 21]).unwrap()),
                der::octet_string(&der::tlv(der::Tag::universal(10), &[4])),
            ]
            .concat(),
        );
        let list = ed25519_revocation_list(
            "root",
            Some(1_000_000_000),
            &[revoked_certificate(&[0x0a], &[reason])],
            &[],
            1,
        );
        let root = ed25519_certificate("root", "root", 1, 1);
        let data = document_entry(
            keystore::Document::RevocationList,
            vec![list.clone(), root.clone()],
        );
        let mut view = EntryDetails::new(0, &data, PathBuf::new());
        let screen = draw(&mut view, &data, 100, 50);
        assert!(screen.contains("CN=root [verified]"));
        assert!(screen.contains("  Revocation list: CN=root [verified]"));
        let text = view.text(&data, 0).to_string();
        for expected in [
            "Issuer: CN=root\n\nThis Update: 2024-01-01 00:00:00 UTC\nNext Update: 2001-09-09 01:46:40 UTC\n\nSignature Algorithm: Ed25519\nSignature: verified with the public key of CN=root.",
            "Extensions: None\n\nRevoked Certificates: 1\n  Serial Number: 0x0A (10)\n    Revoked: 2024-01-01 00:00:00 UTC\n    Reason Code (2.5.29.21)\n      Superseded\n\nStored certificates only",
        ] {
            assert!(text.contains(expected), "{expected}");
        }
        let mut terminal = Terminal::new(TestBackend::new(100, 50)).unwrap();
        terminal
            .draw(|frame| {
                frame.render_widget(
                    Paragraph::new(view.text(&data, 1_000_000_001)).wrap(Wrap { trim: false }),
                    frame.area(),
                );
            })
            .unwrap();
        let red: String = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .filter(|cell| cell.fg == Color::Red)
            .map(|cell| cell.symbol())
            .collect();
        assert_eq!(red, "2001-09-09 01:46:40 UTC");

        let alone = document_entry(keystore::Document::RevocationList, vec![list]);
        let mut view = EntryDetails::new(0, &alone, PathBuf::new());
        assert!(draw(&mut view, &alone, 100, 50).contains("Revocation list: CN=root [unchecked]"));
        assert!(
            view.text(&alone, 0)
                .to_string()
                .contains("Signature: not checked (the issuer certificate is not stored).")
        );
    }

    #[test]
    fn long_revocation_lists_are_counted_but_not_all_listed() {
        use crate::test_support::{ed25519_revocation_list, revoked_certificate};
        let revoked: Vec<_> = (0..document::MAX_REVOKED_SHOWN + 2)
            .map(|i| revoked_certificate(&(i as u32 + 1).to_be_bytes(), &[]))
            .collect();
        let data = document_entry(
            keystore::Document::RevocationList,
            vec![ed25519_revocation_list("root", None, &revoked, &[], 1)],
        );
        let view = EntryDetails::new(0, &data, PathBuf::new());
        let text = view.text(&data, 0).to_string();
        assert!(text.contains("Revoked Certificates: 5002\n"));
        assert!(text.contains("(5000)\n"));
        assert!(!text.contains("(5001)\n"));
        assert!(text.contains("  2 more are not listed.\n"));
    }

    #[test]
    fn exports_use_each_member_pem_label() {
        use crate::test_support::{TestDirectory, ed25519_certificate, ed25519_revocation_list};
        use crown::asn1::pem;
        use ratatui::crossterm::event::KeyModifiers;
        let directory = TestDirectory::new();
        let list = ed25519_revocation_list("root", None, &[], &[], 1);
        let root = ed25519_certificate("root", "root", 1, 1);
        let data = KeystoreEntry {
            alias: "ca".into(),
            ..document_entry(
                keystore::Document::RevocationList,
                vec![list.clone(), root.clone()],
            )
        };
        let mut view = EntryDetails::new(0, &data, directory.path().to_path_buf());
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        view.handle_event(key(KeyCode::Char('x')), &data);
        assert!(draw(&mut view, &data, 100, 50).contains("Save revocation list to: "));
        view.handle_event(key(KeyCode::Enter), &data);
        assert_eq!(
            view.message,
            Some((
                format!(
                    "Saved revocation list to '{}'.",
                    directory.path().join("ca.pem").display()
                ),
                false
            ))
        );
        let saved =
            pem::parse(&std::fs::read_to_string(directory.path().join("ca.pem")).unwrap()).unwrap();
        assert_eq!(
            (saved[0].label.as_str(), &saved[0].data),
            ("X509 CRL", &list)
        );
        view.handle_event(key(KeyCode::Char('X')), &data);
        view.handle_event(key(KeyCode::Enter), &data);
        let saved =
            pem::parse(&std::fs::read_to_string(directory.path().join("ca-chain.pem")).unwrap())
                .unwrap();
        let labels: Vec<_> = saved.iter().map(|block| block.label.as_str()).collect();
        assert_eq!(labels, ["X509 CRL", "CERTIFICATE"]);
        assert_eq!(saved[1].data, root);
        view.handle_key(KeyCode::Up);
        view.handle_event(key(KeyCode::Char('x')), &data);
        assert!(draw(&mut view, &data, 100, 50).contains("Save certificate to: "));
    }
}
