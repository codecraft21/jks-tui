//! Full-screen, read-only entry inspection, independent of the entry table state.
//! A certificate request entry shows the request in place of a hierarchy.
mod chain;
mod request;

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
    certificate::{Summary, details::fingerprint, extensions::Extension, signature::Signature},
    export::{self, ExportPrompt, Outcome, Scope},
    keystore::{Content, KeystoreEntry},
};
use chain::ChainView;
use request::RequestView;

/// An indented section; each extension's title is followed by its decoded values.
fn extensions_text(heading: &str, extensions: &[Extension]) -> String {
    let items: Vec<_> = extensions
        .iter()
        .map(|extension| (extension.title(), extension.lines.clone()))
        .collect();
    section_text(heading, &items)
}

/// An indented section of titled items, or `<heading>: None` when empty.
fn section_text(heading: &str, items: &[(String, Vec<String>)]) -> String {
    if items.is_empty() {
        return format!("{heading}: None\n\n");
    }
    let mut text = format!("{heading}:\n");
    for (title, lines) in items {
        text.push_str(&format!("  {title}\n"));
        for line in lines {
            text.push_str(&format!("    {line}\n"));
        }
    }
    text.push('\n');
    text
}

/// The public key's algorithm and size, or `Unavailable` when it cannot be read.
fn public_key_text(summary: Option<&Summary>) -> String {
    summary.map_or_else(
        || "Unavailable".into(),
        |summary| format!("{} {}", summary.algorithm, summary.key_size_text()),
    )
}

/// A highlighted line for each weakness.
fn weakness_lines(summary: Option<&Summary>) -> Vec<Line<'static>> {
    summary
        .iter()
        .flat_map(|summary| &summary.weaknesses)
        .map(|weakness| Line::from(format!("Weak: {weakness}.")).yellow())
        .collect()
}

/// The fingerprint paragraph, in SHA-1 or SHA-256.
fn fingerprint_text(der: &[u8], sha1: bool) -> String {
    format!(
        "Fingerprint ({}): {}\n\n",
        if sha1 { "SHA-1" } else { "SHA-256" },
        fingerprint(der, sha1)
    )
}

/// A signature check's details line, naming the key it used.
fn signature_line(result: Signature, key: &str) -> Line<'static> {
    match result {
        Signature::Verified => Line::from(format!("Signature: verified with {key}.")).green(),
        Signature::Failed(reason) => {
            Line::from(format!("Signature: does not verify with {key}: {reason}.")).red()
        }
        Signature::Unchecked(reason) => Line::from(format!("Signature: not checked ({reason}).")),
    }
}

/// A hierarchy row: the label, then a `[weak]` tag and the signature tag.
fn hierarchy_row(label: String, weak: bool, signature: Option<Signature>) -> Row<'static> {
    let mut spans = vec![Span::raw(label)];
    if weak {
        spans.extend([Span::raw(" "), Span::raw("[weak]").yellow()]);
    }
    spans.push(Span::raw(" "));
    spans.push(match signature {
        Some(Signature::Verified) => Span::raw("[verified]").green(),
        Some(Signature::Failed(_)) => Span::raw("[bad signature]").red(),
        Some(Signature::Unchecked(_)) | None => Span::raw("[unchecked]"),
    });
    Row::new([Line::from(spans)])
}

/// What the view shows, from the entry's content.
enum View {
    Chain(ChainView),
    Request(RequestView),
}

pub struct EntryDetails {
    alias: String,
    kind: &'static str,
    hierarchy: TableState,
    view: View,
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
    /// Decodes the entry once. The view keeps what it shows, so it does not
    /// depend on the entry table afterwards.
    pub fn new(entry: &KeystoreEntry, directory: PathBuf) -> Self {
        let view = match &entry.content {
            Content::Certificates { certificates, .. } => {
                View::Chain(ChainView::new(certificates, entry.chain_warning))
            }
            Content::Request(der) => {
                View::Request(RequestView::new(der, entry.certificate.clone()))
            }
        };
        let mut details = Self {
            alias: entry.alias.clone(),
            kind: entry.kind(),
            hierarchy: TableState::default(),
            // A request has no hierarchy to navigate, so its details take the keys.
            details_focused: matches!(view, View::Request(_)),
            view,
            sha1: false,
            scroll: 0,
            page: 1,
            max_scroll: 0,
            directory,
            export: None,
            message: None,
        };
        details.hierarchy.select(details.rows().checked_sub(1));
        details
    }

    /// Whether keys are typed into an export file name instead of acting as shortcuts.
    pub fn exporting(&self) -> bool {
        self.export.is_some()
    }

    /// Handles a key press; returns `true` when the view should close.
    pub fn handle_event(&mut self, key: KeyEvent) -> bool {
        if let Some(prompt) = &mut self.export {
            match prompt.handle_key(key) {
                Outcome::Editing => self.message = None,
                Outcome::Cancelled => {
                    self.export = None;
                    self.message = None;
                }
                Outcome::Save(path) => {
                    let scope = prompt.scope;
                    match export::save(&path, &self.export_items(scope), scope.pem_label()) {
                        Ok(()) => {
                            self.export = None;
                            self.message = Some((
                                format!("Saved {} to '{}'.", scope.label(), path.display()),
                                false,
                            ));
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
            KeyCode::Char(letter @ ('x' | 'X')) => {
                if let Some(scope) = self.export_scope(letter == 'X') {
                    self.export = Some(ExportPrompt::new(scope, &self.directory, &self.alias));
                }
            }
            code => self.handle_key(code),
        }
        false
    }

    /// What `x` exports: the request, or the selected certificate. With
    /// `whole_chain` (`X`), the selected certificate's chain instead, which a
    /// request does not have. `None` when there is nothing to export.
    fn export_scope(&self, whole_chain: bool) -> Option<Scope> {
        match &self.view {
            View::Request(_) => (!whole_chain).then_some(Scope::Request),
            View::Chain(chain) => {
                self.selected(chain)?;
                Some(if whole_chain {
                    Scope::Chain
                } else {
                    Scope::Certificate
                })
            }
        }
    }

    /// The DER an export of `scope` saves.
    fn export_items(&self, scope: Scope) -> Vec<Vec<u8>> {
        match (&self.view, scope) {
            (View::Request(view), _) => vec![view.der.clone()],
            (View::Chain(chain), Scope::Chain) => chain.certificates.clone(),
            (View::Chain(chain), _) => self
                .selected(chain)
                .map(|index| vec![chain.certificates[index].clone()])
                .unwrap_or_default(),
        }
    }

    /// The stored-certificate index selected in the chain's hierarchy.
    fn selected(&self, chain: &ChainView) -> Option<usize> {
        self.hierarchy
            .selected()
            .map(|i| chain.certificates.len() - 1 - i)
    }

    /// The number of rows in the hierarchy pane.
    fn rows(&self) -> usize {
        match &self.view {
            View::Chain(chain) => chain.certificates.len(),
            View::Request(_) => 1,
        }
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
                    self.select((index + 1).min(self.rows().saturating_sub(1)));
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

    fn text(&self, now: i64) -> Text<'static> {
        let text = format!("Alias: {}\nType: {}\n\n", self.alias, self.kind);
        match &self.view {
            View::Request(view) => view.text(text, self.sha1),
            View::Chain(chain) => chain.text(text, self.selected(chain), now, self.sha1),
        }
    }

    pub fn draw(&mut self, frame: &mut Frame) {
        let area = frame.area();
        let (shortcuts, tree_title, details_title) = match &self.view {
            View::Chain(_) => (
                "Tab Focus | ↑/↓ j/k Navigate | PgUp/PgDn Home/End Scroll\nf SHA-256/SHA-1 | x Export certificate | X Export chain | Esc Back | q / Ctrl+C Quit",
                "Certificate hierarchy",
                "Certificate details",
            ),
            View::Request(_) => (
                "Tab Focus | ↑/↓ j/k Scroll | PgUp/PgDn Home/End Scroll\nf SHA-256/SHA-1 | x Export request | Esc Back | q / Ctrl+C Quit",
                "Certificate request",
                "Request details",
            ),
        };
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
            Paragraph::new(format!("{} — {}", self.alias, self.kind))
                .blue()
                .bold(),
            header,
        );
        let tree_height = (content.height / 3)
            .min(
                u16::try_from(self.rows())
                    .unwrap_or(u16::MAX)
                    .saturating_add(2),
            )
            .max(3);
        let [hierarchy, details] =
            Layout::vertical([Constraint::Length(tree_height), Constraint::Min(3)]).areas(content);
        let focused = |focus| if focus { Color::Blue } else { Color::Reset };
        let tree_block = Block::bordered()
            .title(if self.details_focused {
                format!(" {tree_title} ")
            } else {
                format!(" {tree_title} [focused] ")
            })
            .border_style(Style::default().fg(focused(!self.details_focused)));
        let rows = match &self.view {
            View::Chain(chain) => chain.hierarchy_rows(),
            View::Request(view) => vec![view.hierarchy_row()],
        };
        if rows.is_empty() {
            frame.render_widget(
                Paragraph::new("No certificate").block(tree_block),
                hierarchy,
            );
        } else {
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
                format!(" {details_title} [focused] ")
            } else {
                format!(" {details_title} ")
            })
            .border_style(Style::default().fg(focused(self.details_focused)));
        let inner = block.inner(details);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs() as i64);
        let paragraph = Paragraph::new(self.text(now)).wrap(Wrap { trim: false });
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
                Span::raw(format!("Save {} to: ", prompt.scope.label())).bold(),
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
    use crate::{
        certificate::details::time_text, keystore::Kind, test_support::metadata_certificate,
    };
    use crown::asn1::{der, oid::ObjectIdentifier};
    use ratatui::{Terminal, backend::TestBackend};
    use std::path::Path;

    fn entry(certificates: Vec<Vec<u8>>) -> KeystoreEntry {
        KeystoreEntry {
            alias: "test-entry".into(),
            certificate: None,
            content: Content::Certificates {
                kind: Kind::PrivateKey,
                certificates,
            },
            chain_warning: None,
        }
    }

    fn draw(details: &mut EntryDetails, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| details.draw(frame)).unwrap();
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
        let view = EntryDetails::new(&data, PathBuf::new());
        let View::Chain(chain) = &view.view else {
            panic!("a certificate entry shows its chain");
        };
        let info = chain.metadata[0].as_ref().unwrap();
        let expiry = info.not_after.to_unix();
        let timestamp = time_text(&info.not_after);
        for now in [expiry - 1, expiry, expiry + 1] {
            let mut terminal = Terminal::new(TestBackend::new(100, 50)).unwrap();
            terminal
                .draw(|frame| {
                    frame.render_widget(
                        Paragraph::new(view.text(now)).wrap(Wrap { trim: false }),
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
        let mut view = EntryDetails::new(&data, PathBuf::new());
        let screen = draw(&mut view, 100, 50);
        assert!(screen.find("CN=root").unwrap() < screen.find("CN=leaf").unwrap());
        assert!(view.text(0).to_string().contains("Subject: CN=leaf"));
        assert!(!view.details_focused);
        view.handle_key(KeyCode::Char('f'));
        view.handle_key(KeyCode::End);
        view.handle_key(KeyCode::Up);
        assert_eq!(view.scroll, 0);
        assert!(view.text(0).to_string().contains("Subject: CN=root"));
        assert!(view.text(0).to_string().contains("Fingerprint (SHA-1)"));
        view.handle_key(KeyCode::Char('j'));
        assert!(view.text(0).to_string().contains("Subject: CN=leaf"));
    }

    #[test]
    fn wrapped_values_remain_accessible_with_scrolling_and_resizing() {
        let long_name = format!("{}THE-END", "long-name-界".repeat(30));
        let data = entry(vec![metadata_certificate(&long_name, "root", &[1], &[])]);
        let mut view = EntryDetails::new(&data, PathBuf::new());
        assert!(!draw(&mut view, 40, 24).contains("THE-END"));
        view.handle_key(KeyCode::Tab);
        assert!(view.details_focused);
        let mut seen = String::new();
        for _ in 0..view.max_scroll + 1 {
            seen.push_str(&draw(&mut view, 40, 24));
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
        draw(&mut view, 160, 100);
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
        let mut view = EntryDetails::new(&data, PathBuf::new());
        let text = view.text(0).to_string();
        let fingerprint = text.find("Fingerprint (SHA-256)").unwrap();
        let section = text.find("Extensions:\n  Basic Constraints (2.5.29.19) [critical]\n    CA: true, path length: unlimited\n").unwrap();
        assert!(fingerprint < section);
        assert!(section < text.find("trust is not verified").unwrap());
        view.handle_key(KeyCode::Up);
        assert!(view.text(0).to_string().contains("Extensions: None"));
    }

    #[test]
    fn unreadable_certificates_do_not_hide_other_members() {
        let data = entry(vec![
            b"unreadable".to_vec(),
            metadata_certificate("root", "root", &[2], &[]),
        ]);
        let mut view = EntryDetails::new(&data, PathBuf::new());
        let screen = draw(&mut view, 100, 30);
        assert!(screen.contains("Certificate 1"));
        assert!(screen.contains("Certificate could not be decoded"));
        assert!(screen.contains("Fingerprint (SHA-256)"));
        view.handle_key(KeyCode::Up);
        assert!(draw(&mut view, 100, 50).contains("Subject: CN=root"));
    }

    #[test]
    fn hierarchy_marks_each_signature_check() {
        use crate::test_support::ed25519_certificate;
        let data = entry(vec![
            ed25519_certificate("leaf", "intermediate", 3, 2),
            ed25519_certificate("intermediate", "root", 2, 9),
            ed25519_certificate("root", "root", 1, 1),
        ]);
        let mut view = EntryDetails::new(&data, PathBuf::new());
        let screen = draw(&mut view, 100, 50);
        assert!(screen.contains("CN=root [verified]"));
        assert!(screen.contains("CN=intermediate [bad signature]"));
        assert!(screen.contains("CN=leaf [verified]"));
        let line = |view: &EntryDetails| {
            let text = view.text(0).to_string();
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
            "Signature: does not verify with the public key of CN=root: the signature does not match."
        );
        view.handle_key(KeyCode::Up);
        assert_eq!(
            line(&view),
            "Signature: verified with its own public key (self-signed)."
        );

        let lone = entry(vec![ed25519_certificate("leaf", "missing", 3, 2)]);
        let mut view = EntryDetails::new(&lone, PathBuf::new());
        assert!(draw(&mut view, 100, 50).contains("CN=leaf [unchecked]"));
        assert!(
            view.text(0)
                .to_string()
                .contains("Signature: not checked (the issuer certificate is not stored).")
        );
        let unreadable = entry(vec![b"unreadable".to_vec(), data.certificates()[2].clone()]);
        let view = EntryDetails::new(&unreadable, PathBuf::new());
        let View::Chain(chain) = &view.view else {
            panic!("a certificate entry shows its chain");
        };
        assert_eq!(
            chain.signatures[0],
            Some(Signature::Unchecked("the certificate could not be decoded"))
        );
    }

    #[test]
    fn request_entries_show_the_request_and_export_it() {
        use crate::test_support::{KEYTOOL_REQUEST, TestDirectory, ed25519_request};
        use ratatui::crossterm::event::KeyModifiers;
        let press = |code| KeyEvent::new(code, KeyModifiers::NONE);
        let file = crate::certificate_file::parse(KEYTOOL_REQUEST).unwrap();
        let data = &file.entries[0];
        let directory = TestDirectory::new();
        let mut view = EntryDetails::new(data, directory.path().to_path_buf());
        assert!(view.details_focused);
        let screen = draw(&mut view, 120, 60);
        assert!(screen.contains(" Certificate request "));
        assert!(screen.contains(" Request details [focused] "));
        assert!(screen.contains("O=keystore-tui,CN=CSR TUI test fixture [verified]"));
        assert!(screen.contains("x Export request"));
        let text = view.text(0).to_string();
        for expected in [
            "Type: Certificate request\n\nVersion: 1\n\nSubject: O=keystore-tui,CN=CSR TUI test fixture\n\nPublic Key: EC 256 bits\n\nSignature Algorithm: SHA-384 with ECDSA\nSignature: verified with its own public key.\n",
            "Fingerprint (SHA-256): ",
            "Requested extensions:\n  Subject Key Identifier (2.5.29.14)\n",
            "    DNS: csr.example.test\n",
            "nothing in it is trusted",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in {text}");
        }
        assert!(!text.contains("Attributes:"));
        view.handle_key(KeyCode::Char('f'));
        assert!(view.text(0).to_string().contains("Fingerprint (SHA-1)"));

        assert!(!view.handle_event(press(KeyCode::Char('X'))));
        assert!(!view.exporting());
        view.handle_event(press(KeyCode::Char('x')));
        let prompt = view.export.as_ref().unwrap();
        assert_eq!(prompt.scope, Scope::Request);
        let path = directory.path().join("CSR_TUI_test_fixture.csr");
        assert_eq!(Path::new(&prompt.path), path);
        view.handle_event(press(KeyCode::Enter));
        assert!(!view.exporting());
        let saved = std::fs::read_to_string(&path).unwrap();
        let blocks = crown::asn1::pem::parse(&saved).unwrap();
        assert_eq!(blocks[0].label, "CERTIFICATE REQUEST");
        assert_eq!(Content::Request(blocks[0].data.clone()), data.content);

        let attributes = der::sequence(
            &[
                der::oid(&ObjectIdentifier::new(&[1, 2, 840, 113549, 1, 9, 7]).unwrap()),
                der::set(&der::utf8_string("synthetic")),
            ]
            .concat(),
        );
        let mut altered = ed25519_request("device", &[attributes]);
        let at = altered.windows(6).position(|w| w == b"device").unwrap();
        altered[at] = b'D';
        let altered_entry = KeystoreEntry {
            content: Content::Request(altered),
            ..entry(vec![])
        };
        let mut view = EntryDetails::new(&altered_entry, PathBuf::new());
        assert!(draw(&mut view, 100, 50).contains("CN=Device [bad signature]"));
        let text = view.text(0).to_string();
        assert!(text.contains(
            "Signature: does not verify with its own public key: the signature does not match."
        ));
        assert!(text.contains(
            "Attributes:\n  Challenge Password (1.2.840.113549.1.9.7)\n    Present; not shown.\n"
        ));
        assert!(!text.contains("synthetic"));
        // Trailing data still verifies, but the details cannot be read, so
        // the request is not reported as verified.
        let Content::Request(request) = &data.content else {
            panic!("the fixture is a request");
        };
        let trailing = [&request[..], &[0]].concat();
        for request in [b"junk".to_vec(), trailing] {
            let junk = KeystoreEntry {
                content: Content::Request(request),
                ..entry(vec![])
            };
            let mut view = EntryDetails::new(&junk, PathBuf::new());
            let screen = draw(&mut view, 100, 30);
            assert!(screen.contains("Certificate request (unreadable or unnamed) [unchecked]"));
            assert!(screen.contains("Certificate request could not be decoded."));
        }
    }

    #[test]
    fn long_hierarchy_scrolls_and_tiny_terminals_do_not_panic() {
        let certificates = (0..30)
            .map(|i| metadata_certificate(&format!("certificate-{i}"), "issuer", &[1], &[]))
            .collect();
        let data = entry(certificates);
        let mut view = EntryDetails::new(&data, PathBuf::new());
        assert!(draw(&mut view, 80, 24).contains("CN=certificate-0"));
        for _ in 0..29 {
            view.handle_key(KeyCode::Up);
        }
        assert!(draw(&mut view, 80, 24).contains("CN=certificate-29"));
        for (width, height) in [(0, 0), (1, 1), (10, 5), (30, 10), (20, 30)] {
            draw(&mut view, width, height);
        }
        assert!(draw(&mut view, 40, 8).contains("Resize terminal"));
    }
}
