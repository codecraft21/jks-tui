//! Full-screen, read-only entry inspection, independent of the entry table state.
use ratatui::{
    Frame,
    crossterm::event::KeyCode,
    layout::{Constraint, Layout},
    style::{Color, Style, Stylize},
    widgets::{Block, Paragraph, Row, Table, TableState, Wrap},
};

use crate::{
    certificate::{
        self,
        details::{Details, fingerprint, time_text},
    },
    keystore::KeystoreEntry,
};

pub struct EntryDetails {
    pub entry: usize,
    hierarchy: TableState,
    metadata: Vec<Option<Details>>,
    details_focused: bool,
    sha1: bool,
    scroll: u16,
    page: u16,
    max_scroll: u16,
}

impl EntryDetails {
    pub fn new(entry: usize, data: &KeystoreEntry) -> Self {
        Self {
            entry,
            hierarchy: TableState::default().with_selected(data.certificates.len().checked_sub(1)),
            metadata: data
                .certificates
                .iter()
                .map(|der| Details::parse(der).ok())
                .collect(),
            details_focused: false,
            sha1: false,
            scroll: 0,
            page: 1,
            max_scroll: 0,
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

    fn text(&self, entry: &KeystoreEntry) -> String {
        let mut text = format!("Alias: {}\nType: {}\n\n", entry.alias, entry.kind);
        if let Some(warning) = entry.chain_warning {
            text.push_str(&format!("{warning}\n\n"));
        }
        let Some(index) = self
            .hierarchy
            .selected()
            .map(|i| self.metadata.len() - 1 - i)
        else {
            text.push_str("No certificate is stored with this entry.");
            return text;
        };
        if let Some(info) = &self.metadata[index] {
            let public_key = certificate::summarize(&entry.certificates[index]).map_or_else(
                || "Unavailable".into(),
                |summary| format!("{} {}", summary.algorithm, summary.key_size_text()),
            );
            text.push_str(&format!(
                "Version: {}\n\nSubject: {}\n\nIssuer: {}\n\nSerial Number (hex): {}\n\nSerial Number (dec): {}\n\nValid From: {}\n\nValid Until: {}\n\nPublic Key: {}\n\nSignature Algorithm: {}\n\n",
                info.version, info.subject, info.issuer, info.serial_hex, info.serial_decimal,
                time_text(&info.not_before), time_text(&info.not_after), public_key, info.signature_algorithm,
            ));
        } else {
            text.push_str("Certificate could not be decoded.\n\n");
        }
        text.push_str(&format!(
            "Fingerprint ({}): {}\n\nStored certificates only; trust is not verified.",
            if self.sha1 { "SHA-1" } else { "SHA-256" },
            fingerprint(&entry.certificates[index], self.sha1)
        ));
        if entry.chain_warning.is_none()
            && self
                .metadata
                .last()
                .and_then(Option::as_ref)
                .is_some_and(|info| info.issuer != info.subject)
        {
            text.push_str("\nIssuer certificate is not stored in this chain.");
        }
        text
    }

    pub fn draw(&mut self, frame: &mut Frame, entry: &KeystoreEntry) {
        let area = frame.area();
        let shortcuts = Paragraph::new("Tab Focus | ↑/↓ j/k Navigate | PgUp/PgDn Home/End Scroll\nf SHA-256/SHA-1 | Esc Back | q / Ctrl+C Quit").wrap(Wrap { trim: false });
        let footer_height = u16::try_from(shortcuts.line_count(area.width)).unwrap_or(u16::MAX);
        if area.width < 20 || area.height < footer_height.saturating_add(10) {
            frame.render_widget(
                Paragraph::new("Resize terminal for entry details. Esc Back | q / Ctrl+C Quit")
                    .wrap(Wrap { trim: false }),
                area,
            );
            return;
        }
        let [header, content, footer] = Layout::vertical([
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
                        let label = info
                            .as_ref()
                            .map(|info| info.subject.to_string())
                            .filter(|name| !name.is_empty())
                            .unwrap_or_else(|| {
                                format!("Certificate {} (unreadable or unnamed)", index + 1)
                            });
                        Row::new([format!("{}{}", "  ".repeat(depth.min(8)), label)])
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
        let paragraph = Paragraph::new(self.text(entry)).wrap(Wrap { trim: false });
        self.page = inner.height.max(1);
        self.max_scroll = u16::try_from(
            paragraph
                .line_count(inner.width)
                .saturating_sub(usize::from(inner.height)),
        )
        .unwrap_or(u16::MAX);
        self.scroll = self.scroll.min(self.max_scroll);
        frame.render_widget(paragraph.scroll((self.scroll, 0)).block(block), details);
        frame.render_widget(shortcuts, footer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::metadata_certificate;
    use ratatui::{Terminal, backend::TestBackend};

    fn entry(certificates: Vec<Vec<u8>>) -> KeystoreEntry {
        KeystoreEntry {
            alias: "test-entry".into(),
            kind: "Private key",
            certificate: None,
            certificates,
            chain_warning: None,
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
    fn starts_at_leaf_and_switching_certificates_resets_scroll_but_keeps_hash() {
        let data = entry(vec![
            metadata_certificate("leaf", "root", &[1], &[]),
            metadata_certificate("root", "root", &[2], &[]),
        ]);
        let mut view = EntryDetails::new(0, &data);
        let screen = draw(&mut view, &data, 100, 50);
        assert!(screen.find("CN=root").unwrap() < screen.find("CN=leaf").unwrap());
        assert!(view.text(&data).contains("Subject: CN=leaf"));
        assert!(!view.details_focused);
        view.handle_key(KeyCode::Char('f'));
        view.handle_key(KeyCode::End);
        view.handle_key(KeyCode::Up);
        assert_eq!(view.scroll, 0);
        assert!(view.text(&data).contains("Subject: CN=root"));
        assert!(view.text(&data).contains("Fingerprint (SHA-1)"));
        view.handle_key(KeyCode::Char('j'));
        assert!(view.text(&data).contains("Subject: CN=leaf"));
    }

    #[test]
    fn wrapped_values_remain_accessible_with_scrolling_and_resizing() {
        let long_name = format!("{}THE-END", "long-name-界".repeat(30));
        let data = entry(vec![metadata_certificate(&long_name, "root", &[1], &[])]);
        let mut view = EntryDetails::new(0, &data);
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
    fn unreadable_certificates_do_not_hide_other_members() {
        let data = entry(vec![
            b"unreadable".to_vec(),
            metadata_certificate("root", "root", &[2], &[]),
        ]);
        let mut view = EntryDetails::new(0, &data);
        let screen = draw(&mut view, &data, 100, 30);
        assert!(screen.contains("Certificate 1"));
        assert!(screen.contains("Certificate could not be decoded"));
        assert!(screen.contains("Fingerprint (SHA-256)"));
        view.handle_key(KeyCode::Up);
        assert!(draw(&mut view, &data, 100, 50).contains("Subject: CN=root"));
    }

    #[test]
    fn long_hierarchy_scrolls_and_tiny_terminals_do_not_panic() {
        let certificates = (0..30)
            .map(|i| metadata_certificate(&format!("certificate-{i}"), "issuer", &[1], &[]))
            .collect();
        let data = entry(certificates);
        let mut view = EntryDetails::new(0, &data);
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
}
