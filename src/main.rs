mod certificate;
mod certificate_file;
mod entry_details;
mod entry_list;
mod export;
mod file_picker;
mod java_serialization;
mod keystore;
mod pkcs12;

#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;

use std::{
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

use ratatui::{
    DefaultTerminal, Frame,
    crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    layout::{Constraint, Layout},
    style::{Color, Style, Stylize},
    text::Line,
    widgets::{Block, Cell, Paragraph, Row, Table, TableState, Wrap},
};

use entry_list::{ExpiryStatus, SortOrder};
use file_picker::FilePicker;
use keystore::KeystoreEntry;
use zeroize::{Zeroize, Zeroizing};

/// Real keystores are far smaller; refuse to read arbitrarily large files.
const MAX_KEYSTORE_SIZE: u64 = 64 * 1024 * 1024;

/// Grows its buffer manually so no reallocation leaves a stale copy behind.
struct Password(Zeroizing<String>);

impl Default for Password {
    fn default() -> Self {
        Self(Zeroizing::new(String::with_capacity(64)))
    }
}

impl Password {
    fn push(&mut self, ch: char) {
        if self.0.len() + ch.len_utf8() > self.0.capacity() {
            let mut grown = String::with_capacity(self.0.capacity() * 2 + ch.len_utf8());
            grown.push_str(&self.0);
            // Dropping the old buffer wipes it.
            self.0 = Zeroizing::new(grown);
        }
        self.0.push(ch);
    }

    fn pop(&mut self) {
        let Some((index, _)) = self.0.char_indices().next_back() else {
            return;
        };
        // Wipe the removed character's bytes before shortening the buffer.
        let mut bytes = std::mem::take(&mut *self.0).into_bytes();
        bytes[index..].zeroize();
        bytes.truncate(index);
        *self.0 = String::from_utf8(bytes).expect("truncated at a char boundary");
    }

    fn clear(&mut self) {
        // Zeroes the whole allocation, including spare capacity.
        self.0.zeroize();
    }
}

struct PasswordPrompt {
    path: PathBuf,
    keystore: Store,
    password: Password,
}

#[derive(Default)]
struct App {
    keystore_path: Option<PathBuf>,
    file_picker: Option<FilePicker>,
    password_prompt: Option<PasswordPrompt>,
    entries: Vec<KeystoreEntry>,
    /// Indices into `entries` shown by the table, after filtering and sorting.
    /// `entries_state` selects a position in this list.
    visible: Vec<usize>,
    entries_state: TableState,
    filter: String,
    /// Whether keys are typed into the filter instead of acting as shortcuts.
    editing_filter: bool,
    sort: SortOrder,
    entry_details: Option<entry_details::EntryDetails>,
    error: Option<String>,
    /// Shown in yellow while the loaded file is displayed.
    warning: Option<&'static str>,
}

const INCOMPLETE_WARNING: &str = "Warning: this PKCS12 entry list is incomplete.";
const SKIPPED_WARNING: &str =
    "Warning: PEM blocks other than certificates, such as private keys, were not read.";

enum Loaded {
    Store(Store),
    Certificates(certificate_file::CertificateFile),
}

enum Store {
    Jks(keystore::Keystore),
    Pkcs12(pkcs12::Store),
}

impl Store {
    fn verify(self, password: &str) -> Result<pkcs12::Verified, Box<(Self, Option<&'static str>)>> {
        match self {
            Self::Jks(store) => store
                .verify(password)
                .map(|entries| pkcs12::Verified {
                    entries,
                    incomplete: false,
                })
                .map_err(|store| Box::new((Self::Jks(store), None))),
            Self::Pkcs12(store) => match store.verify(password) {
                Ok(verified) => Ok(verified),
                Err(pkcs12::VerifyError::Password) => Err(Box::new((Self::Pkcs12(store), None))),
                Err(pkcs12::VerifyError::Invalid(message)) => {
                    Err(Box::new((Self::Pkcs12(store), Some(message))))
                }
            },
        }
    }
}

impl App {
    fn handle_key(&mut self, key: KeyEvent) -> bool {
        if key.kind != KeyEventKind::Press {
            return false;
        }

        if (key.code == KeyCode::Char('q') && !self.typing())
            || (key.code == KeyCode::Char('c')
                && key.modifiers.contains(KeyModifiers::CONTROL)
                && !key.modifiers.contains(KeyModifiers::ALT))
        {
            return true;
        }

        if self.password_prompt.is_some() {
            self.handle_password(key);
        } else if let Some(picker) = &mut self.file_picker {
            if key.code == KeyCode::Esc {
                self.file_picker = None;
            } else if let Some(path) = picker.handle_key(key.code) {
                self.file_picker = None;
                self.open_file(path);
            }
        } else if let Some(details) = &mut self.entry_details {
            if details.handle_event(key, &self.entries[details.entry]) {
                self.entry_details = None;
            }
        } else if self.editing_filter {
            self.handle_filter(key);
        } else {
            match key.code {
                KeyCode::Enter => {
                    if let Some(index) = self.selected_entry() {
                        let directory = self
                            .keystore_path
                            .as_deref()
                            .and_then(Path::parent)
                            .unwrap_or(Path::new("."))
                            .to_path_buf();
                        self.entry_details = Some(entry_details::EntryDetails::new(
                            index,
                            &self.entries[index],
                            directory,
                        ));
                    }
                }
                KeyCode::Char('o') => self.open_picker(),
                KeyCode::Char('/') if !self.entries.is_empty() => self.editing_filter = true,
                KeyCode::Char('s') if !self.entries.is_empty() => {
                    self.sort = self.sort.next();
                    self.refresh_visible();
                }
                KeyCode::Esc => return true,
                KeyCode::Down | KeyCode::Char('j') => self.entries_state.select_next(),
                KeyCode::Up | KeyCode::Char('k') => self.entries_state.select_previous(),
                _ => {}
            }
        }

        false
    }

    /// Whether letter keys are typed as text rather than used as shortcuts.
    fn typing(&self) -> bool {
        self.password_prompt.is_some()
            || self.editing_filter
            || self
                .entry_details
                .as_ref()
                .is_some_and(entry_details::EntryDetails::exporting)
    }

    fn handle_filter(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.editing_filter = false;
                self.filter.clear();
            }
            KeyCode::Enter => {
                self.editing_filter = false;
                return;
            }
            KeyCode::Backspace => {
                self.filter.pop();
            }
            KeyCode::Char(ch) if is_text_input(key.modifiers) => self.filter.push(ch),
            KeyCode::Down => return self.entries_state.select_next(),
            KeyCode::Up => return self.entries_state.select_previous(),
            _ => return,
        }
        self.refresh_visible();
    }

    /// The `entries` index of the selected row, if any row is shown.
    fn selected_entry(&self) -> Option<usize> {
        let last = self.visible.len().checked_sub(1)?;
        let position = self.entries_state.selected()?.min(last);
        Some(self.visible[position])
    }

    /// Re-applies the filter and sort, keeping the selected entry selected
    /// when it is still shown, or else selecting the first shown entry.
    fn refresh_visible(&mut self) {
        let selected = self.selected_entry();
        self.visible = entry_list::visible_entries(&self.entries, &self.filter, self.sort);
        let position = selected
            .and_then(|entry| self.visible.iter().position(|&index| index == entry))
            .or((!self.visible.is_empty()).then_some(0));
        self.entries_state.select(position);
    }

    fn handle_password(&mut self, key: KeyEvent) {
        if key.code == KeyCode::Esc {
            self.password_prompt = None;
            self.error = None;
            return;
        }
        let Some(prompt) = &mut self.password_prompt else {
            return;
        };
        match key.code {
            KeyCode::Char(ch) if is_text_input(key.modifiers) => prompt.password.push(ch),
            KeyCode::Backspace => prompt.password.pop(),
            KeyCode::Enter => {
                let PasswordPrompt {
                    path,
                    keystore,
                    mut password,
                } = self.password_prompt.take().unwrap();
                let result = keystore.verify(&password.0);
                password.clear();
                match result {
                    Ok(verified) => self.show_verified(path, verified),
                    Err(failure) if failure.1.is_some() => {
                        self.error = Some(failure.1.unwrap().into());
                    }
                    Err(failure) => {
                        let (keystore, _) = *failure;
                        self.password_prompt = Some(PasswordPrompt {
                            path,
                            keystore,
                            password,
                        });
                        self.error = Some(
                            "Incorrect password or keystore integrity check failed. Try again or press Esc."
                                .into(),
                        );
                    }
                }
            }
            _ => {}
        }
    }

    fn open_file(&mut self, path: PathBuf) {
        self.error = None;
        // Parse the entire structure once, before prompting. Empty-password
        // stores are verified immediately; others require their password.
        let keystore = match load(&path) {
            Ok(Loaded::Store(keystore)) => keystore,
            Ok(Loaded::Certificates(file)) => {
                self.show_entries(path, file.entries);
                self.warning = file.skipped.then_some(SKIPPED_WARNING);
                return;
            }
            Err(error) => {
                self.error = Some(error);
                return;
            }
        };
        match keystore.verify("") {
            Ok(verified) => self.show_verified(path, verified),
            Err(failure) if failure.1.is_some() => {
                self.error = Some(failure.1.unwrap().into());
            }
            Err(failure) => {
                let (keystore, _) = *failure;
                self.password_prompt = Some(PasswordPrompt {
                    path,
                    keystore,
                    password: Password::default(),
                });
            }
        }
    }

    fn show_entries(&mut self, path: PathBuf, entries: Vec<KeystoreEntry>) {
        self.keystore_path = Some(path);
        self.entries = entries;
        self.filter.clear();
        self.editing_filter = false;
        // The sort order is kept across keystores; the filter is not.
        self.visible = entry_list::visible_entries(&self.entries, "", self.sort);
        self.entries_state =
            TableState::default().with_selected((!self.visible.is_empty()).then_some(0));
        self.entry_details = None;
        self.error = None;
        self.warning = None;
    }

    fn show_verified(&mut self, path: PathBuf, verified: pkcs12::Verified) {
        self.show_entries(path, verified.entries);
        self.warning = verified.incomplete.then_some(INCOMPLETE_WARNING);
    }

    fn open_picker(&mut self) {
        let directory = self
            .keystore_path
            .as_deref()
            .and_then(|path| path.parent())
            .map_or_else(std::env::current_dir, |path| Ok(path.to_path_buf()));

        match directory.and_then(|path| FilePicker::new(&path)) {
            Ok(picker) => {
                self.file_picker = Some(picker);
                self.error = None;
            }
            Err(error) => self.error = Some(format!("Could not open file browser: {error}")),
        }
    }

    fn draw(&mut self, frame: &mut Frame) {
        if self.password_prompt.is_none()
            && self.file_picker.is_none()
            && let Some(details) = &mut self.entry_details
        {
            details.draw(frame, &self.entries[details.entry]);
            return;
        }
        let [content, status, path_bar, help] = Layout::vertical([
            Constraint::Min(3),
            Constraint::Length(2),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .areas(frame.area());

        if let Some(prompt) = &self.password_prompt {
            let masked = "*".repeat(prompt.password.0.chars().count());
            frame.render_widget(
                Paragraph::new(format!(
                    "Enter the keystore password to verify and list its entries.\n\nPassword: {masked}"
                ))
                .block(Block::bordered().title(format!(" {} ", prompt.path.display())))
                .wrap(Wrap { trim: false }),
                content,
            );
        } else if self.keystore_path.is_some() {
            let mut block = Block::bordered().title(" keystore-tui ".blue());
            if !self.entries.is_empty() {
                block = block.title_bottom(Line::from(self.list_title()).right_aligned());
            }
            if self.entries.is_empty() {
                frame.render_widget(
                    Paragraph::new("This keystore contains no entries.").block(block),
                    content,
                );
            } else if self.visible.is_empty() {
                let hint = if self.editing_filter {
                    "Edit the filter with Backspace, or press Esc to clear it."
                } else {
                    "Press / to edit the filter, then Esc to clear it."
                };
                frame.render_widget(
                    Paragraph::new(format!("No matching entries.\n\n{hint}"))
                        .block(block)
                        .wrap(Wrap { trim: false }),
                    content,
                );
            } else {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |elapsed| elapsed.as_secs() as i64);
                let selected = self
                    .entries_state
                    .selected()
                    .map(|position| position.min(self.visible.len() - 1));
                let rows = self.visible.iter().enumerate().map(|(position, &index)| {
                    let entry = &self.entries[index];
                    let is_selected = selected == Some(position);
                    let mut cells = vec![Cell::from(entry.alias.as_str()), Cell::from(entry.kind)];
                    match &entry.certificate {
                        Some(summary) => {
                            let expiry = Cell::from(summary.expiry_text());
                            cells.extend([
                                Cell::from(summary.algorithm.as_str()),
                                Cell::from(summary.key_size_text()),
                                match (entry_list::expiry_status(summary, now), is_selected) {
                                    (ExpiryStatus::Expired, true) => expiry
                                        .fg(Color::Rgb(255, 255, 255))
                                        .bg(Color::Rgb(128, 0, 0)),
                                    (ExpiryStatus::Expired, false) => expiry.fg(Color::Red),
                                    (ExpiryStatus::ExpiringSoon, true) => {
                                        expiry.fg(Color::Rgb(0, 0, 0)).bg(Color::Rgb(255, 175, 0))
                                    }
                                    (ExpiryStatus::ExpiringSoon, false) => expiry.fg(Color::Yellow),
                                    (ExpiryStatus::Valid, _) => expiry,
                                },
                                match (summary.weaknesses.is_empty(), is_selected) {
                                    (true, _) => Cell::from(""),
                                    (false, true) => Cell::from("Weak")
                                        .fg(Color::Rgb(0, 0, 0))
                                        .bg(Color::Rgb(255, 175, 0)),
                                    (false, false) => Cell::from("Weak").fg(Color::Yellow),
                                },
                            ]);
                        }
                        None => cells.extend(["-", "-", "-", "-"].map(Cell::from)),
                    }
                    let row = Row::new(cells);
                    if is_selected {
                        row.style(
                            Style::default()
                                .fg(Color::Rgb(0, 0, 0))
                                .bg(Color::Rgb(175, 255, 255))
                                .bold(),
                        )
                    } else {
                        row
                    }
                });
                let table = Table::new(
                    rows,
                    [
                        Constraint::Fill(1),
                        Constraint::Length(19),
                        Constraint::Length(10),
                        Constraint::Length(9),
                        Constraint::Length(10),
                        Constraint::Length(6),
                    ],
                )
                .header(
                    Row::new([
                        "Alias",
                        "Type",
                        "Algorithm",
                        "Key size",
                        "Expires",
                        "Crypto",
                    ])
                    .bold(),
                )
                .block(block)
                .highlight_symbol("> ");
                frame.render_stateful_widget(table, content, &mut self.entries_state);
            }
        } else {
            frame.render_widget(
                Paragraph::new(
                    "No keystore selected.\n\nPress o to open a keystore (.jks, .jceks, .p12, .pfx) or a certificate file (.pem, .crt, .cer, .der, .p7b, .p7c).",
                )
                .block(Block::bordered().title(" keystore-tui ".blue()))
                .wrap(Wrap { trim: false }),
                content,
            );
        }
        if let Some(error) = &self.error {
            frame.render_widget(
                Paragraph::new(error.as_str())
                    .style(Style::default().fg(Color::Red))
                    .wrap(Wrap { trim: false }),
                status,
            );
        } else if let Some(warning) = self.warning
            && self.file_picker.is_none()
        {
            frame.render_widget(
                Paragraph::new(warning)
                    .style(Style::default().fg(Color::Yellow))
                    .wrap(Wrap { trim: false }),
                status,
            );
        }
        if let Some(path) = &self.keystore_path {
            frame.render_widget(
                Paragraph::new(format!("Path: '{}'", path.display())),
                path_bar,
            );
        }
        if let Some(picker) = &mut self.file_picker {
            picker.draw(frame);
        } else {
            let shortcuts = if self.password_prompt.is_some() {
                "Enter Verify | Backspace Delete | Esc Cancel | Ctrl+C Quit"
            } else if self.editing_filter {
                "Type to filter | Enter Apply | Esc Clear | Up/Down Scroll | Ctrl+C Quit"
            } else {
                "o Open file | Enter Details | Up/Down j/k Scroll | / Filter | s Sort | q / Esc / Ctrl+C Quit"
            };
            frame.render_widget(Paragraph::new(shortcuts), help);
        }
    }

    /// Describes the filter, shown entry count, and sort order.
    fn list_title(&self) -> String {
        let total = self.entries.len();
        let shown = self.visible.len();
        let filter = if self.editing_filter {
            format!("Filter: {}_ | {shown} of {total} entries | ", self.filter)
        } else if self.filter.is_empty() {
            format!("{total} entries | ")
        } else {
            format!("Filter: '{}' | {shown} of {total} entries | ", self.filter)
        };
        format!(" {filter}Sort: {} ", self.sort.label())
    }
}

/// Whether a character key with these modifiers is text rather than a
/// shortcut. Windows reports AltGr as Ctrl+Alt; elsewhere Ctrl+Alt is a chord.
fn is_text_input(modifiers: KeyModifiers) -> bool {
    let control = modifiers.contains(KeyModifiers::CONTROL);
    let alt = modifiers.contains(KeyModifiers::ALT);
    (cfg!(windows) && control && alt) || (!control && !alt)
}

/// Detects the format from the content first, then from the file name.
fn load(path: &Path) -> Result<Loaded, String> {
    let data = read_limited(path, MAX_KEYSTORE_SIZE)
        .map_err(|error| format!("Cannot read {}: {error}", path.display()))?;
    let is_pkcs12_name = path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("p12") || ext.eq_ignore_ascii_case("pfx"));
    let certificates = || {
        certificate_file::parse(&data)
            .map(Loaded::Certificates)
            .map_err(|error| {
                format!(
                    "{} is not a valid certificate file: {error}",
                    path.display()
                )
            })
    };
    let pkcs12 = || {
        pkcs12::parse(&data)
            .map(|store| Loaded::Store(Store::Pkcs12(store)))
            .map_err(|error| format!("{} is not a valid PKCS12 keystore: {error}", path.display()))
    };
    if keystore::has_magic(&data) {
        jks(data, path)
    } else if certificate_file::is_pem(&data) {
        certificates()
    } else if is_pkcs12_name {
        pkcs12()
    } else if certificate_file::has_extension(path) {
        certificates()
    } else if data.first() == Some(&0x30) {
        // A PFX never reads as a certificate or PKCS#7 bundle, so try those first.
        certificates().or_else(|_| pkcs12())
    } else {
        jks(data, path)
    }
}

fn jks(data: Vec<u8>, path: &Path) -> Result<Loaded, String> {
    let format = if keystore::is_jceks(&data) {
        "JCEKS"
    } else {
        "JKS"
    };
    keystore::parse(data)
        .map(|store| Loaded::Store(Store::Jks(store)))
        .map_err(|error| {
            format!(
                "{} is not a valid {format} keystore: {error}",
                path.display()
            )
        })
}

fn read_limited(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let size_hint = file.metadata()?.len();
    if size_hint > limit {
        return Err(too_large(limit));
    }
    read_bounded(file, size_hint, limit)
}

/// Reads at most `limit + 1` bytes, so an oversized input is detected without
/// reading all of it. `size_hint` pre-sizes the buffer to avoid regrowth.
fn read_bounded(reader: impl Read, size_hint: u64, limit: u64) -> io::Result<Vec<u8>> {
    let capacity = usize::try_from(size_hint.min(limit + 1)).unwrap_or(0);
    let mut data = Vec::with_capacity(capacity);
    reader.take(limit + 1).read_to_end(&mut data)?;
    if data.len() as u64 > limit {
        return Err(too_large(limit));
    }
    Ok(data)
}

fn too_large(limit: u64) -> io::Error {
    io::Error::other(format!(
        "file is larger than the {limit}-byte keystore limit"
    ))
}

fn main() -> ExitCode {
    let mut terminal = match ratatui::try_init() {
        Ok(terminal) => terminal,
        Err(err) => {
            // Undo raw mode in case it was enabled before the failure.
            let _ = ratatui::try_restore();
            eprintln!("keystore-tui must be run in an interactive terminal: {err}");
            return ExitCode::FAILURE;
        }
    };
    let result = run(&mut terminal);
    ratatui::restore();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("keystore-tui: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(terminal: &mut DefaultTerminal) -> io::Result<()> {
    let mut app = App::default();
    loop {
        terminal.draw(|frame| app.draw(frame))?;

        if let Event::Key(key) = event::read()?
            && app.handle_key(key)
        {
            return Ok(());
        }
    }
}
