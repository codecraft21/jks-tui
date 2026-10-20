mod certificate;
mod file_picker;
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
    widgets::{Block, Cell, Paragraph, Row, Table, TableState, Wrap},
};

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
    entries_state: TableState,
    error: Option<String>,
    incomplete_warning: bool,
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

        if (key.code == KeyCode::Char('q') && self.password_prompt.is_none())
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
        } else {
            match key.code {
                KeyCode::Char('o') => self.open_picker(),
                KeyCode::Esc => return true,
                KeyCode::Down | KeyCode::Char('j') => self.entries_state.select_next(),
                KeyCode::Up | KeyCode::Char('k') => self.entries_state.select_previous(),
                _ => {}
            }
        }

        false
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
            Ok(keystore) => keystore,
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
        self.entries_state =
            TableState::default().with_selected((!entries.is_empty()).then_some(0));
        self.entries = entries;
        self.error = None;
        self.incomplete_warning = false;
    }

    fn show_verified(&mut self, path: PathBuf, verified: pkcs12::Verified) {
        self.show_entries(path, verified.entries);
        self.incomplete_warning = verified.incomplete;
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
            let block = Block::bordered().title(" keystore-tui ".blue());
            if self.entries.is_empty() {
                frame.render_widget(
                    Paragraph::new("This keystore contains no entries.").block(block),
                    content,
                );
            } else {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |elapsed| elapsed.as_secs() as i64);
                let selected = self.entries_state.selected();
                let rows = self.entries.iter().enumerate().map(|(index, entry)| {
                    let is_selected = selected == Some(index);
                    let mut cells = vec![Cell::from(entry.alias.as_str()), Cell::from(entry.kind)];
                    match &entry.certificate {
                        Some(summary) => {
                            let expiry = Cell::from(summary.expiry_text());
                            cells.extend([
                                Cell::from(summary.algorithm.as_str()),
                                Cell::from(summary.key_size_text()),
                                if summary.is_expired(now) {
                                    expiry.fg(if is_selected {
                                        Color::Rgb(128, 0, 0)
                                    } else {
                                        Color::Red
                                    })
                                } else {
                                    expiry
                                },
                            ]);
                        }
                        None => cells.extend(["-", "-", "-"].map(Cell::from)),
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
                    ],
                )
                .header(Row::new(["Alias", "Type", "Algorithm", "Key size", "Expires"]).bold())
                .block(block)
                .highlight_symbol("> ");
                frame.render_stateful_widget(table, content, &mut self.entries_state);
            }
        } else {
            frame.render_widget(
                Paragraph::new(
                    "No keystore selected.\n\nPress o to open a .jks, .p12, or .pfx file.",
                )
                .block(Block::bordered().title(" keystore-tui ".blue())),
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
        } else if self.incomplete_warning && self.file_picker.is_none() {
            frame.render_widget(
                Paragraph::new("Warning: this PKCS12 entry list is incomplete.")
                    .style(Style::default().fg(Color::Yellow)),
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
            } else {
                "o Open keystore | Up/Down or j/k Scroll | q / Esc / Ctrl+C Quit"
            };
            frame.render_widget(Paragraph::new(shortcuts), help);
        }
    }
}

/// Whether a character key with these modifiers is text rather than a
/// shortcut. Windows reports AltGr as Ctrl+Alt; elsewhere Ctrl+Alt is a chord.
fn is_text_input(modifiers: KeyModifiers) -> bool {
    let control = modifiers.contains(KeyModifiers::CONTROL);
    let alt = modifiers.contains(KeyModifiers::ALT);
    (cfg!(windows) && control && alt) || (!control && !alt)
}

fn load(path: &Path) -> Result<Store, String> {
    let data = read_limited(path, MAX_KEYSTORE_SIZE)
        .map_err(|error| format!("Cannot read {}: {error}", path.display()))?;
    if data.starts_with(&keystore::MAGIC.to_be_bytes()) {
        keystore::parse(data)
            .map(Store::Jks)
            .map_err(|error| format!("{} is not a valid JKS keystore: {error}", path.display()))
    } else if data.first() == Some(&0x30)
        || path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("p12") || ext.eq_ignore_ascii_case("pfx"))
    {
        pkcs12::parse(&data)
            .map(Store::Pkcs12)
            .map_err(|error| format!("{} is not a valid PKCS12 keystore: {error}", path.display()))
    } else {
        keystore::parse(data)
            .map(Store::Jks)
            .map_err(|error| format!("{} is not a valid JKS keystore: {error}", path.display()))
    }
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
