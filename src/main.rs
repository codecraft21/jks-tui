mod file_picker;
mod keystore;

#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;

use std::{fs, io, path::PathBuf};

use jks::KeyStoreError;
use ratatui::{
    DefaultTerminal, Frame,
    crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    layout::{Constraint, Layout},
    style::{Color, Style, Stylize},
    widgets::{Block, Paragraph, Row, Table, TableState, Wrap},
};

use file_picker::FilePicker;
use keystore::{KeystoreEntry, load_entries};

#[derive(Default)]
struct Password(String);

impl Password {
    fn clear(&mut self) {
        let mut bytes = std::mem::take(&mut self.0).into_bytes();
        jks::zeroing(&mut bytes);
    }
}

impl Drop for Password {
    fn drop(&mut self) {
        self.clear();
    }
}

struct PasswordPrompt {
    path: PathBuf,
    data: Vec<u8>,
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
}

impl App {
    fn handle_key(&mut self, key: KeyEvent) -> bool {
        if key.kind != KeyEventKind::Press {
            return false;
        }

        if (key.code == KeyCode::Char('q') && self.password_prompt.is_none())
            || (key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL))
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
            KeyCode::Char(ch)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                prompt.password.0.push(ch);
            }
            KeyCode::Backspace => {
                prompt.password.0.pop();
            }
            KeyCode::Enter => {
                let result = load_entries(&prompt.data, prompt.password.0.as_bytes());
                let path = prompt.path.clone();
                prompt.password.clear();
                match result {
                    Ok(entries) => self.show_entries(path, entries),
                    Err(KeyStoreError::InvalidDigest) => {
                        self.error = Some(
                            "Incorrect password or keystore integrity check failed. Try again or press Esc."
                                .into(),
                        );
                    }
                    Err(error) => {
                        self.error = Some(format!("Not a valid JKS keystore: {error}"));
                    }
                }
            }
            _ => {}
        }
    }

    fn open_file(&mut self, path: PathBuf) {
        self.error = None;
        let data = match fs::read(&path) {
            Ok(data) => data,
            Err(error) => {
                self.error = Some(format!("Cannot read {}: {error}", path.display()));
                return;
            }
        };
        // Parse the entire structure before prompting. Empty-password stores
        // can be verified immediately; other stores require their password.
        match load_entries(&data, b"") {
            Ok(entries) => self.show_entries(path, entries),
            Err(KeyStoreError::InvalidDigest) => {
                self.password_prompt = Some(PasswordPrompt {
                    path,
                    data,
                    password: Password::default(),
                });
            }
            Err(error) => {
                self.error = Some(format!(
                    "{} is not a valid JKS keystore: {error}",
                    path.display()
                ));
            }
        }
    }

    fn show_entries(&mut self, path: PathBuf, entries: Vec<KeystoreEntry>) {
        self.keystore_path = Some(path);
        self.entries_state =
            TableState::default().with_selected((!entries.is_empty()).then_some(0));
        self.entries = entries;
        self.password_prompt = None;
        self.error = None;
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
        let [content, status, help] = Layout::vertical([
            Constraint::Min(3),
            Constraint::Length(2),
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
        } else if let Some(path) = &self.keystore_path {
            let block = Block::bordered().title(format!(
                " {} | {} entries ",
                path.display(),
                self.entries.len()
            ));
            if self.entries.is_empty() {
                frame.render_widget(
                    Paragraph::new("This keystore contains no entries.").block(block),
                    content,
                );
            } else {
                let rows = self
                    .entries
                    .iter()
                    .map(|entry| Row::new([entry.alias.as_str(), entry.kind]));
                let table = Table::new(
                    rows,
                    [Constraint::Percentage(60), Constraint::Percentage(40)],
                )
                .header(Row::new(["Alias", "Type"]).bold())
                .block(block)
                .row_highlight_style(Style::default().bg(Color::DarkGray).bold())
                .highlight_symbol("> ");
                frame.render_stateful_widget(table, content, &mut self.entries_state);
            }
        } else {
            frame.render_widget(
                Paragraph::new("No keystore selected.\n\nPress o to open a .jks file.")
                    .block(Block::bordered().title(" jks-tui ")),
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

fn main() -> io::Result<()> {
    ratatui::run(run)
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
