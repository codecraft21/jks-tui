use std::{
    fs, io,
    path::{Path, PathBuf},
};

use ratatui::{
    Frame,
    crossterm::event::KeyCode,
    layout::{Constraint, Layout, Margin},
    style::{Color, Modifier, Style},
    widgets::{Block, Clear, List, ListItem, ListState, Paragraph, Wrap},
};

struct Entry {
    path: PathBuf,
    is_directory: bool,
}

pub(crate) struct FilePicker {
    directory: PathBuf,
    entries: Vec<Entry>,
    selection: ListState,
    error: Option<String>,
}

impl FilePicker {
    pub(crate) fn new(directory: &Path) -> io::Result<Self> {
        let directory = directory.canonicalize()?;
        let mut entries = Vec::new();
        for entry in fs::read_dir(&directory)? {
            let path = entry?.path();
            let is_directory = path.is_dir();
            let is_jks = path
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("jks"));
            if is_directory || (is_jks && path.is_file()) {
                entries.push(Entry { path, is_directory });
            }
        }
        entries.sort_by(|a, b| {
            b.is_directory
                .cmp(&a.is_directory)
                .then_with(|| a.path.file_name().cmp(&b.path.file_name()))
        });
        if let Some(parent) = directory.parent() {
            entries.insert(
                0,
                Entry {
                    path: parent.to_path_buf(),
                    is_directory: true,
                },
            );
        }

        let selection = ListState::default().with_selected((!entries.is_empty()).then_some(0));
        Ok(Self {
            directory,
            entries,
            selection,
            error: None,
        })
    }

    pub(crate) fn handle_key(&mut self, key: KeyCode) -> Option<PathBuf> {
        let result = match key {
            KeyCode::Up | KeyCode::Char('k') => {
                self.move_selection(-1);
                return None;
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.move_selection(1);
                return None;
            }
            KeyCode::Home => {
                self.selection
                    .select((!self.entries.is_empty()).then_some(0));
                return None;
            }
            KeyCode::End => {
                self.selection.select(self.entries.len().checked_sub(1));
                return None;
            }
            KeyCode::Enter | KeyCode::Right => self.open_selected(key == KeyCode::Enter),
            KeyCode::Backspace | KeyCode::Left => self.open_parent(),
            _ => return None,
        };

        match result {
            Ok(path) => {
                self.error = None;
                path
            }
            Err(error) => {
                self.error = Some(format!("Could not open selection: {error}"));
                None
            }
        }
    }

    fn move_selection(&mut self, offset: isize) {
        if let Some(selected) = self.selection.selected() {
            self.selection.select(Some(
                selected
                    .saturating_add_signed(offset)
                    .min(self.entries.len().saturating_sub(1)),
            ));
        }
    }

    fn open_selected(&mut self, allow_file: bool) -> io::Result<Option<PathBuf>> {
        let Some(entry) = self.selection.selected().and_then(|i| self.entries.get(i)) else {
            return Ok(None);
        };

        if entry.is_directory {
            *self = Self::new(&entry.path)?;
        } else if allow_file {
            let path = entry.path.canonicalize()?;
            if !fs::metadata(&path)?.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "The selected entry is no longer a file.",
                ));
            }
            return Ok(Some(path));
        }

        Ok(None)
    }

    fn open_parent(&mut self) -> io::Result<Option<PathBuf>> {
        if let Some(parent) = self.directory.parent() {
            *self = Self::new(parent)?;
        }
        Ok(None)
    }

    pub(crate) fn draw(&mut self, frame: &mut Frame) {
        let area = frame.area().inner(Margin {
            horizontal: 2,
            vertical: 1,
        });
        let block = Block::bordered().title(" Open keystore (.jks) ");
        let inner = block.inner(area);
        frame.render_widget(Clear, area);
        frame.render_widget(block, area);

        let [directory, entries, status, help] = Layout::vertical([
            Constraint::Length(2),
            Constraint::Min(1),
            Constraint::Length(2),
            Constraint::Length(2),
        ])
        .areas(inner);
        frame.render_widget(
            Paragraph::new(self.directory.to_string_lossy()).wrap(Wrap { trim: false }),
            directory,
        );

        let items = self.entries.iter().map(|entry| {
            let name = if Some(entry.path.as_path()) == self.directory.parent() {
                "../".to_owned()
            } else {
                let name = entry.path.file_name().unwrap_or_default().to_string_lossy();
                format!("{name}{}", if entry.is_directory { "/" } else { "" })
            };
            ListItem::new(name)
        });
        frame.render_stateful_widget(
            List::new(items).highlight_symbol("> ").highlight_style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            entries,
            &mut self.selection,
        );

        let (message, color) = if let Some(error) = &self.error {
            (error.as_str(), Color::Red)
        } else if !self.entries.iter().any(|entry| !entry.is_directory) {
            ("No .jks files in this directory.", Color::Gray)
        } else {
            ("", Color::Reset)
        };
        frame.render_widget(
            Paragraph::new(message)
                .style(Style::default().fg(color))
                .wrap(Wrap { trim: false }),
            status,
        );
        frame.render_widget(
            Paragraph::new(
                "Up/Down or j/k Move | Enter Open\nLeft/Backspace Parent | Esc Cancel | q Quit",
            )
            .wrap(Wrap { trim: false }),
            help,
        );
    }
}
