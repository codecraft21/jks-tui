mod file_picker;

#[cfg(test)]
mod tests;

use std::{io, path::PathBuf};

use ratatui::{
    DefaultTerminal, Frame,
    crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    layout::{Constraint, Layout},
    style::{Color, Style},
    widgets::{Block, Paragraph, Wrap},
};

use file_picker::FilePicker;

#[derive(Default)]
struct App {
    keystore_path: Option<PathBuf>,
    file_picker: Option<FilePicker>,
    error: Option<String>,
}

impl App {
    fn handle_key(&mut self, key: KeyEvent) -> bool {
        if key.kind != KeyEventKind::Press {
            return false;
        }

        if key.code == KeyCode::Char('q')
            || (key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL))
        {
            return true;
        }

        if let Some(picker) = &mut self.file_picker {
            if key.code == KeyCode::Esc {
                self.file_picker = None;
            } else if let Some(path) = picker.handle_key(key.code) {
                self.keystore_path = Some(path);
                self.file_picker = None;
            }
        } else {
            match key.code {
                KeyCode::Char('o') => self.open_picker(),
                KeyCode::Esc => return true,
                _ => {}
            }
        }

        false
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

        let text = match &self.keystore_path {
            Some(path) => format!("Selected keystore:\n\n{}", path.display()),
            None => "No keystore selected.\n\nPress o to open a .jks file.".to_owned(),
        };
        frame.render_widget(
            Paragraph::new(text)
                .block(Block::bordered().title(" jks-tui "))
                .wrap(Wrap { trim: false }),
            content,
        );
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
            frame.render_widget(
                Paragraph::new("o Open keystore | q / Esc / Ctrl+C Quit"),
                help,
            );
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
