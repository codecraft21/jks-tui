//! Saving certificates and certificate requests to new PEM or DER files.
//! Existing files are never replaced.
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

use crown::asn1::pem;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// The certificate selected in the hierarchy.
    Certificate,
    /// Every stored certificate of the entry, leaf first.
    Chain,
    /// A certificate request entry's request.
    Request,
}

impl Scope {
    pub fn label(self) -> &'static str {
        match self {
            Self::Certificate => "certificate",
            Self::Chain => "chain",
            Self::Request => "certificate request",
        }
    }

    /// The suggested file name extension.
    fn extension(self) -> &'static str {
        match self {
            Self::Certificate | Self::Chain => "pem",
            Self::Request => "csr",
        }
    }

    /// The suggested name when the alias gives none.
    fn default_stem(self) -> &'static str {
        match self {
            Self::Certificate | Self::Chain => "certificate",
            Self::Request => "request",
        }
    }

    /// The PEM block label for what this scope saves.
    pub fn pem_label(self) -> &'static str {
        match self {
            Self::Certificate | Self::Chain => "CERTIFICATE",
            Self::Request => "CERTIFICATE REQUEST",
        }
    }
}

pub enum Outcome {
    Editing,
    Cancelled,
    Save(PathBuf),
}

/// The file name being typed for an export.
pub struct ExportPrompt {
    pub scope: Scope,
    pub path: String,
    directory: PathBuf,
}

impl ExportPrompt {
    /// Suggests `<alias>.pem`, `<alias>-chain.pem`, or `<alias>.csr` in
    /// `directory`, numbered to avoid names that already exist.
    pub fn new(scope: Scope, directory: &Path, alias: &str) -> Self {
        let mut stem: String = alias
            .chars()
            .map(|ch| {
                if ch.is_alphanumeric() || "-_.".contains(ch) {
                    ch
                } else {
                    '_'
                }
            })
            .collect();
        if stem.trim_matches('.').is_empty() {
            stem = scope.default_stem().into();
        }
        if scope == Scope::Chain {
            stem.push_str("-chain");
        }
        let extension = scope.extension();
        let path = (1..100)
            .map(|n| match n {
                1 => directory.join(format!("{stem}.{extension}")),
                n => directory.join(format!("{stem}-{n}.{extension}")),
            })
            .find(|path| !path.exists())
            .unwrap_or_else(|| directory.join(format!("{stem}.{extension}")));
        Self {
            scope,
            path: path.to_string_lossy().into_owned(),
            directory: directory.to_path_buf(),
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Outcome {
        match key.code {
            KeyCode::Esc => return Outcome::Cancelled,
            KeyCode::Enter if !self.path.is_empty() => {
                // Relative names are saved next to the opened file.
                return Outcome::Save(self.directory.join(&self.path));
            }
            KeyCode::Backspace => {
                self.path.pop();
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.path.clear()
            }
            KeyCode::Char(ch) if crate::is_text_input(key.modifiers) => self.path.push(ch),
            _ => {}
        }
        Outcome::Editing
    }
}

/// Whether `path` names a DER file; every other name is written as PEM.
pub fn is_der(path: &Path) -> bool {
    path.extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("der"))
}

/// PEM concatenates blocks labelled `pem_label` in the given order; DER holds
/// exactly one item.
pub fn encode(items: &[Vec<u8>], der: bool, pem_label: &str) -> Result<Vec<u8>, &'static str> {
    match (der, items) {
        (true, [item]) => Ok(item.clone()),
        (true, _) => Err("A DER file holds one certificate; use a .pem name for the chain."),
        (false, _) => Ok(items
            .iter()
            .map(|item| pem::encode(pem_label, item))
            .collect::<String>()
            .into_bytes()),
    }
}

/// Writes a new file, failing if `path` already exists.
pub fn save(path: &Path, items: &[Vec<u8>], pem_label: &str) -> Result<(), String> {
    let data = encode(items, is_der(path), pem_label)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| match error.kind() {
            io::ErrorKind::AlreadyExists => {
                format!("'{}' already exists; choose another name.", path.display())
            }
            _ => format!("Cannot create '{}': {error}", path.display()),
        })?;
    file.write_all(&data)
        .and_then(|()| file.sync_all())
        .map_err(|error| {
            drop(fs::remove_file(path));
            format!("Cannot write '{}': {error}", path.display())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{TestDirectory, metadata_certificate};

    fn type_text(prompt: &mut ExportPrompt, text: &str) {
        for ch in text.chars() {
            prompt.handle_key(KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE));
        }
    }

    #[test]
    fn suggests_a_safe_unused_name_next_to_the_opened_file() {
        let directory = TestDirectory::new();
        let prompt = ExportPrompt::new(Scope::Certificate, directory.path(), "my/key: 1");
        assert_eq!(
            Path::new(&prompt.path),
            directory.path().join("my_key__1.pem")
        );
        fs::write(directory.path().join("server-chain.pem"), b"existing").unwrap();
        let prompt = ExportPrompt::new(Scope::Chain, directory.path(), "server");
        assert_eq!(
            Path::new(&prompt.path),
            directory.path().join("server-chain-2.pem")
        );
        let prompt = ExportPrompt::new(Scope::Certificate, directory.path(), "..");
        assert_eq!(
            Path::new(&prompt.path),
            directory.path().join("certificate.pem")
        );
        let prompt = ExportPrompt::new(Scope::Request, directory.path(), "server");
        assert_eq!(Path::new(&prompt.path), directory.path().join("server.csr"));
    }

    #[test]
    fn editing_resolves_relative_names_and_quit_letters_are_text() {
        let directory = TestDirectory::new();
        let mut prompt = ExportPrompt::new(Scope::Certificate, directory.path(), "a");
        prompt.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        assert!(matches!(
            prompt.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
            Outcome::Editing
        ));
        type_text(&mut prompt, "q.derx");
        prompt.handle_key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
        assert_eq!(prompt.path, "q.der");
        let Outcome::Save(path) =
            prompt.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
        else {
            panic!("expected a save");
        };
        assert_eq!(path, directory.path().join("q.der"));
        assert!(matches!(
            prompt.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)),
            Outcome::Cancelled
        ));
    }

    #[test]
    fn saves_pem_chains_and_single_der_without_overwriting() {
        let directory = TestDirectory::new();
        let leaf = metadata_certificate("leaf", "root", &[1], &[]);
        let root = metadata_certificate("root", "root", &[2], &[]);
        let chain = [leaf.clone(), root.clone()];

        let pem_path = directory.path().join("chain.PEM");
        save(&pem_path, &chain, "CERTIFICATE").unwrap();
        let blocks = pem::parse(&fs::read_to_string(&pem_path).unwrap()).unwrap();
        assert_eq!(blocks.len(), 2);
        assert!(blocks.iter().all(|block| block.label == "CERTIFICATE"));
        assert_eq!([blocks[0].data.clone(), blocks[1].data.clone()], chain);

        let der_path = directory.path().join("leaf.DER");
        save(&der_path, &chain[..1], "CERTIFICATE").unwrap();
        assert_eq!(fs::read(&der_path).unwrap(), leaf);
        assert!(
            save(&der_path, &chain[1..], "CERTIFICATE")
                .unwrap_err()
                .contains("already exists")
        );
        assert_eq!(fs::read(&der_path).unwrap(), leaf);

        let request = directory.path().join("request.csr");
        save(&request, &chain[..1], Scope::Request.pem_label()).unwrap();
        let blocks = pem::parse(&fs::read_to_string(&request).unwrap()).unwrap();
        assert_eq!(blocks[0].label, "CERTIFICATE REQUEST");

        let rejected = directory.path().join("chain.der");
        assert!(
            save(&rejected, &chain, "CERTIFICATE")
                .unwrap_err()
                .contains(".pem")
        );
        assert!(!rejected.exists());
        assert!(
            save(
                &directory.path().join("missing/leaf.pem"),
                &chain,
                "CERTIFICATE"
            )
            .is_err()
        );
    }
}
