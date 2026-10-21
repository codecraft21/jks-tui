use std::{
    fs,
    io::{self, Read},
    path::Path,
};

use crown::asn1::Asn1Time;
use ratatui::{Terminal, backend::TestBackend, buffer::Buffer};

use super::*;
use certificate::Summary;
use test_support::{
    KEYTOOL_JKS, TestDirectory, UNICODE_ALIAS_JKS, UNICODE_PASSWORD_JKS, empty_keystore,
    fixture_summary, mixed_keystore,
};

fn browsing(directory: &Path) -> App {
    App {
        file_picker: Some(FilePicker::new(directory).unwrap()),
        ..App::default()
    }
}

fn press(app: &mut App, code: KeyCode) -> bool {
    app.handle_key(KeyEvent::new(code, KeyModifiers::NONE))
}

fn buffer(app: &mut App, width: u16, height: u16) -> Buffer {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|frame| app.draw(frame)).unwrap();
    terminal.backend().buffer().clone()
}

fn screen(app: &mut App, width: u16, height: u16) -> String {
    buffer(app, width, height)
        .content
        .chunks(usize::from(width))
        .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
        .collect::<Vec<_>>()
        .join("\n")
}

fn red_text(app: &mut App) -> String {
    buffer(app, 200, 24)
        .content
        .iter()
        .filter(|cell| cell.fg == Color::Red)
        .map(|cell| cell.symbol())
        .collect()
}

fn type_password(app: &mut App, password: &str) {
    for ch in password.chars() {
        assert!(!press(app, KeyCode::Char(ch)));
    }
}

#[test]
fn java_unicode_keystores_open_through_the_password_prompt() {
    let directory = TestDirectory::new();
    for (name, data, password, alias) in [
        (
            "unicode-password.jks",
            UNICODE_PASSWORD_JKS,
            "pässwörd-😀",
            "root-cert",
        ),
        (
            "unicode-alias.jks",
            UNICODE_ALIAS_JKS,
            "changeit",
            "certificate-😀",
        ),
    ] {
        let path = directory.path().join(name);
        fs::write(&path, data).unwrap();
        let mut app = App::default();
        app.open_file(path.clone());
        assert!(app.password_prompt.is_some());
        assert!(app.entries.is_empty());
        type_password(&mut app, password);
        assert!(screen(&mut app, 100, 24).contains(&format!(
            "Password: {}",
            "*".repeat(password.chars().count())
        )));
        assert!(!screen(&mut app, 100, 24).contains(password));
        press(&mut app, KeyCode::Enter);
        assert!(app.password_prompt.is_none());
        assert!(app.error.is_none());
        assert_eq!(app.keystore_path, Some(path));
        assert_eq!(app.entries[0].alias, alias);
        assert!(screen(&mut app, 100, 24).contains(alias));
    }
}

#[test]
fn malformed_counts_report_an_error_and_preserve_the_loaded_keystore() {
    let directory = TestDirectory::new();
    let original = directory.path().join("original.jks");
    fs::write(&original, empty_keystore()).unwrap();
    let mut app = App::default();
    app.open_file(original.clone());

    let mut data = empty_keystore();
    data[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
    let malformed = directory.path().join("malformed.jks");
    fs::write(&malformed, data).unwrap();
    app.open_file(malformed);
    assert!(app.password_prompt.is_none());
    assert_eq!(app.keystore_path, Some(original));
    assert!(red_text(&mut app).contains("not a valid JKS keystore"));
}

#[test]
fn browser_shows_directories_then_supported_keystore_files() {
    let directory = TestDirectory::new();
    fs::create_dir(directory.path().join("z-directory")).unwrap();
    fs::write(directory.path().join("a-keystore.jks"), "").unwrap();
    fs::write(directory.path().join("b-keystore.JKS"), "").unwrap();
    fs::write(directory.path().join("c-keystore.p12"), "").unwrap();
    fs::write(directory.path().join("d-keystore.PFX"), "").unwrap();
    fs::write(directory.path().join("ignored.txt"), "").unwrap();
    fs::write(directory.path().join("ignored.jks.bak"), "").unwrap();

    let mut app = browsing(directory.path());
    let rendered = screen(&mut app, 100, 24);
    assert!(rendered.find("../").unwrap() < rendered.find("z-directory/").unwrap());
    assert!(rendered.find("z-directory/").unwrap() < rendered.find("a-keystore.jks").unwrap());
    assert!(rendered.find("a-keystore.jks").unwrap() < rendered.find("b-keystore.JKS").unwrap());
    assert!(rendered.find("b-keystore.JKS").unwrap() < rendered.find("c-keystore.p12").unwrap());
    assert!(rendered.find("c-keystore.p12").unwrap() < rendered.find("d-keystore.PFX").unwrap());
    assert!(!rendered.contains("ignored"));
}

#[test]
fn browser_cycles_through_parent_directories_and_files_in_both_directions() {
    let directory = TestDirectory::new();
    fs::create_dir(directory.path().join("nested")).unwrap();
    fs::write(directory.path().join("store.jks"), empty_keystore()).unwrap();

    for (up, down) in [
        (KeyCode::Up, KeyCode::Down),
        (KeyCode::Char('k'), KeyCode::Char('j')),
    ] {
        let mut app = browsing(directory.path());
        assert!(screen(&mut app, 100, 24).contains("> ../"));
        for expected in ["store.jks", "nested/", "../"] {
            assert!(!press(&mut app, up));
            assert!(screen(&mut app, 100, 24).contains(&format!("> {expected}")));
        }
        for expected in ["nested/", "store.jks", "../"] {
            assert!(!press(&mut app, down));
            assert!(screen(&mut app, 100, 24).contains(&format!("> {expected}")));
        }
        assert!(app.keystore_path.is_none());
        assert!(app.file_picker.is_some());
    }
}

#[test]
fn browser_wrapping_scrolls_between_ends_of_a_long_list() {
    let directory = TestDirectory::new();
    for index in 0..40 {
        fs::write(directory.path().join(format!("store-{index:02}.jks")), "").unwrap();
    }
    let mut app = browsing(directory.path());
    assert!(screen(&mut app, 100, 20).contains("> ../"));
    press(&mut app, KeyCode::Up);
    assert!(screen(&mut app, 100, 20).contains("> store-39.jks"));
    press(&mut app, KeyCode::Down);
    assert!(screen(&mut app, 100, 20).contains("> ../"));
}

#[test]
fn browser_cycles_safely_with_only_the_parent_entry() {
    let directory = TestDirectory::new();
    let mut app = browsing(directory.path());
    for key in [
        KeyCode::Up,
        KeyCode::Down,
        KeyCode::Char('k'),
        KeyCode::Char('j'),
    ] {
        assert!(!press(&mut app, key));
        assert!(screen(&mut app, 100, 24).contains("> ../"));
    }
}

#[test]
fn pkcs12_renamed_as_jks_opens_after_password_verification() {
    let directory = TestDirectory::new();
    let path = directory.path().join("renamed.jks");
    fs::write(&path, include_bytes!("../tests/fixtures/trusted-cert.p12")).unwrap();
    let mut app = App::default();
    app.open_file(path.clone());
    assert!(app.password_prompt.is_some());
    type_password(&mut app, "wrong");
    press(&mut app, KeyCode::Enter);
    assert!(app.entries.is_empty());
    type_password(&mut app, "changeit");
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.keystore_path, Some(path));
    assert_eq!(app.entries[0].alias, "root-cert");
    assert!(app.warning.is_none());
}

#[test]
fn entry_list_shows_certificate_algorithm_key_size_and_expiry() {
    let mut app = App::default();
    let expired = Summary {
        not_after: Asn1Time::new(2001, 2, 3, 0, 0, 0, true).unwrap(),
        ..fixture_summary()
    };
    app.show_entries(
        PathBuf::from("/keystore.jks"),
        vec![
            KeystoreEntry {
                alias: "current".into(),
                kind: "Trusted certificate",
                certificate: Some(fixture_summary()),
                certificates: vec![],
                chain_warning: None,
            },
            KeystoreEntry {
                alias: "expired".into(),
                kind: "Private key",
                certificate: Some(expired),
                certificates: vec![],
                chain_warning: None,
            },
            KeystoreEntry {
                alias: "secret".into(),
                kind: "Secret key",
                certificate: None,
                certificates: vec![],
                chain_warning: None,
            },
        ],
    );
    let screen = screen(&mut app, 80, 24);
    for text in [
        "Algorithm",
        "Key size",
        "Expires",
        "EC",
        "256 bits",
        "2036-10-09",
    ] {
        assert!(screen.contains(text), "{text}\n{screen}");
    }
    assert!(
        screen
            .lines()
            .any(|line| line.contains("secret") && line.contains("-"))
    );
    assert_eq!(red_text(&mut app), "2001-02-03");

    press(&mut app, KeyCode::Down);
    let rendered = buffer(&mut app, 80, 24);
    let selected_row = rendered
        .content
        .chunks(80)
        .find(|row| row.iter().any(|cell| cell.symbol() == ">"))
        .unwrap();
    let expiry_start = selected_row
        .windows(10)
        .position(|cells| {
            cells.iter().map(|cell| cell.symbol()).collect::<String>() == "2001-02-03"
        })
        .unwrap();
    for (index, cell) in selected_row.iter().enumerate().skip(1).take(78) {
        let is_expiry = (expiry_start..expiry_start + 10).contains(&index);
        assert_eq!(
            cell.bg,
            if is_expiry {
                Color::Rgb(128, 0, 0)
            } else {
                Color::Rgb(175, 255, 255)
            }
        );
        assert!(cell.modifier.contains(ratatui::style::Modifier::BOLD));
        assert_eq!(
            cell.fg,
            if is_expiry {
                Color::Rgb(255, 255, 255)
            } else {
                Color::Rgb(0, 0, 0)
            }
        );
    }
    assert!(red_text(&mut app).is_empty());
    press(&mut app, KeyCode::Down);
    assert_eq!(red_text(&mut app), "2001-02-03");
}

#[test]
fn jks_renamed_as_p12_still_uses_jks_content() {
    let directory = TestDirectory::new();
    let path = directory.path().join("renamed.p12");
    fs::write(&path, empty_keystore()).unwrap();
    let mut app = App::default();
    app.open_file(path.clone());
    assert_eq!(app.keystore_path, Some(path));
    assert!(app.password_prompt.is_none());
    assert!(app.error.is_none());
}

#[test]
fn truncated_pkcs12_is_rejected_before_password_prompt() {
    let directory = TestDirectory::new();
    let path = directory.path().join("truncated.p12");
    let fixture = include_bytes!("../tests/fixtures/trusted-cert.p12");
    fs::write(&path, &fixture[..fixture.len() - 1]).unwrap();
    let mut app = App::default();
    app.open_file(path);
    assert!(app.password_prompt.is_none());
    assert!(red_text(&mut app).contains("not a valid PKCS12 keystore"));
}

#[test]
fn partial_pkcs12_warning_persists_with_entries() {
    let directory = TestDirectory::new();
    let mut app = App::default();
    app.show_verified(
        directory.path().join("partial.p12"),
        pkcs12::Verified {
            entries: vec![KeystoreEntry {
                alias: "readable".into(),
                kind: "Secret key",
                certificate: None,
                certificates: vec![],
                chain_warning: None,
            }],
            incomplete: true,
        },
    );
    assert!(screen(&mut app, 100, 24).contains("readable"));
    assert!(screen(&mut app, 100, 24).contains("entry list is incomplete"));
    press(&mut app, KeyCode::Char('o'));
    press(&mut app, KeyCode::Esc);
    assert!(screen(&mut app, 100, 24).contains("entry list is incomplete"));
}

#[test]
fn selecting_a_valid_empty_keystore_displays_its_absolute_path() {
    let directory = TestDirectory::new();
    let path = directory.path().join("my keystore-ü.JKS");
    let data = empty_keystore();
    fs::write(&path, &data).unwrap();
    let mut app = browsing(directory.path());

    press(&mut app, KeyCode::End);
    assert!(!press(&mut app, KeyCode::Enter));

    let expected = path.canonicalize().unwrap();
    assert_eq!(app.keystore_path.as_deref(), Some(expected.as_path()));
    assert!(app.file_picker.is_none());
    let rendered = screen(&mut app, 200, 24);
    assert_eq!(
        rendered.lines().nth(22).unwrap().trim_end(),
        format!("Path: '{}'", expected.display())
    );
    let title = rendered.lines().next().unwrap();
    assert!(title.contains(" keystore-tui "));
    assert!(!title.contains(expected.to_str().unwrap()));
    assert!(!title.contains("entries"));
    assert!(screen(&mut app, 200, 24).contains("This keystore contains no entries."));
    assert!(app.password_prompt.is_none());
    assert_eq!(fs::read(&path).unwrap(), data);
}

#[test]
fn directories_can_be_entered_and_left_before_selecting() {
    let directory = TestDirectory::new();
    let nested = directory.path().join("nested");
    fs::create_dir(&nested).unwrap();
    let path = nested.join("nested-keystore.jks");
    fs::write(&path, empty_keystore()).unwrap();
    let mut app = browsing(directory.path());

    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Right);
    assert!(app.keystore_path.is_none());
    assert!(screen(&mut app, 200, 24).contains("nested-keystore.jks"));

    press(&mut app, KeyCode::Backspace);
    let parent = screen(&mut app, 200, 24);
    assert!(parent.contains("nested/"));
    assert!(!parent.contains("nested-keystore.jks"));

    press(&mut app, KeyCode::Char('j'));
    press(&mut app, KeyCode::Enter);
    // The first entry is ../, so Enter also navigates to the parent.
    press(&mut app, KeyCode::Enter);
    assert!(!screen(&mut app, 200, 24).contains("nested-keystore.jks"));

    press(&mut app, KeyCode::End);
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::End);
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.keystore_path, Some(path.canonicalize().unwrap()));
}

#[test]
fn reopening_and_cancelling_preserves_the_previous_keystore() {
    let directory = TestDirectory::new();
    let original = directory.path().join("a.jks");
    fs::write(&original, empty_keystore()).unwrap();
    fs::write(directory.path().join("b.jks"), empty_keystore()).unwrap();
    let original = original.canonicalize().unwrap();
    let mut app = App {
        keystore_path: Some(original.clone()),
        ..App::default()
    };

    assert!(!press(&mut app, KeyCode::Char('o')));
    assert!(screen(&mut app, 200, 24).contains("b.jks"));
    press(&mut app, KeyCode::End);
    assert!(!press(&mut app, KeyCode::Esc));
    assert!(app.file_picker.is_none());
    assert!(screen(&mut app, 200, 24).contains(&format!("Path: '{}'", original.display())));
    assert_eq!(app.keystore_path, Some(original));

    app.handle_key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::CONTROL));
    press(&mut app, KeyCode::End);
    press(&mut app, KeyCode::Enter);
    assert_eq!(
        app.keystore_path,
        Some(directory.path().join("b.jks").canonicalize().unwrap())
    );
}

#[test]
fn a_missing_file_reports_an_error_and_allows_recovery() {
    let directory = TestDirectory::new();
    let path = directory.path().join("removed.jks");
    fs::write(&path, empty_keystore()).unwrap();
    let mut app = browsing(directory.path());
    press(&mut app, KeyCode::End);
    fs::remove_file(&path).unwrap();

    assert!(!press(&mut app, KeyCode::Enter));
    assert!(app.keystore_path.is_none());
    assert!(app.file_picker.is_some());
    assert!(screen(&mut app, 200, 24).contains("Could not open selection"));

    fs::write(&path, empty_keystore()).unwrap();
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.keystore_path, Some(path.canonicalize().unwrap()));
}

#[test]
fn a_missing_directory_does_not_close_the_browser() {
    let directory = TestDirectory::new();
    let nested = directory.path().join("removed-directory");
    fs::create_dir(&nested).unwrap();
    let mut app = browsing(directory.path());
    press(&mut app, KeyCode::End);
    fs::remove_dir(&nested).unwrap();

    press(&mut app, KeyCode::Enter);
    let rendered = screen(&mut app, 200, 24);
    assert!(rendered.contains("Could not open selection"));
    assert!(rendered.contains("removed-directory/"));
    assert!(!press(&mut app, KeyCode::Esc));
    assert!(app.file_picker.is_none());
}

#[test]
fn empty_directories_and_small_terminals_are_handled() {
    let directory = TestDirectory::new();
    let mut app = browsing(directory.path());
    assert!(screen(&mut app, 100, 24).contains("No keystore (.jks, .p12, .pfx) or certificate"));
    press(&mut app, KeyCode::Up);
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Home);
    press(&mut app, KeyCode::End);
    screen(&mut app, 12, 5);
    screen(&mut app, 1, 1);
    assert!(app.keystore_path.is_none());
    assert!(!press(&mut app, KeyCode::Esc));
    assert!(app.file_picker.is_none());
    assert!(press(&mut app, KeyCode::Esc));
}

#[test]
fn invalid_file_shows_a_red_error_and_valid_selection_recovers() {
    let directory = TestDirectory::new();
    fs::write(directory.path().join("a-invalid.jks"), "not a keystore").unwrap();
    fs::write(directory.path().join("b-valid.jks"), mixed_keystore()).unwrap();
    let mut app = browsing(directory.path());

    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Enter);
    assert!(app.file_picker.is_none());
    assert!(app.password_prompt.is_none());
    assert!(app.keystore_path.is_none());
    assert!(red_text(&mut app).contains("not a valid JKS keystore"));

    app.file_picker = Some(FilePicker::new(directory.path()).unwrap());
    press(&mut app, KeyCode::End);
    press(&mut app, KeyCode::Enter);
    assert!(app.password_prompt.is_some());
    assert!(app.error.is_none());
    type_password(&mut app, "changeit");
    press(&mut app, KeyCode::Enter);
    assert!(app.password_prompt.is_none());
    let content = screen(&mut app, 100, 24);
    for expected in [
        "root-cert",
        "Trusted certificate",
        "server-key",
        "Private key",
        "keystore-tui",
    ] {
        assert!(content.contains(expected), "missing {expected}");
    }
    let title = content.lines().next().unwrap();
    assert!(!title.contains("entries"));
    assert!(!title.contains("b-valid.jks"));
    assert!(red_text(&mut app).is_empty());
}

#[test]
fn password_is_masked_and_failed_verification_can_be_retried() {
    let directory = TestDirectory::new();
    fs::write(directory.path().join("valid.jks"), mixed_keystore()).unwrap();
    let mut app = browsing(directory.path());
    press(&mut app, KeyCode::End);
    press(&mut app, KeyCode::Enter);
    type_password(&mut app, "wrong-q");
    let content = screen(&mut app, 100, 24);
    assert!(content.contains("Password: *******"));
    assert!(!content.contains("wrong-q"));

    press(&mut app, KeyCode::Enter);
    assert!(app.keystore_path.is_none());
    assert!(app.entries.is_empty());
    assert!(app.password_prompt.as_ref().unwrap().password.0.is_empty());
    assert!(red_text(&mut app).contains("Incorrect password or keystore integrity check failed"));
    assert!(!screen(&mut app, 100, 24).contains("root-cert"));

    type_password(&mut app, "changeit!");
    press(&mut app, KeyCode::Backspace);
    press(&mut app, KeyCode::Enter);
    assert!(app.password_prompt.is_none());
    assert_eq!(app.entries.len(), 2);
    assert!(app.error.is_none());
}

#[test]
fn truncated_files_are_rejected_before_the_password_prompt() {
    let directory = TestDirectory::new();
    fs::write(
        directory.path().join("truncated.jks"),
        &KEYTOOL_JKS[..KEYTOOL_JKS.len() - 1],
    )
    .unwrap();
    let mut app = browsing(directory.path());
    press(&mut app, KeyCode::End);
    press(&mut app, KeyCode::Enter);
    assert!(app.password_prompt.is_none());
    assert!(app.keystore_path.is_none());
    assert!(red_text(&mut app).contains("not a valid JKS keystore"));
}

#[test]
fn cancelling_a_password_prompt_preserves_the_loaded_entries() {
    let directory = TestDirectory::new();
    let original = directory.path().join("a-original.jks");
    fs::write(&original, mixed_keystore()).unwrap();
    fs::write(directory.path().join("b-other.jks"), KEYTOOL_JKS).unwrap();
    let mut app = browsing(directory.path());
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Enter);
    type_password(&mut app, "changeit");
    press(&mut app, KeyCode::Enter);

    press(&mut app, KeyCode::Char('o'));
    press(&mut app, KeyCode::End);
    press(&mut app, KeyCode::Enter);
    type_password(&mut app, "partial");
    assert!(!press(&mut app, KeyCode::Esc));
    assert!(app.password_prompt.is_none());
    assert_eq!(app.keystore_path, Some(original.canonicalize().unwrap()));
    assert!(screen(&mut app, 200, 24).contains(&format!(
        "Path: '{}'",
        original.canonicalize().unwrap().display()
    )));
    assert_eq!(app.entries.len(), 2);
    assert!(screen(&mut app, 100, 24).contains("server-key"));

    press(&mut app, KeyCode::Char('o'));
    press(&mut app, KeyCode::End);
    press(&mut app, KeyCode::Enter);
    assert!(app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)));
}

#[test]
fn a_read_failure_is_reported_in_red_without_losing_the_loaded_keystore() {
    let directory = TestDirectory::new();
    let original = directory.path().join("original.jks");
    fs::write(&original, empty_keystore()).unwrap();
    let mut app = App::default();
    app.open_file(original.clone());
    app.open_file(directory.path().join("missing.jks"));
    assert!(red_text(&mut app).contains("Cannot read"));
    assert!(screen(&mut app, 200, 24).contains(&format!("Path: '{}'", original.display())));
    assert_eq!(app.keystore_path, Some(original));
    assert!(app.password_prompt.is_none());
}

#[test]
fn path_bar_is_blank_until_loaded_and_clips_without_wrapping() {
    let mut app = App::default();
    assert_eq!(screen(&mut app, 40, 12).lines().nth(10).unwrap().trim(), "");

    app.show_entries(PathBuf::from("/a long directory/keystore.jks"), vec![]);
    app.error = Some("An opening error".to_string());
    let rendered = screen(&mut app, 20, 12);
    let lines: Vec<_> = rendered.lines().collect();
    assert_eq!(lines[8].trim_end(), "An opening error");
    assert_eq!(lines[10], "Path: '/a long direc");
    assert!(lines[11].starts_with("o Open file"));

    for (width, height) in [(1, 1), (5, 3), (20, 5), (0, 0)] {
        buffer(&mut app, width, height);
    }
}

#[test]
fn entry_list_scrolls_to_entries_below_the_viewport() {
    let directory = TestDirectory::new();
    let mut app = App::default();
    app.show_entries(
        directory.path().join("many.jks"),
        (0..40)
            .map(|index| KeystoreEntry {
                alias: format!("entry-{index:02}"),
                kind: "Trusted certificate",
                certificate: None,
                certificates: vec![],
                chain_warning: None,
            })
            .collect(),
    );
    assert!(!screen(&mut app, 100, 20).contains("entry-39"));
    for _ in 0..39 {
        press(&mut app, KeyCode::Down);
        screen(&mut app, 100, 20);
    }
    assert!(screen(&mut app, 100, 20).contains("entry-39"));
}

#[test]
fn altgr_is_typed_on_windows_and_other_modifier_chords_are_ignored() {
    let directory = TestDirectory::new();
    let path = directory.path().join("valid.jks");
    fs::write(&path, mixed_keystore()).unwrap();
    let mut app = App::default();
    app.open_file(path);
    for (ch, modifiers) in [
        ('a', KeyModifiers::ALT),
        ('b', KeyModifiers::CONTROL),
        ('@', KeyModifiers::CONTROL | KeyModifiers::ALT),
        (
            '€',
            KeyModifiers::CONTROL | KeyModifiers::ALT | KeyModifiers::SHIFT,
        ),
        ('X', KeyModifiers::SHIFT),
    ] {
        app.handle_key(KeyEvent::new(KeyCode::Char(ch), modifiers));
    }
    // Only Windows reports AltGr as Ctrl+Alt; elsewhere it is a shortcut chord.
    let expected = if cfg!(windows) { "@€X" } else { "X" };
    assert_eq!(*app.password_prompt.as_ref().unwrap().password.0, expected);
}

#[test]
fn long_passwords_survive_buffer_growth_and_backspace() {
    let mut password = Password::default();
    let mut expected = "pässwörd-😀".repeat(20);
    for ch in expected.chars() {
        password.push(ch);
    }
    assert_eq!(*password.0, expected);
    for _ in 0..3 {
        password.pop();
        expected.pop();
        assert_eq!(*password.0, expected);
    }
    password.clear();
    assert!(password.0.is_empty());
    password.pop();
    assert!(password.0.is_empty());
}

struct CountingReader {
    read: u64,
}

impl Read for CountingReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        buf.fill(0);
        self.read += buf.len() as u64;
        Ok(buf.len())
    }
}

#[test]
fn unbounded_input_is_rejected_after_reading_just_past_the_limit() {
    let mut reader = CountingReader { read: 0 };
    let error = read_bounded(&mut reader, u64::MAX, 1000).unwrap_err();
    assert!(error.to_string().contains("keystore limit"));
    assert_eq!(reader.read, 1001);
}

#[test]
fn oversized_files_are_rejected_without_reading_them_fully() {
    let directory = TestDirectory::new();
    let path = directory.path().join("large.jks");
    fs::write(&path, mixed_keystore()).unwrap();
    let size = fs::metadata(&path).unwrap().len();
    assert!(read_limited(&path, size).is_ok());
    let error = read_limited(&path, size - 1).unwrap_err();
    assert!(error.to_string().contains("keystore limit"));
}

#[test]
fn ctrl_alt_c_does_not_quit() {
    let mut app = App::default();
    let altgr_c = KeyEvent::new(
        KeyCode::Char('c'),
        KeyModifiers::CONTROL | KeyModifiers::ALT,
    );
    assert!(!app.handle_key(altgr_c));
    assert!(app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)));
}

#[test]
fn enter_opens_full_screen_details_and_escape_preserves_list_state() {
    let mut app = App::default();
    let certificates = vec![test_support::fixture_certificate_der().to_vec()];
    app.show_entries(
        PathBuf::from("/keystore.jks"),
        (0..40)
            .map(|i| KeystoreEntry {
                alias: format!("entry-{i:02}"),
                kind: "Trusted certificate",
                certificate: Some(fixture_summary()),
                certificates: certificates.clone(),
                chain_warning: None,
            })
            .collect(),
    );
    for _ in 0..35 {
        press(&mut app, KeyCode::Down);
        screen(&mut app, 100, 20);
    }
    let previous = app.entries_state;
    let previous_screen = screen(&mut app, 100, 20);
    assert!(!press(&mut app, KeyCode::Enter));
    let details = screen(&mut app, 120, 50);
    for label in [
        "entry-35",
        "Certificate hierarchy",
        "Version:",
        "Subject:",
        "Issuer:",
        "Serial Number (hex):",
        "Serial Number (dec):",
        "Valid From:",
        "Valid Until:",
        "Public Key: EC 256 bits",
        "Signature Algorithm:",
        "Fingerprint (SHA-256):",
    ] {
        assert!(details.contains(label), "missing {label}");
    }
    assert!(!details.contains("Path:"));
    assert!(!press(&mut app, KeyCode::Esc));
    assert!(app.entry_details.is_none());
    assert_eq!(app.entries_state, previous);
    assert_eq!(screen(&mut app, 100, 20), previous_screen);
    press(&mut app, KeyCode::Enter);
    assert!(press(&mut app, KeyCode::Char('q')));
    assert!(app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)));
    assert!(!app.handle_key(KeyEvent::new_with_kind(
        KeyCode::Esc,
        KeyModifiers::NONE,
        KeyEventKind::Release
    )));
    assert!(app.entry_details.is_some());
}

#[test]
fn enter_handles_empty_lists_and_entries_without_certificates() {
    let mut app = App::default();
    press(&mut app, KeyCode::Enter);
    assert!(app.entry_details.is_none());
    app.show_entries(PathBuf::from("/empty.jks"), vec![]);
    press(&mut app, KeyCode::Enter);
    assert!(app.entry_details.is_none());
    app.show_entries(
        PathBuf::from("/secret.p12"),
        vec![KeystoreEntry {
            alias: "secret".into(),
            kind: "Secret key",
            certificate: None,
            certificates: vec![],
            chain_warning: None,
        }],
    );
    press(&mut app, KeyCode::Enter);
    let rendered = screen(&mut app, 100, 24);
    assert!(rendered.contains("Type: Secret key"));
    assert!(rendered.contains("No certificate is stored with this entry"));
    assert!(!press(&mut app, KeyCode::Esc));
    assert!(press(&mut app, KeyCode::Esc));
}

fn certificate_entry(alias: &str, not_after: Asn1Time) -> KeystoreEntry {
    KeystoreEntry {
        alias: alias.into(),
        kind: "Trusted certificate",
        certificate: Some(Summary {
            not_after,
            ..fixture_summary()
        }),
        certificates: vec![test_support::fixture_certificate_der().to_vec()],
        chain_warning: None,
    }
}

fn triage_app() -> App {
    let mut app = App::default();
    let date = |year| Asn1Time::new(year, 1, 1, 0, 0, 0, true).unwrap();
    app.show_entries(
        PathBuf::from("/keystore.jks"),
        vec![
            certificate_entry("alpha", date(2040)),
            certificate_entry("beta-quit", date(2035)),
            KeystoreEntry {
                alias: "gamma".into(),
                kind: "Secret key",
                certificate: None,
                certificates: vec![],
                chain_warning: None,
            },
            certificate_entry("zeta", date(2030)),
        ],
    );
    app
}

fn selected_alias(app: &App) -> &str {
    &app.entries[app.selected_entry().unwrap()].alias
}

fn shown_aliases(app: &App) -> Vec<&str> {
    app.visible
        .iter()
        .map(|&index| app.entries[index].alias.as_str())
        .collect()
}

#[test]
fn filter_updates_live_and_types_shortcut_letters() {
    let mut app = triage_app();
    assert!(screen(&mut app, 100, 20).contains("4 entries | Sort: alias"));
    assert!(!press(&mut app, KeyCode::Char('/')));
    assert!(app.editing_filter);
    assert!(screen(&mut app, 100, 20).contains("Type to filter"));
    // Shortcut letters, including q, are typed rather than acted on.
    for ch in ['Q', 'u', 'i', 't', 's', 'o', 'j'] {
        assert!(!press(&mut app, KeyCode::Char(ch)));
    }
    assert_eq!(app.filter, "Quitsoj");
    assert_eq!(app.sort, SortOrder::Alias);
    assert!(app.file_picker.is_none());
    let rendered = screen(&mut app, 100, 20);
    assert!(rendered.contains("No matching entries."), "{rendered}");
    assert!(rendered.contains("Filter: Quitsoj_ | 0 of 4 entries"));
    assert!(!press(&mut app, KeyCode::Enter));
    assert!(app.entry_details.is_none());
    assert!(!app.editing_filter);
    press(&mut app, KeyCode::Char('/'));
    for _ in 0..3 {
        press(&mut app, KeyCode::Backspace);
    }
    assert_eq!(shown_aliases(&app), ["beta-quit"]);
    assert!(screen(&mut app, 100, 20).contains("Filter: Quit_ | 1 of 4 entries"));
    // Modifier chords are not typed, and Ctrl+C still quits while typing.
    app.handle_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::ALT));
    assert_eq!(app.filter, "Quit");
    assert!(app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)));
}

#[test]
fn escape_cancels_filter_and_applied_filter_keeps_quit_keys() {
    let mut app = triage_app();
    press(&mut app, KeyCode::Char('/'));
    type_password(&mut app, "ZET");
    assert_eq!(shown_aliases(&app), ["zeta"]);
    assert!(!press(&mut app, KeyCode::Esc));
    assert!(!app.editing_filter);
    assert!(app.filter.is_empty());
    assert_eq!(app.visible.len(), 4);
    assert_eq!(selected_alias(&app), "zeta");

    // An applied filter matches subjects too and survives Enter.
    press(&mut app, KeyCode::Char('/'));
    type_password(&mut app, "test fixture");
    press(&mut app, KeyCode::Enter);
    assert!(!app.editing_filter);
    assert_eq!(shown_aliases(&app), ["alpha", "beta-quit", "zeta"]);
    let rendered = screen(&mut app, 100, 20);
    assert!(rendered.contains("Filter: 'test fixture' | 3 of 4 entries | Sort: alias"));
    assert!(press(&mut app, KeyCode::Esc));
    assert!(press(&mut app, KeyCode::Char('q')));

    // Reopening `/` edits the applied filter; Esc clears it.
    press(&mut app, KeyCode::Char('/'));
    assert_eq!(app.filter, "test fixture");
    press(&mut app, KeyCode::Esc);
    assert!(app.filter.is_empty());
    assert!(screen(&mut app, 100, 20).contains("4 entries | Sort: alias"));
}

#[test]
fn enter_opens_the_selected_filtered_entry() {
    let mut app = triage_app();
    press(&mut app, KeyCode::Char('/'));
    type_password(&mut app, "ta");
    assert_eq!(shown_aliases(&app), ["beta-quit", "zeta"]);
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Down);
    screen(&mut app, 100, 20);
    assert_eq!(selected_alias(&app), "zeta");
    press(&mut app, KeyCode::Enter);
    let details = app.entry_details.as_ref().unwrap();
    assert_eq!(app.entries[details.entry].alias, "zeta");
    assert!(screen(&mut app, 120, 40).contains("zeta"));
    press(&mut app, KeyCode::Esc);
    assert_eq!(selected_alias(&app), "zeta");
    assert_eq!(app.filter, "ta");

    // An empty result cannot open details.
    press(&mut app, KeyCode::Char('/'));
    type_password(&mut app, "nothing");
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Enter);
    assert!(app.entry_details.is_none());
    assert!(screen(&mut app, 100, 20).contains("No matching entries."));
}

#[test]
fn sort_cycles_between_alias_and_expiry_keeping_the_selection() {
    let mut app = triage_app();
    press(&mut app, KeyCode::Down);
    assert_eq!(selected_alias(&app), "beta-quit");
    assert!(!press(&mut app, KeyCode::Char('s')));
    assert_eq!(app.sort, SortOrder::Expiry);
    assert_eq!(shown_aliases(&app), ["zeta", "beta-quit", "alpha", "gamma"]);
    assert_eq!(selected_alias(&app), "beta-quit");
    let rendered = screen(&mut app, 100, 20);
    assert!(rendered.contains("Sort: expiry"), "{rendered}");
    let aliases = ["zeta", "beta-quit", "alpha", "gamma"];
    let rows: Vec<_> = rendered
        .lines()
        .filter_map(|line| aliases.into_iter().find(|alias| line.contains(alias)))
        .collect();
    assert_eq!(rows, aliases);

    press(&mut app, KeyCode::Char('s'));
    assert_eq!(app.sort, SortOrder::Alias);
    assert_eq!(selected_alias(&app), "beta-quit");
    assert!(screen(&mut app, 100, 20).contains("Sort: alias"));

    // A hidden selection falls back to the first shown entry.
    press(&mut app, KeyCode::Char('/'));
    type_password(&mut app, "al");
    assert_eq!(shown_aliases(&app), ["alpha"]);
    assert_eq!(selected_alias(&app), "alpha");

    // The sort order persists when another keystore is shown; the filter does not.
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Char('s'));
    let entries = std::mem::take(&mut app.entries);
    app.show_entries(PathBuf::from("/other.jks"), entries);
    assert_eq!(app.sort, SortOrder::Expiry);
    assert!(app.filter.is_empty());
    assert_eq!(selected_alias(&app), "zeta");
}

#[test]
fn expiring_soon_dates_use_a_readable_warning_color() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let soon = Asn1Time::from_unix(now + 10 * 24 * 60 * 60, false);
    let soon_text = Summary {
        not_after: soon,
        ..fixture_summary()
    }
    .expiry_text();
    let mut app = App::default();
    app.show_entries(
        PathBuf::from("/keystore.jks"),
        vec![
            certificate_entry("current", Asn1Time::from_unix(now + 400 * 86400, false)),
            certificate_entry("soon", soon),
            certificate_entry("expired", Asn1Time::new(2001, 2, 3, 0, 0, 0, true).unwrap()),
        ],
    );
    let colored = |app: &mut App, fg: Color| -> String {
        buffer(app, 100, 20)
            .content
            .iter()
            .filter(|cell| cell.fg == fg)
            .map(|cell| cell.symbol())
            .collect()
    };
    assert_eq!(colored(&mut app, Color::Yellow), soon_text);
    assert_eq!(red_text(&mut app), "2001-02-03");

    press(&mut app, KeyCode::Down);
    assert!(colored(&mut app, Color::Yellow).is_empty());
    let rendered = buffer(&mut app, 100, 20);
    let selected_row = rendered
        .content
        .chunks(100)
        .find(|row| row.iter().any(|cell| cell.symbol() == ">"))
        .unwrap();
    let warning: String = selected_row
        .iter()
        .filter(|cell| cell.bg == Color::Rgb(255, 175, 0))
        .inspect(|cell| {
            assert_eq!(cell.fg, Color::Rgb(0, 0, 0));
            assert!(cell.modifier.contains(ratatui::style::Modifier::BOLD));
        })
        .map(|cell| cell.symbol())
        .collect();
    assert_eq!(warning, soon_text);
    assert_eq!(red_text(&mut app), "2001-02-03");
}

#[test]
fn certificate_files_open_without_a_prompt_in_file_order() {
    use crown::asn1::pem;
    let directory = TestDirectory::new();
    let der = test_support::fixture_certificate_der();
    let leaf = test_support::metadata_certificate("zz-leaf", "JKS TUI test fixture", &[1], &[]);
    let pem_path = directory.path().join("bundle.crt");
    let text = [
        pem::encode("CERTIFICATE", &leaf),
        pem::encode("PRIVATE KEY", b"synthetic, not a key"),
        pem::encode("CERTIFICATE", der),
    ]
    .concat();
    fs::write(&pem_path, text).unwrap();
    // A DER certificate is recognised by content even without a known name.
    let der_path = directory.path().join("unnamed");
    fs::write(&der_path, der).unwrap();

    let mut app = App::default();
    app.open_file(pem_path);
    assert!(app.password_prompt.is_none());
    assert_eq!(shown_aliases(&app), ["zz-leaf", "JKS TUI test fixture"]);
    let rendered = screen(&mut app, 120, 24);
    assert!(rendered.contains("Certificate"));
    assert!(rendered.contains("private keys, were not read"));
    press(&mut app, KeyCode::Enter);
    let details = screen(&mut app, 120, 50);
    assert!(details.find("CN=JKS TUI test fixture").unwrap() < details.find("CN=zz-leaf").unwrap());

    app.open_file(der_path);
    assert!(app.error.is_none());
    assert!(app.warning.is_none());
    assert_eq!(shown_aliases(&app), ["JKS TUI test fixture"]);

    let bad = directory.path().join("bad.pem");
    fs::write(
        &bad,
        "-----BEGIN CERTIFICATE-----\n!!\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    app.open_file(bad);
    assert!(red_text(&mut app).contains("not a valid certificate file"));
    assert_eq!(shown_aliases(&app), ["JKS TUI test fixture"]);
}

#[test]
fn browser_lists_certificate_files() {
    let directory = TestDirectory::new();
    for name in ["a.pem", "b.CER", "c.p7b", "d.txt"] {
        fs::write(directory.path().join(name), b"").unwrap();
    }
    let mut app = browsing(directory.path());
    let rendered = screen(&mut app, 100, 24);
    for name in ["a.pem", "b.CER", "c.p7b"] {
        assert!(rendered.contains(name), "missing {name}");
    }
    assert!(!rendered.contains("d.txt"));
}

#[test]
fn details_export_certificates_next_to_the_opened_file() {
    let directory = TestDirectory::new();
    let leaf = test_support::metadata_certificate("leaf", "root", &[1], &[]);
    let root = test_support::metadata_certificate("root", "root", &[2], &[]);
    let mut app = App::default();
    app.show_entries(
        directory.path().join("store.jks"),
        vec![KeystoreEntry {
            alias: "server".into(),
            kind: "Private key",
            certificate: None,
            certificates: vec![leaf.clone(), root.clone()],
            chain_warning: None,
        }],
    );
    press(&mut app, KeyCode::Enter);
    assert!(screen(&mut app, 120, 40).contains("x Export certificate"));

    // Letters, including q, are typed into the name; Esc cancels only the prompt.
    press(&mut app, KeyCode::Char('x'));
    assert!(screen(&mut app, 120, 40).contains("Save certificate to: "));
    assert!(!press(&mut app, KeyCode::Char('q')));
    assert!(app.entry_details.as_ref().unwrap().exporting());
    assert!(!press(&mut app, KeyCode::Esc));
    assert!(app.entry_details.is_some());
    assert!(!app.entry_details.as_ref().unwrap().exporting());

    press(&mut app, KeyCode::Char('x'));
    press(&mut app, KeyCode::Enter);
    let saved = directory.path().join("server.pem");
    assert!(
        screen(&mut app, 200, 40).contains(&format!("Saved certificate to '{}'.", saved.display()))
    );
    assert_eq!(
        fs::read_to_string(&saved).unwrap(),
        crown::asn1::pem::encode("CERTIFICATE", &leaf)
    );

    // The root is selected one row up; DER is chosen by the .der name.
    press(&mut app, KeyCode::Up);
    press(&mut app, KeyCode::Char('x'));
    app.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
    type_password(&mut app, "root.der");
    press(&mut app, KeyCode::Enter);
    assert_eq!(fs::read(directory.path().join("root.der")).unwrap(), root);

    // A chain cannot be DER; the prompt stays open with a red error.
    app.handle_key(KeyEvent::new(KeyCode::Char('X'), KeyModifiers::SHIFT));
    assert!(screen(&mut app, 120, 40).contains("Save chain to: "));
    app.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
    type_password(&mut app, "chain.der");
    press(&mut app, KeyCode::Enter);
    assert!(red_text(&mut app).contains("use a .pem name"));
    assert!(app.entry_details.as_ref().unwrap().exporting());
    press(&mut app, KeyCode::Esc);
    app.handle_key(KeyEvent::new(KeyCode::Char('X'), KeyModifiers::SHIFT));
    press(&mut app, KeyCode::Enter);
    let chain = fs::read_to_string(directory.path().join("server-chain.pem")).unwrap();
    assert_eq!(
        chain,
        [leaf, root]
            .map(|der| crown::asn1::pem::encode("CERTIFICATE", &der))
            .concat()
    );
    assert!(press(&mut app, KeyCode::Char('q')));
}
