# jks-tui

TUI for Java KeyStore files, built with Rust and Ratatui.

Open a `.jks` file with the built-in terminal file browser, validate it with the
bounded JKS reader, and list its entry aliases and types (private keys or trusted
certificates).

## Run

Install the current stable Rust toolchain, then run from the repository root in
an interactive terminal:

```sh
cargo run --locked
```

Press `o` (or `Ctrl+O`) to open the keystore browser. It starts in the working
directory, or in the selected keystore's directory when reopening it. Directories
and `.jks` files (case-insensitive) are shown, with directories first.

| Key | Action in the file browser |
| --- | --- |
| `Up` / `Down` or `k` / `j` | Move the selection |
| `Home` / `End` | Jump to the first / last entry |
| `Enter` | Enter a directory or select a keystore |
| `Right` | Enter the selected directory |
| `Left` / `Backspace` or `Enter` on `../` | Go to the parent directory |
| `Esc` | Cancel and keep the previous selection |

After selection, enter the keystore password when prompted and press `Enter` to
verify it. Input is masked; `Backspace` deletes a character and `Esc` cancels.
Keys pressed with `Ctrl` or `Alt` are not typed into the password, except that on
Windows `Ctrl+Alt` (how Windows reports `AltGr`) types its character. The password
is wiped from memory after each attempt and when a character is deleted.
Empty-password keystores open immediately. The main view shows the keystore's
absolute path and a list of entry aliases and types. Use `Up` / `Down` or `j` / `k`
to scroll the entries, or `o` to open another file. Cancelling the browser or the
password prompt keeps the previously loaded keystore.

The app checks the JKS header, lengths, counts, and structure before asking for a
password. Entries are shown only after the password-based integrity check
succeeds. Files larger than 64 MiB are refused. As in Java, data after the
integrity digest is ignored, private-key entries are listed whatever the length
of their encrypted key, and only X.509 certificates are accepted. Every entry is
listed, even when several share an alias, sorted by alias. An alias containing an
unpaired UTF-16 surrogate (which Java allows) shows it as an escape such as
`\uD83D`. Invalid files, unreadable files, and failed integrity checks produce a
red error in the TUI. Java Unicode passwords and aliases (including supplementary
characters such as emoji) are supported. Private keys are neither decrypted nor
displayed. Only the JKS format is supported; PKCS#12 files renamed to `.jks` are
rejected.

Press `q` to quit from the browser or main view, `Esc` to quit from the main view,
or `Ctrl+C` to quit from any view (including the password prompt). The app restores
the terminal when it exits.

## Development

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```
