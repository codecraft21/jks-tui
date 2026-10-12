# jks-tui

TUI for Java KeyStore files, built with Rust and Ratatui.

Open a `.jks` file with the built-in terminal file browser to display its full,
absolute path. The file's contents are not read or parsed yet; the `jks`
dependency is included for future KeyStore support.

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

After selection, the main view displays the keystore's absolute path. Press `q`
or `Ctrl+C` to quit from either view, or `Esc` to quit from the main view. The app
restores the terminal when it exits.

## Development

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```
