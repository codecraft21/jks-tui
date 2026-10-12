# jks-tui

TUI for Java KeyStore files, built with Rust and Ratatui.

This first iteration only opens the TUI and lets you quit. The `jks` dependency
is included for future KeyStore support and is not used yet.

## Run

Install the current stable Rust toolchain, then run from the repository root in
an interactive terminal:

```sh
cargo run --locked
```

Press `q`, `Esc`, or `Ctrl+C` to quit. The app restores the terminal when it exits.

## Development

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```
