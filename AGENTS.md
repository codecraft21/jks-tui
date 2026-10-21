# Agent and contributor guide

keystore-tui is a small, read-only Rust and Ratatui TUI for inspecting JKS and
PKCS12 keystores. [`README.md`](README.md) describes the app from the user's
point of view. [`docs/SPEC.md`](docs/SPEC.md) specifies its detailed behaviour.
This file covers how the code is organised and how to work on it.

## Contents

- [Architecture](#architecture)
- [Development](#development)
  - [Fixtures](#fixtures)
- [Conventions and constraints](#conventions-and-constraints)
- [Documentation](#documentation)
- [Workflow](#workflow)

## Architecture

| Module | Responsibility |
| --- | --- |
| `src/main.rs` | App state, event loop, main view rendering, password prompt, file loading (size limit, format detection), terminal setup and restoration |
| `src/file_picker.rs` | The keystore file browser |
| `src/keystore.rs` | JKS parsing and integrity check (SHA-1); the shared `KeystoreEntry` model |
| `src/pkcs12.rs` | PKCS12 parsing, MAC verification, and decryption of safe contents (AES and legacy PBE) |
| `src/certificate.rs` | X.509 summary (algorithm, key size, expiry) for the entry table |
| `src/certificate/details.rs` | Full certificate fields for the detail view |
| `src/entry_details.rs` | The full-screen detail view and the certificate hierarchy |
| `src/test_support.rs`, `src/tests.rs` | Unit-test helpers, synthetic keystores, and tests |
| `tests/terminal_smoke.py` | PTY smoke tests against the built binary |
| `tests/fixtures/` | Generated keystore fixtures; see its `README.md` for how they were made |

Dependencies are deliberately few:

- `ratatui`, with the `crossterm` backend, for the UI.
- `sha1` for the JKS integrity digest.
- `crown` for ASN.1, X.509, and PKCS12 (MAC and PBE).
- `zeroize` for wiping passwords.

## Development

Cargo sets `TMPDIR` to the repository root for builds and tests (see
`.cargo/config.toml`). Temporary files therefore stay inside the workspace even
when the system temporary directory is unavailable.

Run these after any code or dependency change:

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

On Linux, macOS, or WSL, also run the PTY smoke tests after building. They need
Python 3 and use only its standard library:

```sh
cargo build --locked
python3 tests/terminal_smoke.py
```

To test a build in another location, pass
`--binary /absolute/path/to/keystore-tui`.

The smoke tests use a generated public-certificate fixture with an empty
password. They exercise opening a keystore, detail navigation, scrolling,
fingerprints, resizing, and returning to the list. They also check that both `q`
and `Ctrl+C` restore terminal modes, leave the alternate screen, and show the
cursor again.

CI (`.github/workflows/rust.yml`) runs all of the above on Linux for every push
to `main` and every pull request.

For TUI changes, also check rendering, input, and terminal restoration by hand
in an interactive terminal.

### Fixtures

Fixtures are generated with Java `keytool`. The commands are recorded in
`tests/fixtures/README.md`. Java is needed only to regenerate fixtures, never to
build, test, or run the app. Tests that need private-key entries build them at
runtime from synthetic bytes, so no private key is ever committed.

## Conventions and constraints

- **Scope:** keep changes focused on the small TUI. Add modules as
  responsibilities grow rather than enlarging existing ones.
- **Self-contained:** opening keystores must work without Java or `keytool`.
- **Dependencies:** keep dependencies and their enabled features to a minimum.
  Check that a new dependency is really needed before adding it.
- **Terminal safety:** keep terminal restoration working on initialization
  failure, on errors, and on normal exit. Keep every documented quit shortcut.
- **Secrets:** use generated fixtures only. Keep passwords, private keys, and
  real keystores out of logs, test output, and commits. Wipe password buffers
  after use.
- **Read-only:** the app never writes keystores and never decrypts private keys.

## Documentation

- `README.md` is the user's view: what the app does, how to run it, key bindings,
  and limitations. Update it when user-visible behaviour changes.
- `docs/SPEC.md` holds the detailed behaviour contracts, such as validation
  rules, compatibility details, colours, and edge cases. Update it with every
  behaviour change.
- This file covers architecture, development, and conventions. Update it when
  modules, checks, or workflows change.

## Workflow

- Use the configured GitHub plugin to publish commits, create pull requests,
  check CI, and merge. Use local Git for inspection and checkout management.
  Publishing must not require Git credentials in the workspace.
- When reporting back, say what changed, which checks ran, and any unresolved
  failures.
