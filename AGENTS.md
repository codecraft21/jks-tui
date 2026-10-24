# Agent and contributor guide

keystore-tui is a small, read-only Rust and Ratatui TUI for inspecting JKS,
JCEKS, and PKCS12 keystores, standalone certificate files, and certificate
signing requests. [`README.md`](README.md) describes the app from the user's
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
| `src/certificate_file.rs` | PEM, DER, and PKCS#7 certificate files (including requests), and chain linking within a file |
| `src/certificate_request.rs` | PKCS#10 certificate requests: fields, requested extensions, and attributes |
| `src/file_picker.rs` | The keystore file browser |
| `src/keystore.rs` | JKS and JCEKS parsing and integrity check (SHA-1); the shared `KeystoreEntry` model |
| `src/java_serialization.rs` | Skipping a serialized Java object (a JCEKS secret key) without deserializing it |
| `src/pkcs12.rs` | PKCS12 parsing, MAC verification, and decryption of safe contents (AES and legacy PBE) |
| `src/entry_list.rs` | Entry-list filtering, sorting, and expiry classification |
| `src/certificate.rs` | X.509 summary (subject, algorithm, key size, expiry) for the entry table |
| `src/certificate/details.rs` | Full certificate fields for the detail view |
| `src/certificate/extensions.rs` | Decoding X.509 extensions into display lines |
| `src/certificate/security.rs` | Weak key-size and signature-hash checks |
| `src/certificate/signature.rs` | Checking a certificate's signature with its issuer's public key, and a request's with its own |
| `src/entry_details.rs` | The full-screen detail view and the certificate hierarchy |
| `src/export.rs` | The export name prompt and writing PEM/DER certificate and request files |
| `src/test_support.rs`, `src/tests.rs` | Unit-test helpers, synthetic keystores, and tests |
| `tests/terminal_smoke.py` | PTY smoke tests against the built binary |
| `tests/fixtures/` | Generated keystore fixtures; see its `README.md` for how they were made |

Dependencies are deliberately few:

- `ratatui`, with the `crossterm` backend, for the UI.
- `sha1` for the JKS and JCEKS integrity digest.
- `crown` for ASN.1, PEM, X.509, PKCS#7, PKCS12 (MAC and PBE), and signature
  verification (certificates and requests).
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
signature checks, fingerprints, extensions, resizing, and returning to the list. They also build a
three-entry store at runtime from copies of that certificate to exercise
filtering (including `q` typed into the filter and `Esc` cancelling it) and
sorting. They also open a PEM certificate file and export it, checking that `q`
is typed into the export name and `Esc` cancels the prompt. They open the
`keytool` certificate request fixture, check its signature is verified, and
export it as PEM. They check that `q`,
`Esc`, and `Ctrl+C` (including while typing a filter) restore terminal modes, leave the alternate screen, and show the cursor
again.

CI (`.github/workflows/rust.yml`) runs all of the above on Linux for every push
to `main` and every pull request.

For TUI changes, also check rendering, input, and terminal restoration by hand
in an interactive terminal.

### Fixtures

Fixtures are generated with Java `keytool`, and a few with OpenSSL. The
commands are recorded in `tests/fixtures/README.md`. Java and OpenSSL are needed
only to regenerate fixtures, never to build, test, or run the app. Tests that need private-key entries build them at
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
  Certificate exports only ever create new files.

## Documentation

- `README.md` is the user's view: what the app does, how to run it, key bindings,
  and limitations. Update it when user-visible behaviour changes.
- `docs/SPEC.md` holds the detailed behaviour contracts, such as validation
  rules, compatibility details, colours, and edge cases. Update it with every
  behaviour change.
- This file covers architecture, development, and conventions. Update it when
  modules, checks, or workflows change.

## Workflow

When the user says "publish", do the following without asking for confirmation.
Use the configured GitHub plugin for every GitHub step, so that no Git
credentials are needed in the workspace. Use local Git only for inspection and
checkouts.

1. Run the [Development](#development) checks and fix any failures.
2. Commit to a feature branch, never `main`, and push it.
3. Open a pull request against `main`.
4. When CI finishes, merge if every check passed. If a check failed, fix it and
   push again, or report what is failing.
5. After merging, switch to `main`, pull, and delete the local feature branch.

When reporting back, give the pull request link, what changed, which checks ran
and their results, and any unresolved failures.
