# keystore-tui

TUI for Java KeyStore and Java PKCS12 files, built with Rust and Ratatui.

Open a `.jks`, `.p12`, or `.pfx` file with the built-in terminal file browser and
list its entry aliases and types (private keys, trusted certificates, or PKCS12
secret keys), with each certificate's public key algorithm, key size, and expiry
date. The format is detected from the file content, so a PKCS12 store
renamed `.jks` also opens.

## Run

Install the current stable Rust toolchain, then run from the repository root in
an interactive terminal:

```sh
cargo run --locked
```

Press `o` (or `Ctrl+O`) to open the keystore browser. It starts in the working
directory, or in the selected keystore's directory when reopening it. Directories
and `.jks`, `.p12`, and `.pfx` files (case-insensitive) are shown, with directories
first.

| Key | Action in the file browser |
| --- | --- |
| `Up` / `Down` or `k` / `j` | Move the selection, wrapping at either end (including `../`) |
| `Home` / `End` | Jump to the first / last entry |
| `Enter` | Enter a directory or select a keystore |
| `Right` | Enter the selected directory |
| `Left` / `Backspace` or `Enter` on `../` | Go to the parent directory |
| `Esc` | Cancel and keep the previous selection |

After selection, enter the keystore password when prompted and press `Enter` to
verify it. Input is masked; `Backspace` deletes a character and `Esc` cancels.
Keys pressed with `Ctrl` or `Alt` are not typed into the password, except that on
Windows `Ctrl+Alt` (how Windows reports `AltGr`) types its character. The password
input buffer is wiped after each attempt and when a character is deleted.
Empty-password keystores open immediately. The main view shows the keystore's
absolute path and a table of entries with these columns:

| Column | Shows |
| --- | --- |
| Alias | The entry alias |
| Type | Private key, Trusted certificate, or Secret key |
| Algorithm | The certificate's public key algorithm (RSA, EC, DSA, Ed25519, ...) |
| Key size | The key size in bits (RSA/DSA modulus, EC curve size) |
| Expires | The certificate's expiry date (UTC), in red once it has passed |

For a private key, the certificate is the first one in its chain (for PKCS12, the
certificate sharing the key's local key ID). Secret keys, and certificates that
cannot be read, show `-` in these columns. Unrecognized algorithms show their
OID. Use `Up` / `Down` or `j` / `k`
to scroll the entries, or `o` to open another file. Cancelling the browser or the
password prompt keeps the previously loaded keystore.

The app checks the JKS header, lengths, counts, and structure before asking for a
password. For PKCS12, it checks the outer structure and requires an integrity MAC.
Entries are shown only after the password-based integrity check succeeds. Java
PKCS12 stores using current AES or older legacy encryption are supported. If a
verified PKCS12 store contains unreadable entries, readable entries appear with
a persistent warning that the list is incomplete. Files larger than 64 MiB are
refused. As in Java, data after the JKS integrity digest is ignored, private-key
entries are listed whatever the length of their encrypted key, and only X.509
certificates are accepted. Every entry is
listed, even when several share an alias, sorted by alias. An alias containing an
unpaired UTF-16 surrogate (which Java allows) shows it as an escape such as
`\uD83D`. Invalid files, unreadable files, and failed integrity checks produce a
red error in the TUI. JKS Unicode passwords and aliases (including supplementary
characters such as emoji) are supported; PKCS12 Unicode aliases are also supported.
Private keys are neither decrypted nor displayed. The app runs without
Java or `keytool` installed. PKCS12 compatibility targets Java-generated stores.

Press `q` to quit from the browser or main view, `Esc` to quit from the main view,
or `Ctrl+C` to quit from any view (including the password prompt). The app restores
the terminal when it exits.

## Development

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```
