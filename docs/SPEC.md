# keystore-tui behaviour specification

This document is the reference for how keystore-tui behaves. The key bindings
are listed in [`README.md`](../README.md). When behaviour changes, update this
document, and also the README if users will notice.

## Scope

- The app reads Java KeyStore (JKS) and Java-generated PKCS12 files. It never
  writes or modifies them.
- It runs without Java or `keytool` installed.
- Private keys are never decrypted or displayed.
- The following are out of scope for now: import, export, certificate
  extensions, PEM and ASN.1 views, and clipboard actions.

## File selection

- The browser starts in the working directory. If a keystore is open, it starts
  in that keystore's directory.
- It lists directories, then files whose extension is `.jks`, `.p12`, or `.pfx`
  (case-insensitive). Directories come first.
- A `../` entry leads to the parent directory. Selection wraps at both ends, and
  `../` takes part in the wrap.
- Cancelling the browser keeps the keystore that was already loaded.

## Loading and validation

- Files larger than 64 MiB are refused.
- The format comes from the file content, not the extension.
- **JKS:** the header, lengths, counts, and structure are checked before the
  password prompt appears.
- **PKCS12:** the outer structure is checked before the password prompt appears.
  The file must have an integrity MAC.
- Entries are shown only after the password-based integrity check succeeds.
- A keystore with an empty password opens without a prompt.
- An invalid file, an unreadable file, or a failed integrity check produces a red
  error message in the TUI.

### JKS compatibility (matching Java)

- Data after the integrity digest is ignored.
- Private-key entries are listed whatever the length of their encrypted key.
- Only X.509 certificates are accepted.
- Unicode passwords and aliases are supported, including supplementary characters
  such as emoji.
- Java allows an alias to contain an unpaired UTF-16 surrogate. Such a surrogate
  is shown as an escape, for example `\uD83D`.

### PKCS12 compatibility

- Java PKCS12 stores are supported with either current AES encryption or older
  legacy encryption.
- Unicode aliases are supported.
- A verified store may still contain entries that cannot be read. In that case
  the readable entries are listed, along with a persistent warning that the list
  is incomplete.

## Password prompt

- Input is masked. `Backspace` deletes a character, `Enter` submits, and `Esc`
  cancels.
- Keys pressed with `Ctrl` or `Alt` are not typed into the password. The
  exception is Windows: it reports `AltGr` as `Ctrl+Alt`, so that combination
  types its character there.
- The password buffer is wiped after each attempt and whenever a character is
  deleted.
- Cancelling the prompt keeps the keystore that was already loaded.

## Entry list

- Every entry is listed, even when several entries share an alias. Entries are
  sorted by alias.
- Columns: Alias, Type, Algorithm, Key size, Expires. The meaning of each column
  is in the README.
- For a private-key entry, the certificate used for the columns is the first one
  in its chain. In PKCS12, that is the certificate that shares the key's local
  key ID.
- Secret keys and unreadable certificates show `-` in the certificate columns.
- An unrecognized algorithm is shown as its OID.
- Key size means the modulus size for RSA and DSA, and the curve size for EC.
- Expiry dates are in UTC and turn red once they have passed.
- A status bar above the keyboard shortcuts shows the keystore's absolute path as
  `Path: '<path>'`. Paths too long for the terminal width are clipped.

## Entry details

- The view is full-screen and read-only, and it does not change the entry list's
  state. Returning to the list keeps the list's selection and scroll position.
- The top pane is a selectable certificate hierarchy, starting with the leaf
  certificate selected. The bottom pane shows the fields of the selected
  certificate:
  - version
  - subject and issuer
  - serial number, in both hexadecimal and decimal
  - validity timestamps in UTC; "Valid Until" turns red once the certificate
    has expired
  - public key algorithm and size
  - signature algorithm
  - fingerprint: SHA-256 by default, SHA-1 as an alternative. Both are computed
    over the original certificate bytes. The chosen fingerprint stays selected
    when switching certificates.
- Long values wrap and can be scrolled. Switching certificates resets the detail
  scroll position.
- An entry without certificates still opens, with an explanation.
- If one certificate in a chain cannot be read, the other chain members are
  still shown.

### Certificate hierarchy

- **JKS:** the hierarchy is the chain stored in the keystore.
- **PKCS12:** the app links certificates stored in the file by issuer identity
  and by any authority and subject key identifiers. It stops with an explanation
  when an issuer is missing or ambiguous, or when it finds a cycle.
- The app never fetches certificates and never verifies trust or signatures.

### Small terminals

- When the panes cannot fit, a resize hint is shown instead. The back and quit
  shortcuts still work while the hint is shown.

## Visual style

- The app name at the top is shown in blue.
- The selected row has a `>` marker and bold black text on a light cyan
  background. The colours are explicit RGB values, so contrast stays the same
  across terminal palettes.
- Expired dates are red. On the selected row they are bold white on a dark red
  background instead.

## Quitting and terminal restoration

- `q` quits from the browser, the entry list, and the detail view.
- `Esc` quits from the entry list.
- `Ctrl+C` quits from any view, including the password prompt.
- The terminal is restored on normal exit, on errors, and when initialization
  fails. Restoring means raw mode is turned off, the alternate screen is left,
  and the cursor is visible again.
