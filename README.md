# keystore-tui

A terminal app for inspecting Java keystores. Open a JKS, JCEKS, or PKCS12
(`.jks`, `.jceks`, `.p12`, `.pfx`) file, enter its password, and browse its
entries and certificates. It also
opens standalone certificate files (`.pem`, `.crt`, `.cer`, `.der`, `.p7b`,
`.p7c`), certificate signing requests (`.csr`, `.p10`), and certificate
revocation lists (`.crl`).

- Lists every entry with its type (private key, trusted certificate, or secret
  key), public key algorithm, key size, and expiry date. Certificates expiring
  within 30 days are shown in yellow and expired ones in red.
- Flags weak cryptography: RSA and DSA keys under 2048 bits, EC keys under 256
  bits, and MD2, MD5, or SHA-1 signatures.
- Filters entries by alias or subject, and sorts them by alias or expiry date.
- Shows each certificate's full details, including decoded extensions, and its
  certificate hierarchy, with each signature checked against the issuer's key.
- Shows a certificate request's subject, key, attributes, and requested
  extensions, and checks its signature. Shows a revocation list's issuer,
  update dates, extensions, and revoked certificates, and checks its signature
  against an issuer certificate in the same file.
- Exports a certificate, request, revocation list, or whole chain to a new PEM
  or DER file.
- Detects the format from the file content, so a PKCS12 store renamed `.jks`
  still opens.
- Opens PKCS12 files made by Java, OpenSSL, and other tools. Keys without a
  name are listed under their certificate's common name, and certificates that
  belong to no key are listed as `Certificate` entries.
- Read-only and self-contained: it never modifies existing files, never
  decrypts or displays private keys, and does not need Java or `keytool`.

## Install and run

Install the current stable Rust toolchain, then run from the repository root in
an interactive terminal:

```sh
cargo run --locked
```

## Usage

### Opening a file

Press `o` (or `Ctrl+O`) to open the file browser. It starts in the working
directory, or in the current file's directory when you open another file. It
shows directories first, then keystores (`.jks`, `.jceks`, `.p12`, `.pfx`),
certificate files (`.pem`, `.crt`, `.cer`, `.der`, `.p7b`, `.p7c`), requests
(`.csr`, `.p10`), and revocation lists (`.crl`).

| Key | Action in the file browser |
| --- | --- |
| `Up` / `Down` or `k` / `j` | Move the selection, wrapping at either end (including `../`) |
| `Home` / `End` | Jump to the first / last entry |
| `Enter` | Enter a directory or select a file |
| `Right` | Enter the selected directory |
| `Left` / `Backspace` or `Enter` on `../` | Go to the parent directory |
| `Esc` | Cancel and keep the previous selection |

After you select a file, type the keystore password and press `Enter`. Input is
masked, `Backspace` deletes a character, and `Esc` cancels. A keystore with an
empty password opens without asking. If the file is invalid, unreadable, or the
password is wrong, an error appears in red. Cancelling the browser or the
password prompt keeps the keystore that was already open.

A certificate file opens without a password. Each certificate in it, in PEM,
DER, or PKCS#7 form, is listed as a `Certificate` entry in file order, named by
its subject common name. Its hierarchy is built from the other certificates in
the same file. Certificate requests (PEM or DER PKCS#10) are listed the same way
as `Certificate request` entries, named by their subject. Revocation lists (PEM
or DER, or inside PKCS#7) are `Revocation list` entries, named by their issuer;
an issuer certificate in the same file is placed above the list in its
hierarchy. Private keys and other PEM blocks are not read; a yellow warning says
when some were present.

### Entry list

The main view lists the keystore's entries, sorted by alias. The status bar
shows the path of the open keystore, and the table's bottom border shows the
entry count, any filter, and the sort order.

| Column | Shows |
| --- | --- |
| Alias | The entry alias |
| Type | Private key, Trusted certificate, Secret key, Certificate, Certificate request, or Revocation list |
| Algorithm | The public key algorithm of the certificate or request (RSA, EC, DSA, Ed25519, ...) |
| Key size | The key size in bits (RSA/DSA modulus, EC curve size) |
| Expires | The certificate's expiry date (UTC): yellow within 30 days of expiry, red once it has passed. For a revocation list, its next update, red once it has passed |
| Crypto | `Weak`, in yellow, when the certificate's key is too short or its signature uses a broken hash |

| Key | Action in the entry list |
| --- | --- |
| `Up` / `Down` or `k` / `j` | Move the selection |
| `Enter` | Inspect the selected entry |
| `/` | Type a filter, or edit the applied one |
| `s` | Switch the sort order between alias and expiry date |
| `o` | Open another keystore or certificate file |

Press `/` to filter by part of the alias or the certificate subject (such as
`CN=example`), ignoring case. The list updates as you type, and every letter,
including `q` and `s`, goes into the filter. `Backspace` deletes a character,
`Enter` keeps the filter, and `Esc` clears it. To clear an applied filter, press
`/` and then `Esc`.

Press `s` to sort by expiry date, soonest first, and again to return to alias
order.

### Entry details

Pressing `Enter` on an entry opens a full-screen, read-only view. The top pane
shows the certificate hierarchy, with the entry's own certificate selected. The
bottom pane shows the selected certificate's fields: version, subject, issuer,
serial number, validity, public key, signature algorithm, SHA-256 or SHA-1
fingerprint, and extensions. Common extensions such as Subject Alternative Name,
Key Usage, Extended Key Usage, and Basic Constraints are decoded; others are
shown as their OID and value in hex.

Weak keys and signatures are explained in yellow below the signature algorithm,
and weak certificates are marked `[weak]` in the hierarchy. A self-signed
certificate's own signature is not flagged, because a root is trusted for where
it is stored rather than for its signature.

Each certificate's signature is checked offline with the public key of the
certificate above it in the hierarchy, or with its own key for a self-signed
root. The hierarchy marks each certificate `[verified]` in green, `[bad
signature]` in red, or `[unchecked]` when the issuer is not stored or the
algorithm is not supported, such as brainpool or secp256k1 keys. The details
explain the result below the signature algorithm.

| Key | Action in the detail view |
| --- | --- |
| `Tab` / `Shift+Tab` | Switch focus between hierarchy and details |
| `Up` / `Down` or `k` / `j` | Select a certificate or scroll the focused details |
| `PageUp` / `PageDown`, `Home` / `End` | Scroll details by a page or to the start / end |
| `f` | Toggle SHA-256 / SHA-1 fingerprints; kept while switching certificates |
| `x` | Export the selected certificate |
| `X` | Export the entry's whole chain, leaf first |
| `Esc` | Return to the entry list, preserving its selection and scroll position |
| `q` / `Ctrl+C` | Quit |

For a certificate request, the details show its subject, public key, signature
algorithm, attributes, and requested extensions. A challenge password is never
shown. Its signature is checked with its own public key, which only shows that
whoever made the request holds the matching private key. For a revocation list,
they show its issuer, this and next update (red once it is out of date),
signature algorithm, extensions, and each revoked serial number with its date
and reason. A list with more than 5,000 revoked certificates lists only the
first 5,000.

The hierarchy only shows certificates stored in the keystore. It does not fetch
missing issuers or check whether a certificate is trusted: a verified signature
only means the stored issuer's key made it, not that the chain is valid.

### Exporting certificates

Press `x` or `X` in the detail view, then edit the suggested file name and press
`Enter`. The suggestion is `<alias>.pem` (or `<alias>-chain.pem`) next to the
open file. A name ending in `.der` saves a single certificate, request, or
revocation list as DER; any other name saves PEM. Relative names are saved next to the open file. Every key,
including `q`, is typed into the name; `Backspace` deletes a character,
`Ctrl+U` clears the name, and `Esc` cancels. Existing files are never replaced:
the save fails with a red message and you can choose another name.

### Quitting

| Key | Quits from |
| --- | --- |
| `q` | The file browser, entry list (when not typing a filter), or detail view (when not typing an export name) |
| `Esc` | The entry list, when not typing a filter |
| `Ctrl+C` | Any view, including the password prompt and while typing a filter or export name |

The terminal is restored when the app exits.

## Limitations

- Keystores are read-only: there is no import or editing. Only certificates,
  requests, and revocation lists can be exported.
- Requests and revocation lists can be viewed, but not created or signed.
- Private keys are never decrypted, shown, or exported.
- Raw ASN.1 views and clipboard actions are not available yet.
- PKCS12 files must have an integrity MAC; PBMAC1 MACs are not supported.
- Files larger than 64 MiB are refused.

## More documentation

- [`docs/SPEC.md`](docs/SPEC.md): the detailed behaviour specification.
- [`AGENTS.md`](AGENTS.md): architecture, development checks, and contribution
  guidelines.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
