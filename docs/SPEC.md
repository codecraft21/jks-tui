# keystore-tui behaviour specification

This document is the reference for how keystore-tui behaves. The key bindings
are listed in [`README.md`](../README.md). When behaviour changes, update this
document, and also the README if users will notice.

## Contents

- [Scope](#scope)
- [File selection](#file-selection)
- [Loading and validation](#loading-and-validation)
  - [JKS compatibility (matching Java)](#jks-compatibility-matching-java)
  - [JCEKS compatibility](#jceks-compatibility)
  - [PKCS12 compatibility](#pkcs12-compatibility)
  - [Certificate files](#certificate-files)
- [Password prompt](#password-prompt)
- [Entry list](#entry-list)
  - [Filtering](#filtering)
  - [Sorting](#sorting)
- [Entry details](#entry-details)
  - [Certificate requests](#certificate-requests)
  - [Weak cryptography](#weak-cryptography)
  - [Extensions](#extensions)
  - [Certificate hierarchy](#certificate-hierarchy)
  - [Exporting](#exporting)
  - [Small terminals](#small-terminals)
- [Visual style](#visual-style)
- [Quitting and terminal restoration](#quitting-and-terminal-restoration)

## Scope

- The app reads Java KeyStore (JKS), JCEKS, and PKCS12 files, standalone
  certificate files, and PKCS#10 certificate requests. It never writes or
  modifies them.
- The only files it writes are new certificate and request exports; see
  [Exporting](#exporting).
- It runs without Java or `keytool` installed.
- Private keys are never decrypted, displayed, or exported.
- The following are out of scope for now: import, keystore editing, raw ASN.1
  views, and clipboard actions.

## File selection

- The browser starts in the working directory. If a keystore is open, it starts
  in that keystore's directory.
- It lists directories, then files whose extension is `.jks`, `.jceks`, `.p12`,
  `.pfx`, `.pem`, `.crt`, `.cer`, `.der`, `.p7b`, `.p7c`, `.csr`, or `.p10`
  (case-insensitive). Directories come first.
- A `../` entry leads to the parent directory. Selection wraps at both ends, and
  `../` takes part in the wrap.
- Cancelling the browser keeps the keystore that was already loaded.

## Loading and validation

- Files larger than 64 MiB are refused.
- The format comes from the file content where it is unambiguous:
  1. The JKS magic number means JKS, and the JCEKS magic number means JCEKS.
  2. A PEM `-----BEGIN ` line means a certificate file.
  3. Otherwise a `.p12` or `.pfx` name means PKCS12, and a certificate-file
     extension means a DER certificate or PKCS#7 bundle.
  4. Other DER content is tried as a certificate file, then as PKCS12.
  5. Anything else is read as JKS, so its error describes a JKS file.
- **JKS and JCEKS:** the header, lengths, counts, and structure are checked
  before the password prompt appears.
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

### JCEKS compatibility

- JCEKS has the JKS layout and integrity digest, and everything under
  [JKS compatibility](#jks-compatibility-matching-java) applies to it.
- It adds secret-key entries, shown as `Secret key`. Java stores each one as a
  serialized `SealedObject` without a length, so the app walks the Java
  serialization grammar to find where it ends. The sealed key is never
  decrypted or deserialized, and no class is loaded.
- A secret key that is not a `com.sun.crypto.provider.SealedObjectForKeyProtector`,
  uses serialization features Java does not write for sealed keys (enums, proxy
  classes, externalizable objects, resets, or exceptions), or nests more than 32
  levels deep is reported as an error.
- Secret-key entries in a JKS file are an error, as they are in Java.

### PKCS12 compatibility

- PKCS12 stores from Java, OpenSSL, and other tools are supported with either
  current AES encryption or older legacy encryption. A store must have an
  integrity MAC; PBMAC1 (RFC 9579) is not supported.
- Unicode aliases are supported.
- A key without a friendly name, as OpenSSL writes when not given `-name`, is
  listed under the subject name (common name, else the full subject) of the
  certificate sharing its local key ID, else as `Private key N`.
- Certificates marked with Java's trusted-key-usage attribute are `Trusted
  certificate` entries, named by their friendly name. A certificate without it
  is listed as a `Certificate` entry unless it is part of a private key's
  chain. Such an entry is named by its friendly name, else its subject name,
  else `Certificate N`.
- A verified store may still contain entries that cannot be read. In that case
  the readable entries are listed, along with a persistent warning that the list
  is incomplete.

### Certificate files

- A certificate file opens without a password prompt.
- Accepted forms:
  - PEM blocks labelled `CERTIFICATE`, `X509 CERTIFICATE`, or `TRUSTED
    CERTIFICATE` (OpenSSL's trust settings after the certificate are ignored)
  - PEM `PKCS7` or `CMS` blocks, and DER PKCS#7 SignedData; their X.509
    certificates are listed and anything else in them is ignored
  - a single DER certificate, which must be one complete DER element
  - PEM blocks labelled `CERTIFICATE REQUEST` or `NEW CERTIFICATE REQUEST`
    (as `keytool -certreq` writes), and a single DER PKCS#10 request, which
    must be one complete DER element
- Text outside PEM blocks is ignored. Other PEM blocks, such as private keys,
  are not decoded; a persistent yellow warning says some were skipped.
- A malformed PEM block, invalid Base64, or a file without any certificate or
  request is an error. A certificate inside a PEM block that cannot be decoded is still
  listed, as for keystores.
- Each certificate is one entry of type `Certificate`, and each request one
  entry of type `Certificate request`, listed in file order (the alias sort
  keeps that order). The alias is the subject common name, else the whole
  subject, else `Certificate N` or `Certificate request N` for its position in
  the file. Requests are never part of a certificate's chain.

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
  sorted by alias by default; entries sharing an alias keep their stored order.
- Columns: Alias, Type, Algorithm, Key size, Expires, Crypto. The meaning of
  each column is in the README.
- For a private-key entry, the certificate used for the columns is the first one
  in its chain. In PKCS12, that is the certificate that shares the key's local
  key ID.
- Secret keys and unreadable certificates show `-` in the certificate columns.
- A certificate request shows its public key's algorithm and size, and `-`
  under Expires. Its Crypto column checks only the key size; see
  [Certificate requests](#certificate-requests).
- An unrecognized algorithm is shown as its OID.
- Key size means the modulus size for RSA and DSA, and the curve size for EC.
- Expiry dates are in UTC. They are yellow when the certificate expires within
  30 days and red once it has expired.
- The Crypto column shows `Weak` in yellow when the entry's certificate has a
  weakness (see [Weak cryptography](#weak-cryptography)), and is empty
  otherwise. It checks the entry's own certificate, not the rest of its chain.
- A status bar above the keyboard shortcuts shows the keystore's absolute path as
  `Path: '<path>'`. Paths too long for the terminal width are clipped.
- The table's bottom border shows, right-aligned, the entry count and sort order,
  for example `3 entries | Sort: alias`. With a filter it shows the filter and
  how many entries match, for example `Filter: 'web' | 2 of 9 entries | Sort:
  expiry`; while the filter is being typed it is shown with a trailing `_`
  instead of quotes.
- `/` and `s` do nothing when no keystore is loaded or it has no entries.

### Filtering

- `/` starts typing a filter, or resumes editing the applied one.
- The filter is a case-insensitive substring match against the alias and the
  certificate subject distinguished name (for example `CN=example`). An entry
  whose subject cannot be decoded matches on its alias only.
- The list updates as the filter is typed. While typing, every character
  without `Ctrl` or `Alt` goes into the filter, including `q`, `s`, `o`, `j`,
  and `k`. `Up` / `Down` still move the selection, `Backspace` deletes a
  character, `Enter` keeps the filter, and `Esc` clears it. `Ctrl+C` still
  quits.
- With the filter applied and not being typed, all list keys, including the
  quit keys, work as usual.
- When nothing matches, the list shows "No matching entries." with a hint on how
  to edit or clear the filter, and `Enter` does nothing.
- Opening another keystore clears the filter.

### Sorting

- `s` switches between alias order and expiry order.
- Expiry order puts the soonest expiry first and entries without an expiry date,
  including certificate requests, last. The sort is stable, so entries with equal dates keep their alias order.
- The sort order is kept when another keystore is opened.
- Filtering and sorting keep the same entry selected while it is still listed;
  otherwise the first listed entry is selected. The detail view always opens
  the selected entry, and returning from it restores the filtered list.

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
  - signature algorithm, followed by one yellow `Weak: ...` line for each
    weakness of the certificate, then the signature check; see
    [Signature checks](#signature-checks)
  - fingerprint: SHA-256 by default, SHA-1 as an alternative. Both are computed
    over the original certificate bytes. The chosen fingerprint stays selected
    when switching certificates.
  - extensions; see [Extensions](#extensions).
- Long values wrap and can be scrolled. Switching certificates resets the detail
  scroll position.
- An entry without certificates still opens, with an explanation.
- If one certificate in a chain cannot be read, the other chain members are
  still shown.

### Certificate requests

- A certificate request entry opens in the same full-screen view. The top pane,
  titled "Certificate request", has one row: the request's subject (or
  `Certificate request (unreadable or unnamed)`), followed by `[weak]` when its
  key is short and the signature tag. The bottom pane, titled "Request
  details", has focus when the view opens, so `Up` / `Down` scroll it.
- The details show, in order:
  - alias and type
  - version (the stored value plus one, as for certificates)
  - subject
  - public key algorithm and size
  - signature algorithm, followed by a yellow `Weak: ...` line for a short key,
    then the signature check
  - fingerprint, SHA-256 or SHA-1 as for certificates, over the request's bytes
  - "Requested extensions:", from the PKCS#9 extension request attribute (or
    Microsoft's `1.3.6.1.4.1.311.2.1.14`), decoded as in
    [Extensions](#extensions); `Requested extensions: None` when there are none
  - "Attributes:", only when the request has other attributes. A challenge
    password is shown as `Present; not shown.` and its value is never
    displayed. An unstructured name is shown as text, with control characters
    escaped. Other attributes show their OID and each value in hex. An
    extension request whose value cannot be decoded is listed here with
    `Could not decode; value:` and its hex, and a malformed attribute as
    "Malformed attribute" with its encoding in hex.
  - a closing note that a request has no issuer or validity and is not trusted.
- A request whose fields cannot be decoded shows "Certificate request could not
  be decoded." and its fingerprint.
- The signature is checked with the request's own public key, as for a
  self-signed certificate. The details line reads `verified with its own public
  key.`, `does not verify with its own public key: <reason>.`, or `not checked
  (<reason>).`, with the colours and supported algorithms of
  [Signature checks](#signature-checks).
- Only the key size is checked for weakness. The signature hash is not flagged,
  because the issued certificate is signed by the CA, not with the request's
  hash.
- `x` exports the request; `X` does nothing. See [Exporting](#exporting).

### Weak cryptography

- A certificate is weak when either:
  - its RSA, RSASSA-PSS, or DSA key is shorter than 2048 bits, or its EC curve
    is smaller than 256 bits (NIST SP 800-131A); or
  - it is signed with MD2, MD5, or SHA-1 (RSA, ECDSA, or DSA signatures).
- The signature of a self-signed certificate (issuer and subject encoded
  identically) is not checked: a root is trusted for where it is stored, not
  for its signature. Its key size is still checked.
- Keys of unknown size, unrecognized algorithms, and other signature algorithms
  are not flagged. This check reads only the stored fields; signatures are
  checked separately, see [Signature checks](#signature-checks).
- In the hierarchy, a weak certificate's label ends with `[weak]` in yellow.

### Extensions

- An "Extensions:" section follows the fingerprint and scrolls with the other
  fields. A certificate without extensions shows `Extensions: None`.
- Each extension is listed in certificate order by name and dotted OID, with
  ` [critical]` appended when flagged, and its decoded values indented below.
- Decoded extensions:

  | Extension | Shows |
  | --- | --- |
  | Subject / Issuer Alternative Name | DNS names, IPv4/IPv6 addresses, emails, URIs, directory names, registered IDs; other name forms in hex |
  | Key Usage | Named usages on one line (Digital Signature, Certificate Sign, ...); unknown bits as `Bit N` |
  | Extended Key Usage | `serverAuth`, `clientAuth`, `codeSigning`, `emailProtection`, `timeStamping`, `OCSPSigning`, `anyExtendedKeyUsage`; others as dotted OIDs |
  | Basic Constraints | CA flag and path length (`unlimited` for a CA without one) |
  | Subject / Authority Key Identifier | Key identifiers in hex; the authority's issuer names and serial when present |
  | CRL Distribution Points | Distribution point names (usually URIs) and CRL issuers; reasons and relative names in hex |
  | Authority Information Access | OCSP and CA Issuers locations |
  | Certificate Policies | Policy OIDs, naming `anyPolicy` and the CA/Browser Forum validation levels; qualifiers are not shown |

- Other extensions show their OID and `Value:` in hex. Hex is colon-separated
  uppercase, as for fingerprints.
- A known extension whose value cannot be decoded, including truncated or
  trailing data, shows `Could not decode; value:` with the value in hex. An
  extension whose own structure is malformed is shown as "Malformed extension"
  with its encoding in hex. Neither hides the other fields or extensions, and
  neither prevents chain linking.
- Control characters in decoded names are shown escaped, for example `\u{1b}`,
  so they cannot affect the terminal.

### Certificate hierarchy

- **JKS:** the hierarchy is the chain stored in the keystore.
- **PKCS12:** the app links certificates stored in the file by issuer identity
  and by any authority and subject key identifiers. It stops with an explanation
  when an issuer is missing or ambiguous, or when it finds a cycle.
- **Certificate files:** each entry's chain follows issuer names to the first
  certificate in the same file with that subject. Names are compared by their
  decoded text, ignoring case. The chain stops at a self-issued certificate, a
  missing issuer, or a certificate already in the chain.
- The app never fetches certificates and never verifies trust.

### Signature checks

- Each certificate's signature is checked with the public key of the next
  certificate in the hierarchy (its stored issuer). The last certificate is
  checked with its own key when it is self-issued (issuer and subject decode to
  the same name); otherwise its issuer is not stored and it is not checked.
- Checks run offline when the detail view opens. Only the signature is checked:
  names, validity, basic constraints, key usage, and revocation are not, and no
  trust decision is made. A verified self-signature only shows that the root
  certificate is intact.
- Results, as a tag at the end of each hierarchy label (after any `[weak]`) and
  as a `Signature:` line in the details:

  | Result | Tag | Details line |
  | --- | --- | --- |
  | Verified | `[verified]`, green | `verified with the public key of <issuer subject>.` or `verified with its own public key (self-signed).`, green |
  | Failed | `[bad signature]`, red | `does not verify with ...: <reason>.`, red |
  | Unchecked | `[unchecked]` | `not checked (<reason>).` |

- A signature fails when the signature algorithm inside the signed part differs
  from the one outside it, when the issuer's key type cannot make that kind of
  signature, or when the signature does not match the signed bytes.
- A signature is unchecked when the issuer is not stored, when either
  certificate cannot be decoded, or when the signature algorithm or the issuer's
  key type is not supported.
- Supported signatures include RSA PKCS#1 v1.5, RSASSA-PSS made by RSA keys,
  ECDSA on P-256, P-384, and P-521, DSA, Ed25519, and Ed448. Keys of type
  RSASSA-PSS, brainpool curves, and secp256k1 are not supported.

### Exporting

- `x` exports the certificate selected in the hierarchy; `X` exports every
  certificate stored with the entry, leaf first. Neither does anything for an
  entry without certificates. For a certificate request entry, `x` exports the
  request and `X` does nothing.
- A prompt replaces the detail shortcuts. It suggests `<alias>.pem`,
  `<alias>-chain.pem`, or `<alias>.csr` for a request, in the open file's
  directory. Characters other than
  letters, digits, `-`, `_`, and `.` in the alias become `_`, and a name that
  already exists gets a number, such as `server-2.pem`.
- While the prompt is open, every character without `Ctrl` or `Alt` is typed
  into the name, including `q`, `x`, and `j`. `Backspace` deletes a character,
  `Ctrl+U` clears the name, `Enter` saves, and `Esc` cancels without leaving the
  detail view. `Ctrl+C` still quits.
- A relative name is resolved against the open file's directory.
- A `.der` name (case-insensitive) saves one certificate or the request as raw
  DER; a chain cannot be saved as DER. Any other name saves PEM `CERTIFICATE`
  blocks, or a `CERTIFICATE REQUEST` block for a request, with 64-character
  lines. The DER is written byte for byte as stored.
- The file must not exist yet; it is never replaced. On success a green message
  names the saved file and the prompt closes. On failure a red message explains
  why and the prompt stays open to correct the name. The message clears on the
  next key.

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
- Dates expiring within 30 days, and not yet expired, are yellow. On the
  selected row they are bold black on an amber (`Rgb(255, 175, 0)`) background
  instead. A `Weak` crypto marker uses the same colours.

## Quitting and terminal restoration

- `q` quits from the browser, the entry list, and the detail view, except while
  an export name is being typed; see [Exporting](#exporting).
- `Esc` quits from the entry list.
- While a filter is being typed, `q` and `Esc` edit the filter instead; see
  [Filtering](#filtering).
- `Ctrl+C` quits from any view, including the password prompt and while typing
  a filter or an export name.
- The terminal is restored on normal exit, on errors, and when initialization
  fails. Restoring means raw mode is turned off, the alternate screen is left,
  and the cursor is visible again.
