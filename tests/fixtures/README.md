`trusted-cert.jks` is a Java-generated test fixture containing only a trusted
certificate (`root-cert`), with the test store password `changeit`. No private key
is included. Tests construct private-key entries at runtime using synthetic bytes,
so listing both entry types is covered without committing private keys.

Generate a replacement from this directory (remove the old fixture first):

```sh
fixture_dir=$(mktemp -d)
keytool -genkeypair -alias server-key -dname 'CN=JKS TUI test fixture' \
  -keyalg EC -groupname secp256r1 -validity 3650 -storetype JKS \
  -keystore "$fixture_dir/key.jks" -storepass changeit -keypass keypass
keytool -exportcert -alias server-key -keystore "$fixture_dir/key.jks" \
  -storepass changeit -file "$fixture_dir/cert.der"
keytool -importcert -noprompt -alias root-cert -file "$fixture_dir/cert.der" \
  -keystore trusted-cert.jks -storepass changeit -storetype JKS
rm "$fixture_dir/key.jks" "$fixture_dir/cert.der"
rmdir "$fixture_dir"
```

Tests read the committed fixture; Java is not required to run them.

`trusted-cert.p12` and `trusted-cert-legacy.p12` are generated Java PKCS12
truststores containing the same public certificate. `unicode-alias.p12` contains
that certificate under the alias `certificate-😀`. Recreate them with:

```sh
keytool -importkeystore -noprompt -srckeystore trusted-cert.jks \
  -srcstoretype JKS -srcstorepass changeit -destkeystore trusted-cert.p12 \
  -deststoretype PKCS12 -deststorepass changeit
keytool -J-Dkeystore.pkcs12.legacy=true -importkeystore -noprompt \
  -srckeystore trusted-cert.jks -srcstoretype JKS -srcstorepass changeit \
  -destkeystore trusted-cert-legacy.p12 -deststoretype PKCS12 \
  -deststorepass changeit
keytool -importkeystore -noprompt -srckeystore trusted-cert.jks \
  -srcstoretype JKS -srcstorepass changeit -srcalias root-cert \
  -destkeystore unicode-alias.p12 -deststoretype PKCS12 \
  -deststorepass changeit -destalias 'certificate-😀'
```

`empty-password.p12` and `nul-password.p12` contain the same certificate under
the alias `root-cert`, stored by Java with an empty password and with a single
NUL character as the password. Java opens both with an empty password. `keytool`
rejects such short passwords, so recreate them with `jshell` from this directory:

```sh
jshell -q <<'EOF'
var source = java.security.KeyStore.getInstance("PKCS12");
source.load(new java.io.FileInputStream("trusted-cert.p12"), "changeit".toCharArray());
for (var fixture : new String[][] {{"empty-password.p12", ""}, {"nul-password.p12", "\0"}}) {
  var store = java.security.KeyStore.getInstance("PKCS12");
  store.load(null, null);
  store.setCertificateEntry("root-cert", source.getCertificate("root-cert"));
  try (var out = new java.io.FileOutputStream(fixture[0])) { store.store(out, fixture[1].toCharArray()); }
}
/exit
EOF
```

Private-key and secret-key PKCS12 cases are generated only in memory by tests;
no private key fixture is committed. Neither Java nor `keytool` is needed to run
the app or its tests.

`unicode-password.jks` and `unicode-alias.jks` are copies of the same trusted
certificate fixture. The first uses the synthetic test password `pässwörd-😀` to
exercise Java's UTF-16 password digest encoding. The second keeps `changeit` and
uses the alias `certificate-😀` to exercise Java's modified UTF-8 string encoding.
Neither contains private keys. Recreate them from this directory with:

```sh
cp trusted-cert.jks unicode-password.jks
keytool -storepasswd -keystore unicode-password.jks -storetype JKS \
  -storepass changeit -new 'pässwörd-😀'
cp trusted-cert.jks unicode-alias.jks
keytool -changealias -keystore unicode-alias.jks -storetype JKS \
  -storepass changeit -alias root-cert -destalias 'certificate-😀'
```

`trusted-cert.jceks` holds the same certificate under `root-cert` in a JCEKS
store with the password `changeit`. JCEKS secret-key entries are built only in
memory by tests, from synthetic bytes in the layout Java writes. Recreate the
fixture with:

```sh
keytool -importkeystore -noprompt -srckeystore trusted-cert.jks \
  -srcstoretype JKS -srcstorepass changeit -destkeystore trusted-cert.jceks \
  -deststoretype JCEKS -deststorepass changeit
```

`openssl-cert.p12` and `openssl-cert-legacy.p12` are OpenSSL PKCS12 stores
containing only that certificate, with the password `changeit`. They have no
friendly names or Java trust attributes, as OpenSSL writes them. The first uses
OpenSSL 3's default AES encryption and the second its legacy RC2 encryption.
Recreate them with:

```sh
keytool -exportcert -rfc -alias root-cert -keystore trusted-cert.jks \
  -storepass changeit -file fixture.pem
openssl pkcs12 -export -nokeys -in fixture.pem -out openssl-cert.p12 \
  -passout pass:changeit
openssl pkcs12 -export -legacy -nokeys -in fixture.pem \
  -out openssl-cert-legacy.p12 -passout pass:changeit
rm fixture.pem
```

`openssl-request.csr` is an OpenSSL PEM certificate signing request for
`CN=keystore-tui test request`, with a 2048-bit RSA key and a Subject Alternative
Name extension request. `openssl-ca-crl.pem` holds a self-signed EC P-256 CA
certificate followed by a revocation list it signed, which revokes serial `0A`
for key compromise. Both private keys are deleted after signing. Recreate them
from this directory with:

```sh
work=$(mktemp -d)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$work/ca.key" -subj '/CN=keystore-tui test CA' -days 3650 \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' -out "$work/ca.pem"
openssl req -new -newkey rsa:2048 -nodes -keyout "$work/request.key" \
  -subj '/CN=keystore-tui test request' \
  -addext 'subjectAltName=DNS:request.example.test' -out openssl-request.csr
echo 1000 > "$work/crlnumber"
printf 'R\t360101000000Z\t240101000000Z,keyCompromise\t0A\tunknown\t/CN=revoked\n' \
  > "$work/index.txt"
printf '[ca]\ndefault_ca = test\n[test]\ndatabase = %s/index.txt\ncrlnumber = %s/crlnumber\ndefault_md = sha256\ndefault_crl_days = 3650\n' \
  "$work" "$work" > "$work/ca.cnf"
openssl ca -config "$work/ca.cnf" -gencrl -keyfile "$work/ca.key" \
  -cert "$work/ca.pem" -out "$work/crl.pem"
cat "$work/ca.pem" "$work/crl.pem" > openssl-ca-crl.pem
rm -r "$work"
```

Tests build other requests and revocation lists at runtime, signed with
synthetic Ed25519 secrets.
