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
