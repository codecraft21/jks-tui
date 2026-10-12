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
