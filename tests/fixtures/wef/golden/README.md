# WEF golden wire vectors

Provenance: hand-written from the element structure of a real Windows 10 WEF capture
(described in openwec doc/protocol.md); no text copied; used by Rust parser tests and
the Python emulator tests.

Hostnames (`win10.example.com`, `logthing.example.com`) and GUIDs are ours. Files are stored
as UTF-8 for diffability; tests encode them to UTF-16LE with BOM before use.

`multipart_layout.txt` is the Kerberos-encrypted multipart body template with real CRLF line
endings. `{N}` and `<BINARY>` are literal placeholder text: tests substitute the plaintext
length for `{N}` and the encrypted bytes for `<BINARY>`, then compare.
