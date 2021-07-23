# v0.0.0

- Basic working functionality of chacha20 cipher stream
- Implement basic functionality of poly1305 mac
- aead on top of chacha20 and poly1305
- Test vector for basic functionality from rfc 8439 get passed

# v0.0.1

- Add extended chacha20 (xchacha20) support
- Modify poly1305 and aead to support xchacha20
- Add test to xchacha20
- Split initialization step of chacha20 state
- Change poly1305 utility to use big.Number.bytes()
- Struct based cipher operation
