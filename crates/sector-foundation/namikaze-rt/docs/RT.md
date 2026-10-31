# namikaze-rt

The foundation runtime library: the small, tested primitives every
other crate builds on. This is where the zero-third-party-dependency
rule is paid down once, so no other crate has to.

## Modules

| module   | provides                                              |
| -------- | ----------------------------------------------------- |
| aead     | XChaCha20-Poly1305 authenticated encryption            |
| args     | tiny CLI model (subcommand, flags, free args, usage)   |
| b64      | base64 encode/decode (standard alphabet, padding)      |
| fsutil   | recursive walking, atomic writes, permission helpers   |
| hex      | hex encode/decode                                      |
| hmac     | HMAC-SHA-256                                           |
| http     | minimal HTTP/1.1 client and request parsing            |
| json     | JSON value model, parser and pretty printer            |
| log      | leveled logging with timestamps                        |
| lz       | LZ77-class compression used by archive tooling         |
| prompt   | terminal prompts (password, confirm)                   |
| random   | OS entropy interface, ids and hex tokens               |
| sha256   | SHA-256 (file and incremental)                         |
| toml     | TOML subset parser and value model                     |

## Design rules

- std-only, `#![forbid(unsafe_code)]`: entropy comes from the OS, not
  from a reimplementation.
- Every primitive carries round-trip and known-answer tests in-tree;
  crypto modules use published test vectors.
- APIs are boring on purpose: bytes in, bytes out, `Result` everywhere,
  no globals, no threads hidden inside the library.

## When to extend

If a crate needs a new primitive (a cipher, a format, a parser), it is
added here with tests, not pulled in from outside. Keep modules small
and independently testable; the SBOM reports this crate as the
dependency root of all others.
