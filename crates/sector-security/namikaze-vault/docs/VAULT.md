# namikaze-vault

Encrypted XChaCha20-Poly1305 containers for tier-3 data (keys, recovery
codes, credentials).

## Why

Full-disk encryption protects the machine at rest but not the file that
must survive a machine loss. Vault containers are single-file,
authenticated-encryption stores that can live on removable media, and
their content never touches the page cache as plaintext mappings
because decryption happens in userspace memory only.

## Commands

    namikaze-vault new <container>
    namikaze-vault add <container> <file> [--as-name NAME]
    namikaze-vault list <container>
    namikaze-vault extract <container> <name>

- `new` creates a container and prompts twice for its passphrase
  (key derivation is Argon2-class KDF from `namikaze-rt`).
- `add` imports a file under its own name or `--as-name`; duplicate
  names are rejected instead of silently shadowing.
- `list` prints entry names and sizes, never contents.
- `extract` writes one entry to stdout or a file.

## Crypto

Per-container random 24-byte nonce prefix, XChaCha20-Poly1305 AEAD from
`namikaze-rt`, HMAC over the header so truncated or reordered
containers fail authentication before any plaintext is produced.
The crypto is compact and tested in-tree; see `namikaze-rt` docs for
the primitive design notes.
