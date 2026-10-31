# SPDX-License-Identifier: MPL-2.0
# NamikazeOS Rust userland precedence: prepend the namikaze-userland
# symlink farm so the hardened, deterministic Rust core tools override
# the base distribution utilities. Idempotent on re-source.
case ":$PATH:" in
    *":/usr/lib/namikaze/userland/bin:"*) ;;
    *) export PATH="/usr/lib/namikaze/userland/bin:$PATH" ;;
esac
