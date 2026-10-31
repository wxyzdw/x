#!/bin/sh
# OneISO transplant: move the ISO work from the NamikazeOS/-prefixed dev
# tree (commit 9cc0b74) onto the remote root-layout main (iso-main branch),
# verify with the full gate, build the image and commit.
set -eu
cd /home/z/my-project

echo "== [1/7] archive the committed dev tree"
rm -rf /tmp/nam-iso && mkdir -p /tmp/nam-iso
git archive 9cc0b74 NamikazeOS | tar -x -C /tmp/nam-iso
test -f /tmp/nam-iso/NamikazeOS/xtask/src/tasks/iso/mod.rs

echo "== [2/7] checkout remote-layout branch"
git checkout -f iso-main 2>/dev/null
test -f Cargo.toml
test -f xtask/src/main.rs

echo "== [3/7] transplant new files"
cp -r /tmp/nam-iso/NamikazeOS/xtask/src/tasks/iso xtask/src/tasks/iso
rm -f xtask/src/tasks/iso.rs
cp /tmp/nam-iso/NamikazeOS/iso/manifest/limine.lock iso/manifest/limine.lock
mkdir -p iso/payload/limine
cp -r /tmp/nam-iso/NamikazeOS/iso/payload/limine/v12.9.6 iso/payload/limine/
mkdir -p xtask/docs
cp /tmp/nam-iso/NamikazeOS/xtask/docs/ISO.md xtask/docs/

echo "== [4/7] patch shared files (idempotent, assertive)"
# .cargo/config.toml: add the cargo xtask alias
if ! grep -q 'xtask = ' .cargo/config.toml; then
cat >> .cargo/config.toml <<'EOF'

# `cargo xtask` is the documented build interface (see xtask/src/main.rs);
# the alias routes it through the workspace build orchestration crate.
[alias]
xtask = "run -p xtask --"
EOF
fi
grep -q 'xtask = ' .cargo/config.toml

# limine.conf: fix the stale generator reference
sed -i 's|# Placeholders substituted by scripts/mkiso.sh at ISO build time:|# Placeholders substituted by `cargo xtask iso` at ISO build time:|' iso/limine/limine.conf
grep -q 'cargo xtask iso` at ISO build time' iso/limine/limine.conf

# main.rs: extend the usage text
python3 - <<'PYEOF'
import sys
p = 'xtask/src/main.rs'
s = open(p).read()
if 'iso builds the OneISO image' not in s:
    old = '''    "tasks:  ci | sbom | verify | kernel-check [<.config>] | kernel-fragments",
    "        iso | ebuilds | bootid | release <out-dir>",
];'''
    new = '''    "tasks:  ci | sbom | verify | kernel-check [<.config>] | kernel-fragments",
    "        iso | ebuilds | bootid | release <out-dir>",
    "",
    "iso builds the OneISO image end to end (staging, ISO9660 + El Torito",
    "serialization, round-trip verification, SHA-256 seal) into dist/.",
];'''
    if old not in s:
        sys.exit('main.rs anchor not found')
    s = s.replace(old, new)
    open(p, 'w').write(s)
print('main.rs ok')
PYEOF

# ci.yml: add the ISO build step and release assets
python3 - <<'PYEOF'
import sys
p = '.github/workflows/ci.yml'
s = open(p).read()
if 'OneISO image' not in s:
    old = '''          cargo run -p xtask -- verify
      - name: Create release with artifacts'''
    new = '''          cargo run -p xtask -- verify
      - name: OneISO image (pure-Rust ISO9660 + El Torito writer)
        run: cargo run -p xtask -- iso
      - name: Create release with artifacts'''
    if old not in s:
        sys.exit('ci.yml anchor A not found')
    s = s.replace(old, new)
    s = s.replace(
        'dist/sbom.json dist/bootid dist/SHA256SUMS \\\n',
        'dist/NamikazeOS-*-oneiso.iso dist/NamikazeOS-*-oneiso.iso.sha256 \\\n            dist/sbom.json dist/bootid dist/SHA256SUMS \\\n')
    s = s.replace(
        'dist/sbom.json dist/bootid dist/SHA256SUMS\n',
        'dist/NamikazeOS-*-oneiso.iso dist/NamikazeOS-*-oneiso.iso.sha256 \\\n                 dist/sbom.json dist/bootid dist/SHA256SUMS\n')
    open(p, 'w').write(s)
print('ci.yml ok')
PYEOF

# CHANGELOG.md: insert the OneISO section before the components section
python3 - <<'PYEOF'
import sys
p = 'CHANGELOG.md'
s = open(p).read()
if 'OneISO image pipeline' not in s:
    entry = open('/tmp/changelog-entry.md').read()
    anchor = '### Added - new components'
    if anchor not in s:
        sys.exit('CHANGELOG anchor not found')
    s = s.replace(anchor, entry + anchor, 1)
    open(p, 'w').write(s)
print('CHANGELOG ok')
PYEOF

# .gitignore: make sure build outputs stay out of git
grep -q '^/dist' .gitignore || echo '/dist' >> .gitignore
grep -q '^/target' .gitignore || echo '/target' >> .gitignore

cp /tmp/changelog-entry.md /tmp/changelog-entry.md 2>/dev/null || true

echo "== [5/7] full gate"
export PATH="$HOME/.cargo/bin:$PATH"
cargo xtask ci 2>&1 | tail -4

echo "== [6/7] build the ISO twice (determinism proof)"
rm -f dist/bootid
cargo run -q -p xtask -- iso > /tmp/iso-run1.txt
sha256sum dist/NamikazeOS-*-oneiso.iso | tee /tmp/iso-sha-run1.txt
cargo run -q -p xtask -- iso > /tmp/iso-run2.txt
sha256sum dist/NamikazeOS-*-oneiso.iso | tee /tmp/iso-sha-run2.txt
a=$(cut -d' ' -f1 /tmp/iso-sha-run1.txt); b=$(cut -d' ' -f1 /tmp/iso-sha-run2.txt)
test "$a" = "$b" || { echo "NOT DETERMINISTIC"; exit 1; }
echo "deterministic: $a"

echo "== [7/7] commit on iso-main"
git add .cargo/config.toml .github/workflows/ci.yml CHANGELOG.md .gitignore \
    iso/limine/limine.conf iso/manifest/limine.lock iso/payload \
    xtask/src/main.rs xtask/src/tasks/iso.rs xtask/src/tasks/iso xtask/docs
git commit -m "OneISO pipeline: pure-Rust ISO9660 + El Torito image builder" \
    -m "cargo xtask iso builds the OneISO image end to end with zero external
tools and zero third-party crates: ECMA-119 serialization (PVD, El Torito
boot record, L+M path tables, Rock Ridge SP/RR/NM/PX), a no-emulation
BIOS + UEFI boot catalog with full validation checksum, staging of the
sha256-pinned Limine v12.9.6 payload (BSD-2-Clause boot firmware, not a
Cargo dependency), a round-trip verifier (structures + per-file SHA-256)
and deterministic output (byte-identical rebuilds, .sha256 release seal).
The CI release job now attaches the ISO and its checksum to GitHub
releases; the cargo xtask alias makes the documented interface work from
the repository root." 2>&1 | tail -3
git log --oneline -2
echo "== transplant complete"
