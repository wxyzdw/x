#!/usr/bin/env python3
"""Independent El Torito + ISO9660 validator for NamikazeOS OneISO.

Parses the image strictly per ECMA-119 and the El Torito spec v1.0 and
cross-checks file extents against the staging tree. Deliberately does NOT
reuse the xtask reader so writer bugs cannot self-verify.
"""
import hashlib
import struct
import sys

BLOCK = 2048


def perr(msgs, m):
    msgs.append(("FAIL", m))


def pok(msgs, m):
    msgs.append(("ok  ", m))


def le32(b, off):
    return struct.unpack_from("<I", b, off)[0]


def be32(b, off):
    return struct.unpack_from(">I", b, off)[0]


def main(iso_path, staging):
    img = open(iso_path, "rb").read()
    msgs = []
    if len(img) % BLOCK:
        perr(msgs, f"image length {len(img)} not sector aligned")
    sectors = len(img) // BLOCK
    pok(msgs, f"image {len(img)} bytes = {sectors} sectors")

    # ---- descriptor set walk (real spec order, not assumed offsets) ----
    vds = []
    s = 16
    while s < min(sectors, 64):
        typ = img[s * BLOCK]
        tag = img[s * BLOCK + 1: s * BLOCK + 6]
        if tag != b"CD001":
            perr(msgs, f"sector {s}: descriptor without CD001 tag (type={typ})")
            break
        vds.append((s, typ))
        if typ == 255:
            break
        s += 1
    kinds = {1: "PVD", 0: "boot record", 2: "SVD", 255: "terminator"}
    seq = [f"{kinds.get(t, t)}@{o}" for o, t in vds]
    pok(msgs, "descriptor set: " + ", ".join(seq))
    pvd_at = next((o for o, t in vds if t == 1), None)
    boot_at = next((o for o, t in vds if t == 0), None)
    term_at = next((o for o, t in vds if t == 255), None)
    if pvd_at != 16:
        perr(msgs, f"PVD at sector {pvd_at}, expected 16")

    # ---- PVD ----
    p = pvd_at * BLOCK
    if img[p + 6] != 1:
        perr(msgs, "PVD version != 1")
    volid = img[p + 40: p + 72].decode("ascii", "replace").rstrip(" \0")
    space = le32(img, p + 80)
    lbs = le32(img, p + 128)
    pt_size = le32(img, p + 132)
    pt_l = le32(img, p + 140)
    pt_m = be32(img, p + 148)
    root_len = img[p + 156]
    root_ext = le32(img, p + 158)
    root_size = le32(img, p + 166)
    root_flags = img[p + 156 + 25]
    fsv = img[p + 874]
    pok(msgs, f"PVD volume id {volid!r}, block size {lbs}")
    if lbs != BLOCK:
        perr(msgs, f"logical block size {lbs}")
    if space != sectors:
        perr(msgs, f"volume space size {space} != image sectors {sectors}")
    else:
        pok(msgs, "volume space size matches image")
    if fsv != 1:
        perr(msgs, f"file structure version {fsv}")
    if root_len != 34 or not root_flags & 2:
        perr(msgs, "root directory record malformed")
    else:
        pok(msgs, f"root dir at LBA {root_ext}, size {root_size}")

    # ---- El Torito boot record (spec: catalog pointer at offset 71, LE) ----
    cat_lba = None
    if boot_at is None:
        perr(msgs, "no El Torito boot record volume descriptor")
    else:
        b = boot_at * BLOCK
        sysid = img[b + 8: b + 40]
        if not sysid.startswith(b"EL TORITO SPECIFICATION"):
            perr(msgs, f"boot record system id {sysid[:24]!r}")
        else:
            pok(msgs, "boot record VD system id 'EL TORITO SPECIFICATION'")
        raw71 = le32(img, b + 71)
        raw72 = le32(img, b + 72)
        pok(msgs, f"boot catalog pointer @71 = {raw71}, @72 = {raw72}")
        cat_lba = raw71
        if raw71 <= 16 or raw71 >= sectors:
            perr(msgs, f"catalog pointer at spec offset 71 invalid ({raw71})")
        else:
            pok(msgs, f"El Torito catalog pointer valid at offset 71: LBA {raw71}")

    # ---- boot catalog ----
    if cat_lba is not None and 0 < cat_lba < sectors:
        c = cat_lba * BLOCK
        # validation entry
        hdr, plat = struct.unpack_from("<H", img, c)[0], struct.unpack_from("<H", img, c + 2)[0]
        key = img[c + 30: c + 32]
        words = [struct.unpack_from("<H", img, c + i * 2)[0] for i in range(16)]
        csum = (sum(words) & 0xFFFF)
        ident = img[c + 4: c + 28].decode("ascii", "replace").rstrip()
        if hdr != 1:
            perr(msgs, f"validation entry header id {hdr} != 1")
        if plat != 0:
            perr(msgs, f"validation entry platform {plat} != 0 (BIOS)")
        if key != b"\x55\xaa":
            perr(msgs, f"validation entry key {key.hex()} != 55aa")
        if csum != 0:
            perr(msgs, f"validation checksum sum={csum:#06x} (must be 0)")
        else:
            pok(msgs, f"validation entry ok (id {ident!r}, checksum zero-sum)")
        # initial/default entry at +32
        e = c + 32
        if img[e] != 0x88:
            perr(msgs, f"initial entry boot indicator {img[e]:#04x} != 0x88")
        if img[e + 1] != 0:
            perr(msgs, f"initial entry media type {img[e+1]} != 0 (no emulation)")
        seg = struct.unpack_from("<H", img, e + 2)[0]
        cnt = struct.unpack_from("<H", img, e + 6)[0]
        rba = le32(img, e + 8)
        pok(msgs, f"BIOS entry: bootable, no-emulation, load seg {seg:#06x}, "
                  f"{cnt} virtual sectors, RBA {rba}")
        # section header at +64
        sh = c + 64
        if img[sh] != 0x91:
            perr(msgs, f"section header {img[sh]:#04x} != 0x91 (last)")
        elif img[sh + 1] != 0xEF:
            perr(msgs, f"section platform {img[sh+1]:#04x} != 0xEF (UEFI)")
        else:
            n = struct.unpack_from("<H", img, sh + 2)[0]
            sid = img[sh + 4: sh + 32].decode("ascii", "replace").rstrip()
            pok(msgs, f"UEFI section header ok ({n} entry, id {sid!r})")
        # section entry at +96
        e2 = c + 96
        if img[e2] != 0x88 or img[e2 + 1] != 0:
            perr(msgs, f"UEFI entry flags {img[e2]:#04x}/{img[e2+1]:#04x}")
        else:
            cnt2 = struct.unpack_from("<H", img, e2 + 6)[0]
            rba2 = le32(img, e2 + 8)
            pok(msgs, f"UEFI entry: bootable, no-emulation, {cnt2} virtual sectors, RBA {rba2}")

        # verify boot entries point at the real staged payloads
        for name, rba, cnt in [("limine-bios-cd.bin", rba, cnt),
                               ("limine-uefi-cd.bin", rba2, cnt2)]:
            data = open(f"{staging}/{name}", "rb").read()
            want = (len(data) + 511) // 512
            got = img[rba * BLOCK: rba * BLOCK + len(data)]
            if cnt != want:
                perr(msgs, f"{name}: catalog sector count {cnt} != {want}")
            if got != data:
                perr(msgs, f"{name}: extent bytes differ from staged payload")
            else:
                pok(msgs, f"{name}: catalog RBA {rba} matches staged payload")

    # ---- path tables ----
    if pt_size == 0:
        perr(msgs, "path table size 0")
    l_at, m_at = pt_l * BLOCK, pt_m * BLOCK
    if img[l_at: l_at + 40] == b"\x00" * 40:
        perr(msgs, f"L path table at {pt_l} is zeroed")
    else:
        pok(msgs, f"L path table @ {pt_l}, M @ {pt_m}, size {pt_size}")
    dirs = {}
    pos, idx = l_at, 0
    while pos < l_at + pt_size:
        ln = img[pos]
        if ln == 0:
            break
        ext = le32(img, pos + 2)
        parent = struct.unpack_from("<H", img, pos + 6)[0]
        name = img[pos + 8: pos + 8 + ln]
        idx += 1
        dirs[idx] = (ext, name.decode("ascii", "replace"), parent)
        pos += 8 + ln + ((8 + ln) % 2)
    if not dirs or dirs[1][0] != root_ext:
        perr(msgs, "L path table first entry is not the root")
    else:
        pok(msgs, f"L path table: {len(dirs)} entries, root extent ok")

    # ---- directory walk + file hashes vs staging ----
    files, bad_names, out_of_range = {}, [], []

    def recs(ext, size):
        pos, end = ext * BLOCK, ext * BLOCK + size
        out = []
        while pos < end:
            ln = img[pos]
            if ln == 0:
                pos = (pos // BLOCK + 1) * BLOCK
                continue
            rec = img[pos: pos + ln]
            out.append(rec)
            pos += ln
        return out

    def susp_names(rec):
        idl = rec[32]
        pos = 33 + idl
        if pos % 2:
            pos += 1
        name, px = b"", None
        while pos + 4 <= len(rec):
            sig, ln, ver = rec[pos: pos + 2], rec[pos + 2], rec[pos + 3]
            if ln < 4 or pos + ln > len(rec):
                break
            if sig == b"NM":
                name += rec[pos + 5: pos + ln]
            if sig == b"PX":
                px = struct.unpack_from("<I", rec, pos + 4)[0]
            pos += ln
        return (name.decode("utf-8", "replace") if name else None), px

    def walk(ext, size, prefix):
        first = True
        for rec in recs(ext, size):
            idl = rec[32]
            rid = rec[33: 33 + idl].decode("ascii", "replace")
            if first and rid == ".":
                first = False
                nm, _ = susp_names(rec)
                continue
            if rid == "..":
                continue
            first = False
            is_dir = bool(rec[25] & 2)
            fext = le32(rec, 2)
            fsize = le32(rec, 10)
            nm, px = susp_names(rec)
            real = nm or rid.split(";")[0]
            rel = f"{prefix}/{real}"
            if fext * BLOCK + fsize > len(img):
                out_of_range.append(rel)
            if is_dir:
                walk(fext, fsize, rel)
            else:
                files[rel] = (fext, fsize, px)
                digest = hashlib.sha256(img[fext * BLOCK: fext * BLOCK + fsize]).hexdigest()
                try:
                    sdata = open(f"{staging}/{rel}", "rb").read()
                except OSError:
                    perr(msgs, f"/{rel} missing from staging")
                    continue
                if hashlib.sha256(sdata).hexdigest() != digest:
                    perr(msgs, f"/{rel} content hash mismatch")

    walk(root_ext, root_size, "")
    pok(msgs, f"directory walk: {len(dirs)} dirs (path table), {len(files)} files hashed")

    # every staged file must appear in the ISO
    import os
    staged_all = []
    for dp, _, fns in os.walk(staging):
        for fn in fns:
            staged_all.append(os.path.relpath(os.path.join(dp, fn), staging))
    missing = [s for s in sorted(staged_all) if f"/{s}" not in files]
    if missing:
        perr(msgs, f"staged files missing from ISO: {missing[:8]}")
    else:
        pok(msgs, f"all {len(staged_all)} staged files present in image")

    if out_of_range:
        perr(msgs, f"extents out of range: {out_of_range[:5]}")

    fails = [m for s, m in msgs if s == "FAIL"]
    for s, m in msgs:
        print(f"[{s}] {m}")
    print(f"\nRESULT: {'FAIL' if fails else 'PASS'} ({len(fails)} failures, "
          f"{len(msgs) - len(fails)} checks ok)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
