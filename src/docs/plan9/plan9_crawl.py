#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Crawl the Plan 9 from Bell Labs source tree at http://9p.io/sources/plan9/
directory by directory, building the complete manifest that backs
usr/src/namikaze/docs/plan9/plan9-tree.json and plan9-adaptation.md.

Polite: 0.2s delay between requests, HTML cached under /tmp/plan9cache so
re-runs only fetch new pages. The listing rows are ls -l style
("d-rwxrwxr-x glenda sys 0 Jul 15 2018 <a href=...>"); the leading
permission character separates directories from files.

Usage:
  python3 plan9_crawl.py --out plan9-tree.json \
      [--delay S] [--max N] [--file RELATIVE/PATH]...
"""
import argparse
import html
import json
import os
import re
import sys
import time
import urllib.request

BASE = "http://9p.io/sources/plan9/"
CACHE = "/tmp/plan9cache"
ROW = re.compile(
    r"^(?P<perm>[d\-][rwx\-]{10})\s+(?P<owner>\S+)\s+(?P<group>\S+)\s+"
    r"(?P<size>\d+)\s+(?P<date>[A-Z][a-z]{2}\s+\d+\s+(?:\d{4}|\d{2}:\d{2}))\s+"
    r'<a href="(?P<href>[^"]+)">(?P<label>[^<]*)</a>',
    re.M,
)


def fetch(url: str, delay: float) -> bytes:
    """Fetch a URL with on-disk caching and polite pacing."""
    key = os.path.join(CACHE, url[len(BASE):].strip("/") or "ROOT").replace("/", ",")
    if os.path.exists(key) and os.path.getsize(key) > 0:
        with open(key, "rb") as fh:
            return fh.read()
    req = urllib.request.Request(url, headers={"User-Agent": "namikaze-plan9-inventory/1.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = resp.read()
    tmp = key + ".part"
    with open(tmp, "wb") as fh:
        fh.write(data)
    os.replace(tmp, key)
    time.sleep(delay)
    return data


def parse_listing(raw: bytes, rel: str):
    """One directory page -> (entries, errors)."""
    text = raw.decode("utf-8", "replace")
    entries, errs = [], []
    for match in ROW.finditer(text):
        href = html.unescape(match.group("href"))
        label = html.unescape(match.group("label"))
        name = label if label else href
        if name in (".",):
            continue
        is_dir = match.group("perm").startswith("d")
        try:
            size = int(match.group("size"))
        except ValueError:
            size = -1
        entries.append(
            {
                "n": name,
                "d": is_dir,
                "s": size,
                "t": match.group("date"),
                "o": match.group("owner"),
            }
        )
    if not entries:
        # empty listings are real: mount-point stubs are empty on purpose
        errs.append(f"no rows parsed for {rel}")
    return entries, errs


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--delay", type=float, default=0.2)
    ap.add_argument("--max", type=int, default=4000)
    ap.add_argument("--out", default="plan9-tree.json")
    ap.add_argument("--file", action="append", default=[],
                    help="extra file path (relative) to record and cache")
    args = ap.parse_args()
    os.makedirs(CACHE, exist_ok=True)

    dirs = [""]  # relative dir paths, "" = root
    seen = set()
    manifest = []
    extra_files = []
    errors = []

    while dirs and len(seen) < args.max:
        rel = dirs.pop(0)
        if rel in seen:
            continue
        seen.add(rel)
        url = BASE + (rel + "/" if rel else "")
        try:
            raw = fetch(url, args.delay)
        except Exception as exc:  # log and continue the sweep
            errors.append(f"{rel}: {exc}")
            continue
        entries, errs = parse_listing(raw, rel)
        errors.extend(errs)
        subdirs = []
        total_files = 0
        total_bytes = 0
        for entry in entries:
            if entry["d"]:
                subdirs.append((rel + "/" + entry["n"]) if rel else entry["n"])
            else:
                total_files += 1
                total_bytes += entry["s"]
        manifest.append(
            {
                "path": rel or ".",
                "url": url,
                "dirs": sum(1 for e in entries if e["d"]),
                "files": total_files,
                "bytes": total_bytes,
                "entries": entries,
            }
        )
        dirs.extend(d for d in subdirs if d not in seen)
        if len(seen) % 25 == 0:
            print(f"[{len(seen)} dirs swept, {len(dirs)} queued]", flush=True)

    for rel in args.file:
        url = BASE + rel
        try:
            raw = fetch(url, args.delay)
            extra_files.append({"path": rel, "bytes": len(raw)})
            key = os.path.join(CACHE, rel.replace("/", ","))
            with open(key, "wb") as fh:
                fh.write(raw)
        except Exception as exc:  # a missing extra file is not fatal
            errors.append(f"file {rel}: {exc}")

    total_dirs = len(manifest)
    total_files = sum(m["files"] for m in manifest)
    total_bytes = sum(m["bytes"] for m in manifest)
    inventory = {
        "source": BASE,
        "crawled_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "totals": {"directories": total_dirs, "files": total_files, "bytes": total_bytes},
        "errors": errors,
        "extra_files": extra_files,
        "dirs": manifest,
    }
    out = os.path.abspath(args.out)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(inventory, fh, ensure_ascii=False, separators=(",", ":"))
    print(f"done: {total_dirs} directories, {total_files} files, {total_bytes} bytes -> {out}")
    if errors:
        print(f"{len(errors)} empty/unreadable listings (mount stubs are expected)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
