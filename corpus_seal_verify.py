#!/usr/bin/env python3
"""
corpus_seal_verify.py — chain-of-custody sealing and verification.

PURPOSE
-------
This is the "do next" tool for the Hidden Blade investigation's quiet phase.
The case is with the AFP. The corpus's job now is to be a SEALED, PRESERVABLE
record and you a CONTACTABLE WITNESS. This tool does exactly that:

  seal   — walk the corpus, hash every file (SHA-256), and write a single
           master manifest. From all the per-file hashes it derives ONE root
           hash that fingerprints the entire corpus. Quote that root hash in
           your status note. If it ever matches again, the whole corpus is
           provably unchanged since the seal date.

  verify — re-walk the corpus later, recompute, and compare against the sealed
           manifest. Reports OK / CHANGED / MISSING / NEW per file, and whether
           the root hash still matches. This is what lets you (or anyone) prove
           months from now that nothing was altered.

This complements the existing manifest_generator / evidence_auto_builder. Those
build per-evidence manifests; this seals the WHOLE corpus under one root hash
and gives you a repeatable integrity check.

Nothing here transmits anything. It is local, read-only against your data
(except writing the manifest file itself), and deterministic.

USAGE
-----
  # seal the corpus (run once, now):
  python3 corpus_seal_verify.py seal  C:\\RH\\MASTER  --out corpus_seal_2026-06-10.json

  # verify later (run anytime someone asks "is it intact?"):
  python3 corpus_seal_verify.py verify  C:\\RH\\MASTER  --manifest corpus_seal_2026-06-10.json

Exit codes: 0 = all good / sealed; 1 = integrity differences found; 2 = usage error.
"""

import os
import sys
import json
import hashlib
import argparse
from datetime import datetime, timezone


CHUNK = 1024 * 1024  # 1 MiB read chunks (handles multi-GB captures)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def walk_files(root: str, ignore_exts):
    """Yield (relative_path, absolute_path) for every file under root."""
    for dirpath, _dirs, files in os.walk(root):
        for name in sorted(files):
            ext = os.path.splitext(name)[1].lower()
            if ext in ignore_exts:
                continue
            ap = os.path.join(dirpath, name)
            rp = os.path.relpath(ap, root).replace(os.sep, "/")
            yield rp, ap


def compute_manifest(root: str, ignore_exts):
    """Build {relpath: {sha256, size}} plus a derived root hash."""
    entries = {}
    for rp, ap in walk_files(root, ignore_exts):
        try:
            size = os.path.getsize(ap)
            digest = sha256_file(ap)
        except (OSError, IOError) as e:
            entries[rp] = {"error": str(e)}
            continue
        entries[rp] = {"sha256": digest, "size": size}

    # Root hash: deterministic over sorted "relpath:sha256" lines.
    # This single value fingerprints the entire corpus state.
    root_h = hashlib.sha256()
    for rp in sorted(entries):
        e = entries[rp]
        line = f"{rp}:{e.get('sha256','ERROR')}\n"
        root_h.update(line.encode("utf-8"))
    return entries, root_h.hexdigest()


def cmd_seal(args):
    if not os.path.isdir(args.root):
        print(f"ERROR: not a directory: {args.root}", file=sys.stderr)
        return 2
    ignore = set(e if e.startswith(".") else "." + e
                 for e in (args.ignore_ext or []))
    entries, root_hash = compute_manifest(args.root, ignore)
    total_bytes = sum(v.get("size", 0) for v in entries.values())
    errors = {k: v for k, v in entries.items() if "error" in v}

    manifest = {
        "manifest_type": "hidden_blade_corpus_seal",
        "version": 1,
        "sealed_at_utc": datetime.now(timezone.utc).isoformat(),
        "root_dir": os.path.abspath(args.root),
        "file_count": len(entries),
        "total_bytes": total_bytes,
        "root_hash_sha256": root_hash,
        "ignored_extensions": sorted(ignore),
        "files": entries,
    }
    out = args.out or f"corpus_seal_{datetime.now().strftime('%Y-%m-%d')}.json"
    with open(out, "w") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)

    print("CORPUS SEALED")
    print(f"  root dir   : {manifest['root_dir']}")
    print(f"  files      : {manifest['file_count']:,}")
    print(f"  total size : {total_bytes/1e9:.3f} GB ({total_bytes:,} bytes)")
    print(f"  manifest   : {out}")
    if errors:
        print(f"  WARNING    : {len(errors)} file(s) could not be read")
    print()
    print("  ROOT HASH (quote this in your status note):")
    print(f"  {root_hash}")
    return 0


def cmd_verify(args):
    if not os.path.isdir(args.root):
        print(f"ERROR: not a directory: {args.root}", file=sys.stderr)
        return 2
    if not os.path.isfile(args.manifest):
        print(f"ERROR: manifest not found: {args.manifest}", file=sys.stderr)
        return 2

    with open(args.manifest) as f:
        sealed = json.load(f)
    sealed_files = sealed.get("files", {})
    ignore = set(sealed.get("ignored_extensions", []))

    current, current_root = compute_manifest(args.root, ignore)

    changed, missing, new, ok = [], [], [], []
    for rp, sv in sealed_files.items():
        cv = current.get(rp)
        if cv is None:
            missing.append(rp)
        elif cv.get("sha256") != sv.get("sha256"):
            changed.append(rp)
        else:
            ok.append(rp)
    for rp in current:
        if rp not in sealed_files:
            new.append(rp)

    root_match = (current_root == sealed.get("root_hash_sha256"))

    print("CORPUS VERIFICATION")
    print(f"  manifest sealed : {sealed.get('sealed_at_utc')}")
    print(f"  files in seal   : {len(sealed_files):,}")
    print(f"  unchanged       : {len(ok):,}")
    print(f"  CHANGED         : {len(changed):,}")
    print(f"  MISSING         : {len(missing):,}")
    print(f"  NEW (not sealed): {len(new):,}")
    print()
    print(f"  sealed root hash : {sealed.get('root_hash_sha256')}")
    print(f"  current root hash: {current_root}")
    print(f"  ROOT HASH MATCH  : {'YES — corpus provably unchanged' if root_match else 'NO — corpus differs from seal'}")

    if changed:
        print("\n  CHANGED FILES:")
        for rp in changed[:50]:
            print(f"    {rp}")
        if len(changed) > 50:
            print(f"    ... and {len(changed)-50} more")
    if missing:
        print("\n  MISSING FILES:")
        for rp in missing[:50]:
            print(f"    {rp}")
        if len(missing) > 50:
            print(f"    ... and {len(missing)-50} more")
    if new:
        print("\n  NEW FILES (added since seal):")
        for rp in new[:50]:
            print(f"    {rp}")
        if len(new) > 50:
            print(f"    ... and {len(new)-50} more")

    return 0 if root_match else 1


def main():
    ap = argparse.ArgumentParser(description="Corpus chain-of-custody seal/verify")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("seal", help="hash the corpus and write a master manifest")
    sp.add_argument("root", help="corpus root directory")
    sp.add_argument("--out", help="output manifest path")
    sp.add_argument("--ignore-ext", nargs="*", default=[],
                    help="file extensions to skip (e.g. tmp log)")
    sp.set_defaults(func=cmd_seal)

    vp = sub.add_parser("verify", help="check the corpus against a sealed manifest")
    vp.add_argument("root", help="corpus root directory")
    vp.add_argument("--manifest", required=True, help="sealed manifest to verify against")
    vp.set_defaults(func=cmd_verify)

    args = ap.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
