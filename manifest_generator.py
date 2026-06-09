import hashlib, json, time
from datetime import datetime, timezone
from pathlib import Path


class ManifestGenerator:
    def __init__(self, cfg):
        self.cfg = cfg

    def _hash_file(self, path):
        p = Path(path)
        try:
            data = p.read_bytes()
            return {
                "path": str(p),
                "filename": p.name,
                "sha256": hashlib.sha256(data).hexdigest(),
                "md5": hashlib.md5(data).hexdigest(),
                "size_bytes": len(data),
                "size_human": self._sz(len(data)),
                "modified_utc": datetime.fromtimestamp(
                    p.stat().st_mtime, tz=timezone.utc).isoformat()
            }
        except Exception as e:
            return {
                "path": str(p), "filename": p.name,
                "sha256": "ERROR", "md5": "ERROR",
                "size_bytes": 0, "modified_utc": "ERROR",
                "error": str(e)
            }

    @staticmethod
    def _sz(n):
        for u in ("B", "KB", "MB", "GB"):
            if n < 1024:
                return f"{n:.1f} {u}"
            n /= 1024
        return f"{n:.1f} TB"

    def generate(self, file_list):
        ts = int(time.time())
        utc = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
        entries, errors, total = [], 0, 0
        print(f"  [MANIFEST] Hashing {len(file_list)} file(s)...")
        for i, f in enumerate(sorted(file_list), 1):
            e = self._hash_file(f)
            entries.append(e)
            if e.get("error"):
                errors += 1
            else:
                total += e["size_bytes"]
            if i % 50 == 0:
                print(f"  [MANIFEST] {i}/{len(file_list)} hashed...")

        manifest = {
            "manifest_version": "1.0",
            "tool": "rayhunter-threat-analyzer",
            "generated_utc": utc,
            "total_files": len(entries),
            "total_size_bytes": total,
            "total_size_human": self._sz(total),
            "hash_errors": errors,
            "algorithm": "SHA-256 + MD5",
            "files": entries
        }

        jp = f"sha256_manifest_{ts}.json"
        Path(jp).write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        tp = f"sha256_manifest_{ts}.txt"
        lines = [
            "=" * 72,
            "RAYHUNTER THREAT ANALYZER - SHA-256 FORENSIC EVIDENCE MANIFEST",
            "=" * 72,
            f"Generated (UTC) : {utc}",
            f"Total files     : {len(entries)}",
            f"Total size      : {self._sz(total)}",
            f"Algorithm       : SHA-256 + MD5",
            f"Hash errors     : {errors}",
            "=" * 72, ""
        ]
        for e in entries:
            if e.get("error"):
                lines += [
                    f"ERROR  {e['filename']}",
                    f"  Error : {e['error']}", ""
                ]
            else:
                sz = e["size_bytes"]
                lines += [
                    f"SHA256  {e['sha256']}",
                    f"MD5     {e['md5']}",
                    f"  File : {e['filename']}",
                    f"  Path : {e['path']}",
                    f"  Size : {e['size_human']} ({sz:,} bytes)",
                    f"  Mod  : {e['modified_utc']}",
                    ""
                ]
        lines += ["=" * 72, "END OF MANIFEST", "=" * 72]
        Path(tp).write_text("\n".join(lines), encoding="utf-8")
        print(f"  [MANIFEST] Saved: {jp}")
        print(f"  [MANIFEST] Saved: {tp}")
        return jp
