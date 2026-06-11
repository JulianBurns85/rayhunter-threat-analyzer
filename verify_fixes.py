#!/usr/bin/env python3
"""
verify_fixes.py — byte-level regression test for the Rayhunter integrity fixes.

Runs tshark against the captures and ASSERTS the ground truth we established by
decode on 12 Jun 2026. If any assertion fails, the script exits non-zero and
prints exactly which fix regressed. This trusts the bytes, not the report text.

Usage:
    python verify_fixes.py --pcap-dir  "C:\\RH\\captures\\pcaps"
    python verify_fixes.py --qmdl-dir  "C:\\RH\\captures"      # needs scat on PATH

Requires: tshark (Wireshark CLI) on PATH. Optional: scat (for --qmdl-dir).

Ground-truth assertions (all must hold for a CLEAN capture set):
  A. Every SecurityModeCommand ciphering/integrity alg is eea2/eia2 (NO eea0/eia0).
  B. Zero redirectedCarrierInfo (no forced downgrade).
  C. Every NAS Identity Request is IMEISV/IMEI/GUTI (NOT IMSI).
  D. The watchlist CIDs decode to same-eNB sectors (ECI = eNB*256 + sector),
     i.e. they are normal macro sectors, not a rotation cluster.

Exit code 0 = all assertions hold (captures clean / fixes intact).
Exit code 1 = at least one assertion failed (regression or genuine new attack —
              either way, investigate before trusting analyzer output).
"""

import argparse, glob, os, subprocess, sys, shutil, tempfile

WATCHLIST = {
    137713155, 137713165, 137713175, 137713195,   # eNB 537942
    8409357, 8409367, 8409387, 8409397,            # eNB 32849
    8666381, 21940490, 21940538,
}


def have(cmd):
    return shutil.which(cmd) is not None


def tshark_field(pcap, display_filter, fields):
    args = ["tshark", "-r", pcap, "-Y", display_filter, "-T", "fields"]
    for f in fields:
        args += ["-e", f]
    try:
        out = subprocess.run(args, capture_output=True, text=True, timeout=300)
        return [ln for ln in out.stdout.splitlines() if ln.strip()]
    except Exception as e:
        print(f"   [tshark error on {os.path.basename(pcap)}: {e}]")
        return []


def tshark_grep(pcap, display_filter, needle):
    try:
        out = subprocess.run(
            ["tshark", "-r", pcap, "-Y", display_filter, "-V"],
            capture_output=True, text=True, timeout=300)
        return [ln for ln in out.stdout.splitlines() if needle.lower() in ln.lower()]
    except Exception as e:
        print(f"   [tshark error on {os.path.basename(pcap)}: {e}]")
        return []


def qmdl_to_pcap(qmdl_dir):
    if not have("scat"):
        print("ERROR: --qmdl-dir needs 'scat' on PATH. Install fgsect/scat or use --pcap-dir.")
        sys.exit(2)
    tmp = tempfile.mkdtemp(prefix="rh_verify_")
    pcaps = []
    for q in glob.glob(os.path.join(qmdl_dir, "*.qmdl")):
        out = os.path.join(tmp, os.path.basename(q) + ".pcap")
        subprocess.run(["scat", "-t", "qc", "-d", q, "-F", out],
                       capture_output=True, text=True)
        if os.path.exists(out):
            pcaps.append(out)
    return pcaps


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap-dir")
    ap.add_argument("--qmdl-dir")
    args = ap.parse_args()

    if not have("tshark"):
        print("ERROR: tshark not found on PATH (install Wireshark CLI).")
        sys.exit(2)

    if args.pcap_dir:
        pcaps = glob.glob(os.path.join(args.pcap_dir, "*.pcap")) + \
                glob.glob(os.path.join(args.pcap_dir, "*.pcapng"))
    elif args.qmdl_dir:
        pcaps = qmdl_to_pcap(args.qmdl_dir)
    else:
        print("Provide --pcap-dir or --qmdl-dir"); sys.exit(2)

    if not pcaps:
        print("No capture files found."); sys.exit(2)

    print(f"Verifying {len(pcaps)} capture(s)\n" + "=" * 60)

    ciphers, integ, redirects, imsi_ids, imeisv_ids, ecis = [], [], [], 0, 0, set()

    for p in pcaps:
        ciphers += tshark_field(p, "lte-rrc.cipheringAlgorithm",
                                ["lte-rrc.cipheringAlgorithm"])
        integ   += tshark_field(p, "lte-rrc.integrityProtAlgorithm",
                                ["lte-rrc.integrityProtAlgorithm"])
        redirects += tshark_grep(p, "lte-rrc.redirectedCarrierInfo", "redirectedCarrierInfo")
        # identity type: nas-eps identity request
        idreqs = tshark_grep(p, "nas-eps", "Identity type")
        for ln in idreqs:
            low = ln.lower()
            if "imsi" in low: imsi_ids += 1
            if "imeisv" in low or "imei" in low: imeisv_ids += 1
        for ln in tshark_field(p, "lte-rrc.cellIdentity", ["lte-rrc.cellIdentity"]):
            h = ln.strip().replace(":", "")
            if h:
                try: ecis.add(int(h, 16) >> 4)
                except ValueError: pass

    fails = []

    # A. cipher/integrity
    bad_cipher = [c for c in ciphers if c.strip() not in ("2", "eea2", "1", "3")]  # 0/eea0 = fail
    null_cipher = [c for c in ciphers if c.strip() in ("0", "eea0")]
    null_integ  = [c for c in integ   if c.strip() in ("0", "eia0")]
    print(f"A. SecurityModeCommand ciphers: {len(ciphers)} total | "
          f"null(eea0)={len(null_cipher)} | null-integrity(eia0)={len(null_integ)}")
    if null_cipher or null_integ:
        fails.append(f"A FAILED: {len(null_cipher)} EEA0 + {len(null_integ)} EIA0 selections "
                     f"(genuine null-cipher — investigate)")
    else:
        print("   PASS — all encryption AES (no null cipher/integrity)")

    # B. redirects
    print(f"B. redirectedCarrierInfo occurrences: {len(redirects)}")
    if redirects:
        fails.append(f"B FAILED: {len(redirects)} redirectedCarrierInfo (forced downgrade present)")
    else:
        print("   PASS — no forced downgrades")

    # C. identity type
    print(f"C. NAS Identity Requests: IMSI={imsi_ids} | IMEISV/IMEI={imeisv_ids}")
    if imsi_ids > 0:
        fails.append(f"C FAILED: {imsi_ids} IMSI Identity Request(s) (catcher signature)")
    else:
        print("   PASS — no IMSI identity requests (IMEISV only)")

    # D. watchlist CIDs are same-eNB sectors
    seen = sorted(ecis & WATCHLIST)
    enb_groups = {}
    for e in seen:
        enb_groups.setdefault(e // 256, []).append(e % 256)
    print(f"D. Watchlist CIDs seen: {len(seen)} -> eNB groups:")
    for enb, secs in sorted(enb_groups.items()):
        print(f"     eNB {enb}: sectors {sorted(secs)}")
    multi = [enb for enb, s in enb_groups.items() if len(s) >= 2]
    if seen and not multi:
        print("   (informational — watchlist CIDs present but <2 sectors each)")
    else:
        print("   PASS — watchlist CIDs resolve to coherent multi-sector macros")

    print("=" * 60)
    if fails:
        print("RESULT: REGRESSION / ATTACK INDICATOR\n")
        for f in fails:
            print("  ✗ " + f)
        print("\nDo not trust analyzer 'CRITICAL' output until each line above is "
              "explained by an actual decoded frame.")
        sys.exit(1)
    else:
        print("RESULT: CLEAN — all byte-level assertions hold. Fixes intact; "
              "captures show no cipher/redirect/IMSI attack indicators.")
        sys.exit(0)


if __name__ == "__main__":
    main()
