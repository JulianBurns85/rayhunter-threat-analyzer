# How to apply the patches (auto-patcher)

The modules are already in your repo root and import fine. The only missing step
is wiring them into main.py. Don't hand-edit — run the patcher.

## Steps (in the repo root)
```powershell
cd C:\RH\rayhunter-threat-analyzer
python patch_main.py
```
It will:
- back up main.py -> main.py.bak
- insert the reconcile call after 'elapsed = time.time() - start'
- insert the corpus-guard block before the 'if args.format ... json' block
- print what it did
- it's idempotent: running twice is safe (detects existing patch)

## Verify it parsed
```powershell
python -c "import ast; ast.parse(open('main.py',encoding='utf-8').read()); print('main.py parses OK')"
```

## Re-run
```powershell
python main.py --dir "C:\Users\Jessum Chap\Desktop\June Ray Files\11.06.26" --verbose
```

## What you'll now see that was MISSING before
Right after "Total events: 13,845" / before PHASE 2:
```
  [RECONCILE] CID-rotation downgraded: one eNB (32849), sectors [13, 23, 43, 53] - normal macro.
  [RECONCILE] CID-rotation downgraded: one eNB (537942), sectors [3, 13, 23, 43] - normal macro.
  [RECONCILE] Novel-CID 21940490 capped to INFO (verify against register).
  [RECONCILE] Handover-inject quarantined (no reconfig in events).
```
And before the JSON is written:
```
  [GUARD] 3 issue(s) - report stamped UNVERIFIED:
     [COUNT_OVERFLOW] 'RegulatoryEscalationScorer' event_count=9,425 exceeds ...
     [GEO_UNSOURCED] 'Forensic Map' makes a location claim with no in-capture measurement ...
     [UNTAGGED_SOURCE] 'RegulatoryEscalationScorer' appears to use external/CASTNET data ...
```
In the findings list, the two CID Rotation clusters and both Novel CIDs drop to
INFO, and the handover finding carries verification_status=UNVERIFIED.

## If something looks wrong
Restore instantly:
```powershell
copy /Y main.py.bak main.py
```
Then paste me the console and we'll adjust.

## NOTE on the heuristic banner
The "[HEURISTIC] 9/10 CONFIRMED / YAICD 5.00" line and the PLATFORM FUSION block
are computed by HeuristicScorerDetector and PlatformFusionEngine, which run
*inside* run_analysis BEFORE reconcile. So those headline lines won't change yet
- the reconcile pass corrects the per-finding severities and the guard stamps the
report, but the YAICD score is computed upstream. Fixing the YAICD/fusion to read
post-reconcile findings is the next patch (it needs heuristic_scorer.py and
fusion_engine.py). Flagging so the unchanged banner doesn't look like a failure.
