# Rayhunter Evidence Deduplication and Master Manifest Generator
# Julian Burns — Cranbourne East Investigation
# ============================================================
# Run AFTER the full C:\ scan completes
# This script:
#   1. Finds ALL rayhunter capture files on C:\
#   2. SHA-256 hashes every file
#   3. Identifies duplicates (same hash, different paths)
#   4. Produces a master forensic manifest CSV
#   5. Reports which files to keep vs deduplicate

param(
    [string]$SearchRoot = "C:\",
    [string]$OutputDir  = "C:\rayhunter-threat-analyzer-V2.1.4",
    [switch]$DryRun     = $false
)

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$manifestFile = "$OutputDir\MASTER_MANIFEST_$timestamp.csv"
$dupeReport   = "$OutputDir\DUPLICATE_REPORT_$timestamp.csv"
$summaryFile  = "$OutputDir\DEDUP_SUMMARY_$timestamp.txt"

Write-Host "`n╔══════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  Rayhunter Master Manifest Generator     ║" -ForegroundColor Cyan
Write-Host "║  Julian Burns Investigation — 2026       ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════╝`n" -ForegroundColor Cyan

# Extensions to scan
$extensions = @("*.ndjson","*.qmdl","*.pcap","*.pcapng","*.json")

Write-Host "Scanning $SearchRoot for capture files..." -ForegroundColor Yellow
Write-Host "Extensions: $($extensions -join ', ')`n"

# Collect all files
$allFiles = @()
foreach ($ext in $extensions) {
    $found = Get-ChildItem -Path $SearchRoot -Recurse -Filter $ext -ErrorAction SilentlyContinue |
             Where-Object { !$_.PSIsContainer }
    $allFiles += $found
    Write-Host "  $ext : $($found.Count) files found"
}

Write-Host "`nTotal files to process: $($allFiles.Count)" -ForegroundColor White

# Hash everything
Write-Host "`nComputing SHA-256 hashes..." -ForegroundColor Yellow
$results    = @()
$hashLookup = @{}  # hash -> list of paths
$i = 0

foreach ($file in $allFiles) {
    $i++
    if ($i % 100 -eq 0) {
        Write-Host "  Progress: $i / $($allFiles.Count) ($([math]::Round($i/$allFiles.Count*100))%)" -ForegroundColor Gray
    }
    
    try {
        $hash = (Get-FileHash -Path $file.FullName -Algorithm SHA256).Hash
        $sizeMB = [math]::Round($file.Length / 1MB, 3)
        
        $entry = [PSCustomObject]@{
            Filename    = $file.Name
            FullPath    = $file.FullName
            SHA256      = $hash
            Size_Bytes  = $file.Length
            Size_MB     = $sizeMB
            Modified    = $file.LastWriteTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
            Extension   = $file.Extension
            IsDuplicate = $false
            DupeOf      = ""
        }
        
        if ($hashLookup.ContainsKey($hash)) {
            $entry.IsDuplicate = $true
            $entry.DupeOf = $hashLookup[$hash][0]
            $hashLookup[$hash] += $file.FullName
        } else {
            $hashLookup[$hash] = @($file.FullName)
        }
        
        $results += $entry
    } catch {
        Write-Host "  WARN: Could not hash $($file.FullName): $_" -ForegroundColor DarkYellow
    }
}

# Export master manifest
$results | Export-Csv -Path $manifestFile -NoTypeInformation
Write-Host "`n✅ Master manifest: $manifestFile" -ForegroundColor Green

# Duplicate analysis
$dupes = $results | Where-Object { $_.IsDuplicate -eq $true }
$unique = $results | Where-Object { $_.IsDuplicate -eq $false }

$dupes | Export-Csv -Path $dupeReport -NoTypeInformation
Write-Host "✅ Duplicate report: $dupeReport" -ForegroundColor Green

# Summary
$totalSize   = ($results | Measure-Object -Property Size_Bytes -Sum).Sum
$dupeSize    = ($dupes   | Measure-Object -Property Size_Bytes -Sum).Sum
$uniqueSize  = ($unique  | Measure-Object -Property Size_Bytes -Sum).Sum

$summary = @"
RAYHUNTER MASTER MANIFEST SUMMARY
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')
Investigator: Julian Burns
Location: Cranbourne East, VIC, Australia
Search root: $SearchRoot

FILE COUNTS:
  Total files scanned:    $($results.Count)
  Unique files (keep):    $($unique.Count)
  Duplicate files:        $($dupes.Count)
  Deduplication rate:     $([math]::Round($dupes.Count/$results.Count*100, 1))%

STORAGE:
  Total size:             $([math]::Round($totalSize/1GB, 2)) GB
  Unique data:            $([math]::Round($uniqueSize/1GB, 2)) GB
  Recoverable (dupes):    $([math]::Round($dupeSize/1GB, 2)) GB

BY EXTENSION:
$(($results | Group-Object Extension | Sort-Object Count -Descending | ForEach-Object {
    "  $($_.Name.PadRight(10)) $($_.Count) files"
}) -join "`n")

UNIQUE HASH COUNT: $($hashLookup.Keys.Count)

OUTPUT FILES:
  Master manifest:  $manifestFile
  Duplicate report: $dupeReport
  This summary:     $summaryFile
"@

$summary | Out-File -FilePath $summaryFile -Encoding utf8
Write-Host "`n$summary" -ForegroundColor White

Write-Host "`n✅ Done! Review duplicate report to identify files safe to remove." -ForegroundColor Green
Write-Host "⚠️  Do NOT delete any files until ACMA complaint is resolved." -ForegroundColor Yellow
