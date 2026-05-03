# OpenCellID Cell Verification Script
# Rayhunter Threat Analyzer — Julian Burns Investigation
# ======================================================
# Requires free API key from: https://opencellid.org/register.php
# Set your API key below then run in PowerShell

$API_KEY = "YOUR_API_KEY_HERE"   # <-- get free key at opencellid.org

$cells = @(
    @{cid=21940530; tac=53360; mcc=505; mnc=1;  label="ANOMALOUS TAC — HIGHEST PRIORITY"},
    @{cid=135836191;tac=12385; mcc=505; mnc=1;  label="Midnight burst CID"},
    @{cid=8435470;  tac=30336; mcc=505; mnc=1;  label="Transient Vodafone CID"},
    @{cid=8666391;  tac=30336; mcc=505; mnc=1;  label="65h recurrence CID"},
    @{cid=8395030;  tac=30336; mcc=505; mnc=1;  label="New this dataset"},
    @{cid=8666381;  tac=30336; mcc=505; mnc=1;  label="New this dataset"},
    @{cid=8666411;  tac=30336; mcc=505; mnc=1;  label="New this dataset"},
    @{cid=8395020;  tac=30336; mcc=505; mnc=1;  label="New this dataset"},
    @{cid=135836161;tac=12385; mcc=505; mnc=1;  label="New this dataset"},
    @{cid=135836171;tac=12385; mcc=505; mnc=1;  label="New this dataset"}
)

$results = @()
Write-Host "`n=== OpenCellID Cell Verification ===" -ForegroundColor Cyan
Write-Host "MCC=505 (Australia) | Telstra MNC=001 | Vodafone MNC=003`n"

foreach ($cell in $cells) {
    $url = "https://api.opencellid.org/cell/get?key=$API_KEY&mcc=$($cell.mcc)&mnc=$($cell.mnc)&lac=$($cell.tac)&cellid=$($cell.cid)&format=json"
    
    Write-Host "CID $($cell.cid) TAC $($cell.tac) — $($cell.label)" -ForegroundColor Yellow
    
    try {
        $response = Invoke-RestMethod -Uri $url -Method Get -TimeoutSec 10
        
        if ($response.stat -eq "ok") {
            Write-Host "  STATUS: FOUND IN DATABASE ✅" -ForegroundColor Green
            Write-Host "  Lat/Lng: $($response.lat), $($response.lon)"
            Write-Host "  Range:   $($response.range)m"
            Write-Host "  Samples: $($response.samples)"
            Write-Host "  Updated: $($response.updated)"
            $status = "LEGITIMATE"
        } else {
            Write-Host "  STATUS: NOT IN DATABASE ⚠️ SUSPICIOUS" -ForegroundColor Red
            Write-Host "  Response: $($response | ConvertTo-Json)"
            $status = "NOT_FOUND_SUSPICIOUS"
        }
    } catch {
        if ($_.Exception.Response.StatusCode -eq 404) {
            Write-Host "  STATUS: 404 NOT FOUND — UNREGISTERED CELL ❌" -ForegroundColor Red
            $status = "UNREGISTERED"
        } else {
            Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red
            $status = "ERROR"
        }
    }
    
    $results += [PSCustomObject]@{
        CellID  = $cell.cid
        TAC     = $cell.tac
        MCC     = $cell.mcc
        MNC     = $cell.mnc
        Label   = $cell.label
        Status  = $status
    }
    
    Write-Host ""
    Start-Sleep -Milliseconds 500  # Rate limit
}

# Export results
$outFile = "C:\rayhunter-threat-analyzer-V2.1.4\opencellid_results_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"
$results | Export-Csv -Path $outFile -NoTypeInformation
Write-Host "`n=== Results saved to: $outFile ===" -ForegroundColor Cyan
Write-Host "`nSUMMARY:" -ForegroundColor White
$results | Format-Table -AutoSize

# Flag any unregistered cells
$suspicious = $results | Where-Object { $_.Status -eq "UNREGISTERED" -or $_.Status -eq "NOT_FOUND_SUSPICIOUS" }
if ($suspicious) {
    Write-Host "`n⚠️  SUSPICIOUS UNREGISTERED CELLS:" -ForegroundColor Red
    $suspicious | Format-Table -AutoSize
    Write-Host "These Cell IDs are not in the OpenCellID database." -ForegroundColor Red
    Write-Host "An unregistered Cell ID operating on licensed Telstra/Vodafone spectrum" -ForegroundColor Red
    Write-Host "is a direct Radiocommunications Act 1992 (Cth) s.189 violation." -ForegroundColor Red
}
