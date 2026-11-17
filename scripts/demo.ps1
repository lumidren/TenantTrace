<#
.SYNOPSIS
  TenantTrace demo: set up the environment, generate the synthetic demo case, run the full
  pipeline and print where the HTML, PDF and JSON reports are.

.DESCRIPTION
  Works on a fresh clone with Python 3.12 installed. Creates a project-local virtual environment
  in .venv (nothing is installed system-wide), installs TenantTrace into it, generates the demo
  exports (a phished finance manager at the fictional Harbor Lane Logistics), and runs
  `tenanttrace run`. The tool itself makes no network connection; only `pip install` downloads
  packages, and only when the environment does not exist yet.

.PARAMETER Out
  Folder for the generated exports and the case. Default: .\demo-out (git-ignored).
#>
param(
    [string]$Out = (Join-Path $PSScriptRoot "..\demo-out")
)

$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $root

function Find-Python {
    # Prefer the Python launcher's 3.12; fall back to python on PATH. Must be 64-bit 3.12+.
    $candidates = @()
    if (Get-Command py -ErrorAction SilentlyContinue) { $candidates += , @("py", "-3.12") }
    if (Get-Command python -ErrorAction SilentlyContinue) { $candidates += , @("python") }
    foreach ($c in $candidates) {
        $exe = $c[0]
        $extra = @()
        if ($c.Count -gt 1) { $extra = $c[1..($c.Count - 1)] }
        try {
            $ver = & $exe @extra -c "import sys, struct; print(sys.version_info[0], sys.version_info[1], struct.calcsize('P') * 8)" 2>$null
        } catch { continue }
        if ($LASTEXITCODE -ne 0 -or -not $ver) { continue }
        $parts = $ver.Trim().Split(" ")
        if ([int]$parts[0] -eq 3 -and [int]$parts[1] -ge 12 -and [int]$parts[2] -eq 64) { return , $c }
    }
    throw "Python 3.12 or newer (64-bit) was not found. Install it, then run this script again."
}

$venvPython = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    $py = Find-Python
    Write-Host "Creating .venv with $($py -join ' ')"
    $pyArgs = @()
    if ($py.Count -gt 1) { $pyArgs = $py[1..($py.Count - 1)] }
    & $py[0] @pyArgs -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw "could not create the virtual environment" }
}
& $venvPython -c "import tenanttrace, ttcorpus" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Installing TenantTrace into .venv"
    & $venvPython -m pip install --quiet --upgrade pip
    & $venvPython -m pip install --quiet -e .
    if ($LASTEXITCODE -ne 0) { throw "pip install failed" }
}

New-Item -ItemType Directory -Force -Path $Out | Out-Null
$Out = (Resolve-Path $Out).Path
$corpus = Join-Path $Out "corpus"
$case = Join-Path $Out "case"

Write-Host "Generating the synthetic demo exports"
& $venvPython -m ttcorpus generate --out $corpus demo_bec | Out-Null
if ($LASTEXITCODE -ne 0) { throw "corpus generation failed" }

$truth = Get-Content (Join-Path $corpus "demo_bec\ground_truth.json") -Raw | ConvertFrom-Json
Write-Host "Running TenantTrace on $($truth.primary_user)"
& $venvPython -m tenanttrace -q run (Join-Path $corpus "demo_bec\exports") `
    --user $truth.primary_user --case $case --force --collected-at $truth.collected_at
if ($LASTEXITCODE -ne 0) { throw "tenanttrace run failed" }

$report = Join-Path $case "report"
Write-Host ""
Write-Host "Demo case:   $case"
Write-Host "HTML report: $(Join-Path $report 'report.html')"
Write-Host "PDF report:  $(Join-Path $report 'report.pdf')"
Write-Host "JSON export: $(Join-Path $report 'report.json')"
