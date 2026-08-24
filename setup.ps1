# setup.ps1 — Windows: (re)create .venv with Python >= 3.10 and install pinned deps.
# Downloads a standalone Python 3.12 via uv if none is installed. Run in PowerShell:
#     powershell -ExecutionPolicy Bypass -File setup.ps1
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$py = $null
foreach ($v in "3.13","3.12","3.11","3.10") {
    if (Get-Command py -ErrorAction SilentlyContinue) {
        & py "-$v" -c "import sys" 2>$null
        if ($LASTEXITCODE -eq 0) { $py = @("py", "-$v"); break }
    }
}

if ($py) {
    Write-Host "Using Python $($py[1])"
    if (Test-Path .venv) { Remove-Item -Recurse -Force .venv }
    & $py[0] $py[1] -m venv .venv
    .\.venv\Scripts\python -m pip install -q --upgrade pip
    .\.venv\Scripts\python -m pip install -q -r requirements.txt
} else {
    Write-Host "No Python >= 3.10 found. Fetching one with uv..."
    if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
        powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
        $env:Path = "$env:USERPROFILE\.local\bin;$env:Path"
    }
    if (Test-Path .venv) { Remove-Item -Recurse -Force .venv }
    uv venv -q --seed --python 3.12 .venv
    .\.venv\Scripts\python -m pip install -q -r requirements.txt
}

Write-Host ""
.\.venv\Scripts\python --version
.\.venv\Scripts\python tests\test_all.py 2>&1 | Select-String -NotMatch Warning | Select-Object -Last 1
Write-Host ""
Write-Host "Ready. Use:  .venv\Scripts\python sweeper.py --help"
