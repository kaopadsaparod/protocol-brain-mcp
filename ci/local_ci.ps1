# Protocol Brain - Local CI Runner (PowerShell)
$ErrorActionPreference = "Stop"

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  Protocol Brain - Local CI Runner (PowerShell)" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""

# Detect Python executable
if (Get-Command py -ErrorAction SilentlyContinue) {
    $pythonCmd = "py"
    $pythonArgs = @("-3")
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $pythonCmd = "python"
    $pythonArgs = @()
} else {
    Write-Host "[ERROR] Neither 'py' nor 'python' was found in PATH!" -ForegroundColor Red
    exit 1
}

Write-Host "[1/3] Detecting Python environment..." -ForegroundColor Yellow
& $pythonCmd @pythonArgs --version
Write-Host ""

Write-Host "[2/3] Running Ruff Linter..." -ForegroundColor Yellow
& $pythonCmd @pythonArgs -m ruff check .
if ($LASTEXITCODE -ne 0) {
    Write-Host "[FAIL] Ruff linter found issues!" -ForegroundColor Red
    exit $LASTEXITCODE
}
Write-Host "[PASS] All lint checks passed!" -ForegroundColor Green
Write-Host ""

Write-Host "[3/3] Running Pytest Suite..." -ForegroundColor Yellow
& $pythonCmd @pythonArgs -m pytest --tb=short
if ($LASTEXITCODE -ne 0) {
    Write-Host "[FAIL] Tests failed!" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host ""
Write-Host "========================================================" -ForegroundColor Green
Write-Host "  [SUCCESS] All tests and lint checks passed cleanly!" -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Green
exit 0
