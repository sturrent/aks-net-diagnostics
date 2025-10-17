Write-Host "Running code quality checks for aks-net-diagnostics..." -ForegroundColor Cyan

Write-Host "`n=== Running Black (code formatter check) ===" -ForegroundColor Yellow
black --check --line-length 120 .
if ($LASTEXITCODE -ne 0) {
    Write-Host "  Black found formatting issues. Run 'black .' to fix." -ForegroundColor Red
} else {
    Write-Host "  Black: PASSED" -ForegroundColor Green
}

Write-Host "`n=== Running isort (import sorter check) ===" -ForegroundColor Yellow
isort --check-only --profile black .
if ($LASTEXITCODE -ne 0) {
    Write-Host "  isort found import issues. Run 'isort .' to fix." -ForegroundColor Red
} else {
    Write-Host "  isort: PASSED" -ForegroundColor Green
}

Write-Host "`n=== Running Flake8 (PEP8 style check) ===" -ForegroundColor Yellow
flake8 --config=.flake8 .
if ($LASTEXITCODE -ne 0) {
    Write-Host "  Flake8: FAILED" -ForegroundColor Red
} else {
    Write-Host "  Flake8: PASSED" -ForegroundColor Green
}

Write-Host "`n=== Running Pylint (code quality check) ===" -ForegroundColor Yellow
pylint --rcfile=pylintrc aks_diagnostics/ aks-net-diagnostics.py
$pylintScore = $LASTEXITCODE
if ($pylintScore -eq 0) {
    Write-Host "  Pylint: PASSED (10.0/10)" -ForegroundColor Green
} else {
    Write-Host "  Pylint: Check score above (target: 9.5/10)" -ForegroundColor Yellow
}

Write-Host "`n=== Running Tests ===" -ForegroundColor Yellow
pytest -v
if ($LASTEXITCODE -ne 0) {
    Write-Host "  Tests: FAILED" -ForegroundColor Red
} else {
    Write-Host "  Tests: PASSED" -ForegroundColor Green
}

Write-Host "`n=====================================" -ForegroundColor Cyan
Write-Host "All quality checks complete!" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
