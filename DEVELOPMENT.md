# Development Guide

## Setting Up Your Development Environment

### 1. Prerequisites
- Python 3.7 or higher
- Git
- Azure CLI (optional, for testing integration)

### 2. Clone and Setup

```bash
# Clone the repository
git clone https://github.com/sturrent/aks-net-diagnostics.git
cd aks-net-diagnostics

# Create a virtual environment
python -m venv venv

# Activate the virtual environment
# On Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# On Windows (CMD):
venv\Scripts\activate.bat
# On Linux/Mac:
source venv/bin/activate

# Install development dependencies
pip install -r dev-requirements.txt
```

### 3. Code Quality Tools

This project uses several tools to maintain code quality:

#### Pylint
Checks for code quality and adherence to Python best practices.

```bash
# Run pylint on all Python files
pylint aks_diagnostics/

# Run pylint on a specific file
pylint aks-net-diagnostics.py

# Run with specific configuration
pylint --rcfile=pylintrc aks_diagnostics/
```

**Target Score:** 9.5/10 or higher (Azure CLI standard)

#### Flake8 (PEP8)
Checks for PEP8 style compliance.

```bash
# Run flake8 on all files
flake8 .

# Run flake8 on specific directory
flake8 aks_diagnostics/

# Run with verbose output
flake8 --show-source --statistics .
```

**Target:** Zero violations

#### Black (Code Formatter)
Automatically formats code to match style guidelines.

```bash
# Check what would be reformatted (dry run)
black --check .

# Format all Python files
black .

# Format specific file
black aks-net-diagnostics.py
```

#### isort (Import Sorter)
Sorts and organizes imports.

```bash
# Check import sorting
isort --check-only .

# Sort imports
isort .
```

### 4. Running Tests

```bash
# Run all tests
pytest

# Run with coverage report
pytest --cov=aks_diagnostics --cov-report=html

# Run specific test file
pytest tests/test_specific.py

# Run with verbose output
pytest -v
```

### 5. Pre-commit Checklist

Before committing code, ensure:

1. **Format code:**
   ```bash
   black .
   isort .
   ```

2. **Check style:**
   ```bash
   flake8 .
   ```

3. **Check code quality:**
   ```bash
   pylint aks_diagnostics/
   ```

4. **Run tests:**
   ```bash
   pytest
   ```

### 6. Quick Quality Check Script

Save this as `check_quality.ps1` (Windows) or `check_quality.sh` (Linux/Mac):

**PowerShell (check_quality.ps1):**
```powershell
Write-Host "Running code quality checks..." -ForegroundColor Cyan

Write-Host "`n=== Running Black (formatter check) ===" -ForegroundColor Yellow
black --check .

Write-Host "`n=== Running isort (import check) ===" -ForegroundColor Yellow
isort --check-only .

Write-Host "`n=== Running Flake8 (PEP8 check) ===" -ForegroundColor Yellow
flake8 .

Write-Host "`n=== Running Pylint (code quality check) ===" -ForegroundColor Yellow
pylint aks_diagnostics/

Write-Host "`n=== Running Tests ===" -ForegroundColor Yellow
pytest

Write-Host "`nAll checks complete!" -ForegroundColor Green
```

**Bash (check_quality.sh):**
```bash
#!/bin/bash
echo "Running code quality checks..."

echo -e "\n=== Running Black (formatter check) ==="
black --check .

echo -e "\n=== Running isort (import check) ==="
isort --check-only .

echo -e "\n=== Running Flake8 (PEP8 check) ==="
flake8 .

echo -e "\n=== Running Pylint (code quality check) ==="
pylint aks_diagnostics/

echo -e "\n=== Running Tests ==="
pytest

echo -e "\nAll checks complete!"
```

Run with:
```bash
# PowerShell
.\check_quality.ps1

# Bash
chmod +x check_quality.sh
./check_quality.sh
```

### 7. Configuration Files

- **pylintrc** - Pylint configuration (based on Azure CLI standards)
- **.flake8** - Flake8/PEP8 configuration
- **pyproject.toml** - Black and isort configuration
- **pytest.ini** - Pytest configuration

### 8. Continuous Integration

The project uses GitHub Actions to run automated checks on every PR:
- Code formatting (Black)
- Import sorting (isort)
- Style checking (Flake8)
- Code quality (Pylint)
- Unit tests (Pytest)
- Coverage reporting

### 9. IDE Setup

#### VS Code
Recommended extensions:
- Python (Microsoft)
- Pylance
- Pylint
- Black Formatter
- isort

Recommended settings (.vscode/settings.json):
```json
{
    "python.linting.enabled": true,
    "python.linting.pylintEnabled": true,
    "python.linting.flake8Enabled": true,
    "python.formatting.provider": "black",
    "python.formatting.blackArgs": ["--line-length", "120"],
    "editor.formatOnSave": true,
    "python.sortImports.args": ["--profile", "black"],
    "[python]": {
        "editor.codeActionsOnSave": {
            "source.organizeImports": true
        }
    }
}
```

### 10. Common Issues and Solutions

#### Issue: Pylint score too low
- Focus on fixing errors (E) and warnings (W) first
- Refactoring (R) and convention (C) issues are lower priority
- Use `# pylint: disable=specific-rule` sparingly for false positives

#### Issue: Import errors in Pylint
- These are often false positives with Azure SDK packages
- They're disabled in pylintrc but can be ignored if they appear

#### Issue: Line too long
- Prefer breaking lines at logical points (after commas, operators)
- Use implicit line continuation inside parentheses
- Keep max line length at 120 characters

### 11. Release Process

1. Update version number in `__version__.py`
2. Update CHANGELOG.md
3. Run full quality check suite
4. Create git tag: `git tag -a v1.x.x -m "Release v1.x.x"`
5. Push tag: `git push origin v1.x.x`
6. GitHub Actions will handle the release

## Questions?

If you have questions about the development process, please:
1. Check existing documentation
2. Review the CONTRIBUTING.md file
3. Open an issue on GitHub
