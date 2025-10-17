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

# Create a virtual environment (recommended)
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

**Why use a virtual environment?**
- Isolates project dependencies from system Python
- Prevents version conflicts with other projects
- Makes it easy to reproduce the development environment
- Required for pre-push hooks to work correctly

**Verify installation:**
```bash
# Check Python version (should be 3.7+)
python --version

# Verify tools are installed
black --version
flake8 --version
pylint --version
pytest --version

# Check you're in the virtual environment
# (venv) should appear in your prompt
```

### 3. Understanding Dependencies

The project uses **two requirements files**:

#### `requirements.txt` - Runtime Dependencies
Production dependencies needed to run the tool:
- `azure-identity` (1.15.0+) - Azure authentication
- `azure-mgmt-containerservice` (29.0.0+) - AKS management
- `azure-mgmt-network` (25.0.0+) - Network resources
- `azure-mgmt-compute` (30.0.0+) - VM/VMSS management
- `azure-mgmt-privatedns` (1.1.0+) - Private DNS zones
- `azure-mgmt-resource` (23.0.0+) - Resource management

#### `dev-requirements.txt` - Development Dependencies
Additional tools for development (includes all runtime deps):
- **Code Quality:** pylint (2.17.0+), flake8 (6.0.0+), black (23.0.0+), isort (5.12.0+)
- **Type Checking:** mypy (1.0.0+)
- **Testing:** pytest (7.4.0+), pytest-cov (4.1.0+), pytest-mock (3.11.0+)
- **Documentation:** sphinx (6.0.0+), sphinx-rtd-theme (1.2.0+)
- Plus all runtime dependencies (via `-r requirements.txt`)

**Install only what you need:**
```bash
# Development (recommended - includes everything)
pip install -r dev-requirements.txt

# Runtime only (if you just want to run the tool)
pip install -r requirements.txt
```

### 4. Code Quality Tools

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

### 5. Running All Quality Checks

For convenience, the project includes automated scripts that run all quality checks in sequence:

#### Linux/macOS
```bash
./tools/check_quality.sh
```

#### Windows (PowerShell)
```powershell
.\tools\check_quality.ps1
```

These scripts run:
- **Black** (code formatting)
- **isort** (import sorting)
- **Flake8** (PEP8 style checking)
- **Pylint** (code quality analysis)
- **Pytest** (unit tests)

The scripts provide colored output and stop on first failure. See [tools/README.md](../tools/README.md) for more details.

### 6. Running Tests

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_specific.py

# Run with coverage report  
pytest --cov=aks_diagnostics --cov-report=term-missing

# Run with HTML coverage report
pytest --cov=aks_diagnostics --cov-report=html
# Open htmlcov/index.html in browser
```

**Test Coverage:** Aim for 80%+ coverage on new code.

### 7. Automated Quality Checks

#### Pre-Push Git Hook

The repository includes a **pre-push git hook** that automatically runs quality checks before allowing a push.

**What it checks:**
- ✅ Black (code formatting) - **blocks push if fails**
- ✅ isort (import sorting) - **blocks push if fails**
- ✅ Flake8 (PEP8 style) - **blocks push if fails**
- ⚠️ Pylint (code quality) - **shows warnings, doesn't block**
- ✅ Pytest (unit tests) - **blocks push if fails**

**Bypassing the hook** (not recommended):
```bash
git push --no-verify
```

**Testing the hook manually:**
```powershell
.git\hooks\pre-push.ps1
```

See [docs/PRE_PUSH_HOOK.md](docs/PRE_PUSH_HOOK.md) for more details.

#### GitHub Actions CI/CD

Every push to `main`, `develop`, or `azure-sdk-migration-ng` branches triggers automated checks:

- Code formatting (Black)
- Import sorting (isort)  
- Style checking (Flake8)
- Code quality (Pylint)
- Unit tests (Pytest with coverage)

Pull requests will show CI status and require passing checks before merge.

View workflow: [.github/workflows/ci.yml](.github/workflows/ci.yml)

### 7. Pre-commit Checklist

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

**Or use the convenience script:**
```powershell
.\check_quality.ps1
```

This script runs all checks in sequence and reports results.

### 8. Quality Check Script

The repository includes `check_quality.ps1` that runs all quality checks:

```powershell
# Run all quality checks
.\check_quality.ps1
```

This runs:
1. Black formatter check
2. isort import check
3. Flake8 PEP8 check
4. Pylint code quality check
5. Pytest unit tests

The script provides clear, color-coded output for each check.

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

#### Issue: Virtual environment not activating
**Windows PowerShell:**
```powershell
# If you get "running scripts is disabled", run:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Then activate again:
.\venv\Scripts\Activate.ps1
```

**Verify activation:**
- Your prompt should show `(venv)` prefix
- `python --version` should match your venv Python version
- `pip list` should show your installed packages

#### Issue: Module not found after pip install
**Solution:**
```bash
# Ensure you're in the virtual environment
# Look for (venv) in your prompt

# Reinstall dependencies
pip install -r dev-requirements.txt

# Verify installation
pip list | grep azure  # Linux/Mac
pip list | Select-String azure  # Windows PowerShell
```

#### Issue: Pre-push hook can't find tools
**Solution:**
The pre-push hook tries to activate the virtual environment automatically, but if it fails:
```bash
# Ensure venv exists in project root
ls venv/  # Linux/Mac
dir venv\  # Windows

# Reinstall dependencies in venv
.\venv\Scripts\Activate.ps1  # Windows
pip install -r dev-requirements.txt
```

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

#### Issue: Different tool versions showing different results
**Solution:**
Use the exact versions from `dev-requirements.txt`:
```bash
# Upgrade pip first
pip install --upgrade pip

# Reinstall with exact versions
pip install -r dev-requirements.txt --upgrade
```

Check versions match CI:
- Black 23.0.0+
- Flake8 6.0.0+
- isort 5.12.0+
- Pylint 2.17.0+
- pytest 7.4.0+

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
