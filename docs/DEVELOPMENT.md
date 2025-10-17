# Development Guide

## Setting Up Your Development Environment

### 1. Prerequisites
- Python 3.9 or higher
- Git
- Azure CLI 2.0+ (optional, for testing integration)
- Virtual environment tool (venv)

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
# Check Python version (should be 3.9+)
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
```
# No external dependencies required
# The tool uses Azure CLI for all Azure operations
```

#### `dev-requirements.txt` - Development Dependencies
Additional tools for development (includes all runtime deps):
- **Code Quality:** 
  - `pylint>=4.0.0` - Code quality checker
  - `flake8>=7.0.0` - PEP8 style checker
  - `black>=25.0.0` - Code formatter
  - `isort>=7.0.0` - Import sorter
- **Type Checking:** `mypy>=1.13.0`
- **Testing:** 
  - `pytest>=8.4.0` - Test framework
  - `pytest-cov>=7.0.0` - Coverage reporting
  - `pytest-mock>=3.15.0` - Mocking support
- **Documentation:** 
  - `sphinx>=8.1.0` - Documentation generator
  - `sphinx-rtd-theme>=3.0.0` - Documentation theme

**Install only what you need:**
```bash
# Development (recommended - includes everything)
pip install -r dev-requirements.txt

# Runtime only (if you just want to run the tool)
pip install -r requirements.txt
```

## Code Quality Tools

This project maintains high code quality standards using automated tools. **All code must pass these checks before being merged.**

### Quality Standards

- **Pylint Score**: 9.5/10 or higher (current: 9.96/10)
- **Flake8 Violations**: 0 (excluding E501 line-too-long)
- **Test Coverage**: 80%+ on new code
- **All Tests**: Must pass (139/139 currently)

### Running Quality Checks

#### All-in-One Quality Check
```bash
# Run all quality checks at once (Linux/Mac)
./tools/check_quality.sh

# Or on Windows (PowerShell)
.\tools\check_quality.ps1
```

This script runs:
1. Black (code formatting) - **blocks if fails**
2. isort (import sorting) - **blocks if fails**
3. Flake8 (PEP8 style) - **blocks if fails**
4. Pylint (code quality) - **shows warnings**
5. Pytest (unit tests) - **blocks if fails**

#### Individual Tool Usage

##### Pylint
Checks for code quality and adherence to Python best practices.

```bash
# Run pylint on all Python files
pylint aks_diagnostics/ aks-net-diagnostics.py

# Run pylint on a specific file
pylint aks-net-diagnostics.py

# Run with specific configuration
pylint --rcfile=pylintrc aks_diagnostics/
```

**Target Score:** 9.5/10 or higher

**Configuration:** `.pylintrc` file in project root

##### Flake8 (PEP8)
Checks for PEP8 style compliance.

```bash
# Run flake8 on all files
flake8 aks_diagnostics/ aks-net-diagnostics.py tests/

# Run flake8 on specific directory
flake8 aks_diagnostics/

# Run with verbose output
flake8 --show-source --statistics .
```

**Target:** Zero violations (excluding E501)

**Configuration:** `.flake8` file in project root

##### Black (Code Formatter)
Automatically formats code to match style guidelines.

```bash
# Check what would be reformatted (dry run)
black --check .

# Format all Python files
black .

# Format specific file
black aks-net-diagnostics.py
```

**Configuration:** `pyproject.toml` - line-length = 120

##### isort (Import Sorter)
Sorts and organizes imports.

```bash
# Check import sorting
isort --check-only .

# Sort imports
isort .

# Sort specific file
isort aks-net-diagnostics.py
```

**Configuration:** `pyproject.toml` - profile = "black"

## Running Tests

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_nsg_analyzer.py

# Run specific test
pytest tests/test_nsg_analyzer.py::TestNSGAnalyzer::test_initialization

# Run with coverage report  
pytest --cov=aks_diagnostics --cov-report=term-missing

# Run with HTML coverage report
pytest --cov=aks_diagnostics --cov-report=html
# Open htmlcov/index.html in browser
```

**Test Coverage:** Aim for 80%+ coverage on new code.

**Test Structure:**
- `tests/` - All test files
- Naming: `test_<module>.py`
- Test classes: `Test<ClassName>`
- Test methods: `test_<method>_<scenario>_<expected_result>`

## Automated Quality Checks

### Pre-Push Git Hook

The repository includes a **pre-push git hook** that automatically runs quality checks before allowing a push.

**Location:** `.git/hooks/pre-push` (PowerShell script)

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
.git\hooks\pre-push
```

See [PRE_PUSH_HOOK.md](PRE_PUSH_HOOK.md) for more details.

### GitHub Actions CI/CD

Every push to `main` or `develop` branches triggers automated checks:

- Code formatting (Black)
- Import sorting (isort)  
- Style checking (Flake8)
- Code quality (Pylint)
- Unit tests (Pytest with coverage)

**Configuration:** `.github/workflows/ci.yml`

## Development Workflow

### 1. Create a Feature Branch

```bash
# Update main branch
git checkout main
git pull origin main

# Create feature branch
git checkout -b feature/my-feature

# Or for bug fixes
git checkout -b fix/bug-description
```

### 2. Make Changes

- Edit code files
- Add/update tests
- Update documentation if needed

### 3. Run Quality Checks

```bash
# Run all checks (Linux/Mac)
./tools/check_quality.sh

# Or on Windows
.\tools\check_quality.ps1

# Or run individually
black .
isort .
flake8 aks_diagnostics/ aks-net-diagnostics.py tests/
pylint aks_diagnostics/ aks-net-diagnostics.py
pytest -v
```

### 4. Commit Changes

```bash
# Stage changes
git add .

# Commit with conventional commit message
git commit -m "feat: Add new feature"
# or
git commit -m "fix: Fix bug in NSG analyzer"
```

### 5. Push Changes

```bash
# Push to your fork/branch
git push origin feature/my-feature

# Pre-push hook will run automatically
```

### 6. Create Pull Request

- Go to GitHub
- Create pull request from your branch to `main` or `develop`
- Fill out PR template
- Wait for CI checks to pass
- Address review comments

## Project Structure

```
aks-net-diagnostics/
├── aks_diagnostics/           # Main package
│   ├── __init__.py
│   ├── api_server_analyzer.py
│   ├── azure_cli.py           # Azure CLI executor
│   ├── base_analyzer.py
│   ├── cluster_data_collector.py
│   ├── connectivity_tester.py
│   ├── dns_analyzer.py
│   ├── exceptions.py
│   ├── misconfiguration_analyzer.py
│   ├── models.py
│   ├── nsg_analyzer.py
│   ├── outbound_analyzer.py
│   ├── report_generator.py
│   ├── route_table_analyzer.py
│   └── validators.py
├── tests/                     # Unit tests
│   ├── test_*.py
├── docs/                      # Documentation
│   ├── ARCHITECTURE.md
│   ├── DEVELOPMENT.md (this file)
│   └── PRE_PUSH_HOOK.md
├── .github/workflows/         # CI/CD
│   └── ci.yml
├── tools/                     # Development tools
│   ├── build_zipapp.py       # Build script for .pyz
│   ├── check_quality.sh      # Quality check (Linux/Mac)
│   └── check_quality.ps1     # Quality check (Windows)
├── .flake8                   # Flake8 config
├── pylintrc                  # Pylint config
├── pyproject.toml            # Black/isort config
├── dev-requirements.txt      # Dev dependencies
├── requirements.txt          # Runtime dependencies
├── CONTRIBUTING.md           # Contribution guide
├── README.md                 # User documentation
├── CHANGELOG.md              # Version history
└── LICENSE                   # License file
```

## Troubleshooting

### Pre-push hook not running

```bash
# Check if hook exists
ls -la .git/hooks/pre-push

# Verify Python environment
which python

# Manually run quality checks
./tools/check_quality.sh
```
### Import errors

```bash
# Ensure you're in virtual environment
# (venv) should appear in prompt

# Reinstall dependencies
pip install -r dev-requirements.txt
```

### Test failures

```bash
# Run tests with verbose output
pytest -v

# Run specific failing test
pytest tests/test_file.py::TestClass::test_method -v

# Check test output for details
```

### Quality check failures

```bash
# Black formatting
black .

# isort import sorting
isort .

# Fix Flake8 issues manually
# (most common: unused imports, line too long)

# Pylint issues
pylint aks_diagnostics/ aks-net-diagnostics.py
# Review output and fix issues
```

## Additional Resources

- [CONTRIBUTING.md](../CONTRIBUTING.md) - Contribution guidelines
- [ARCHITECTURE.md](ARCHITECTURE.md) - Technical architecture
- [PRE_PUSH_HOOK.md](PRE_PUSH_HOOK.md) - Pre-push hook details
- [README.md](../README.md) - User documentation
- [Python Style Guide (PEP 8)](https://peps.python.org/pep-0008/)
- [Conventional Commits](https://www.conventionalcommits.org/)
