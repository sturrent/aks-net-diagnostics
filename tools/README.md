# Development Tools

This directory contains scripts and tools for development, building, and quality assurance.

## Scripts

### Quality Check Scripts

#### `check_quality.sh` (Linux/Mac)
Bash script that runs all code quality checks:
- Black (code formatting)
- isort (import sorting)
- Flake8 (PEP8 style)
- Pylint (code quality)
- Pytest (unit tests)

**Usage:**
```bash
./tools/check_quality.sh
```

**Exit Codes:**
- `0`: All checks passed
- `1`: One or more checks failed

#### `check_quality.ps1` (Windows)
PowerShell equivalent of the bash script with identical functionality.

**Usage:**
```powershell
.\tools\check_quality.ps1
```

### Build Script

#### `build_zipapp.py`
Creates a single-file Python zipapp (`.pyz`) distribution of the tool.

**Usage:**
```bash
python tools/build_zipapp.py
```

**Output:**
- Creates `aks-net-diagnostics.pyz` in the project root
- File size: ~57 KB (compressed)
- Contains all modules bundled together

**What it does:**
1. Creates temporary `build_temp/` directory
2. Copies `aks-net-diagnostics.py` as `__main__.py`
3. Copies `aks_diagnostics/` module
4. Uses `zipapp.create_archive()` to bundle
5. Cleans up temporary files

**Testing the build:**
```bash
python tools/build_zipapp.py
python aks-net-diagnostics.pyz --help
```

## Development Workflow

### Before Committing

```bash
# Run quality checks
./tools/check_quality.sh

# If any checks fail, fix the issues:
black .                    # Auto-format code
isort .                    # Auto-sort imports
pytest -v                  # Run tests
```

### Before Release

```bash
# Build the distribution
python tools/build_zipapp.py

# Test the build
python aks-net-diagnostics.pyz --version
python aks-net-diagnostics.pyz --help
```

## Requirements

All tools require the virtual environment with development dependencies:

```bash
# Activate virtual environment
source venv/bin/activate  # Linux/Mac
.\venv\Scripts\Activate.ps1  # Windows

# Ensure dev dependencies are installed
pip install -r dev-requirements.txt
```

## CI/CD Integration

These tools are also used in:
- **Pre-push Git Hook**: Automatically runs quality checks before push
- **GitHub Actions**: CI/CD pipeline uses these for automated testing
- **Release Process**: Build script creates artifacts for GitHub releases

## Related Documentation

- [CONTRIBUTING.md](../CONTRIBUTING.md) - Contribution guidelines
- [docs/DEVELOPMENT.md](../docs/DEVELOPMENT.md) - Development setup
- [docs/PRE_PUSH_HOOK.md](../docs/PRE_PUSH_HOOK.md) - Pre-push hook guide
