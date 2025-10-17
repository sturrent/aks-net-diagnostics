# Linux Development Setup and Repository Organization

**Date:** October 17, 2025  
**Branch:** develop  
**Purpose:** Document the changes made to support Linux development and improve repository organization

## Overview

This document describes the comprehensive changes made to enable full Linux/Mac development support and reorganize the repository structure. These changes were made to the `develop` branch and should be ported to other branches (e.g., `azure-sdk-migration-ng`) to maintain consistency across implementations.

## Motivation

### Original State
- Development setup was primarily Windows/PowerShell-focused
- Quality check script only available for Windows (`check_quality.ps1`)
- Development tools scattered in project root
- Documentation had encoding issues (corrupted UTF-8 characters)
- Cross-platform development not fully supported

### Goals
- Enable seamless development on Linux/Mac/Windows
- Organize development tools in dedicated directory
- Fix documentation encoding issues
- Provide comprehensive cross-platform documentation
- Maintain feature parity across all platforms

## Changes Made

### 1. Cross-Platform Quality Check Scripts

#### Created `tools/check_quality.sh` (Linux/Mac)
- Bash script equivalent of PowerShell version
- Runs all quality checks: Black, isort, Flake8, Pylint, Pytest
- Color-coded output for better readability
- Proper exit codes (0 = success, 1 = failure)
- Executable permissions set by default

**Location:** `tools/check_quality.sh`

**Features:**
- ANSI color codes for terminal output
- Sequential execution with failure tracking
- Blocks on critical failures (Black, isort, Flake8, Pytest)
- Allows warnings on Pylint without blocking
- Matches PowerShell version functionality exactly

**Usage:**
```bash
./tools/check_quality.sh
```

#### Kept `tools/check_quality.ps1` (Windows)
- Original PowerShell script maintained
- Moved to `tools/` directory for consistency
- No functional changes

### 2. Repository Organization - `tools/` Directory

#### Created Directory Structure
```
tools/
├── README.md              # Comprehensive documentation
├── build_zipapp.py        # Single-file distribution builder
├── check_quality.sh       # Quality checks (Linux/Mac)
└── check_quality.ps1      # Quality checks (Windows)
```

#### Moved Files
- `build_zipapp.py` → `tools/build_zipapp.py`
- `check_quality.ps1` → `tools/check_quality.ps1`

#### Benefits
- Cleaner project root directory
- Clear separation of development vs. production code
- Easier to find and maintain development tools
- Consistent location across branches

### 3. Documentation Updates

#### New Documentation
**`tools/README.md`** - Comprehensive guide covering:
- Description of each tool
- Usage instructions for all platforms
- Development workflow
- Quality check process
- Build process for .pyz distribution
- Requirements and setup
- CI/CD integration notes
- Cross-references to other docs

#### Updated Documentation

**`README.md`**
- Updated build command: `python tools/build_zipapp.py`
- Updated quality check commands with both OS versions
- Cross-platform examples

**`CONTRIBUTING.md`**
- Updated all tool references to `tools/` directory
- Added Linux/Mac and Windows examples side-by-side
- Updated quality check section
- Updated build test checklist

**`docs/DEVELOPMENT.md`**
- Updated quality check commands for both platforms
- Updated project structure diagram to show `tools/` directory
- Updated troubleshooting section with bash commands
- Changed PowerShell examples to bash where appropriate

**`docs/ARCHITECTURE.md`**
- Updated build process diagrams to reference `tools/build_zipapp.py`
- Updated release workflow documentation
- Updated build script details section

**`docs/PRE_PUSH_HOOK.md`**
- **Fixed encoding issues** - Removed all corrupted UTF-8 characters
- Updated manual testing commands for both platforms
- Updated related documentation links
- Changed all PowerShell-only examples to include bash alternatives

**`CHANGELOG.md`**
- Added entry documenting the tool organization
- Updated quality check script references
- Mentioned both bash and PowerShell versions

### 4. Encoding Issues Fixed

#### Problem
The `PRE_PUSH_HOOK.md` file had corrupted UTF-8 characters:
- `Γ£à` instead of `✅`
- `ΓÜá∩╕Å` instead of `⚠️`
- `Γ¥î` instead of `❌`
- Duplicate content sections

#### Solution
- Completely rewrote the file with proper UTF-8 encoding
- Used correct Unicode characters for checkmarks and symbols
- Verified no encoding issues in other markdown files
- File was 67% rewritten to fix issues

### 5. Virtual Environment Setup Process

#### Added System Dependencies
Since Linux systems often don't have `python3-venv` installed by default, documented the installation:

```bash
# Ubuntu/Debian
sudo apt install python3.10-venv

# Or generally
sudo apt install python3-venv
```

#### Virtual Environment Creation
```bash
# Create virtual environment
python3 -m venv venv

# Activate (Linux/Mac)
source venv/bin/activate

# Activate (Windows)
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install --upgrade pip
pip install -r dev-requirements.txt
```

#### Verification Steps
```bash
# Check Python version
python --version

# Verify tools installed
black --version
flake8 --version
pylint --version
pytest --version
isort --version
```

## Implementation Details

### Script Comparison: PowerShell vs. Bash

Both scripts provide identical functionality:

| Feature | PowerShell | Bash |
|---------|-----------|------|
| Black check | ✅ | ✅ |
| isort check | ✅ | ✅ |
| Flake8 check | ✅ | ✅ |
| Pylint check | ✅ | ✅ |
| Pytest execution | ✅ | ✅ |
| Color output | ✅ | ✅ |
| Exit codes | ✅ | ✅ |
| Blocks on failure | ✅ | ✅ |

### File Permissions

The bash script requires executable permissions:
```bash
chmod +x tools/check_quality.sh
```

This is set in the repository, but may need to be reset if the file is recreated.

### Path References

All documentation now uses platform-appropriate paths:

**Linux/Mac:**
```bash
./tools/check_quality.sh
python tools/build_zipapp.py
```

**Windows:**
```powershell
.\tools\check_quality.ps1
python tools\build_zipapp.py
```

## Testing Performed

### Quality Checks
- ✅ All 139 tests passing on Linux (Python 3.10.12)
- ✅ Pylint score: 9.96/10
- ✅ Black: All files properly formatted
- ✅ isort: All imports properly sorted
- ✅ Flake8: Zero violations

### Build Process
- ✅ `python tools/build_zipapp.py` creates valid .pyz file
- ✅ Generated .pyz file works correctly
- ✅ File size ~57 KB (unchanged)

### Scripts
- ✅ `tools/check_quality.sh` runs all checks successfully
- ✅ Proper color output on Linux terminal
- ✅ Exit codes work correctly
- ✅ Failure detection works as expected

## Porting to Other Branches

### For `azure-sdk-migration-ng` Branch

When porting these changes to the Azure SDK migration branch:

1. **Copy Files:**
   ```bash
   # From develop branch
   git checkout develop
   
   # Switch to target branch
   git checkout azure-sdk-migration-ng
   
   # Cherry-pick the commit or manually copy:
   cp -r <develop-path>/tools ./
   ```

2. **Update Documentation:**
   - Merge the documentation changes
   - Keep any SDK-specific documentation
   - Update any SDK-specific build or test commands

3. **Verify Paths:**
   - Check if any code references the old paths
   - Update imports if needed
   - Update any CI/CD configurations

4. **Test:**
   ```bash
   ./tools/check_quality.sh
   python tools/build_zipapp.py
   pytest -v
   ```

5. **Commit:**
   ```bash
   git add tools/
   git add docs/ README.md CONTRIBUTING.md CHANGELOG.md
   git commit -m "chore: port Linux development support and tool organization from develop"
   ```

### Key Files to Port

**Essential files:**
- `tools/check_quality.sh` (new)
- `tools/check_quality.ps1` (moved)
- `tools/build_zipapp.py` (moved)
- `tools/README.md` (new)

**Documentation updates:**
- `README.md`
- `CONTRIBUTING.md`
- `docs/DEVELOPMENT.md`
- `docs/ARCHITECTURE.md`
- `docs/PRE_PUSH_HOOK.md` (important: encoding fixes)
- `CHANGELOG.md`

### Potential Conflicts

When merging to `azure-sdk-migration-ng`:

1. **Code differences**: The SDK branch may have different implementations
   - Keep SDK-specific code
   - Only port the tooling and documentation changes

2. **Dependencies**: `dev-requirements.txt` may differ
   - Merge dependencies, don't replace
   - Azure SDK packages should be kept

3. **Build process**: May have SDK-specific build steps
   - Update `tools/build_zipapp.py` if needed
   - Document any SDK-specific build requirements

4. **Documentation**: SDK branch may have additional docs
   - Merge changes, don't replace
   - Keep SDK-specific documentation sections

## Benefits

### For Development
- ✅ Full Linux/Mac support out of the box
- ✅ Consistent experience across platforms
- ✅ Single command for all quality checks
- ✅ Clear, organized project structure

### For Contributors
- ✅ Easy to find development tools
- ✅ Clear documentation for setup
- ✅ No platform-specific barriers
- ✅ Comprehensive guides in `tools/README.md`

### For Maintainers
- ✅ Easier to maintain cross-platform support
- ✅ Better organized codebase
- ✅ Consistent tooling across branches
- ✅ Clear separation of concerns

## Future Considerations

### For Azure CLI Integration

When implementing the tool as an Azure CLI module:

1. **Keep tooling structure**: The `tools/` directory can remain for development
2. **Update build process**: May need different packaging for CLI extension
3. **Update documentation**: Add Azure CLI-specific development docs
4. **Keep quality checks**: Same standards should apply to CLI module code
5. **Virtual environment**: CLI development may have different venv requirements

### For Continued Development

1. **CI/CD Updates**: Update GitHub Actions to use new paths
2. **Pre-commit hooks**: Consider adding pre-commit framework
3. **Make/Task runners**: Could add Makefile for common tasks
4. **Docker**: Could add Dockerfile for consistent dev environment

## Related Commits

- **Commit:** `e9bea3e` - "refactor: reorganize development tools and fix encoding issues"
- **Branch:** `develop`
- **Date:** October 17, 2025

## Summary

These changes represent a significant improvement in cross-platform development support and repository organization. The changes are non-breaking and purely additive (except for moved files). All existing functionality is preserved while adding comprehensive Linux/Mac support.

The same structure and tools should be ported to the `azure-sdk-migration-ng` branch to maintain consistency, especially since the SDK-based implementation will eventually replace or supplement the CLI-based approach.

## Quick Reference

### Commands Changed

| Old Command | New Command |
|-------------|-------------|
| `python build_zipapp.py` | `python tools/build_zipapp.py` |
| `.\check_quality.ps1` | `.\tools\check_quality.ps1` (Windows) |
| N/A | `./tools/check_quality.sh` (Linux/Mac) |

### New Files
- `tools/README.md` - Tool documentation
- `tools/check_quality.sh` - Linux/Mac quality checks

### Moved Files
- `build_zipapp.py` → `tools/build_zipapp.py`
- `check_quality.ps1` → `tools/check_quality.ps1`

### Fixed Files
- `docs/PRE_PUSH_HOOK.md` - Encoding issues resolved
