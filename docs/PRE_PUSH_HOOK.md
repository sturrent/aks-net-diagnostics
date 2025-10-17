# Pre-Push Git Hook

## Overview

A pre-push Git hook has been configured to automatically run code quality checks before pushing to the remote repository. This provides **immediate feedback** in your terminal and prevents pushing code that doesn't meet quality standards.

## What Gets Checked

When you run `git push`, the following checks run automatically:

| Check | Type | Blocks Push? |
|-------|------|--------------|
| **Black** | Code formatting | ✅ Yes |
| **isort** | Import sorting | ✅ Yes |
| **Flake8** | PEP8 style | ✅ Yes |
| **Pylint** | Code quality | ⚠️ No (warnings only) |
| **Pytest** | Unit tests | ✅ Yes |

## Benefits

- ✅ **Instant feedback** - See quality issues before waiting for CI
- ✅ **Faster iteration** - Fix issues locally rather than after push
- ✅ **Clean history** - Only quality code reaches GitHub
- ✅ **Same checks as CI** - No surprises in the GitHub Actions workflow

## Example Output

When all checks pass:

```
🔍 Running pre-push quality checks...

Running Black (code formatting)...
✅ Black (code formatting) PASSED

Running isort (import sorting)...
✅ isort (import sorting) PASSED

Running Flake8 (PEP8 style)...
✅ Flake8 (PEP8 style) PASSED

Running Pylint (code quality)...
⚠️ Pylint (code quality) has warnings

Running Pytest (unit tests)...
✅ Pytest (unit tests) PASSED

═══════════════════════════════════════════════════
✅ All critical checks passed! Pushing to remote...
```

When a check fails:

```
Running Flake8 (PEP8 style)...
❌ Flake8 (PEP8 style) FAILED

═══════════════════════════════════════════════════
❌ Critical checks failed! Push aborted.

Fix the issues above and try again.
Or use: git push --no-verify  to skip these checks (not recommended).
```

## Bypassing the Hook

In rare cases where you need to push without running checks:

```bash
git push --no-verify
```

**Note:** This is not recommended as it bypasses quality checks.

## Manual Testing

Test the hook without pushing:

```bash
# Linux/Mac
.git/hooks/pre-push

# Windows
.git\hooks\pre-push.ps1
```

Or use the convenience script:

```bash
# Linux/Mac
./tools/check_quality.sh

# Windows
.\tools\check_quality.ps1
```

## Troubleshooting

### Hook doesn't run

- Verify the file exists: `.git/hooks/pre-push`
- Check script exists: `.git/hooks/pre-push.ps1` (Windows) or ensure pre-push is executable (Linux/Mac)
- Check file permissions (Linux/Mac): `chmod +x .git/hooks/pre-push`

### Virtual environment not found

The hook looks for a virtual environment in these locations (in order):
1. `./venv/`
2. `./.venv/`
3. System Python

If you use a different location, update the hook script.

### Tests fail unexpectedly

```bash
# Make sure dependencies are installed
pip install -r dev-requirements.txt

# Run tests manually to see detailed output
pytest -v
```

### Performance issues

If the hook is too slow:
- The hook runs the full test suite - consider using `pytest -x` (stop at first failure) for faster feedback
- Or modify the hook to skip tests during push and rely on CI

## Related Documentation

- [DEVELOPMENT.md](DEVELOPMENT.md) - Development setup and workflow
- [Quality Check Scripts](../tools/) - Manual quality check scripts
- [.github/workflows/ci.yml](../.github/workflows/ci.yml) - GitHub Actions CI workflow

## How It Works

The pre-push hook:
1. Detects if you're in a git repository
2. Activates the virtual environment (if available)
3. Runs each quality check in sequence
4. Blocks the push if any critical check fails
5. Allows warnings (like Pylint suggestions) but doesn't block

The hook script is located at `.git/hooks/pre-push` and is automatically triggered by Git before any push operation.
