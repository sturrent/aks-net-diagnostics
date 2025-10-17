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

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ All critical checks passed! Pushing to remote...
```

When a check fails:

```
Running Flake8 (PEP8 style)...
❌ Flake8 (PEP8 style) FAILED

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
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

```powershell
.git\hooks\pre-push.ps1
```

Or use the convenience script:

```powershell
.\check_quality.ps1
```

## Troubleshooting

### Hook doesn't run

- Verify the file exists: `.git\hooks\pre-push`
- Check PowerShell script exists: `.git\hooks\pre-push.ps1`

### Virtual environment not found

The hook will attempt to activate `venv\Scripts\Activate.ps1`. If your virtual environment is elsewhere, ensure it's already activated before pushing.

### Tests fail

Run pytest manually to see detailed output:

```powershell
pytest -v
```

## Related Documentation

- [DEVELOPMENT.md](../DEVELOPMENT.md) - Development setup and workflow
- [check_quality.ps1](../check_quality.ps1) - Manual quality check script
- [.github/workflows/ci.yml](../.github/workflows/ci.yml) - GitHub Actions CI workflow
