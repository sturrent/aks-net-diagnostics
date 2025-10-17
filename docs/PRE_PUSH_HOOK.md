# Pre-Push Git Hook# Pre-Push Git Hook



## Overview



A pre-push Git hook has been configured to automatically run code quality checks before pushing to the remote repository. This provides **immediate feedback** in your terminal and prevents pushing code that doesn't meet quality standards.## Overview



## What Gets Checked



When you run `git push`, the following checks run automatically:A pre-push Git hook has been configured to automatically run code quality checks before pushing to the remote repository. This provides **immediate feedback** in your terminal and prevents pushing code that doesn't meet quality standards.



| Check | Type | Blocks Push? |

|-------|------|--------------|

| **Black** | Code formatting | ✅ Yes |## What Gets Checked

| **isort** | Import sorting | ✅ Yes |

| **Flake8** | PEP8 style | ✅ Yes |

| **Pylint** | Code quality | ⚠️ No (warnings only) |

| **Pytest** | Unit tests | ✅ Yes |When you run `git push`, the following checks run automatically:



## Benefits



- ✅ **Instant feedback** - See quality issues before waiting for CI| Check | Type | Blocks Push? |

- ✅ **Faster iteration** - Fix issues locally rather than after push

- ✅ **Clean history** - Only quality code reaches GitHub|-------|------|--------------|

- ✅ **Same checks as CI** - No surprises in the GitHub Actions workflow

| **Black** | Code formatting | Γ£à Yes |

## Example Output

| **isort** | Import sorting | Γ£à Yes |

When all checks pass:

| **Flake8** | PEP8 style | Γ£à Yes |

```

🔍 Running pre-push quality checks...| **Pylint** | Code quality | ΓÜá∩╕Å No (warnings only) |



Running Black (code formatting)...| **Pytest** | Unit tests | Γ£à Yes |

✅ Black (code formatting) PASSED



Running isort (import sorting)...

✅ isort (import sorting) PASSED## Benefits



Running Flake8 (PEP8 style)...

✅ Flake8 (PEP8 style) PASSED

- Γ£à **Instant feedback** - See quality issues before waiting for CI

Running Pylint (code quality)...

⚠️ Pylint (code quality) has warnings- Γ£à **Faster iteration** - Fix issues locally rather than after push



Running Pytest (unit tests)...- Γ£à **Clean history** - Only quality code reaches GitHub

✅ Pytest (unit tests) PASSED

- Γ£à **Same checks as CI** - No surprises in the GitHub Actions workflow

═══════════════════════════════════════════════════

✅ All critical checks passed! Pushing to remote...

```

## Example Output

When a check fails:



```

Running Flake8 (PEP8 style)...When all checks pass:

❌ Flake8 (PEP8 style) FAILED



═══════════════════════════════════════════════════

❌ Critical checks failed! Push aborted.```



Fix the issues above and try again.≡ƒöì Running pre-push quality checks...

Or use: git push --no-verify  to skip these checks (not recommended).

```



## Bypassing the HookRunning Black (code formatting)...



In rare cases where you need to push without running checks:Γ£à Black (code formatting) PASSED



```bash

git push --no-verify

```Running isort (import sorting)...



**Note:** This is not recommended as it bypasses quality checks.Γ£à isort (import sorting) PASSED



## Manual Testing



Test the hook without pushing:Running Flake8 (PEP8 style)...



```powershellΓ£à Flake8 (PEP8 style) PASSED

.git\hooks\pre-push.ps1

```



Or use the convenience script:Running Pylint (code quality)...



```powershellΓÜá∩╕Å Pylint (code quality) has warnings

.\check_quality.ps1

```



## TroubleshootingRunning Pytest (unit tests)...



### Hook doesn't runΓ£à Pytest (unit tests) PASSED



- Verify the file exists: `.git\hooks\pre-push`

- Check PowerShell script exists: `.git\hooks\pre-push.ps1`

ΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöü

### Virtual environment not found

Γ£à All critical checks passed! Pushing to remote...

The hook will attempt to activate `venv\Scripts\Activate.ps1`. If your virtual environment is elsewhere, ensure it's already activated before pushing.

```

### Tests fail



Run pytest manually to see detailed output:

When a check fails:

```powershell

pytest -v

```

```

## Related Documentation

Running Flake8 (PEP8 style)...

- [DEVELOPMENT.md](../DEVELOPMENT.md) - Development setup and workflow

- [check_quality.ps1](../check_quality.ps1) - Manual quality check scriptΓ¥î Flake8 (PEP8 style) FAILED

- [.github/workflows/ci.yml](../.github/workflows/ci.yml) - GitHub Actions CI workflow



ΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöüΓöü

Γ¥î Critical checks failed! Push aborted.



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

