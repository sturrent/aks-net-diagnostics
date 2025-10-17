"""Fix common Pylint violations"""
import re
from pathlib import Path


def fix_logging_fstrings(file_path):
    """Fix logging f-string interpolation to use lazy % formatting"""
    content = file_path.read_text(encoding="utf-8")
    original = content

    # Pattern to match logging calls with f-strings
    # Matches: logger.info(f"...{var}...")
    pattern = r'(logger\.(debug|info|warning|error|critical))\(f(["\'])(.+?)\3\)'

    def replace_fstring(match):
        log_func = match.group(1)
        quote = match.group(3)
        msg = match.group(4)

        # Convert {var} to %s and extract variables
        vars_pattern = r"\{([^}]+)\}"
        variables = re.findall(vars_pattern, msg)

        if not variables:
            # No variables, just remove the f
            return f"{log_func}({quote}{msg}{quote})"

        # Replace {var} with %s
        new_msg = re.sub(vars_pattern, "%s", msg)
        var_list = ", ".join(variables)

        return f"{log_func}({quote}{new_msg}{quote}, {var_list})"

    content = re.sub(pattern, replace_fstring, content)

    if content != original:
        file_path.write_text(content, encoding="utf-8")
        return True
    return False


def remove_unnecessary_pass(file_path):
    """Remove unnecessary pass statements from classes/functions with docstrings"""
    content = file_path.read_text(encoding="utf-8")
    original = content

    # Remove pass statements that come after docstrings in exception classes
    pattern = r'("""[^"]*"""\n\s+)pass\n'
    content = re.sub(pattern, r"\1\n", content)

    if content != original:
        file_path.write_text(content, encoding="utf-8")
        return True
    return False


if __name__ == "__main__":
    # Find all Python files
    files_to_fix = []
    for pattern in ["aks_diagnostics/*.py", "aks-net-diagnostics.py"]:
        files_to_fix.extend(Path().glob(pattern))

    fixed_logging = 0
    fixed_pass = 0

    for file_path in files_to_fix:
        if fix_logging_fstrings(file_path):
            print(f"✅ Fixed logging in {file_path}")
            fixed_logging += 1

        if remove_unnecessary_pass(file_path):
            print(f"✅ Removed unnecessary pass in {file_path}")
            fixed_pass += 1

    print(f"\nFixed logging in {fixed_logging} files")
    print(f"Removed unnecessary pass in {fixed_pass} files")
