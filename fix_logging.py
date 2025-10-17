#!/usr/bin/env python3
"""
Script to fix logging f-string interpolation (W1203).
Converts: logging.info(f"Message {var}")
To: logging.info("Message %s", var)
"""

import re
from pathlib import Path


def fix_logging_fstring(content: str) -> tuple[str, int]:
    """Fix logging calls that use f-strings."""
    fixes = 0

    # Pattern to match logging calls with f-strings
    # Matches: logging.level(f"text {var} more text")
    # Also handles: self.logger.level(f"...")
    pattern = r'((?:logging|self\.logger|logger)\.\w+)\(f"([^"]*?)"\)'

    def replace_fstring(match):
        nonlocal fixes
        log_call = match.group(1)
        message = match.group(2)

        # Find all {variable} or {expression} patterns
        var_pattern = r"\{([^}]+)\}"
        variables = re.findall(var_pattern, message)

        if not variables:
            # No variables, just remove the f prefix
            fixes += 1
            return f'{log_call}("{message}")'

        # Replace {var} with %s in the message
        new_message = re.sub(var_pattern, "%s", message)

        # Build the new call
        vars_str = ", ".join(variables)
        fixes += 1
        return f'{log_call}("{new_message}", {vars_str})'

    new_content = re.sub(pattern, replace_fstring, content)
    return new_content, fixes


def process_file(filepath: Path) -> bool:
    """Process a single Python file."""
    try:
        content = filepath.read_text(encoding="utf-8")
        new_content, fixes = fix_logging_fstring(content)

        if fixes > 0:
            filepath.write_text(new_content, encoding="utf-8")
            print(f"✅ Fixed {fixes} logging issues in {filepath.name}")
            return True
        else:
            print(f"⏭️  No logging issues in {filepath.name}")
            return False
    except Exception as e:
        print(f"❌ Error processing {filepath}: {e}")
        return False


def main():
    """Main function."""
    # Get all Python files in aks_diagnostics directory and main script
    files = []
    files.extend(Path("aks_diagnostics").glob("*.py"))
    files.append(Path("aks-net-diagnostics.py"))

    total_fixed = 0
    for filepath in sorted(files):
        if process_file(filepath):
            total_fixed += 1

    print(f"\n{'=' * 60}")
    print(f"✅ Fixed logging in {total_fixed} files")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
