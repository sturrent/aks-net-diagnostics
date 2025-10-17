#!/usr/bin/env python3
"""
Script to automatically fix common Flake8 violations.
- F401: Remove unused imports
- F541: Convert f-strings without placeholders to regular strings
- F841: Remove or prefix unused variables with underscore
"""

import re
from pathlib import Path

# Specific unused imports to remove (verified manually)
UNUSED_IMPORTS_TO_REMOVE = {
    "aks-net-diagnostics.py": [
        "import json",
        "import re", 
        "import stat",
        "from dataclasses import dataclass, field",
        "from datetime import datetime, timezone",
        "from pathlib import Path",
        "from typing import Dict, List, Optional, Any, Tuple",
        "from aks_diagnostics.connectivity_tester import ConnectivityTester, VMSSInstance",
    ],
    "aks_diagnostics/connectivity_tester.py": [
        "from typing import Dict, List, Optional, Any, Tuple",
    ],
    "aks_diagnostics/nsg_analyzer.py": [
        "from typing import Dict, List, Optional, Any",
        "from .models import Finding, FindingCode, Severity",
    ],
    "aks_diagnostics/report_generator.py": [
        "import stat",
    ],
    "tests/test_api_server_analyzer.py": [
        "from unittest.mock import Mock, MagicMock",
    ],
    "tests/test_cluster_data_collector.py": [
        "from unittest.mock import Mock, patch, call",
    ],
    "tests/test_connectivity_tester.py": [
        "from unittest.mock import Mock, patch",
    ],
    "tests/test_dns_analyzer.py": [
        "from unittest.mock import Mock, patch",
    ],
    "tests/test_nsg_analyzer.py": [
        "from unittest.mock import Mock, MagicMock, patch",
    ],
    "tests/test_route_table_analyzer.py": [
        "from unittest.mock import Mock, patch",
    ],
    "tests/test_validators.py": [
        "from pathlib import Path",
    ],
}

def fix_unused_imports(file_path: Path) -> int:
    """Remove unused imports from a file."""
    fixes = 0
    rel_path = str(file_path).replace("\\", "/")
    
    if rel_path not in UNUSED_IMPORTS_TO_REMOVE:
        return 0
    
    content = file_path.read_text(encoding="utf-8")
    original = content
    
    for import_line in UNUSED_IMPORTS_TO_REMOVE[rel_path]:
        # Remove the import line (with potential comma variations)
        if import_line in content:
            content = content.replace(import_line + "\n", "")
            fixes += 1
    
    if content != original:
        file_path.write_text(content, encoding="utf-8")
    
    return fixes

def fix_f_strings_without_placeholders(file_path: Path) -> int:
    """Convert f-strings without placeholders to regular strings."""
    fixes = 0
    content = file_path.read_text(encoding="utf-8")
    original = content
    
    # Pattern: f"string without {placeholders}"
    # Match f-strings that don't contain any { }
    pattern = r'"([^"{]*)"'
    
    def replace_if_no_placeholder(match):
        nonlocal fixes
        string_content = match.group(1)
        if "{" not in string_content:
            fixes += 1
            return f'"{string_content}"'
        return match.group(0)
    
    content = re.sub(pattern, replace_if_no_placeholder, content)
    
    # Also handle "..." single quotes
    pattern = r""([^"{]*)'"
    content = re.sub(pattern, replace_if_no_placeholder, content)
    
    if content != original:
        file_path.write_text(content, encoding="utf-8")
    
    return fixes

def main():
    """Main function to fix Flake8 issues."""
    root = Path(".")
    total_import_fixes = 0
    total_fstring_fixes = 0
    
    # Fix unused imports
    for rel_path in UNUSED_IMPORTS_TO_REMOVE:
        file_path = root / rel_path
        if file_path.exists():
            fixes = fix_unused_imports(file_path)
            if fixes > 0:
                print(f"✅ Fixed {fixes} unused imports in {rel_path}")
                total_import_fixes += fixes
    
    # Fix f-strings without placeholders
    for file_path in root.rglob("*.py"):
        if "venv" in str(file_path) or ".git" in str(file_path):
            continue
        
        fixes = fix_f_strings_without_placeholders(file_path)
        if fixes > 0:
            print(f"✅ Fixed {fixes} f-strings in {file_path}")
            total_fstring_fixes += fixes
    
    print(f"\n{'='*60}")
    print(f"✅ Total: {total_import_fixes} import fixes, {total_fstring_fixes} f-string fixes")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()
