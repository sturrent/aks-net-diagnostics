#!/usr/bin/env python3
"""
Build script to create a single-file executable .pyz archive
Usage: python build_zipapp.py
Output: aks-net-diagnostics.pyz (single file, ~200KB)
"""

import zipapp
import shutil
from pathlib import Path

def build():
    # Create temporary build directory
    build_dir = Path("build_temp")
    if build_dir.exists():
        shutil.rmtree(build_dir, ignore_errors=True)
    build_dir.mkdir()
    
    # Copy main script as __main__.py
    shutil.copy("aks-net-diagnostics.py", build_dir / "__main__.py")
    
    # Copy aks_diagnostics module (excluding __pycache__)
    shutil.copytree(
        "aks_diagnostics", 
        build_dir / "aks_diagnostics",
        ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '*.pyo')
    )
    
    # Create zipapp
    zipapp.create_archive(
        build_dir,
        target="aks-net-diagnostics.pyz",
        interpreter="/usr/bin/env python3",
        compressed=True
    )
    
    # Cleanup
    shutil.rmtree(build_dir, ignore_errors=True)
    
    print("✅ Created aks-net-diagnostics.pyz")
    print("📦 Usage: python aks-net-diagnostics.pyz -g myRG -n myCluster")

if __name__ == "__main__":
    build()
