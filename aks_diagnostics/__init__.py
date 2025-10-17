"""
AKS Network Diagnostics Package
Modular package for analyzing AKS cluster network configurations
"""

__version__ = "1.1.2"
__author__ = "Azure Networking Diagnostics Generator"

# Import only the modules that exist
from .models import DiagnosticResult, Finding, VMSSInstance

# Core will be imported when it's created
# from .core import AKSNetworkDiagnostics

__all__ = [
    # 'AKSNetworkDiagnostics',  # TODO: Uncomment when core.py is created
    "VMSSInstance",
    "Finding",
    "DiagnosticResult",
]
