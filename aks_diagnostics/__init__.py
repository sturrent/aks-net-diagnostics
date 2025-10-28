"""AKS Network Diagnostics - Comprehensive AKS network configuration analysis tool"""

__version__ = "1.2.0"
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
