"""
Custom exceptions for standardized error handling
"""


class AKSDiagnosticsError(Exception):
    """Base exception for AKS diagnostics"""


class AzureSDKError(AKSDiagnosticsError):
    """Azure SDK API call failed"""

    def __init__(self, message: str, error_code: str = None, status_code: int = None):
        self.error_code = error_code
        self.status_code = status_code
        super().__init__(message)


class AzureAuthenticationError(AKSDiagnosticsError):
    """Azure authentication failed"""


class ClusterNotFoundError(AKSDiagnosticsError):
    """AKS cluster not found"""


class InvalidConfigurationError(AKSDiagnosticsError):
    """Invalid configuration provided"""


class ValidationError(AKSDiagnosticsError):
    """Input validation failed"""
