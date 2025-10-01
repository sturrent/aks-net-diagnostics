"""
Custom exceptions for standardized error handling
"""


class AKSDiagnosticsError(Exception):
    """Base exception for AKS diagnostics"""
    pass


class AzureCLIError(AKSDiagnosticsError):
    """Azure CLI command execution failed"""
    def __init__(self, message: str, command: str = None, stderr: str = None):
        self.command = command
        self.stderr = stderr
        super().__init__(message)


class AzureAuthenticationError(AKSDiagnosticsError):
    """Azure authentication failed"""
    pass


class ClusterNotFoundError(AKSDiagnosticsError):
    """AKS cluster not found"""
    pass


class InvalidConfigurationError(AKSDiagnosticsError):
    """Invalid configuration provided"""
    pass


class ValidationError(AKSDiagnosticsError):
    """Input validation failed"""
    pass


class CacheError(AKSDiagnosticsError):
    """Cache operation failed"""
    pass
