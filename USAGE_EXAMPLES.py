"""
Quick Start Guide for Refactored AKS Diagnostics
=================================================

This guide explains how to use the refactored components.
"""

# Testing the refactored components
# ==================================

# 1. Set up your Python environment
# Ensure Python 3.6+ is installed:
#   python --version  (or python3 --version)

# 2. Navigate to the project directory
#   cd aks-net-diagnostics

# 3. Run all tests
#   python -m tests
#   or
#   python -m unittest discover -s tests -v

# 4. Run specific test file
#   python -m unittest tests.test_validators
#   python -m unittest tests.test_cache  
#   python -m unittest tests.test_models

# Example: Using the new modules
# ================================

from aks_diagnostics.models import Finding, FindingCode, Severity
from aks_diagnostics.cache import CacheManager
from aks_diagnostics.validators import InputValidator
from aks_diagnostics.azure_cli import AzureCLIExecutor
from aks_diagnostics.exceptions import ValidationError, AzureCLIError

# 1. Input Validation
# -------------------
try:
    # Validate cluster name
    cluster_name = InputValidator.validate_resource_name('my-cluster', 'cluster')
    
    # Sanitize filename
    safe_filename = InputValidator.sanitize_filename('my/dangerous/../filename')
    
    # Validate Azure CLI command
    cmd = ['aks', 'show', '-n', cluster_name, '-g', 'my-rg']
    InputValidator.validate_azure_cli_command(cmd)
    
except ValidationError as e:
    print(f"Validation failed: {e}")

# 2. Cache Management
# -------------------
from pathlib import Path

# Create cache manager
cache = CacheManager(
    cache_dir=Path('.aks_cache'),
    default_ttl=3600,  # 1 hour
    enabled=True
)

# Cache some data
cache.set('az aks list', [{'name': 'cluster1'}], ttl=1800)

# Retrieve cached data
data = cache.get('az aks list')
if data:
    print(f"Found cached data: {data}")

# Get cache statistics
stats = cache.get_stats()
print(f"Cache stats: {stats}")

# Cleanup expired entries
cache.cleanup_expired()

# Clear all cache
cache.clear()

# 3. Azure CLI Execution
# ----------------------
try:
    # Create executor with cache
    azure_cli = AzureCLIExecutor(cache_manager=cache)
    
    # Check prerequisites
    azure_cli.check_prerequisites()
    
    # Execute command
    result = azure_cli.execute(['account', 'show'])
    print(f"Current subscription: {result.get('name')}")
    
    # Get current subscription
    sub_id = azure_cli.get_current_subscription()
    print(f"Subscription ID: {sub_id}")
    
except AzureCLIError as e:
    print(f"CLI Error: {e}")
    print(f"Command: {e.command}")
except FileNotFoundError as e:
    print(f"Azure CLI not found: {e}")

# 4. Creating Findings
# --------------------

# Using factory methods (recommended)
critical_finding = Finding.create_critical(
    FindingCode.CLUSTER_OPERATION_FAILURE,
    message="Cluster operation failed",
    recommendation="Check Azure Activity Log",
    error_code="InternalError"
)

warning_finding = Finding.create_warning(
    FindingCode.UDR_CONFLICT,
    message="UDR conflicts with outbound configuration",
    recommendation="Review User Defined Routes"
)

info_finding = Finding.create_info(
    FindingCode.API_ACCESS_RESTRICTED,
    message="API server access is restricted",
    recommendation="Review authorized IP ranges if needed"
)

# Convert to dictionary for JSON export
finding_dict = critical_finding.to_dict()
print(finding_dict)
# Output:
# {
#     'severity': 'critical',
#     'code': 'CLUSTER_OPERATION_FAILURE',
#     'message': 'Cluster operation failed',
#     'recommendation': 'Check Azure Activity Log',
#     'details': {'error_code': 'InternalError'}
# }

# 5. Error Handling Pattern
# --------------------------

from aks_diagnostics.exceptions import (
    AKSDiagnosticsError,
    AzureCLIError,
    AzureAuthenticationError,
    ValidationError
)

def analyze_cluster(cluster_name, resource_group):
    """Example function with proper error handling"""
    try:
        # Validate inputs
        cluster_name = InputValidator.validate_resource_name(cluster_name, 'cluster')
        resource_group = InputValidator.validate_resource_name(resource_group, 'resource group')
        
        # Create Azure CLI executor
        cache = CacheManager(enabled=True)
        azure_cli = AzureCLIExecutor(cache_manager=cache)
        
        # Check prerequisites
        azure_cli.check_prerequisites()
        
        # Get cluster info
        cmd = ['aks', 'show', '-n', cluster_name, '-g', resource_group, '-o', 'json']
        cluster_info = azure_cli.execute(cmd)
        
        return cluster_info
        
    except ValidationError as e:
        print(f"Invalid input: {e}")
        return None
    except AzureAuthenticationError as e:
        print(f"Not authenticated: {e}")
        print("Please run: az login")
        return None
    except AzureCLIError as e:
        print(f"Azure CLI error: {e}")
        print(f"Failed command: {e.command}")
        return None
    except AKSDiagnosticsError as e:
        print(f"Diagnostics error: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error: {e}")
        return None

# Usage
result = analyze_cluster('my-cluster', 'my-resource-group')
if result:
    print(f"Cluster: {result.get('name')}")


# 6. Writing Custom Analyzers
# ----------------------------

from aks_diagnostics.base_analyzer import BaseAnalyzer

class CustomAnalyzer(BaseAnalyzer):
    """Example custom analyzer"""
    
    def analyze(self):
        """Perform custom analysis"""
        self.logger.info("Running custom analysis...")
        
        # Get cluster properties safely
        cluster_name = self.get_cluster_property('name', default='unknown')
        location = self.get_cluster_property('location')
        
        # Perform some checks
        if location == 'eastus':
            finding = Finding.create_info(
                FindingCode.API_ACCESS_RESTRICTED,
                message=f"Cluster {cluster_name} is in East US region",
                recommendation="Consider regional redundancy"
            )
            self.add_finding(finding)
        
        # Return analysis results
        return {
            'cluster_name': cluster_name,
            'location': location,
            'findings_count': len(self.findings)
        }

# Use the analyzer
cluster_info = {'name': 'test-cluster', 'location': 'eastus'}
analyzer = CustomAnalyzer(azure_cli, cluster_info)
results = analyzer.analyze()
findings = analyzer.get_findings()


# Summary of Benefits
# ===================

# ✅ Modular Design
#    - Each component has single responsibility
#    - Easy to test and maintain
#    - Reusable across different scripts

# ✅ Proper Error Handling
#    - Specific exception types
#    - Clear error messages
#    - Easy to catch and handle

# ✅ Improved Caching
#    - TTL expiration prevents stale data
#    - File persistence between runs
#    - Memory cache for performance
#    - Automatic cleanup

# ✅ Input Validation
#    - Prevents injection attacks
#    - Sanitizes user input
#    - Clear validation rules

# ✅ Testability
#    - Unit tests for all components
#    - Mock-friendly design
#    - Test coverage tracking

# Next Steps
# ==========

# 1. Complete the refactoring:
#    - Create core.py orchestrator
#    - Port remaining analyzers
#    - Update CLI entry point

# 2. Run tests:
#    python -m tests

# 3. Review test results:
#    - Ensure all tests pass
#    - Check coverage

# 4. Integrate with original script:
#    - Gradual migration
#    - Maintain backward compatibility
