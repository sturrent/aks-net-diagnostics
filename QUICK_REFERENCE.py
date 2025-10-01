"""
QUICK REFERENCE - Refactored AKS Diagnostics
==============================================

High Priority Refactoring - Completed ✅
"""

# ============================================================================
# 1. VALIDATING USER INPUT
# ============================================================================

from aks_diagnostics.validators import InputValidator
from aks_diagnostics.exceptions import ValidationError

# Validate cluster/resource names
try:
    name = InputValidator.validate_resource_name('my-cluster', 'cluster')
    rg = InputValidator.validate_resource_name('my-rg', 'resource group')
    sub = InputValidator.validate_subscription_id('12345678-1234-...')
except ValidationError as e:
    print(f"Invalid: {e}")

# Sanitize filenames
safe_name = InputValidator.sanitize_filename('my/dangerous/../file.json')
# Returns: 'my_dangerous_..__file.json'

# Validate Azure CLI commands
cmd = ['aks', 'show', '-n', 'cluster', '-g', 'rg']
InputValidator.validate_azure_cli_command(cmd)  # Raises if dangerous

# ============================================================================
# 2. USING THE CACHE
# ============================================================================

from aks_diagnostics.cache import CacheManager
from pathlib import Path

# Create cache (disabled by default)
cache = CacheManager(
    cache_dir=Path('.aks_cache'),  # Cache directory
    default_ttl=3600,               # 1 hour default
    enabled=True                    # Enable caching
)

# Store data
cache.set('command', {'data': 'value'})                    # Default TTL
cache.set('command', {'data': 'value'}, ttl=1800)         # Custom TTL (30min)

# Retrieve data
result = cache.get('command')  # Returns None if expired/missing

# Management
cache.clear()             # Clear all cache
cache.cleanup_expired()   # Remove expired entries only
stats = cache.get_stats() # Get cache statistics

# Stats output:
# {
#     'enabled': True,
#     'memory_entries': 10,
#     'file_entries': 10,
#     'cache_dir': '/path/to/.aks_cache'
# }

# ============================================================================
# 3. EXECUTING AZURE CLI COMMANDS
# ============================================================================

from aks_diagnostics.azure_cli import AzureCLIExecutor
from aks_diagnostics.exceptions import AzureCLIError, AzureAuthenticationError

# Create executor
azure_cli = AzureCLIExecutor(cache_manager=cache)  # Optional cache

# Check prerequisites
try:
    azure_cli.check_prerequisites()  # Checks: az installed, logged in
except FileNotFoundError as e:
    print(f"Azure CLI not found: {e}")
except AzureAuthenticationError as e:
    print(f"Not logged in: {e}")

# Set subscription
azure_cli.set_subscription('my-subscription-id')

# Get current subscription
sub_id = azure_cli.get_current_subscription()

# Execute commands
try:
    # JSON output
    result = azure_cli.execute(['aks', 'show', '-n', 'cluster', '-g', 'rg'])
    print(result['name'])
    
    # Plain text output
    version = azure_cli.execute(['--version'], expect_json=False)
    print(version)
    
except AzureCLIError as e:
    print(f"Error: {e.message}")
    print(f"Command: {e.command}")
    print(f"Stderr: {e.stderr}")

# ============================================================================
# 4. CREATING FINDINGS
# ============================================================================

from aks_diagnostics.models import Finding, FindingCode, Severity

# Factory methods (recommended)
critical = Finding.create_critical(
    FindingCode.CLUSTER_OPERATION_FAILURE,
    message="Cluster failed",
    recommendation="Check Activity Log",
    error_code="InternalError"  # kwargs become details
)

warning = Finding.create_warning(
    FindingCode.UDR_CONFLICT,
    message="UDR conflicts detected",
    recommendation="Review routes"
)

info = Finding.create_info(
    FindingCode.API_ACCESS_RESTRICTED,
    message="API access restricted",
    recommendation="No action needed"
)

# Direct instantiation
finding = Finding(
    severity=Severity.CRITICAL,
    code=FindingCode.CLUSTER_STOPPED,
    message="Cluster is stopped",
    recommendation="Start cluster",
    details={'state': 'Stopped', 'reason': 'UserAction'}
)

# Convert to dict for JSON
finding_dict = finding.to_dict()
# {
#     'severity': 'critical',
#     'code': 'CLUSTER_STOPPED',
#     'message': 'Cluster is stopped',
#     'recommendation': 'Start cluster',
#     'details': {'state': 'Stopped', 'reason': 'UserAction'}
# }

# ============================================================================
# 5. CUSTOM ANALYZERS
# ============================================================================

from aks_diagnostics.base_analyzer import BaseAnalyzer

class MyAnalyzer(BaseAnalyzer):
    """Custom analyzer example"""
    
    def analyze(self):
        """Perform analysis"""
        # Log to analyzer's logger
        self.logger.info("Starting analysis...")
        
        # Get cluster properties safely
        name = self.get_cluster_property('name', default='unknown')
        location = self.get_cluster_property('location')
        network = self.get_cluster_property('networkProfile', 'outboundType')
        
        # Check conditions
        if network == 'userDefinedRouting':
            finding = Finding.create_warning(
                FindingCode.UDR_CONFLICT,
                message=f"Cluster {name} uses UDR outbound",
                recommendation="Verify UDR configuration",
                location=location
            )
            self.add_finding(finding)
        
        # Return analysis results
        return {
            'cluster_name': name,
            'location': location,
            'outbound_type': network,
            'findings_count': len(self.findings)
        }

# Usage
cluster_info = {...}  # From Azure CLI
analyzer = MyAnalyzer(azure_cli, cluster_info)
results = analyzer.analyze()
findings = analyzer.get_findings()

# ============================================================================
# 6. ERROR HANDLING PATTERNS
# ============================================================================

from aks_diagnostics.exceptions import (
    AKSDiagnosticsError,      # Base
    AzureCLIError,            # CLI failures
    AzureAuthenticationError, # Auth issues
    ValidationError,          # Invalid input
    ClusterNotFoundError,     # Cluster not found
)

def analyze_cluster_safe(cluster_name, resource_group):
    """Example with comprehensive error handling"""
    try:
        # Validate
        cluster_name = InputValidator.validate_resource_name(cluster_name, 'cluster')
        resource_group = InputValidator.validate_resource_name(resource_group, 'rg')
        
        # Setup
        cache = CacheManager(enabled=True)
        azure_cli = AzureCLIExecutor(cache_manager=cache)
        azure_cli.check_prerequisites()
        
        # Execute
        result = azure_cli.execute([
            'aks', 'show',
            '-n', cluster_name,
            '-g', resource_group
        ])
        
        return {'success': True, 'data': result}
        
    except ValidationError as e:
        return {'success': False, 'error': 'Invalid input', 'message': str(e)}
    
    except AzureAuthenticationError as e:
        return {'success': False, 'error': 'Not authenticated', 'message': 'Run: az login'}
    
    except AzureCLIError as e:
        return {
            'success': False,
            'error': 'CLI error',
            'message': e.message,
            'command': e.command
        }
    
    except AKSDiagnosticsError as e:
        return {'success': False, 'error': 'Diagnostics error', 'message': str(e)}
    
    except Exception as e:
        return {'success': False, 'error': 'Unexpected error', 'message': str(e)}

# ============================================================================
# 7. TESTING
# ============================================================================

# Run all tests
# $ python -m tests

# Run specific test file
# $ python -m unittest tests.test_validators

# Run specific test class
# $ python -m unittest tests.test_cache.TestCacheManager

# Run specific test method
# $ python -m unittest tests.test_cache.TestCacheManager.test_cache_expiration

# Run with verbose output
# $ python -m unittest discover -s tests -v

# ============================================================================
# 8. COMMON PATTERNS
# ============================================================================

# Pattern 1: Setup with validation
def setup_diagnostics(cluster_name, resource_group, use_cache=True):
    """Standard setup pattern"""
    # Validate
    cluster_name = InputValidator.validate_resource_name(cluster_name, 'cluster')
    resource_group = InputValidator.validate_resource_name(resource_group, 'rg')
    
    # Create components
    cache = CacheManager(enabled=use_cache, default_ttl=3600)
    azure_cli = AzureCLIExecutor(cache_manager=cache)
    
    # Check prerequisites
    azure_cli.check_prerequisites()
    
    return azure_cli, cache

# Pattern 2: Safe property access
def get_network_type(cluster_info):
    """Safely extract nested property"""
    from aks_diagnostics.base_analyzer import BaseAnalyzer
    
    # Use BaseAnalyzer helper
    analyzer = BaseAnalyzer(None, cluster_info)
    return analyzer.get_cluster_property(
        'networkProfile',
        'outboundType',
        default='loadBalancer'
    )

# Pattern 3: Batch findings
def create_findings_from_issues(issues):
    """Convert issues to findings"""
    findings = []
    
    for issue in issues:
        if issue['severity'] == 'critical':
            finding = Finding.create_critical(
                FindingCode.CLUSTER_OPERATION_FAILURE,
                message=issue['message'],
                recommendation=issue['fix'],
                **issue.get('details', {})
            )
        else:
            finding = Finding.create_warning(
                FindingCode.UDR_CONFLICT,
                message=issue['message'],
                recommendation=issue['fix'],
                **issue.get('details', {})
            )
        
        findings.append(finding)
    
    return findings

# ============================================================================
# QUICK REFERENCE SUMMARY
# ============================================================================

"""
Module             Purpose                    Key Classes/Functions
----------------   ------------------------   ---------------------------
validators.py      Input validation           InputValidator
cache.py           Caching with TTL           CacheManager
azure_cli.py       Execute Azure CLI          AzureCLIExecutor
models.py          Data structures            Finding, VMSSInstance, etc.
exceptions.py      Error handling             7 custom exceptions
base_analyzer.py   Analyzer base class        BaseAnalyzer

All modules follow:
✅ Single Responsibility Principle
✅ Type hints
✅ Comprehensive docstrings
✅ Unit tests
✅ Error handling
✅ Logging support
"""
