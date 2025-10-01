# AKS Network Diagnostics Tool

A comprehensive Python tool for analyzing Azure Kubernetes Service (AKS) cluster network configurations. Performs deep analysis to diagnose networking issues, validate security configurations, and detect misconfigurations including User Defined Routes (UDRs), DNS, NAT Gateway setups, NSGs, and API server access restrictions.

## 🆕 What's New

- **✅ Windows Support**: Full compatibility with Windows PowerShell and Command Prompt
- **✅ Modular Architecture**: New `aks_diagnostics` package with reusable components
- **✅ Test Suite**: 26 unit tests ensuring code quality and reliability
- **✅ Production-Ready Caching**: TTL-based cache with persistence for faster repeated runs
- **✅ Modern Python**: Updated to use timezone-aware datetime (Python 3.7+ compatible)

## 🚀 Quick Start

### Windows (PowerShell/CMD)

```powershell
# Basic analysis with summary output
python aks-net-diagnostics.py -n my-cluster -g my-resource-group

# Detailed analysis with verbose output
python aks-net-diagnostics.py -n my-cluster -g my-resource-group --verbose

# Include active connectivity testing from cluster nodes
python aks-net-diagnostics.py -n my-cluster -g my-resource-group --probe-test
```

### Linux/macOS

```bash
# Basic analysis with summary output
python3 aks-net-diagnostics.py -n my-cluster -g my-resource-group

# Detailed analysis with verbose output
python3 aks-net-diagnostics.py -n my-cluster -g my-resource-group --verbose

# Include active connectivity testing from cluster nodes
python3 aks-net-diagnostics.py -n my-cluster -g my-resource-group --probe-test
```

## ✨ Key Features

### **🔍 Comprehensive Analysis**

- **Network Configuration**: Outbound types (LoadBalancer/NAT Gateway/UDR), VNet topology, DNS settings
- **Outbound Connectivity**: Load Balancer IPs, NAT Gateway public IPs and prefixes, UDR conflict detection
- **UDR Analysis**: User Defined Routes detection, virtual appliance routing, traffic impact assessment  
- **NSG Analysis**: Network Security Groups on subnets and NICs, rule compliance checking, blocking rule detection
- **Private Clusters**: DNS zone validation, VNet links, private endpoint verification
- **API Server Security**: Authorized IP ranges analysis, security validation, outbound IP authorization checks
- **Security Assessment**: Broad IP range detection, private range validation, connectivity impact analysis
- **Active Connectivity**: Optional VMSS-based testing with DNS-first logic (DNS resolution, HTTPS connectivity, API server access)

### **📊 Output Modes**

- **Summary Mode** (default): Concise findings with key issues highlighted
- **Verbose Mode** (`--verbose`): Detailed report with comprehensive analysis and test outputs
- **JSON Reports**: Structured data automatically saved to timestamped files

### **🛡️ Read Only Operations**

- **Read-Only**: Uses only Azure CLI show/list commands
- **Optional Probing**: Active connectivity tests require explicit `--probe-test` flag

## 📋 Prerequisites

### Required Tools

```bash
# Python 3.7 or higher
python --version     # Windows
python3 --version    # Linux/macOS

# Azure CLI 2.0 or higher
az --version
```

### Azure Authentication

```bash
# Login to Azure
az login

# Set subscription (optional, if you have multiple subscriptions)
az account set --subscription "your-subscription-id"
```

### Optional: Install Development Dependencies

```bash
# For running tests and development
pip install -r requirements.txt
```

## 🎯 Usage Examples

### Basic Commands

```bash
# Standard analysis (summary + JSON report)
python3 aks-net-diagnostics.py -n prod-cluster -g prod-rg

# Detailed analysis for troubleshooting
python3 aks-net-diagnostics.py -n failed-cluster -g rg --verbose

# Active connectivity testing (executes nslookup and curl commands in cluster nodes)
python3 aks-net-diagnostics.py -n cluster -g rg --probe-test
```

## 📊 Sample Output

### Summary Mode (Default)

```text
# AKS Network Assessment Summary

**Cluster:** my-cluster (Succeeded)
**Resource Group:** my-rg
**Generated:** 2025-09-02 23:30:45 UTC

**Configuration:**
- Network Plugin: azure
- Outbound Type: managedNATGateway
- Private Cluster: false

**Outbound Configuration:**
- NAT Gateway IPs:
  - 4.205.231.XX

**API Server Security:**
- Authorized IP Ranges: 1 range(s)
  - 100.65.190.XX/32

**Findings Summary:**
- ❌ Cluster outbound IPs (4.205.231.XX) are not in authorized IP ranges
- ⚠️ Very restrictive authorized IP range detected

💡 Tip: Use --verbose flag for detailed analysis
📄 JSON report saved to: aks-net-diagnostics_my-cluster_20250902_233045.json
```

## 🔍 What It Detects

### **Common Issues**

| Code | Issue | Severity |
|------|-------|----------|
| `API_OUTBOUND_NOT_AUTHORIZED` | Cluster outbound IPs not in authorized IP ranges (nodes cannot access API) | ❌ Critical |
| `UDR_HIGH_IMPACT_ROUTE` | Default route (0.0.0.0/0) redirects traffic to virtual appliance | ❌ Critical |
| `CLUSTER_OPERATION_FAILURE` | Cluster failed with operation errors | ❌ Critical |
| `NODE_POOL_FAILURE` | Node pools in failed state | ❌ Critical |
| `UDR_DEFAULT_ROUTE_VA` | Virtual appliance routing may affect AKS connectivity | ⚠️ Warning |
| `UDR_AZURE_SERVICES_VA` | Azure service traffic routed through virtual appliance | ⚠️ Warning |
| `UDR_CONTAINER_REGISTRY_VA` | Container registry traffic routed through virtual appliance | ⚠️ Warning |
| `NSG_BLOCKING_RULE_DETECTED` | NSG rule blocking required AKS traffic | ❌ Critical |
| `CONNECTIVITY_DNS_FAILURE` | DNS resolution tests failed | ❌ Critical |
| `CONNECTIVITY_HTTPS_FAILURE` | HTTPS connectivity tests failed (firewall/NSG blocking) | ❌ Critical |
| `CONNECTIVITY_API_SERVER_FAILURE` | API server connectivity test failed | ❌ Critical |
| `PDNS_DNS_HOST_VNET_LINK_MISSING` | DNS server in peered VNet not linked to private DNS zone | ❌ Critical |

### **Analysis Coverage**

- ✅ **Cluster State**: Provisioning status, power state, network plugin configuration
- ✅ **Network Topology**: VNets, subnets, peerings, DNS configuration
- ✅ **Outbound Connectivity**: Load balancers, NAT gateways, public IP prefixes, effective public IPs
- ✅ **UDR Analysis**: Route tables, virtual appliance detection, traffic impact assessment, conflict detection
- ✅ **NSG Analysis**: Network Security Groups on subnets and NICs, rule compliance, blocking rule detection
- ✅ **API Server Security**: Authorized IP ranges, security validation, outbound IP authorization
- ✅ **Private DNS**: Zone validation, VNet links, A record verification
- ✅ **Active Testing**: DNS-first connectivity testing (DNS resolution → HTTPS connectivity, API server access)

## 📋 Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-n <NAME>` | AKS cluster name | Required |
| `-g <GROUP>` | Resource group name | Required |
| `--verbose` | Show detailed analysis output and test results | Summary mode |
| `--probe-test` | Enable active connectivity tests from cluster nodes | Disabled |
| `--subscription <ID>` | Azure subscription override | Current context |

## 🏗️ Real-World Scenarios

### **Scenario 1: Healthy Public Cluster**

```bash
# Standard public cluster with all services working
python3 aks-net-diagnostics.py -n aks-good-cluster -g aks-good-cluster --probe-test
```

**Expected Results:**

- ✅ DNS Resolution tests: All pass (MCR, Azure Management, API Server)
- ✅ HTTPS Connectivity tests: All pass (proper SSL handshake completion)
- ✅ Load Balancer outbound IP: 130.107.224.XX
- ✅ No API server restrictions (unrestricted public access)
- ✅ No blocking NSG rules detected

### **Scenario 2: Private Cluster with DNS Issues**

```bash
# Private cluster with missing DNS zone links
python3 aks-net-diagnostics.py -n aks-api-connection -g aks-api-connection-lab1-rg --probe-test
```

**Detects:**

- ✅ DNS Resolution: MCR and Azure Management pass
- ❌ **Critical**: API Server DNS resolves to public IP instead of private IP
- 🚫 **Skipped**: API Server HTTPS test (DNS-first logic skips due to DNS failure)
- ❌ **Critical**: DNS server in peered VNet not linked to private DNS zone
- ❌ **Critical**: Private cluster connectivity failure

### **Scenario 3: Azure Firewall/NVA with SSL Inspection**

```bash
# Cluster with Azure Firewall intercepting SSL traffic
python3 aks-net-diagnostics.py -n aks-slb-fw -g aks-slb-fw-rg --probe-test --verbose
```

**Detects:**

- ⚠️ Load Balancer configured (130.107.205.XX) but not effective
- ✅ Effective outbound via Virtual Appliance: 10.0.1.4
- ✅ DNS Resolution tests: All pass (firewall allows DNS)
- ❌ **Critical**: HTTPS connectivity tests fail (SSL handshake interrupted)
- ❌ Error: `ssl routines::unexpected eof while reading` (firewall blocking SSL)
- ⚠️ Default route (0.0.0.0/0) affects all traffic including container registry

### **Scenario 4: NSG Analysis with Blocking Rules**

```bash
# Cluster with NSGs potentially blocking traffic
python3 aks-net-diagnostics.py -n cluster-with-nsgs -g rg --verbose
```

**Detects:**

- ✅ NSG analysis on subnets and NICs
- ❌ **Critical**: NSG rules blocking required AKS traffic (if present)
- ✅ Inter-node communication validation
- ✅ Deduplication of NSG findings across multiple NICs with same NSG

## 🧪 Testing

The tool includes a comprehensive test suite to ensure reliability:

```bash
# Run all tests
python -m unittest discover -s tests -v

# Run specific test module
python -m unittest tests.test_validators -v
python -m unittest tests.test_cache -v
python -m unittest tests.test_models -v
```

**Test Coverage:**

- 26 unit tests across 3 test modules
- Input validation tests (14 test cases)
- Cache functionality tests (8 test cases)
- Data model tests (7 test cases)

## 🏗️ Modular Architecture

The tool now includes a modular `aks_diagnostics` package for developers:

```python
from aks_diagnostics.validators import InputValidator
from aks_diagnostics.cache import CacheManager
from aks_diagnostics.azure_cli import AzureCLIExecutor
from aks_diagnostics.exceptions import AzureCLIError, ValidationError

# Validate input
try:
    cluster = InputValidator.validate_resource_name('my-cluster', 'cluster')
except ValidationError as e:
    print(f"Invalid: {e}")

# Use cache for better performance
cache = CacheManager(enabled=True, default_ttl=3600)

# Execute Azure CLI with caching
azure_cli = AzureCLIExecutor(cache_manager=cache)
result = azure_cli.execute(['aks', 'show', '-n', cluster, '-g', 'rg'])
```

**Package Structure:**

```text
aks_diagnostics/
├── models.py         # Data models (VMSSInstance, Finding, DiagnosticResult)
├── exceptions.py     # Custom exception hierarchy (7 types)
├── validators.py     # Input validation and sanitization
├── cache.py          # TTL-based cache with file persistence
├── azure_cli.py      # Azure CLI executor with error handling
└── base_analyzer.py  # Base class for custom analyzers
```

## 🔧 Troubleshooting

### Windows Issues

**Azure CLI not found:**

```powershell
# Verify Azure CLI is installed and in PATH
az --version

# If not found, add to PATH or use full path
"C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin\az.cmd" --version
```

**Python not found:**

```powershell
# Verify Python is installed
python --version

# If using python3 command
python3 --version
```

### Linux/macOS Issues

**Permission denied:**

```bash
# Make script executable
chmod +x aks-net-diagnostics.py

# Or run with python directly
python3 aks-net-diagnostics.py -n cluster -g rg
```
