# AKS Network Diagnostics Tool

A comprehensive Python tool for analyzing Azure Kubernetes Service (AKS) network configurations and diagnosing connectivity issues. Features a modular architecture with specialized analyzers for deep network troubleshooting.

**Version**: 2.2.0 (Azure SDK)

[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![Azure SDK](https://img.shields.io/badge/Azure%20SDK-latest-blue.svg)](https://azure.github.io/azure-sdk-for-python/)
[![Tests](https://img.shields.io/badge/tests-136%20passing-success.svg)](tests/)
[![Code Quality](https://img.shields.io/badge/pylint-9.70%2F10-brightgreen.svg)](pylintrc)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Version](https://img.shields.io/badge/version-2.2.0-green.svg)](CHANGELOG.md)

## Key Features

- **Comprehensive Analysis**: 9 specialized analyzers for deep network diagnostics
- **Active Testing**: Optional connectivity probes from cluster nodes
- **Multiple Output Formats**: Console summary + detailed output + JSON export
- **Security Focused**: NSG compliance, inter-node traffic validation
- **Modular design**: 136 unit tests, type-safe Azure SDK
- **Detailed Reports**: Actionable recommendations for every finding

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation & Usage](#installation--usage)
- [Quick Start](#quick-start)
- [What It Analyzes](#what-it-analyzes)
- [Architecture](#architecture)
- [Command Options](#command-options)
- [Usage Examples](#usage-examples)
- [Active Connectivity Tests](#active-connectivity-tests)
- [Output Files](#output-files)
- [Development](#development)
- [Troubleshooting](#troubleshooting)

## Prerequisites

- **Python 3.7+** - [Download](https://www.python.org/downloads/)
- **Azure SDK Packages** - Automatically installed via pip (see below)
- **Azure Authentication**: Azure credentials configured (DefaultAzureCredential)
- **Permissions**: Reader access to AKS cluster and related network resources

> **Note**: This version (2.0.0) uses the **Azure SDK for Python** instead of Azure CLI. No Azure CLI installation required!

## Installation & Usage

### Option 1: Single-File Distribution (Recommended for End Users)

Download and run the pre-built `.pyz` file from [Releases](https://github.com/sturrent/aks-net-diagnostics/releases):

**Step 1: Install Azure SDK dependencies**

> ⚠️ **IMPORTANT**: The `.pyz` file contains only the tool code (~58 KB). You must install Azure SDK packages separately.

```bash
# Install required Azure SDK packages (one-time setup)
pip install azure-identity azure-mgmt-containerservice azure-mgmt-network \
            azure-mgmt-compute azure-mgmt-privatedns azure-mgmt-resource
```

**Step 2: Download the tool**

```bash
# Download the latest release
wget https://github.com/sturrent/aks-net-diagnostics/releases/latest/download/aks-net-diagnostics.pyz
chmod +x aks-net-diagnostics.pyz
```

**Step 3: Run the tool**

```bash
# Verify installation
./aks-net-diagnostics.pyz --version

# Run diagnostic
./aks-net-diagnostics.pyz -n myCluster -g myResourceGroup
```

**Why separate installation?**
- `.pyz` file stays small (~58 KB) for easy distribution
- Azure SDK packages (~50-100 MB) are managed by your Python environment
- Standard Python packaging practice (like any pip package)

### Option 2: Clone Repository (For Development/Customization)

```bash
git clone https://github.com/sturrent/aks-net-diagnostics.git
cd aks-net-diagnostics

# Install Azure SDK dependencies
pip install -r requirements.txt

# Run the tool
python aks-net-diagnostics.py -n myCluster -g myResourceGroup
```

**Required Azure SDK packages:**
- `azure-identity` - Authentication
- `azure-mgmt-containerservice` - AKS management
- `azure-mgmt-network` - Network resources
- `azure-mgmt-compute` - VM/VMSS management
- `azure-mgmt-resource` - Resource management
- `azure-mgmt-privatedns` - Private DNS zones

### Building Your Own .pyz File

To create the single-file distribution:

```bash
pip install -r requirements.txt  # Install dependencies first
python tools/build_zipapp.py
# Creates: aks-net-diagnostics.pyz (~58 KB with Azure SDK)
```

## Quick Start

```bash
# Using the .pyz file (recommended)
python aks-net-diagnostics.pyz -n my-cluster -g my-resource-group

# OR using the source code
python aks-net-diagnostics.py -n my-cluster -g my-resource-group

# With detailed output
python aks-net-diagnostics.pyz -n my-cluster -g my-resource-group --details

# Save JSON report with auto-generated filename
python aks-net-diagnostics.pyz -n my-cluster -g my-resource-group --json-report

# Save JSON report with custom filename
python aks-net-diagnostics.pyz -n my-cluster -g my-resource-group --json-report my-report.json

# Include connectivity testing from cluster nodes
python aks-net-diagnostics.pyz -n my-cluster -g my-resource-group --probe-test
```

## What It Analyzes

### Network Components

- **VNet Configuration**: Topology, address spaces, peerings
- **Outbound Connectivity**: LoadBalancer, NAT Gateway, User Defined Routes
- **DNS Configuration**: Azure DNS, Custom DNS, Private DNS zones
- **VMSS Network Profiles**: Node subnet assignments, NIC configurations

### Security & Access Control

- **NSG Rules**: Required AKS traffic, blocking rules, inter-node communication
- **API Server Access**: Authorized IP ranges, private endpoints
- **Route Tables**: UDR impact on AKS management traffic

### Active Testing (Optional)

- **DNS Resolution**: MCR, API server hostname lookup from nodes
- **HTTPS Connectivity**: Container registry, API server reachability
- **Network Path**: Validates full network path from nodes to Azure services

## Architecture

The tool uses a **modular architecture** with specialized analyzers:

- **Data Collection**: Gathers cluster info, VNets, VMSS configurations
- **Network Analysis**: NSG rules, DNS, routing, outbound connectivity
- **Security Validation**: API server access, authorized IPs
- **Active Testing**: Optional connectivity probes from nodes
- **Reporting**: Console output, JSON export, finding correlation

**Key Modules**: NSGAnalyzer, DNSAnalyzer, RouteTableAnalyzer, APIServerAccessAnalyzer, ConnectivityTester, OutboundConnectivityAnalyzer

For detailed architecture documentation, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

## Common Issues Detected

| Issue | Severity | Description |
|-------|----------|-------------|
| Outbound IPs not in authorized ranges | Critical | Cluster can't reach API server |
| Default route to firewall/NVA | Critical | Breaks AKS management traffic |
| NSG blocking required traffic | Critical | Prevents node communication |
| NSG blocking inter-node traffic | Warning | Breaks system components (konnectivity, metrics-server) |
| DNS resolution failures | Critical | Nodes can't resolve Azure services |
| HTTPS connectivity blocked | Critical | SSL interception or firewall blocking |
| Private DNS zone VNet link missing | Critical | Private cluster name resolution fails |
| Custom DNS not forwarding to Azure DNS | Critical | Private endpoints unreachable |

## Command Options

| Option | Description | Example |
|--------|-------------|---------|
| `-n <NAME>` | AKS cluster name (required) | `-n my-cluster` |
| `-g <GROUP>` | Resource group name (required) | `-g my-rg` |
| `--details` | Show detailed analysis and test results | `--details` |
| `--probe-test` | Enable active connectivity tests from nodes | `--probe-test` |
| `--json-report [FILE]` | Save JSON report (optional filename) | `--json-report report.json` |
| `--subscription <ID>` | Override Azure subscription | `--subscription abc-123` |

## Usage Examples

### Basic Analysis

Quick health check of cluster network configuration:

```bash
python aks-net-diagnostics.py -n production-cluster -g prod-rg
```

### Detailed Analysis

Get comprehensive details about all network components:

```bash
python aks-net-diagnostics.py -n production-cluster -g prod-rg --details
```

### Active Connectivity Testing

Test actual connectivity from cluster nodes (DNS + HTTPS):

```bash
python aks-net-diagnostics.py -n production-cluster -g prod-rg --probe-test
```

### Save JSON Report

Export full analysis data for documentation or automation:

```bash
# Auto-generated filename
python aks-net-diagnostics.py -n production-cluster -g prod-rg --json-report

# Custom filename
python aks-net-diagnostics.py -n production-cluster -g prod-rg --json-report audit-2025-10-03.json
```

### Troubleshoot Failed Cluster

Comprehensive analysis with connectivity tests:

```bash
python aks-net-diagnostics.py -n failed-cluster -g troubleshooting-rg --details --probe-test
```

### Multi-Subscription Analysis

Analyze cluster in different subscription:

```bash
python aks-net-diagnostics.py -n cluster -g rg --subscription xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

## Sample Output

### Example: Private Cluster with DNS Issues

```bash
python aks-net-diagnostics.py -g my-resource-group -n my-private-cluster --details
```

**Output:**

```text
# AKS Network Assessment Report

**Cluster:** my-private-cluster
**Resource Group:** my-resource-group
**Generated:** 2025-10-03 14:17:24 UTC

## Cluster Overview

| Property | Value |
|----------|-------|
| Provisioning State | Failed |
| Power State | Running |
| Network Plugin | azure |
| Outbound Type | loadBalancer |
| Private Cluster | true |

## Network Configuration

### API Server Access
- **Type:** Private cluster
- **Private FQDN:** my-cluster-xxx.privatelink.eastus.azmk8s.io
- **Private DNS Zone:** system
- **Access Restrictions:** None (unrestricted public access)

### Outbound Connectivity
- **Type:** loadBalancer
- **Effective Public IPs:** 20.10.5.100

### Network Security Group (NSG) Analysis
- **NSGs Analyzed:** 2
- **Issues Found:** 0
- **Inter-node Communication:** [OK] Ok

**Subnet NSGs:**
- **aks-subnet** -> NSG: my-subnet-nsg-eastus
  - Custom Rules: 0, Default Rules: 6

**NIC NSGs:**
- **my-nodepool-nsg** (used by: aks-nodepool1-vmss)
  - Custom Rules: 0, Default Rules: 6

## Findings

**Findings Summary:**
- [CRITICAL] 4

### [CRITICAL] PRIVATE_DNS_MISCONFIGURED
**Message:** Private cluster is using custom DNS servers (10.1.0.10) that cannot resolve Azure private DNS zones
**Recommendation:** Configure DNS forwarding to 168.63.129.16 for '*.privatelink.*.azmk8s.io'

### [CRITICAL] CLUSTER_OPERATION_FAILURE
**Message:** Cluster failed with error: VMExtensionProvisioningError - agents are unable to resolve Kubernetes API server name
**Recommendation:** Check Azure Activity Log and custom DNS configuration

### [CRITICAL] NODE_POOL_FAILURE
**Message:** Node pools in failed state: nodepool1
**Recommendation:** Check node pool configuration and Azure Activity Log

### [CRITICAL] PDNS_DNS_HOST_VNET_LINK_MISSING
**Message:** DNS server 10.1.0.10 is hosted in VNet hub-vnet but this VNet is not linked to private DNS zone
**Recommendation:** Link VNet hub-vnet to private DNS zone for proper DNS resolution
```

This example shows the tool detecting a common private cluster misconfiguration where custom DNS servers aren't properly configured to resolve Azure private DNS zones.

## 🧪 Active Connectivity Tests

When using `--probe-test`, the tool executes connectivity tests directly from cluster nodes using VMSS run-command.

### Test Suite

| Test | Description | Purpose |
|------|-------------|---------|
| **MCR DNS Resolution** | Resolves `mcr.microsoft.com` | Validates DNS for container registry |
| **Internet Connectivity** | HTTPS to MCR | Tests outbound internet access |
| **API Server DNS** | Resolves cluster API hostname | Validates private DNS configuration |
| **API Server HTTPS** | HTTPS to API server | Tests API server reachability |

### Test Logic

- Tests use **dependency checking**: HTTPS tests skip if DNS fails
- **Timeouts configured**: 60s for MCR, 15s for API server
- **Full error visibility**: Detailed curl output shows exact failure points
- **VMSS timeout**: 5 minutes to account for queuing and execution

### Sample Output

```text
### Connectivity Tests

**Test Results:**
- [PASS] MCR DNS Resolution - PASSED
  - Resolved to: 150.171.70.10, 150.171.69.10
  
- [PASS] Internet Connectivity - PASSED
  - Successfully connected to mcr.microsoft.com
  
- [PASS] API Server DNS Resolution - PASSED
  - Resolved to: 10.0.0.10
  
- [FAIL] API Server HTTPS Connectivity - FAILED
  - Error: Connection timeout after 15s
  - Possible causes: Firewall blocking, NSG rules, routing issues
```

## Output Files

### Console Output

- **Summary Mode** (default): High-level findings and recommendations
- **Detailed Mode** (`--details`): Detailed analysis of all components
- **Exit Codes**:
  - `0`: Analysis completed successfully
  - `1`: Unexpected error
  - `2`: Configuration/validation error
  - `3`: File error
  - `4`: Permission error
  - `130`: Cancelled by user (Ctrl+C)

### JSON Report

Generated with `--json-report`, contains:

```json
{
  "metadata": {
    "cluster_name": "my-cluster",
    "resource_group": "my-rg",
    "subscription": "xxx",
    "generated": "2025-10-03T14:30:00Z",
    "script_version": "2.1"
  },
  "cluster_info": { "..." },
  "findings": [
    {
      "severity": "critical",
      "code": "CLUSTER_OPERATION_FAILURE",
      "message": "...",
      "recommendation": "..."
    }
  ],
  "network_analysis": {
    "vnets": [],
    "outbound": {},
    "nsgs": {},
    "dns": {},
    "api_server": {}
  },
  "connectivity_tests": []
}
```

## Development

This project uses automated code quality tools and testing:

- **Code Quality Tools**: Black, isort, Flake8, Pylint
- **Testing**: 136 unit tests with pytest
- **CI/CD**: GitHub Actions for automated checks
- **Pre-Push Hook**: Automatic quality checks before push

**For contributors:**
- See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines and setup
- See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for development environment setup
- See [docs/PRE_PUSH_HOOK.md](docs/PRE_PUSH_HOOK.md) for git hook details

**Quality Standards:**
- Zero Flake8 violations (PEP8 compliance)
- Pylint score 9.5+/10 (Azure CLI standards)
- 120 character line length
- Full type hints and docstrings

For architecture details, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Troubleshooting

### Common Issues

**Azure SDK authentication errors**

```bash
# Verify Azure credentials are configured
# Option 1: Azure CLI (recommended)
az login
az account show

# Option 2: Environment variables
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"
export AZURE_TENANT_ID="your-tenant-id"

# Option 3: Managed Identity (when running in Azure)
# No configuration needed - works automatically
```

**Not logged in to Azure**

```bash
# Login to Azure
az login

# Verify authentication
az account show

# Set specific subscription
az account set --subscription "My Subscription"
```

**Python not found**

```bash
# Check Python version
python --version  # or python3 --version

# Requires Python 3.7+
# Download from: https://www.python.org/downloads/
```

**Permission errors on Linux/macOS**

```bash
# Make script executable
chmod +x aks-net-diagnostics.py

# Run with python explicitly
python3 aks-net-diagnostics.py -n my-cluster -g my-rg
```

**VMSS run-command timeout**

If connectivity tests timeout:
- Cluster nodes may be under heavy load
- Network path may be experiencing latency
- Use `--details` to see detailed error messages
- Re-run without `--probe-test` for static analysis only

**Module import errors**

If you see `ModuleNotFoundError: No module named 'azure.mgmt.containerservice'`:

> ⚠️ **The .pyz file does NOT include Azure SDK packages**. You must install them separately.

```bash
# Install Azure SDK dependencies (required for v2.0.0+)
pip install azure-identity azure-mgmt-containerservice azure-mgmt-network \
            azure-mgmt-compute azure-mgmt-privatedns azure-mgmt-resource

# Verify installation
python -c "import azure.mgmt.containerservice; print('SDK installed ✓')"

# Then run the tool
./aks-net-diagnostics.pyz --version
```

**For repository clone:**

```bash
# Ensure you're in the project directory
cd aks-net-diagnostics

# Install dependencies
pip install -r requirements.txt
```

### Getting Help

- **Issues**: [GitHub Issues](https://github.com/sturrent/aks-net-diagnostics/issues)
- **Detailed Mode**: Always use `--details` when reporting issues
- **JSON Export**: Attach JSON report (`--json-report`) for detailed diagnostics

## License

MIT License - See [LICENSE](LICENSE) file for details

## Acknowledgments

Built for Azure Kubernetes Service troubleshooting by the Azure community.

---

**Version**: 2.1  
**Last Updated**: October 2025  
**Maintained by**: [@sturrent](https://github.com/sturrent)
