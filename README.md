# AKS Network Diagnostics Tool

A comprehensive Python tool for analyzing Azure Kubernetes Service (AKS) network configurations and diagnosing connectivity issues. Features a modular architecture with specialized analyzers for deep network troubleshooting.

[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![Azure CLI 2.0+](https://img.shields.io/badge/Azure%20CLI-2.0+-blue.svg)](https://docs.microsoft.com/en-us/cli/azure/)
[![Tests](https://img.shields.io/badge/tests-147%20passing-success.svg)](tests/)

## Key Features

- **Comprehensive Analysis**: 9 specialized analyzers for deep network diagnostics
- **Active Testing**: Optional connectivity probes from cluster nodes
- **Multiple Output Formats**: Console summary + detailed output + JSON export
- **Security Focused**: NSG compliance, inter-node traffic validation
- **Modular design**: 147 unit tests, modular architecture
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
- **Azure CLI 2.0+** - [Installation guide](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli)
- **Azure Authentication**: Run `az login` before using the tool
- **Permissions**: Reader access to AKS cluster and related network resources

## Installation & Usage

### Option 1: Single-File Distribution (Recommended for End Users)

Download and run the pre-built `.pyz` file from [Releases](https://github.com/sturrent/aks-net-diagnostics/releases):

```bash
# Download the latest release
wget https://github.com/sturrent/aks-net-diagnostics/releases/latest/download/aks-net-diagnostics.pyz
```

```bash
# Run directly with Python
python aks-net-diagnostics.pyz -n myCluster -g myResourceGroup

# Or make it executable (Linux/macOS)
chmod +x aks-net-diagnostics.pyz
./aks-net-diagnostics.pyz -n myCluster -g myResourceGroup
```

**Advantages:**
- Single file (~57 KB)
- No installation required
- Just download and run
- All modules bundled inside

### Option 2: Clone Repository (For Development/Customization)

```bash
git clone https://github.com/sturrent/aks-net-diagnostics.git
cd aks-net-diagnostics
python aks-net-diagnostics.py -n myCluster -g myResourceGroup
```

### Building Your Own .pyz File

To create the single-file distribution:

```bash
python build_zipapp.py
# Creates: aks-net-diagnostics.pyz
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

For detailed architecture documentation, see [ARCHITECTURE.md](ARCHITECTURE.md)

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
| `--cache` | Enable response caching (faster reruns) | `--cache` |

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
- [X] 4 Critical issue(s)

**Critical Issues:**

### [X] PRIVATE_DNS_MISCONFIGURED
**Severity:** CRITICAL
**Message:** Private cluster is using custom DNS servers (10.1.0.10) that cannot resolve Azure private DNS zones
**Recommendation:** Configure DNS forwarding to 168.63.129.16 for '*.privatelink.*.azmk8s.io'

### [X] CLUSTER_OPERATION_FAILURE
**Severity:** CRITICAL
**Message:** Cluster failed with error: VMExtensionProvisioningError - agents are unable to resolve Kubernetes API server name
**Recommendation:** Check Azure Activity Log and custom DNS configuration

### [X] NODE_POOL_FAILURE
**Severity:** CRITICAL
**Message:** Node pools in failed state: nodepool1
**Recommendation:** Check node pool configuration and Azure Activity Log

### [X] PDNS_DNS_HOST_VNET_LINK_MISSING
**Severity:** CRITICAL
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

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, testing guidelines, and contribution process.

For architecture details, see [ARCHITECTURE.md](ARCHITECTURE.md).

## Troubleshooting

### Common Issues

**Azure CLI not found**

```bash
# Verify Azure CLI installation
az --version

# Install if missing
# Windows: https://aka.ms/installazurecliwindows
# Linux: curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
# macOS: brew install azure-cli
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

```bash
# Ensure you're in the project directory
cd aks-net-diagnostics

# Install any missing dependencies
pip install -r requirements.txt  # if requirements.txt exists
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
