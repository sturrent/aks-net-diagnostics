# AKS Network Diagnostics Tool

A comprehensive Python script for analyzing Azure Kubernetes Service (AKS) cluster network configurations. Performs read-only analysis to diagnose networking issues, validate configurations, and detect misconfigurations including User Defined Routes (UDRs) and virtual appliance routing.

## 🚀 Quick Start

```bash
# Basic analysis with summary output
python3 aks-net-diagnostics.py -n my-cluster -g my-resource-group

# Detailed analysis with verbose output
python3 aks-net-diagnostics.py -n my-cluster -g my-resource-group --verbose

# Include active connectivity testing from cluster nodes
python3 aks-net-diagnostics.py -n my-cluster -g my-resource-group --probe-api
```

## ✨ Key Features

### **🔍 Comprehensive Analysis**

- **Network Configuration**: Outbound types (LoadBalancer/NAT Gateway/UDR), VNet topology, DNS settings
- **UDR Analysis**: User Defined Routes detection, virtual appliance routing, traffic impact assessment  
- **Private Clusters**: DNS zone validation, VNet links, private endpoint verification
- **Security Assessment**: NSG rules, route tables, authorized IP ranges
- **Active Connectivity**: Optional VMSS-based testing (DNS resolution, HTTPS connectivity, API server access)

### **📊 Smart Output Modes**

- **Summary Mode** (default): Concise findings with key issues highlighted
- **Verbose Mode** (`--verbose`): Detailed report with comprehensive analysis and test outputs
- **JSON Reports**: Structured data automatically saved to timestamped files

### **🛡️ Production Safe**

- **Read-Only**: Uses only Azure CLI show/list commands
- **Optional Probing**: Active connectivity tests require explicit `--probe-api` flag
- **Performance Optimized**: Limits connectivity testing to single VMSS instance

## 📋 Prerequisites

```bash
# Required tools
python3 --version     # Python 3.6+
az --version          # Azure CLI 2.0+

# Azure authentication
az login
az account set --subscription "your-subscription-id"
```

## 🎯 Usage Examples

### Basic Commands

```bash
# Standard analysis (summary + JSON report)
python3 aks-net-diagnostics.py -n prod-cluster -g prod-rg

# Detailed analysis for troubleshooting
python3 aks-net-diagnostics.py -n failed-cluster -g rg --verbose

# Active connectivity testing (executes commands in cluster nodes)
python3 aks-net-diagnostics.py -n cluster -g rg --probe-api
```

### Advanced Options

```bash
# All options combined
python3 aks-net-diagnostics.py -n cluster -g rg --verbose --probe-api

# Specific subscription
python3 aks-net-diagnostics.py -n cluster -g rg --subscription "12345678-1234-1234-1234-123456789012"
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
- Outbound Type: loadBalancer
- Private Cluster: false

**Outbound IPs:**
- 130.107.205.36

**UDR Analysis:**
- Route Tables: 1 (aks-udr)
- Virtual Appliance Routes: 1 (10.0.1.4)
- High Impact Routes: 1

**Connectivity Tests:** (6 total)
- ✅ DNS Resolution: 3/3 passed
- ❌ HTTPS Connectivity: 0/3 passed (blocked by firewall)

**Findings Summary:**
- ❌ 2 Critical/Error issue(s)
- ⚠️ 3 Warning issue(s)

💡 Tip: Use --verbose flag for detailed analysis
📄 JSON report saved to: aks-net-diagnostics_my-cluster_20250902_233045.json
```

## 🔍 What It Detects

### **Common Issues**

| Code | Issue | Severity |
|------|-------|----------|
| `UDR_HIGH_IMPACT_ROUTE` | Default route (0.0.0.0/0) redirects traffic to virtual appliance | ❌ Critical |
| `UDR_DEFAULT_ROUTE_VA` | Virtual appliance routing may affect AKS connectivity | ⚠️ Warning |
| `CONNECTIVITY_HTTPS_FAILURE` | HTTPS connectivity tests failed (firewall/NSG blocking) | ❌ Critical |
| `CONNECTIVITY_API_SERVER_FAILURE` | API server connectivity test failed | ❌ Critical |
| `PDNS_DNS_HOST_VNET_LINK_MISSING` | DNS server in peered VNet not linked to private DNS zone | ❌ Critical |

### **Analysis Coverage**

- ✅ **Cluster State**: Provisioning status, power state, network plugin configuration
- ✅ **Network Topology**: VNets, subnets, peerings, DNS configuration
- ✅ **Outbound Connectivity**: Load balancers, NAT gateways, effective public IPs
- ✅ **UDR Analysis**: Route tables, virtual appliance detection, traffic impact assessment
- ✅ **Private DNS**: Zone validation, VNet links, A record verification
- ✅ **Active Testing**: DNS resolution, HTTPS connectivity, API server access (optional)

## 📋 Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-n <NAME>` | AKS cluster name | Required |
| `-g <GROUP>` | Resource group name | Required |
| `--verbose` | Show detailed analysis output and test results | Summary mode |
| `--probe-api` | Enable active connectivity tests from cluster nodes | Disabled |
| `--subscription <ID>` | Azure subscription override | Current context |
