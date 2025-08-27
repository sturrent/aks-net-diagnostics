# AKS Network Diagnostics Tool

A comprehensive Bash script for analyzing Azure Kubernetes Service (AKS) cluster network configurations. Performs read-only analysis to diagnose networking issues, validate configurations, and detect misconfigurations in AKS clusters.

## 🚀 Quick Start

```bash
# Basic analysis with summary output
./aks-net-diagnostics.sh -n my-cluster -g my-resource-group

# Detailed analysis with verbose output
./aks-net-diagnostics.sh -n my-cluster -g my-resource-group --verbose

# Skip JSON report generation
./aks-net-diagnostics.sh -n my-cluster -g my-resource-group --no-json
```

## ✨ Key Features

### **🔍 Comprehensive Analysis**
- **Network Configuration**: Outbound types (LoadBalancer/NAT Gateway/UDR), VNet topology, DNS settings
- **Private Clusters**: DNS zone validation, VNet links, private endpoint verification
- **Security Assessment**: NSG rules, route tables, authorized IP ranges
- **Failure Analysis**: Azure activity logs, cluster failure correlation, node pool status

### **📊 Smart Output Modes**
- **Summary Mode** (default): Concise findings with key issues highlighted
- **Verbose Mode** (`--verbose`): Detailed report with comprehensive analysis
- **JSON Reports**: Structured data saved to auto-generated files for automation

### **🛡️ Production Safe**
- **Read-Only**: Uses only Azure CLI show/list commands
- **Optional Probing**: Active connectivity tests require explicit `--probe-api` flag
- **Secure**: No modifications to cluster or Azure resources

## 📋 Prerequisites

```bash
# Required tools
az --version    # Azure CLI 2.0+
jq --version    # JSON processor

# Azure authentication
az login
az account set --subscription "your-subscription-id"
```

## 🎯 Usage Examples

### Basic Commands
```bash
# Standard analysis (summary + JSON report)
./aks-net-diagnostics.sh -n prod-cluster -g prod-rg

# Detailed analysis for troubleshooting
./aks-net-diagnostics.sh -n failed-cluster -g rg --verbose

# Quick check without saving JSON
./aks-net-diagnostics.sh -n dev-cluster -g dev-rg --no-json

# Custom JSON filename
./aks-net-diagnostics.sh -n cluster -g rg --json-out my-report.json
```

### Advanced Options
```bash
# Active connectivity testing (executes commands in cluster nodes)
./aks-net-diagnostics.sh -n cluster -g rg --probe-api

# Specific subscription
./aks-net-diagnostics.sh -n cluster -g rg --subscription "12345678-1234-1234-1234-123456789012"

# All options
./aks-net-diagnostics.sh -n cluster -g rg --verbose --probe-api --json-out report.json --cache
```

## 📊 Sample Output

### Summary Mode (Default)
```
# AKS Network Assessment Summary

**Cluster:** my-cluster (Failed)
**Resource Group:** my-rg
**Generated:** 2025-08-26 15:30:45 UTC

**Configuration:**
- Network Plugin: azure
- Outbound Type: loadBalancer
- Private Cluster: true

**⚠️ Cluster Failure Summary:**
- Network-related failures detected
- Primary error: VMExtensionError_K8SAPIServerDNSLookupFail

**Findings Summary:**
- 🔴 2 Critical/Error issue(s)
- 🟡 1 Warning(s)
- ℹ️ 1 Informational finding(s)

**Critical Issues:**
- PDNS_DNS_HOST_VNET_LINK_MISSING: DNS server in peered VNet not linked to private DNS zone
- CLUSTER_NETWORK_FAILURE: Cluster failed due to DNS configuration issues

💡 Tip: Use --verbose flag for detailed analysis
📄 JSON report saved to: aks-network-report_my-cluster_20250826_153045.json
```

## 🔍 What It Detects

### **Common Issues**
| Code | Issue | Severity |
|------|-------|----------|
| `PDNS_DNS_HOST_VNET_LINK_MISSING` | DNS server in peered VNet not linked to private DNS zone | ❌ Critical |
| `CLUSTER_NETWORK_FAILURE` | Cluster provisioning failed due to network issues | ❌ Critical |
| `UDR_MISSING_DEFAULT_ROUTE` | User-defined routing without default route | ❌ Critical |
| `NSG_BLOCKS_API_ACCESS` | NSG rules may block API server access | ⚠️ Warning |
| `PEERED_VNET_DNS_SERVERS` | VNet uses DNS servers in peered VNets | ℹ️ Info |

### **Analysis Coverage**
- ✅ **Cluster State**: Provisioning status, failure reasons, node pool health
- ✅ **Network Topology**: VNets, subnets, peerings, DNS configuration
- ✅ **Outbound Connectivity**: Load balancers, NAT gateways, effective public IPs
- ✅ **Private DNS**: Zone validation, VNet links, A record verification
- ✅ **Security**: NSG rules, route tables, authorized IP ranges
- ✅ **Failure Correlation**: Activity logs linked to network misconfigurations

## � Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-n <NAME>` | AKS cluster name | Required |
| `-g <GROUP>` | Resource group name | Required |
| `--verbose` | Show detailed analysis output | Summary mode |
| `--no-json` | Skip JSON report generation | Auto-generated JSON |
| `--json-out <FILE>` | Custom JSON filename | `aks-network-report_<cluster>_<timestamp>.json` |
| `--probe-api` | Enable active connectivity tests | Disabled |
| `--subscription <ID>` | Azure subscription override | Current context |
| `--cache` | Cache Azure CLI responses | No caching |

## 🆘 Troubleshooting

| Error | Solution |
|-------|----------|
| `Not logged into Azure CLI` | Run `az login` |
| `jq is required but not found` | Install jq: `sudo apt install jq` |
| `Failed to fetch cluster information` | Check Azure permissions (Reader role required) |

## 📚 Documentation

- [AKS Outbound Types](https://learn.microsoft.com/azure/aks/egress-outboundtype)
- [Private AKS Clusters](https://learn.microsoft.com/azure/aks/private-clusters)
- [Private DNS Zones](https://learn.microsoft.com/azure/dns/private-dns-overview)
- [AKS Network Concepts](https://learn.microsoft.com/azure/aks/concepts-network)

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.
