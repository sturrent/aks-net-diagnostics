# AKS Network Diagnostics Tool

A Python tool for analyzing Azure Kubernetes Service (AKS) network configurations and diagnosing connectivity issues.

## Quick Start

```bash
# Basic analysis
python aks-net-diagnostics.py -n my-cluster -g my-resource-group

# Detailed output
python aks-net-diagnostics.py -n my-cluster -g my-resource-group --verbose

# Include connectivity testing from cluster nodes
python aks-net-diagnostics.py -n my-cluster -g my-resource-group --probe-test
```

## Prerequisites

- Python 3.7+
- Azure CLI 2.0+
- Azure authentication: `az login`

## What It Analyzes

- **Network Configuration**: Outbound type (LoadBalancer/NAT Gateway/UDR), VNet topology, DNS
- **Outbound Connectivity**: Public IPs, NAT Gateway, User Defined Routes (UDRs)
- **Security**: NSG rules, API Server authorized IP ranges
- **Private Clusters**: DNS zones, VNet links, private endpoints
- **Active Testing** (optional): DNS resolution and HTTPS connectivity from nodes

## Common Issues Detected

| Issue | Severity |
|-------|----------|
| Cluster outbound IPs not in authorized IP ranges | Critical |
| Default route redirecting traffic to firewall/NVA | Critical |
| NSG rules blocking required AKS traffic | Critical |
| DNS resolution failures | Critical |
| HTTPS connectivity failures (SSL/firewall blocking) | Critical |
| Private DNS zone VNet link missing | Critical |
| Firewall/NVA routing affecting container registry | Warning |

## Command Options

| Option | Description |
|--------|-------------|
| `-n <NAME>` | AKS cluster name (required) |
| `-g <GROUP>` | Resource group name (required) |
| `--verbose` | Show detailed analysis and test results |
| `--probe-test` | Enable active connectivity tests from nodes |
| `--subscription <ID>` | Override Azure subscription |

## Sample Output

### Example: Private Cluster with DNS Issues

```bash
python aks-net-diagnostics.py -g my-resource-group -n my-private-cluster --no-json --verbose
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
- [!] 4 Critical issue(s)

**Critical Issues:**

### [!] PRIVATE_DNS_MISCONFIGURED
**Message:** Private cluster is using custom DNS servers (10.1.0.10) that cannot resolve Azure private DNS zones
**Recommendation:** Configure DNS forwarding to 168.63.129.16 for '*.privatelink.*.azmk8s.io'

### [!] CLUSTER_OPERATION_FAILURE
**Message:** Cluster failed with error: VMExtensionProvisioningError - agents are unable to resolve Kubernetes API server name
**Recommendation:** Check Azure Activity Log and custom DNS configuration

### [!] NODE_POOL_FAILURE
**Message:** Node pools in failed state: nodepool1
**Recommendation:** Check node pool configuration and Azure Activity Log

### [!] PDNS_DNS_HOST_VNET_LINK_MISSING
**Message:** DNS server 10.1.0.10 is hosted in VNet hub-vnet but this VNet is not linked to private DNS zone
**Recommendation:** Link VNet hub-vnet to private DNS zone for proper DNS resolution
```

This example shows the tool detecting a common private cluster misconfiguration where custom DNS servers aren't properly configured to resolve Azure private DNS zones.

## Active Connectivity Tests

When using `--probe-test`, the tool runs these tests from cluster nodes:

1. **MCR DNS Resolution** - Test DNS for mcr.microsoft.com
2. **Internet Connectivity** - Test HTTPS to Microsoft Container Registry
3. **API Server DNS** - Test DNS for cluster API server
4. **API Server HTTPS** - Test HTTPS to cluster API server

Tests use dependency logic: HTTPS tests are skipped if their DNS test fails.

## Output Files

Reports are automatically saved as JSON:
- Format: `aks-net-diagnostics_{cluster-name}_{timestamp}.json`
- Location: Current directory
- Use `--no-json` to disable

## Running Tests

```bash
# Install development dependencies
pip install -r requirements.txt

# Run test suite
python -m pytest tests/ -v
```

## Architecture

The tool uses a modular design with specialized analyzers:

- **DNS Analyzer**: Private cluster DNS validation
- **NSG Analyzer**: Network security group compliance
- **Route Table Analyzer**: UDR impact assessment
- **API Server Analyzer**: Access control validation
- **Connectivity Tester**: Active node connectivity testing

## Troubleshooting

**Azure CLI not found:**
```bash
az --version  # Verify installation
```

**Python not found:**
```bash
python --version  # or python3 --version
```

**Permission errors on Linux/macOS:**
```bash
chmod +x aks-net-diagnostics.py
```

## License

MIT License - See [LICENSE](LICENSE) file
