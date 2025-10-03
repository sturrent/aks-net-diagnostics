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

```text
# AKS Network Assessment Summary

**Cluster:** my-cluster (Succeeded)
**Resource Group:** my-rg

**Configuration:**
- Network Plugin: azure
- Outbound Type: managedNATGateway
- Private Cluster: false

**Outbound Configuration:**
- NAT Gateway IPs: 4.205.231.XX

**API Server Security:**
- Authorized IP Ranges: 100.65.190.XX/32

**Findings Summary:**
- [!] 1 Critical issue(s)

**Critical Issues:**
- Cluster outbound IPs not in authorized IP ranges

 JSON report: aks-net-diagnostics_my-cluster_20250902_233045.json
```

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
