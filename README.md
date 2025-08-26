# AKS Network Diagnostics Tool

A comprehensive Bash script for analyzing Azure Kubernetes Service (AKS) cluster network configurations. This tool performs read-only discovery and analysis to help diagnose networking issues, validate configurations, and detect potential misconfigurations in AKS clusters.

## Features

### 🔍 **Comprehensive Network Analysis**
- **Cluster Type Detection**: Identifies public vs. private clusters with VNet integration details
- **Network Plugin Analysis**: Supports kubenet and Azure CNI configurations
- **Outbound Connectivity**: Analyzes LoadBalancer, NAT Gateway, and User-Defined Routing configurations
- **VNet Discovery**: Maps virtual networks, subnets, peerings, and DNS configurations
- **Private DNS Validation**: Validates private DNS zones and A record configurations for private clusters

### 🛡️ **Security Assessment**
- **Network Security Groups**: Analyzes NSG rules affecting API server and DNS access
- **Route Tables**: Examines custom routes and default route configurations
- **Private Endpoint Validation**: Verifies private endpoint IP matches private DNS A records
- **DNS Server Analysis**: Identifies DNS server locations (current VNet, peered VNet, or external)

### ⚡ **Active Connectivity Testing** (Optional)
- **API Reachability**: Tests DNS resolution and TCP connectivity to API server from VMSS instances
- **Network Route Verification**: Validates routing from cluster nodes
- **Safe Execution**: Requires explicit `--probe-api` flag with clear warnings

### 📊 **Comprehensive Reporting**
- **Human-Readable Markdown**: Detailed assessment report with findings and recommendations
- **Machine-Readable JSON**: Structured data for automation and integration
- **Misconfiguration Detection**: Identifies common network issues with remediation guidance
- **Documentation Links**: Direct links to relevant Microsoft Learn articles

## Prerequisites

### Required Tools
- **Azure CLI**: Version 2.0 or later
  ```bash
  # Install Azure CLI
  curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
  ```
- **jq**: JSON processor for parsing Azure CLI responses
  ```bash
  # Ubuntu/Debian
  sudo apt-get install jq
  
  # CentOS/RHEL
  sudo yum install jq
  
  # macOS
  brew install jq
  ```

### Azure Authentication
```bash
# Login to Azure
az login

# Set subscription (if needed)
az account set --subscription "your-subscription-id"
```

## Usage

### Basic Usage
```bash
./aks-net-diagnostics.sh -n <AKS_CLUSTER_NAME> -g <RESOURCE_GROUP>
```

### Advanced Options
```bash
./aks-net-diagnostics.sh -n my-aks-cluster -g my-resource-group \
  --subscription "12345678-1234-1234-1234-123456789012" \
  --probe-api \
  --json-out report.json \
  --cache
```

### Command Line Options

| Option | Description | Required |
|--------|-------------|----------|
| `-n <NAME>` | AKS cluster name | ✅ Yes |
| `-g <GROUP>` | AKS resource group | ✅ Yes |
| `--subscription <ID>` | Azure subscription ID (overrides current context) | ❌ No |
| `--probe-api` | Enable active connectivity checks from VMSS instances | ❌ No |
| `--json-out <FILE>` | Save JSON report to file | ❌ No |
| `--cache` | Cache Azure CLI responses for faster re-runs | ❌ No |
| `-h, --help` | Show help message | ❌ No |

## What It Analyzes

### 🏗️ **Cluster Configuration**
- Provisioning state and basic cluster information
- Network plugin type (kubenet vs. Azure CNI)
- Service CIDR, Pod CIDR, and DNS service IP configuration
- API server access configuration (public/private)

### 🌐 **Outbound Connectivity**
- **LoadBalancer**: Identifies public IPs from load balancer outbound rules
- **NAT Gateway**: Lists public IPs and prefixes attached to NAT gateways
- **User-Defined Routing**: Analyzes custom route tables and default routes
- **Effective Public IPs**: Determines actual egress IP addresses

### 🔒 **Private Cluster Analysis**
- Private DNS zone configuration (System vs. Bring-Your-Own)
- A record validation against private endpoint IPs
- VNet link verification for custom DNS servers
- Private FQDN resolution validation

### 🔗 **Network Infrastructure**
- **Virtual Networks**: Address spaces, custom DNS servers, peering relationships
- **Subnets**: NSG and route table associations, NAT gateway attachments
- **DNS Configuration**: Location analysis (current VNet, peered VNet, external)
- **VMSS Network Setup**: Per-node pool network interface configurations

### 🛡️ **Security Analysis**
- **NSG Rules**: Identifies rules affecting API server (443), DNS (53), and NTP (123)
- **Route Tables**: Custom routes, default route configurations, next hop analysis
- **Access Control**: Authorized IP ranges for public clusters

## Sample Output

### Markdown Report
```markdown
# AKS Network Assessment Report

**Cluster:** my-aks-cluster
**Resource Group:** my-resource-group
**Subscription:** 12345678-1234-1234-1234-123456789012
**Generated:** 2025-08-26 15:30:45 UTC

## Cluster Overview
| Property | Value |
|----------|-------|
| Provisioning State | Succeeded |
| Location | East US |
| Network Plugin | azure |
| Outbound Type | loadBalancer |
| Private Cluster | true |

## Network Configuration
### Outbound Connectivity
- **Outbound Type:** loadBalancer
- **Effective Public IPs:**
  - 20.1.2.3
  - 20.1.2.4

### Virtual Networks
#### VNet: aks-vnet-eastus
- **Address Space:** 10.0.0.0/16
- **DNS:** Azure default
- **VNet Peerings:** 1
  - hub-peering → hub-vnet (Connected)

## Findings and Recommendations
✅ No issues detected in the current configuration.
```

### JSON Report Structure
```json
{
  "metadata": {
    "timestamp": "2025-08-26T15:30:45Z",
    "version": "2.0",
    "generatedBy": "AKS Network Diagnostics Script"
  },
  "cluster": {
    "name": "my-aks-cluster",
    "resourceGroup": "my-resource-group",
    "subscription": "12345678-1234-1234-1234-123456789012",
    "networkProfile": {
      "networkPlugin": "azure",
      "outboundType": "loadBalancer"
    }
  },
  "networking": {
    "vnets": [...],
    "outbound": {
      "effectivePublicIPs": ["20.1.2.3", "20.1.2.4"]
    }
  },
  "diagnostics": {
    "findings": [...]
  }
}
```

## Common Issues Detected

### ❌ **Configuration Errors**
- **UDR_MISSING_DEFAULT_ROUTE**: User-defined routing configured without default route
- **NATGW_NOT_ATTACHED**: NAT Gateway outbound type without attached NAT Gateway
- **PDNS_A_RECORD_MISMATCH**: Private DNS A record doesn't match private endpoint IP

### ⚠️ **Configuration Warnings**
- **NSG_BLOCKS_API_ACCESS**: NSG rules may block API server access (port 443)
- **NSG_BLOCKS_DNS_ACCESS**: NSG rules may block DNS resolution (port 53)
- **PDNS_NODE_VNET_LINK_MISSING**: Private DNS zone not linked to node VNets

### ℹ️ **Informational**
- **EXTERNAL_DNS_SERVERS**: VNet uses external DNS servers (verify reachability)

## Safety and Security

### 🔒 **Read-Only by Default**
- Uses only `az ... show/list` commands for metadata queries
- No create, update, or delete operations
- Safe to run in production environments

### ⚠️ **Active Probing (Optional)**
- `--probe-api` flag enables active connectivity testing
- Executes commands inside VMSS instances using `az vmss run-command invoke`
- Requires explicit consent and shows clear warnings
- Time-boxed operations with sensible timeouts

### 📁 **Caching Support**
- `--cache` flag caches Azure CLI responses in temp directory
- Reduces API calls for repeated analysis
- Automatically cleaned up unless `--cache` is specified

## Troubleshooting

### Common Issues

#### Azure CLI Not Authenticated
```bash
Error: Not logged into Azure CLI
Solution: Run 'az login'
```

#### Missing Permissions
```bash
Error: Failed to fetch cluster information
Solution: Ensure you have Reader permissions on the AKS cluster and resource group
```

#### Tool Dependencies
```bash
Error: jq is required but not found
Solution: Install jq using your package manager
```

### Debug Mode
For verbose output, you can modify the script to add debug information:
```bash
# Add at the beginning of the script
set -x  # Enable debug mode
```

## Integration Examples

### CI/CD Pipeline
```yaml
# Azure DevOps Pipeline
- task: AzureCLI@2
  displayName: 'AKS Network Assessment'
  inputs:
    azureSubscription: 'your-service-connection'
    scriptType: 'bash'
    scriptLocation: 'inlineScript'
    inlineScript: |
      ./aks-net-diagnostics.sh -n $(aksClusterName) -g $(resourceGroup) \
        --json-out aks-network-report.json
      # Process findings for pipeline decisions
```

### Automation Script
```bash
#!/bin/bash
# Automated AKS cluster analysis
CLUSTERS=(
  "prod-aks-cluster:prod-rg"
  "dev-aks-cluster:dev-rg"
)

for cluster_info in "${CLUSTERS[@]}"; do
  IFS=':' read -r cluster_name resource_group <<< "$cluster_info"
  echo "Analyzing cluster: $cluster_name"
  
  ./aks-net-diagnostics.sh -n "$cluster_name" -g "$resource_group" \
    --json-out "reports/${cluster_name}-network-report.json"
done
```

## Contributing

### Development Guidelines
1. Maintain read-only default behavior
2. Add comprehensive error handling
3. Include detailed logging and progress indicators
4. Update documentation for new features
5. Test with various AKS configurations

### Testing Different Configurations
- Public clusters with LoadBalancer outbound
- Private clusters with System managed DNS
- Private clusters with BYO DNS zones
- Clusters with NAT Gateway outbound
- Clusters with User-Defined Routing
- Multi-VNet scenarios with peering

## Documentation References

### Microsoft Learn Resources
- [AKS Outbound Types Overview](https://learn.microsoft.com/azure/aks/egress-outboundtype)
- [Private AKS Clusters](https://learn.microsoft.com/azure/aks/private-clusters)
- [Private DNS Zones](https://learn.microsoft.com/azure/dns/private-dns-overview)
- [User-Defined Routes](https://learn.microsoft.com/azure/virtual-network/virtual-networks-udr-overview)
- [NAT Gateway](https://learn.microsoft.com/azure/virtual-network/nat-gateway/)
- [Network Security Groups](https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview)
- [AKS Network Concepts](https://learn.microsoft.com/azure/aks/concepts-network)
- [Effective Security Rules](https://learn.microsoft.com/azure/virtual-network/diagnose-network-traffic-filtering-problem)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For issues and questions:
1. Check the troubleshooting section above
2. Review Azure documentation links
3. Create an issue in this repository with:
   - AKS cluster configuration details (anonymized)
   - Error messages or unexpected behavior
   - Output from the script (with sensitive data removed)
