# AKS Network Diagnostics Tool

A POC Python script for analyzing Azure Kubernetes Service (AKS) cluster network configurations. Performs analysis to diagnose networking issues, validate security configurations, and detect misconfigurations including User Defined Routes (UDRs), DNS, NAT Gateway setups, NSGs, and API server access restrictions.

## 🚀 Quick Start

```bash
# Basic analysis with summary output
python3 aks-net-diagnostics.py -n my-cluster -g my-resource-group

# Detailed analysis with verbose output (includes NAT Gateway + API security analysis)
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
