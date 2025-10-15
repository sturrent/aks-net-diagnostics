# Azure SDK Refactoring Plan

## Overview

This document outlines the plan to refactor the AKS Network Diagnostics tool from using Azure CLI subprocess calls to using the Azure SDK for Python. This is necessary for integration as an `az aks` subcommand in the Azure CLI repository.

**Branch:** `azure-cli-refactor`

**Target Command:** `az aks net-diagnostics`

---

## Current Architecture

### Azure CLI Usage Pattern

The tool currently uses `AzureCLIExecutor` class which:
1. Executes `az` commands via subprocess
2. Parses JSON output
3. Handles authentication, timeouts, and errors
4. Implements caching for performance

### Modules Using Azure CLI

| Module | Purpose | Azure CLI Commands Used |
|--------|---------|------------------------|
| `cluster_data_collector.py` | Fetch cluster, VNet, VMSS info | 9 command types |
| `outbound_analyzer.py` | Analyze outbound connectivity | 6 command types |
| `nsg_analyzer.py` | Analyze NSG rules | 2 command types |
| `route_table_analyzer.py` | Analyze UDRs | 2 command types |
| `dns_analyzer.py` | Analyze DNS configuration | 1 command type |
| `misconfiguration_analyzer.py` | Find DNS misconfigurations | 4 command types |
| `connectivity_tester.py` | Run active connectivity tests | 3 command types |
| Main script | Get subscription info | 1 command type |

**Total: 28 distinct Azure CLI command patterns to migrate**

---

## Azure CLI Commands Inventory

### 1. Subscription & Account Management

#### Commands:
```bash
# Get current subscription ID
az account show --query id -o tsv
```

#### Azure SDK Equivalent:
```python
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import SubscriptionClient

credential = DefaultAzureCredential()
subscription_client = SubscriptionClient(credential)
subscription = subscription_client.subscriptions.get(subscription_id)
# Or list subscriptions
subscriptions = list(subscription_client.subscriptions.list())
```

#### Required Package:
- `azure-mgmt-resource`

---

### 2. AKS Cluster Operations

#### Commands:
```bash
# Get cluster information
az aks show -n {cluster_name} -g {resource_group}

# List agent pools
az aks nodepool list -g {resource_group} --cluster-name {cluster_name}
```

#### Azure SDK Equivalent:
```python
from azure.mgmt.containerservice import ContainerServiceClient
from azure.identity import DefaultAzureCredential

credential = DefaultAzureCredential()
aks_client = ContainerServiceClient(credential, subscription_id)

# Get cluster
cluster = aks_client.managed_clusters.get(resource_group, cluster_name)

# List agent pools
agent_pools = list(aks_client.agent_pools.list(resource_group, cluster_name))
```

#### Required Package:
- `azure-mgmt-containerservice`

#### Files to Update:
- `cluster_data_collector.py` (lines 47, 58)

---

### 3. Virtual Network Operations

#### Commands:
```bash
# Get VNet information
az network vnet show -n {vnet_name} -g {resource_group}

# List VNet peerings
az network vnet peering list -g {resource_group} --vnet-name {vnet_name}

# Get subnet information
az network vnet subnet show --ids {subnet_id}
az network vnet subnet show -g {rg} --vnet-name {vnet} -n {subnet}
```

#### Azure SDK Equivalent:
```python
from azure.mgmt.network import NetworkManagementClient
from azure.identity import DefaultAzureCredential

credential = DefaultAzureCredential()
network_client = NetworkManagementClient(credential, subscription_id)

# Get VNet
vnet = network_client.virtual_networks.get(resource_group, vnet_name)

# List peerings
peerings = list(network_client.virtual_network_peerings.list(
    resource_group, vnet_name
))

# Get subnet by resource ID parsing
# Parse subnet_id to extract: subscription, rg, vnet, subnet_name
subnet = network_client.subnets.get(resource_group, vnet_name, subnet_name)
```

#### Required Package:
- `azure-mgmt-network`

#### Files to Update:
- `cluster_data_collector.py` (lines 110, 125)
- `nsg_analyzer.py` (line 167)
- `route_table_analyzer.py` (line 134)

---

### 4. Virtual Machine Scale Set (VMSS) Operations

#### Commands:
```bash
# List VMSS in resource group
az vmss list -g {resource_group}

# Get VMSS details
az vmss show -n {vmss_name} -g {resource_group}

# List VMSS instances
az vmss list-instances -g {resource_group} -n {vmss_name}

# Run command on VMSS instance
az vmss run-command invoke \
  -g {resource_group} \
  -n {vmss_name} \
  --instance-id {instance_id} \
  --command-id RunShellScript \
  --scripts "{script}"
```

#### Azure SDK Equivalent:
```python
from azure.mgmt.compute import ComputeManagementClient
from azure.identity import DefaultAzureCredential

credential = DefaultAzureCredential()
compute_client = ComputeManagementClient(credential, subscription_id)

# List VMSS
vmss_list = list(compute_client.virtual_machine_scale_sets.list(resource_group))

# Get VMSS details
vmss = compute_client.virtual_machine_scale_sets.get(resource_group, vmss_name)

# List instances
instances = list(compute_client.virtual_machine_scale_set_vms.list(
    resource_group, vmss_name
))

# Run command (async operation)
from azure.mgmt.compute.models import RunCommandInput

run_command_params = RunCommandInput(
    command_id='RunShellScript',
    script=[script_content]
)

async_operation = compute_client.virtual_machine_scale_set_vms.begin_run_command(
    resource_group,
    vmss_name,
    instance_id,
    run_command_params
)

# Wait for completion
result = async_operation.result(timeout=300)
```

#### Required Package:
- `azure-mgmt-compute`

#### Files to Update:
- `cluster_data_collector.py` (lines 160, 175)
- `connectivity_tester.py` (lines 146, 160, 381)

---

### 5. Load Balancer Operations

#### Commands:
```bash
# List load balancers
az network lb list -g {resource_group}

# Get frontend IP configuration
az network lb frontend-ip show \
  -g {resource_group} \
  --lb-name {lb_name} \
  -n {frontend_config_name}

# Get public IP address
az network public-ip show --ids {public_ip_id}
```

#### Azure SDK Equivalent:
```python
from azure.mgmt.network import NetworkManagementClient

# List load balancers
lbs = list(network_client.load_balancers.list(resource_group))

# Load balancer details already include frontend configs
lb = network_client.load_balancers.get(resource_group, lb_name)
frontend_configs = lb.frontend_ip_configurations

# Get public IP
# Parse public_ip_id to get: subscription, rg, pip_name
public_ip = network_client.public_ip_addresses.get(
    resource_group, public_ip_name
)
```

#### Required Package:
- `azure-mgmt-network` (already included)

#### Files to Update:
- `outbound_analyzer.py` (lines 246, 292, 299)

---

### 6. NAT Gateway Operations

#### Commands:
```bash
# List NAT gateways
az network nat gateway list -g {resource_group}
```

#### Azure SDK Equivalent:
```python
from azure.mgmt.network import NetworkManagementClient

# List NAT gateways
nat_gateways = list(network_client.nat_gateways.list(resource_group))

# Get specific NAT gateway
nat_gateway = network_client.nat_gateways.get(resource_group, nat_gateway_name)
```

#### Required Package:
- `azure-mgmt-network` (already included)

#### Files to Update:
- `outbound_analyzer.py` (line 344)

---

### 7. Network Security Group (NSG) Operations

#### Commands:
```bash
# Get NSG details
az network nsg show --ids {nsg_id}
```

#### Azure SDK Equivalent:
```python
from azure.mgmt.network import NetworkManagementClient

# Parse NSG ID to get resource_group and nsg_name
nsg = network_client.network_security_groups.get(resource_group, nsg_name)

# Security rules are included in the NSG object
rules = nsg.security_rules
default_rules = nsg.default_security_rules
```

#### Required Package:
- `azure-mgmt-network` (already included)

#### Files to Update:
- `nsg_analyzer.py` (lines 180, 220)

---

### 8. Route Table Operations

#### Commands:
```bash
# Get route table details
az network route-table show \
  --subscription {subscription_id} \
  -g {resource_group} \
  -n {route_table_name}
```

#### Azure SDK Equivalent:
```python
from azure.mgmt.network import NetworkManagementClient

# Get route table (cross-subscription if needed)
credential = DefaultAzureCredential()
network_client = NetworkManagementClient(credential, subscription_id)

route_table = network_client.route_tables.get(resource_group, route_table_name)

# Routes are included
routes = route_table.routes
disable_bgp_route_propagation = route_table.disable_bgp_route_propagation
```

#### Required Package:
- `azure-mgmt-network` (already included)

#### Files to Update:
- `route_table_analyzer.py` (line 172)

---

### 9. Private DNS Operations

#### Commands:
```bash
# List private DNS zones
az network private-dns zone list -g {resource_group}

# List VNet links for a private DNS zone
az network private-dns link vnet list \
  -g {resource_group} \
  -z {zone_name}

# List all VNets in subscription
az network vnet list --subscription {subscription_id}
```

#### Azure SDK Equivalent:
```python
from azure.mgmt.privatedns import PrivateDnsManagementClient
from azure.mgmt.network import NetworkManagementClient

# Private DNS client
privatedns_client = PrivateDnsManagementClient(credential, subscription_id)

# List private DNS zones
zones = list(privatedns_client.private_zones.list_by_resource_group(resource_group))

# List VNet links for a zone
links = list(privatedns_client.virtual_network_links.list(
    resource_group, zone_name
))

# List all VNets in subscription
network_client = NetworkManagementClient(credential, subscription_id)
vnets = list(network_client.virtual_networks.list_all())
```

#### Required Package:
- `azure-mgmt-privatedns`
- `azure-mgmt-network` (already included)

#### Files to Update:
- `misconfiguration_analyzer.py` (lines 217, 249, 293, 338, 360)
- `dns_analyzer.py` (line 145)

---

## Refactoring Strategy

### Phase 1: Create Azure SDK Client Wrapper

**Goal:** Replace `AzureCLIExecutor` with `AzureSDKClient`

**New File:** `aks_diagnostics/azure_sdk_client.py`

```python
"""
Azure SDK client wrapper for AKS Network Diagnostics
"""

from typing import Any, Dict, List, Optional
from azure.identity import DefaultAzureCredential
from azure.mgmt.containerservice import ContainerServiceClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.privatedns import PrivateDnsManagementClient
from .cache import CacheManager

class AzureSDKClient:
    """Wrapper for Azure SDK clients with caching"""
    
    def __init__(self, subscription_id: str, cache_manager: Optional[CacheManager] = None):
        self.subscription_id = subscription_id
        self.cache_manager = cache_manager
        self.credential = DefaultAzureCredential()
        
        # Initialize clients
        self.aks_client = ContainerServiceClient(self.credential, subscription_id)
        self.network_client = NetworkManagementClient(self.credential, subscription_id)
        self.compute_client = ComputeManagementClient(self.credential, subscription_id)
        self.privatedns_client = PrivateDnsManagementClient(self.credential, subscription_id)
    
    # AKS Operations
    def get_cluster(self, resource_group: str, cluster_name: str) -> Any:
        """Get AKS cluster details"""
        cache_key = f"cluster:{resource_group}:{cluster_name}"
        if self.cache_manager:
            cached = self.cache_manager.get(cache_key)
            if cached:
                return cached
        
        cluster = self.aks_client.managed_clusters.get(resource_group, cluster_name)
        
        if self.cache_manager:
            self.cache_manager.set(cache_key, cluster)
        
        return cluster
    
    def list_agent_pools(self, resource_group: str, cluster_name: str) -> List[Any]:
        """List AKS agent pools"""
        # Implementation here
        pass
    
    # Network Operations
    def get_vnet(self, resource_group: str, vnet_name: str) -> Any:
        """Get virtual network details"""
        pass
    
    # ... more methods ...
```

### Phase 2: Update Data Collectors

**Files to Modify:**
1. `cluster_data_collector.py`
2. `outbound_analyzer.py`
3. `nsg_analyzer.py`
4. `route_table_analyzer.py`
5. `dns_analyzer.py`
6. `misconfiguration_analyzer.py`
7. `connectivity_tester.py`

**Pattern:**
- Replace `azure_cli_executor.execute([...])` with SDK client method calls
- Convert string parsing to object property access
- Handle Azure SDK exceptions instead of subprocess errors

### Phase 3: Update Exception Handling

**Current Exceptions:**
- `AzureCLIError`
- `AzureAuthenticationError`

**New Exceptions:**
```python
from azure.core.exceptions import (
    AzureError,
    ResourceNotFoundError,
    HttpResponseError
)
```

### Phase 4: Update Tests

**Test Changes:**
- Mock Azure SDK clients instead of subprocess
- Update test fixtures to use SDK response objects
- Verify all 147 tests pass

---

## Required Azure SDK Packages

Add to `requirements.txt`:

```txt
# Azure SDK packages
azure-identity>=1.15.0
azure-mgmt-containerservice>=29.0.0
azure-mgmt-network>=25.0.0
azure-mgmt-compute>=30.0.0
azure-mgmt-privatedns>=1.1.0
azure-mgmt-resource>=23.0.0
```

---

## Migration Checklist

### Pre-Migration
- [x] Create `azure-cli-refactor` branch
- [ ] Document all Azure CLI commands
- [ ] Identify Azure SDK equivalents
- [ ] Review Azure CLI extension integration requirements

### Implementation
- [ ] Create `AzureSDKClient` wrapper class
- [ ] Migrate `cluster_data_collector.py`
- [ ] Migrate `outbound_analyzer.py`
- [ ] Migrate `nsg_analyzer.py`
- [ ] Migrate `route_table_analyzer.py`
- [ ] Migrate `dns_analyzer.py`
- [ ] Migrate `misconfiguration_analyzer.py`
- [ ] Migrate `connectivity_tester.py`
- [ ] Update main script
- [ ] Update exception handling

### Testing
- [ ] Update unit tests
- [ ] Run full test suite (147 tests)
- [ ] Test with real AKS clusters
- [ ] Test all outbound types (LoadBalancer, NAT Gateway, UDR)
- [ ] Test private vs public clusters
- [ ] Test connectivity probes

### Documentation
- [ ] Update ARCHITECTURE.md
- [ ] Update CONTRIBUTING.md
- [ ] Update README.md (if needed)
- [ ] Add Azure SDK integration notes

### Integration with Azure CLI
- [ ] Fork azure-cli repository
- [ ] Create extension structure
- [ ] Integrate refactored code
- [ ] Test as `az aks net-diagnostics`
- [ ] Submit PR to Azure CLI

---

## Key Considerations

### 1. Authentication
- **Current:** Uses `az login` authentication via subprocess
- **SDK:** Uses `DefaultAzureCredential` which supports:
  - Environment variables
  - Managed Identity
  - Azure CLI credential (fallback)
  - Interactive browser
  - Service Principal

### 2. Resource ID Parsing
Many operations require parsing Azure Resource IDs:
```
/subscriptions/{sub}/resourceGroups/{rg}/providers/{provider}/{type}/{name}
```

Create utility function:
```python
def parse_resource_id(resource_id: str) -> Dict[str, str]:
    """Parse Azure resource ID into components"""
    parts = resource_id.split('/')
    return {
        'subscription_id': parts[2],
        'resource_group': parts[4],
        'provider': parts[6],
        'resource_type': parts[7],
        'resource_name': parts[8]
    }
```

### 3. Async Operations
Some SDK operations are async (e.g., VMSS run-command):
- Use `.begin_*()` methods
- Call `.result(timeout=...)` to wait
- Handle long-running operations

### 4. Cross-Subscription Operations
The tool may need to access resources in different subscriptions:
- Create separate clients per subscription
- Parse resource IDs to determine subscription
- Cache clients by subscription ID

### 5. Error Handling
Replace subprocess error handling with SDK exceptions:
```python
try:
    cluster = aks_client.managed_clusters.get(rg, name)
except ResourceNotFoundError:
    raise ValueError(f"Cluster {name} not found in {rg}")
except HttpResponseError as e:
    raise AzureSDKError(f"Failed to get cluster: {e.message}")
```

---

## Testing Strategy

### Unit Tests
- Mock all SDK clients
- Use `unittest.mock` to mock client methods
- Verify correct parameters passed to SDK

### Integration Tests
- Test against real Azure resources
- Use dedicated test resource groups
- Clean up resources after tests

### Compatibility Tests
- Ensure output format remains identical
- Verify all findings codes work
- Check JSON report structure unchanged

---

## Benefits of Azure SDK Migration

1. **Performance:** Direct API calls, no subprocess overhead
2. **Type Safety:** Strong typing with Python type hints
3. **Better Error Handling:** Structured exceptions vs. string parsing
4. **Official Support:** Microsoft-maintained packages
5. **Azure CLI Integration:** Native integration as subcommand
6. **Async Support:** Better handling of long operations
7. **Authentication Flexibility:** Multiple auth methods
8. **Reduced Dependencies:** No need for Azure CLI binary

---

## Risks & Mitigation

| Risk | Impact | Mitigation |
|------|--------|------------|
| API behavior differences | Incorrect analysis | Extensive testing against real clusters |
| SDK version compatibility | Breaking changes | Pin SDK versions, test across versions |
| Async operation handling | Timeout issues | Implement proper timeout handling |
| Resource ID parsing errors | Failed operations | Robust parsing with error handling |
| Authentication issues | Tool won't work | Fallback to multiple auth methods |
| Performance regression | Slower execution | Implement caching, async operations |

---

## Timeline Estimate

| Phase | Effort | Duration |
|-------|--------|----------|
| Planning & Design | Small | 1-2 days |
| SDK Client Wrapper | Medium | 2-3 days |
| Migrate Data Collectors | Large | 5-7 days |
| Update Tests | Medium | 3-4 days |
| Integration Testing | Medium | 2-3 days |
| Documentation | Small | 1-2 days |
| **Total** | | **14-21 days** |

---

## Next Steps

1. **Review this document** with stakeholders
2. **Prototype** `AzureSDKClient` wrapper
3. **Migrate one module** as proof of concept (suggest `cluster_data_collector.py`)
4. **Test thoroughly** before proceeding
5. **Iterate** on remaining modules
6. **Fork Azure CLI** repository when ready

---

## Questions to Resolve

1. Should we maintain backward compatibility with Azure CLI execution?
2. What authentication methods must be supported for Azure CLI integration?
3. Are there Azure CLI specific APIs we need to use?
4. What's the Azure CLI extension development workflow?
5. Do we need to support offline/disconnected scenarios?

---

**Document Version:** 1.0  
**Last Updated:** October 15, 2025  
**Author:** Azure SDK Refactoring Team
