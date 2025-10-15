# Test Migration Guide: Azure CLI → Azure SDK

This guide documents the patterns for updating unit tests from Azure CLI subprocess mocks to Azure SDK mocks.

## Overview

All production code has been migrated from `AzureCLIExecutor` (subprocess calls) to `AzureSDKClient` (Azure SDK for Python). Unit tests need to be updated to mock SDK methods instead of CLI commands.

## Migration Status

- ✅ **test_cluster_data_collector.py** - 14/14 tests passing
- ⏳ **test_nsg_analyzer.py** - Needs update
- ⏳ **test_route_table_analyzer.py** - Needs update
- ⏳ **test_dns_analyzer.py** - Needs update
- ⏳ **test_connectivity_tester.py** - Needs update

## Core Migration Patterns

### 1. Import Changes

**Before:**
```python
from aks_diagnostics.exceptions import AzureCLIError
```

**After:**
```python
from azure.core.exceptions import ResourceNotFoundError, HttpResponseError
```

### 2. Setup Method Updates

**Before:**
```python
def setUp(self):
    self.azure_cli = Mock()
    self.analyzer = SomeAnalyzer(self.azure_cli, ...)
```

**After:**
```python
def setUp(self):
    self.sdk_client = Mock()
    self.analyzer = SomeAnalyzer(self.sdk_client, ...)
```

### 3. SDK Object Mocking Pattern

Azure SDK returns objects (not dictionaries). Mock them with properties and `as_dict()` method:

**Example: Mocking AKS Cluster**
```python
# Create mock cluster object
mock_cluster = Mock()
mock_cluster.name = 'test-cluster'
mock_cluster.location = 'eastus'
mock_cluster.provisioning_state = 'Succeeded'

# Add as_dict() for compatibility
mock_cluster.as_dict.return_value = {
    'name': 'test-cluster',
    'location': 'eastus',
    'provisioningState': 'Succeeded'
}

# Setup SDK client mock
self.sdk_client.get_cluster.return_value = mock_cluster
```

### 4. Common SDK Method Mocks

#### AKS Operations
```python
# Get cluster
self.sdk_client.get_cluster.return_value = mock_cluster

# List agent pools
mock_pool1 = Mock()
mock_pool1.as_dict.return_value = {'name': 'pool1', 'count': 3}
self.sdk_client.aks_client.agent_pools.list.return_value = [mock_pool1]
```

#### Network Operations
```python
# Get VNet
mock_vnet = Mock()
mock_vnet.name = 'test-vnet'
mock_vnet.id = '/subscriptions/.../virtualNetworks/test-vnet'
mock_vnet.address_space = Mock()
mock_vnet.address_space.address_prefixes = ['10.0.0.0/16']
self.sdk_client.network_client.virtual_networks.get.return_value = mock_vnet

# Get subnet
mock_subnet = Mock()
mock_subnet.name = 'subnet1'
mock_subnet.network_security_group = Mock()
mock_subnet.network_security_group.id = '/subscriptions/.../networkSecurityGroups/nsg1'
self.sdk_client.network_client.subnets.get.return_value = mock_subnet

# Get NSG
mock_nsg = Mock()
mock_nsg.name = 'nsg1'
mock_security_rule = Mock()
mock_security_rule.name = 'AllowHTTPS'
mock_security_rule.priority = 100
mock_security_rule.direction = 'Outbound'
mock_security_rule.access = 'Allow'
mock_nsg.security_rules = [mock_security_rule]
self.sdk_client.network_client.network_security_groups.get.return_value = mock_nsg

# Parse resource ID
self.sdk_client.parse_resource_id.return_value = {
    'subscription': 'sub-id',
    'resource_group': 'test-rg',
    'resource_name': 'test-vnet'
}
```

#### Compute Operations (VMSS)
```python
# List VMSS
mock_vmss = Mock()
mock_vmss.name = 'aks-nodepool1-vmss'
self.sdk_client.compute_client.virtual_machine_scale_sets.list.return_value = [mock_vmss]

# Get VMSS details
mock_vmss_detail = Mock()
mock_vmss_detail.as_dict.return_value = {
    'name': 'aks-nodepool1-vmss',
    'virtualMachineProfile': {...}
}
self.sdk_client.compute_client.virtual_machine_scale_sets.get.return_value = mock_vmss_detail

# VMSS run-command (async)
mock_async_op = Mock()
mock_result = Mock()
mock_result.as_dict.return_value = {'value': [...]}
mock_async_op.result.return_value = mock_result
self.sdk_client.compute_client.virtual_machine_scale_set_vms.begin_run_command.return_value = mock_async_op
```

### 5. Exception Handling

**Before:**
```python
from aks_diagnostics.exceptions import AzureCLIError

self.azure_cli.execute.side_effect = AzureCLIError("Network error")
```

**After:**
```python
from azure.core.exceptions import ResourceNotFoundError, HttpResponseError

# Resource not found
self.sdk_client.get_cluster.side_effect = ResourceNotFoundError("Cluster not found")

# HTTP error
mock_error = HttpResponseError("Service unavailable")
mock_error.message = "Service unavailable"
self.sdk_client.network_client.subnets.get.side_effect = mock_error
```

### 6. Multiple Return Values (side_effect)

**Before:**
```python
self.azure_cli.execute.side_effect = [
    {'name': 'cluster1'},  # First call
    [{'name': 'pool1'}]    # Second call
]
```

**After:**
```python
# Option 1: Different methods
self.sdk_client.get_cluster.return_value = mock_cluster
self.sdk_client.aks_client.agent_pools.list.return_value = [mock_pool]

# Option 2: Same method, multiple calls
def get_vnet_side_effect(rg, name):
    if name == 'vnet-1':
        return mock_vnet_1
    else:
        return mock_vnet_2

self.sdk_client.network_client.virtual_networks.get.side_effect = get_vnet_side_effect
```

## Complete Test Example

**Before (Azure CLI):**
```python
def test_collect_cluster_info(self):
    mock_cluster = {'name': 'test-cluster', 'location': 'eastus'}
    mock_pools = [{'name': 'pool1', 'count': 3}]
    
    self.azure_cli.execute.side_effect = [mock_cluster, mock_pools]
    
    result = self.collector.collect_cluster_info('test-cluster', 'test-rg')
    
    # Verify CLI commands
    self.assertEqual(self.azure_cli.execute.call_count, 2)
    first_call = self.azure_cli.execute.call_args_list[0]
    self.assertEqual(first_call[0][0], ['aks', 'show', '-n', 'test-cluster', ...])
```

**After (Azure SDK):**
```python
def test_collect_cluster_info(self):
    # Mock cluster object
    mock_cluster = Mock()
    mock_cluster.as_dict.return_value = {
        'name': 'test-cluster',
        'location': 'eastus'
    }
    
    # Mock pool object
    mock_pool = Mock()
    mock_pool.as_dict.return_value = {'name': 'pool1', 'count': 3}
    
    # Setup SDK mocks
    self.sdk_client.get_cluster.return_value = mock_cluster
    self.sdk_client.aks_client.agent_pools.list.return_value = [mock_pool]
    
    result = self.collector.collect_cluster_info('test-cluster', 'test-rg')
    
    # Verify SDK method calls
    self.sdk_client.get_cluster.assert_called_once_with('test-rg', 'test-cluster')
    self.sdk_client.aks_client.agent_pools.list.assert_called_once_with('test-rg', 'test-cluster')
```

## SDK Method Reference

### ClusterDataCollector
- `sdk_client.get_cluster(resource_group, cluster_name)` → ManagedCluster
- `sdk_client.aks_client.agent_pools.list(rg, cluster)` → Iterator[AgentPool]
- `sdk_client.network_client.virtual_networks.get(rg, vnet_name)` → VirtualNetwork
- `sdk_client.network_client.virtual_network_peerings.list(rg, vnet)` → Iterator[Peering]
- `sdk_client.compute_client.virtual_machine_scale_sets.list(rg)` → Iterator[VMSS]
- `sdk_client.compute_client.virtual_machine_scale_sets.get(rg, vmss_name)` → VMSS

### NSGAnalyzer
- `sdk_client.parse_resource_id(resource_id)` → dict
- `sdk_client.network_client.subnets.get(rg, vnet, subnet)` → Subnet
- `sdk_client.network_client.network_security_groups.get(rg, nsg_name)` → NSG

### RouteTableAnalyzer
- `sdk_client.network_client.subnets.get(rg, vnet, subnet)` → Subnet
- `sdk_client.network_client.route_tables.get(rg, route_table)` → RouteTable
- `sdk_client.parse_resource_id(resource_id)` → dict

### DNSAnalyzer
- `sdk_client.network_client.virtual_networks.get(rg, vnet)` → VirtualNetwork
- `sdk_client.parse_resource_id(resource_id)` → dict

### MisconfigurationAnalyzer
- `sdk_client.privatedns_client.private_zones.list(rg)` → Iterator[PrivateZone]
- `sdk_client.privatedns_client.virtual_network_links.list(rg, zone)` → Iterator[VNetLink]
- `sdk_client.network_client.virtual_networks.list_all()` → Iterator[VirtualNetwork]

### ConnectivityTester
- `sdk_client.compute_client.virtual_machine_scale_sets.list(rg)` → Iterator[VMSS]
- `sdk_client.compute_client.virtual_machine_scale_set_vms.list(rg, vmss)` → Iterator[VMSSInstance]
- `sdk_client.compute_client.virtual_machine_scale_set_vms.begin_run_command(...)` → LROPoller

## Quick Migration Checklist

For each test file:

1. ✅ Update imports (add Azure SDK exceptions)
2. ✅ Replace `self.azure_cli` → `self.sdk_client` in setUp()
3. ✅ Replace `AzureCLIError` → `ResourceNotFoundError` or `HttpResponseError`
4. ✅ Replace all `NSGAnalyzer(self.azure_cli, ...)` → `NSGAnalyzer(self.sdk_client, ...)`
5. ✅ Replace `self.azure_cli.execute(...)` with appropriate SDK method mocks
6. ✅ Mock SDK objects with properties and `as_dict()` where needed
7. ✅ Update assertions from CLI command verification to SDK method verification
8. ✅ Run tests: `python -m pytest tests/test_filename.py -v`
9. ✅ Commit when all tests pass

## Running Tests

```bash
# Single test file
python -m pytest tests/test_cluster_data_collector.py -v

# All tests
python -m pytest tests/ -v

# With coverage
python -m pytest tests/ --cov=aks_diagnostics --cov-report=html
```

## Troubleshooting

### "AttributeError: Mock object has no attribute 'as_dict'"
**Solution:** Add `mock_object.as_dict.return_value = {...}` to your mock

### "ResourceNotFoundError not defined"
**Solution:** Import from `azure.core.exceptions`

### "Mock has no attribute 'execute'"
**Solution:** SDK client doesn't have `execute()` - use specific SDK methods like `get_cluster()`, `network_client.subnets.get()`, etc.

### Tests fail with "call not found"
**Solution:** Check you're mocking the right SDK method path (e.g., `network_client.subnets.get` not just `subnets.get`)

## Reference: test_cluster_data_collector.py

See `tests/test_cluster_data_collector.py` for a complete working example with 14 passing tests demonstrating all the patterns above.
