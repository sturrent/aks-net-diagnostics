# Azure CLI Architecture - How Commands Work

## Summary of Findings

After reviewing the Azure CLI source code, here's how `az aks` commands are implemented:

## ✅ **YES, Azure CLI Uses Azure SDK for Python!**

Azure CLI commands **do NOT execute subprocess calls to `az` commands**. Instead, they:

1. **Use Azure SDK for Python directly** via management clients
2. **Wrap SDK clients** in factory functions
3. **Call SDK methods** directly from command implementations

---

## Architecture Pattern

### 1. Client Factories (`_client_factory.py`)

Client factories create and return Azure SDK management clients:

```python
# From: src/azure-cli/azure/cli/command_modules/acs/_client_factory.py

from azure.cli.core.commands.client_factory import get_mgmt_service_client
from azure.cli.core.profiles import ResourceType

def get_container_service_client(cli_ctx, subscription_id=None):
    """Returns ContainerServiceClient from Azure SDK"""
    return get_mgmt_service_client(
        cli_ctx, 
        ResourceType.MGMT_CONTAINERSERVICE, 
        subscription_id=subscription_id
    )

def cf_managed_clusters(cli_ctx, *_):
    """Returns the managed_clusters operation group"""
    return get_container_service_client(cli_ctx).managed_clusters

def cf_agent_pools(cli_ctx, *_):
    """Returns the agent_pools operation group"""
    return get_container_service_client(cli_ctx).agent_pools
```

**Key Insight**: `get_mgmt_service_client()` is a core Azure CLI utility that:
- Handles authentication (DefaultAzureCredential)
- Manages subscriptions
- Handles API versioning
- Adds telemetry and logging
- Supports cross-tenant authentication

---

### 2. Command Registration (`commands.py`)

Commands are registered with SDK operation groups:

```python
# From: src/azure-cli/azure/cli/command_modules/acs/commands.py

managed_clusters_sdk = CliCommandType(
    operations_tmpl='azure.mgmt.containerservice.operations.'
                    '_managed_clusters_operations#ManagedClustersOperations.{}',
    operation_group='managed_clusters',
    resource_type=ResourceType.MGMT_CONTAINERSERVICE,
    client_factory=cf_managed_clusters  # <-- Links to factory
)

with self.command_group('aks', managed_clusters_sdk, 
                       client_factory=cf_managed_clusters) as g:
    g.custom_command('create', 'aks_create', supports_no_wait=True)
    g.custom_command('update', 'aks_update', supports_no_wait=True)
    g.command('show', 'get')  # <-- Directly maps to SDK's .get()
    g.custom_show_command('show', 'aks_show')
    g.command('delete', 'begin_delete', supports_no_wait=True)
```

---

### 3. Command Implementation (`custom.py`)

Custom commands receive the SDK client and call methods directly:

```python
# From: src/azure-cli/azure/cli/command_modules/acs/custom.py

def aks_show(cmd, client, resource_group_name, name):
    """
    Args:
        cmd: Command context
        client: ManagedClustersOperations from Azure SDK
        resource_group_name: RG name
        name: Cluster name
    """
    # Direct SDK call - no subprocess!
    mc = client.get(resource_group_name, name)
    return _remove_nulls([mc])[0]

def aks_create(cmd, client, resource_group_name, name, **kwargs):
    """
    Creates AKS cluster using Azure SDK
    """
    # Build ManagedCluster object using SDK models
    decorator = AKSCreateDecorator(cmd, client, kwargs)
    mc = decorator.construct_default_mc_profile()
    
    # Send request via SDK client (not subprocess)
    return decorator.create_mc(mc)  # Calls client.begin_create_or_update()
```

**Example from real implementation**:
```python
# From servicefabric managed clusters
def create_cluster(cmd, client, resource_group_name, cluster_name, **kwargs):
    # Create SDK model
    new_cluster = ManagedCluster(
        location=location,
        sku=skuObj,
        admin_user_name=admin_user_name,
        admin_password=admin_password,
        # ... more properties
    )
    
    # Direct SDK call via LongRunningOperation wrapper
    poller = client.managed_clusters.begin_create_or_update(
        resource_group_name, cluster_name, new_cluster
    )
    cluster = LongRunningOperation(cmd.cli_ctx)(poller)
    return cluster
```

---

## How `get_mgmt_service_client()` Works

This is the **core utility** that Azure CLI uses (from `azure-cli-core`):

```python
# From: src/azure-cli-core/azure/cli/core/commands/client_factory.py

def get_mgmt_service_client(cli_ctx, client_or_resource_type, 
                           subscription_id=None, api_version=None,
                           aux_subscriptions=None, aux_tenants=None, 
                           credential=None, **kwargs):
    """
    Create Python SDK mgmt-plane client with features:
    - Multi-API support
    - Server telemetry
    - Safe logging
    - Cross-tenant authentication
    
    Args:
        cli_ctx: AzCli instance (provides auth context)
        client_or_resource_type: SDK client class or ResourceType enum
        subscription_id: Override current subscription
        api_version: Override default API version
        credential: Custom credential (defaults to DefaultAzureCredential)
    """
    # Implementation creates SDK client with CLI auth context
    # Returns fully configured management client
```

---

## What This Means for Our Refactoring

### ✅ **Our Approach is Correct**

We're following the **exact same pattern** that Azure CLI uses internally:

| Our Current Code | Azure CLI Pattern | What We Need To Do |
|-----------------|-------------------|-------------------|
| `AzureCLIExecutor` (subprocess) | `get_mgmt_service_client()` | Replace with SDK clients |
| `azure_cli.execute(['aks', 'show', ...])` | `client.managed_clusters.get(rg, name)` | Call SDK methods directly |
| JSON parsing from stdout | Native Python objects | Use SDK response objects |
| Caching in CacheManager | Same caching patterns | Keep our cache manager |

### 🎯 **Key Simplifications**

1. **No subprocess overhead** - Direct Python SDK calls
2. **No JSON parsing** - Get Python objects directly
3. **Better error handling** - SDK exceptions instead of parsing stderr
4. **Type safety** - SDK provides type hints
5. **Same auth pattern** - DefaultAzureCredential (what Azure CLI uses)

---

## Concrete Examples from Azure CLI

### Example 1: `az aks show`

```python
# What happens when you run: az aks show -g rg -n cluster

# 1. Command routing (commands.py)
g.custom_show_command('show', 'aks_show')

# 2. Custom implementation (custom.py)  
def aks_show(cmd, client, resource_group_name, name):
    mc = client.get(resource_group_name, name)  # SDK call!
    return _remove_nulls([mc])[0]

# 3. Client is ManagedClustersOperations from:
from azure.mgmt.containerservice import ContainerServiceClient
client = ContainerServiceClient(credential, subscription_id).managed_clusters
```

### Example 2: `az aks nodepool list`

```python
# What happens when you run: az aks nodepool list -g rg --cluster-name cluster

# 1. Command routing
agent_pools_sdk = CliCommandType(
    operations_tmpl='azure.mgmt.containerservice.operations.'
                    '_agent_pools_operations#AgentPoolsOperations.{}',
    client_factory=cf_agent_pools
)

# 2. Direct SDK mapping
g.command('list', 'list')  # Maps to AgentPoolsOperations.list()

# 3. SDK call
from azure.mgmt.containerservice import ContainerServiceClient
client = ContainerServiceClient(credential, subscription_id)
nodepools = client.agent_pools.list(resource_group_name, cluster_name)
```

### Example 3: `az vmss run-command invoke`

```python
# From connectivity tests - this is the ASYNC operation we need

# Azure CLI does this:
from azure.mgmt.compute import ComputeManagementClient
compute_client = ComputeManagementClient(credential, subscription_id)

# Async operation
poller = compute_client.virtual_machine_scale_sets.begin_run_command(
    resource_group_name=mc_rg,
    vm_scale_set_name=vmss_name,
    parameters=run_command_input
)

# Wait for completion
result = poller.result(timeout=300)
```

---

## Updated Refactoring Strategy

### Phase 1: Create Azure SDK Client Wrapper ✅ SIMPLIFIED

Instead of creating complex wrappers, we can use Azure CLI's pattern:

```python
# aks_diagnostics/azure_sdk_client.py

from azure.identity import DefaultAzureCredential
from azure.mgmt.containerservice import ContainerServiceClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.privatedns import PrivateDnsManagementClient

class AzureSDKClient:
    """Replaces AzureCLIExecutor with direct SDK calls"""
    
    def __init__(self, subscription_id=None, cache_manager=None):
        self.credential = DefaultAzureCredential()
        
        # Lazy initialization of clients
        self._subscription_id = subscription_id
        self._cache = cache_manager
        self._aks_client = None
        self._network_client = None
        self._compute_client = None
        self._privatedns_client = None
    
    @property
    def aks_client(self):
        if not self._aks_client:
            self._aks_client = ContainerServiceClient(
                self.credential, 
                self._subscription_id
            )
        return self._aks_client
    
    @property
    def network_client(self):
        if not self._network_client:
            self._network_client = NetworkManagementClient(
                self.credential,
                self._subscription_id
            )
        return self._network_client
    
    # ... similar for compute_client, privatedns_client
    
    def get_cluster(self, resource_group, name):
        """Equivalent to: az aks show -g rg -n name"""
        cache_key = f"cluster_{resource_group}_{name}"
        if self._cache and self._cache.has(cache_key):
            return self._cache.get(cache_key)
        
        cluster = self.aks_client.managed_clusters.get(resource_group, name)
        
        if self._cache:
            self._cache.set(cache_key, cluster)
        return cluster
```

### Phase 2: Migration is Much Simpler

**Old way (subprocess)**:
```python
cluster_result = self.azure_cli.execute(['aks', 'show', '-n', name, '-g', rg])
cluster_id = cluster_result['id']
node_rg = cluster_result['nodeResourceGroup']
```

**New way (SDK)**:
```python
cluster = self.sdk_client.get_cluster(rg, name)
cluster_id = cluster.id
node_rg = cluster.node_resource_group
```

---

## Benefits of This Approach

1. **✅ Proven Pattern** - This is how Azure CLI itself works
2. **✅ No Subprocess** - Direct Python SDK calls
3. **✅ Better Performance** - No process spawning overhead
4. **✅ Type Safety** - SDK provides IntelliSense and type hints
5. **✅ Better Errors** - SDK exceptions vs parsing stderr
6. **✅ Easier Testing** - Mock SDK clients (like Azure CLI tests do)
7. **✅ Compatible** - Can integrate into Azure CLI directly

---

## Key Files to Reference in Azure CLI Repo

| File | Purpose | What to Learn |
|------|---------|---------------|
| `src/azure-cli/azure/cli/command_modules/acs/_client_factory.py` | Client creation | How to create SDK clients |
| `src/azure-cli/azure/cli/command_modules/acs/commands.py` | Command registration | How commands map to SDK operations |
| `src/azure-cli/azure/cli/command_modules/acs/custom.py` | Command implementation | How to call SDK methods |
| `src/azure-cli-core/azure/cli/core/commands/client_factory.py` | Core client factory | `get_mgmt_service_client()` pattern |

---

## Questions Answered

### Q: Does Azure CLI use subprocess to call `az` commands?
**A**: ❌ **NO** - It uses Azure SDK for Python directly

### Q: How does Azure CLI authenticate?
**A**: Uses `DefaultAzureCredential` from `azure-identity`, same as we plan to use

### Q: How does Azure CLI handle async operations (like run-command)?
**A**: Uses `.begin_*()` methods that return pollers, then calls `.result(timeout=X)`

### Q: Do we need to create complex wrapper classes?
**A**: Not really - We can follow Azure CLI's pattern of thin wrappers around SDK clients

### Q: Will our refactored code work as an Azure CLI extension?
**A**: ✅ **YES** - We'll be using the exact same SDK clients that Azure CLI uses

---

## Next Steps

1. ✅ **No need to change the refactoring plan significantly**
2. ✅ **Our SDK approach is validated** - it's what Azure CLI does
3. ✅ **Simplify AzureSDKClient** - Don't over-engineer, follow Azure CLI's pattern
4. ✅ **Can reference Azure CLI code** - for async operations, error handling, etc.

The good news: **Our refactoring plan is architecturally sound!** We're essentially doing what Azure CLI already does internally.
