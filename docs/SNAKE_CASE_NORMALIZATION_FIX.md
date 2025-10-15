# Snake Case to CamelCase Normalization Fix

## Issue Summary

**Problem**: Azure SDK returns Python objects with `snake_case` attributes (e.g., `node_resource_group`, `ip_address`), but the rest of the codebase expects `camelCase` format (e.g., `nodeResourceGroup`, `ipAddress`) which matches Azure CLI JSON output.

**Impact**: Without normalization, the tool couldn't find critical data like:
- Node resource group (`nodeResourceGroup`)
- Outbound IPs (`ipAddress`)
- VMSS configuration (`virtualMachineProfile`)
- NSG rules (`securityRules`, `defaultSecurityRules`)
- Route table info (`routeTable`)
- And many more fields

## Root Cause

Azure Python SDK uses Python naming conventions (snake_case) while Azure CLI JSON uses Azure Resource Manager conventions (camelCase). When calling `.as_dict()` on SDK objects, the resulting dictionaries have snake_case keys.

## Solution

Created a `normalize_dict_keys()` function in `azure_sdk_client.py` that recursively converts all dictionary keys from snake_case to camelCase.

### Implementation

```python
def normalize_dict_keys(obj: Any) -> Any:
    """
    Recursively normalize dictionary keys from snake_case to camelCase.
    
    Azure SDK returns objects with snake_case attributes when serialized with as_dict(),
    but Azure CLI returns JSON with camelCase keys. This function normalizes SDK output
    to match Azure CLI format for compatibility with existing code.
    """
    if isinstance(obj, dict):
        return {snake_to_camel(k): normalize_dict_keys(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [normalize_dict_keys(item) for item in obj]
    else:
        return obj

def snake_to_camel(snake_str: str) -> str:
    """Convert snake_case string to camelCase"""
    if '_' not in snake_str:
        return snake_str
    components = snake_str.split('_')
    return components[0] + ''.join(x.title() for x in components[1:])
```

## Files Modified

### 1. `aks_diagnostics/azure_sdk_client.py`
- ✅ Added `normalize_dict_keys()` function
- ✅ Added `snake_to_camel()` helper function
- ✅ Exported both functions for use in other modules

### 2. `aks_diagnostics/cluster_data_collector.py`
- ✅ Line 55: `cluster.as_dict()` → `normalize_dict_keys(cluster.as_dict())`
- ✅ Line 80: Agent pools normalization
- ✅ Line 208: VMSS details normalization

### 3. `aks_diagnostics/outbound_analyzer.py`
- ✅ Line 452: Public IP normalization
- ✅ Line 495: Public IP prefix normalization
- ✅ Line 107: Fixed `self.azure_cli` → `self.sdk_client`

### 4. `aks_diagnostics/nsg_analyzer.py`
- ✅ Line 198: Subnet NSG details normalization
- ✅ Line 248: NIC NSG details normalization
- ✅ Line 256: Fixed `nsg_details.get()` → `nsg_dict.get()` (typo bug)

### 5. `aks_diagnostics/route_table_analyzer.py`
- ✅ Line 147: Subnet details normalization
- ✅ Line 189: Route table normalization

### 6. `aks_diagnostics/misconfiguration_analyzer.py`
- ✅ Line 236: DNS zone normalization

### 7. `aks_diagnostics/connectivity_tester.py`
- ✅ Line 369: VMSS run command response normalization

### 8. `aks-net-diagnostics.py`
- ✅ Line 261: Fixed `azure_cli=` → `azure_sdk_client=`
- ✅ Line 285: Fixed `azure_cli=` → `azure_sdk_client=`
- ✅ Line 328: Fixed `azure_cli=` → `azure_sdk_client=`

## Testing Results

### Unit Tests
- ✅ **147/147 tests passing** (100%)
- All existing unit tests continue to pass with normalization

### Integration Tests
- ✅ **Scenario 1: Public Cluster** (aks-overlay)
  - Cluster data collected correctly
  - Node resource group found: `MC_aks-overlay-rg_aks-overlay_canadacentral`
  - Outbound IP detected: `130.107.45.124`
  - VMSS configuration analyzed
  - NSG rules detected and analyzed
  - Route tables found and processed
  - JSON report generated successfully

### Before vs After

**Before (broken):**
```
No node resource group found
No outbound IPs detected
Power State: Unknown
Network Plugin: kubenet (incorrect)
No NSGs found on cluster node subnets or NICs
```

**After (working):**
```
Node Resource Group: MC_aks-overlay-rg_aks-overlay_canadacentral
Found outbound IP: 130.107.45.124
Power State: Running
Network Plugin: azure
Found NSG on subnet default: aks-overlay-rg-vnet-default-nsg-canadacentral
Found NSG on VMSS aks-agentpool-41785413-vmss NIC: aks-agentpool-17863964-nsg
```

## Additional Bugs Fixed

1. **Parameter name mismatch**: `azure_cli` → `azure_sdk_client` in 3 locations
2. **Attribute reference bug**: `self.azure_cli` → `self.sdk_client` in outbound_analyzer.py
3. **Object vs dict bug**: `nsg_details.get()` → `nsg_dict.get()` in nsg_analyzer.py

## Coverage Verification

Verified **ALL** `.as_dict()` calls in the codebase now use `normalize_dict_keys()`:

```bash
# Search pattern: as_dict() calls
grep -r "\.as_dict()" aks_diagnostics/

# Results: 11 unique locations, all wrapped with normalize_dict_keys()
```

## UDR Override Detection

**Confirmed working**: The tool correctly handles scenarios where cluster outbound type is "loadBalancer" but UDRs force traffic through a different path (e.g., Azure Firewall).

Logic flow:
1. Detects configured outbound type (loadBalancer)
2. Finds Load Balancer public IPs
3. **Always checks for UDRs** on node subnets
4. Detects if 0.0.0.0/0 route points to virtual appliance
5. Warns that Load Balancer IPs are not effective
6. Reports true egress path

## Recommendations

1. **Always normalize SDK output**: Any new code that calls `.as_dict()` must wrap with `normalize_dict_keys()`
2. **Naming consistency**: Parameter names should use `azure_sdk_client` not `azure_cli`
3. **Integration testing**: Essential for catching issues that unit tests miss
4. **Documentation**: Update all examples to show normalization pattern

## Migration Complete

With these fixes:
- ✅ All modules migrated from Azure CLI to Azure SDK
- ✅ All 147 unit tests passing
- ✅ Integration testing successful with real clusters
- ✅ Output format identical to Azure CLI version (camelCase)
- ✅ UDR override detection working correctly
- ✅ Ready for Azure CLI integration (`az aks net-diagnostics`)
