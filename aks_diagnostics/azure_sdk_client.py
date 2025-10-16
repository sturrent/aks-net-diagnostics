"""
Azure SDK client wrapper for AKS Network Diagnostics.

This module provides a thin wrapper around Azure SDK clients following the
Azure CLI pattern: lazy initialization, property-based access, minimal abstraction.

Pattern inspired by Azure CLI's client factory approach in:
- src/azure-cli/azure/cli/command_modules/acs/_client_factory.py
- src/azure-cli-core/azure/cli/core/commands/client_factory.py
"""

from typing import Any, Dict, Optional
from azure.identity import DefaultAzureCredential
from azure.mgmt.containerservice import ContainerServiceClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.privatedns import PrivateDnsManagementClient
from azure.core.exceptions import ResourceNotFoundError, HttpResponseError


def _snake_to_camel(snake_str: str) -> str:
    """Convert snake_case to camelCase."""
    components = snake_str.split('_')
    return components[0] + ''.join(x.title() for x in components[1:])


def normalize_dict_keys(data: Any) -> Any:
    """
    Recursively convert dictionary keys from snake_case to camelCase.
    
    Azure SDK returns objects with snake_case attributes when serialized with as_dict(),
    but the existing codebase expects camelCase (Azure CLI JSON format).
    
    Args:
        data: Dictionary, list, or primitive value to normalize
        
    Returns:
        Data with normalized keys (camelCase)
    """
    if isinstance(data, dict):
        return {_snake_to_camel(k): normalize_dict_keys(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [normalize_dict_keys(item) for item in data]
    else:
        return data


class AzureSDKError(Exception):
    """Base exception for Azure SDK operations"""
    pass


class AzureSDKClient:
    """
    Thin wrapper for Azure SDK clients.
    
    Design Philosophy:
    - Lazy initialization: Create clients only when needed
    - Property-based access: Use @property decorators (Azure CLI pattern)
    - Minimal abstraction: Expose SDK clients directly for most operations
    - Selective helpers: Only add methods for frequently used operations
    
    Usage:
        # Create client
        sdk_client = AzureSDKClient(subscription_id)
        
        # Direct SDK access
        cluster = sdk_client.aks_client.managed_clusters.get(rg, name)
        vnet = sdk_client.network_client.virtual_networks.get(rg, vnet_name)
        
        # Helper methods for common operations
        cluster = sdk_client.get_cluster(rg, name)
    """
    
    def __init__(self, subscription_id: str):
        """
        Initialize Azure SDK client wrapper.
        
        Args:
            subscription_id: Azure subscription ID
        """
        self.subscription_id = subscription_id
        
        # Use DefaultAzureCredential (same as Azure CLI)
        # Supports: Environment vars, Managed Identity, Azure CLI, Interactive, Service Principal
        self.credential = DefaultAzureCredential()
        
        # Lazy initialization - clients created on first access
        self._aks_client = None
        self._network_client = None
        self._compute_client = None
        self._privatedns_client = None
    
    @property
    def aks_client(self) -> ContainerServiceClient:
        """
        Get or create ContainerServiceClient (for AKS operations).
        
        Lazy initialization pattern from Azure CLI.
        
        Returns:
            ContainerServiceClient instance
        """
        if not self._aks_client:
            self._aks_client = ContainerServiceClient(
                self.credential,
                self.subscription_id
            )
        return self._aks_client
    
    @property
    def network_client(self) -> NetworkManagementClient:
        """
        Get or create NetworkManagementClient (for VNet, NSG, LB, NAT operations).
        
        Lazy initialization pattern from Azure CLI.
        
        Returns:
            NetworkManagementClient instance
        """
        if not self._network_client:
            self._network_client = NetworkManagementClient(
                self.credential,
                self.subscription_id
            )
        return self._network_client
    
    @property
    def compute_client(self) -> ComputeManagementClient:
        """
        Get or create ComputeManagementClient (for VMSS operations).
        
        Lazy initialization pattern from Azure CLI.
        
        Returns:
            ComputeManagementClient instance
        """
        if not self._compute_client:
            self._compute_client = ComputeManagementClient(
                self.credential,
                self.subscription_id
            )
        return self._compute_client
    
    @property
    def privatedns_client(self) -> PrivateDnsManagementClient:
        """
        Get or create PrivateDnsManagementClient (for Private DNS operations).
        
        Lazy initialization pattern from Azure CLI.
        
        Returns:
            PrivateDnsManagementClient instance
        """
        if not self._privatedns_client:
            self._privatedns_client = PrivateDnsManagementClient(
                self.credential,
                self.subscription_id
            )
        return self._privatedns_client
    
    # Helper methods with caching (selective - only for frequently accessed resources)
    
    def get_cluster(self, resource_group: str, cluster_name: str) -> Any:
        """
        Get AKS cluster details with caching.
        
        Equivalent to: az aks show -g {rg} -n {name}
        
        Args:
            resource_group: Resource group name
            cluster_name: AKS cluster name
            
        Returns:
            ManagedCluster object
            
        Raises:
            AzureSDKError: If cluster not found or API call fails
        """
        try:
            # Direct SDK call
            cluster = self.aks_client.managed_clusters.get(resource_group, cluster_name)
            return cluster
            
        except ResourceNotFoundError:
            raise AzureSDKError(
                f"Cluster '{cluster_name}' not found in resource group '{resource_group}'"
            )
        except HttpResponseError as e:
            raise AzureSDKError(
                f"Failed to get cluster '{cluster_name}': {e.message}"
            )
    
    @staticmethod
    def parse_resource_id(resource_id: str) -> Dict[str, str]:
        """
        Parse Azure resource ID into components.
        
        Azure resource IDs follow this format:
        /subscriptions/{sub}/resourceGroups/{rg}/providers/{provider}/{type}/{name}
        
        For nested resources:
        /subscriptions/{sub}/resourceGroups/{rg}/providers/{provider}/{type}/{parent}/{subtype}/{name}
        
        Args:
            resource_id: Full Azure resource ID
            
        Returns:
            Dictionary with parsed components:
            - subscription_id
            - resource_group
            - provider
            - resource_type
            - resource_name
            - parent_name (optional, for nested resources)
            - sub_resource_type (optional, for nested resources)
            
        Raises:
            ValueError: If resource ID format is invalid
            
        Examples:
            # VNet
            /subscriptions/123/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet
            
            # Subnet (nested)
            /subscriptions/123/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/subnet
        """
        if not resource_id or not resource_id.startswith('/subscriptions/'):
            raise ValueError(f"Invalid resource ID format: {resource_id}")
        
        parts = resource_id.split('/')
        
        if len(parts) < 9:
            raise ValueError(f"Resource ID has insufficient parts: {resource_id}")
        
        result = {
            'subscription_id': parts[2],
            'resource_group': parts[4],
            'provider': parts[6],
            'resource_type': parts[7],
            'resource_name': parts[8]
        }
        
        # Handle nested resources (e.g., VNet subnets, LB frontend IPs)
        if len(parts) > 9:
            result['parent_name'] = parts[8]
            if len(parts) >= 11:
                result['sub_resource_type'] = parts[9]
                result['resource_name'] = parts[10]
        
        return result
    
    def close(self):
        """
        Close all SDK clients and clean up resources.
        
        Call this when done with the client to ensure proper cleanup.
        """
        # SDK clients handle their own cleanup, but we can explicitly close them
        if self._aks_client:
            self._aks_client.close()
            self._aks_client = None
        
        if self._network_client:
            self._network_client.close()
            self._network_client = None
        
        if self._compute_client:
            self._compute_client.close()
            self._compute_client = None
        
        if self._privatedns_client:
            self._privatedns_client.close()
            self._privatedns_client = None
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - ensure cleanup"""
        self.close()
