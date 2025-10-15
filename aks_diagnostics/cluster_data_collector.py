"""
Cluster Data Collector for AKS Network Diagnostics

This module handles fetching and collecting cluster-related data from Azure,
including cluster information, agent pools, VNets, and VMSS configurations.

Migrated from Azure CLI subprocess to Azure SDK for Python.
"""

import re
from typing import Dict, List, Any, Optional
import logging
from azure.core.exceptions import ResourceNotFoundError, HttpResponseError


class ClusterDataCollector:
    """Collects cluster information and related Azure resources using Azure SDK."""
    
    def __init__(self, azure_sdk_client, logger: Optional[logging.Logger] = None):
        """
        Initialize ClusterDataCollector.
        
        Args:
            azure_sdk_client: AzureSDKClient instance for Azure SDK operations
            logger: Optional logger instance. If not provided, creates a default logger.
        """
        self.sdk_client = azure_sdk_client
        self.logger = logger or logging.getLogger(__name__)
    
    def collect_cluster_info(self, cluster_name: str, resource_group: str) -> Dict[str, Any]:
        """
        Fetch basic cluster information and agent pools.
        
        Args:
            cluster_name: Name of the AKS cluster
            resource_group: Resource group containing the cluster
            
        Returns:
            Dictionary containing:
                - cluster_info: Cluster configuration details
                - agent_pools: List of node pool configurations
                
        Raises:
            ValueError: If cluster information cannot be retrieved
        """
        self.logger.info("Fetching cluster information...")
        
        try:
            # Get cluster info using SDK (replaces: az aks show)
            cluster = self.sdk_client.get_cluster(resource_group, cluster_name)
            
            # Convert SDK object to dictionary (for compatibility with existing code)
            cluster_result = cluster.as_dict()
            
        except ResourceNotFoundError:
            raise ValueError(
                f"Cluster '{cluster_name}' not found in resource group '{resource_group}'. "
                f"Please check the cluster name and resource group."
            )
        except HttpResponseError as e:
            raise ValueError(
                f"Failed to get cluster information for {cluster_name}: {e.message}"
            )
        
        if not cluster_result or not isinstance(cluster_result, dict):
            raise ValueError(
                f"Failed to get cluster information for {cluster_name}. "
                f"Please check the cluster name and resource group."
            )
        
        try:
            # Get agent pools using SDK (replaces: az aks nodepool list)
            agent_pools_list = list(
                self.sdk_client.aks_client.agent_pools.list(resource_group, cluster_name)
            )
            
            # Convert SDK objects to dictionaries
            agent_pools = [pool.as_dict() for pool in agent_pools_list]
            
        except (ResourceNotFoundError, HttpResponseError) as e:
            self.logger.warning(f"Failed to retrieve agent pools: {e}")
            agent_pools = []
        
        return {
            'cluster_info': cluster_result,
            'agent_pools': agent_pools
        }
    
    def collect_vnet_info(self, agent_pools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Collect VNet configuration from agent pools.
        
        Args:
            agent_pools: List of agent pool configurations
            
        Returns:
            List of VNet analysis results containing VNet details and peerings
        """
        self.logger.info("Analyzing VNet configuration...")
        
        # Get unique subnet IDs from agent pools
        subnet_ids = set()
        for pool in agent_pools:
            subnet_id = pool.get('vnetSubnetId')
            if subnet_id and subnet_id != "null":
                subnet_ids.add(subnet_id)
        
        if not subnet_ids:
            self.logger.info(
                "Agent pools use AKS-managed VNet (vnetSubnetId not set). "
                "VNet details will be retrieved from VMSS configuration."
            )
            return []
        
        # Analyze each VNet
        vnets_map = {}
        for subnet_id in subnet_ids:
            if not subnet_id:
                continue
            
            # Extract VNet info from subnet ID
            vnet_match = re.search(r'/virtualNetworks/([^/]+)', subnet_id)
            if not vnet_match:
                continue
            
            vnet_name = vnet_match.group(1)
            vnet_rg = subnet_id.split('/')[4]  # Resource group is at index 4 in the resource ID
            
            if vnet_name not in vnets_map:
                try:
                    # Get VNet information using SDK (replaces: az network vnet show)
                    vnet = self.sdk_client.network_client.virtual_networks.get(vnet_rg, vnet_name)
                    
                    vnets_map[vnet_name] = {
                        "name": vnet_name,
                        "resourceGroup": vnet_rg,
                        "id": vnet.id,
                        "addressSpace": vnet.address_space.address_prefixes if vnet.address_space else [],
                        "subnets": [],
                        "peerings": []
                    }
                    
                    # Get VNet peerings using SDK (replaces: az network vnet peering list)
                    peerings_list = list(
                        self.sdk_client.network_client.virtual_network_peerings.list(vnet_rg, vnet_name)
                    )
                    
                    for peering in peerings_list:
                        vnets_map[vnet_name]["peerings"].append({
                            "name": peering.name,
                            "remoteVirtualNetwork": peering.remote_virtual_network.id if peering.remote_virtual_network else '',
                            "peeringState": peering.peering_state,
                            "allowVirtualNetworkAccess": peering.allow_virtual_network_access,
                            "allowForwardedTraffic": peering.allow_forwarded_traffic,
                            "allowGatewayTransit": peering.allow_gateway_transit,
                            "useRemoteGateways": peering.use_remote_gateways
                        })
                        
                except (ResourceNotFoundError, HttpResponseError) as e:
                    self.logger.warning(f"Failed to retrieve VNet {vnet_name}: {e}")
                    continue
        
        return list(vnets_map.values())
    
    def collect_vmss_info(self, cluster_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Collect VMSS network configuration from the managed resource group.
        
        Args:
            cluster_info: Cluster configuration dictionary
            
        Returns:
            List of VMSS details with network profiles
        """
        self.logger.info("Analyzing VMSS network configuration...")
        
        mc_rg = cluster_info.get('nodeResourceGroup', '')
        if not mc_rg:
            self.logger.warning("No managed resource group found in cluster info")
            return []
        
        try:
            # List VMSS in the managed resource group using SDK (replaces: az vmss list)
            vmss_list = list(
                self.sdk_client.compute_client.virtual_machine_scale_sets.list(mc_rg)
            )
        except (ResourceNotFoundError, HttpResponseError) as e:
            self.logger.warning(f"Failed to list VMSS in {mc_rg}: {e}")
            return []
        
        vmss_analysis = []
        for vmss in vmss_list:
            vmss_name = vmss.name
            if not vmss_name:
                continue
            
            self.logger.info(f"  - Analyzing VMSS: {vmss_name}")
            
            try:
                # Get VMSS details using SDK (replaces: az vmss show)
                vmss_detail = self.sdk_client.compute_client.virtual_machine_scale_sets.get(
                    mc_rg, vmss_name
                )
                
                # Convert to dictionary for compatibility with existing code
                vmss_detail_dict = vmss_detail.as_dict()
                
                network_profile = vmss_detail_dict.get('virtualMachineProfile', {}).get('networkProfile', {})
                network_interfaces = network_profile.get('networkInterfaceConfigurations', [])
                
                # Collect unique subnets for this VMSS
                unique_subnets = set()
                for nic in network_interfaces:
                    ip_configs = nic.get('ipConfigurations', [])
                    for ip_config in ip_configs:
                        subnet = ip_config.get('subnet', {})
                        if subnet and subnet.get('id'):
                            subnet_name = subnet['id'].split('/')[-1]
                            unique_subnets.add(subnet_name)
                
                # Log unique subnets only once per VMSS
                for subnet_name in sorted(unique_subnets):
                    self.logger.info(f"    Found subnet: {subnet_name}")
                
                # Store VMSS info with proper structure for NSG analyzer
                # NSG analyzer expects the full VMSS detail with virtualMachineProfile
                vmss_analysis.append(vmss_detail_dict)
                
            except (ResourceNotFoundError, HttpResponseError) as e:
                self.logger.warning(f"Failed to get details for VMSS {vmss_name}: {e}")
                continue
        
        return vmss_analysis
    
    def collect_all(
        self, 
        cluster_name: str, 
        resource_group: str
    ) -> Dict[str, Any]:
        """
        Collect all cluster data in one call.
        
        This is a convenience method that collects cluster info, agent pools,
        VNet information, and VMSS configurations in sequence.
        
        Args:
            cluster_name: Name of the AKS cluster
            resource_group: Resource group containing the cluster
            
        Returns:
            Dictionary containing:
                - cluster_info: Cluster configuration details
                - agent_pools: List of node pool configurations
                - vnets_analysis: List of VNet details and peerings
                - vmss_analysis: List of VMSS network configurations
                
        Raises:
            ValueError: If cluster information cannot be retrieved
        """
        # Collect cluster info and agent pools
        cluster_data = self.collect_cluster_info(cluster_name, resource_group)
        cluster_info = cluster_data['cluster_info']
        agent_pools = cluster_data['agent_pools']
        
        # Collect VNet information
        vnets_analysis = self.collect_vnet_info(agent_pools)
        
        # Collect VMSS information
        vmss_analysis = self.collect_vmss_info(cluster_info)
        
        return {
            'cluster_info': cluster_info,
            'agent_pools': agent_pools,
            'vnets_analysis': vnets_analysis,
            'vmss_analysis': vmss_analysis
        }
