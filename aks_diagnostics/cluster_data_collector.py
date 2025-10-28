"""
Cluster Data Collector for AKS Network Diagnostics

This module handles fetching and collecting cluster-related data from Azure,
including cluster information, agent pools, VNets, and VMSS configurations.
"""

import logging
import re
from typing import Any, Dict, List, Optional


class ClusterDataCollector:
    """Collects cluster information and related Azure resources."""

    def __init__(self, azure_cli_executor, logger: Optional[logging.Logger] = None):
        """
        Initialize ClusterDataCollector.

        Args:
            azure_cli_executor: AzureCLIExecutor instance for running Azure CLI commands
            logger: Optional logger instance. If not provided, creates a default logger.
        """
        self.azure_cli = azure_cli_executor
        self.logger = logger or logging.getLogger(__name__)
        self.findings = []  # Store permission-related findings

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

        # Get cluster info
        cluster_cmd = ["aks", "show", "-n", cluster_name, "-g", resource_group, "-o", "json"]
        cluster_result = self.azure_cli.execute(cluster_cmd)

        if not cluster_result or not isinstance(cluster_result, dict):
            raise ValueError(
                f"Failed to get cluster information for {cluster_name}. "
                "Please check the cluster name and resource group."
            )

        # Get agent pools
        agent_pools_cmd = [
            "aks",
            "nodepool",
            "list",
            "-g",
            resource_group,
            "--cluster-name",
            cluster_name,
            "-o",
            "json",
        ]
        agent_pools_result = self.azure_cli.execute(agent_pools_cmd)

        agent_pools = agent_pools_result if isinstance(agent_pools_result, list) else []

        return {"cluster_info": cluster_result, "agent_pools": agent_pools}

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
            subnet_id = pool.get("vnetSubnetId")
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
            vnet_match = re.search(r"/virtualNetworks/([^/]+)", subnet_id)
            if not vnet_match:
                continue

            vnet_name = vnet_match.group(1)
            vnet_rg = subnet_id.split("/")[4]  # Resource group is at index 4 in the resource ID

            if vnet_name not in vnets_map:
                # Get VNet information with permission handling
                vnet_cmd = ["network", "vnet", "show", "-n", vnet_name, "-g", vnet_rg, "-o", "json"]
                vnet_info = self.azure_cli.execute_with_permission_check(
                    vnet_cmd, f"retrieve VNet '{vnet_name}' details"
                )

                if vnet_info is None:
                    # Permission denied - add finding and skip this VNet
                    from .models import Finding, FindingCode

                    finding = Finding.create_warning(
                        code=FindingCode.PERMISSION_INSUFFICIENT_VNET,
                        message=f"Insufficient permissions to retrieve VNet '{vnet_name}' details",
                        recommendation=(
                            f"Grant the following permission to analyze VNet configuration:\n"
                            f"  Microsoft.Network/virtualNetworks/read\n\n"
                            f"Example Azure CLI command:\n"
                            f"  az role assignment create --assignee <user-principal-id> \\\n"
                            f"    --role 'Network Contributor' \\\n"
                            f"    --scope '/subscriptions/<sub-id>/resourceGroups/{vnet_rg}'"
                        ),
                    )
                    self.findings.append(finding)
                    continue

                if vnet_info:
                    vnets_map[vnet_name] = {
                        "name": vnet_name,
                        "resourceGroup": vnet_rg,
                        "id": vnet_info.get("id", ""),
                        "addressSpace": vnet_info.get("addressSpace", {}).get("addressPrefixes", []),
                        "subnets": [],
                        "peerings": [],
                    }

                    # Get VNet peerings with permission handling
                    peering_cmd = [
                        "network",
                        "vnet",
                        "peering",
                        "list",
                        "-g",
                        vnet_rg,
                        "--vnet-name",
                        vnet_name,
                        "-o",
                        "json",
                    ]
                    peerings = self.azure_cli.execute_with_permission_check(
                        peering_cmd, f"retrieve VNet peerings for '{vnet_name}'"
                    )

                    if peerings is None:
                        # Permission denied for peerings - log and continue
                        self.logger.debug(f"Skipping VNet peerings for '{vnet_name}' due to insufficient permissions")
                    elif isinstance(peerings, list):
                        for peering in peerings:
                            vnets_map[vnet_name]["peerings"].append(
                                {
                                    "name": peering.get("name", ""),
                                    "remoteVirtualNetwork": peering.get("remoteVirtualNetwork", {}).get("id", ""),
                                    "peeringState": peering.get("peeringState", ""),
                                    "allowVirtualNetworkAccess": peering.get("allowVirtualNetworkAccess", False),
                                    "allowForwardedTraffic": peering.get("allowForwardedTraffic", False),
                                    "allowGatewayTransit": peering.get("allowGatewayTransit", False),
                                    "useRemoteGateways": peering.get("useRemoteGateways", False),
                                }
                            )

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

        mc_rg = cluster_info.get("nodeResourceGroup", "")
        if not mc_rg:
            self.logger.warning("No managed resource group found in cluster info")
            return []

        # List VMSS in the managed resource group with permission handling
        vmss_cmd = ["vmss", "list", "-g", mc_rg, "-o", "json"]
        vmss_list = self.azure_cli.execute_with_permission_check(vmss_cmd, f"retrieve VMSS list in '{mc_rg}'")

        if vmss_list is None:
            # Permission denied - add finding
            from .models import Finding, FindingCode

            finding = Finding.create_warning(
                code=FindingCode.PERMISSION_INSUFFICIENT_VMSS,
                message=f"Insufficient permissions to retrieve VMSS configuration in '{mc_rg}'",
                recommendation=(
                    f"Grant the following permission to analyze VMSS network configuration:\n"
                    f"  Microsoft.Compute/virtualMachineScaleSets/read\n\n"
                    f"Example Azure CLI command:\n"
                    f"  az role assignment create --assignee <user-principal-id> \\\n"
                    f"    --role 'Reader' \\\n"
                    f"    --scope '/subscriptions/<sub-id>/resourceGroups/{mc_rg}'"
                ),
            )
            self.findings.append(finding)
            return []

        if not isinstance(vmss_list, list):
            return []

        vmss_analysis = []
        for vmss in vmss_list:
            vmss_name = vmss.get("name", "")
            if not vmss_name:
                continue

            self.logger.info(f"  - Analyzing VMSS: {vmss_name}")

            # Get VMSS network profile
            vmss_detail_cmd = ["vmss", "show", "-n", vmss_name, "-g", mc_rg, "-o", "json"]
            vmss_detail = self.azure_cli.execute_with_permission_check(
                vmss_detail_cmd, context=f"retrieve VMSS '{vmss_name}' details"
            )

            if vmss_detail:
                network_profile = vmss_detail.get("virtualMachineProfile", {}).get("networkProfile", {})
                network_interfaces = network_profile.get("networkInterfaceConfigurations", [])

                # Collect unique subnets for this VMSS
                unique_subnets = set()
                for nic in network_interfaces:
                    ip_configs = nic.get("ipConfigurations", [])
                    for ip_config in ip_configs:
                        subnet = ip_config.get("subnet", {})
                        if subnet and subnet.get("id"):
                            subnet_name = subnet["id"].split("/")[-1]
                            unique_subnets.add(subnet_name)

                # Log unique subnets only once per VMSS
                for subnet_name in sorted(unique_subnets):
                    self.logger.info(f"    Found subnet: {subnet_name}")

                # Store VMSS info with proper structure for NSG analyzer
                # NSG analyzer expects the full VMSS detail with virtualMachineProfile
                vmss_analysis.append(vmss_detail)

        return vmss_analysis

    def collect_all(self, cluster_name: str, resource_group: str) -> Dict[str, Any]:
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
        cluster_info = cluster_data["cluster_info"]
        agent_pools = cluster_data["agent_pools"]

        # Collect VNet information
        vnets_analysis = self.collect_vnet_info(agent_pools)

        # Collect VMSS information
        vmss_analysis = self.collect_vmss_info(cluster_info)

        return {
            "cluster_info": cluster_info,
            "agent_pools": agent_pools,
            "vnets_analysis": vnets_analysis,
            "vmss_analysis": vmss_analysis,
        }
