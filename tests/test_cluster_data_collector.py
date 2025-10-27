"""
Unit tests for ClusterDataCollector module
"""

import unittest
from unittest.mock import MagicMock

from aks_diagnostics.cluster_data_collector import ClusterDataCollector


class TestClusterDataCollector(unittest.TestCase):
    """Test cases for ClusterDataCollector class"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_azure_cli = MagicMock()
        self.mock_logger = MagicMock()
        self.collector = ClusterDataCollector(self.mock_azure_cli, self.mock_logger)

    def test_initialization(self):
        """Test ClusterDataCollector initialization"""
        self.assertEqual(self.collector.azure_cli, self.mock_azure_cli)
        self.assertEqual(self.collector.logger, self.mock_logger)

    def test_initialization_without_logger(self):
        """Test ClusterDataCollector initialization without logger creates default logger"""
        collector = ClusterDataCollector(self.mock_azure_cli)
        self.assertIsNotNone(collector.logger)

    def test_collect_cluster_info_success(self):
        """Test successful cluster info collection"""
        # Mock cluster info
        mock_cluster = {"name": "test-cluster", "location": "eastus", "provisioningState": "Succeeded"}

        # Mock agent pools
        mock_agent_pools = [{"name": "agentpool1", "count": 3}, {"name": "agentpool2", "count": 2}]

        self.mock_azure_cli.execute.side_effect = [mock_cluster, mock_agent_pools]

        result = self.collector.collect_cluster_info("test-cluster", "test-rg")

        # Verify execute was called with correct commands
        self.assertEqual(self.mock_azure_cli.execute.call_count, 2)

        cluster_cmd_call = self.mock_azure_cli.execute.call_args_list[0]
        self.assertEqual(cluster_cmd_call[0][0], ["aks", "show", "-n", "test-cluster", "-g", "test-rg", "-o", "json"])

        agent_pools_cmd_call = self.mock_azure_cli.execute.call_args_list[1]
        self.assertEqual(
            agent_pools_cmd_call[0][0],
            ["aks", "nodepool", "list", "-g", "test-rg", "--cluster-name", "test-cluster", "-o", "json"],
        )

        # Verify result structure
        self.assertIn("cluster_info", result)
        self.assertIn("agent_pools", result)
        self.assertEqual(result["cluster_info"], mock_cluster)
        self.assertEqual(result["agent_pools"], mock_agent_pools)

    def test_collect_cluster_info_no_cluster(self):
        """Test cluster info collection when cluster doesn't exist"""
        self.mock_azure_cli.execute.return_value = None

        with self.assertRaises(ValueError) as context:
            self.collector.collect_cluster_info("nonexistent-cluster", "test-rg")

        self.assertIn("Failed to get cluster information", str(context.exception))

    def test_collect_cluster_info_invalid_response(self):
        """Test cluster info collection with invalid response type"""
        self.mock_azure_cli.execute.return_value = "invalid response"

        with self.assertRaises(ValueError) as context:
            self.collector.collect_cluster_info("test-cluster", "test-rg")

        self.assertIn("Failed to get cluster information", str(context.exception))

    def test_collect_cluster_info_no_agent_pools(self):
        """Test cluster info collection when agent pools command returns non-list"""
        mock_cluster = {"name": "test-cluster"}
        self.mock_azure_cli.execute.side_effect = [mock_cluster, None]

        result = self.collector.collect_cluster_info("test-cluster", "test-rg")

        self.assertEqual(result["cluster_info"], mock_cluster)
        self.assertEqual(result["agent_pools"], [])

    def test_collect_vnet_info_no_subnets(self):
        """Test VNet collection when no vnetSubnetId is set (AKS-managed VNet)"""
        agent_pools = [{"name": "agentpool1"}, {"name": "agentpool2", "vnetSubnetId": "null"}]

        result = self.collector.collect_vnet_info(agent_pools)

        self.assertEqual(result, [])
        self.mock_logger.info.assert_called()
        # Verify the log message about AKS-managed VNet
        log_calls = [str(c) for c in self.mock_logger.info.call_args_list]
        self.assertTrue(any("AKS-managed VNet" in str(c) for c in log_calls))

    def test_collect_vnet_info_with_subnets(self):
        """Test VNet collection with custom subnet IDs"""
        subnet_id = "/subscriptions/sub-123/resourceGroups/vnet-rg/providers/Microsoft.Network/virtualNetworks/test-vnet/subnets/default"

        agent_pools = [{"name": "agentpool1", "vnetSubnetId": subnet_id}]

        mock_vnet = {
            "id": "/subscriptions/sub-123/resourceGroups/vnet-rg/providers/Microsoft.Network/virtualNetworks/test-vnet",
            "addressSpace": {"addressPrefixes": ["10.0.0.0/16"]},
            "name": "test-vnet",
        }

        mock_peerings = [
            {
                "name": "peering1",
                "remoteVirtualNetwork": {
                    "id": "/subscriptions/sub-123/resourceGroups/other-rg/providers/Microsoft.Network/virtualNetworks/other-vnet"
                },
                "peeringState": "Connected",
                "allowVirtualNetworkAccess": True,
                "allowForwardedTraffic": False,
                "allowGatewayTransit": False,
                "useRemoteGateways": False,
            }
        ]

        self.mock_azure_cli.execute_with_permission_check.side_effect = [mock_vnet, mock_peerings]

        result = self.collector.collect_vnet_info(agent_pools)

        # Verify VNet show command was called
        vnet_cmd_call = self.mock_azure_cli.execute_with_permission_check.call_args_list[0]
        self.assertEqual(
            vnet_cmd_call[0][0], ["network", "vnet", "show", "-n", "test-vnet", "-g", "vnet-rg", "-o", "json"]
        )

        # Verify peering command was called
        peering_cmd_call = self.mock_azure_cli.execute_with_permission_check.call_args_list[1]
        self.assertEqual(
            peering_cmd_call[0][0],
            ["network", "vnet", "peering", "list", "-g", "vnet-rg", "--vnet-name", "test-vnet", "-o", "json"],
        )

        # Verify result structure
        self.assertEqual(len(result), 1)
        vnet_result = result[0]
        self.assertEqual(vnet_result["name"], "test-vnet")
        self.assertEqual(vnet_result["resourceGroup"], "vnet-rg")
        self.assertEqual(vnet_result["addressSpace"], ["10.0.0.0/16"])
        self.assertEqual(len(vnet_result["peerings"]), 1)
        self.assertEqual(vnet_result["peerings"][0]["name"], "peering1")
        self.assertEqual(vnet_result["peerings"][0]["peeringState"], "Connected")

    def test_collect_vnet_info_multiple_vnets(self):
        """Test VNet collection with multiple VNets (deduplication)"""
        subnet_id_1 = "/subscriptions/sub-123/resourceGroups/vnet-rg/providers/Microsoft.Network/virtualNetworks/vnet-1/subnets/subnet-1"
        subnet_id_2 = "/subscriptions/sub-123/resourceGroups/vnet-rg/providers/Microsoft.Network/virtualNetworks/vnet-1/subnets/subnet-2"
        subnet_id_3 = "/subscriptions/sub-123/resourceGroups/vnet-rg/providers/Microsoft.Network/virtualNetworks/vnet-2/subnets/subnet-3"

        agent_pools = [
            {"name": "pool1", "vnetSubnetId": subnet_id_1},
            {"name": "pool2", "vnetSubnetId": subnet_id_2},  # Same VNet as pool1
            {"name": "pool3", "vnetSubnetId": subnet_id_3},  # Different VNet
        ]

        mock_vnet_1 = {"id": "vnet-1-id", "name": "vnet-1", "addressSpace": {"addressPrefixes": ["10.0.0.0/16"]}}

        mock_vnet_2 = {"id": "vnet-2-id", "name": "vnet-2", "addressSpace": {"addressPrefixes": ["10.1.0.0/16"]}}

        self.mock_azure_cli.execute.side_effect = [
            mock_vnet_1,
            [],  # VNet 1 with no peerings
            mock_vnet_2,
            [],  # VNet 2 with no peerings
        ]

        result = self.collector.collect_vnet_info(agent_pools)

        # Should only query each unique VNet once
        self.assertEqual(len(result), 2)
        vnet_names = [vnet["name"] for vnet in result]
        self.assertIn("vnet-1", vnet_names)
        self.assertIn("vnet-2", vnet_names)

    def test_collect_vmss_info_no_managed_rg(self):
        """Test VMSS collection when nodeResourceGroup is missing"""
        cluster_info = {"name": "test-cluster"}

        result = self.collector.collect_vmss_info(cluster_info)

        self.assertEqual(result, [])
        self.mock_logger.warning.assert_called_once()

    def test_collect_vmss_info_success(self):
        """Test successful VMSS info collection"""
        cluster_info = {"nodeResourceGroup": "MC_test-rg_test-cluster_eastus"}

        mock_vmss_list = [{"name": "aks-agentpool-12345-vmss"}, {"name": "aks-userpool-67890-vmss"}]

        mock_vmss_detail_1 = {
            "name": "aks-agentpool-12345-vmss",
            "virtualMachineProfile": {
                "networkProfile": {
                    "networkInterfaceConfigurations": [
                        {
                            "ipConfigurations": [
                                {
                                    "subnet": {
                                        "id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/default"
                                    }
                                }
                            ]
                        }
                    ]
                }
            },
        }

        mock_vmss_detail_2 = {
            "name": "aks-userpool-67890-vmss",
            "virtualMachineProfile": {
                "networkProfile": {
                    "networkInterfaceConfigurations": [
                        {
                            "ipConfigurations": [
                                {
                                    "subnet": {
                                        "id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/user-subnet"
                                    }
                                }
                            ]
                        }
                    ]
                }
            },
        }

        self.mock_azure_cli.execute_with_permission_check.side_effect = [
            mock_vmss_list,
            mock_vmss_detail_1,
            mock_vmss_detail_2,
        ]

        result = self.collector.collect_vmss_info(cluster_info)

        # Verify VMSS list command
        list_cmd_call = self.mock_azure_cli.execute_with_permission_check.call_args_list[0]
        self.assertEqual(list_cmd_call[0][0], ["vmss", "list", "-g", "MC_test-rg_test-cluster_eastus", "-o", "json"])

        # Verify VMSS details commands (now using execute_with_permission_check)
        self.assertEqual(self.mock_azure_cli.execute_with_permission_check.call_count, 3)

        # Verify result
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["name"], "aks-agentpool-12345-vmss")
        self.assertEqual(result[1]["name"], "aks-userpool-67890-vmss")

    def test_collect_vmss_info_empty_list(self):
        """Test VMSS collection when no VMSS are found"""
        cluster_info = {"nodeResourceGroup": "MC_test-rg"}
        self.mock_azure_cli.execute.return_value = []

        result = self.collector.collect_vmss_info(cluster_info)

        self.assertEqual(result, [])

    def test_collect_vmss_info_invalid_response(self):
        """Test VMSS collection with invalid response type"""
        cluster_info = {"nodeResourceGroup": "MC_test-rg"}
        self.mock_azure_cli.execute.return_value = "invalid"

        result = self.collector.collect_vmss_info(cluster_info)

        self.assertEqual(result, [])

    def test_collect_all_success(self):
        """Test collect_all method integrates all collection methods"""
        # Mock cluster info
        mock_cluster = {"name": "test-cluster", "nodeResourceGroup": "MC_test-rg"}

        # Mock agent pools with subnet
        mock_agent_pools = [
            {
                "name": "agentpool1",
                "vnetSubnetId": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/default",
            }
        ]

        # Mock VNet
        mock_vnet = {"name": "vnet", "addressSpace": {"addressPrefixes": ["10.0.0.0/16"]}}

        # Mock VMSS
        mock_vmss_list = [{"name": "vmss-1"}]
        mock_vmss_detail = {
            "name": "vmss-1",
            "virtualMachineProfile": {"networkProfile": {"networkInterfaceConfigurations": []}},
        }

        # Mock execute for cluster_info calls (still use .execute)
        # Mock execute_with_permission_check for VNet and VMSS calls
        self.mock_azure_cli.execute.side_effect = [
            mock_cluster,  # collect_cluster_info: cluster
            mock_agent_pools,  # collect_cluster_info: agent pools
        ]
        self.mock_azure_cli.execute_with_permission_check.side_effect = [
            mock_vnet,  # collect_vnet_info: vnet show
            [],  # collect_vnet_info: peerings
            mock_vmss_list,  # collect_vmss_info: vmss list
            mock_vmss_detail,  # collect_vmss_info: vmss detail
        ]

        result = self.collector.collect_all("test-cluster", "test-rg")

        # Verify result structure
        self.assertIn("cluster_info", result)
        self.assertIn("agent_pools", result)
        self.assertIn("vnets_analysis", result)
        self.assertIn("vmss_analysis", result)

        # Verify data
        self.assertEqual(result["cluster_info"], mock_cluster)
        self.assertEqual(result["agent_pools"], mock_agent_pools)
        self.assertEqual(len(result["vnets_analysis"]), 1)
        self.assertEqual(len(result["vmss_analysis"]), 1)


if __name__ == "__main__":
    unittest.main()
