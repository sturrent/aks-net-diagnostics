"""
Unit tests for ClusterDataCollector module
"""

import unittest
from unittest.mock import MagicMock, Mock, PropertyMock
from azure.core.exceptions import ResourceNotFoundError, HttpResponseError
from aks_diagnostics.cluster_data_collector import ClusterDataCollector


class TestClusterDataCollector(unittest.TestCase):
    """Test cases for ClusterDataCollector class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.mock_sdk_client = MagicMock()
        self.mock_logger = MagicMock()
        self.collector = ClusterDataCollector(self.mock_sdk_client, self.mock_logger)
    
    def test_initialization(self):
        """Test ClusterDataCollector initialization"""
        self.assertEqual(self.collector.sdk_client, self.mock_sdk_client)
        self.assertEqual(self.collector.logger, self.mock_logger)
    
    def test_initialization_without_logger(self):
        """Test ClusterDataCollector initialization without logger creates default logger"""
        collector = ClusterDataCollector(self.mock_sdk_client)
        self.assertIsNotNone(collector.logger)
    
    def test_collect_cluster_info_success(self):
        """Test successful cluster info collection"""
        # Mock cluster object from SDK
        mock_cluster = Mock()
        mock_cluster.as_dict.return_value = {
            'name': 'test-cluster',
            'location': 'eastus',
            'provisioningState': 'Succeeded'
        }
        # Mock status with additional_properties
        mock_cluster.status = None  # No status object (normal case)
        
        # Mock agent pool objects from SDK
        mock_pool1 = Mock()
        mock_pool1.as_dict.return_value = {'name': 'agentpool1', 'count': 3}
        mock_pool2 = Mock()
        mock_pool2.as_dict.return_value = {'name': 'agentpool2', 'count': 2}
        
        # Setup SDK client mocks
        self.mock_sdk_client.get_cluster.return_value = mock_cluster
        self.mock_sdk_client.aks_client.agent_pools.list.return_value = [mock_pool1, mock_pool2]
        
        result = self.collector.collect_cluster_info('test-cluster', 'test-rg')
        
        # Verify SDK methods were called correctly
        self.mock_sdk_client.get_cluster.assert_called_once_with('test-rg', 'test-cluster')
        self.mock_sdk_client.aks_client.agent_pools.list.assert_called_once_with('test-rg', 'test-cluster')
        
        # Verify result structure
        self.assertIn('cluster_info', result)
        self.assertIn('agent_pools', result)
        self.assertEqual(result['cluster_info']['name'], 'test-cluster')
        self.assertEqual(len(result['agent_pools']), 2)
    
    def test_collect_cluster_info_no_cluster(self):
        """Test cluster info collection when cluster doesn't exist"""
        self.mock_sdk_client.get_cluster.side_effect = ResourceNotFoundError("Cluster not found")
        
        with self.assertRaises(ValueError) as context:
            self.collector.collect_cluster_info('nonexistent-cluster', 'test-rg')
        
        self.assertIn('not found', str(context.exception))
    
    def test_collect_cluster_info_invalid_response(self):
        """Test cluster info collection with HTTP error"""
        mock_error = HttpResponseError("Service unavailable")
        mock_error.message = "Service unavailable"
        self.mock_sdk_client.get_cluster.side_effect = mock_error
        
        with self.assertRaises(ValueError) as context:
            self.collector.collect_cluster_info('test-cluster', 'test-rg')
        
        self.assertIn('Failed to get cluster information', str(context.exception))
    
    def test_collect_cluster_info_no_agent_pools(self):
        """Test cluster info collection when agent pools list is empty"""
        mock_cluster = Mock()
        mock_cluster.as_dict.return_value = {'name': 'test-cluster'}
        mock_cluster.status = None  # No status object
        
        self.mock_sdk_client.get_cluster.return_value = mock_cluster
        self.mock_sdk_client.aks_client.agent_pools.list.return_value = []
        
        result = self.collector.collect_cluster_info('test-cluster', 'test-rg')
        
        self.assertEqual(result['cluster_info']['name'], 'test-cluster')
        self.assertEqual(result['agent_pools'], [])
    
    def test_collect_vnet_info_no_subnets(self):
        """Test VNet collection when no vnetSubnetId is set (AKS-managed VNet)"""
        agent_pools = [
            {'name': 'agentpool1'},
            {'name': 'agentpool2', 'vnetSubnetId': 'null'}
        ]
        
        result = self.collector.collect_vnet_info(agent_pools)
        
        self.assertEqual(result, [])
        self.mock_logger.info.assert_called()
        # Verify the log message about AKS-managed VNet
        log_calls = [str(call) for call in self.mock_logger.info.call_args_list]
        self.assertTrue(any('AKS-managed VNet' in str(call) for call in log_calls))
    
    def test_collect_vnet_info_with_subnets(self):
        """Test VNet collection with custom subnet IDs"""
        subnet_id = '/subscriptions/sub-123/resourceGroups/vnet-rg/providers/Microsoft.Network/virtualNetworks/test-vnet/subnets/default'
        
        agent_pools = [
            {'name': 'agentpool1', 'vnetSubnetId': subnet_id}
        ]
        
        # Mock VNet object from SDK
        mock_vnet = Mock()
        mock_vnet.id = '/subscriptions/sub-123/resourceGroups/vnet-rg/providers/Microsoft.Network/virtualNetworks/test-vnet'
        mock_vnet.name = 'test-vnet'
        mock_vnet.address_space = Mock()
        mock_vnet.address_space.address_prefixes = ['10.0.0.0/16']
        
        # Mock peering object from SDK
        mock_peering = Mock()
        mock_peering.name = 'peering1'
        mock_peering.remote_virtual_network = Mock()
        mock_peering.remote_virtual_network.id = '/subscriptions/sub-123/resourceGroups/other-rg/providers/Microsoft.Network/virtualNetworks/other-vnet'
        mock_peering.peering_state = 'Connected'
        mock_peering.allow_virtual_network_access = True
        mock_peering.allow_forwarded_traffic = False
        mock_peering.allow_gateway_transit = False
        mock_peering.use_remote_gateways = False
        
        # Setup SDK client mocks
        self.mock_sdk_client.network_client.virtual_networks.get.return_value = mock_vnet
        self.mock_sdk_client.network_client.virtual_network_peerings.list.return_value = [mock_peering]
        
        result = self.collector.collect_vnet_info(agent_pools)
        
        # Verify SDK methods were called correctly
        self.mock_sdk_client.network_client.virtual_networks.get.assert_called_once_with('vnet-rg', 'test-vnet')
        self.mock_sdk_client.network_client.virtual_network_peerings.list.assert_called_once_with('vnet-rg', 'test-vnet')
        
        # Verify result structure
        self.assertEqual(len(result), 1)
        vnet_result = result[0]
        self.assertEqual(vnet_result['name'], 'test-vnet')
        self.assertEqual(vnet_result['resourceGroup'], 'vnet-rg')
        self.assertEqual(vnet_result['addressSpace'], ['10.0.0.0/16'])
        self.assertEqual(len(vnet_result['peerings']), 1)
        self.assertEqual(vnet_result['peerings'][0]['name'], 'peering1')
        self.assertEqual(vnet_result['peerings'][0]['peeringState'], 'Connected')
    
    def test_collect_vnet_info_multiple_vnets(self):
        """Test VNet collection with multiple VNets (deduplication)"""
        subnet_id_1 = '/subscriptions/sub-123/resourceGroups/vnet-rg/providers/Microsoft.Network/virtualNetworks/vnet-1/subnets/subnet-1'
        subnet_id_2 = '/subscriptions/sub-123/resourceGroups/vnet-rg/providers/Microsoft.Network/virtualNetworks/vnet-1/subnets/subnet-2'
        subnet_id_3 = '/subscriptions/sub-123/resourceGroups/vnet-rg/providers/Microsoft.Network/virtualNetworks/vnet-2/subnets/subnet-3'
        
        agent_pools = [
            {'name': 'pool1', 'vnetSubnetId': subnet_id_1},
            {'name': 'pool2', 'vnetSubnetId': subnet_id_2},  # Same VNet as pool1
            {'name': 'pool3', 'vnetSubnetId': subnet_id_3}   # Different VNet
        ]
        
        # Mock VNet 1 object
        mock_vnet_1 = Mock()
        mock_vnet_1.id = 'vnet-1-id'
        mock_vnet_1.name = 'vnet-1'
        mock_vnet_1.address_space = Mock()
        mock_vnet_1.address_space.address_prefixes = ['10.0.0.0/16']
        
        # Mock VNet 2 object
        mock_vnet_2 = Mock()
        mock_vnet_2.id = 'vnet-2-id'
        mock_vnet_2.name = 'vnet-2'
        mock_vnet_2.address_space = Mock()
        mock_vnet_2.address_space.address_prefixes = ['10.1.0.0/16']
        
        # Setup SDK client mocks - return different VNets based on name
        def get_vnet_mock(rg, name):
            if name == 'vnet-1':
                return mock_vnet_1
            else:
                return mock_vnet_2
        
        self.mock_sdk_client.network_client.virtual_networks.get.side_effect = get_vnet_mock
        self.mock_sdk_client.network_client.virtual_network_peerings.list.return_value = []
        
        result = self.collector.collect_vnet_info(agent_pools)
        
        # Should only query each unique VNet once
        self.assertEqual(len(result), 2)
        vnet_names = [vnet['name'] for vnet in result]
        self.assertIn('vnet-1', vnet_names)
        self.assertIn('vnet-2', vnet_names)
    
    def test_collect_vmss_info_no_managed_rg(self):
        """Test VMSS collection when nodeResourceGroup is missing"""
        cluster_info = {'name': 'test-cluster'}
        
        result = self.collector.collect_vmss_info(cluster_info)
        
        self.assertEqual(result, [])
        self.mock_logger.warning.assert_called_once()
    
    def test_collect_vmss_info_success(self):
        """Test successful VMSS info collection"""
        cluster_info = {'nodeResourceGroup': 'MC_test-rg_test-cluster_eastus'}
        
        # Mock VMSS list objects
        mock_vmss_1 = Mock()
        mock_vmss_1.name = 'aks-agentpool-12345-vmss'
        mock_vmss_2 = Mock()
        mock_vmss_2.name = 'aks-userpool-67890-vmss'
        
        # Mock detailed VMSS objects
        mock_vmss_detail_1 = Mock()
        mock_vmss_detail_1.as_dict.return_value = {
            'name': 'aks-agentpool-12345-vmss',
            'virtualMachineProfile': {
                'networkProfile': {
                    'networkInterfaceConfigurations': [
                        {
                            'ipConfigurations': [
                                {
                                    'subnet': {
                                        'id': '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/default'
                                    }
                                }
                            ]
                        }
                    ]
                }
            }
        }
        
        mock_vmss_detail_2 = Mock()
        mock_vmss_detail_2.as_dict.return_value = {
            'name': 'aks-userpool-67890-vmss',
            'virtualMachineProfile': {
                'networkProfile': {
                    'networkInterfaceConfigurations': [
                        {
                            'ipConfigurations': [
                                {
                                    'subnet': {
                                        'id': '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/user-subnet'
                                    }
                                }
                            ]
                        }
                    ]
                }
            }
        }
        
        # Setup SDK client mocks
        self.mock_sdk_client.compute_client.virtual_machine_scale_sets.list.return_value = [mock_vmss_1, mock_vmss_2]
        self.mock_sdk_client.compute_client.virtual_machine_scale_sets.get.side_effect = [mock_vmss_detail_1, mock_vmss_detail_2]
        
        result = self.collector.collect_vmss_info(cluster_info)
        
        # Verify SDK methods were called correctly
        self.mock_sdk_client.compute_client.virtual_machine_scale_sets.list.assert_called_once_with('MC_test-rg_test-cluster_eastus')
        self.assertEqual(self.mock_sdk_client.compute_client.virtual_machine_scale_sets.get.call_count, 2)
        
        # Verify result
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]['name'], 'aks-agentpool-12345-vmss')
        self.assertEqual(result[1]['name'], 'aks-userpool-67890-vmss')
    
    def test_collect_vmss_info_empty_list(self):
        """Test VMSS collection when no VMSS are found"""
        cluster_info = {'nodeResourceGroup': 'MC_test-rg_test-cluster_eastus'}
        self.mock_sdk_client.compute_client.virtual_machine_scale_sets.list.return_value = []
        
        result = self.collector.collect_vmss_info(cluster_info)
        
        self.assertEqual(result, [])
    
    def test_collect_vmss_info_http_error(self):
        """Test VMSS collection with HTTP error"""
        cluster_info = {'nodeResourceGroup': 'MC_test-rg'}
        mock_error = HttpResponseError("Service unavailable")
        self.mock_sdk_client.compute_client.virtual_machine_scale_sets.list.side_effect = mock_error
        
        result = self.collector.collect_vmss_info(cluster_info)
        
        self.assertEqual(result, [])
    
    def test_collect_all_success(self):
        """Test collect_all method integrates all collection methods"""
        # Mock cluster object
        mock_cluster = Mock()
        mock_cluster.as_dict.return_value = {
            'name': 'test-cluster',
            'nodeResourceGroup': 'MC_test-rg'
        }
        mock_cluster.status = None  # No status object
        
        # Mock agent pool objects
        mock_pool = Mock()
        mock_pool.as_dict.return_value = {
            'name': 'agentpool1',
            'vnetSubnetId': '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/default'
        }
        
        # Mock VNet
        mock_vnet = Mock()
        mock_vnet.name = 'vnet'
        mock_vnet.id = 'vnet-id'
        mock_vnet.address_space = Mock()
        mock_vnet.address_space.address_prefixes = ['10.0.0.0/16']
        
        # Mock VMSS
        mock_vmss = Mock()
        mock_vmss.name = 'vmss-1'
        
        mock_vmss_detail = Mock()
        mock_vmss_detail.as_dict.return_value = {
            'name': 'vmss-1',
            'virtualMachineProfile': {
                'networkProfile': {
                    'networkInterfaceConfigurations': []
                }
            }
        }
        
        # Setup SDK client mocks
        self.mock_sdk_client.get_cluster.return_value = mock_cluster
        self.mock_sdk_client.aks_client.agent_pools.list.return_value = [mock_pool]
        self.mock_sdk_client.network_client.virtual_networks.get.return_value = mock_vnet
        self.mock_sdk_client.network_client.virtual_network_peerings.list.return_value = []
        self.mock_sdk_client.compute_client.virtual_machine_scale_sets.list.return_value = [mock_vmss]
        self.mock_sdk_client.compute_client.virtual_machine_scale_sets.get.return_value = mock_vmss_detail
        
        result = self.collector.collect_all('test-cluster', 'test-rg')
        
        # Verify result structure
        self.assertIn('cluster_info', result)
        self.assertIn('agent_pools', result)
        self.assertIn('vnets_analysis', result)
        self.assertIn('vmss_analysis', result)
        
        # Verify data
        self.assertEqual(result['cluster_info']['name'], 'test-cluster')
        self.assertEqual(len(result['agent_pools']), 1)
        self.assertEqual(len(result['vnets_analysis']), 1)
        self.assertEqual(len(result['vmss_analysis']), 1)


if __name__ == '__main__':
    unittest.main()
