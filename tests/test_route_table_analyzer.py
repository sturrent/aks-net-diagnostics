"""
Unit tests for RouteTableAnalyzer module.

Tests cover:
- Route table discovery and analysis
- Route impact assessment (critical, high, medium, low)
- Route categorization (default, Azure services, container registry, private network)
- Virtual appliance route detection
- BGP route propagation settings
- Error handling for invalid configurations
"""

import unittest
from unittest.mock import MagicMock, Mock

from aks_diagnostics.route_table_analyzer import RouteTableAnalyzer


class TestRouteTableAnalyzer(unittest.TestCase):
    """Test cases for RouteTableAnalyzer"""

    def setUp(self):
        """Set up test fixtures"""
        self.mock_sdk_client = MagicMock()

        # Sample agent pools with subnet IDs
        self.agent_pools = [
            {
                "name": "nodepool1",
                "vnetSubnetId": "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/vnet1/subnets/subnet1",
            }
        ]

        self.analyzer = RouteTableAnalyzer(self.agent_pools, self.mock_sdk_client)

    def test_initialization(self):
        """Test analyzer initialization"""
        self.assertEqual(self.analyzer.agent_pools, self.agent_pools)
        self.assertEqual(self.analyzer.sdk_client, self.mock_sdk_client)

    def test_get_unique_subnet_ids(self):
        """Test extraction of unique subnet IDs"""
        agent_pools = [
            {
                "vnetSubnetId": "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/vnet1/subnets/subnet1"
            },
            {
                "vnetSubnetId": "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/vnet1/subnets/subnet2"
            },
            {
                "vnetSubnetId": "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/vnet1/subnets/subnet1"
            },  # duplicate
            {"vnetSubnetId": "null"},  # should be filtered
            {"vnetSubnetId": None},  # should be filtered
        ]

        analyzer = RouteTableAnalyzer(agent_pools, self.mock_sdk_client)
        subnet_ids = analyzer._get_unique_subnet_ids()

        # Should return only 2 unique subnet IDs (duplicates and null filtered)
        self.assertEqual(len(subnet_ids), 2)

    def test_analyze_no_vnet_integration(self):
        """Test analysis when no VNet-integrated node pools exist"""
        agent_pools = [{"vnetSubnetId": None}, {"vnetSubnetId": "null"}]

        analyzer = RouteTableAnalyzer(agent_pools, self.mock_sdk_client)
        result = analyzer.analyze()

        self.assertEqual(result["routeTables"], [])
        self.assertEqual(result["criticalRoutes"], [])
        self.assertEqual(result["virtualApplianceRoutes"], [])
        self.assertEqual(result["internetRoutes"], [])

    def test_get_subnet_details(self):
        """Test subnet details retrieval"""
        subnet_id = (
            "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/vnet1/subnets/subnet1"
        )

        # Mock parse_resource_id
        self.mock_sdk_client.parse_resource_id.return_value = {
            "subscription_id": "sub1",
            "resource_group": "rg1",
            "parent_name": "vnet1",
            "resource_name": "subnet1",
        }

        # Mock subscription ID check
        self.mock_sdk_client.subscription_id = "sub1"

        # Mock subnet object
        mock_subnet = Mock()
        mock_subnet.route_table = Mock()
        mock_subnet.route_table.id = (
            "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Network/routeTables/rt1"
        )
        mock_subnet.as_dict.return_value = {
            "name": "subnet1",
            "routeTable": {"id": "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Network/routeTables/rt1"},
        }

        self.mock_sdk_client.network_client.subnets.get.return_value = mock_subnet

        result = self.analyzer._get_subnet_details(subnet_id)

        self.assertEqual(result["name"], "subnet1")
        self.assertEqual(
            result["routeTable"]["id"],
            "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Network/routeTables/rt1",
        )
        self.mock_sdk_client.parse_resource_id.assert_called_once_with(subnet_id)
        self.mock_sdk_client.network_client.subnets.get.assert_called_once_with("rg1", "vnet1", "subnet1")

    def test_get_subnet_details_invalid_id(self):
        """Test subnet details with invalid subnet ID"""
        invalid_subnet_id = "/too/short/path"

        # Mock parse_resource_id to raise ValueError for invalid ID
        self.mock_sdk_client.parse_resource_id.side_effect = ValueError("Invalid resource ID format")

        result = self.analyzer._get_subnet_details(invalid_subnet_id)

        self.assertIsNone(result)
        self.mock_sdk_client.parse_resource_id.assert_called_once_with(invalid_subnet_id)

    def test_analyze_route_table_with_routes(self):
        """Test route table analysis with multiple routes"""
        route_table_id = "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Network/routeTables/rt1"
        subnet_id = (
            "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/vnet1/subnets/subnet1"
        )

        # Mock parse_resource_id
        self.mock_sdk_client.parse_resource_id.return_value = {
            "subscription_id": "sub1",
            "resource_group": "rg1",
            "resource_name": "rt1",
        }

        # Mock subscription ID check
        self.mock_sdk_client.subscription_id = "sub1"

        # Mock route table object
        mock_route1 = Mock()
        mock_route1.name = "default-route"
        mock_route1.address_prefix = "0.0.0.0/0"
        mock_route1.next_hop_type = "VirtualAppliance"
        mock_route1.next_hop_ip_address = "10.1.0.4"
        mock_route1.provisioning_state = "Succeeded"
        mock_route1.as_dict.return_value = {
            "name": "default-route",
            "addressPrefix": "0.0.0.0/0",
            "nextHopType": "VirtualAppliance",
            "nextHopIpAddress": "10.1.0.4",
            "provisioningState": "Succeeded",
        }

        mock_route2 = Mock()
        mock_route2.name = "azure-route"
        mock_route2.address_prefix = "168.63.129.16/32"
        mock_route2.next_hop_type = "Internet"
        mock_route2.next_hop_ip_address = ""
        mock_route2.provisioning_state = "Succeeded"
        mock_route2.as_dict.return_value = {
            "name": "azure-route",
            "addressPrefix": "168.63.129.16/32",
            "nextHopType": "Internet",
            "nextHopIpAddress": "",
            "provisioningState": "Succeeded",
        }

        mock_route_table = Mock()
        mock_route_table.name = "rt1"
        mock_route_table.disable_bgp_route_propagation = False
        mock_route_table.routes = [mock_route1, mock_route2]
        mock_route_table.as_dict.return_value = {
            "name": "rt1",
            "disableBgpRoutePropagation": False,
            "routes": [mock_route1.as_dict.return_value, mock_route2.as_dict.return_value],
        }

        self.mock_sdk_client.network_client.route_tables.get.return_value = mock_route_table

        result = self.analyzer._analyze_route_table(route_table_id, subnet_id)

        self.assertIsNotNone(result)
        self.assertEqual(result["name"], "rt1")
        self.assertEqual(result["resourceGroup"], "rg1")
        self.assertEqual(result["associatedSubnet"], subnet_id)
        self.assertEqual(len(result["routes"]), 2)
        self.assertFalse(result["disableBgpRoutePropagation"])

    def test_analyze_route_table_bgp_disabled(self):
        """Test route table with BGP route propagation disabled"""
        route_table_id = "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Network/routeTables/rt1"
        subnet_id = (
            "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/vnet1/subnets/subnet1"
        )

        # Mock parse_resource_id
        self.mock_sdk_client.parse_resource_id.return_value = {
            "subscription_id": "sub1",
            "resource_group": "rg1",
            "resource_name": "rt1",
        }

        # Mock subscription ID check
        self.mock_sdk_client.subscription_id = "sub1"

        # Mock route table object
        mock_route_table = Mock()
        mock_route_table.name = "rt1"
        mock_route_table.disable_bgp_route_propagation = True
        mock_route_table.routes = []
        mock_route_table.as_dict.return_value = {"name": "rt1", "disableBgpRoutePropagation": True, "routes": []}

        self.mock_sdk_client.network_client.route_tables.get.return_value = mock_route_table

        result = self.analyzer._analyze_route_table(route_table_id, subnet_id)

        self.assertTrue(result["disableBgpRoutePropagation"])

    def test_analyze_individual_route(self):
        """Test analysis of an individual route"""
        route = {
            "name": "test-route",
            "addressPrefix": "10.0.0.0/8",
            "nextHopType": "VirtualAppliance",
            "nextHopIpAddress": "10.1.0.4",
            "provisioningState": "Succeeded",
        }

        result = self.analyzer._analyze_individual_route(route)

        self.assertIsNotNone(result)
        self.assertEqual(result["name"], "test-route")
        self.assertEqual(result["addressPrefix"], "10.0.0.0/8")
        self.assertEqual(result["nextHopType"], "VirtualAppliance")
        self.assertEqual(result["nextHopIpAddress"], "10.1.0.4")
        self.assertIn("impact", result)

    def test_assess_route_impact_default_route_virtual_appliance(self):
        """Test impact assessment for default route through virtual appliance"""
        impact = self.analyzer._assess_route_impact("0.0.0.0/0", "VirtualAppliance", "10.1.0.4")

        self.assertEqual(impact["severity"], "high")
        self.assertIn("internet", impact["affectedTraffic"])
        self.assertIn("container_registry", impact["affectedTraffic"])
        self.assertIn("azure_services", impact["affectedTraffic"])
        self.assertIn("api_server", impact["affectedTraffic"])

    def test_assess_route_impact_default_route_blackhole(self):
        """Test impact assessment for blackhole default route"""
        impact = self.analyzer._assess_route_impact("0.0.0.0/0", "None", "")

        self.assertEqual(impact["severity"], "critical")
        self.assertIn("ALL internet traffic", impact["description"])
        self.assertIn("internet", impact["affectedTraffic"])

    def test_assess_route_impact_default_route_internet(self):
        """Test impact assessment for explicit internet default route"""
        impact = self.analyzer._assess_route_impact("0.0.0.0/0", "Internet", "")

        self.assertEqual(impact["severity"], "low")
        self.assertIn("internet", impact["affectedTraffic"])

    def test_assess_route_impact_azure_service_virtual_appliance(self):
        """Test impact assessment for Azure service route through virtual appliance"""
        impact = self.analyzer._assess_route_impact("40.112.0.0/16", "VirtualAppliance", "10.1.0.4")

        self.assertEqual(impact["severity"], "medium")
        self.assertIn("azure_services", impact["affectedTraffic"])

    def test_assess_route_impact_azure_service_blocked(self):
        """Test impact assessment for blocked Azure service route"""
        # Use 40.112.0.0/16 which is Azure services but NOT MCR
        impact = self.analyzer._assess_route_impact("40.112.0.0/16", "None", "")

        self.assertEqual(impact["severity"], "high")
        self.assertIn("azure_services", impact["affectedTraffic"])

    def test_assess_route_impact_container_registry_virtual_appliance(self):
        """Test impact assessment for container registry route through virtual appliance"""
        impact = self.analyzer._assess_route_impact("20.81.0.0/16", "VirtualAppliance", "10.1.0.4")

        self.assertEqual(impact["severity"], "medium")
        self.assertIn("container_registry", impact["affectedTraffic"])

    def test_assess_route_impact_container_registry_blocked(self):
        """Test impact assessment for blocked container registry route"""
        impact = self.analyzer._assess_route_impact("52.159.0.0/16", "None", "")

        self.assertEqual(impact["severity"], "high")
        self.assertIn("container_registry", impact["affectedTraffic"])

    def test_assess_route_impact_private_network(self):
        """Test impact assessment for private network route"""
        impact = self.analyzer._assess_route_impact("10.0.0.0/8", "VirtualAppliance", "10.1.0.4")

        self.assertEqual(impact["severity"], "low")
        self.assertIn("private_network", impact["affectedTraffic"])

    def test_is_azure_service_prefix(self):
        """Test Azure service prefix detection"""
        self.assertTrue(self.analyzer._is_azure_service_prefix("13.0.0.0/8"))
        self.assertTrue(self.analyzer._is_azure_service_prefix("20.81.0.0/16"))
        self.assertTrue(self.analyzer._is_azure_service_prefix("52.168.0.0/16"))
        self.assertTrue(self.analyzer._is_azure_service_prefix("168.63.129.16/32"))
        self.assertFalse(self.analyzer._is_azure_service_prefix("8.8.8.8/32"))
        self.assertFalse(self.analyzer._is_azure_service_prefix("1.1.1.1/32"))

    def test_is_container_registry_prefix(self):
        """Test container registry prefix detection"""
        self.assertTrue(self.analyzer._is_container_registry_prefix("20.81.0.0/16"))
        self.assertTrue(self.analyzer._is_container_registry_prefix("20.117.0.0/16"))
        self.assertTrue(self.analyzer._is_container_registry_prefix("52.159.0.0/16"))
        self.assertTrue(self.analyzer._is_container_registry_prefix("52.168.0.0/16"))
        self.assertFalse(self.analyzer._is_container_registry_prefix("20.0.0.0/8"))
        self.assertFalse(self.analyzer._is_container_registry_prefix("52.0.0.0/8"))

    def test_is_private_network_prefix(self):
        """Test private network prefix detection (RFC 1918)"""
        self.assertTrue(self.analyzer._is_private_network_prefix("10.0.0.0/8"))
        self.assertTrue(self.analyzer._is_private_network_prefix("172.16.0.0/12"))
        self.assertTrue(self.analyzer._is_private_network_prefix("172.24.0.0/16"))
        self.assertTrue(self.analyzer._is_private_network_prefix("192.168.0.0/16"))
        self.assertFalse(self.analyzer._is_private_network_prefix("8.8.8.8/32"))
        self.assertFalse(self.analyzer._is_private_network_prefix("1.1.1.1/32"))

    def test_categorize_route_critical(self):
        """Test categorization of critical routes"""
        udr_analysis = {"routeTables": [], "criticalRoutes": [], "virtualApplianceRoutes": [], "internetRoutes": []}

        route = {
            "name": "blackhole-route",
            "addressPrefix": "0.0.0.0/0",
            "nextHopType": "None",
            "nextHopIpAddress": "",
            "impact": {"severity": "critical", "description": "Blocks all traffic", "affectedTraffic": ["internet"]},
        }

        self.analyzer._categorize_route(route, udr_analysis)

        self.assertEqual(len(udr_analysis["criticalRoutes"]), 1)
        self.assertEqual(len(udr_analysis["internetRoutes"]), 1)

    def test_categorize_route_virtual_appliance(self):
        """Test categorization of virtual appliance routes"""
        udr_analysis = {"routeTables": [], "criticalRoutes": [], "virtualApplianceRoutes": [], "internetRoutes": []}

        route = {
            "name": "firewall-route",
            "addressPrefix": "0.0.0.0/0",
            "nextHopType": "VirtualAppliance",
            "nextHopIpAddress": "10.1.0.4",
            "impact": {"severity": "high", "description": "Routes through firewall", "affectedTraffic": ["internet"]},
        }

        self.analyzer._categorize_route(route, udr_analysis)

        self.assertEqual(len(udr_analysis["criticalRoutes"]), 1)  # high severity
        self.assertEqual(len(udr_analysis["virtualApplianceRoutes"]), 1)
        self.assertEqual(len(udr_analysis["internetRoutes"]), 1)  # 0.0.0.0/0

    def test_categorize_route_internet(self):
        """Test categorization of internet routes"""
        udr_analysis = {"routeTables": [], "criticalRoutes": [], "virtualApplianceRoutes": [], "internetRoutes": []}

        route = {
            "name": "internet-route",
            "addressPrefix": "8.8.8.8/32",
            "nextHopType": "Internet",
            "nextHopIpAddress": "",
            "impact": {"severity": "info", "description": "Direct internet route", "affectedTraffic": []},
        }

        self.analyzer._categorize_route(route, udr_analysis)

        self.assertEqual(len(udr_analysis["internetRoutes"]), 1)
        self.assertEqual(len(udr_analysis["criticalRoutes"]), 0)  # info severity

    def test_analyze_full_workflow(self):
        """Test complete analysis workflow"""
        # Mock subscription ID check
        self.mock_sdk_client.subscription_id = "sub1"

        # Mock parse_resource_id for subnet
        def parse_side_effect(resource_id):
            if "subnets" in resource_id:
                return {
                    "subscription_id": "sub1",
                    "resource_group": "rg1",
                    "parent_name": "vnet1",
                    "resource_name": "subnet1",
                }
            else:  # route table
                return {"subscription_id": "sub1", "resource_group": "rg1", "resource_name": "rt1"}

        self.mock_sdk_client.parse_resource_id.side_effect = parse_side_effect

        # Mock subnet object
        mock_subnet = Mock()
        mock_subnet.route_table = Mock()
        mock_subnet.route_table.id = (
            "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Network/routeTables/rt1"
        )
        mock_subnet.as_dict.return_value = {
            "name": "subnet1",
            "routeTable": {"id": "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Network/routeTables/rt1"},
        }

        # Mock route objects
        mock_route1 = Mock()
        mock_route1.name = "default-to-firewall"
        mock_route1.address_prefix = "0.0.0.0/0"
        mock_route1.next_hop_type = "VirtualAppliance"
        mock_route1.next_hop_ip_address = "10.1.0.4"
        mock_route1.provisioning_state = "Succeeded"
        mock_route1.as_dict.return_value = {
            "name": "default-to-firewall",
            "addressPrefix": "0.0.0.0/0",
            "nextHopType": "VirtualAppliance",
            "nextHopIpAddress": "10.1.0.4",
            "provisioningState": "Succeeded",
        }

        mock_route2 = Mock()
        mock_route2.name = "private-network"
        mock_route2.address_prefix = "10.0.0.0/8"
        mock_route2.next_hop_type = "VirtualAppliance"
        mock_route2.next_hop_ip_address = "10.1.0.4"
        mock_route2.provisioning_state = "Succeeded"
        mock_route2.as_dict.return_value = {
            "name": "private-network",
            "addressPrefix": "10.0.0.0/8",
            "nextHopType": "VirtualAppliance",
            "nextHopIpAddress": "10.1.0.4",
            "provisioningState": "Succeeded",
        }

        # Mock route table object
        mock_route_table = Mock()
        mock_route_table.name = "rt1"
        mock_route_table.disable_bgp_route_propagation = False
        mock_route_table.routes = [mock_route1, mock_route2]
        mock_route_table.as_dict.return_value = {
            "name": "rt1",
            "disableBgpRoutePropagation": False,
            "routes": [mock_route1.as_dict.return_value, mock_route2.as_dict.return_value],
        }

        self.mock_sdk_client.network_client.subnets.get.return_value = mock_subnet
        self.mock_sdk_client.network_client.route_tables.get.return_value = mock_route_table

        result = self.analyzer.analyze()

        # Verify results
        self.assertEqual(len(result["routeTables"]), 1)
        self.assertEqual(len(result["criticalRoutes"]), 1)  # default route is high severity
        self.assertEqual(len(result["virtualApplianceRoutes"]), 2)  # both routes
        self.assertEqual(len(result["internetRoutes"]), 1)  # only default route

        # Verify route table details
        rt = result["routeTables"][0]
        self.assertEqual(rt["name"], "rt1")
        self.assertEqual(len(rt["routes"]), 2)

    def test_analyze_error_handling(self):
        """Test error handling during analysis"""
        # Mock subscription ID check
        self.mock_sdk_client.subscription_id = "sub1"

        # Mock parse_resource_id
        self.mock_sdk_client.parse_resource_id.return_value = {
            "subscription_id": "sub1",
            "resource_group": "rg1",
            "parent_name": "vnet1",
            "resource_name": "subnet1",
        }

        # Mock exception during subnet retrieval
        self.mock_sdk_client.network_client.subnets.get.side_effect = Exception("Network error")

        # Should not raise exception, just log and continue
        result = self.analyzer.analyze()

        self.assertEqual(result["routeTables"], [])


if __name__ == "__main__":
    unittest.main()
