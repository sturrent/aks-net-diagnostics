"""
Unit tests for NSG Analyzer module.
"""

import unittest
from unittest.mock import Mock, MagicMock, patch
from aks_diagnostics.nsg_analyzer import NSGAnalyzer
from aks_diagnostics.models import FindingCode, Severity
from aks_diagnostics.exceptions import AzureCLIError


class TestNSGAnalyzer(unittest.TestCase):
    """Test cases for NSGAnalyzer class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.azure_cli = Mock()
        self.cluster_info = {
            "name": "test-cluster",
            "resourceGroup": "test-rg",
            "location": "eastus",
            "apiServerAccessProfile": {
                "enablePrivateCluster": False
            }
        }
        self.vmss_info = [
            {
                "name": "aks-nodepool1-12345678-vmss",
                "virtualMachineProfile": {
                    "networkProfile": {
                        "networkInterfaceConfigurations": [
                            {
                                "name": "nic-0",
                                "ipConfigurations": [
                                    {
                                        "subnet": {
                                            "id": "/subscriptions/sub-id/resourceGroups/test-rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/subnet1"
                                        }
                                    }
                                ]
                            }
                        ]
                    }
                }
            }
        ]
    
    def test_initialization(self):
        """Test NSGAnalyzer initialization."""
        analyzer = NSGAnalyzer(self.azure_cli, self.cluster_info, self.vmss_info)
        
        self.assertEqual(analyzer.cluster_info, self.cluster_info)
        self.assertEqual(analyzer.vmss_info, self.vmss_info)
        self.assertIn("subnetNsgs", analyzer.nsg_analysis)
        self.assertIn("nicNsgs", analyzer.nsg_analysis)
        self.assertIn("requiredRules", analyzer.nsg_analysis)
        self.assertIn("blockingRules", analyzer.nsg_analysis)
        self.assertIn("interNodeCommunication", analyzer.nsg_analysis)
    
    def test_is_private_cluster_false(self):
        """Test private cluster detection for public cluster."""
        analyzer = NSGAnalyzer(self.azure_cli, self.cluster_info, self.vmss_info)
        self.assertFalse(analyzer._is_private_cluster())
    
    def test_is_private_cluster_true(self):
        """Test private cluster detection for private cluster."""
        cluster_info = self.cluster_info.copy()
        cluster_info["apiServerAccessProfile"]["enablePrivateCluster"] = True
        analyzer = NSGAnalyzer(self.azure_cli, cluster_info, self.vmss_info)
        self.assertTrue(analyzer._is_private_cluster())
    
    def test_is_private_cluster_no_profile(self):
        """Test private cluster detection when no API server profile."""
        cluster_info = {"name": "test", "resourceGroup": "test-rg"}
        analyzer = NSGAnalyzer(self.azure_cli, cluster_info, self.vmss_info)
        self.assertFalse(analyzer._is_private_cluster())
    
    def test_get_required_aks_rules_public_cluster(self):
        """Test required rules for public cluster."""
        analyzer = NSGAnalyzer(self.azure_cli, self.cluster_info, self.vmss_info)
        rules = analyzer._get_required_aks_rules(is_private_cluster=False)
        
        self.assertIn("outbound", rules)
        self.assertIn("inbound", rules)
        self.assertIsInstance(rules["outbound"], list)
        self.assertIsInstance(rules["inbound"], list)
        
        # Public cluster should have API server access rule
        rule_names = [rule["name"] for rule in rules["outbound"]]
        self.assertIn("AKS_API_Server_Access", rule_names)
    
    def test_get_required_aks_rules_private_cluster(self):
        """Test required rules for private cluster."""
        analyzer = NSGAnalyzer(self.azure_cli, self.cluster_info, self.vmss_info)
        rules = analyzer._get_required_aks_rules(is_private_cluster=True)
        
        # Private cluster should not have API server access rule
        rule_names = [rule["name"] for rule in rules["outbound"]]
        self.assertNotIn("AKS_API_Server_Access", rule_names)
        
        # Should still have essential rules
        self.assertIn("AKS_Registry_Access", rule_names)
        self.assertIn("AKS_DNS", rule_names)
    
    def test_analyze_subnet_nsgs_with_nsg(self):
        """Test subnet NSG analysis when NSG exists."""
        analyzer = NSGAnalyzer(self.azure_cli, self.cluster_info, self.vmss_info)
        
        # Mock subnet response with NSG
        subnet_response = {
            "name": "subnet1",
            "id": "/subscriptions/sub-id/resourceGroups/test-rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/subnet1",
            "networkSecurityGroup": {
                "id": "/subscriptions/sub-id/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/nsg1"
            }
        }
        
        nsg_response = {
            "name": "nsg1",
            "id": "/subscriptions/sub-id/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/nsg1",
            "securityRules": [
                {
                    "name": "AllowHTTPS",
                    "priority": 100,
                    "direction": "Outbound",
                    "access": "Allow",
                    "protocol": "TCP",
                    "destinationPortRange": "443"
                }
            ],
            "defaultSecurityRules": []
        }
        
        self.azure_cli.execute.side_effect = [subnet_response, nsg_response]
        
        analyzer._analyze_subnet_nsgs()
        
        self.assertEqual(len(analyzer.nsg_analysis["subnetNsgs"]), 1)
        self.assertEqual(analyzer.nsg_analysis["subnetNsgs"][0]["nsgName"], "nsg1")
        self.assertEqual(len(analyzer.nsg_analysis["subnetNsgs"][0]["rules"]), 1)
    
    def test_analyze_subnet_nsgs_without_nsg(self):
        """Test subnet NSG analysis when no NSG exists."""
        analyzer = NSGAnalyzer(self.azure_cli, self.cluster_info, self.vmss_info)
        
        # Mock subnet response without NSG
        subnet_response = {
            "name": "subnet1",
            "id": "/subscriptions/sub-id/resourceGroups/test-rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/subnet1"
        }
        
        self.azure_cli.execute.return_value = subnet_response
        
        analyzer._analyze_subnet_nsgs()
        
        self.assertEqual(len(analyzer.nsg_analysis["subnetNsgs"]), 0)
    
    def test_analyze_subnet_nsgs_cli_error(self):
        """Test subnet NSG analysis handles CLI errors gracefully."""
        analyzer = NSGAnalyzer(self.azure_cli, self.cluster_info, self.vmss_info)
        
        self.azure_cli.execute.side_effect = AzureCLIError("Network error")
        
        # Should not raise exception
        analyzer._analyze_subnet_nsgs()
        
        self.assertEqual(len(analyzer.nsg_analysis["subnetNsgs"]), 0)
    
    def test_analyze_nic_nsgs_with_nsg(self):
        """Test NIC NSG analysis when NSG exists."""
        vmss_info = [
            {
                "name": "aks-nodepool1-12345678-vmss",
                "virtualMachineProfile": {
                    "networkProfile": {
                        "networkInterfaceConfigurations": [
                            {
                                "name": "nic-0",
                                "networkSecurityGroup": {
                                    "id": "/subscriptions/sub-id/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/nic-nsg"
                                },
                                "ipConfigurations": []
                            }
                        ]
                    }
                }
            }
        ]
        
        analyzer = NSGAnalyzer(self.azure_cli, self.cluster_info, vmss_info)
        
        nsg_response = {
            "name": "nic-nsg",
            "id": "/subscriptions/sub-id/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/nic-nsg",
            "securityRules": [],
            "defaultSecurityRules": []
        }
        
        self.azure_cli.execute.return_value = nsg_response
        
        analyzer._analyze_nic_nsgs()
        
        self.assertEqual(len(analyzer.nsg_analysis["nicNsgs"]), 1)
        self.assertEqual(analyzer.nsg_analysis["nicNsgs"][0]["nsgName"], "nic-nsg")
        self.assertEqual(analyzer.nsg_analysis["nicNsgs"][0]["vmssName"], "aks-nodepool1-12345678-vmss")
    
    def test_analyze_inter_node_communication_no_issues(self):
        """Test inter-node communication analysis with no blocking rules."""
        analyzer = NSGAnalyzer(self.azure_cli, self.cluster_info, self.vmss_info)
        
        analyzer.nsg_analysis["subnetNsgs"] = [
            {
                "nsgName": "test-nsg",
                "rules": [
                    {
                        "name": "AllowVnetInbound",
                        "priority": 100,
                        "direction": "Inbound",
                        "access": "Allow",
                        "sourceAddressPrefix": "VirtualNetwork"
                    }
                ],
                "defaultRules": []
            }
        ]
        
        analyzer._analyze_inter_node_communication()
        
        self.assertEqual(analyzer.nsg_analysis["interNodeCommunication"]["status"], "ok")
        self.assertEqual(len(analyzer.nsg_analysis["interNodeCommunication"]["issues"]), 0)
    
    def test_analyze_inter_node_communication_with_blocking_rule(self):
        """Test inter-node communication analysis with blocking rules."""
        analyzer = NSGAnalyzer(self.azure_cli, self.cluster_info, self.vmss_info)
        
        analyzer.nsg_analysis["subnetNsgs"] = [
            {
                "nsgName": "test-nsg",
                "subnetId": "/subscriptions/sub-id/resourceGroups/test-rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/subnet1",
                "rules": [
                    {
                        "name": "DenyVnetInbound",
                        "priority": 100,
                        "direction": "Inbound",
                        "access": "Deny",
                        "sourceAddressPrefix": "VirtualNetwork",
                        "destinationAddressPrefix": "*",
                        "protocol": "*",
                        "destinationPortRange": "*"
                    }
                ],
                "defaultRules": []
            }
        ]
        
        analyzer._analyze_inter_node_communication()
        
        self.assertEqual(analyzer.nsg_analysis["interNodeCommunication"]["status"], "potential_issues")
        self.assertEqual(len(analyzer.nsg_analysis["interNodeCommunication"]["issues"]), 1)
        self.assertEqual(len(analyzer.get_findings()), 1)
        self.assertEqual(analyzer.get_findings()[0].code, FindingCode.NSG_INTER_NODE_BLOCKED)
    
    def test_is_vnet_source(self):
        """Test VirtualNetwork source detection."""
        analyzer = NSGAnalyzer(self.azure_cli, self.cluster_info, self.vmss_info)
        
        self.assertTrue(analyzer._is_vnet_source("*"))
        self.assertTrue(analyzer._is_vnet_source("VirtualNetwork"))
        self.assertTrue(analyzer._is_vnet_source("10.0.0.0/8"))
        self.assertTrue(analyzer._is_vnet_source("192.168.1.0/24"))
        self.assertTrue(analyzer._is_vnet_source("172.16.0.0/12"))
        self.assertFalse(analyzer._is_vnet_source("AzureLoadBalancer"))
        self.assertFalse(analyzer._is_vnet_source("Internet"))
    
    def test_blocks_aks_traffic(self):
        """Test AKS traffic blocking detection."""
        analyzer = NSGAnalyzer(self.azure_cli, self.cluster_info, self.vmss_info)
        
        # Should detect blocking
        self.assertTrue(analyzer._blocks_aks_traffic("*", "443", "TCP"))
        self.assertTrue(analyzer._blocks_aks_traffic("Internet", "443", "TCP"))
        self.assertTrue(analyzer._blocks_aks_traffic("*", "*", "TCP"))
        self.assertTrue(analyzer._blocks_aks_traffic("*", "443", "*"))
        
        # Should not detect blocking
        self.assertFalse(analyzer._blocks_aks_traffic("10.0.0.0/8", "443", "TCP"))
        self.assertFalse(analyzer._blocks_aks_traffic("*", "80", "TCP"))
        self.assertFalse(analyzer._blocks_aks_traffic("*", "443", "UDP"))
    
    def test_check_rule_precedence_with_override(self):
        """Test rule precedence checking with overriding allow rule."""
        analyzer = NSGAnalyzer(self.azure_cli, self.cluster_info, self.vmss_info)
        
        deny_rule = {
            "name": "DenyAllOutbound",
            "priority": 200,
            "direction": "Outbound",
            "access": "Deny",
            "destinationAddressPrefix": "*",
            "destinationPortRange": "*",
            "protocol": "*"
        }
        
        allow_rule = {
            "name": "AllowAzureOutbound",
            "priority": 100,
            "direction": "Outbound",
            "access": "Allow",
            "destinationAddressPrefix": "AzureCloud",
            "destinationPortRange": "443",
            "protocol": "TCP"
        }
        
        sorted_rules = [allow_rule, deny_rule]
        
        is_overridden, overriding_rules = analyzer._check_rule_precedence(deny_rule, sorted_rules)
        
        self.assertTrue(is_overridden)
        self.assertEqual(len(overriding_rules), 1)
        self.assertEqual(overriding_rules[0]["ruleName"], "AllowAzureOutbound")
    
    def test_check_rule_precedence_without_override(self):
        """Test rule precedence checking without overriding rule."""
        analyzer = NSGAnalyzer(self.azure_cli, self.cluster_info, self.vmss_info)
        
        deny_rule = {
            "name": "DenyAllOutbound",
            "priority": 100,
            "direction": "Outbound",
            "access": "Deny",
            "destinationAddressPrefix": "*",
            "destinationPortRange": "*",
            "protocol": "*"
        }
        
        sorted_rules = [deny_rule]
        
        is_overridden, overriding_rules = analyzer._check_rule_precedence(deny_rule, sorted_rules)
        
        self.assertFalse(is_overridden)
        self.assertEqual(len(overriding_rules), 0)
    
    def test_rules_overlap_destination(self):
        """Test rule overlap detection for destination."""
        analyzer = NSGAnalyzer(self.azure_cli, self.cluster_info, self.vmss_info)
        
        deny_rule = {
            "destinationAddressPrefix": "*",
            "destinationPortRange": "443",
            "protocol": "TCP"
        }
        
        allow_rule_overlap = {
            "destinationAddressPrefix": "AzureCloud",
            "destinationPortRange": "443",
            "protocol": "TCP"
        }
        
        allow_rule_no_overlap = {
            "destinationAddressPrefix": "10.0.0.0/8",
            "destinationPortRange": "443",
            "protocol": "TCP"
        }
        
        self.assertTrue(analyzer._rules_overlap(deny_rule, allow_rule_overlap))
        self.assertFalse(analyzer._rules_overlap(deny_rule, allow_rule_no_overlap))
    
    def test_rules_overlap_port(self):
        """Test rule overlap detection for ports."""
        analyzer = NSGAnalyzer(self.azure_cli, self.cluster_info, self.vmss_info)
        
        deny_rule = {
            "destinationAddressPrefix": "*",
            "destinationPortRange": "443",
            "protocol": "TCP"
        }
        
        allow_rule_overlap = {
            "destinationAddressPrefix": "*",
            "destinationPortRange": "*",
            "protocol": "TCP"
        }
        
        allow_rule_no_overlap = {
            "destinationAddressPrefix": "*",
            "destinationPortRange": "80",
            "protocol": "TCP"
        }
        
        self.assertTrue(analyzer._rules_overlap(deny_rule, allow_rule_overlap))
        self.assertFalse(analyzer._rules_overlap(deny_rule, allow_rule_no_overlap))
    
    def test_rules_overlap_protocol(self):
        """Test rule overlap detection for protocol."""
        analyzer = NSGAnalyzer(self.azure_cli, self.cluster_info, self.vmss_info)
        
        deny_rule = {
            "destinationAddressPrefix": "*",
            "destinationPortRange": "443",
            "protocol": "TCP"
        }
        
        allow_rule_overlap = {
            "destinationAddressPrefix": "*",
            "destinationPortRange": "443",
            "protocol": "*"
        }
        
        allow_rule_no_overlap = {
            "destinationAddressPrefix": "*",
            "destinationPortRange": "443",
            "protocol": "UDP"
        }
        
        self.assertTrue(analyzer._rules_overlap(deny_rule, allow_rule_overlap))
        self.assertFalse(analyzer._rules_overlap(deny_rule, allow_rule_no_overlap))
    
    def test_analyze_nsg_compliance_with_blocking_rule(self):
        """Test NSG compliance analysis detects blocking rules."""
        analyzer = NSGAnalyzer(self.azure_cli, self.cluster_info, self.vmss_info)
        
        analyzer.nsg_analysis["subnetNsgs"] = [
            {
                "nsgName": "test-nsg",
                "rules": [
                    {
                        "name": "DenyAllOutbound",
                        "priority": 100,
                        "direction": "Outbound",
                        "access": "Deny",
                        "destinationAddressPrefix": "*",
                        "destinationPortRange": "443",
                        "protocol": "TCP"
                    }
                ],
                "defaultRules": []
            }
        ]
        
        analyzer._analyze_nsg_compliance()
        
        self.assertEqual(len(analyzer.nsg_analysis["blockingRules"]), 1)
        self.assertEqual(analyzer.nsg_analysis["blockingRules"][0]["ruleName"], "DenyAllOutbound")
        self.assertEqual(len(analyzer.get_findings()), 1)
        self.assertEqual(analyzer.get_findings()[0].severity, Severity.CRITICAL)
    
    def test_analyze_nsg_compliance_with_overridden_blocking_rule(self):
        """Test NSG compliance analysis with overridden blocking rule."""
        analyzer = NSGAnalyzer(self.azure_cli, self.cluster_info, self.vmss_info)
        
        analyzer.nsg_analysis["subnetNsgs"] = [
            {
                "nsgName": "test-nsg",
                "rules": [
                    {
                        "name": "AllowAzureCloud",
                        "priority": 50,
                        "direction": "Outbound",
                        "access": "Allow",
                        "destinationAddressPrefix": "AzureCloud",
                        "destinationPortRange": "443",
                        "protocol": "TCP"
                    },
                    {
                        "name": "DenyAllOutbound",
                        "priority": 100,
                        "direction": "Outbound",
                        "access": "Deny",
                        "destinationAddressPrefix": "*",
                        "destinationPortRange": "443",
                        "protocol": "TCP"
                    }
                ],
                "defaultRules": []
            }
        ]
        
        analyzer._analyze_nsg_compliance()
        
        self.assertEqual(len(analyzer.nsg_analysis["blockingRules"]), 1)
        self.assertTrue(analyzer.nsg_analysis["blockingRules"][0]["isOverridden"])
        self.assertEqual(analyzer.nsg_analysis["blockingRules"][0]["effectiveSeverity"], "warning")
        self.assertEqual(len(analyzer.get_findings()), 1)
        self.assertEqual(analyzer.get_findings()[0].severity, Severity.WARNING)
    
    def test_full_analyze_workflow(self):
        """Test full analyze workflow."""
        analyzer = NSGAnalyzer(self.azure_cli, self.cluster_info, self.vmss_info)
        
        # Mock responses
        subnet_response = {
            "name": "subnet1",
            "id": "/subscriptions/sub-id/resourceGroups/test-rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/subnet1"
        }
        
        self.azure_cli.execute.return_value = subnet_response
        
        result = analyzer.analyze()
        
        self.assertIsInstance(result, dict)
        self.assertIn("subnetNsgs", result)
        self.assertIn("nicNsgs", result)
        self.assertIn("requiredRules", result)
        self.assertIn("blockingRules", result)
        self.assertIn("interNodeCommunication", result)
        self.assertIsInstance(result["requiredRules"], dict)
        self.assertIn("inbound", result["requiredRules"])
        self.assertIn("outbound", result["requiredRules"])


if __name__ == '__main__':
    unittest.main()
