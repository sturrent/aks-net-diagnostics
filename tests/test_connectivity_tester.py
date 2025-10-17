"""
Unit tests for Connectivity Tester
"""

import unittest
from unittest.mock import MagicMock, Mock

from azure.core.exceptions import HttpResponseError

from aks_diagnostics.connectivity_tester import ConnectivityTester, VMSSInstance


class TestConnectivityTester(unittest.TestCase):
    """Test cases for ConnectivityTester"""

    def setUp(self):
        """Set up test fixtures"""
        self.base_cluster_info = {
            "name": "test-cluster",
            "location": "eastus",
            "nodeResourceGroup": "MC_test-rg_test-cluster_eastus",
            "fqdn": "test-cluster.hcp.eastus.azmk8s.io",
        }

        # Create a mock SDK client
        self.mock_sdk_client = MagicMock()

    def test_initialization(self):
        """Test tester initialization"""
        tester = ConnectivityTester(self.base_cluster_info, self.mock_sdk_client)

        self.assertEqual(tester.cluster_info, self.base_cluster_info)
        self.assertEqual(tester.sdk_client, self.mock_sdk_client)
        self.assertIsNotNone(tester.logger)
        self.assertFalse(tester.probe_results["enabled"])

    def test_probe_disabled(self):
        """Test when connectivity probing is disabled"""
        tester = ConnectivityTester(self.base_cluster_info, self.mock_sdk_client)
        result = tester.test_connectivity(enable_probes=False)

        self.assertFalse(result["enabled"])
        self.assertEqual(result["summary"]["total_tests"], 0)

    def test_cluster_stopped(self):
        """Test with stopped cluster"""
        cluster_info = {**self.base_cluster_info, "powerState": {"code": "Stopped"}}

        tester = ConnectivityTester(cluster_info, self.mock_sdk_client)
        result = tester.test_connectivity(enable_probes=True)

        self.assertFalse(result["enabled"])
        self.assertTrue(result.get("skipped"))
        self.assertEqual(result.get("reason"), "Cluster is stopped")

    def test_cluster_failed(self):
        """Test with failed cluster"""
        cluster_info = {**self.base_cluster_info, "provisioningState": "Failed"}

        tester = ConnectivityTester(cluster_info, self.mock_sdk_client)
        # Should continue but log warning
        # We can't easily test logging, so just ensure it doesn't crash
        tester.test_connectivity(enable_probes=True)

    def test_no_vmss_instances(self):
        """Test when no VMSS instances are found"""
        # Mock empty VMSS list
        self.mock_sdk_client.compute_client.virtual_machine_scale_sets.list.return_value = []

        tester = ConnectivityTester(self.base_cluster_info, self.mock_sdk_client)
        result = tester.test_connectivity(enable_probes=True)

        self.assertTrue(result["enabled"])
        self.assertEqual(result["summary"]["total_tests"], 0)

    def test_get_api_server_fqdn_public(self):
        """Test getting API server FQDN for public cluster"""
        tester = ConnectivityTester(self.base_cluster_info, self.mock_sdk_client)
        fqdn = tester._get_api_server_fqdn()

        self.assertEqual(fqdn, "test-cluster.hcp.eastus.azmk8s.io")

    def test_get_api_server_fqdn_private(self):
        """Test getting API server FQDN for private cluster"""
        cluster_info = {**self.base_cluster_info, "privateFqdn": "test-cluster.privatelink.eastus.azmk8s.io"}

        tester = ConnectivityTester(cluster_info, self.mock_sdk_client)
        fqdn = tester._get_api_server_fqdn()

        self.assertEqual(fqdn, "test-cluster.privatelink.eastus.azmk8s.io")

    def test_get_api_server_fqdn_no_fqdn(self):
        """Test when no FQDN is available"""
        cluster_info = {"name": "test-cluster"}

        tester = ConnectivityTester(cluster_info, self.mock_sdk_client)
        fqdn = tester._get_api_server_fqdn()

        self.assertIsNone(fqdn)

    def test_parse_vmss_message_success(self):
        """Test parsing successful VMSS command response"""
        message = {
            "value": [
                {"code": "ComponentStatus/StdOut/succeeded", "message": "test output"},
                {"code": "ComponentStatus/StdErr/succeeded", "message": ""},
                {"code": "ProvisioningState/succeeded", "message": "exitCode: 0"},
            ]
        }

        tester = ConnectivityTester(self.base_cluster_info, self.mock_sdk_client)
        result = tester._parse_vmss_message(message)

        self.assertEqual(result["stdout"], "test output")
        self.assertEqual(result["stderr"], "")
        self.assertEqual(result["exit_code"], 0)

    def test_parse_vmss_message_failure(self):
        """Test parsing failed VMSS command response"""
        message = {
            "value": [
                {"code": "ComponentStatus/StdOut/succeeded", "message": ""},
                {"code": "ComponentStatus/StdErr/succeeded", "message": "error occurred"},
                {"code": "ProvisioningState/failed", "message": "Command execution finished with exitCode: 1"},
            ]
        }

        tester = ConnectivityTester(self.base_cluster_info, self.mock_sdk_client)
        result = tester._parse_vmss_message(message)

        self.assertEqual(result["stdout"], "")
        self.assertEqual(result["stderr"], "error occurred")
        self.assertEqual(result["exit_code"], 1)

    def test_check_expected_output(self):
        """Test checking for expected output"""
        tester = ConnectivityTester(self.base_cluster_info, self.mock_sdk_client)

        # Should find keyword
        self.assertTrue(tester._check_expected_output("Connection successful", ["successful"]))

        # Should be case-insensitive
        self.assertTrue(tester._check_expected_output("Connection successful", ["SUCCESSFUL"]))

        # Should not find missing keyword
        self.assertFalse(tester._check_expected_output("Connection failed", ["successful"]))

        # Empty keywords should pass
        self.assertTrue(tester._check_expected_output("any output", []))

    def test_check_expected_output_combined_http(self):
        """Test combined output check for HTTP tests"""
        tester = ConnectivityTester(self.base_cluster_info, self.mock_sdk_client)

        test = {"name": "HTTP Connectivity"}
        stdout = "200"
        stderr = "Connected to server\\nHTTP/1.1 200 OK"

        # Should check both stdout and stderr for HTTP tests
        result = tester._check_expected_output_combined(test, stdout, stderr, ["200"])
        self.assertTrue(result)

        # Should find in stderr
        result = tester._check_expected_output_combined(test, "", stderr, ["Connected"])
        self.assertTrue(result)

    def test_check_expected_output_combined_dns(self):
        """Test combined output check for DNS tests"""
        tester = ConnectivityTester(self.base_cluster_info, self.mock_sdk_client)

        test = {"name": "DNS Resolution"}
        stdout = "Server: 168.63.129.16\\nAddress: 10.0.0.1"
        stderr = ""

        # Should check only stdout for DNS tests
        result = tester._check_expected_output_combined(test, stdout, stderr, ["Address"])
        self.assertTrue(result)

    def test_validate_private_dns_resolution_private_ip(self):
        """Test validation of private DNS resolution"""
        nslookup_output = """Server: 168.63.129.16
Address: 168.63.129.16

Non-authoritative answer:
Name: test-cluster.privatelink.eastus.azmk8s.io
Address: 10.0.0.5"""

        tester = ConnectivityTester(self.base_cluster_info, self.mock_sdk_client)
        result = tester._validate_private_dns_resolution(nslookup_output, "test-cluster.privatelink.eastus.azmk8s.io")

        self.assertTrue(result)

    def test_validate_private_dns_resolution_public_ip(self):
        """Test validation fails for public IP"""
        nslookup_output = """Server: 168.63.129.16
Address: 168.63.129.16

Non-authoritative answer:
Name: test-cluster.eastus.azmk8s.io
Address: 20.62.130.50"""

        tester = ConnectivityTester(self.base_cluster_info, self.mock_sdk_client)
        result = tester._validate_private_dns_resolution(nslookup_output, "test-cluster.eastus.azmk8s.io")

        self.assertFalse(result)

    def test_validate_private_dns_resolution_nxdomain(self):
        """Test validation fails for NXDOMAIN"""
        nslookup_output = """Server: 168.63.129.16
Address: 168.63.129.16

** server can't find test-cluster.privatelink.eastus.azmk8s.io: NXDOMAIN"""

        tester = ConnectivityTester(self.base_cluster_info, self.mock_sdk_client)
        result = tester._validate_private_dns_resolution(nslookup_output, "test-cluster.privatelink.eastus.azmk8s.io")

        self.assertFalse(result)

    def test_list_ready_vmss_instances_success(self):
        """Test listing ready VMSS instances"""
        # Mock VMSS
        mock_vmss = Mock()
        mock_vmss.name = "aks-agentpool-vmss"

        # Mock VMSS instance
        mock_vm = Mock()
        mock_vm.instance_id = "0"
        mock_vm.provisioning_state = "Succeeded"
        mock_vm.os_profile = Mock()
        mock_vm.os_profile.computer_name = "aks-agentpool-0"

        self.mock_sdk_client.compute_client.virtual_machine_scale_sets.list.return_value = [mock_vmss]
        self.mock_sdk_client.compute_client.virtual_machine_scale_set_vms.list.return_value = [mock_vm]

        tester = ConnectivityTester(self.base_cluster_info, self.mock_sdk_client)
        instances = tester._list_ready_vmss_instances()

        self.assertEqual(len(instances), 1)
        self.assertEqual(instances[0].vmss_name, "aks-agentpool-vmss")
        self.assertEqual(instances[0].instance_id, "0")
        self.assertEqual(instances[0].computer_name, "aks-agentpool-0")
        self.assertEqual(instances[0].provisioning_state, "Succeeded")

    def test_list_ready_vmss_instances_no_resource_group(self):
        """Test when node resource group is missing"""
        cluster_info = {"name": "test-cluster"}

        tester = ConnectivityTester(cluster_info, self.mock_sdk_client)
        instances = tester._list_ready_vmss_instances()

        self.assertEqual(len(instances), 0)

    def test_list_ready_vmss_instances_error(self):
        """Test handling of SDK errors"""
        self.mock_sdk_client.compute_client.virtual_machine_scale_sets.list.side_effect = HttpResponseError(
            "Azure SDK error"
        )

        tester = ConnectivityTester(self.base_cluster_info, self.mock_sdk_client)
        instances = tester._list_ready_vmss_instances()

        self.assertEqual(len(instances), 0)

    def test_vmss_instance_dataclass(self):
        """Test VMSSInstance dataclass"""
        instance = VMSSInstance(
            vmss_name="test-vmss", instance_id="0", computer_name="test-node-0", provisioning_state="Succeeded"
        )

        self.assertEqual(instance.vmss_name, "test-vmss")
        self.assertEqual(instance.instance_id, "0")
        self.assertEqual(instance.computer_name, "test-node-0")
        self.assertEqual(instance.provisioning_state, "Succeeded")

    def test_curl_error_detection(self):
        """Test that curl errors are properly detected even with exit code 0"""
        tester = ConnectivityTester(self.base_cluster_info, self.mock_sdk_client)

        # Simulate response with curl SSL error (like the firewall blocking case)
        test = {"name": "API Server HTTPS Connectivity", "expected_keywords": ["200", "401", "403"], "critical": True}

        result = {
            "test_name": "API Server HTTPS Connectivity",
            "status": "error",
            "stdout": "",
            "stderr": "",
            "exit_code": None,
            "analysis": "",
            "critical": True,
        }

        response = {
            "value": [
                {
                    "code": "ProvisioningState/succeeded",
                    "message": "Enable succeeded: \n[stdout]\n\n[stderr]\n* Connected to server (1.2.3.4) port 443 (#0)\n* error:0A000126:SSL routines::unexpected eof while reading\ncurl: (35) error:0A000126:SSL routines::unexpected eof while reading",
                }
            ]
        }

        analyzed_result = tester._analyze_test_result(test, response, result)

        # Should detect the curl error and mark as failed
        self.assertEqual(analyzed_result["status"], "failed")
        self.assertIn("curl error", analyzed_result["analysis"].lower())


if __name__ == "__main__":
    unittest.main()
