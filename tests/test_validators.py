"""
Unit tests for validators module
"""

import unittest

from aks_diagnostics.exceptions import ValidationError
from aks_diagnostics.validators import InputValidator


class TestInputValidator(unittest.TestCase):
    """Test input validation"""

    def test_validate_azure_cli_command_valid(self):
        """Test valid Azure CLI commands"""
        valid_commands = [["aks", "show", "-n", "test", "-g", "rg"], ["network", "vnet", "list"], ["account", "show"]]

        for cmd in valid_commands:
            try:
                InputValidator.validate_azure_cli_command(cmd)
            except ValidationError:
                self.fail(f"Valid command rejected: {cmd}")

    def test_validate_azure_cli_command_invalid(self):
        """Test invalid Azure CLI commands"""
        invalid_commands = [
            [],  # Empty
            ["rm", "-r", "/"],  # Disallowed command
            ["aks", "show", "-n", "test; rm -rf /"],  # Injection attempt
            ["aks", "show", "$(malicious)"],  # Command substitution
        ]

        for cmd in invalid_commands:
            with self.assertRaises(ValidationError):
                InputValidator.validate_azure_cli_command(cmd)

    def test_validate_azure_cli_command_safe_arguments(self):
        """Test commands with safe special characters"""
        # Azure resource IDs should be allowed
        cmd = [
            "aks",
            "show",
            "--id",
            "/subscriptions/12345/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/cluster",
        ]
        try:
            InputValidator.validate_azure_cli_command(cmd)
        except ValidationError:
            self.fail("Valid resource ID rejected")

    def test_sanitize_filename_basic(self):
        """Test basic filename sanitization"""
        tests = [
            ("my-cluster", "my-cluster"),
            ("my/cluster", "my_cluster"),
            ("my\\cluster", "my_cluster"),
            ("../../../etc/passwd", "______etc_passwd"),  # Fixed expected value
            ("cluster<script>", "cluster_script_"),
        ]

        for input_name, expected in tests:
            result = InputValidator.sanitize_filename(input_name)
            self.assertEqual(result, expected)

    def test_sanitize_filename_length_limit(self):
        """Test filename length limiting"""
        long_name = "a" * 100
        result = InputValidator.sanitize_filename(long_name)
        self.assertLessEqual(len(result), 50)

    def test_sanitize_filename_empty(self):
        """Test empty filename handling"""
        result = InputValidator.sanitize_filename("")
        self.assertEqual(result, "unknown")

    def test_validate_resource_name_valid(self):
        """Test valid resource names"""
        valid_names = ["my-cluster", "test-rg-123", "aks_cluster_prod"]

        for name in valid_names:
            try:
                result = InputValidator.validate_resource_name(name, "cluster")
                self.assertEqual(result, name)
            except ValidationError:
                self.fail(f"Valid name rejected: {name}")

    def test_validate_resource_name_invalid(self):
        """Test invalid resource names"""
        invalid_names = [
            "",  # Empty
            " ",  # Whitespace only
            "../malicious",  # Path traversal
            "<script>alert()</script>",  # XSS attempt
            "a" * 300,  # Too long
        ]

        for name in invalid_names:
            with self.assertRaises(ValidationError):
                InputValidator.validate_resource_name(name, "cluster")

    def test_validate_subscription_id_guid(self):
        """Test GUID subscription ID validation"""
        valid_guid = "12345678-1234-1234-1234-123456789012"
        result = InputValidator.validate_subscription_id(valid_guid)
        self.assertEqual(result, valid_guid)

    def test_validate_subscription_id_name(self):
        """Test subscription name validation"""
        valid_name = "My-Subscription-Name"
        result = InputValidator.validate_subscription_id(valid_name)
        self.assertEqual(result, valid_name)

    def test_validate_subscription_id_invalid(self):
        """Test invalid subscription IDs"""
        invalid_ids = [
            "",  # Empty
            "a" * 200,  # Too long
        ]

        for sub_id in invalid_ids:
            with self.assertRaises(ValidationError):
                InputValidator.validate_subscription_id(sub_id)


if __name__ == "__main__":
    unittest.main()
