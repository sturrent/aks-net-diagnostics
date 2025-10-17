"""
Azure CLI command executor with improved error handling
"""

import json
import logging
import os
import subprocess
from typing import Any, List, Optional

from .exceptions import AzureAuthenticationError, AzureCLIError
from .validators import InputValidator

# Platform detection for subprocess shell parameter
IS_WINDOWS = os.name == "nt"


class AzureCLIExecutor:
    """Executes Azure CLI commands with error handling"""

    # Configuration constants
    AZURE_CLI_TIMEOUT = 90

    def __init__(self):
        """Initialize Azure CLI executor"""
        self.logger = logging.getLogger("aks_net_diagnostics.azure_cli")

    def execute(self, cmd: List[str], expect_json: bool = True, timeout: Optional[int] = None) -> Any:
        """
        Execute Azure CLI command

        Args:
            cmd: Command arguments (without 'az' prefix)
            expect_json: Whether to parse output as JSON
            timeout: Optional custom timeout in seconds (defaults to AZURE_CLI_TIMEOUT)

        Returns:
            Command output (parsed JSON if expect_json=True, raw string otherwise)

        Raises:
            AzureCLIError: If command execution fails
        """
        # Validate command arguments to prevent injection
        InputValidator.validate_azure_cli_command(cmd)

        # Add -o json if expecting JSON output and not already present
        if expect_json and "-o" not in cmd and "--output" not in cmd:
            cmd = cmd + ["-o", "json"]

        cmd_str = " ".join(cmd)

        # Use custom timeout or default
        cmd_timeout = timeout if timeout is not None else self.AZURE_CLI_TIMEOUT

        try:
            result = subprocess.run(
                ["az"] + cmd, capture_output=True, text=True, check=True, timeout=cmd_timeout, shell=IS_WINDOWS
            )

            output = result.stdout.strip()
            if not output:
                return {} if expect_json else ""

            if expect_json:
                try:
                    data = json.loads(output)
                    return data
                except json.JSONDecodeError:
                    # If JSON parsing fails, return the raw output
                    self.logger.warning(f"Failed to parse JSON from command: {cmd_str}")
                    return output
            else:
                return output

        except subprocess.TimeoutExpired as e:
            self.logger.error(f"Azure CLI command timed out after {cmd_timeout}s: {cmd_str}")
            raise AzureCLIError(f"Command timed out after {cmd_timeout}s", command=cmd_str) from e

        except subprocess.CalledProcessError as e:
            stderr_output = e.stderr.strip() if e.stderr else ""
            stdout_output = e.stdout.strip() if e.stdout else ""

            self.logger.error(f"Azure CLI command failed: {cmd_str}")
            if stderr_output:
                self.logger.error(f"Error: {stderr_output}")
            elif stdout_output:
                self.logger.error(f"Output: {stdout_output}")

            # Check for authentication errors
            if "az login" in stderr_output.lower() or "authentication" in stderr_output.lower():
                raise AzureAuthenticationError("Not authenticated to Azure. Please run 'az login'") from e

            raise AzureCLIError(
                f"Command failed: {stderr_output or stdout_output or 'Unknown error'}",
                command=cmd_str,
                stderr=stderr_output,
            ) from e

    def check_prerequisites(self) -> bool:
        """
        Check if Azure CLI is available and user is authenticated

        Returns:
            True if prerequisites are met

        Raises:
            FileNotFoundError: If Azure CLI is not installed
            AzureAuthenticationError: If not authenticated
        """
        # Check Azure CLI
        try:
            subprocess.run(
                ["az", "--version"], capture_output=True, check=True, timeout=self.AZURE_CLI_TIMEOUT, shell=IS_WINDOWS
            )
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            raise FileNotFoundError(
                "Azure CLI is not installed or not in PATH. "
                "Please install from: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
            ) from e

        # Check if logged in
        try:
            subprocess.run(
                ["az", "account", "show"],
                capture_output=True,
                check=True,
                timeout=self.AZURE_CLI_TIMEOUT,
                shell=IS_WINDOWS,
            )
        except subprocess.CalledProcessError as e:
            raise AzureAuthenticationError("Not logged in to Azure. Please run 'az login' first.") from e

        return True

    def set_subscription(self, subscription: str) -> str:
        """
        Set active Azure subscription

        Args:
            subscription: Subscription ID or name

        Returns:
            Subscription ID that was set

        Raises:
            AzureCLIError: If setting subscription fails
        """
        try:
            subprocess.run(
                ["az", "account", "set", "--subscription", subscription],
                capture_output=True,
                check=True,
                timeout=self.AZURE_CLI_TIMEOUT,
            )
            self.logger.info(f"Using Azure subscription: {subscription}")
            return subscription
        except subprocess.CalledProcessError as e:
            raise AzureCLIError(
                f"Failed to set subscription: {subscription}", stderr=e.stderr.decode() if e.stderr else None
            ) from e

    def get_current_subscription(self) -> str:
        """
        Get current Azure subscription ID

        Returns:
            Current subscription ID
        """
        result = self.execute(["account", "show", "--query", "id", "-o", "tsv"], expect_json=False)
        if isinstance(result, str) and result.strip():
            return result.strip()
        return ""
