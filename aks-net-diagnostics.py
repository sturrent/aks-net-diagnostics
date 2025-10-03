#!/usr/bin/env python3
"""
AKS Network Diagnostics Script
Comprehensive read-only analysis of AKS cluster network configuration
Author: Azure Networking Diagnostics Generator
Version: 2.1
"""

import argparse
import json
import logging
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

# Import new modular components
from aks_diagnostics.nsg_analyzer import NSGAnalyzer
from aks_diagnostics.dns_analyzer import DNSAnalyzer
from aks_diagnostics.route_table_analyzer import RouteTableAnalyzer
from aks_diagnostics.api_server_analyzer import APIServerAccessAnalyzer
from aks_diagnostics.connectivity_tester import ConnectivityTester, VMSSInstance
from aks_diagnostics.outbound_analyzer import OutboundConnectivityAnalyzer
from aks_diagnostics.report_generator import ReportGenerator
from aks_diagnostics.azure_cli import AzureCLIExecutor
from aks_diagnostics.cache import CacheManager

# Configuration constants
SCRIPT_VERSION = "2.1"
MAX_FILENAME_LENGTH = 50
MAX_RESOURCE_NAME_LENGTH = 260

# Platform-specific settings
IS_WINDOWS = os.name == 'nt'
VMSS_COMMAND_TIMEOUT = 60
AZURE_CLI_TIMEOUT = 90
DEFAULT_FILE_PERMISSIONS = 0o600  # Owner read/write only (octal notation)

# Allowed Azure CLI commands for security validation
ALLOWED_AZ_COMMANDS = {
    'account', 'aks', 'network', 'vmss', 'vm'
}


def safe_print(text: str) -> None:
    """
    Print text - kept for consistency with previous versions.
    Now uses ASCII-only characters for maximum compatibility.
    """
    print(text)


class AKSNetworkDiagnostics:
    """Main class for AKS network diagnostics"""
    
    def __init__(self):
        self.aks_name: str = ""
        self.aks_rg: str = ""
        self.subscription: Optional[str] = None
        self.probe_test: bool = False
        self.json_out: Optional[str] = None
        self.no_json: bool = False
        self.verbose: bool = False
        self.cache: bool = False
        
        # Cache for Azure CLI responses
        self._cache: Dict[str, Any] = {}
        
        # Analysis results
        self.cluster_info: Dict[str, Any] = {}
        self.agent_pools: List[Dict[str, Any]] = []
        self.vnets_analysis: List[Dict[str, Any]] = []
        self.outbound_analysis: Dict[str, Any] = {}
        self.outbound_ips: List[str] = []
        self.private_dns_analysis: Dict[str, Any] = {}
        self.api_server_access_analysis: Dict[str, Any] = {}
        self.vmss_analysis: List[Dict[str, Any]] = []
        self.nsg_analysis: Dict[str, Any] = {}
        self.api_probe_results: Optional[Dict[str, Any]] = None
        self.failure_analysis: Dict[str, Any] = {"enabled": False}
        self.findings: List[Dict[str, Any]] = []
        
        # Setup logging
        self.logger = self._setup_logging()
        
        # Initialize modular components (will be set up after cache is enabled)
        self.azure_cli_executor: Optional[AzureCLIExecutor] = None
        self.cache_manager: Optional[CacheManager] = None
        self.dns_analyzer: Optional[DNSAnalyzer] = None
    
    def _setup_logging(self):
        """Configure logging with appropriate handlers and formatters"""
        # Create formatter
        formatter = logging.Formatter(
            fmt='%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        logger = logging.getLogger("aks_net_diagnostics")
        logger.propagate = False
        
        if not logger.handlers:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)
        
        logger.setLevel(logging.INFO)
        
        # Optionally add file handler for debugging
        if os.environ.get('AKS_DIAGNOSTICS_DEBUG', '').lower() == 'true' and not any(
            isinstance(handler, logging.FileHandler) and handler.baseFilename.endswith('aks-diagnostics-debug.log')
            for handler in logger.handlers
        ):
            file_handler = logging.FileHandler('aks-diagnostics-debug.log')
            file_handler.setFormatter(formatter)
            file_handler.setLevel(logging.DEBUG)
            logger.addHandler(file_handler)
            logger.setLevel(logging.DEBUG)

        return logger
    
    def parse_arguments(self):
        """Parse command line arguments"""
        parser = argparse.ArgumentParser(
            description="Performs comprehensive read-only analysis of AKS cluster network configuration",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
EXAMPLES:
  %(prog)s -n my-aks-cluster -g my-resource-group
  %(prog)s -n my-cluster -g my-rg --subscription 12345678-1234-1234-1234-123456789012
  %(prog)s -n my-cluster -g my-rg --probe-test --json-report custom-report.json
  %(prog)s -n my-cluster -g my-rg --verbose --json-report
            """
        )
        
        # Required arguments
        parser.add_argument('-n', '--name', required=True, 
                          help='AKS cluster name')
        parser.add_argument('-g', '--resource-group', required=True,
                          help='AKS resource group')
        
        # Optional arguments
        parser.add_argument('--subscription',
                          help='Azure subscription ID (overrides current context)')
        parser.add_argument('--probe-test', action='store_true',
                          help='Enable active connectivity checks from VMSS instances (WARNING: Executes commands inside cluster nodes)')
        parser.add_argument('--json-report', nargs='?', const='auto', metavar='FILENAME',
                          help='Save JSON report to file (optional: specify filename, default: auto-generated)')
        parser.add_argument('--verbose', action='store_true',
                          help='Show detailed console output (default: summary only)')
        parser.add_argument('--cache', action='store_true',
                          help='Cache Azure CLI responses for faster re-runs')
        
        args = parser.parse_args()
        
        # Validate required arguments
        self.aks_name = self._validate_resource_name(args.name, "cluster name")
        self.aks_rg = self._validate_resource_name(args.resource_group, "resource group")
        
        # Validate optional arguments
        if args.subscription:
            self.subscription = self._validate_subscription_id(args.subscription)
        else:
            self.subscription = None
            
        self.probe_test = args.probe_test
        self.json_report = args.json_report
        self.verbose = args.verbose
        self.cache = args.cache
        
        # Initialize modular components
        self.cache_manager = CacheManager(
            cache_dir=Path(".aks_cache"),
            default_ttl=3600,
            enabled=self.cache
        )
        self.azure_cli_executor = AzureCLIExecutor(cache_manager=self.cache_manager)
        
        # Handle JSON output filename
        if self.json_report:
            if self.json_report == 'auto':
                # Auto-generate filename when --json-report used without argument
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                safe_cluster_name = self._sanitize_filename(self.aks_name)
                self.json_report = f"aks-net-diagnostics_{safe_cluster_name}_{timestamp}.json"
            else:
                # Validate user-provided filename
                self.json_report = self._validate_output_path(self.json_report)
    
    def _validate_azure_cli_command(self, cmd: List[str]) -> None:
        """Validate Azure CLI command to prevent injection attacks"""
        if not cmd or not isinstance(cmd, list):
            raise ValueError("Command must be a non-empty list")
        
        # Check if the first argument is an allowed command
        if cmd[0] not in ALLOWED_AZ_COMMANDS:
            raise ValueError(f"Command '{cmd[0]}' is not allowed")
        
        # Check if this is a VMSS run-command (scripts are executed remotely, not locally)
        is_vmss_script = ('vmss' in cmd and 'run-command' in cmd and '--scripts' in cmd)
        
        # Validate that arguments don't contain shell metacharacters
        dangerous_chars = ['|', '&', ';', '(', ')', '$', '`', '\\', '"', "'", '<', '>']
        for i, arg in enumerate(cmd):
            if any(char in str(arg) for char in dangerous_chars):
                # For VMSS run-command, the --scripts argument is executed remotely on the VM
                # so it's safe to allow quotes and other characters
                if is_vmss_script and i > 0 and cmd[i-1] == '--scripts':
                    continue  # Skip validation for remote scripts
                # Allow some safe characters in specific contexts
                if not self._is_safe_argument(str(arg)):
                    raise ValueError(f"Command argument contains potentially dangerous characters: {arg}")
    
    def _is_safe_argument(self, arg: str) -> bool:
        """Check if an argument with special characters is safe"""
        # Allow Azure resource IDs which contain forward slashes
        if arg.startswith('/subscriptions/'):
            return True
        # Allow JSON queries which might contain quotes
        if arg.startswith('[') and arg.endswith(']'):
            return True
        # Allow other safe patterns as needed
        return False
    
    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize filename to prevent path traversal and invalid characters"""
        # Remove path separators and other dangerous characters
        dangerous_chars = ['/', '\\', '..', '<', '>', ':', '"', '|', '?', '*']
        sanitized = filename
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '_')
        
        # Limit length and ensure it's not empty
        sanitized = sanitized[:MAX_FILENAME_LENGTH].strip()
        if not sanitized:
            sanitized = "unknown"
        
        return sanitized
    
    def _validate_output_path(self, filepath: str) -> str:
        """Validate and sanitize output file path"""
        # Resolve the path to prevent traversal attacks
        resolved_path = Path(filepath).expanduser().resolve()
        current_dir = Path.cwd().resolve()

        try:
            resolved_path.relative_to(current_dir)
        except ValueError:
            raise ValueError("Output file path must be within the current directory")
        
        # Ensure the filename has a safe extension
        if not str(resolved_path).lower().endswith('.json'):
            resolved_path = resolved_path.with_suffix('.json')
        
        return str(resolved_path)
    
    def _validate_resource_name(self, name: str, resource_type: str) -> str:
        """Validate Azure resource name"""
        if not name or not isinstance(name, str):
            raise ValueError(f"{resource_type.capitalize()} cannot be empty")
        
        # Remove leading/trailing whitespace
        name = name.strip()
        
        # Basic length validation
        if len(name) < 1 or len(name) > MAX_RESOURCE_NAME_LENGTH:
            raise ValueError(f"{resource_type.capitalize()} must be between 1 and 260 characters")
        
        # Check for obviously malicious patterns
        dangerous_patterns = ['../', '\\', '<script>', 'javascript:', 'data:']
        for pattern in dangerous_patterns:
            if pattern.lower() in name.lower():
                raise ValueError(f"{resource_type.capitalize()} contains invalid characters")
        
        return name
    
    def _validate_subscription_id(self, subscription_id: str) -> str:
        """Validate Azure subscription ID format"""
        if not subscription_id:
            raise ValueError("Subscription ID cannot be empty")
        
        # Basic GUID format validation (loose)
        import re
        guid_pattern = r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
        
        if not re.match(guid_pattern, subscription_id):
            # Allow subscription names as well, not just GUIDs
            if len(subscription_id) < 1 or len(subscription_id) > 100:
                raise ValueError("Invalid subscription ID format")
        
        return subscription_id
    
    def run_azure_cli(self, cmd: List[str], expect_json: bool = True) -> Any:
        """Run Azure CLI command and return result"""
        # Validate command arguments to prevent injection
        self._validate_azure_cli_command(cmd)
        
        cmd_str = ' '.join(cmd)
        
        # Check cache first
        if self.cache and cmd_str in self._cache:
            return self._cache[cmd_str]
        
        try:
            result = subprocess.run(
                ['az'] + cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=AZURE_CLI_TIMEOUT,
                shell=IS_WINDOWS  # Windows needs shell=True for .cmd files
            )
            
            output = result.stdout.strip()
            if not output:
                return {} if expect_json else ""
            
            if expect_json:
                try:
                    data = json.loads(output)
                    # Cache the result
                    if self.cache:
                        self._cache[cmd_str] = data
                    return data
                except json.JSONDecodeError:
                    # If JSON parsing fails, return the raw output
                    return output
            else:
                return output
            
        except subprocess.TimeoutExpired as e:
            self.logger.error(f"Azure CLI command timed out after {AZURE_CLI_TIMEOUT}s: {cmd_str}")
            raise RuntimeError(f"Azure CLI command timed out: {cmd_str}") from e
        except subprocess.CalledProcessError as e:
            stderr_output = e.stderr.strip() if e.stderr else ''
            stdout_output = e.stdout.strip() if e.stdout else ''
            self.logger.error(f"Azure CLI command failed: {cmd_str}")
            if stderr_output:
                self.logger.error(f"Error: {stderr_output}")
            elif stdout_output:
                self.logger.error(f"Output: {stdout_output}")
            raise RuntimeError(f"Azure CLI command failed: {cmd_str}") from e
    
    def check_prerequisites(self):
        """Check if required tools are available"""
        # Check Azure CLI
        try:
            subprocess.run(['az', '--version'], capture_output=True, check=True, timeout=AZURE_CLI_TIMEOUT, shell=IS_WINDOWS)
        except (subprocess.CalledProcessError, FileNotFoundError):
            raise FileNotFoundError("Azure CLI is not installed or not in PATH")
        
        # Check if logged in
        try:
            subprocess.run(['az', 'account', 'show'], capture_output=True, check=True, timeout=AZURE_CLI_TIMEOUT, shell=IS_WINDOWS)
        except subprocess.CalledProcessError:
            raise PermissionError("Not logged in to Azure. Run 'az login' first.")
        
        # Set subscription if provided
        if self.subscription:
            try:
                subprocess.run(['az', 'account', 'set', '--subscription', self.subscription], 
                             capture_output=True, check=True, timeout=AZURE_CLI_TIMEOUT, shell=IS_WINDOWS)
                self.logger.info(f"Using Azure subscription: {self.subscription}")
            except subprocess.CalledProcessError:
                raise ValueError(f"Failed to set subscription: {self.subscription}")
        else:
            # Get current subscription
            current_sub = self.run_azure_cli(['account', 'show', '--query', 'id', '-o', 'tsv'], expect_json=False)
            if isinstance(current_sub, str) and current_sub.strip():
                self.subscription = current_sub.strip()
                self.logger.info(f"Using Azure subscription: {self.subscription}")
    
    def fetch_cluster_information(self):
        """Fetch basic cluster information"""
        self.logger.info("Fetching cluster information...")
        
        # Get cluster info
        cluster_cmd = ['aks', 'show', '-n', self.aks_name, '-g', self.aks_rg, '-o', 'json']
        cluster_result = self.run_azure_cli(cluster_cmd)
        
        if not cluster_result or not isinstance(cluster_result, dict):
            raise ValueError(f"Failed to get cluster information for {self.aks_name}. Please check the cluster name and resource group.")
        
        self.cluster_info = cluster_result
        
        # Get agent pools
        agent_pools_cmd = ['aks', 'nodepool', 'list', '-g', self.aks_rg, '--cluster-name', self.aks_name, '-o', 'json']
        agent_pools_result = self.run_azure_cli(agent_pools_cmd)
        
        if isinstance(agent_pools_result, list):
            self.agent_pools = agent_pools_result
        else:
            self.agent_pools = []
    
    def analyze_vnet_configuration(self):
        """Analyze VNet configuration"""
        self.logger.info("Analyzing VNet configuration...")
        
        # Get unique subnet IDs from agent pools
        subnet_ids = set()
        for pool in self.agent_pools:
            subnet_id = pool.get('vnetSubnetId')
            if subnet_id and subnet_id != "null":
                subnet_ids.add(subnet_id)
        
        if not subnet_ids:
            self.logger.info("Agent pools use AKS-managed VNet (vnetSubnetId not set). VNet details will be retrieved from VMSS configuration.")
            return
        
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
                # Get VNet information
                vnet_cmd = ['network', 'vnet', 'show', '-n', vnet_name, '-g', vnet_rg, '-o', 'json']
                vnet_info = self.run_azure_cli(vnet_cmd)
                
                if vnet_info:
                    vnets_map[vnet_name] = {
                        "name": vnet_name,
                        "resourceGroup": vnet_rg,
                        "id": vnet_info.get('id', ''),
                        "addressSpace": vnet_info.get('addressSpace', {}).get('addressPrefixes', []),
                        "subnets": [],
                        "peerings": []
                    }
                    
                    # Get VNet peerings
                    peering_cmd = ['network', 'vnet', 'peering', 'list', '-g', vnet_rg, '--vnet-name', vnet_name, '-o', 'json']
                    peerings = self.run_azure_cli(peering_cmd)
                    
                    if isinstance(peerings, list):
                        for peering in peerings:
                            vnets_map[vnet_name]["peerings"].append({
                                "name": peering.get('name', ''),
                                "remoteVirtualNetwork": peering.get('remoteVirtualNetwork', {}).get('id', ''),
                                "peeringState": peering.get('peeringState', ''),
                                "allowVirtualNetworkAccess": peering.get('allowVirtualNetworkAccess', False),
                                "allowForwardedTraffic": peering.get('allowForwardedTraffic', False),
                                "allowGatewayTransit": peering.get('allowGatewayTransit', False),
                                "useRemoteGateways": peering.get('useRemoteGateways', False)
                            })
        
        self.vnets_analysis = list(vnets_map.values())
    
    def analyze_outbound_connectivity(self):
        """Analyze outbound connectivity configuration using OutboundConnectivityAnalyzer"""
        analyzer = OutboundConnectivityAnalyzer(
            cluster_info=self.cluster_info,
            agent_pools=self.agent_pools,
            azure_cli=self.azure_cli_executor,
            logger=self.logger
        )
        
        self.outbound_analysis = analyzer.analyze(verbose=self.verbose)
        self.outbound_ips = analyzer.get_outbound_ips()
    
    
    def _analyze_node_subnet_udrs(self):
        """Analyze User Defined Routes on node subnets using RouteTableAnalyzer"""
        analyzer = RouteTableAnalyzer(self.agent_pools, self.azure_cli_executor)
        return analyzer.analyze()
    def analyze_vmss_configuration(self):
        """Analyze VMSS network configuration"""
        self.logger.info("Analyzing VMSS network configuration...")
        
        mc_rg = self.cluster_info.get('nodeResourceGroup', '')
        if not mc_rg:
            return
        
        # List VMSS in the managed resource group
        vmss_cmd = ['vmss', 'list', '-g', mc_rg, '-o', 'json']
        vmss_list = self.run_azure_cli(vmss_cmd)
        
        if not isinstance(vmss_list, list):
            return
        
        for vmss in vmss_list:
            vmss_name = vmss.get('name', '')
            if not vmss_name:
                continue
            
            self.logger.info(f"  - Analyzing VMSS: {vmss_name}")
            
            # Get VMSS network profile
            vmss_detail_cmd = ['vmss', 'show', '-n', vmss_name, '-g', mc_rg, '-o', 'json']
            vmss_detail = self.run_azure_cli(vmss_detail_cmd)
            
            if vmss_detail:
                network_profile = vmss_detail.get('virtualMachineProfile', {}).get('networkProfile', {})
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
                self.vmss_analysis.append(vmss_detail)
    
    def analyze_nsg_configuration(self):
        """Analyze Network Security Group configuration for AKS nodes using modular NSGAnalyzer"""
        self.logger.info("Analyzing NSG configuration...")
        
        try:
            # Create NSG analyzer instance with the new modular component
            nsg_analyzer = NSGAnalyzer(
                azure_cli=self.azure_cli_executor,
                cluster_info=self.cluster_info,
                vmss_info=self.vmss_analysis
            )
            
            # Run analysis
            self.nsg_analysis = nsg_analyzer.analyze()
            
            # Get findings from analyzer
            analyzer_findings = nsg_analyzer.get_findings()
            
            # Convert findings to dict format for compatibility with existing report generation
            for finding in analyzer_findings:
                self.findings.append(finding.to_dict())
            
            # Log summary
            subnet_count = len(self.nsg_analysis.get("subnetNsgs", []))
            nic_count = len(self.nsg_analysis.get("nicNsgs", []))
            blocking_count = len(self.nsg_analysis.get("blockingRules", []))
            
            self.logger.info(f"  Subnet NSGs: {subnet_count}")
            self.logger.info(f"  NIC NSGs: {nic_count}")
            if blocking_count > 0:
                self.logger.warning(f"  Found {blocking_count} potential blocking rule(s)")
            
        except Exception as e:
            self.logger.error(f"Failed to analyze NSG configuration: {e}")
            # Initialize with empty structure to prevent downstream errors
            self.nsg_analysis = {
                "subnetNsgs": [],
                "nicNsgs": [],
                "requiredRules": {"outbound": [], "inbound": []},
                "blockingRules": [],
                "interNodeCommunication": {"status": "unknown", "issues": []}
            }
    def analyze_private_dns(self):
        """Analyze private DNS configuration using modular DNSAnalyzer"""
        self.logger.info("Analyzing private DNS configuration...")
        
        try:
            # Create DNS analyzer instance with Azure CLI executor
            dns_analyzer = DNSAnalyzer(
                cluster_info=self.cluster_info,
                azure_cli=self.azure_cli_executor
            )
            
            # Run analysis
            self.private_dns_analysis = dns_analyzer.analyze()
            
            # Get findings from analyzer
            analyzer_findings = dns_analyzer.get_findings()
            
            # Convert findings to dict format for compatibility with existing report generation
            for finding in analyzer_findings:
                finding_dict = finding.to_dict()
                self.findings.append(finding_dict)
            
            # Store analyzer instance for later use (e.g., in connectivity tests)
            self.dns_analyzer = dns_analyzer
            
        except Exception as e:
            self.logger.error(f"Failed to analyze DNS configuration: {e}")
            # Initialize with empty structure to prevent downstream errors
            self.private_dns_analysis = {
                "type": "none",
                "isPrivateCluster": False,
                "privateDnsZone": None,
                "analysis": f"Error analyzing DNS: {e}"
            }
            self.dns_analyzer = None
    
    def analyze_api_server_access(self):
        """Analyze API server access configuration using APIServerAccessAnalyzer"""
        self.logger.info("Analyzing API server access configuration...")
        
        analyzer = APIServerAccessAnalyzer(self.cluster_info, self.outbound_ips, self.outbound_analysis)
        self.api_server_access_analysis = analyzer.analyze()
    
    def _get_current_client_ip(self):
        """Attempt to get the current client's public IP address"""
        try:
            # Try to get public IP using a simple web service
            import urllib.request
            import urllib.error
            
            response = urllib.request.urlopen('https://api.ipify.org', timeout=5)
            return response.read().decode('utf-8').strip()
        except:
            return None
    
    def check_api_connectivity(self):
        """Check API server connectivity using ConnectivityTester module"""
        tester = ConnectivityTester(self.cluster_info, self.run_azure_cli, self.dns_analyzer, verbose=self.verbose)
        self.api_probe_results = tester.test_connectivity(enable_probes=self.probe_test)
    
    def analyze_misconfigurations(self):
        """Analyze potential misconfigurations and failures"""
        self.logger.info("Analyzing potential misconfigurations...")
        
        # Add findings based on analysis
        findings = []
        
        # Check cluster power state first
        power_state = self.cluster_info.get('powerState', {})
        power_code = power_state.get('code', 'Unknown') if isinstance(power_state, dict) else str(power_state)
        
        if power_code.lower() == 'stopped':
            findings.append({
                "severity": "warning",
                "code": "CLUSTER_STOPPED",
                "message": "Cluster is in stopped state",
                "recommendation": "Start the cluster using 'az aks start' before running connectivity tests or accessing cluster resources"
            })
            # Set flag to skip connectivity tests
            self._cluster_stopped = True
        else:
            self._cluster_stopped = False
        
        # Check cluster operational state
        provisioning_state = self.cluster_info.get('provisioningState', '')
        if provisioning_state.lower() == 'failed':
            # Try to get detailed error information from cluster status
            error_info = self._get_cluster_status_error()
            
            if error_info:
                error_code, detailed_error = error_info
                findings.append({
                    "severity": "critical",
                    "code": "CLUSTER_OPERATION_FAILURE", 
                    "message": f"Cluster failed with error: {detailed_error}",
                    "error_code": error_code,  # Store the short error code for non-verbose display
                    "recommendation": "Check Azure Activity Log for detailed failure information and contact Azure support if needed"
                })
            else:
                findings.append({
                    "severity": "critical",
                    "code": "CLUSTER_OPERATION_FAILURE", 
                    "message": f"Cluster failed with error: Failed (Operation: Microsoft.ContainerService/managedClusters/stop/action)",
                    "recommendation": "Check Azure Activity Log for detailed failure information and contact Azure support if needed"
                })
        
        # Check node pool states
        failed_node_pools = []
        agent_pool_profiles = self.cluster_info.get('agentPoolProfiles', [])
        for pool in agent_pool_profiles:
            pool_state = pool.get('provisioningState', '')
            if pool_state.lower() == 'failed':
                failed_node_pools.append(pool.get('name', 'unknown'))
        
        if failed_node_pools:
            findings.append({
                "severity": "critical", 
                "code": "NODE_POOL_FAILURE",
                "message": f"Node pools in failed state: {', '.join(failed_node_pools)}",
                "recommendation": "Check node pool configuration and Azure Activity Log for detailed failure information"
            })
        
        # Check private DNS configuration for private clusters
        api_server_profile = self.cluster_info.get('apiServerAccessProfile')
        is_private = api_server_profile.get('enablePrivateCluster', False) if api_server_profile else False
        
        if is_private:
            self._analyze_private_dns_issues(findings)
        
        # Check for missing outbound IPs (only for Load Balancer and NAT Gateway outbound types)
        # For UDR, it's expected to have no public IPs since traffic goes through virtual appliance
        network_profile = self.cluster_info.get('networkProfile', {})
        outbound_type = network_profile.get('outboundType', 'loadBalancer')
        
        if not self.outbound_ips and outbound_type in ['loadBalancer', 'managedNATGateway']:
            findings.append({
                "severity": "warning",
                "code": "NO_OUTBOUND_IPS",
                "message": f"No outbound IP addresses detected for {outbound_type} outbound type",
                "recommendation": "Verify outbound connectivity configuration. Check that the load balancer or NAT gateway has public IPs assigned."
            })
        
        # Check VNet configuration issues
        self._analyze_vnet_issues(findings)
        
        # Check UDR configuration issues
        self._analyze_udr_issues(findings)
        
        # Check API server access configuration issues
        self._analyze_api_server_access_issues(findings)
        
        # Check NSG configuration issues
        self._analyze_nsg_issues(findings)
        
        # Check connectivity test results (only if cluster is running)
        if not getattr(self, '_cluster_stopped', False):
            self._analyze_connectivity_test_results(findings)
        
        # Extend existing findings instead of replacing them
        self.findings.extend(findings)
    
    def _get_cluster_status_error(self):
        """Get detailed cluster error information from status field"""
        try:
            # Check for status.errordetail in cluster info
            status = self.cluster_info.get('status', {})
            if isinstance(status, dict):
                error_detail = status.get('errordetail', {})
                if isinstance(error_detail, dict):
                    # Extract the detailed error message
                    error_message = error_detail.get('message', '')
                    error_code = error_detail.get('code', '')
                    
                    if error_message:
                        if error_code:
                            # Return tuple: (error_code, full_message)
                            return (error_code, f"{error_code}: {error_message}")
                        else:
                            return (None, error_message)
                
                # Check for provisioningError as fallback
                provisioning_error = status.get('provisioningError')
                if provisioning_error:
                    return (None, str(provisioning_error))
            
            return None
            
        except Exception as e:
            self.logger.info(f"Could not retrieve cluster status error: {e}")
            return None

    def _analyze_private_dns_issues(self, findings):
        """Analyze private DNS configuration issues"""
        if not self.private_dns_analysis:
            return
            
        # Get private DNS zone info
        api_server_profile = self.cluster_info.get('apiServerAccessProfile', {})
        private_dns_zone = api_server_profile.get('privateDnsZone', '')
        
        if private_dns_zone == 'system':
            # For system-managed private DNS zones, check for comprehensive DNS issues
            self._check_system_private_dns_issues(findings)
        elif private_dns_zone and private_dns_zone != 'system':
            # For custom private DNS zones, check VNet links
            self._check_private_dns_vnet_links(findings, private_dns_zone)
    
    def _check_system_private_dns_issues(self, findings):
        """Check system-managed private DNS zone issues"""
        try:
            # Find the system-managed private DNS zone
            cmd = ['network', 'private-dns', 'zone', 'list', '-o', 'json']
            zones = self.run_azure_cli(cmd)
            
            aks_private_zones = []
            if isinstance(zones, list):
                for zone in zones:
                    zone_name = zone.get('name', '')
                    if 'azmk8s.io' in zone_name and 'privatelink' in zone_name:
                        aks_private_zones.append(zone)
            
            if not aks_private_zones:
                return
            
            # Check each private DNS zone for VNet link issues
            for zone in aks_private_zones:
                zone_name = zone.get('name', '')
                zone_rg = zone.get('resourceGroup', '')
                
                if zone_rg and zone_name:
                    self._check_dns_server_vnet_links(findings, zone_rg, zone_name)
                    
        except Exception as e:
            self.logger.info(f"Could not analyze system private DNS issues: {e}")
    
    def _check_dns_server_vnet_links(self, findings, zone_rg, zone_name):
        """Check if VNets with custom DNS servers are properly linked to private DNS zone"""
        try:
            # Get VNet links for this private DNS zone
            cmd = ['network', 'private-dns', 'link', 'vnet', 'list', 
                  '-g', zone_rg, '-z', zone_name, '-o', 'json']
            links = self.run_azure_cli(cmd)
            
            if not isinstance(links, list):
                return
                
            linked_vnet_ids = [link.get('virtualNetwork', {}).get('id', '') for link in links]
            
            # Get cluster VNets and their DNS configurations
            cluster_vnets = self._get_cluster_vnets_with_dns()
            
            for vnet_info in cluster_vnets:
                vnet_id = vnet_info.get('id', '')
                vnet_name = vnet_info.get('name', '')
                dns_servers = vnet_info.get('dnsServers', [])
                
                # Check if this VNet uses custom DNS servers
                if dns_servers:
                    for dns_server in dns_servers:
                        # Find which VNet hosts this DNS server
                        dns_host_vnet = self._find_dns_server_host_vnet(dns_server)
                        
                        if dns_host_vnet and dns_host_vnet.get('id') not in linked_vnet_ids:
                            dns_host_vnet_name = dns_host_vnet.get('name', 'unknown')
                            findings.append({
                                "severity": "critical",
                                "code": "PDNS_DNS_HOST_VNET_LINK_MISSING",
                                "message": f"DNS server {dns_server} is hosted in VNet {dns_host_vnet_name} but this VNet is not linked to private DNS zone {zone_name}. Cluster VNet {vnet_name} uses this DNS server.",
                                "recommendation": f"Link VNet {dns_host_vnet_name} to private DNS zone {zone_name} to ensure proper DNS resolution for the private cluster"
                            })
                            
        except Exception as e:
            self.logger.info(f"Could not check DNS server VNet links: {e}")
    
    def _get_cluster_vnets_with_dns(self):
        """Get cluster VNets with their DNS configurations"""
        vnets = []
        
        # Get VNets from agent pool profiles
        agent_pools = self.cluster_info.get('agentPoolProfiles', [])
        for pool in agent_pools:
            subnet_id = pool.get('vnetSubnetId', '')
            if subnet_id:
                # Extract VNet info from subnet ID
                vnet_parts = subnet_id.split('/')
                if len(vnet_parts) >= 9:
                    vnet_rg = vnet_parts[4]
                    vnet_name = vnet_parts[8]
                    
                    # Get VNet DNS configuration
                    try:
                        cmd = ['network', 'vnet', 'show', '-g', vnet_rg, '-n', vnet_name, '-o', 'json']
                        vnet_info = self.run_azure_cli(cmd)
                        
                        if isinstance(vnet_info, dict):
                            vnets.append({
                                'id': vnet_info.get('id', ''),
                                'name': vnet_name,
                                'resourceGroup': vnet_rg,
                                'dnsServers': vnet_info.get('dhcpOptions', {}).get('dnsServers', [])
                            })
                    except Exception:
                        pass
        
        return vnets
    
    def _find_dns_server_host_vnet(self, dns_server_ip):
        """Find which VNet hosts the given DNS server IP"""
        try:
            # List all VNets and check their address spaces
            cmd = ['network', 'vnet', 'list', '-o', 'json']
            vnets = self.run_azure_cli(cmd)
            
            if not isinstance(vnets, list):
                return None
                
            import ipaddress
            dns_ip = ipaddress.ip_address(dns_server_ip)
            
            for vnet in vnets:
                address_prefixes = vnet.get('addressSpace', {}).get('addressPrefixes', [])
                for prefix in address_prefixes:
                    try:
                        network = ipaddress.ip_network(prefix, strict=False)
                        if dns_ip in network:
                            return {
                                'id': vnet.get('id', ''),
                                'name': vnet.get('name', ''),
                                'resourceGroup': vnet.get('resourceGroup', '')
                            }
                    except Exception:
                        continue
                        
        except Exception as e:
            self.logger.info(f"Could not find DNS server host VNet: {e}")
            
        return None
    
    def _check_private_dns_vnet_links(self, findings, private_dns_zone):
        """Check if VNets are properly linked to private DNS zone"""
        try:
            # Get the private DNS zone resource group and name
            if '/' in private_dns_zone:
                # Full resource ID format
                dns_zone_parts = private_dns_zone.split('/')
                dns_zone_rg = dns_zone_parts[4] if len(dns_zone_parts) > 4 else ''
                dns_zone_name = dns_zone_parts[-1] if dns_zone_parts else ''
            else:
                # Just the zone name - need to find the resource group
                dns_zone_name = private_dns_zone
                dns_zone_rg = self._find_private_dns_zone_rg(dns_zone_name)
            
            if dns_zone_rg and dns_zone_name:
                # Check VNet links for this private DNS zone
                cmd = ['network', 'private-dns', 'link', 'vnet', 'list', 
                      '-g', dns_zone_rg, '-z', dns_zone_name, '-o', 'json']
                links = self.run_azure_cli(cmd)
                
                if isinstance(links, list):
                    # Get cluster VNet info
                    cluster_vnet_ids = self._get_cluster_vnet_ids()
                    linked_vnet_ids = [link.get('virtualNetwork', {}).get('id', '') for link in links]
                    
                    # Check if cluster VNets are linked
                    for vnet_id in cluster_vnet_ids:
                        if vnet_id not in linked_vnet_ids:
                            vnet_name = vnet_id.split('/')[-1] if vnet_id else 'unknown'
                            findings.append({
                                "severity": "critical",
                                "code": "PDNS_DNS_HOST_VNET_LINK_MISSING",
                                "message": f"Cluster VNet {vnet_name} is not linked to private DNS zone {dns_zone_name}",
                                "recommendation": "Link the cluster VNet to the private DNS zone to ensure proper name resolution"
                            })
        except Exception as e:
            self.logger.info(f"Could not analyze private DNS VNet links: {e}")
    
    def _find_private_dns_zone_rg(self, zone_name):
        """Find the resource group containing the private DNS zone"""
        try:
            cmd = ['network', 'private-dns', 'zone', 'list', '-o', 'json']
            zones = self.run_azure_cli(cmd)
            if isinstance(zones, list):
                for zone in zones:
                    if zone.get('name') == zone_name:
                        return zone.get('resourceGroup', '')
        except Exception:
            pass
        return ''
    
    def _get_cluster_vnet_ids(self):
        """Get VNet IDs associated with the cluster"""
        vnet_ids = []
        
        # Get VNet from agent pool profiles
        agent_pools = self.cluster_info.get('agentPoolProfiles', [])
        for pool in agent_pools:
            subnet_id = pool.get('vnetSubnetId', '')
            if subnet_id:
                # Extract VNet ID from subnet ID
                vnet_id = '/'.join(subnet_id.split('/')[:-2])
                if vnet_id not in vnet_ids:
                    vnet_ids.append(vnet_id)
        
        return vnet_ids
    
    def _analyze_vnet_issues(self, findings):
        """Analyze VNet configuration issues"""
        # Check for subnet capacity issues
        if hasattr(self, 'vmss_analysis') and self.vmss_analysis:
            for vmss_info in self.vmss_analysis:
                network_profile = vmss_info.get('networkProfile', {})
                if network_profile.get('subnetId'):
                    # Could add subnet capacity analysis here
                    pass

    def _analyze_udr_issues(self, findings):
        """Analyze User Defined Route configuration issues"""
        udr_analysis = self.outbound_analysis.get("udrAnalysis")
        if not udr_analysis:
            return
        
        # Check for critical routes that might break connectivity
        critical_routes = udr_analysis.get("criticalRoutes", [])
        va_routes = udr_analysis.get("virtualApplianceRoutes", [])
        default_va_routes = [r for r in va_routes if r.get('addressPrefix') == '0.0.0.0/0']
        
        for route in critical_routes:
            impact = route.get("impact", {})
            severity = impact.get("severity", "info")
            route_prefix = route.get('addressPrefix', '')
            
            # Skip high-impact findings for default routes if we have a specific default route VA finding
            if severity == "high" and route_prefix == '0.0.0.0/0' and default_va_routes:
                continue
            
            if severity == "critical":
                findings.append({
                    "severity": "critical",
                    "code": "UDR_CRITICAL_ROUTE",
                    "message": f"Critical UDR detected: {route.get('name', 'unnamed')} ({route_prefix}) - {impact.get('description', '')}",
                    "recommendation": "Review and modify the route table to ensure essential AKS traffic can reach its destinations. Consider using service tags or more specific routes."
                })
            elif severity == "high":
                findings.append({
                    "severity": "error",
                    "code": "UDR_HIGH_IMPACT_ROUTE",
                    "message": f"High-impact UDR detected: {route.get('name', 'unnamed')} ({route_prefix}) - {impact.get('description', '')}",
                    "recommendation": "Verify that the virtual appliance or next hop can properly handle this traffic and has appropriate rules configured."
                })
        
        # Check for virtual appliance routes
        if va_routes:
            # Check for default route through virtual appliance
            if default_va_routes:
                outbound_type = self.outbound_analysis.get("type", "unknown")
                # Build comprehensive message for default route including all affected traffic
                affected_services = []
                if any('azure_services' in r.get('impact', {}).get('affectedTraffic', []) for r in default_va_routes):
                    affected_services.append("Azure services")
                if any('container_registry' in r.get('impact', {}).get('affectedTraffic', []) for r in default_va_routes):
                    affected_services.append("container registries")
                
                base_message = f"Default route (0.0.0.0/0) redirects all internet traffic through virtual appliance at {default_va_routes[0].get('nextHopIpAddress', 'unknown IP')}. Outbound type is {outbound_type}."
                if affected_services:
                    base_message += f" This affects: {', '.join(affected_services)}."
                
                findings.append({
                    "severity": "warning",
                    "code": "UDR_DEFAULT_ROUTE_VA",
                    "message": base_message,
                    "recommendation": "Ensure the virtual appliance is properly configured to handle AKS traffic including: container image pulls, Azure service connectivity, and API server access. Consider adding specific routes for AKS requirements."
                })
            else:
                # Only add specific service findings if there's no default route
                # Check for Azure service routes through virtual appliance
                azure_va_routes = [r for r in va_routes if r.get('impact', {}).get('affectedTraffic', []) and 'azure_services' in r.get('impact', {}).get('affectedTraffic', [])]
                if azure_va_routes:
                    route_names = [r.get('name', 'unnamed') for r in azure_va_routes]
                    findings.append({
                        "severity": "warning",
                        "code": "UDR_AZURE_SERVICES_VA",
                        "message": f"Azure service traffic is routed through virtual appliance: {', '.join(route_names)}",
                        "recommendation": "Verify the virtual appliance allows Azure service connectivity or add specific routes with nextHopType 'Internet' for required Azure services."
                    })
                
                # Check for container registry routes through virtual appliance
                mcr_va_routes = [r for r in va_routes if r.get('impact', {}).get('affectedTraffic', []) and 'container_registry' in r.get('impact', {}).get('affectedTraffic', [])]
                if mcr_va_routes:
                    route_names = [r.get('name', 'unnamed') for r in mcr_va_routes]
                    findings.append({
                        "severity": "warning", 
                        "code": "UDR_CONTAINER_REGISTRY_VA",
                        "message": f"Container registry traffic is routed through virtual appliance: {', '.join(route_names)}",
                        "recommendation": "Ensure the virtual appliance allows container registry access or add specific routes for Microsoft Container Registry (mcr.microsoft.com) endpoints."
                    })
        
        # Check for BGP route propagation issues
        route_tables = udr_analysis.get("routeTables", [])
        bgp_disabled_tables = [rt for rt in route_tables if rt.get('disableBgpRoutePropagation') == True]
        if bgp_disabled_tables:
            table_names = [rt.get('name', 'unnamed') for rt in bgp_disabled_tables]
            findings.append({
                "severity": "info",
                "code": "UDR_BGP_PROPAGATION_DISABLED",
                "message": f"BGP route propagation is disabled on route tables: {', '.join(table_names)}",
                "recommendation": "Consider the impact on connectivity if you have ExpressRoute or VPN gateways that rely on BGP route propagation."
            })
        
        # Summary finding for UDR analysis
        if route_tables:
            total_routes = sum(len(rt.get('routes', [])) for rt in route_tables)
            va_route_count = len(va_routes)
            critical_route_count = len(critical_routes)
            
            if total_routes > 0:
                outbound_type = self.outbound_analysis.get("type", "unknown")
                findings.append({
                    "severity": "info",
                    "code": "UDR_ANALYSIS_SUMMARY",
                    "message": f"UDR Analysis: Found {len(route_tables)} route table(s) with {total_routes} total routes on node subnets. {va_route_count} routes use virtual appliances, {critical_route_count} have high impact on connectivity. Cluster uses {outbound_type} outbound type.",
                    "recommendation": "Review the detailed UDR analysis in the JSON report for specific route impacts and recommendations."
                })
    
    def _analyze_api_server_access_issues(self, findings):
        """Analyze API server access configuration issues"""
        if not hasattr(self, 'api_server_access_analysis') or not self.api_server_access_analysis:
            return
        
        # Add security findings from API server access analysis
        security_findings = self.api_server_access_analysis.get("securityFindings", [])
        for security_finding in security_findings:
            severity = security_finding.get("severity", "info")
            issue = security_finding.get("issue", "Unknown issue")
            description = security_finding.get("description", "")
            recommendation = security_finding.get("recommendation", "")
            range_info = security_finding.get("range", "")
            
            # Create finding code based on issue type
            if "unrestricted access" in issue.lower():
                code = "API_UNRESTRICTED_ACCESS"
            elif "broad ip range" in issue.lower():
                code = "API_BROAD_IP_RANGE" 
            elif "outbound ips not" in issue.lower():
                # Different codes for managedNATGateway vs other outbound types
                if "managednatgateway" in issue.lower():
                    code = "API_OUTBOUND_NATGW_INFO"
                else:
                    code = "API_OUTBOUND_NOT_AUTHORIZED"
            elif "invalid ip range" in issue.lower():
                code = "API_INVALID_IP_RANGE"
            elif "redundant configuration" in issue.lower():
                code = "API_REDUNDANT_CONFIG"
            elif "unrestricted public access" in issue.lower():
                code = "API_UNRESTRICTED_PUBLIC"
            else:
                code = "API_SECURITY_ISSUE"
            
            message = f"API server access: {issue}"
            if range_info:
                message += f" ({range_info})"
            if description:
                message += f" - {description}"
            
            findings.append({
                "severity": severity,
                "code": code,
                "message": message,
                "recommendation": recommendation
            })
        
        # Add summary finding for API server access configuration
        authorized_ranges = self.api_server_access_analysis.get("authorizedIpRanges", [])
        is_private = self.api_server_access_analysis.get("privateCluster", False)
        access_model = self.api_server_access_analysis.get("accessRestrictions", {}).get("model", "unknown")
        
        if access_model == "unrestricted_public" and not security_findings:
            findings.append({
                "severity": "info",
                "code": "API_PUBLIC_UNRESTRICTED",
                "message": "API server is publicly accessible without IP restrictions",
                "recommendation": "Consider implementing authorized IP ranges or converting to a private cluster for enhanced security"
            })
        elif access_model == "restricted_public":
            findings.append({
                "severity": "info", 
                "code": "API_RESTRICTED_ACCESS",
                "message": f"API server access restricted to {len(authorized_ranges)} authorized IP range(s)",
                "recommendation": "Verify that all necessary IP ranges are included and review ranges periodically"
            })
    
    def _analyze_nsg_issues(self, findings):
        """Analyze NSG configuration issues"""
        if not hasattr(self, 'nsg_analysis') or not self.nsg_analysis:
            return
        
        # Check for blocking rules that could affect AKS functionality
        blocking_rules = self.nsg_analysis.get("blockingRules", [])
        for rule in blocking_rules:
            # Use the effective severity based on rule precedence analysis
            effective_severity = rule.get("effectiveSeverity", "critical")
            is_overridden = rule.get("isOverridden", False)
            overriding_rules = rule.get("overriddenBy", [])
            
            # Create appropriate message based on precedence
            if is_overridden:
                overriding_rule_names = [r.get('ruleName', 'unknown') for r in overriding_rules[:2]]  # Show first 2
                message = f"NSG rule '{rule.get('ruleName')}' could block AKS traffic, but higher-priority allow rules override it: {', '.join(overriding_rule_names)}"
                recommendation = f"Rule is currently ineffective due to higher-priority rules. Consider removing or adjusting priority {rule.get('priority')} for cleaner NSG configuration."
            else:
                message = f"NSG rule '{rule.get('ruleName')}' in '{rule.get('nsgName')}' may block AKS traffic"
                recommendation = f"Review NSG rule priority {rule.get('priority')} - {rule.get('impact', 'Could affect cluster functionality')}"
            
            findings.append({
                "severity": effective_severity,
                "code": "NSG_BLOCKING_AKS_TRAFFIC",
                "message": message,
                "recommendation": recommendation
            })
        
        # Check for inter-node communication issues
        inter_node = self.nsg_analysis.get("interNodeCommunication", {})
        if inter_node.get("status") == "potential_issues":
            for issue in inter_node.get("issues", []):
                nsg_name = issue.get("nsgName", "unknown")
                location = issue.get("location", "unknown")
                rule_count = len(issue.get("blockingRules", []))
                
                findings.append({
                    "severity": "warning",
                    "code": "NSG_INTER_NODE_BLOCKING",
                    "message": f"NSG '{nsg_name}' on {location} has {rule_count} rule(s) that may block inter-node communication",
                    "recommendation": "Ensure VirtualNetwork traffic is allowed between cluster nodes for proper functionality"
                })
        
        # Check NSG coverage - only report when no NSGs are found (security recommendation)
        subnet_nsgs = self.nsg_analysis.get("subnetNsgs", [])
        nic_nsgs = self.nsg_analysis.get("nicNsgs", [])
        
        if not subnet_nsgs and not nic_nsgs:
            findings.append({
                "severity": "info",
                "code": "NSG_NO_RESTRICTIONS", 
                "message": "No NSGs found on cluster node subnets or NICs",
                "recommendation": "Consider implementing NSGs for enhanced network security while ensuring AKS traffic is allowed"
            })
    
    def _analyze_connectivity_test_results(self, findings):
        """Analyze connectivity test results and add findings"""
        if not hasattr(self, 'api_probe_results') or not self.api_probe_results:
            return
        
        if not self.api_probe_results.get('enabled'):
            return
        
        summary = self.api_probe_results.get('summary', {})
        tests = self.api_probe_results.get('tests', [])
        
        failed_tests = [t for t in tests if t.get('status') == 'failed']
        error_tests = [t for t in tests if t.get('status') == 'error']
        
        # Analyze failed DNS tests
        dns_failures = [t for t in failed_tests if 'DNS Resolution' in t.get('test_name', '')]
        if dns_failures:
            dns_test_names = [t.get('test_name', '') for t in dns_failures]
            findings.append({
                "severity": "error",
                "code": "CONNECTIVITY_DNS_FAILURE",
                "message": f"DNS resolution tests failed: {', '.join(dns_test_names)}",
                "recommendation": "Check DNS server configuration and network connectivity. Verify custom DNS servers are accessible and properly configured."
            })
        
        # Analyze failed HTTP connectivity tests
        http_failures = [t for t in failed_tests if any(keyword in t.get('test_name', '') for keyword in ['HTTP', 'Connectivity', 'curl'])]
        if http_failures:
            http_test_names = [t.get('test_name', '') for t in http_failures]
            findings.append({
                "severity": "error", 
                "code": "CONNECTIVITY_HTTP_FAILURE",
                "message": f"HTTP connectivity tests failed: {', '.join(http_test_names)}",
                "recommendation": "Check outbound connectivity rules, firewall settings, and network security groups. Verify internet access from cluster nodes."
            })
        
        # Analyze API server connectivity specifically
        api_failures = [t for t in failed_tests if 'API Server' in t.get('test_name', '')]
        if api_failures:
            findings.append({
                "severity": "critical",
                "code": "CONNECTIVITY_API_SERVER_FAILURE", 
                "message": "API server connectivity test failed from cluster nodes",
                "recommendation": "Check private DNS configuration, VNet links, and API server access policies. For private clusters, ensure DNS resolution is working correctly."
            })
        
        # Analyze test execution errors
        if error_tests:
            findings.append({
                "severity": "warning",
                "code": "CONNECTIVITY_TEST_ERRORS",
                "message": f"{len(error_tests)} connectivity tests could not be executed",
                "recommendation": "Check VMSS instance status and run-command permissions. Ensure instances are running and accessible."
            })
    
    def generate_report(self):
        """Generate comprehensive report using ReportGenerator"""
        self.logger.info("Generating comprehensive report...")
        
        # Create report generator with all analysis data
        report_gen = ReportGenerator(
            cluster_name=self.aks_name,
            resource_group=self.aks_rg,
            subscription=self.subscription,
            cluster_info=self.cluster_info,
            findings=self.findings,
            vnets_analysis=self.vnets_analysis,
            outbound_analysis=self.outbound_analysis,
            outbound_ips=self.outbound_ips,
            private_dns_analysis=self.private_dns_analysis,
            api_server_access_analysis=self.api_server_access_analysis,
            vmss_analysis=self.vmss_analysis,
            nsg_analysis=self.nsg_analysis,
            api_probe_results=self.api_probe_results,
            failure_analysis=self.failure_analysis,
            script_version=SCRIPT_VERSION,
            logger=self.logger
        )
        
        # Print console report
        report_gen.print_console_report(verbose=self.verbose, json_report_path=self.json_report)
        
        # Save JSON report if requested
        if self.json_report:
            report_gen.save_json_report(self.json_report, file_permissions=DEFAULT_FILE_PERMISSIONS)
    
    def run(self):
        """Main execution method"""
        self.parse_arguments()
        
        print(f"\nAnalyzing AKS cluster: {self.aks_name} in resource group: {self.aks_rg}")
        print("=" * 74)
        
        self.check_prerequisites()
        self.fetch_cluster_information()
        self.analyze_vnet_configuration()
        self.analyze_outbound_connectivity()
        self.analyze_vmss_configuration()
        self.analyze_nsg_configuration()
        self.analyze_private_dns()
        self.analyze_api_server_access()
        self.check_api_connectivity()
        self.analyze_misconfigurations()
        self.generate_report()


def main():
    """Main entry point"""
    exit_code = 0
    try:
        diagnostics = AKSNetworkDiagnostics()
        diagnostics.run()
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        exit_code = 130  # Standard exit code for SIGINT
    except ValueError as e:
        print(f"\nConfiguration Error: {e}")
        exit_code = 2
    except FileNotFoundError as e:
        print(f"\nFile Error: {e}")
        exit_code = 3
    except PermissionError as e:
        print(f"\nPermission Error: {e}")
        exit_code = 4
    except Exception as e:
        print(f"\nUnexpected Error: {e}")
        # In verbose mode or debug, show stack trace
        import traceback
        traceback.print_exc()
        exit_code = 1
    finally:
        sys.exit(exit_code)


if __name__ == "__main__":
    main()
