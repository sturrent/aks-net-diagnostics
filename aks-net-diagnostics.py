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

# Configuration constants
SCRIPT_VERSION = "2.1"
MAX_FILENAME_LENGTH = 50
MAX_RESOURCE_NAME_LENGTH = 260
VMSS_COMMAND_TIMEOUT = 60
AZURE_CLI_TIMEOUT = 90
DEFAULT_FILE_PERMISSIONS = 0o600  # Owner read/write only (octal notation)

# Allowed Azure CLI commands for security validation
ALLOWED_AZ_COMMANDS = {
    'account', 'aks', 'network', 'vmss', 'vm'
}


@dataclass
class VMSSInstance:
    """Represents a VMSS instance eligible for connectivity testing."""

    vmss_name: str
    resource_group: str
    instance_id: str
    metadata: Dict[str, Any] = field(default_factory=dict)

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
  %(prog)s -n my-cluster -g my-rg --probe-test --json-out custom-report.json
  %(prog)s -n my-cluster -g my-rg --verbose --no-json
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
        parser.add_argument('--json-out',
                          help='Output JSON report to file (default: auto-generated filename)')
        parser.add_argument('--no-json', action='store_true',
                          help='Skip JSON report generation')
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
        self.json_out = args.json_out
        self.no_json = args.no_json
        self.verbose = args.verbose
        self.cache = args.cache
        
        # Auto-generate JSON filename if not disabled and not specified
        if not self.no_json and not self.json_out:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            # Sanitize cluster name for filename
            safe_cluster_name = self._sanitize_filename(self.aks_name)
            self.json_out = f"aks-net-diagnostics_{safe_cluster_name}_{timestamp}.json"
        elif self.json_out:
            # Validate user-provided filename
            self.json_out = self._validate_output_path(self.json_out)
    
    def _validate_azure_cli_command(self, cmd: List[str]) -> None:
        """Validate Azure CLI command to prevent injection attacks"""
        if not cmd or not isinstance(cmd, list):
            raise ValueError("Command must be a non-empty list")
        
        # Check if the first argument is an allowed command
        if cmd[0] not in ALLOWED_AZ_COMMANDS:
            raise ValueError(f"Command '{cmd[0]}' is not allowed")
        
        # Validate that arguments don't contain shell metacharacters
        dangerous_chars = ['|', '&', ';', '(', ')', '$', '`', '\\', '"', "'", '<', '>']
        for arg in cmd:
            if any(char in str(arg) for char in dangerous_chars):
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
                shell=True
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
            subprocess.run(['az', '--version'], capture_output=True, check=True, timeout=AZURE_CLI_TIMEOUT, shell=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            raise FileNotFoundError("Azure CLI is not installed or not in PATH")
        
        # Check if logged in
        try:
            subprocess.run(['az', 'account', 'show'], capture_output=True, check=True, timeout=AZURE_CLI_TIMEOUT, shell=True)
        except subprocess.CalledProcessError:
            raise PermissionError("Not logged in to Azure. Run 'az login' first.")
        
        # Set subscription if provided
        if self.subscription:
            try:
                subprocess.run(['az', 'account', 'set', '--subscription', self.subscription], 
                             capture_output=True, check=True, timeout=AZURE_CLI_TIMEOUT, shell=True)
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
            self.logger.warning("No VNet-integrated node pools found. Using default Azure networking.")
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
        """Analyze outbound connectivity configuration"""
        self.logger.info("Analyzing outbound connectivity...")
        
        network_profile = self.cluster_info.get('networkProfile', {})
        outbound_type = network_profile.get('outboundType', 'loadBalancer')
        
        if outbound_type == 'loadBalancer':
            self._analyze_load_balancer_outbound()
        elif outbound_type == 'userDefinedRouting':
            self._analyze_udr_outbound()
        elif outbound_type == 'managedNATGateway':
            self._analyze_nat_gateway_outbound()
        
        # Always check for UDRs on node subnets regardless of outbound type
        # This helps detect scenarios where Azure Firewall is used with Load Balancer outbound
        self.logger.info("  - Checking for UDRs on node subnets...")
        udr_analysis = self._analyze_node_subnet_udrs()
        
        # Determine effective outbound configuration and warn about conflicts
        effective_outbound_summary = self._determine_effective_outbound(outbound_type, udr_analysis)
        
        self.outbound_analysis = {
            "type": outbound_type,
            "configuredPublicIPs": self.outbound_ips,  # IPs configured in load balancer
            "effectiveOutbound": effective_outbound_summary,
            "udrAnalysis": udr_analysis if udr_analysis.get("routeTables") else None
        }
        
        # Display summary of effective outbound configuration
        self._display_outbound_summary(effective_outbound_summary)
    
    def _determine_effective_outbound(self, outbound_type, udr_analysis):
        """Determine the effective outbound configuration considering UDRs"""
        effective_summary = {
            "mechanism": outbound_type,
            "overridden_by_udr": False,
            "effective_mechanism": outbound_type,
            "virtual_appliance_ips": [],
            "load_balancer_ips": self.outbound_ips.copy(),
            "warnings": [],
            "description": ""
        }
        
        # Check if UDRs override the configured outbound type
        virtual_appliance_routes = udr_analysis.get("virtualApplianceRoutes", [])
        internet_routes = udr_analysis.get("internetRoutes", [])
        
        # Look for default routes (0.0.0.0/0) that redirect traffic
        default_route_to_appliance = None
        for route in virtual_appliance_routes:
            if route.get("addressPrefix") == "0.0.0.0/0":
                default_route_to_appliance = route
                break
        
        if default_route_to_appliance:
            # UDR overrides the configured outbound mechanism
            effective_summary["overridden_by_udr"] = True
            effective_summary["effective_mechanism"] = "virtualAppliance"
            appliance_ip = default_route_to_appliance.get("nextHopIpAddress", "unknown")
            effective_summary["virtual_appliance_ips"] = [appliance_ip]
            
            if outbound_type == "loadBalancer":
                effective_summary["warnings"].append({
                    "level": "warning",
                    "message": f"Load Balancer outbound configuration detected but UDR forces traffic to virtual appliance ({appliance_ip})",
                    "impact": "The Load Balancer public IPs are not the effective outbound IPs"
                })
                effective_summary["description"] = f"Traffic is routed through virtual appliance {appliance_ip} via UDR (overriding Load Balancer)"
            else:
                effective_summary["description"] = f"Traffic is routed through virtual appliance {appliance_ip} via UDR"
        else:
            # No UDR override, use configured mechanism
            if outbound_type == "loadBalancer":
                if self.outbound_ips:
                    effective_summary["description"] = f"Traffic uses Load Balancer with public IP(s): {', '.join(self.outbound_ips)}"
                else:
                    effective_summary["warnings"].append({
                        "level": "error",
                        "message": "Load Balancer outbound type configured but no public IPs found",
                        "impact": "Outbound connectivity may be broken"
                    })
                    effective_summary["description"] = "Load Balancer outbound configured but no public IPs detected"
            elif outbound_type == "userDefinedRouting":
                if virtual_appliance_routes:
                    # Collect all virtual appliance IPs from routes
                    appliance_ips = list(set([r.get("nextHopIpAddress", "unknown") for r in virtual_appliance_routes if r.get("nextHopIpAddress")]))
                    effective_summary["virtual_appliance_ips"] = appliance_ips
                    effective_summary["description"] = f"User Defined Routing through virtual appliance(s): {', '.join(appliance_ips)}"
                else:
                    effective_summary["warnings"].append({
                        "level": "warning",
                        "message": "User Defined Routing configured but no virtual appliance routes found",
                        "impact": "May indicate misconfigured routing"
                    })
                    effective_summary["description"] = "User Defined Routing configured"
            elif outbound_type == "managedNATGateway":
                if self.outbound_ips:
                    ip_list = ', '.join(self.outbound_ips)
                    effective_summary["description"] = f"Managed NAT Gateway with outbound IPs: {ip_list}"
                else:
                    effective_summary["description"] = "Managed NAT Gateway (no outbound IPs detected)"
        
        return effective_summary
    
    def _display_outbound_summary(self, effective_summary):
        """Display a summary of the effective outbound configuration"""
        mechanism = effective_summary["effective_mechanism"]
        description = effective_summary["description"]
        
        if effective_summary["overridden_by_udr"]:
            self.logger.info(f"  ⚠️  {description}")
            if effective_summary["load_balancer_ips"]:
                self.logger.info(f"    Load Balancer IPs (not effective): {', '.join(effective_summary['load_balancer_ips'])}")
        else:
            if mechanism == "loadBalancer" and effective_summary["load_balancer_ips"]:
                for ip in effective_summary["load_balancer_ips"]:
                    self.logger.info(f"    Found outbound IP: {ip}")
            elif mechanism == "virtualAppliance" and effective_summary["virtual_appliance_ips"]:
                for ip in effective_summary["virtual_appliance_ips"]:
                    self.logger.info(f"    Virtual appliance IP: {ip}")
            elif mechanism == "managedNATGateway" and effective_summary["load_balancer_ips"]:  # NAT Gateway IPs are stored in load_balancer_ips field
                for ip in effective_summary["load_balancer_ips"]:
                    self.logger.info(f"    NAT Gateway outbound IP: {ip}")
        
        # Display warnings
        for warning in effective_summary.get("warnings", []):
            level = warning["level"]
            message = warning["message"]
            if level == "error":
                self.logger.info(f"    ❌ {message}")
            else:
                self.logger.info(f"    ⚠️  {message}")
    
    def _analyze_load_balancer_outbound(self):
        """Analyze load balancer outbound configuration"""
        self.logger.info("  - Analyzing Load Balancer outbound configuration...")
        
        # Get the managed cluster's load balancer
        mc_rg = self.cluster_info.get('nodeResourceGroup', '')
        if not mc_rg:
            if self.verbose:
                self.logger.info("    No node resource group found")
            return
        
        # List load balancers in the managed resource group
        lb_cmd = ['network', 'lb', 'list', '-g', mc_rg, '-o', 'json']
        load_balancers = self.run_azure_cli(lb_cmd)
        
        if not isinstance(load_balancers, list):
            if self.verbose:
                self.logger.info(f"    No load balancers found in {mc_rg}")
            return
        
        # Process load balancers quietly and only report the final results
        for lb in load_balancers:
            lb_name = lb.get('name', '')
            if not lb_name:
                continue
            
            # Check outbound rules first
            outbound_rules = lb.get('outboundRules', [])
            frontend_configs = lb.get('frontendIpConfigurations', [])
            
            # Collect frontend config IDs that might have outbound IPs
            frontend_config_ids = []
            
            # Add frontend configs from outbound rules (this is the main path for AKS)
            for rule in outbound_rules:
                # Try both possible field names for frontend IP configurations
                frontend_ips = rule.get('frontendIPConfigurations', [])
                if not frontend_ips:
                    frontend_ips = rule.get('frontendIpConfigurations', [])
                
                for frontend_ip in frontend_ips:
                    if frontend_ip.get('id'):
                        frontend_config_ids.append(frontend_ip['id'])
            
            # Also add all direct frontend configs (for standard LB without outbound rules)
            for frontend in frontend_configs:
                if frontend.get('id'):
                    frontend_config_ids.append(frontend['id'])
            
            # Process each frontend config
            for config_id in frontend_config_ids:
                # Extract load balancer name and frontend config name from ID
                parts = config_id.split('/')
                if len(parts) >= 11:
                    config_name = parts[10]  # Frontend IP config name
                    
                    # Get the frontend IP configuration details
                    frontend_cmd = ['network', 'lb', 'frontend-ip', 'show', 
                                  '-g', mc_rg, '--lb-name', lb_name, '-n', config_name, '-o', 'json']
                    frontend_config = self.run_azure_cli(frontend_cmd)
                    
                    if isinstance(frontend_config, dict):
                        public_ip = frontend_config.get('publicIPAddress', {})
                        if public_ip and public_ip.get('id'):
                            # Get public IP details
                            ip_cmd = ['network', 'public-ip', 'show', '--ids', public_ip['id'], '-o', 'json']
                            ip_info = self.run_azure_cli(ip_cmd)
                            
                            if ip_info and ip_info.get('ipAddress'):
                                ip_address = ip_info['ipAddress']
                                if ip_address not in self.outbound_ips:
                                    self.outbound_ips.append(ip_address)
        
        # Summary of outbound IP discovery will be handled by _display_outbound_summary
        if self.verbose and not self.outbound_ips:
            self.logger.info("    No outbound IPs detected")
    
    def _analyze_udr_outbound(self):
        """Analyze User Defined Routing outbound configuration"""
        self.logger.info("  - Analyzing User Defined Routing configuration...")
        
        # Get route table information for node subnets
        udr_analysis = self._analyze_node_subnet_udrs()
        
        # Store UDR analysis results
        self.outbound_analysis = {
            "type": "userDefinedRouting",
            "routeTables": udr_analysis.get("routeTables", []),
            "criticalRoutes": udr_analysis.get("criticalRoutes", []),
            "virtualApplianceRoutes": udr_analysis.get("virtualApplianceRoutes", []),
            "internetRoutes": udr_analysis.get("internetRoutes", [])
        }
    
    def _analyze_nat_gateway_outbound(self):
        """Analyze NAT Gateway outbound configuration"""
        self.logger.info("  - Analyzing NAT Gateway configuration...")
        
        # Get the managed cluster's resource group
        mc_rg = self.cluster_info.get('nodeResourceGroup', '')
        if not mc_rg:
            if self.verbose:
                self.logger.info("    No node resource group found")
            return
        
        # List NAT Gateways in the managed resource group
        natgw_cmd = ['network', 'nat', 'gateway', 'list', '-g', mc_rg, '-o', 'json']
        nat_gateways = self.run_azure_cli(natgw_cmd)
        
        if not isinstance(nat_gateways, list):
            if self.verbose:
                self.logger.info(f"    No NAT Gateways found in {mc_rg}")
            return
        
        # Process each NAT Gateway
        for natgw in nat_gateways:
            natgw_name = natgw.get('name', '')
            if not natgw_name:
                continue
            
            self.logger.info(f"    Found NAT Gateway: {natgw_name}")
            
            # Get public IP prefixes and public IPs associated with this NAT Gateway
            public_ip_prefixes = natgw.get('publicIpPrefixes', [])
            public_ips = natgw.get('publicIpAddresses', [])
            
            # Extract IPs from public IP resources
            for public_ip_ref in public_ips:
                public_ip_id = public_ip_ref.get('id', '')
                if public_ip_id:
                    public_ip_info = self._get_public_ip_details(public_ip_id)
                    if public_ip_info:
                        ip_address = public_ip_info.get('ipAddress', '')
                        if ip_address:
                            self.outbound_ips.append(ip_address)
                            if self.verbose:
                                self.logger.info(f"      Public IP: {ip_address}")
            
            # Extract IPs from public IP prefixes
            for prefix_ref in public_ip_prefixes:
                prefix_id = prefix_ref.get('id', '')
                if prefix_id:
                    prefix_info = self._get_public_ip_prefix_details(prefix_id)
                    if prefix_info:
                        ip_prefix = prefix_info.get('ipPrefix', '')
                        if ip_prefix:
                            # For prefixes, we'll note the range but also try to get individual IPs
                            if self.verbose:
                                self.logger.info(f"      Public IP Prefix: {ip_prefix}")
                            # Extract the first IP from the prefix for outbound IP tracking
                            try:
                                import ipaddress
                                network = ipaddress.ip_network(ip_prefix, strict=False)
                                first_ip = str(list(network.hosts())[0]) if list(network.hosts()) else str(network.network_address)
                                self.outbound_ips.append(f"{ip_prefix} (range)")
                            except:
                                self.outbound_ips.append(f"{ip_prefix} (prefix)")
        
        if not self.outbound_ips and self.verbose:
            self.logger.info("    No outbound IPs detected from NAT Gateway")
    
    def _get_public_ip_details(self, public_ip_id):
        """Get detailed information about a public IP resource"""
        try:
            # Parse public IP ID to extract components
            parts = public_ip_id.split('/')
            if len(parts) < 9:
                return None
            
            subscription_id = parts[2]
            resource_group = parts[4]
            public_ip_name = parts[8]
            
            # Get public IP details
            cmd = ['network', 'public-ip', 'show',
                   '--subscription', subscription_id,
                   '-g', resource_group,
                   '-n', public_ip_name,
                   '-o', 'json']
            
            return self.run_azure_cli(cmd)
            
        except Exception as e:
            if self.verbose:
                self.logger.info(f"    Error getting public IP details for {public_ip_id}: {e}")
            return None
    
    def _get_public_ip_prefix_details(self, prefix_id):
        """Get detailed information about a public IP prefix resource"""
        try:
            # Parse public IP prefix ID to extract components
            parts = prefix_id.split('/')
            if len(parts) < 9:
                return None
            
            subscription_id = parts[2]
            resource_group = parts[4]
            prefix_name = parts[8]
            
            # Get public IP prefix details
            cmd = ['network', 'public-ip', 'prefix', 'show',
                   '--subscription', subscription_id,
                   '-g', resource_group,
                   '-n', prefix_name,
                   '-o', 'json']
            
            return self.run_azure_cli(cmd)
            
        except Exception as e:
            if self.verbose:
                self.logger.info(f"    Error getting public IP prefix details for {prefix_id}: {e}")
            return None

    def _analyze_node_subnet_udrs(self):
        """Analyze User Defined Routes on node subnets"""
        self.logger.info("    Analyzing UDRs on node subnets...")
        
        udr_analysis = {
            "routeTables": [],
            "criticalRoutes": [],
            "virtualApplianceRoutes": [],
            "internetRoutes": []
        }
        
        # Get unique subnet IDs from agent pools
        subnet_ids = set()
        for pool in self.agent_pools:
            subnet_id = pool.get('vnetSubnetId')
            if subnet_id and subnet_id != "null":
                subnet_ids.add(subnet_id)
        
        if not subnet_ids:
            self.logger.info("    No VNet-integrated node pools found")
            return udr_analysis
        
        # Analyze each subnet for route tables
        for subnet_id in subnet_ids:
            try:
                subnet_info = self._get_subnet_details(subnet_id)
                if not subnet_info:
                    continue
                
                route_table = subnet_info.get('routeTable')
                if route_table and route_table.get('id'):
                    route_table_id = route_table['id']
                    self.logger.info(f"    Found route table: {route_table_id}")
                    
                    # Get route table details
                    rt_analysis = self._analyze_route_table(route_table_id, subnet_id)
                    if rt_analysis:
                        udr_analysis["routeTables"].append(rt_analysis)
                        
                        # Categorize routes
                        for route in rt_analysis.get("routes", []):
                            self._categorize_route(route, udr_analysis)
                else:
                    self.logger.info(f"    No route table associated with subnet: {subnet_id}")
                    
            except Exception as e:
                self.logger.info(f"    Error analyzing subnet {subnet_id}: {e}")
        
        return udr_analysis
    
    def _get_subnet_details(self, subnet_id):
        """Get detailed information about a subnet"""
        try:
            # Parse subnet ID to extract components
            parts = subnet_id.split('/')
            if len(parts) < 11:
                return None
            
            subscription_id = parts[2]
            resource_group = parts[4]
            vnet_name = parts[8]
            subnet_name = parts[10]
            
            # Get subnet details
            cmd = ['network', 'vnet', 'subnet', 'show', 
                   '--subscription', subscription_id,
                   '-g', resource_group, 
                   '--vnet-name', vnet_name, 
                   '-n', subnet_name, 
                   '-o', 'json']
            
            return self.run_azure_cli(cmd)
            
        except Exception as e:
            self.logger.info(f"    Error getting subnet details for {subnet_id}: {e}")
            return None
    
    def _analyze_route_table(self, route_table_id, subnet_id):
        """Analyze a specific route table"""
        try:
            # Parse route table ID
            parts = route_table_id.split('/')
            if len(parts) < 9:
                return None
            
            subscription_id = parts[2]
            resource_group = parts[4]
            route_table_name = parts[8]
            
            # Get route table details
            cmd = ['network', 'route-table', 'show',
                   '--subscription', subscription_id,
                   '-g', resource_group,
                   '-n', route_table_name,
                   '-o', 'json']
            
            route_table_info = self.run_azure_cli(cmd)
            
            if not route_table_info:
                return None
            
            analysis = {
                "id": route_table_id,
                "name": route_table_name,
                "resourceGroup": resource_group,
                "associatedSubnet": subnet_id,
                "routes": [],
                "disableBgpRoutePropagation": route_table_info.get('disableBgpRoutePropagation', False)
            }
            
            # Analyze each route
            routes = route_table_info.get('routes', [])
            for route in routes:
                route_analysis = self._analyze_individual_route(route)
                if route_analysis:
                    analysis["routes"].append(route_analysis)
            
            self.logger.info(f"    Route table {route_table_name} has {len(routes)} route(s)")
            
            return analysis
            
        except Exception as e:
            self.logger.info(f"    Error analyzing route table {route_table_id}: {e}")
            return None
    
    def _analyze_individual_route(self, route):
        """Analyze an individual route"""
        try:
            next_hop_type = route.get('nextHopType', '')
            address_prefix = route.get('addressPrefix', '')
            next_hop_ip = route.get('nextHopIpAddress', '')
            route_name = route.get('name', '')
            
            analysis = {
                "name": route_name,
                "addressPrefix": address_prefix,
                "nextHopType": next_hop_type,
                "nextHopIpAddress": next_hop_ip,
                "provisioningState": route.get('provisioningState', ''),
                "impact": self._assess_route_impact(address_prefix, next_hop_type, next_hop_ip)
            }
            
            return analysis
            
        except Exception as e:
            self.logger.info(f"    Error analyzing route: {e}")
            return None
    
    def _assess_route_impact(self, address_prefix, next_hop_type, next_hop_ip):
        """Assess the potential impact of a route on AKS connectivity"""
        impact = {
            "severity": "info",
            "description": "",
            "affectedTraffic": []
        }
        
        # Check for default route (0.0.0.0/0)
        if address_prefix == "0.0.0.0/0":
            if next_hop_type == "VirtualAppliance":
                impact["severity"] = "high"
                impact["description"] = "Default route redirects ALL internet traffic to virtual appliance"
                impact["affectedTraffic"] = ["internet", "container_registry", "azure_services", "api_server"]
            elif next_hop_type == "None":
                impact["severity"] = "critical"
                impact["description"] = "Default route drops ALL internet traffic (blackhole)"
                impact["affectedTraffic"] = ["internet", "container_registry", "azure_services", "api_server"]
            elif next_hop_type == "Internet":
                impact["severity"] = "low"
                impact["description"] = "Explicit default route to internet (may override system routes)"
                impact["affectedTraffic"] = ["internet"]
        
        # Check for Azure service routes
        elif self._is_azure_service_prefix(address_prefix):
            if next_hop_type == "VirtualAppliance":
                impact["severity"] = "medium"
                impact["description"] = f"Azure service traffic ({address_prefix}) redirected to virtual appliance"
                impact["affectedTraffic"] = ["azure_services"]
            elif next_hop_type == "None":
                impact["severity"] = "high"
                impact["description"] = f"Azure service traffic ({address_prefix}) blocked"
                impact["affectedTraffic"] = ["azure_services"]
        
        # Check for container registry routes
        elif self._is_container_registry_prefix(address_prefix):
            if next_hop_type == "VirtualAppliance":
                impact["severity"] = "medium"
                impact["description"] = f"Container registry traffic ({address_prefix}) redirected to virtual appliance"
                impact["affectedTraffic"] = ["container_registry"]
            elif next_hop_type == "None":
                impact["severity"] = "high"
                impact["description"] = f"Container registry traffic ({address_prefix}) blocked"
                impact["affectedTraffic"] = ["container_registry"]
        
        # Check for private network routes
        elif self._is_private_network_prefix(address_prefix):
            if next_hop_type == "VirtualAppliance":
                impact["severity"] = "low"
                impact["description"] = f"Private network traffic ({address_prefix}) redirected to virtual appliance"
                impact["affectedTraffic"] = ["private_network"]
        
        return impact
    
    def _is_azure_service_prefix(self, address_prefix):
        """Check if address prefix covers Azure service endpoints"""
        # Common Azure service IP ranges (simplified check)
        azure_prefixes = [
            "13.", "20.", "23.", "40.", "52.", "104.", "168.", "191."
        ]
        return any(address_prefix.startswith(prefix) for prefix in azure_prefixes)
    
    def _is_container_registry_prefix(self, address_prefix):
        """Check if address prefix covers container registry endpoints"""
        # Microsoft Container Registry typically uses these ranges
        mcr_prefixes = [
            "20.81.", "20.117.", "52.159.", "52.168."
        ]
        return any(address_prefix.startswith(prefix) for prefix in mcr_prefixes)
    
    def _is_private_network_prefix(self, address_prefix):
        """Check if address prefix is for private networks"""
        private_prefixes = ["10.", "172.16.", "172.17.", "172.18.", "172.19.", 
                           "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                           "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                           "172.30.", "172.31.", "192.168."]
        return any(address_prefix.startswith(prefix) for prefix in private_prefixes)
    
    def _categorize_route(self, route, udr_analysis):
        """Categorize routes based on their impact"""
        impact = route.get("impact", {})
        severity = impact.get("severity", "info")
        next_hop_type = route.get("nextHopType", "")
        address_prefix = route.get("addressPrefix", "")
        
        # Critical routes (high impact on connectivity)
        if severity in ["critical", "high"]:
            udr_analysis["criticalRoutes"].append({
                "name": route.get("name", ""),
                "addressPrefix": address_prefix,
                "nextHopType": next_hop_type,
                "impact": impact
            })
        
        # Virtual appliance routes
        if next_hop_type == "VirtualAppliance":
            udr_analysis["virtualApplianceRoutes"].append({
                "name": route.get("name", ""),
                "addressPrefix": address_prefix,
                "nextHopIpAddress": route.get("nextHopIpAddress", ""),
                "impact": impact
            })
        
        # Internet routes
        if address_prefix == "0.0.0.0/0" or next_hop_type == "Internet":
            udr_analysis["internetRoutes"].append({
                "name": route.get("name", ""),
                "addressPrefix": address_prefix,
                "nextHopType": next_hop_type,
                "impact": impact
            })
    
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
                
                self.vmss_analysis.append({
                    "name": vmss_name,
                    "resourceGroup": mc_rg,
                    "networkProfile": network_profile
                })
    
    def analyze_nsg_configuration(self):
        """Analyze Network Security Group configuration for AKS nodes"""
        self.logger.info("Analyzing NSG configuration...")
        
        self.nsg_analysis = {
            "subnetNsgs": [],
            "nicNsgs": [], 
            "requiredRules": [],
            "missingRules": [],
            "blockingRules": [],
            "interNodeCommunication": {"status": "unknown", "issues": []}
        }
        
        # Determine if cluster is private
        api_server_profile = self.cluster_info.get('apiServerAccessProfile')
        is_private_cluster = False
        if api_server_profile:
            is_private_cluster = api_server_profile.get('enablePrivateCluster', False)
        
        # Get required outbound rules based on cluster type
        required_rules = self._get_required_aks_rules(is_private_cluster)
        self.nsg_analysis["requiredRules"] = required_rules
        
        # Analyze NSGs on node subnets
        self._analyze_subnet_nsgs()
        
        # Analyze NSGs on node NICs
        self._analyze_nic_nsgs()
        
        # Check for inter-node communication issues
        self._analyze_inter_node_communication()
        
        # Check for rule conflicts and missing rules
        self._analyze_nsg_compliance()
    
    def _get_required_aks_rules(self, is_private_cluster):
        """Get required NSG rules for AKS based on cluster type"""
        rules = {
            "outbound": [
                {
                    "name": "AKS_Registry_Access",
                    "protocol": "TCP",
                    "destination": "MicrosoftContainerRegistry",
                    "ports": ["443"],
                    "description": "Access to Microsoft Container Registry"
                },
                {
                    "name": "AKS_Azure_Management", 
                    "protocol": "TCP",
                    "destination": "AzureCloud",
                    "ports": ["443"],
                    "description": "Azure management endpoints"
                },
                {
                    "name": "AKS_DNS",
                    "protocol": "UDP", 
                    "destination": "*",
                    "ports": ["53"],
                    "description": "DNS resolution"
                },
                {
                    "name": "AKS_NTP",
                    "protocol": "UDP",
                    "destination": "*", 
                    "ports": ["123"],
                    "description": "Network Time Protocol"
                }
            ],
            "inbound": [
                {
                    "name": "AKS_Inter_Node_Communication",
                    "protocol": "*",
                    "source": "VirtualNetwork",
                    "ports": ["*"],
                    "description": "Communication between cluster nodes"
                }
            ]
        }
        
        if not is_private_cluster:
            # Public clusters need API server access
            rules["outbound"].append({
                "name": "AKS_API_Server_Access",
                "protocol": "TCP",
                "destination": "*",
                "ports": ["443"],
                "description": "Access to AKS API server"
            })
        
        # Add Azure Load Balancer access
        rules["inbound"].append({
            "name": "AKS_Load_Balancer",
            "protocol": "*",
            "source": "AzureLoadBalancer",
            "ports": ["*"],
            "description": "Azure Load Balancer health probes"
        })
        
        return rules
    
    def _analyze_subnet_nsgs(self):
        """Analyze NSGs associated with node subnets"""
        processed_subnets = set()  # Track processed subnets to avoid duplicates
        
        for vmss in self.vmss_analysis:
            vmss_name = vmss.get("name", "unknown")
            network_profile = vmss.get("networkProfile", {})
            network_interfaces = network_profile.get("networkInterfaceConfigurations", [])
            
            for nic in network_interfaces:
                ip_configs = nic.get('ipConfigurations', [])
                for ip_config in ip_configs:
                    subnet = ip_config.get('subnet', {})
                    subnet_id = subnet.get('id')
                    
                    if not subnet_id or subnet_id in processed_subnets:
                        continue
                    
                    processed_subnets.add(subnet_id)
                    
                    # Get subnet information
                    subnet_cmd = ['network', 'vnet', 'subnet', 'show', '--ids', subnet_id, '-o', 'json']
                    subnet_info = self.run_azure_cli(subnet_cmd)
                    
                    if not subnet_info or not isinstance(subnet_info, dict):
                        continue
                        
                    nsg_info = subnet_info.get('networkSecurityGroup')
                    if nsg_info:
                        nsg_id = nsg_info.get('id')
                        nsg_name = nsg_id.split('/')[-1] if nsg_id else 'unknown'
                        
                        # Get NSG details
                        nsg_cmd = ['network', 'nsg', 'show', '--ids', nsg_id, '-o', 'json']
                        nsg_details = self.run_azure_cli(nsg_cmd)
                        
                        if nsg_details and isinstance(nsg_details, dict):
                            self.nsg_analysis["subnetNsgs"].append({
                                "subnetId": subnet_id,
                                "subnetName": subnet_info.get('name', 'unknown'),
                                "nsgId": nsg_id,
                                "nsgName": nsg_name,
                                "rules": nsg_details.get('securityRules', []),
                                "defaultRules": nsg_details.get('defaultSecurityRules', [])
                            })
                            
                            if self.verbose:
                                self.logger.info(f"  Found NSG on subnet {subnet_info.get('name')}: {nsg_name}")
                    else:
                        if self.verbose:
                            self.logger.info(f"  No NSG found on subnet {subnet_info.get('name')}")
    
    def _analyze_nic_nsgs(self):
        """Analyze NSGs associated with node NICs"""
        for vmss in self.vmss_analysis:
            vmss_name = vmss.get("name")
            if not vmss_name:
                continue
                
            network_profile = vmss.get("networkProfile", {})
            network_interfaces = network_profile.get('networkInterfaceConfigurations', [])
            
            for nic_config in network_interfaces:
                # Check for NSG on NIC configuration
                nsg_info = nic_config.get('networkSecurityGroup')
                if nsg_info:
                    nsg_id = nsg_info.get('id')
                    nsg_name = nsg_id.split('/')[-1] if nsg_id else 'unknown'
                    
                    # Get NSG details
                    nsg_cmd = ['network', 'nsg', 'show', '--ids', nsg_id, '-o', 'json']
                    nsg_details = self.run_azure_cli(nsg_cmd)
                    
                    if nsg_details and isinstance(nsg_details, dict):
                        self.nsg_analysis["nicNsgs"].append({
                            "vmssName": vmss_name,
                            "nicName": nic_config.get('name', 'unknown'),
                            "nsgId": nsg_id,
                            "nsgName": nsg_name,
                            "rules": nsg_details.get('securityRules', []),
                            "defaultRules": nsg_details.get('defaultSecurityRules', [])
                        })
                        
                        if self.verbose:
                            self.logger.info(f"  Found NSG on VMSS {vmss_name} NIC: {nsg_name}")
                else:
                    if self.verbose:
                        self.logger.info(f"  No NSG found on VMSS {vmss_name} NIC")
    
    def _analyze_inter_node_communication(self):
        """Analyze if NSG rules could block inter-node communication"""
        all_nsgs = self.nsg_analysis["subnetNsgs"] + self.nsg_analysis["nicNsgs"]
        issues = []
        
        for nsg in all_nsgs:
            # Check for rules that might block VirtualNetwork traffic
            blocking_rules = []
            all_rules = nsg.get("rules", []) + nsg.get("defaultRules", [])
            
            for rule in all_rules:
                if (rule.get('access', '').lower() == 'deny' and 
                    rule.get('direction', '').lower() == 'inbound' and
                    rule.get('priority', 0) < 65000):
                    
                    source = rule.get('sourceAddressPrefix', '')
                    if source in ['*', 'VirtualNetwork'] or source.startswith('10.') or source.startswith('192.168.') or source.startswith('172.'):
                        blocking_rules.append({
                            "ruleName": rule.get('name', 'unknown'),
                            "priority": rule.get('priority', 0),
                            "source": source,
                            "destination": rule.get('destinationAddressPrefix', ''),
                            "protocol": rule.get('protocol', ''),
                            "ports": rule.get('destinationPortRange', '')
                        })
            
            if blocking_rules:
                issues.append({
                    "nsgName": nsg.get("nsgName"),
                    "location": "subnet" if "subnetId" in nsg else "nic",
                    "blockingRules": blocking_rules
                })
        
        self.nsg_analysis["interNodeCommunication"] = {
            "status": "potential_issues" if issues else "ok",
            "issues": issues
        }
    
    def _analyze_nsg_compliance(self):
        """Analyze NSG compliance with AKS requirements"""
        all_nsgs = self.nsg_analysis["subnetNsgs"] + self.nsg_analysis["nicNsgs"]
        missing_rules = []
        blocking_rules = []
        
        for nsg in all_nsgs:
            nsg_name = nsg.get("nsgName", "unknown")
            all_rules = nsg.get("rules", []) + nsg.get("defaultRules", [])
            
            # Sort rules by priority for proper precedence analysis
            sorted_rules = sorted(all_rules, key=lambda x: x.get('priority', 65000))
            
            # Check for rules that might block required AKS traffic
            for rule in sorted_rules:
                if rule.get('access', '').lower() == 'deny' and rule.get('priority', 0) < 65000:
                    # Check if this rule could block required AKS outbound traffic
                    if rule.get('direction', '').lower() == 'outbound':
                        dest = rule.get('destinationAddressPrefix', '')
                        ports = rule.get('destinationPortRange', '')
                        protocol = rule.get('protocol', '')
                        
                        # Check for rules that could block essential AKS traffic
                        if (dest in ['*', 'Internet'] or 'MicrosoftContainerRegistry' in str(dest) or 'AzureCloud' in str(dest)):
                            if ('443' in str(ports) or '*' in str(ports)) and protocol.upper() in ['TCP', '*']:
                                # Check if there are higher priority allow rules that would override this deny rule
                                is_overridden, overriding_rules = self._check_rule_precedence(
                                    rule, sorted_rules, nsg_name
                                )
                                
                                blocking_rule = {
                                    "nsgName": nsg_name,
                                    "ruleName": rule.get('name', 'unknown'),
                                    "priority": rule.get('priority', 0),
                                    "direction": rule.get('direction', ''),
                                    "protocol": protocol,
                                    "destination": dest,
                                    "ports": ports,
                                    "impact": "Could block AKS management traffic",
                                    "isOverridden": is_overridden,
                                    "overriddenBy": overriding_rules,
                                    "effectiveSeverity": "warning" if is_overridden else "critical"
                                }
                                
                                blocking_rules.append(blocking_rule)
        
        self.nsg_analysis["blockingRules"] = blocking_rules
        self.nsg_analysis["missingRules"] = missing_rules
    
    def _check_rule_precedence(self, deny_rule, sorted_rules, nsg_name):
        """Check if a deny rule is overridden by higher priority allow rules"""
        deny_priority = deny_rule.get('priority', 65000)
        overriding_rules = []
        
        # Look for allow rules with higher priority (lower number) that would override this deny rule
        for rule in sorted_rules:
            rule_priority = rule.get('priority', 65000)
            
            # Only check rules with higher priority (lower priority number)
            if rule_priority >= deny_priority:
                break
                
            # Only check allow rules in the same direction
            if (rule.get('access', '').lower() == 'allow' and 
                rule.get('direction', '').lower() == deny_rule.get('direction', '').lower()):
                
                # Check if this allow rule covers the same traffic as the deny rule
                if self._rules_overlap(deny_rule, rule):
                    overriding_rules.append({
                        "ruleName": rule.get('name', 'unknown'),
                        "priority": rule_priority,
                        "destination": rule.get('destinationAddressPrefix', ''),
                        "ports": rule.get('destinationPortRange', ''),
                        "protocol": rule.get('protocol', '')
                    })
        
        is_overridden = len(overriding_rules) > 0
        return is_overridden, overriding_rules
    
    def _rules_overlap(self, deny_rule, allow_rule):
        """Check if an allow rule overlaps with a deny rule for AKS traffic"""
        # Check destination overlap
        deny_dest = deny_rule.get('destinationAddressPrefix', '').lower()
        allow_dest = allow_rule.get('destinationAddressPrefix', '').lower()
        
        # Check if allow rule covers AKS-related destinations
        aks_destinations = ['*', 'internet', 'azurecloud', 'microsoftcontainerregistry']
        
        dest_overlap = False
        if allow_dest in aks_destinations:
            dest_overlap = True
        elif deny_dest in ['*', 'internet'] and allow_dest in ['azurecloud', 'microsoftcontainerregistry']:
            dest_overlap = True
        elif deny_dest in aks_destinations and allow_dest == deny_dest:
            dest_overlap = True
        
        if not dest_overlap:
            return False
        
        # Check port overlap
        deny_ports = str(deny_rule.get('destinationPortRange', '')).lower()
        allow_ports = str(allow_rule.get('destinationPortRange', '')).lower()
        
        port_overlap = False
        if allow_ports == '*' or deny_ports == '*':
            port_overlap = True
        elif '443' in deny_ports and ('443' in allow_ports or '*' in allow_ports):
            port_overlap = True
        elif deny_ports == allow_ports:
            port_overlap = True
        
        if not port_overlap:
            return False
        
        # Check protocol overlap
        deny_protocol = deny_rule.get('protocol', '').upper()
        allow_protocol = allow_rule.get('protocol', '').upper()
        
        protocol_overlap = (
            allow_protocol == '*' or 
            deny_protocol == '*' or 
            deny_protocol == allow_protocol or
            (deny_protocol in ['TCP', '*'] and allow_protocol in ['TCP', '*'])
        )
        
        return protocol_overlap
    
    def analyze_private_dns(self):
        """Analyze private DNS configuration"""
        self.logger.info("Analyzing private DNS configuration...")
        
        api_server_profile = self.cluster_info.get('apiServerAccessProfile')
        if not api_server_profile:
            return
        
        is_private = api_server_profile.get('enablePrivateCluster', False)
        if not is_private:
            return
        
        private_dns_zone = api_server_profile.get('privateDnsZone', '')
        
        if private_dns_zone and private_dns_zone != 'system':
            # Analyze custom private DNS zone
            self.private_dns_analysis = {
                "type": "custom",
                "privateDnsZone": private_dns_zone,
                "analysis": "Custom private DNS zone configured"
            }
        else:
            # System-managed private DNS zone
            self.private_dns_analysis = {
                "type": "system",
                "privateDnsZone": "system",
                "analysis": "System-managed private DNS zone"
            }
    
    def analyze_api_server_access(self):
        """Analyze API server access configuration including authorized IP ranges"""
        self.logger.info("Analyzing API server access configuration...")
        
        api_server_profile = self.cluster_info.get('apiServerAccessProfile')
        if not api_server_profile:
            self.logger.info("  - No API server access profile found")
            return
        
        # Initialize API server access analysis
        self.api_server_access_analysis = {
            "privateCluster": api_server_profile.get('enablePrivateCluster', False),
            "authorizedIpRanges": api_server_profile.get('authorizedIpRanges', []),
            "disableRunCommand": api_server_profile.get('disableRunCommand', False),
            "analysis": {},
            "securityFindings": [],
            "accessRestrictions": {}
        }
        
        # Analyze authorized IP ranges
        self._analyze_authorized_ip_ranges()
        
        # Check for security best practices
        self._validate_api_security_configuration()
        
        # Analyze access restrictions and their implications
        self._analyze_access_restrictions()
    
    def _analyze_authorized_ip_ranges(self):
        """Analyze authorized IP ranges configuration"""
        authorized_ranges = self.api_server_access_analysis["authorizedIpRanges"]
        
        if not authorized_ranges:
            self.logger.info("  - No authorized IP ranges configured (unrestricted access)")
            self.api_server_access_analysis["analysis"]["ipRangeRestriction"] = "none"
            return
        
        self.logger.info(f"  - Found {len(authorized_ranges)} authorized IP range(s):")
        for range_cidr in authorized_ranges:
            self.logger.info(f"    • {range_cidr}")
        
        self.api_server_access_analysis["analysis"]["ipRangeRestriction"] = "enabled"
        self.api_server_access_analysis["analysis"]["rangeCount"] = len(authorized_ranges)
        
        # Analyze each range for security implications
        for range_cidr in authorized_ranges:
            self._analyze_ip_range_security(range_cidr)
    
    def _analyze_ip_range_security(self, range_cidr):
        """Analyze individual IP range for security implications"""
        try:
            import ipaddress
            
            # Parse the CIDR range
            network = ipaddress.ip_network(range_cidr, strict=False)
            
            # Calculate range size
            num_addresses = network.num_addresses
            prefix_length = network.prefixlen
            
            # Security analysis based on range characteristics
            if range_cidr == "0.0.0.0/0":
                self.api_server_access_analysis["securityFindings"].append({
                    "severity": "critical",
                    "range": range_cidr,
                    "issue": "Complete unrestricted access",
                    "description": "0.0.0.0/0 allows access from any IP address on the internet",
                    "recommendation": "Replace with specific IP ranges or CIDR blocks for your organization"
                })
            elif prefix_length <= 8:  # /8 or larger (16M+ addresses)
                self.api_server_access_analysis["securityFindings"].append({
                    "severity": "high",
                    "range": range_cidr,
                    "issue": "Very broad IP range",
                    "description": f"Range contains {num_addresses:,} addresses (/{prefix_length})",
                    "recommendation": "Consider narrowing to more specific IP ranges"
                })
            elif prefix_length <= 16:  # /16 or larger (65K+ addresses)
                self.api_server_access_analysis["securityFindings"].append({
                    "severity": "medium",
                    "range": range_cidr,
                    "issue": "Broad IP range",
                    "description": f"Range contains {num_addresses:,} addresses (/{prefix_length})",
                    "recommendation": "Review if this broad range is necessary"
                })
            elif prefix_length >= 32:  # Single IP
                if self.verbose:
                    self.logger.info(f"    ✅ Specific IP address: {range_cidr}")
            else:  # Reasonable range
                if self.verbose:
                    self.logger.info(f"    ✅ Reasonable range: {range_cidr} ({num_addresses} addresses)")
            
            # Check for private IP ranges in authorized list
            if network.is_private:
                self.api_server_access_analysis["analysis"]["containsPrivateRanges"] = True
                if self.verbose:
                    self.logger.info(f"    📝 Private IP range detected: {range_cidr}")
            
        except Exception as e:
            self.api_server_access_analysis["securityFindings"].append({
                "severity": "warning",
                "range": range_cidr,
                "issue": "Invalid IP range format",
                "description": f"Could not parse IP range: {str(e)}",
                "recommendation": "Verify the CIDR notation is correct"
            })
    
    def _validate_api_security_configuration(self):
        """Validate API server security configuration"""
        # Check if run command is disabled
        disable_run_command = self.api_server_access_analysis["disableRunCommand"]
        if disable_run_command:
            if self.verbose:
                self.logger.info("  ✅ Run command is disabled (enhanced security)")
        else:
            if self.verbose:
                self.logger.info("  📝 Run command is enabled")
        
        # Check private cluster configuration
        is_private = self.api_server_access_analysis["privateCluster"]
        authorized_ranges = self.api_server_access_analysis["authorizedIpRanges"]
        
        if is_private and authorized_ranges:
            self.api_server_access_analysis["securityFindings"].append({
                "severity": "info",
                "issue": "Redundant configuration",
                "description": "Both private cluster and authorized IP ranges are enabled",
                "recommendation": "Private clusters don't need authorized IP ranges since they're already isolated"
            })
        elif not is_private and not authorized_ranges:
            self.api_server_access_analysis["securityFindings"].append({
                "severity": "medium",
                "issue": "Unrestricted public access",
                "description": "API server is publicly accessible without IP restrictions",
                "recommendation": "Consider enabling authorized IP ranges or converting to a private cluster"
            })
    
    def _analyze_access_restrictions(self):
        """Analyze access restrictions and their implications"""
        authorized_ranges = self.api_server_access_analysis["authorizedIpRanges"]
        is_private = self.api_server_access_analysis["privateCluster"]
        
        # Determine access model
        if is_private:
            access_model = "private"
            access_description = "Private cluster - API server only accessible from VNet"
        elif authorized_ranges:
            access_model = "restricted_public"
            access_description = f"Public cluster with IP restrictions ({len(authorized_ranges)} range(s))"
        else:
            access_model = "unrestricted_public"
            access_description = "Public cluster with unrestricted access"
        
        self.api_server_access_analysis["accessRestrictions"] = {
            "model": access_model,
            "description": access_description,
            "implications": self._get_access_implications(access_model, authorized_ranges)
        }
    
    def _get_access_implications(self, access_model, authorized_ranges):
        """Get implications of the current access configuration"""
        implications = []
        
        if access_model == "private":
            implications.extend([
                "✅ API server is isolated from the internet",
                "✅ Access only from resources within the VNet or peered networks",
                "📝 Requires VPN or ExpressRoute for external access",
                "📝 Private DNS zone required for name resolution"
            ])
        elif access_model == "restricted_public":
            implications.extend([
                "✅ API server access is restricted to specified IP ranges",
                "⚠️ API server is still exposed to the internet",
                "📝 Users/services must access from authorized IP ranges",
                "📝 Node-to-API traffic must originate from authorized ranges"
            ])
            
            # Check if outbound IPs are in authorized ranges
            if hasattr(self, 'outbound_ips') and self.outbound_ips:
                self._check_outbound_ip_authorization(authorized_ranges, implications)
                
        else:  # unrestricted_public
            implications.extend([
                "⚠️ API server is publicly accessible from any IP",
                "⚠️ No network-level access restrictions",
                "📝 Security relies entirely on authentication and RBAC",
                "📝 Consider implementing IP restrictions for enhanced security"
            ])
        
        return implications
    
    def _check_outbound_ip_authorization(self, authorized_ranges, implications):
        """Check if cluster outbound IPs are authorized for API access"""
        if not authorized_ranges:
            return
        
        # Get outbound type from cluster network profile
        network_profile = self.cluster_info.get('networkProfile', {})
        outbound_type = network_profile.get('outboundType', 'loadBalancer')
        
        try:
            import ipaddress
            
            # Parse authorized ranges
            authorized_networks = []
            for range_cidr in authorized_ranges:
                try:
                    authorized_networks.append(ipaddress.ip_network(range_cidr, strict=False))
                except:
                    continue
            
            # Check each outbound IP
            unauthorized_outbound_ips = []
            for outbound_ip in self.outbound_ips:
                # Clean up IP (remove port, prefix notation, etc.)
                clean_ip = outbound_ip.split(':')[0].split('/')[0].strip()
                if '(' in clean_ip:  # Handle "IP (range)" format
                    clean_ip = clean_ip.split('(')[0].strip()
                
                try:
                    ip_addr = ipaddress.ip_address(clean_ip)
                    is_authorized = any(ip_addr in network for network in authorized_networks)
                    
                    if not is_authorized:
                        unauthorized_outbound_ips.append(clean_ip)
                except:
                    continue
            
            if unauthorized_outbound_ips:
                # Special handling for managedNATGateway outbound type
                if outbound_type == 'managedNATGateway':
                    implications.append(f"ℹ️ Outbound IPs not in authorized ranges: {', '.join(unauthorized_outbound_ips)}")
                    implications.append("📝 Note: With managedNATGateway, nodes use internal Azure networking for API access")
                    implications.append("📝 Authorized IP ranges primarily restrict external access, not internal node communication")
                    
                    # Add to security findings with informational severity for managedNATGateway
                    self.api_server_access_analysis["securityFindings"].append({
                        "severity": "info",
                        "issue": "Outbound IPs not in authorized ranges (managedNATGateway)",
                        "description": f"Cluster outbound IPs ({', '.join(unauthorized_outbound_ips)}) are not in authorized IP ranges. However, with managedNATGateway outbound type, nodes use internal Azure networking paths for API server communication that bypass these restrictions.",
                        "recommendation": "Monitor actual connectivity with --probe-test. Consider adding NAT Gateway IPs to authorized ranges if external tools need to match node source IPs, but this is not required for cluster functionality."
                    })
                else:
                    implications.append(f"❌ Outbound IPs not in authorized ranges: {', '.join(unauthorized_outbound_ips)}")
                    implications.append("📝 Nodes may not be able to communicate with API server")
                    
                    # Add to security findings with critical severity for other outbound types
                    self.api_server_access_analysis["securityFindings"].append({
                        "severity": "critical",
                        "issue": "Outbound IPs not authorized",
                        "description": f"Cluster outbound IPs ({', '.join(unauthorized_outbound_ips)}) are not in authorized IP ranges",
                        "recommendation": "Add cluster outbound IPs to authorized ranges or nodes cannot access the API server"
                    })
            else:
                implications.append("✅ All outbound IPs are in authorized ranges")
                
        except Exception as e:
            implications.append(f"⚠️ Could not validate outbound IP authorization: {e}")
    
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
        """Check API server connectivity and network reachability from cluster nodes"""
        self.logger.info("Checking API connectivity...")
        
        if not self.probe_test:
            self.logger.info("API connectivity probing disabled. Use --probe-test to enable active connectivity checks.")
            return
        
        # Check if cluster is stopped
        power_state = self.cluster_info.get('powerState', {})
        power_code = power_state.get('code', 'Unknown') if isinstance(power_state, dict) else str(power_state)
        
        if power_code.lower() == 'stopped':
            self.logger.info("Cluster is in stopped state. Skipping connectivity tests.")
            self.api_probe_results = {
                "enabled": False,
                "skipped": True,
                "reason": "Cluster is stopped",
                "tests": [],
                "summary": {
                    "total_tests": 0,
                    "passed": 0,
                    "failed": 0,
                    "errors": 0
                }
            }
            return
        
        # Check if cluster has failed
        provisioning_state = self.cluster_info.get('provisioningState', '')
        if provisioning_state.lower() == 'failed':
            self.logger.info("Cluster is in failed state. Connectivity tests may not be reliable.")
        
        self.logger.info("Starting active connectivity probes from VMSS instances...")
        
        # Initialize probe results
        self.api_probe_results = {
            "enabled": True,
            "tests": [],
            "summary": {
                "total_tests": 0,
                "passed": 0,
                "failed": 0,
                "errors": 0
            }
        }
        
        # Get VMSS instances for testing (limited to first available for performance)
        vmss_instances = self._list_ready_vmss_instances()
        if not vmss_instances:
            self.logger.info("No VMSS instances found for connectivity testing")
            return
        
        # Run connectivity tests on only the first available VMSS to avoid long execution times
        # in clusters with many node pools
        first_vmss = vmss_instances[0]
        total_vmss_count = len(vmss_instances)
        if total_vmss_count > 1:
            self.logger.info(
                "Found %s VMSS instance(s). Testing connectivity from the first one: %s (skipping %s others for performance)",
                total_vmss_count,
                first_vmss.vmss_name,
                total_vmss_count - 1,
            )
        else:
            self.logger.info("Found %s VMSS instance(s). Testing connectivity from: %s", total_vmss_count, first_vmss.vmss_name)
        
        self._run_vmss_connectivity_tests(first_vmss)
    
    def _list_ready_vmss_instances(self) -> List[VMSSInstance]:
        """Return one ready instance per VMSS for connectivity probing."""
        instances: List[VMSSInstance] = []
        mc_rg = self.cluster_info.get('nodeResourceGroup', '')
        if not mc_rg:
            return instances

        try:
            vmss_list = self.run_azure_cli(['vmss', 'list', '-g', mc_rg, '-o', 'json'])
        except RuntimeError as exc:
            self.logger.info(f"Error listing VMSS in {mc_rg}: {exc}")
            return instances

        if not isinstance(vmss_list, list):
            return instances

        for vmss in vmss_list:
            vmss_name = vmss.get('name')
            if not vmss_name:
                continue

            try:
                vmss_nodes = self.run_azure_cli(['vmss', 'list-instances', '-g', mc_rg, '-n', vmss_name, '-o', 'json'])
            except RuntimeError as exc:
                self.logger.info(f"Error listing instances for VMSS {vmss_name}: {exc}")
                continue

            if not isinstance(vmss_nodes, list):
                continue

            for node in vmss_nodes:
                if node.get('provisioningState') != 'Succeeded':
                    continue

                instances.append(
                    VMSSInstance(
                        vmss_name=vmss_name,
                        resource_group=mc_rg,
                        instance_id=str(node.get('instanceId', '0')),
                        metadata={'vmss': vmss, 'instance': node},
                    )
                )
                break  # Only need one ready instance per VMSS

        return instances
    
    def _run_vmss_connectivity_tests(self, vmss_instance: VMSSInstance):
        """Run connectivity tests on a VMSS instance"""
        vmss_name = vmss_instance.vmss_name
        resource_group = vmss_instance.resource_group
        instance_id = vmss_instance.instance_id
        
        self.logger.info(f"Running connectivity tests on VMSS {vmss_name}, instance {instance_id}")
        
        # Define connectivity test groups (DNS first, then HTTPS if DNS succeeds)
        test_groups = [
            {
                'service': 'Microsoft Container Registry',
                'dns_test': {
                    'name': 'DNS Resolution - Microsoft Container Registry',
                    'script': 'nslookup mcr.microsoft.com',
                    'timeout': 10,
                    'expected_keywords': ['Address:', 'mcr.microsoft.com']
                },
                'connectivity_test': {
                    'name': 'HTTPS Connectivity - Microsoft Container Registry',
                    'script': 'timeout 10 curl -v --insecure --proxy-insecure https://mcr.microsoft.com/v2/',
                    'timeout': 15,
                    'expected_keywords': ['HTTP/', 'Connected to']
                }
            },
            {
                'service': 'Azure Management',
                'dns_test': {
                    'name': 'DNS Resolution - Azure Management',
                    'script': 'nslookup management.azure.com',
                    'timeout': 10,
                    'expected_keywords': ['Address:', 'management.azure.com']
                },
                'connectivity_test': {
                    'name': 'HTTPS Connectivity - Azure Management',
                    'script': 'timeout 10 curl -v --insecure --proxy-insecure https://management.azure.com',
                    'timeout': 15,
                    'expected_keywords': ['HTTP/', 'Connected to']
                }
            }
        ]
        
        # Add cluster-specific tests
        api_server_fqdn = self._get_api_server_fqdn()
        if api_server_fqdn:
            # Extract hostname from URL for DNS resolution test
            api_hostname = api_server_fqdn.replace('https://', '').replace('http://', '')
            
            # For private clusters, we need to validate that DNS returns a private IP
            is_private_cluster = self._is_private_cluster()
            if is_private_cluster:
                dns_test = {
                    'name': f'DNS Resolution - API Server (Private)',
                    'script': f'nslookup {api_hostname}',
                    'timeout': 15,  # Reduced timeout for DNS tests
                    'expected_keywords': ['Address:', api_hostname.split('.')[0]],
                    'validate_private_ip': True,  # Special flag for private IP validation
                    'hostname': api_hostname
                }
            else:
                dns_test = {
                    'name': f'DNS Resolution - API Server',
                    'script': f'nslookup {api_hostname}',
                    'timeout': 10,
                    'expected_keywords': ['Address:', api_hostname.split('.')[0]]
                }
            
            # Use AKS node provisioning style API server test with proper cert validation
            # For private clusters, use the hostname:port format; for public clusters, use the full URL
            if is_private_cluster:
                api_connectivity_script = f'timeout 10 curl -v --cacert /etc/kubernetes/certs/ca.crt https://{api_hostname}:443'
            else:
                api_connectivity_script = f'timeout 10 curl -v --cacert /etc/kubernetes/certs/ca.crt {api_server_fqdn}:443'
            
            api_test_group = {
                'service': 'API Server',
                'dns_test': dns_test,
                'connectivity_test': {
                    'name': f'API Server Connectivity - {api_server_fqdn}',
                    'script': api_connectivity_script,
                    'timeout': 15,
                    'expected_keywords': ['Connected to', 'HTTP/']
                }
            }
            test_groups.append(api_test_group)
        
        # Execute test groups with DNS-first logic
        for group in test_groups:
            service_name = group['service']
            
            # Always run DNS test first
            self.logger.info(f"  Testing {service_name} - DNS Resolution")
            dns_result = self._execute_vmss_test(vmss_instance, group['dns_test'])
            
            # Only run connectivity test if DNS succeeded
            if dns_result and dns_result.get('status') == 'passed':
                self.logger.info(f"  Testing {service_name} - HTTPS Connectivity")
                self._execute_vmss_test(vmss_instance, group['connectivity_test'])
            else:
                # DNS failed, skip connectivity test and log why
                self.logger.info(f"  Skipping {service_name} HTTPS test - DNS resolution failed")
                
                # Create a skipped test result for the connectivity test
                skipped_result = {
                    'test_name': group['connectivity_test']['name'],
                    'vmss_name': vmss_instance.vmss_name,
                    'instance_id': vmss_instance.instance_id,
                    'status': 'skipped',
                    'exit_code': -1,
                    'output': '',
                    'stderr': '',
                    'error': f"Skipped due to DNS resolution failure for {service_name}",
                    'execution_time': 0,
                    'analysis': f"Test skipped because DNS resolution for {service_name} failed"
                }
                
                # Add to test results
                if 'tests' not in self.api_probe_results:
                    self.api_probe_results['tests'] = []
                self.api_probe_results['tests'].append(skipped_result)
    
    def _get_api_server_fqdn(self):
        """Get the API server FQDN for testing"""
        try:
            # Check if this is a private cluster
            api_server_profile = self.cluster_info.get('apiServerAccessProfile', {})
            if api_server_profile is None:
                api_server_profile = {}
            
            is_private = api_server_profile.get('enablePrivateCluster', False)
            
            if is_private:
                # For private clusters, try multiple sources for private FQDN
                private_fqdn = ''
                if api_server_profile.get('privateFqdn'):
                    private_fqdn = api_server_profile.get('privateFqdn', '')
                elif self.cluster_info.get('privateFqdn'):
                    private_fqdn = self.cluster_info.get('privateFqdn', '')
                
                if private_fqdn:
                    return f'https://{private_fqdn}'
            
            # For public clusters or fallback, use public FQDN
            fqdn = self.cluster_info.get('fqdn', '')
            if fqdn:
                return f'https://{fqdn}'
            
            # Final fallback - try private FQDN from either location
            private_fqdn = api_server_profile.get('privateFqdn', '') or self.cluster_info.get('privateFqdn', '')
            if private_fqdn:
                return f'https://{private_fqdn}'
            
            return None
        except Exception as e:
            self.logger.info(f"Error getting API server FQDN: {e}")
            return None
    
    def _is_private_cluster(self):
        """Check if this is a private AKS cluster"""
        try:
            api_server_profile = self.cluster_info.get('apiServerAccessProfile', {})
            if api_server_profile is None:
                return False
            return api_server_profile.get('enablePrivateCluster', False)
        except Exception:
            return False
    
    def _execute_vmss_test(self, vmss_instance: VMSSInstance, test):
        """Execute a single connectivity test on VMSS instance"""
        vmss_name = vmss_instance.vmss_name
        resource_group = vmss_instance.resource_group
        instance_id = vmss_instance.instance_id
        
        try:
            self.logger.info(f"  Running test: {test['name']}")
            
            # Build the run-command
            cmd = ['vmss', 'run-command', 'invoke']
            if self.subscription:
                cmd.extend(['--subscription', self.subscription])
            cmd.extend([
                '-g', resource_group,
                '-n', vmss_name,
                '--command-id', 'RunShellScript',
                '--instance-id', instance_id,
                '--scripts', test['script'],
                '-o', 'json'
            ])
            
            # Execute the command with timeout - use special handling for VMSS commands
            result = self._run_vmss_command(cmd)
            
            # Analyze results
            test_result = self._analyze_test_result(test, result)
            test_result.update({
                'vmss_name': vmss_name,
                'instance_id': instance_id,
                'test_name': test['name']
            })
            
            self.api_probe_results['tests'].append(test_result)
            self.api_probe_results['summary']['total_tests'] += 1
            
            if test_result['status'] == 'passed':
                self.api_probe_results['summary']['passed'] += 1
                self.logger.info(f"    ✅ PASSED: {test['name']}")
            elif test_result['status'] == 'failed':
                self.api_probe_results['summary']['failed'] += 1
                self.logger.info(f"    ❌ FAILED: {test['name']} - {test_result.get('error', 'Unknown error')}")
            else:
                self.api_probe_results['summary']['errors'] += 1
                self.logger.info(f"    ⚠️ ERROR: {test['name']} - {test_result.get('error', 'Execution error')}")
            
            return test_result
                
        except Exception as e:
            error_result = {
                'vmss_name': vmss_name,
                'instance_id': instance_id,
                'test_name': test['name'],
                'status': 'error',
                'error': str(e),
                'output': '',
                'execution_time': 0
            }
            self.api_probe_results['tests'].append(error_result)
            self.api_probe_results['summary']['total_tests'] += 1
            self.api_probe_results['summary']['errors'] += 1
            self.logger.info(f"    ⚠️ ERROR: {test['name']} - {str(e)}")
            return error_result
    
    def _run_vmss_command(self, cmd: List[str]) -> Any:
        """Run VMSS command with enhanced error handling"""
        cmd_str = ' '.join(cmd)
        
        try:
            result = subprocess.run(
                ['az'] + cmd,
                capture_output=True,
                text=True,
                timeout=VMSS_COMMAND_TIMEOUT
            )
            
            output = result.stdout.strip()
            
            # For VMSS run-command, even successful commands might have exit code != 0
            # if the script inside fails, so we need to parse the output regardless
            if output:
                try:
                    return json.loads(output)
                except json.JSONDecodeError:
                    # Return raw output if JSON parsing fails
                    return {"raw_output": output, "stderr": result.stderr}
            else:
                # No output but command might have failed
                return {
                    "error": "No output from VMSS command",
                    "stderr": result.stderr,
                    "exit_code": result.returncode
                }
                
        except subprocess.TimeoutExpired:
            return {
                "error": f"VMSS command timed out after {VMSS_COMMAND_TIMEOUT} seconds",
                "stderr": "Command execution timeout - This often indicates DNS resolution failure for private clusters with missing private DNS zone links"
            }
        except subprocess.CalledProcessError as e:
            # This is where the Azure CLI command itself failed
            return {
                "error": f"Azure CLI command failed: {e}",
                "stderr": e.stderr if hasattr(e, 'stderr') else str(e),
                "exit_code": e.returncode if hasattr(e, 'returncode') else -1
            }
        except Exception as e:
            return {
                "error": f"Unexpected error running VMSS command: {str(e)}",
                "stderr": str(e)
            }
    
    def _analyze_test_result(self, test, result):
        """Analyze the result of a connectivity test"""
        test_result = {
            'status': 'error',
            'output': '',
            'stderr': '',
            'error': '',
            'execution_time': 0,
            'exit_code': -1
        }
        
        try:
            if isinstance(result, dict):
                # Check if this is an error from our _run_vmss_command method
                if 'error' in result and 'value' not in result:
                    # This means the Azure CLI command itself failed
                    test_result['error'] = result.get('error', 'Unknown Azure CLI error')
                    test_result['stderr'] = result.get('stderr', '')
                    test_result['exit_code'] = result.get('exit_code', -1)
                    test_result['status'] = 'error'
                    return test_result
                
                # Check if command executed successfully
                value = result.get('value', [])
                if isinstance(value, list) and value:
                    first_result = value[0]
                    if isinstance(first_result, dict):
                        # Parse the message field to extract stdout/stderr
                        message = first_result.get('message', '')
                        stdout, stderr, exit_code = self._parse_vmss_message(message)
                        
                        test_result['output'] = stdout
                        test_result['stderr'] = stderr
                        test_result['exit_code'] = exit_code
                        test_result['execution_time'] = 0  # Not available in this format
                        
                        # Check if the command was successful
                        if first_result.get('code') == 'ProvisioningState/succeeded':
                            # Check for expected keywords in output
                            expected_keywords = test.get('expected_keywords', [])
                            
                            # Special validation for private IP DNS resolution
                            if test.get('validate_private_ip', False):
                                if self._validate_private_dns_resolution(stdout, test.get('hostname', '')):
                                    test_result['status'] = 'passed'
                                else:
                                    test_result['status'] = 'failed'
                                    test_result['error'] = "DNS resolved to public IP instead of private IP. Private DNS zone link may be missing or misconfigured."
                            else:
                                # For HTTP connectivity tests, we need special handling for expected HTTP responses
                                test_name = test.get('name', '').lower()
                                if 'connectivity' in test_name and 'http' in test_name:
                                    # For HTTP connectivity tests, check if we got a valid HTTP response
                                    if self._is_successful_http_connection(stdout, stderr, exit_code):
                                        test_result['status'] = 'passed'
                                    else:
                                        test_result['status'] = 'failed'
                                        # Provide specific error messages based on the failure type
                                        if exit_code != 0:
                                            if 'ssl' in stderr.lower() or 'tls' in stderr.lower():
                                                test_result['error'] = f"HTTPS connection failed due to SSL/TLS error (exit code: {exit_code})"
                                            elif 'timeout' in stderr.lower():
                                                test_result['error'] = f"Connection timeout (exit code: {exit_code})"
                                            elif 'refused' in stderr.lower():
                                                test_result['error'] = f"Connection refused (exit code: {exit_code})"
                                            else:
                                                test_result['error'] = f"HTTP connectivity test failed (exit code: {exit_code})"
                                        else:
                                            test_result['error'] = "HTTP connectivity test failed - no valid HTTP response detected"
                                else:
                                    # For non-HTTP tests (DNS, etc.), use the original logic
                                    if exit_code == 0:
                                        if self._check_expected_output_combined(test, stdout, stderr, expected_keywords):
                                            test_result['status'] = 'passed'
                                        else:
                                            test_result['status'] = 'failed'
                                            test_result['error'] = f"Command succeeded but expected output not found. Keywords: {expected_keywords}"
                                    else:
                                        # Exit code != 0 means the command failed
                                        test_result['status'] = 'failed'
                                        if 'dns' in test_name:
                                            test_result['error'] = f"DNS resolution failed (exit code: {exit_code})"
                                        else:
                                            test_result['error'] = f"Command failed with exit code: {exit_code}"
                        else:
                            test_result['status'] = 'failed'
                            test_result['error'] = f"VMSS command failed: {first_result.get('displayStatus', 'Unknown error')}"
                    else:
                        test_result['error'] = "Invalid result format"
                else:
                    test_result['error'] = "No command output received"
            else:
                test_result['error'] = "Invalid result type"
                
        except Exception as e:
            test_result['error'] = f"Result analysis failed: {str(e)}"
        
        return test_result
    
    def _parse_vmss_message(self, message):
        """Parse VMSS run-command message to extract stdout, stderr, and exit code"""
        stdout = ''
        stderr = ''
        exit_code = 0  # Default to success
        
        try:
            # The message format is typically:
            # "Enable succeeded: \n[stdout]\n...\n[stderr]\n..."
            if '[stdout]' in message:
                # Extract stdout section
                stdout_start = message.find('[stdout]') + len('[stdout]')
                if '[stderr]' in message:
                    stdout_end = message.find('[stderr]')
                    stdout = message[stdout_start:stdout_end].strip()
                    # Extract stderr section
                    stderr_start = message.find('[stderr]') + len('[stderr]')
                    stderr = message[stderr_start:].strip()
                else:
                    stdout = message[stdout_start:].strip()
            
            # If there's stderr content, it usually indicates an issue
            # but not necessarily a failure (warnings are common)
            if stderr and 'error' in stderr.lower():
                exit_code = 1
                
        except Exception:
            # If parsing fails, return the raw message as stdout
            stdout = message
        
        # Compact the output by replacing newlines with \n characters for JSON storage
        # This makes verbose output (like curl -v) more compact and JSON-friendly
        stdout = self._compact_output_for_json(stdout)
        stderr = self._compact_output_for_json(stderr)
            
        return stdout, stderr, exit_code
    
    def _compact_output_for_json(self, output):
        """Compact multi-line output into a single line with \\n characters for better JSON formatting"""
        if not output:
            return output
        
        # Replace actual newlines with \n characters and clean up extra whitespace
        compacted = output.replace('\n', '\\n').replace('\r', '')
        
        # Remove excessive whitespace sequences that might occur
        import re
        compacted = re.sub(r'\\n\s*\\n', '\\n', compacted)  # Remove empty lines
        compacted = re.sub(r'\s+', ' ', compacted)  # Collapse multiple spaces
        compacted = compacted.strip()
        
        return compacted
    
    def _is_successful_http_connection(self, stdout, stderr, exit_code):
        """Check if an HTTP connectivity test was successful"""
        # Combine stdout and stderr for analysis since curl -v outputs to both
        # Handle both regular newlines and compacted \\n format
        combined_output = f"{stdout}\n{stderr}".lower()
        # Convert \\n back to actual newlines for pattern matching
        combined_output = combined_output.replace('\\n', '\n')
        
        # First, check for clear failure indicators that should always result in failure
        critical_failure_indicators = [
            'connection refused',
            'connection timed out', 
            'could not resolve host',
            'network is unreachable',
            'ssl routines::unexpected eof while reading',  # SSL handshake interrupted (firewall/proxy)
            'ssl connect error',
            'certificate verify failed',
            'operation timed out',
            'recv failure: connection reset by peer'
        ]
        
        has_critical_failure = any(indicator in combined_output for indicator in critical_failure_indicators)
        if has_critical_failure:
            return False
        
        # If exit code is non-zero, generally means failure unless we have specific exceptions
        if exit_code != 0:
            # Only allow non-zero exit codes if we have a complete HTTP response
            if not any(indicator in combined_output for indicator in ['http/1.1', 'http/2', 'http/1.0']):
                return False
        
        # Check for successful connection indicators
        connection_indicators = [
            'connected to',           # TCP connection established
        ]
        
        # Check for successful HTTP response indicators  
        http_response_indicators = [
            'http/1.1',              # HTTP/1.1 response
            'http/2',                # HTTP/2 response  
            'http/1.0'               # HTTP/1.0 response
        ]
        
        # We need BOTH a connection AND a valid HTTP response for success
        has_connection = any(indicator in combined_output for indicator in connection_indicators)
        has_http_response = any(indicator in combined_output for indicator in http_response_indicators)
        
        if has_connection and has_http_response:
            # For specific services, certain HTTP status codes are expected and should be considered success
            
            # Microsoft Container Registry: 400 responses are normal for GET requests without parameters
            if 'mcr.microsoft.com' in combined_output:
                if any(status in combined_output for status in ['http/2 400', 'http/1.1 400', '400 bad request']):
                    return True  # MCR returns 400 for unauthorized/invalid requests, but connection is successful
            
            # Azure Management API: Various responses are acceptable
            if 'management.azure.com' in combined_output:
                # 200, 401, 403 are all valid responses indicating successful connectivity
                if any(status in combined_output for status in ['http/2 200', 'http/2 401', 'http/2 403', 
                                                                'http/1.1 200', 'http/1.1 401', 'http/1.1 403']):
                    return True
            
            # For AKS API server, 401/403 responses are normal without authentication
            if any(api_indicator in combined_output for api_indicator in ['azmk8s.io', 'hcp.']):
                if any(status in combined_output for status in ['http/2 401', 'http/2 403', 'http/1.1 401', 'http/1.1 403']):
                    return True
            
            # Generic success: any complete HTTP response indicates successful connectivity
            # Even error responses (4xx, 5xx) mean we connected successfully and completed the SSL handshake
            http_response_patterns = [
                'content-length:', 'content-type:',    # Response headers
                'x-ms-', 'server:'                     # Common response headers
            ]
            
            if any(pattern in combined_output for pattern in http_response_patterns):
                return True
        
        # If we only have connection but no HTTP response, it's likely a firewall/proxy issue
        if has_connection and not has_http_response:
            return False
        
        # No connection established
        return False
    
    def _check_expected_output(self, output, expected_keywords):
        """Check if output contains expected keywords"""
        if not expected_keywords:
            return True  # No specific expectations
        
        # Handle compacted output format
        output_to_check = output.replace('\\n', '\n').lower()
        for keyword in expected_keywords:
            if keyword.lower() not in output_to_check:
                return False
        return True
    
    def _check_expected_output_combined(self, test, stdout, stderr, expected_keywords):
        """Check if output contains expected keywords, looking in both stdout and stderr for HTTP tests"""
        if not expected_keywords:
            return True  # No specific expectations
        
        # For HTTP connectivity tests, curl -v puts connection info in stderr
        test_name = test.get('name', '').lower()
        if 'http' in test_name or 'connectivity' in test_name:
            # Combine stdout and stderr for HTTP tests since curl -v uses stderr for connection details
            # Handle compacted format by converting \\n back to newlines for pattern matching
            combined_output = f"{stdout}\n{stderr}".replace('\\n', '\n').lower()
            for keyword in expected_keywords:
                if keyword.lower() not in combined_output:
                    return False
            return True
        else:
            # For other tests (like DNS), use only stdout
            return self._check_expected_output(stdout, expected_keywords)
    
    def _validate_private_dns_resolution(self, nslookup_output, hostname):
        """Validate that DNS resolution returns a private IP address for private clusters"""
        import ipaddress
        import re
        
        try:
            # Convert compacted format back to regular format for parsing
            output_to_parse = nslookup_output.replace('\\n', '\n')
            
            # Check for DNS resolution failures first
            dns_error_patterns = [
                'nxdomain', 'servfail', 'refused', "can't find", 
                'no servers could be reached', 'communications error', 'timed out'
            ]
            if any(error in output_to_parse.lower() for error in dns_error_patterns):
                return False  # DNS resolution failed completely
            
            # Parse nslookup output to extract IP addresses
            # Look for lines like "Address: 10.1.2.3" or "10.1.2.3"
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            found_ips = re.findall(ip_pattern, output_to_parse)
            
            if not found_ips:
                return False  # No IP addresses found
            
            # Filter out DNS server IPs (usually the first IP listed)
            # DNS server IPs are typically shown as "Server: 10.1.0.10" or "Address: 10.1.0.10#53"
            dns_server_pattern = r'(?:Server:|Address:)\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})(?:#\d+)?'
            dns_server_ips = set(re.findall(dns_server_pattern, output_to_parse))
            
            # Check resolved IPs (excluding DNS server IPs)
            resolved_ips = [ip for ip in found_ips if ip not in dns_server_ips]
            
            if not resolved_ips:
                return False  # Only DNS server IPs found, no actual resolution
            
            # Check if any of the resolved IPs are private
            for ip_str in resolved_ips:
                try:
                    ip = ipaddress.ip_address(ip_str)
                    # Check if this is a private IP address
                    if ip.is_private:
                        # Additional validation: private IPs for AKS API servers are typically in specific ranges
                        # Common AKS private IP ranges: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
                        return True
                except ValueError:
                    continue  # Skip invalid IP addresses
            
            # If we found IP addresses but none were private, this indicates the issue
            return False
            
        except Exception as e:
            # If we can't parse the output, be conservative and check for any error indicators
            dns_error_patterns = [
                'nxdomain', 'servfail', 'refused', "can't find", 
                'no servers could be reached', 'communications error', 'timed out'
            ]
            # Return False if any error patterns are found, True only if none are found
            return not any(error in nslookup_output.lower() for error in dns_error_patterns)
    
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
        
        # Check for missing outbound IPs
        if not self.outbound_ips:
            findings.append({
                "severity": "warning",
                "code": "NO_OUTBOUND_IPS",
                "message": "No outbound IP addresses detected",
                "recommendation": "Verify outbound connectivity configuration"
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
        
        self.findings = findings
    
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
        """Generate comprehensive report"""
        self.logger.info("Generating comprehensive report...")
        
        # Prepare all data for JSON report
        report_data = {
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "version": SCRIPT_VERSION,
                "generatedBy": "AKS Network Diagnostics Script (Python)"
            },
            "cluster": {
                "name": self.aks_name,
                "resourceGroup": self.aks_rg,
                "subscription": self.subscription,
                "provisioningState": self.cluster_info.get('provisioningState', ''),
                "location": self.cluster_info.get('location', ''),
                "nodeResourceGroup": self.cluster_info.get('nodeResourceGroup', ''),
                "networkProfile": self.cluster_info.get('networkProfile', {}),
                "apiServerAccess": self.cluster_info.get('apiServerAccessProfile', {})
            },
            "networking": {
                "vnets": self.vnets_analysis,
                "outbound": self.outbound_analysis,
                "privateDns": self.private_dns_analysis,
                "apiServerAccess": self.api_server_access_analysis,
                "vmssConfiguration": self.vmss_analysis,
                "nsgConfiguration": self.nsg_analysis,
                "routingAnalysis": {
                    "outboundType": self.cluster_info.get('networkProfile', {}).get('outboundType', 'loadBalancer'),
                    "udrAnalysis": self.outbound_analysis.get("udrAnalysis")
                }
            },
            "diagnostics": {
                "apiConnectivityProbe": self.api_probe_results,
                "failureAnalysis": self.failure_analysis,
                "findings": self.findings
            }
        }
        
        # Output console report
        self._print_console_report()
        
        # Output JSON report if not disabled
        if not self.no_json and self.json_out:
            try:
                # Create file with secure permissions (owner read/write only)
                import stat
                with open(self.json_out, 'w') as f:
                    json.dump(report_data, f, indent=2)
                
                # Set secure file permissions (readable/writable by owner only)
                os.chmod(self.json_out, DEFAULT_FILE_PERMISSIONS)
                self.logger.info(f"📄 JSON report saved to: {self.json_out}")
            except Exception as e:
                self.logger.error(f"Failed to save JSON report: {e}")
    
    def _print_console_report(self):
        """Print console report"""
        print("\n" + "=" * 74)
        
        if self.verbose:
            self._print_verbose_report()
        else:
            self._print_summary_report()
        
        print(f"\n✅ AKS network assessment completed successfully!")
    
    def _print_summary_report(self):
        """Print summary report"""
        print("# AKS Network Assessment Summary")
        print()
        print(f"**Cluster:** {self.aks_name} ({self.cluster_info.get('provisioningState', 'Unknown')})")
        print(f"**Resource Group:** {self.aks_rg}")
        print(f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print()
        
        print("**Configuration:**")
        network_profile = self.cluster_info.get('networkProfile', {})
        print(f"- Network Plugin: {network_profile.get('networkPlugin', 'kubenet')}")
        print(f"- Outbound Type: {network_profile.get('outboundType', 'loadBalancer')}")
        
        api_server_profile = self.cluster_info.get('apiServerAccessProfile')
        is_private = api_server_profile.get('enablePrivateCluster', False) if api_server_profile else False
        print(f"- Private Cluster: {str(is_private).lower()}")
        
        if self.outbound_ips or (self.outbound_analysis and self.outbound_analysis.get('effectiveOutbound')):
            print()
            print("**Outbound Configuration:**")
            
            effective_outbound = self.outbound_analysis.get('effectiveOutbound', {}) if self.outbound_analysis else {}
            
            if effective_outbound.get('overridden_by_udr'):
                # UDR overrides the load balancer
                print("- Configured Load Balancer IPs (not effective):")
                for ip in self.outbound_ips:
                    print(f"  - {ip}")
                print("- Effective Outbound (via UDR):")
                for ip in effective_outbound.get('virtual_appliance_ips', []):
                    print(f"  - Virtual Appliance: {ip}")
            else:
                # No UDR override, show based on configured mechanism
                outbound_type = self.outbound_analysis.get('type', 'loadBalancer') if self.outbound_analysis else 'loadBalancer'
                
                if outbound_type == 'loadBalancer' and self.outbound_ips:
                    print("- Load Balancer IPs:")
                    for ip in self.outbound_ips:
                        print(f"  - {ip}")
                elif outbound_type == 'userDefinedRouting' and effective_outbound.get('virtual_appliance_ips'):
                    print("- Virtual Appliance IPs:")
                    for ip in effective_outbound.get('virtual_appliance_ips', []):
                        print(f"  - {ip}")
                elif self.outbound_ips:
                    # Fallback to showing configured IPs
                    print("- Outbound IPs:")
                    for ip in self.outbound_ips:
                        print(f"  - {ip}")
        
        print()
        print("**Findings Summary:**")
        
        critical_findings = [f for f in self.findings if f.get('severity') in ['critical', 'error']]
        warning_findings = [f for f in self.findings if f.get('severity') == 'warning']
        
        if len(critical_findings) == 0 and len(warning_findings) == 0:
            print("- ✅ No critical issues detected")
        else:
            # Show critical/error findings
            for finding in critical_findings:
                # For cluster operation failures, show only the error code in non-verbose mode
                if finding.get('code') == 'CLUSTER_OPERATION_FAILURE' and finding.get('error_code'):
                    print(f"- ❌ Cluster failed with error: {finding.get('error_code')}")
                else:
                    message = finding.get('message', 'Unknown issue')
                    print(f"- ❌ {message}")
            
            # Show warning findings
            for finding in warning_findings:
                message = finding.get('message', 'Unknown issue')
                print(f"- ⚠️ {message}")
        
        print()
        print("Tip: Use --verbose flag for detailed analysis or check the JSON report for complete findings.")
    
    def _print_verbose_report(self):
        """Print detailed verbose report"""
        print("# AKS Network Assessment Report")
        print()
        print(f"**Cluster:** {self.aks_name}")
        print(f"**Resource Group:** {self.aks_rg}")
        print(f"**Subscription:** {self.subscription}")
        print(f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print()
        
        # Cluster overview
        print("## Cluster Overview")
        print()
        print("| Property | Value |")
        print("|----------|-------|")
        print(f"| Provisioning State | {self.cluster_info.get('provisioningState', '')} |")
        
        # Show power state
        power_state = self.cluster_info.get('powerState', {})
        power_code = power_state.get('code', 'Unknown') if isinstance(power_state, dict) else str(power_state)
        print(f"| Power State | {power_code} |")
        
        print(f"| Location | {self.cluster_info.get('location', '')} |")
        
        network_profile = self.cluster_info.get('networkProfile', {})
        print(f"| Network Plugin | {network_profile.get('networkPlugin', 'kubenet')} |")
        print(f"| Outbound Type | {network_profile.get('outboundType', 'loadBalancer')} |")
        
        api_server_profile = self.cluster_info.get('apiServerAccessProfile')
        is_private = api_server_profile.get('enablePrivateCluster', False) if api_server_profile else False
        print(f"| Private Cluster | {str(is_private).lower()} |")
        print()
        
        # Network configuration
        print("## Network Configuration")
        print()
        print("### Service Network")
        print(f"- **Service CIDR:** {network_profile.get('serviceCidr', '')}")
        print(f"- **DNS Service IP:** {network_profile.get('dnsServiceIp', '')}")
        print(f"- **Pod CIDR:** {network_profile.get('podCidr', '')}")
        print()
        
        # API Server access
        print("### API Server Access")
        api_server_profile = self.cluster_info.get('apiServerAccessProfile')
        is_private = api_server_profile.get('enablePrivateCluster', False) if api_server_profile else False
        
        if is_private and api_server_profile:
            print("- **Type:** Private cluster")
            
            # Try multiple sources for private FQDN
            private_fqdn = ''
            if api_server_profile.get('privateFqdn'):
                private_fqdn = api_server_profile.get('privateFqdn', '')
            elif self.cluster_info.get('privateFqdn'):
                private_fqdn = self.cluster_info.get('privateFqdn', '')
            
            print(f"- **Private FQDN:** {private_fqdn}")
            print(f"- **Private DNS Zone:** {api_server_profile.get('privateDnsZone', '')}")
        else:
            print("- **Type:** Public cluster")
            print(f"- **Public FQDN:** {self.cluster_info.get('fqdn', '')}")
        
        # Add authorized IP ranges information
        if api_server_profile:
            authorized_ranges = api_server_profile.get('authorizedIpRanges', [])
            if authorized_ranges:
                print(f"- **Authorized IP Ranges:** {len(authorized_ranges)} range(s)")
                for range_cidr in authorized_ranges:
                    print(f"  - {range_cidr}")
                
                # Show access implications if we have the analysis
                if hasattr(self, 'api_server_access_analysis') and self.api_server_access_analysis:
                    access_restrictions = self.api_server_access_analysis.get('accessRestrictions', {})
                    implications = access_restrictions.get('implications', [])
                    if implications:
                        print("- **Access Implications:**")
                        for implication in implications:
                            print(f"  {implication}")
            else:
                print("- **Access Restrictions:** None (unrestricted public access)")
                if not is_private:
                    print("  ⚠️ API server is accessible from any IP address on the internet")
        
        print()
        
        # Outbound connectivity
        if self.outbound_ips:
            print("### Outbound Connectivity")
            print(f"- **Type:** {network_profile.get('outboundType', 'loadBalancer')}")
            print("- **Effective Public IPs:**")
            for ip in self.outbound_ips:
                print(f"  - {ip}")
            print()
        
        # UDR Analysis (if route tables found on node subnets)
        udr_analysis = self.outbound_analysis.get("udrAnalysis")
        if udr_analysis:
            print("### User Defined Routes Analysis")
            route_tables = udr_analysis.get("routeTables", [])
            if route_tables:
                print(f"- **Route Tables Found:** {len(route_tables)}")
                
                for rt in route_tables:
                    print(f"- **Route Table:** {rt.get('name', 'unnamed')}")
                    print(f"  - **Resource Group:** {rt.get('resourceGroup', '')}")
                    print(f"  - **BGP Propagation:** {'Disabled' if rt.get('disableBgpRoutePropagation') else 'Enabled'}")
                    print(f"  - **Routes:** {len(rt.get('routes', []))}")
                    
                    # Show critical routes
                    critical_routes = [r for r in rt.get('routes', []) if r.get('impact', {}).get('severity') in ['critical', 'high']]
                    if critical_routes:
                        print(f"  - **Critical Routes:**")
                        for route in critical_routes:
                            impact = route.get('impact', {})
                            print(f"    - {route.get('name', 'unnamed')} ({route.get('addressPrefix', '')}) → {route.get('nextHopType', '')} - {impact.get('description', '')}")
                
                # Show virtual appliance routes summary
                va_routes = udr_analysis.get("virtualApplianceRoutes", [])
                if va_routes:
                    print(f"- **Virtual Appliance Routes:** {len(va_routes)}")
                    for route in va_routes:
                        print(f"  - {route.get('name', 'unnamed')} ({route.get('addressPrefix', '')}) → {route.get('nextHopIpAddress', '')}")
                
                print()
            else:
                print("- **No route tables found on node subnets**")
                print()
        
        # Connectivity test results
        if hasattr(self, 'api_probe_results') and self.api_probe_results:
            print("### Connectivity Tests")
            
            if self.api_probe_results.get('skipped'):
                reason = self.api_probe_results.get('reason', 'Unknown reason')
                print(f"- **Status:** Skipped ({reason})")
                print()
            else:
                summary = self.api_probe_results.get('summary', {})
                total = summary.get('total_tests', 0)
                passed = summary.get('passed', 0)
                failed = summary.get('failed', 0)
                errors = summary.get('errors', 0)
                
                print(f"- **Tests Executed:** {total}")
                if passed > 0:
                    print(f"- **✅ Passed:** {passed}")
                if failed > 0:
                    print(f"- **❌ Failed:** {failed}")
                if errors > 0:
                    print(f"- **⚠️ Errors:** {errors}")
                
                # Show detailed results if verbose
                if self.verbose:
                    tests = self.api_probe_results.get('tests', [])
                    if tests:
                        print("\n**Test Details:**")
                        for test in tests:
                            status_icon = {
                                'passed': '✅',
                                'failed': '❌', 
                                'error': '⚠️'
                            }.get(test.get('status'), '❓')
                            
                            test_name = test.get('test_name', 'Unknown Test')
                            vmss_name = test.get('vmss_name', 'unknown')
                            exit_code = test.get('exit_code', -1)
                            print(f"- {status_icon} **{test_name}** (VMSS: {vmss_name}, Exit Code: {exit_code})")
                            
                            if test.get('status') in ['failed', 'error'] and test.get('error'):
                                print(f"  - Error: {test['error']}")
                            
                            if test.get('execution_time'):
                                print(f"  - Execution time: {test['execution_time']}s")
                            
                            # Show command output for debugging
                            stdout = test.get('output', '')
                            stderr = test.get('stderr', '')
                            
                            if stdout.strip():
                                print(f"  - **Command Output (stdout):**")
                                # Indent each line of output
                                for line in stdout.strip().split('\n'):
                                    print(f"    ```")
                                    print(f"    {line}")
                                    print(f"    ```")
                            
                            if stderr.strip():
                                print(f"  - **Command Error Output (stderr):**")
                                # Indent each line of stderr
                                for line in stderr.strip().split('\n'):
                                    print(f"    ```")
                                    print(f"    {line}")
                                    print(f"    ```")
                print()
        
        # NSG Analysis Results
        if hasattr(self, 'nsg_analysis') and self.nsg_analysis:
            print("### Network Security Group (NSG) Analysis")
            
            # NSG Analysis Summary
            subnet_nsgs = self.nsg_analysis.get('subnetNsgs', [])
            nic_nsgs = self.nsg_analysis.get('nicNsgs', [])
            total_nsgs = len(subnet_nsgs) + len(nic_nsgs)
            blocking_rules = self.nsg_analysis.get('blockingRules', [])
            inter_node_status = self.nsg_analysis.get('interNodeCommunication', {}).get('status', 'unknown')
            
            print(f"- **NSGs Analyzed:** {total_nsgs}")
            print(f"- **Issues Found:** {len(blocking_rules)}")
            
            # Inter-node communication status
            status_icon = {
                'ok': '✅',
                'potential_issues': '⚠️',
                'blocked': '❌',
                'unknown': '❓'
            }.get(inter_node_status, '❓')
            print(f"- **Inter-node Communication:** {status_icon} {inter_node_status.replace('_', ' ').title()}")
            
            # Show detailed NSG information in verbose mode
            if self.verbose and total_nsgs > 0:
                print()
                
                # Subnet NSGs
                if subnet_nsgs:
                    print("**Subnet NSGs:**")
                    for nsg in subnet_nsgs:
                        nsg_name = nsg.get('nsgName', 'unknown')
                        subnet_name = nsg.get('subnetName', 'unknown')
                        custom_rules = len(nsg.get('rules', []))
                        default_rules = len(nsg.get('defaultRules', []))
                        
                        print(f"- **{subnet_name}** → NSG: {nsg_name}")
                        print(f"  - Custom Rules: {custom_rules}, Default Rules: {default_rules}")
                        
                        # Show custom rules
                        if custom_rules > 0 and nsg.get('rules'):
                            print(f"  - **Custom Rules:**")
                            for rule in nsg.get('rules', []):
                                access = rule.get('access', 'Unknown')
                                direction = rule.get('direction', 'Unknown')
                                priority = rule.get('priority', 'Unknown')
                                protocol = rule.get('protocol', 'Unknown')
                                dest = rule.get('destinationAddressPrefix', 'Unknown')
                                ports = rule.get('destinationPortRange', 'Unknown')
                                
                                access_icon = '✅' if access.lower() == 'allow' else '❌'
                                print(f"    - {access_icon} **{rule.get('name', 'Unknown')}** (Priority: {priority})")
                                print(f"      - {direction} {protocol} to {dest} on ports {ports}")
                
                # NIC NSGs (deduplicated by NSG name)
                if nic_nsgs:
                    print("\n**NIC NSGs:**")
                    
                    # Group NICs by NSG name to avoid duplicates
                    nsg_groups = {}
                    for nsg in nic_nsgs:
                        nsg_name = nsg.get('nsgName', 'unknown')
                        vmss_name = nsg.get('vmssName', 'unknown')
                        
                        if nsg_name not in nsg_groups:
                            nsg_groups[nsg_name] = {
                                'nsg_data': nsg,
                                'vmss_list': []
                            }
                        nsg_groups[nsg_name]['vmss_list'].append(vmss_name)
                    
                    # Display each unique NSG with its associated VMSS instances
                    for nsg_name, group_data in nsg_groups.items():
                        nsg = group_data['nsg_data']
                        vmss_list = group_data['vmss_list']
                        custom_rules = len(nsg.get('rules', []))
                        default_rules = len(nsg.get('defaultRules', []))
                        
                        # Show NSG with all VMSS instances using it
                        vmss_names = ', '.join(vmss_list)
                        print(f"- **{nsg_name}** (used by: {vmss_names})")
                        print(f"  - Custom Rules: {custom_rules}, Default Rules: {default_rules}")
                        
                        # Show custom rules if any
                        if custom_rules > 0 and nsg.get('rules'):
                            print(f"  - **Custom Rules:**")
                            for rule in nsg.get('rules', []):
                                access = rule.get('access', 'Unknown')
                                direction = rule.get('direction', 'Unknown')
                                priority = rule.get('priority', 'Unknown')
                                protocol = rule.get('protocol', 'Unknown')
                                dest = rule.get('destinationAddressPrefix', 'Unknown')
                                ports = rule.get('destinationPortRange', 'Unknown')
                                
                                access_icon = '✅' if access.lower() == 'allow' else '❌'
                                print(f"    - {access_icon} **{rule.get('name', 'Unknown')}** (Priority: {priority})")
                                print(f"      - {direction} {protocol} to {dest} on ports {ports}")
                
                # Show blocking rules details
                if blocking_rules:
                    print("\n**⚠️ Potentially Blocking Rules:**")
                    for rule in blocking_rules:
                        print(f"- **{rule.get('ruleName', 'Unknown')}** in NSG {rule.get('nsgName', 'Unknown')}")
                        print(f"  - Priority: {rule.get('priority', 'Unknown')}")
                        print(f"  - Direction: {rule.get('direction', 'Unknown')}")
                        print(f"  - Protocol: {rule.get('protocol', 'Unknown')}")
                        print(f"  - Destination: {rule.get('destination', 'Unknown')}")
                        print(f"  - Ports: {rule.get('ports', 'Unknown')}")
                        print(f"  - Impact: {rule.get('impact', 'Unknown')}")
            
            print()
        
        # Findings
        if self.findings:
            print("## Findings")
            print()
            
            # Count findings by severity
            critical_count = len([f for f in self.findings if f.get('severity') == 'critical'])
            error_count = len([f for f in self.findings if f.get('severity') == 'error'])
            warning_count = len([f for f in self.findings if f.get('severity') == 'warning'])
            info_count = len([f for f in self.findings if f.get('severity') == 'info'])
            
            # Display findings summary
            print("**Findings Summary:**")
            if critical_count > 0:
                print(f"- 🔴 {critical_count} Critical issue(s)")
            if error_count > 0:
                print(f"- ❌ {error_count} Error issue(s)")
            if warning_count > 0:
                print(f"- ⚠️ {warning_count} Warning issue(s)")
            if info_count > 0:
                print(f"- ℹ️ {info_count} Informational finding(s)")
            print()
            
            # Display critical and error issues first
            critical_and_error_findings = [f for f in self.findings if f.get('severity') in ['critical', 'error']]
            if critical_and_error_findings:
                print("**Critical Issues:**")
                for finding in critical_and_error_findings:
                    print(f"- {finding.get('code', 'UNKNOWN')}: {finding.get('message', '')}")
                print()
            
            # Display all findings in detail
            for finding in self.findings:
                severity_icon = {
                    'critical': '🔴',
                    'error': '❌',
                    'warning': '⚠️',
                    'info': 'ℹ️'
                }.get(finding.get('severity', 'info'), 'ℹ️')
                
                print(f"### {severity_icon} {finding.get('code', 'UNKNOWN')}")
                print(f"**Severity:** {finding.get('severity', 'info').upper()}")
                print(f"**Message:** {finding.get('message', '')}")
                if finding.get('recommendation'):
                    print(f"**Recommendation:** {finding.get('recommendation', '')}")
                print()
        else:
            print("✅ No issues detected in the network configuration!")
            print()
    
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
