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
from aks_diagnostics.misconfiguration_analyzer import MisconfigurationAnalyzer
from aks_diagnostics.azure_cli import AzureCLIExecutor
from aks_diagnostics.cache import CacheManager
from aks_diagnostics.validators import InputValidator
from aks_diagnostics.exceptions import ValidationError

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
        self.aks_name = InputValidator.validate_resource_name(args.name, "cluster name")
        self.aks_rg = InputValidator.validate_resource_name(args.resource_group, "resource group")
        
        # Validate optional arguments
        if args.subscription:
            self.subscription = InputValidator.validate_subscription_id(args.subscription)
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
                safe_cluster_name = InputValidator.sanitize_filename(self.aks_name)
                self.json_report = f"aks-net-diagnostics_{safe_cluster_name}_{timestamp}.json"
            else:
                # Validate user-provided filename
                self.json_report = InputValidator.validate_output_path(self.json_report)
    
    def run_azure_cli(self, cmd: List[str], expect_json: bool = True) -> Any:
        """Run Azure CLI command and return result"""
        # Validate command arguments to prevent injection
        InputValidator.validate_azure_cli_command(cmd)
        
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
        """Analyze potential misconfigurations and failures using MisconfigurationAnalyzer"""
        analyzer = MisconfigurationAnalyzer(self.azure_cli_executor, self.logger)
        
        # Run analysis and get findings
        findings, cluster_stopped = analyzer.analyze(
            cluster_info=self.cluster_info,
            outbound_analysis=self.outbound_analysis,
            outbound_ips=self.outbound_ips,
            private_dns_analysis=self.private_dns_analysis,
            api_server_access_analysis=self.api_server_access_analysis,
            nsg_analysis=self.nsg_analysis,
            api_probe_results=self.api_probe_results,
            vmss_analysis=self.vmss_analysis
        )
        
        # Store results
        self._cluster_stopped = cluster_stopped
        self.findings.extend(findings)
    
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
    except (ValueError, ValidationError) as e:
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
