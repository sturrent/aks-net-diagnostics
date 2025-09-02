#!/usr/bin/env python3
"""
AKS Network Diagnostics Script
Comprehensive read-only analysis of AKS cluster network configuration
Author: Azure Networking Diagnostics Generator
Version: 2.0
"""

import argparse
import json
import subprocess
import sys
import os
import re
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
import logging

class AKSNetworkDiagnostics:
    """Main class for AKS network diagnostics"""
    
    def __init__(self):
        self.aks_name: str = ""
        self.aks_rg: str = ""
        self.subscription: Optional[str] = None
        self.probe_api: bool = False
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
        self.vmss_analysis: List[Dict[str, Any]] = []
        self.api_probe_results: Optional[Dict[str, Any]] = None
        self.failure_analysis: Dict[str, Any] = {"enabled": False}
        self.findings: List[Dict[str, Any]] = []
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def parse_arguments(self):
        """Parse command line arguments"""
        parser = argparse.ArgumentParser(
            description="Performs comprehensive read-only analysis of AKS cluster network configuration",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
EXAMPLES:
  %(prog)s -n my-aks-cluster -g my-resource-group
  %(prog)s -n my-cluster -g my-rg --subscription 12345678-1234-1234-1234-123456789012
  %(prog)s -n my-cluster -g my-rg --probe-api --json-out custom-report.json
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
        parser.add_argument('--probe-api', action='store_true',
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
        
        self.aks_name = args.name
        self.aks_rg = args.resource_group
        self.subscription = args.subscription
        self.probe_api = args.probe_api
        self.json_out = args.json_out
        self.no_json = args.no_json
        self.verbose = args.verbose
        self.cache = args.cache
        
        # Auto-generate JSON filename if not disabled and not specified
        if not self.no_json and not self.json_out:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.json_out = f"aks-net-diagnostics_{self.aks_name}_{timestamp}.json"
    
    def run_azure_cli(self, cmd: List[str], expect_json: bool = True) -> Any:
        """Run Azure CLI command and return result"""
        cmd_str = ' '.join(cmd)
        
        # Check cache first
        if self.cache and cmd_str in self._cache:
            return self._cache[cmd_str]
        
        try:
            result = subprocess.run(
                ['az'] + cmd,
                capture_output=True,
                text=True,
                check=True
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
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Azure CLI command failed: {cmd_str}")
            if e.stderr:
                self.logger.error(f"Error: {e.stderr}")
            return {} if expect_json else ""
    
    def check_prerequisites(self):
        """Check if required tools are available"""
        # Check Azure CLI
        try:
            subprocess.run(['az', '--version'], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.logger.error("Azure CLI is not installed or not in PATH")
            sys.exit(1)
        
        # Check if logged in
        try:
            subprocess.run(['az', 'account', 'show'], capture_output=True, check=True)
        except subprocess.CalledProcessError:
            self.logger.error("Not logged in to Azure. Run 'az login' first.")
            sys.exit(1)
        
        # Set subscription if provided
        if self.subscription:
            try:
                subprocess.run(['az', 'account', 'set', '--subscription', self.subscription], 
                             capture_output=True, check=True)
                self.logger.info(f"Using Azure subscription: {self.subscription}")
            except subprocess.CalledProcessError:
                self.logger.error(f"Failed to set subscription: {self.subscription}")
                sys.exit(1)
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
            self.logger.error(f"Failed to get cluster information for {self.aks_name}")
            sys.exit(1)
        
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
        
        self.outbound_analysis = {
            "type": outbound_type,
            "effectivePublicIPs": self.outbound_ips,
            "udrAnalysis": udr_analysis if udr_analysis.get("routeTables") else None
        }
    
    def _analyze_load_balancer_outbound(self):
        """Analyze load balancer outbound configuration"""
        self.logger.info("  - Analyzing Load Balancer outbound configuration...")
        
        # Get the managed cluster's load balancer
        mc_rg = self.cluster_info.get('nodeResourceGroup', '')
        if not mc_rg:
            self.logger.info("    No node resource group found")
            return
        
        # List load balancers in the managed resource group
        lb_cmd = ['network', 'lb', 'list', '-g', mc_rg, '-o', 'json']
        load_balancers = self.run_azure_cli(lb_cmd)
        
        if not isinstance(load_balancers, list):
            self.logger.info(f"    No load balancers found in {mc_rg}")
            return
        
        self.logger.info(f"    Found {len(load_balancers)} load balancer(s)")
        
        for lb in load_balancers:
            lb_name = lb.get('name', '')
            if not lb_name:
                continue
            
            self.logger.info(f"    Analyzing load balancer: {lb_name}")
            
            # Check outbound rules first
            outbound_rules = lb.get('outboundRules', [])
            frontend_configs = lb.get('frontendIpConfigurations', [])
            
            self.logger.info(f"    Found {len(outbound_rules)} outbound rule(s) and {len(frontend_configs)} frontend config(s)")
            
            # Collect frontend config IDs that might have outbound IPs
            frontend_config_ids = []
            
            # Add frontend configs from outbound rules (this is the main path for AKS)
            for rule in outbound_rules:
                rule_name = rule.get('name', 'unnamed')
                self.logger.info(f"    Processing outbound rule: {rule_name}")
                
                # Try both possible field names for frontend IP configurations
                frontend_ips = rule.get('frontendIPConfigurations', [])
                if not frontend_ips:
                    frontend_ips = rule.get('frontendIpConfigurations', [])
                
                self.logger.info(f"    Rule has {len(frontend_ips)} frontend IP configuration(s)")
                
                for frontend_ip in frontend_ips:
                    if frontend_ip.get('id'):
                        frontend_config_ids.append(frontend_ip['id'])
                        self.logger.info(f"    Added frontend config ID: {frontend_ip['id']}")
            
            # Also add all direct frontend configs (for standard LB without outbound rules)
            for frontend in frontend_configs:
                if frontend.get('id'):
                    frontend_config_ids.append(frontend['id'])
                    self.logger.info(f"    Added direct frontend config ID: {frontend['id']}")
            
            self.logger.info(f"    Processing {len(frontend_config_ids)} frontend configuration(s)")
            
            # Process each frontend config
            for config_id in frontend_config_ids:
                self.logger.info(f"    Checking frontend config: {config_id}")
                
                # Extract load balancer name and frontend config name from ID
                parts = config_id.split('/')
                if len(parts) >= 11:
                    config_name = parts[10]  # Frontend IP config name
                    self.logger.info(f"    Config name: {config_name}")
                    
                    # Get the frontend IP configuration details
                    frontend_cmd = ['network', 'lb', 'frontend-ip', 'show', 
                                  '-g', mc_rg, '--lb-name', lb_name, '-n', config_name, '-o', 'json']
                    frontend_config = self.run_azure_cli(frontend_cmd)
                    
                    if isinstance(frontend_config, dict):
                        public_ip = frontend_config.get('publicIPAddress', {})
                        if public_ip and public_ip.get('id'):
                            self.logger.info(f"    Found public IP reference: {public_ip['id']}")
                            
                            # Get public IP details
                            ip_cmd = ['network', 'public-ip', 'show', '--ids', public_ip['id'], '-o', 'json']
                            ip_info = self.run_azure_cli(ip_cmd)
                            
                            if ip_info and ip_info.get('ipAddress'):
                                ip_address = ip_info['ipAddress']
                                if ip_address not in self.outbound_ips:
                                    self.outbound_ips.append(ip_address)
                                    self.logger.info(f"    Found outbound IP: {ip_address}")
                            else:
                                self.logger.info(f"    No IP address found in public IP resource")
                        else:
                            self.logger.info(f"    No public IP address reference in frontend config")
                    else:
                        self.logger.info(f"    Failed to get frontend config details")
                else:
                    self.logger.info(f"    Invalid frontend config ID format: {config_id}")
        
        if not self.outbound_ips:
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
        # NAT Gateway analysis would go here
        pass

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
    
    def check_api_connectivity(self):
        """Check API server connectivity and network reachability from cluster nodes"""
        self.logger.info("Checking API connectivity...")
        
        if not self.probe_api:
            self.logger.info("API connectivity probing disabled. Use --probe-api to enable active connectivity checks.")
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
        
        # Get VMSS instances for testing
        vmss_instances = self._get_vmss_instances()
        if not vmss_instances:
            self.logger.info("No VMSS instances found for connectivity testing")
            return
        
        # Run connectivity tests
        for vmss_info in vmss_instances:
            self._run_vmss_connectivity_tests(vmss_info)
    
    def _get_vmss_instances(self):
        """Get VMSS instances suitable for connectivity testing"""
        vmss_instances = []
        
        try:
            # Get managed cluster resource group
            mc_rg = self.cluster_info.get('nodeResourceGroup', '')
            if not mc_rg:
                return vmss_instances
            
            # List VMSS in the managed cluster resource group
            cmd = ['vmss', 'list', '-g', mc_rg, '-o', 'json']
            vmss_list = self.run_azure_cli(cmd)
            
            if isinstance(vmss_list, list):
                for vmss in vmss_list:
                    vmss_name = vmss.get('name', '')
                    if vmss_name:
                        # Get instances for this VMSS
                        instances_cmd = ['vmss', 'list-instances', '-g', mc_rg, '-n', vmss_name, '-o', 'json']
                        instances = self.run_azure_cli(instances_cmd)
                        
                        if isinstance(instances, list) and instances:
                            # Use the first running instance
                            for instance in instances:
                                if instance.get('provisioningState') == 'Succeeded':
                                    vmss_instances.append({
                                        'vmss_name': vmss_name,
                                        'resource_group': mc_rg,
                                        'instance_id': str(instance.get('instanceId', '0')),
                                        'vmss_info': vmss
                                    })
                                    break  # Only need one instance per VMSS
            
        except Exception as e:
            self.logger.info(f"Error getting VMSS instances: {e}")
        
        return vmss_instances
    
    def _run_vmss_connectivity_tests(self, vmss_info):
        """Run connectivity tests on a VMSS instance"""
        vmss_name = vmss_info['vmss_name']
        resource_group = vmss_info['resource_group']
        instance_id = vmss_info['instance_id']
        
        self.logger.info(f"Running connectivity tests on VMSS {vmss_name}, instance {instance_id}")
        
        # Define connectivity tests
        tests = [
            {
                'name': 'DNS Resolution - Microsoft Container Registry',
                'script': 'nslookup mcr.microsoft.com',
                'timeout': 10,
                'expected_keywords': ['Address:', 'mcr.microsoft.com']
            },
            {
                'name': 'HTTP Connectivity - Microsoft Container Registry',
                'script': 'curl -kv --connect-timeout 5 --max-time 10 mcr.microsoft.com',
                'timeout': 15,
                'expected_keywords': ['HTTP/', 'Connected to']
            },
            {
                'name': 'DNS Resolution - Azure Management',
                'script': 'nslookup management.azure.com',
                'timeout': 10,
                'expected_keywords': ['Address:', 'management.azure.com']
            }
        ]
        
        # Add cluster-specific tests
        api_server_fqdn = self._get_api_server_fqdn()
        if api_server_fqdn:
            # Extract hostname from URL for DNS resolution test
            api_hostname = api_server_fqdn.replace('https://', '').replace('http://', '')
            
            tests.append({
                'name': f'API Server Connectivity - {api_server_fqdn}',
                'script': f'curl -kv --connect-timeout 5 --max-time 10 {api_server_fqdn}',
                'timeout': 15,
                'expected_keywords': ['Connected to', 'HTTP/']
            })
            
            # For private clusters, we need to validate that DNS returns a private IP
            is_private_cluster = self._is_private_cluster()
            if is_private_cluster:
                tests.append({
                    'name': f'DNS Resolution - API Server (Private)',
                    'script': f'nslookup {api_hostname}',
                    'timeout': 15,  # Reduced timeout for DNS tests
                    'expected_keywords': ['Address:', api_hostname.split('.')[0]],
                    'validate_private_ip': True,  # Special flag for private IP validation
                    'hostname': api_hostname
                })
            else:
                tests.append({
                    'name': f'DNS Resolution - API Server',
                    'script': f'nslookup {api_hostname}',
                    'timeout': 10,
                    'expected_keywords': ['Address:', api_hostname.split('.')[0]]
                })
        
        # Execute each test
        for test in tests:
            self._execute_vmss_test(vmss_info, test)
    
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
    
    def _execute_vmss_test(self, vmss_info, test):
        """Execute a single connectivity test on VMSS instance"""
        vmss_name = vmss_info['vmss_name']
        resource_group = vmss_info['resource_group']
        instance_id = vmss_info['instance_id']
        
        try:
            self.logger.info(f"  Running test: {test['name']}")
            
            # Build the run-command
            cmd = [
                'vmss', 'run-command', 'invoke',
                '--subscription', self.subscription or '',
                '-g', resource_group,
                '-n', vmss_name,
                '--command-id', 'RunShellScript',
                '--instance-id', instance_id,
                '--scripts', test['script'],
                '-o', 'json'
            ]
            
            # Remove empty subscription if not provided
            if not self.subscription:
                cmd = cmd[3:]  # Remove --subscription and empty value
            
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
    
    def _run_vmss_command(self, cmd: List[str]) -> Any:
        """Run VMSS command with enhanced error handling"""
        cmd_str = ' '.join(cmd)
        
        try:
            result = subprocess.run(
                ['az'] + cmd,
                capture_output=True,
                text=True,
                timeout=60  # 60 second timeout for VMSS commands
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
                "error": "VMSS command timed out after 60 seconds",
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
                            elif self._check_expected_output_combined(test, stdout, stderr, expected_keywords):
                                test_result['status'] = 'passed'
                            else:
                                test_result['status'] = 'failed'
                                test_result['error'] = f"Expected output not found. Keywords: {expected_keywords}"
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
            
        return stdout, stderr, exit_code
    
    def _check_expected_output(self, output, expected_keywords):
        """Check if output contains expected keywords"""
        if not expected_keywords:
            return True  # No specific expectations
        
        output_lower = output.lower()
        for keyword in expected_keywords:
            if keyword.lower() not in output_lower:
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
            combined_output = f"{stdout}\n{stderr}".lower()
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
            # Check for DNS resolution failures first
            if any(error in nslookup_output.lower() for error in ['nxdomain', 'servfail', 'refused', "can't find"]):
                return False  # DNS resolution failed completely
            
            # Parse nslookup output to extract IP addresses
            # Look for lines like "Address: 10.1.2.3" or "10.1.2.3"
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            found_ips = re.findall(ip_pattern, nslookup_output)
            
            if not found_ips:
                return False  # No IP addresses found
            
            # Filter out DNS server IPs (usually the first IP listed)
            # DNS server IPs are typically shown as "Server: 10.1.0.10" or "Address: 10.1.0.10#53"
            dns_server_pattern = r'(?:Server:|Address:)\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})(?:#\d+)?'
            dns_server_ips = set(re.findall(dns_server_pattern, nslookup_output))
            
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
            # If we can't parse the output, fall back to checking for resolution errors
            return not any(error in nslookup_output.lower() for error in ['nxdomain', 'servfail', 'refused', "can't find"])
    
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
        
        # Check connectivity test results (only if cluster is running)
        if not getattr(self, '_cluster_stopped', False):
            self._analyze_connectivity_test_results(findings)
        
        self.findings = findings
    
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
        for route in critical_routes:
            impact = route.get("impact", {})
            severity = impact.get("severity", "info")
            
            if severity == "critical":
                findings.append({
                    "severity": "critical",
                    "code": "UDR_CRITICAL_ROUTE",
                    "message": f"Critical UDR detected: {route.get('name', 'unnamed')} ({route.get('addressPrefix', '')}) - {impact.get('description', '')}",
                    "recommendation": "Review and modify the route table to ensure essential AKS traffic can reach its destinations. Consider using service tags or more specific routes."
                })
            elif severity == "high":
                findings.append({
                    "severity": "error",
                    "code": "UDR_HIGH_IMPACT_ROUTE",
                    "message": f"High-impact UDR detected: {route.get('name', 'unnamed')} ({route.get('addressPrefix', '')}) - {impact.get('description', '')}",
                    "recommendation": "Verify that the virtual appliance or next hop can properly handle this traffic and has appropriate rules configured."
                })
        
        # Check for virtual appliance routes
        va_routes = udr_analysis.get("virtualApplianceRoutes", [])
        if va_routes:
            # Check for default route through virtual appliance
            default_va_routes = [r for r in va_routes if r.get('addressPrefix') == '0.0.0.0/0']
            if default_va_routes:
                outbound_type = self.outbound_analysis.get("type", "unknown")
                findings.append({
                    "severity": "warning",
                    "code": "UDR_DEFAULT_ROUTE_VA",
                    "message": f"Default route (0.0.0.0/0) redirects all internet traffic through virtual appliance at {default_va_routes[0].get('nextHopIpAddress', 'unknown IP')}. Outbound type is {outbound_type}.",
                    "recommendation": "Ensure the virtual appliance is properly configured to handle AKS traffic including: container image pulls, Azure service connectivity, and API server access. Consider adding specific routes for AKS requirements."
                })
            
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
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "version": "2.0",
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
                "vmssConfiguration": self.vmss_analysis,
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
                with open(self.json_out, 'w') as f:
                    json.dump(report_data, f, indent=2)
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
        print(f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print()
        
        print("**Configuration:**")
        network_profile = self.cluster_info.get('networkProfile', {})
        print(f"- Network Plugin: {network_profile.get('networkPlugin', 'kubenet')}")
        print(f"- Outbound Type: {network_profile.get('outboundType', 'loadBalancer')}")
        
        api_server_profile = self.cluster_info.get('apiServerAccessProfile')
        is_private = api_server_profile.get('enablePrivateCluster', False) if api_server_profile else False
        print(f"- Private Cluster: {str(is_private).lower()}")
        
        if self.outbound_ips:
            print()
            print("**Outbound IPs:**")
            for ip in self.outbound_ips:
                print(f"- {ip}")
        
        print()
        print("**Findings Summary:**")
        
        critical_count = len([f for f in self.findings if f.get('severity') in ['critical', 'error']])
        warning_count = len([f for f in self.findings if f.get('severity') == 'warning'])
        
        if critical_count == 0 and warning_count == 0:
            print("- ✅ No critical issues detected")
        else:
            if critical_count > 0:
                print(f"- ❌ {critical_count} Critical/Error finding(s)")
            if warning_count > 0:
                print(f"- ⚠️ {warning_count} Warning finding(s)")
        
        print()
        print("Tip: Use --verbose flag for detailed analysis or check the JSON report for complete findings.")
    
    def _print_verbose_report(self):
        """Print detailed verbose report"""
        print("# AKS Network Assessment Report")
        print()
        print(f"**Cluster:** {self.aks_name}")
        print(f"**Resource Group:** {self.aks_rg}")
        print(f"**Subscription:** {self.subscription}")
        print(f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
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
        self.analyze_private_dns()
        self.check_api_connectivity()
        self.analyze_misconfigurations()
        self.generate_report()


def main():
    """Main entry point"""
    try:
        diagnostics = AKSNetworkDiagnostics()
        diagnostics.run()
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
