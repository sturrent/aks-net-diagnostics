"""
MisconfigurationAnalyzer Module
Analyzes AKS cluster misconfigurations and generates findings

Migrated from Azure CLI subprocess to Azure SDK for Python.
"""

import logging
from typing import Dict, List, Any, Optional, Tuple
import ipaddress
from azure.core.exceptions import ResourceNotFoundError, HttpResponseError


class MisconfigurationAnalyzer:
    """Analyzes AKS cluster for potential misconfigurations and failures"""
    
    def __init__(self, azure_sdk_client, logger: Optional[logging.Logger] = None):
        """
        Initialize the MisconfigurationAnalyzer
        
        Args:
            azure_sdk_client: AzureSDKClient instance for SDK operations
            logger: Optional logger instance
        """
        self.sdk_client = azure_sdk_client
        self.logger = logger or logging.getLogger(__name__)
        self._cluster_stopped = False
    
    def analyze(
        self,
        cluster_info: Dict[str, Any],
        outbound_analysis: Dict[str, Any],
        outbound_ips: List[str],
        private_dns_analysis: Dict[str, Any],
        api_server_access_analysis: Dict[str, Any],
        nsg_analysis: Dict[str, Any],
        api_probe_results: Optional[Dict[str, Any]],
        vmss_analysis: List[Dict[str, Any]]
    ) -> Tuple[List[Dict[str, Any]], bool]:
        """
        Analyze cluster for misconfigurations and generate findings
        
        Args:
            cluster_info: Cluster information from AKS API
            outbound_analysis: Outbound connectivity analysis results
            outbound_ips: List of outbound IP addresses
            private_dns_analysis: Private DNS configuration analysis
            api_server_access_analysis: API server access analysis results
            nsg_analysis: NSG configuration analysis results
            api_probe_results: API connectivity probe results
            vmss_analysis: VMSS configuration analysis
        
        Returns:
            Tuple of (findings list, cluster_stopped flag)
        """
        self.logger.info("Analyzing potential misconfigurations...")
        
        findings = []
        
        # Check cluster power state
        self._check_cluster_power_state(cluster_info, findings)
        
        # Check cluster operational state
        self._check_cluster_provisioning_state(cluster_info, findings)
        
        # Check node pool states
        self._check_node_pool_states(cluster_info, findings)
        
        # Check private DNS configuration for private clusters
        api_server_profile = cluster_info.get('apiServerAccessProfile')
        is_private = api_server_profile.get('enablePrivateCluster', False) if api_server_profile else False
        
        if is_private:
            self._analyze_private_dns_issues(cluster_info, private_dns_analysis, findings)
        
        # Check for missing outbound IPs
        self._check_outbound_ips(cluster_info, outbound_ips, findings)
        
        # Check VNet configuration issues
        self._analyze_vnet_issues(vmss_analysis, findings)
        
        # Check UDR configuration issues
        self._analyze_udr_issues(outbound_analysis, findings)
        
        # Check API server access configuration issues
        self._analyze_api_server_access_issues(api_server_access_analysis, findings)
        
        # Check NSG configuration issues
        self._analyze_nsg_issues(nsg_analysis, findings)
        
        # Check connectivity test results (only if cluster is running)
        if not self._cluster_stopped:
            self._analyze_connectivity_test_results(api_probe_results, findings)
        
        return findings, self._cluster_stopped
    
    def _check_cluster_power_state(self, cluster_info: Dict[str, Any], findings: List[Dict[str, Any]]) -> None:
        """Check cluster power state"""
        power_state = cluster_info.get('powerState', {})
        power_code = power_state.get('code', 'Unknown') if isinstance(power_state, dict) else str(power_state)
        
        if power_code.lower() == 'stopped':
            findings.append({
                "severity": "warning",
                "code": "CLUSTER_STOPPED",
                "message": "Cluster is in stopped state",
                "recommendation": "Start the cluster using 'az aks start' before running connectivity tests or accessing cluster resources"
            })
            self._cluster_stopped = True
        else:
            self._cluster_stopped = False
    
    def _check_cluster_provisioning_state(self, cluster_info: Dict[str, Any], findings: List[Dict[str, Any]]) -> None:
        """Check cluster operational/provisioning state"""
        provisioning_state = cluster_info.get('provisioningState', '')
        if provisioning_state.lower() == 'failed':
            # Try to get detailed error information from cluster status
            error_info = self._get_cluster_status_error(cluster_info)
            
            if error_info:
                error_code, detailed_error = error_info
                findings.append({
                    "severity": "critical",
                    "code": "CLUSTER_OPERATION_FAILURE",
                    "message": f"Cluster failed with error: {detailed_error}",
                    "error_code": error_code,
                    "recommendation": "Check Azure Activity Log for detailed failure information and contact Azure support if needed"
                })
            else:
                # No detailed error available - indicate this clearly instead of showing fake/generic error
                findings.append({
                    "severity": "critical",
                    "code": "CLUSTER_OPERATION_FAILURE",
                    "message": f"Cluster provisioning failed (state: {provisioning_state}). Detailed error information not available.",
                    "recommendation": "Check Azure Activity Log or Azure Portal for detailed failure information. Run 'az aks show -n <cluster-name> -g <resource-group>' to see current cluster status."
                })
    
    def _check_node_pool_states(self, cluster_info: Dict[str, Any], findings: List[Dict[str, Any]]) -> None:
        """Check node pool provisioning states"""
        failed_node_pools = []
        agent_pool_profiles = cluster_info.get('agentPoolProfiles', [])
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
    
    def _check_outbound_ips(
        self,
        cluster_info: Dict[str, Any],
        outbound_ips: List[str],
        findings: List[Dict[str, Any]]
    ) -> None:
        """Check for missing outbound IPs"""
        network_profile = cluster_info.get('networkProfile', {})
        outbound_type = network_profile.get('outboundType', 'loadBalancer')
        
        if not outbound_ips and outbound_type in ['loadBalancer', 'managedNATGateway']:
            findings.append({
                "severity": "warning",
                "code": "NO_OUTBOUND_IPS",
                "message": f"No outbound IP addresses detected for {outbound_type} outbound type",
                "recommendation": "Verify outbound connectivity configuration. Check that the load balancer or NAT gateway has public IPs assigned."
            })
    
    def _get_cluster_status_error(self, cluster_info: Dict[str, Any]) -> Optional[Tuple[Optional[str], str]]:
        """Get detailed cluster error information from status field"""
        try:
            status = cluster_info.get('status', {})
            if isinstance(status, dict):
                error_detail = status.get('errordetail', {})
                if isinstance(error_detail, dict):
                    error_message = error_detail.get('message', '')
                    error_code = error_detail.get('code', '')
                    
                    if error_message:
                        if error_code:
                            return (error_code, f"{error_code}: {error_message}")
                        else:
                            return (None, error_message)
                
                provisioning_error = status.get('provisioningError')
                if provisioning_error:
                    return (None, str(provisioning_error))
            
            return None
            
        except Exception as e:
            self.logger.info(f"Could not retrieve cluster status error: {e}")
            return None
    
    def _analyze_private_dns_issues(
        self,
        cluster_info: Dict[str, Any],
        private_dns_analysis: Dict[str, Any],
        findings: List[Dict[str, Any]]
    ) -> None:
        """Analyze private DNS configuration issues"""
        if not private_dns_analysis:
            return
        
        api_server_profile = cluster_info.get('apiServerAccessProfile', {})
        private_dns_zone = api_server_profile.get('privateDnsZone', '')
        
        if private_dns_zone == 'system':
            self._check_system_private_dns_issues(findings)
        elif private_dns_zone and private_dns_zone != 'system':
            self._check_private_dns_vnet_links(cluster_info, private_dns_zone, findings)
    
    def _check_system_private_dns_issues(self, findings: List[Dict[str, Any]]) -> None:
        """Check system-managed private DNS zone issues"""
        try:
            # List all private DNS zones in the subscription
            # Note: Using list() to get all zones across subscription (not limited to one RG)
            zones_list = list(self.sdk_client.privatedns_client.private_zones.list())
            
            aks_private_zones = []
            for zone in zones_list:
                zone_name = zone.name
                if 'azmk8s.io' in zone_name and 'privatelink' in zone_name:
                    # Convert to dict and normalize keys to camelCase for compatibility
                    from .azure_sdk_client import normalize_dict_keys
                    zone_dict = normalize_dict_keys(zone.as_dict())
                    # Parse resource group from zone ID
                    parsed = self.sdk_client.parse_resource_id(zone.id)
                    zone_dict['resourceGroup'] = parsed['resource_group']
                    aks_private_zones.append(zone_dict)
            
            if not aks_private_zones:
                return
            
            for zone in aks_private_zones:
                zone_name = zone.get('name', '')
                zone_rg = zone.get('resourceGroup', '')
                
                if zone_rg and zone_name:
                    self._check_dns_server_vnet_links(zone_rg, zone_name, findings)
                    
        except Exception as e:
            self.logger.info(f"Could not analyze system private DNS issues: {e}")
    
    def _check_dns_server_vnet_links(
        self,
        zone_rg: str,
        zone_name: str,
        findings: List[Dict[str, Any]]
    ) -> None:
        """Check if VNets with custom DNS servers are properly linked to private DNS zone"""
        try:
            # List VNet links for the private DNS zone using SDK
            # (replaces: az network private-dns link vnet list)
            links_list = list(
                self.sdk_client.privatedns_client.virtual_network_links.list(zone_rg, zone_name)
            )
            
            linked_vnet_ids = []
            for link in links_list:
                if link.virtual_network:
                    linked_vnet_ids.append(link.virtual_network.id)
            
            cluster_vnets = self._get_cluster_vnets_with_dns()
            
            for vnet_info in cluster_vnets:
                vnet_id = vnet_info.get('id', '')
                vnet_name = vnet_info.get('name', '')
                dns_servers = vnet_info.get('dnsServers', [])
                
                if dns_servers:
                    for dns_server in dns_servers:
                        dns_host_vnet = self._find_dns_server_host_vnet(dns_server)
                        
                        if dns_host_vnet and dns_host_vnet.get('id') not in linked_vnet_ids:
                            dns_host_vnet_name = dns_host_vnet.get('name', 'unknown')
                            findings.append({
                                "severity": "critical",
                                "code": "PDNS_DNS_HOST_VNET_LINK_MISSING",
                                "message": f"DNS server {dns_server} is hosted in VNet {dns_host_vnet_name} but this VNet is not linked to private DNS zone {zone_name}. Cluster VNet {vnet_name} uses this DNS server.",
                                "recommendation": f"Link VNet {dns_host_vnet_name} to private DNS zone {zone_name} to ensure proper DNS resolution for the private cluster"
                            })
                            
        except (ResourceNotFoundError, HttpResponseError) as e:
            self.logger.info(f"Could not check DNS server VNet links: {e}")
        except Exception as e:
            self.logger.info(f"Could not check DNS server VNet links: {e}")
    
    def _get_cluster_vnets_with_dns(self) -> List[Dict[str, Any]]:
        """Get cluster VNets with their DNS configurations"""
        vnets = []
        
        # Note: This method needs cluster_info to get agent pools
        # For now, we'll return empty list and let the caller pass this data
        # This is a design consideration - might need to refactor
        
        return vnets
    
    def _find_dns_server_host_vnet(self, dns_server_ip: str) -> Optional[Dict[str, str]]:
        """Find which VNet hosts the given DNS server IP"""
        try:
            # List all VNets in subscription using SDK (replaces: az network vnet list)
            vnets_list = list(self.sdk_client.network_client.virtual_networks.list_all())
            
            dns_ip = ipaddress.ip_address(dns_server_ip)
            
            for vnet in vnets_list:
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
    
    def _check_private_dns_vnet_links(
        self,
        cluster_info: Dict[str, Any],
        private_dns_zone: str,
        findings: List[Dict[str, Any]]
    ) -> None:
        """Check if VNets are properly linked to private DNS zone"""
        try:
            if '/' in private_dns_zone:
                dns_zone_parts = private_dns_zone.split('/')
                dns_zone_rg = dns_zone_parts[4] if len(dns_zone_parts) > 4 else ''
                dns_zone_name = dns_zone_parts[-1] if dns_zone_parts else ''
            else:
                dns_zone_name = private_dns_zone
                dns_zone_rg = self._find_private_dns_zone_rg(dns_zone_name)
            
            if dns_zone_rg and dns_zone_name:
                # List VNet links for the private DNS zone using SDK
                # (replaces: az network private-dns link vnet list)
                links_list = list(
                    self.sdk_client.privatedns_client.virtual_network_links.list(dns_zone_rg, dns_zone_name)
                )
                
                cluster_vnet_ids = self._get_cluster_vnet_ids(cluster_info)
                linked_vnet_ids = []
                for link in links_list:
                    if link.virtual_network:
                        linked_vnet_ids.append(link.virtual_network.id)
                
                for vnet_id in cluster_vnet_ids:
                    if vnet_id not in linked_vnet_ids:
                        vnet_name = vnet_id.split('/')[-1] if vnet_id else 'unknown'
                        findings.append({
                            "severity": "critical",
                            "code": "PDNS_DNS_HOST_VNET_LINK_MISSING",
                            "message": f"Cluster VNet {vnet_name} is not linked to private DNS zone {dns_zone_name}",
                            "recommendation": "Link the cluster VNet to the private DNS zone to ensure proper name resolution"
                        })
        except (ResourceNotFoundError, HttpResponseError) as e:
            self.logger.info(f"Could not analyze private DNS VNet links: {e}")
        except Exception as e:
            self.logger.info(f"Could not analyze private DNS VNet links: {e}")
    
    def _find_private_dns_zone_rg(self, zone_name: str) -> str:
        """Find the resource group containing the private DNS zone"""
        try:
            # List all private DNS zones using SDK (replaces: az network private-dns zone list)
            zones_list = list(self.sdk_client.privatedns_client.private_zones.list())
            
            for zone in zones_list:
                if zone.name == zone_name:
                    # Parse resource group from zone ID
                    parsed = self.sdk_client.parse_resource_id(zone.id)
                    return parsed['resource_group']
        except (ResourceNotFoundError, HttpResponseError):
            pass
        except Exception:
            pass
        return ''
    
    def _get_cluster_vnet_ids(self, cluster_info: Dict[str, Any]) -> List[str]:
        """Get VNet IDs associated with the cluster"""
        vnet_ids = []
        
        agent_pools = cluster_info.get('agentPoolProfiles', [])
        for pool in agent_pools:
            subnet_id = pool.get('vnetSubnetId', '')
            if subnet_id:
                vnet_id = '/'.join(subnet_id.split('/')[:-2])
                if vnet_id not in vnet_ids:
                    vnet_ids.append(vnet_id)
        
        return vnet_ids
    
    def _analyze_vnet_issues(self, vmss_analysis: List[Dict[str, Any]], findings: List[Dict[str, Any]]) -> None:
        """Analyze VNet configuration issues"""
        # Placeholder for future VNet subnet capacity analysis
        pass
    
    def _analyze_udr_issues(self, outbound_analysis: Dict[str, Any], findings: List[Dict[str, Any]]) -> None:
        """Analyze User Defined Route configuration issues"""
        udr_analysis = outbound_analysis.get("udrAnalysis")
        if not udr_analysis:
            return
        
        critical_routes = udr_analysis.get("criticalRoutes", [])
        va_routes = udr_analysis.get("virtualApplianceRoutes", [])
        default_va_routes = [r for r in va_routes if r.get('addressPrefix') == '0.0.0.0/0']
        
        for route in critical_routes:
            impact = route.get("impact", {})
            severity = impact.get("severity", "info")
            route_prefix = route.get('addressPrefix', '')
            
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
        
        if va_routes:
            if default_va_routes:
                outbound_type = outbound_analysis.get("type", "unknown")
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
                azure_va_routes = [r for r in va_routes if r.get('impact', {}).get('affectedTraffic', []) and 'azure_services' in r.get('impact', {}).get('affectedTraffic', [])]
                if azure_va_routes:
                    route_names = [r.get('name', 'unnamed') for r in azure_va_routes]
                    findings.append({
                        "severity": "warning",
                        "code": "UDR_AZURE_SERVICES_VA",
                        "message": f"Azure service traffic is routed through virtual appliance: {', '.join(route_names)}",
                        "recommendation": "Verify the virtual appliance allows Azure service connectivity or add specific routes with nextHopType 'Internet' for required Azure services."
                    })
                
                mcr_va_routes = [r for r in va_routes if r.get('impact', {}).get('affectedTraffic', []) and 'container_registry' in r.get('impact', {}).get('affectedTraffic', [])]
                if mcr_va_routes:
                    route_names = [r.get('name', 'unnamed') for r in mcr_va_routes]
                    findings.append({
                        "severity": "warning",
                        "code": "UDR_CONTAINER_REGISTRY_VA",
                        "message": f"Container registry traffic is routed through virtual appliance: {', '.join(route_names)}",
                        "recommendation": "Ensure the virtual appliance allows container registry access or add specific routes for Microsoft Container Registry (mcr.microsoft.com) endpoints."
                    })
        
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
        
        if route_tables:
            total_routes = sum(len(rt.get('routes', [])) for rt in route_tables)
            va_route_count = len(va_routes)
            critical_route_count = len(critical_routes)
            
            if total_routes > 0:
                outbound_type = outbound_analysis.get("type", "unknown")
                findings.append({
                    "severity": "info",
                    "code": "UDR_ANALYSIS_SUMMARY",
                    "message": f"UDR Analysis: Found {len(route_tables)} route table(s) with {total_routes} total routes on node subnets. {va_route_count} routes use virtual appliances, {critical_route_count} have high impact on connectivity. Cluster uses {outbound_type} outbound type.",
                    "recommendation": "Review the detailed UDR analysis in the JSON report for specific route impacts and recommendations."
                })
    
    def _analyze_api_server_access_issues(
        self,
        api_server_access_analysis: Dict[str, Any],
        findings: List[Dict[str, Any]]
    ) -> None:
        """Analyze API server access configuration issues"""
        if not api_server_access_analysis:
            return
        
        security_findings = api_server_access_analysis.get("securityFindings", [])
        for security_finding in security_findings:
            severity = security_finding.get("severity", "info")
            issue = security_finding.get("issue", "Unknown issue")
            description = security_finding.get("description", "")
            recommendation = security_finding.get("recommendation", "")
            range_info = security_finding.get("range", "")
            
            if "unrestricted access" in issue.lower():
                code = "API_UNRESTRICTED_ACCESS"
            elif "broad ip range" in issue.lower():
                code = "API_BROAD_IP_RANGE"
            elif "outbound ips not" in issue.lower():
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
        
        authorized_ranges = api_server_access_analysis.get("authorizedIpRanges", [])
        is_private = api_server_access_analysis.get("privateCluster", False)
        access_model = api_server_access_analysis.get("accessRestrictions", {}).get("model", "unknown")
        
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
    
    def _analyze_nsg_issues(self, nsg_analysis: Dict[str, Any], findings: List[Dict[str, Any]]) -> None:
        """Analyze NSG configuration issues"""
        if not nsg_analysis:
            return
        
        blocking_rules = nsg_analysis.get("blockingRules", [])
        for rule in blocking_rules:
            effective_severity = rule.get("effectiveSeverity", "critical")
            is_overridden = rule.get("isOverridden", False)
            overriding_rules = rule.get("overriddenBy", [])
            
            if is_overridden:
                overriding_rule_names = [r.get('ruleName', 'unknown') for r in overriding_rules[:2]]
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
        
        inter_node = nsg_analysis.get("interNodeCommunication", {})
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
        
        subnet_nsgs = nsg_analysis.get("subnetNsgs", [])
        nic_nsgs = nsg_analysis.get("nicNsgs", [])
        
        if not subnet_nsgs and not nic_nsgs:
            findings.append({
                "severity": "info",
                "code": "NSG_NO_RESTRICTIONS",
                "message": "No NSGs found on cluster node subnets or NICs",
                "recommendation": "Consider implementing NSGs for enhanced network security while ensuring AKS traffic is allowed"
            })
    
    def _analyze_connectivity_test_results(
        self,
        api_probe_results: Optional[Dict[str, Any]],
        findings: List[Dict[str, Any]]
    ) -> None:
        """Analyze connectivity test results and add findings"""
        if not api_probe_results:
            return
        
        if not api_probe_results.get('enabled'):
            return
        
        tests = api_probe_results.get('tests', [])
        
        failed_tests = [t for t in tests if t.get('status') == 'failed']
        error_tests = [t for t in tests if t.get('status') == 'error']
        
        dns_failures = [t for t in failed_tests if 'DNS Resolution' in t.get('test_name', '')]
        if dns_failures:
            dns_test_names = [t.get('test_name', '') for t in dns_failures]
            findings.append({
                "severity": "error",
                "code": "CONNECTIVITY_DNS_FAILURE",
                "message": f"DNS resolution tests failed: {', '.join(dns_test_names)}",
                "recommendation": "Check DNS server configuration and network connectivity. Verify custom DNS servers are accessible and properly configured."
            })
        
        http_failures = [t for t in failed_tests if any(keyword in t.get('test_name', '') for keyword in ['HTTP', 'Connectivity', 'curl'])]
        if http_failures:
            http_test_names = [t.get('test_name', '') for t in http_failures]
            findings.append({
                "severity": "error",
                "code": "CONNECTIVITY_HTTP_FAILURE",
                "message": f"HTTP connectivity tests failed: {', '.join(http_test_names)}",
                "recommendation": "Check outbound connectivity rules, firewall settings, and network security groups. Verify internet access from cluster nodes."
            })
        
        api_failures = [t for t in failed_tests if 'API Server' in t.get('test_name', '')]
        if api_failures:
            findings.append({
                "severity": "critical",
                "code": "CONNECTIVITY_API_SERVER_FAILURE",
                "message": "API server connectivity test failed from cluster nodes",
                "recommendation": "Check private DNS configuration, VNet links, and API server access policies. For private clusters, ensure DNS resolution is working correctly."
            })
        
        if error_tests:
            findings.append({
                "severity": "warning",
                "code": "CONNECTIVITY_TEST_ERRORS",
                "message": f"{len(error_tests)} connectivity tests could not be executed",
                "recommendation": "Check VMSS instance status and run-command permissions. Ensure instances are running and accessible."
            })
