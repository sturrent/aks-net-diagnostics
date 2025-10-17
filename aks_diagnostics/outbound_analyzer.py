"""
Outbound Connectivity Analyzer for AKS clusters

This module analyzes outbound connectivity mechanisms including:
- Load Balancer outbound configuration
- NAT Gateway configuration
- User Defined Routing (UDR) with virtual appliances
- Effective outbound path determination with UDR override detection

Migrated from Azure CLI subprocess to Azure SDK for Python.
"""

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from azure.core.exceptions import HttpResponseError, ResourceNotFoundError

from .route_table_analyzer import RouteTableAnalyzer


@dataclass
class OutboundAnalysisResult:
    """Result of outbound connectivity analysis"""

    outbound_type: str
    configured_public_ips: List[str]
    effective_outbound: Dict[str, Any]
    udr_analysis: Optional[Dict[str, Any]] = None


class OutboundConnectivityAnalyzer:
    """Analyzer for AKS cluster outbound connectivity configuration"""

    def __init__(
        self,
        cluster_info: Dict[str, Any],
        agent_pools: List[Dict[str, Any]],
        azure_sdk_client,
        logger: Optional[logging.Logger] = None,
    ):
        """
        Initialize the OutboundConnectivityAnalyzer

        Args:
            cluster_info: AKS cluster configuration dictionary
            agent_pools: List of agent pool configurations
            azure_sdk_client: Azure SDK client instance
            logger: Optional logger instance
        """
        self.cluster_info = cluster_info
        self.agent_pools = agent_pools
        self.sdk_client = azure_sdk_client
        self.logger = logger or logging.getLogger(__name__)

        # Results storage
        self.outbound_ips: List[str] = []
        self.outbound_analysis: Dict[str, Any] = {}

    def analyze(self, show_details: bool = False) -> Dict[str, Any]:
        """
        Analyze outbound connectivity configuration

        Args:
            show_details: Enable detailed logging

        Returns:
            Dictionary containing outbound connectivity analysis results
        """
        self.logger.info("Analyzing outbound connectivity...")

        network_profile = self.cluster_info.get("networkProfile", {})
        outbound_type = network_profile.get("outboundType", "loadBalancer")

        # Analyze based on configured outbound type
        if outbound_type == "loadBalancer":
            self._analyze_load_balancer_outbound(show_details)
        elif outbound_type == "userDefinedRouting":
            self._analyze_udr_outbound()
        elif outbound_type == "managedNATGateway":
            self._analyze_nat_gateway_outbound(show_details)

        # Always check for UDRs on node subnets regardless of outbound type
        # This helps detect scenarios where Azure Firewall is used with Load Balancer outbound
        self.logger.info("  - Checking for UDRs on node subnets...")
        udr_analysis = self._analyze_node_subnet_udrs()

        # Determine effective outbound configuration and warn about conflicts
        effective_outbound_summary = self._determine_effective_outbound(outbound_type, udr_analysis)

        self.outbound_analysis = {
            "type": outbound_type,
            "configuredPublicIPs": self.outbound_ips.copy(),
            "effectiveOutbound": effective_outbound_summary,
            "udrAnalysis": udr_analysis if udr_analysis.get("routeTables") else None,
        }

        # Display summary of effective outbound configuration
        self._display_outbound_summary(effective_outbound_summary)

        return self.outbound_analysis

    def get_outbound_ips(self) -> List[str]:
        """Get list of configured outbound public IPs"""
        return self.outbound_ips.copy()

    def _analyze_node_subnet_udrs(self) -> Dict[str, Any]:
        """Analyze User Defined Routes on node subnets using RouteTableAnalyzer"""
        analyzer = RouteTableAnalyzer(self.agent_pools, self.sdk_client)
        return analyzer.analyze()

    def _determine_effective_outbound(self, outbound_type: str, udr_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Determine the effective outbound configuration considering UDRs

        Args:
            outbound_type: Configured outbound type from cluster
            udr_analysis: UDR analysis results

        Returns:
            Dictionary with effective outbound configuration details
        """
        effective_summary = {
            "mechanism": outbound_type,
            "overridden_by_udr": False,
            "effective_mechanism": outbound_type,
            "virtual_appliance_ips": [],
            "load_balancer_ips": self.outbound_ips.copy(),
            "warnings": [],
            "description": "",
        }

        # Check if UDRs override the configured outbound type
        virtual_appliance_routes = udr_analysis.get("virtualApplianceRoutes", [])

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
                effective_summary["warnings"].append(
                    {
                        "level": "warning",
                        "message": f"Load Balancer outbound configuration detected but UDR forces traffic to virtual appliance ({appliance_ip})",
                        "impact": "The Load Balancer public IPs are not the effective outbound IPs",
                    }
                )
                effective_summary["description"] = (
                    f"Traffic is routed through virtual appliance {appliance_ip} via UDR (overriding Load Balancer)"
                )
            else:
                effective_summary["description"] = f"Traffic is routed through virtual appliance {appliance_ip} via UDR"
        else:
            # No UDR override, use configured mechanism
            if outbound_type == "loadBalancer":
                if self.outbound_ips:
                    effective_summary["description"] = (
                        f"Traffic uses Load Balancer with public IP(s): {', '.join(self.outbound_ips)}"
                    )
                else:
                    effective_summary["warnings"].append(
                        {
                            "level": "error",
                            "message": "Load Balancer outbound type configured but no public IPs found",
                            "impact": "Outbound connectivity may be broken",
                        }
                    )
                    effective_summary["description"] = "Load Balancer outbound configured but no public IPs detected"
            elif outbound_type == "userDefinedRouting":
                if virtual_appliance_routes:
                    # Collect all virtual appliance IPs from routes
                    appliance_ips = list(
                        set(
                            [
                                r.get("nextHopIpAddress", "unknown")
                                for r in virtual_appliance_routes
                                if r.get("nextHopIpAddress")
                            ]
                        )
                    )
                    effective_summary["virtual_appliance_ips"] = appliance_ips
                    effective_summary["description"] = (
                        f"User Defined Routing through virtual appliance(s): {', '.join(appliance_ips)}"
                    )
                else:
                    effective_summary["warnings"].append(
                        {
                            "level": "warning",
                            "message": "User Defined Routing configured but no virtual appliance routes found",
                            "impact": "May indicate misconfigured routing",
                        }
                    )
                    effective_summary["description"] = "User Defined Routing configured"
            elif outbound_type == "managedNATGateway":
                if self.outbound_ips:
                    ip_list = ", ".join(self.outbound_ips)
                    effective_summary["description"] = f"Managed NAT Gateway with outbound IPs: {ip_list}"
                else:
                    effective_summary["description"] = "Managed NAT Gateway (no outbound IPs detected)"

        return effective_summary

    def _display_outbound_summary(self, effective_summary: Dict[str, Any]) -> None:
        """
        Display a summary of the effective outbound configuration

        Args:
            effective_summary: Effective outbound configuration summary
        """
        mechanism = effective_summary["effective_mechanism"]
        description = effective_summary["description"]

        if effective_summary["overridden_by_udr"]:
            self.logger.warning(f"  [!]  {description}")
            if effective_summary["load_balancer_ips"]:
                self.logger.warning(
                    f"    Load Balancer IPs (not effective): {', '.join(effective_summary['load_balancer_ips'])}"
                )
        else:
            if mechanism == "loadBalancer" and effective_summary["load_balancer_ips"]:
                for ip in effective_summary["load_balancer_ips"]:
                    self.logger.info(f"    Found outbound IP: {ip}")
            elif mechanism == "virtualAppliance" and effective_summary["virtual_appliance_ips"]:
                for ip in effective_summary["virtual_appliance_ips"]:
                    self.logger.info(f"    Virtual appliance IP: {ip}")
            elif mechanism == "managedNATGateway" and effective_summary["load_balancer_ips"]:
                for ip in effective_summary["load_balancer_ips"]:
                    self.logger.info(f"    NAT Gateway outbound IP: {ip}")

        # Display warnings
        for warning in effective_summary.get("warnings", []):
            level = warning["level"]
            message = warning["message"]
            if level == "error":
                self.logger.error(f"    [ERROR] {message}")
            else:
                self.logger.warning(f"    [!]  {message}")

    def _analyze_load_balancer_outbound(self, show_details: bool = False) -> None:
        """
        Analyze load balancer outbound configuration

        Args:
            show_details: Enable detailed logging
        """
        self.logger.info("  - Analyzing Load Balancer outbound configuration...")

        # Get the managed cluster's load balancer
        mc_rg = self.cluster_info.get("nodeResourceGroup", "")
        if not mc_rg:
            if show_details:
                self.logger.info("    No node resource group found")
            return

        try:
            # List load balancers in the managed resource group using SDK (replaces: az network lb list)
            load_balancers_list = list(self.sdk_client.network_client.load_balancers.list(mc_rg))

            if not load_balancers_list:
                if show_details:
                    self.logger.info(f"    No load balancers found in {mc_rg}")
                return

        except (ResourceNotFoundError, HttpResponseError) as e:
            self.logger.warning(f"Failed to list load balancers in {mc_rg}: {e}")
            return

        # Process load balancers quietly and only report the final results
        for lb in load_balancers_list:
            lb_name = lb.name
            if not lb_name:
                continue

            # Check outbound rules first
            outbound_rules = lb.outbound_rules or []
            frontend_configs = lb.frontend_ip_configurations or []

            # Collect frontend config IDs that might have outbound IPs
            frontend_config_ids = []

            # Add frontend configs from outbound rules (this is the main path for AKS)
            for rule in outbound_rules:
                # SDK uses frontend_ip_configurations (snake_case)
                frontend_ips = rule.frontend_ip_configurations or []

                for frontend_ip in frontend_ips:
                    if frontend_ip.id:
                        frontend_config_ids.append(frontend_ip.id)

            # Also add all direct frontend configs (for standard LB without outbound rules)
            for frontend in frontend_configs:
                if frontend.id:
                    frontend_config_ids.append(frontend.id)

            # Process each frontend config
            for config_id in frontend_config_ids:
                # Extract load balancer name and frontend config name from ID
                parts = config_id.split("/")
                if len(parts) >= 11:
                    config_name = parts[10]  # Frontend IP config name

                    try:
                        # Get the frontend IP configuration details using SDK
                        # (replaces: az network lb frontend-ip show)
                        frontend_config = self.sdk_client.network_client.load_balancer_frontend_ip_configurations.get(
                            mc_rg, lb_name, config_name
                        )

                        if frontend_config and frontend_config.public_ip_address:
                            public_ip_id = frontend_config.public_ip_address.id
                            if public_ip_id:
                                # Get public IP details using SDK
                                # (replaces: az network public-ip show --ids)
                                ip_info = self._get_public_ip_details(public_ip_id)

                                if ip_info and ip_info.get("ipAddress"):
                                    ip_address = ip_info["ipAddress"]
                                    if ip_address not in self.outbound_ips:
                                        self.outbound_ips.append(ip_address)

                    except (ResourceNotFoundError, HttpResponseError) as e:
                        self.logger.debug(f"Failed to get frontend config {config_name}: {e}")
                        continue

        # Summary of outbound IP discovery will be handled by _display_outbound_summary
        if show_details and not self.outbound_ips:
            self.logger.info("    No outbound IPs detected")

    def _analyze_udr_outbound(self) -> None:
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
            "internetRoutes": udr_analysis.get("internetRoutes", []),
        }

    def _analyze_nat_gateway_outbound(self, show_details: bool = False) -> None:
        """
        Analyze NAT Gateway outbound configuration

        Args:
            show_details: Enable detailed logging
        """
        self.logger.info("  - Analyzing NAT Gateway configuration...")

        # Get the managed cluster's resource group
        mc_rg = self.cluster_info.get("nodeResourceGroup", "")
        if not mc_rg:
            if show_details:
                self.logger.info("    No node resource group found")
            return

        try:
            # List NAT Gateways in the managed resource group using SDK
            # (replaces: az network nat gateway list)
            nat_gateways_list = list(self.sdk_client.network_client.nat_gateways.list(mc_rg))

            if not nat_gateways_list:
                if show_details:
                    self.logger.info(f"    No NAT Gateways found in {mc_rg}")
                return

        except (ResourceNotFoundError, HttpResponseError) as e:
            self.logger.warning(f"Failed to list NAT Gateways in {mc_rg}: {e}")
            return

        # Process each NAT Gateway
        for natgw in nat_gateways_list:
            natgw_name = natgw.name
            if not natgw_name:
                continue

            self.logger.info(f"    Found NAT Gateway: {natgw_name}")

            # Get public IP prefixes and public IPs associated with this NAT Gateway
            public_ip_prefixes = natgw.public_ip_prefixes or []
            public_ips = natgw.public_ip_addresses or []

            # Extract IPs from public IP resources
            for public_ip_ref in public_ips:
                public_ip_id = public_ip_ref.id if public_ip_ref else None
                if public_ip_id:
                    public_ip_info = self._get_public_ip_details(public_ip_id)
                    if public_ip_info:
                        ip_address = public_ip_info.get("ipAddress", "")
                        if ip_address:
                            self.outbound_ips.append(ip_address)
                            if show_details:
                                self.logger.info(f"      Public IP: {ip_address}")

            # Extract IPs from public IP prefixes
            for prefix_ref in public_ip_prefixes:
                prefix_id = prefix_ref.get("id", "")
                if prefix_id:
                    prefix_info = self._get_public_ip_prefix_details(prefix_id)
                    if prefix_info:
                        ip_prefix = prefix_info.get("ipPrefix", "")
                        if ip_prefix:
                            # For prefixes, we'll note the range but also try to get individual IPs
                            if show_details:
                                self.logger.info(f"      Public IP Prefix: {ip_prefix}")
                            # Extract the first IP from the prefix for outbound IP tracking
                            try:
                                import ipaddress

                                ipaddress.ip_network(ip_prefix, strict=False)  # Validate the prefix
                                self.outbound_ips.append(f"{ip_prefix} (range)")
                            except Exception:
                                self.outbound_ips.append(f"{ip_prefix} (prefix)")

        if not self.outbound_ips and show_details:
            self.logger.info("    No outbound IPs detected from NAT Gateway")

    def _get_public_ip_details(self, public_ip_id: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a public IP resource

        Args:
            public_ip_id: Azure resource ID of the public IP

        Returns:
            Dictionary with public IP details or None if error
        """
        try:
            # Parse public IP ID to extract components using SDK client helper
            parsed = self.sdk_client.parse_resource_id(public_ip_id)
            subscription_id = parsed["subscription_id"]
            resource_group = parsed["resource_group"]
            public_ip_name = parsed["resource_name"]

            # Create network client for the public IP's subscription if different
            if subscription_id != self.sdk_client.subscription_id:
                # Need to create a client for different subscription
                from azure.mgmt.network import NetworkManagementClient

                network_client = NetworkManagementClient(self.sdk_client.credential, subscription_id)
            else:
                network_client = self.sdk_client.network_client

            # Get public IP details using SDK (replaces: az network public-ip show)
            public_ip = network_client.public_ip_addresses.get(resource_group, public_ip_name)

            # Convert to dictionary and normalize keys to camelCase for compatibility
            from .azure_sdk_client import normalize_dict_keys

            return normalize_dict_keys(public_ip.as_dict())

        except (ResourceNotFoundError, HttpResponseError) as e:
            self.logger.debug(f"Error getting public IP details for {public_ip_id}: {e}")
            return None
        except Exception as e:
            self.logger.debug(f"Error parsing public IP ID {public_ip_id}: {e}")
            return None

    def _get_public_ip_prefix_details(self, prefix_id: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a public IP prefix resource

        Args:
            prefix_id: Azure resource ID of the public IP prefix

        Returns:
            Dictionary with public IP prefix details or None if error
        """
        try:
            # Parse public IP prefix ID to extract components using SDK client helper
            parsed = self.sdk_client.parse_resource_id(prefix_id)
            subscription_id = parsed["subscription_id"]
            resource_group = parsed["resource_group"]
            prefix_name = parsed["resource_name"]

            # Create network client for the prefix's subscription if different
            if subscription_id != self.sdk_client.subscription_id:
                from azure.mgmt.network import NetworkManagementClient

                network_client = NetworkManagementClient(self.sdk_client.credential, subscription_id)
            else:
                network_client = self.sdk_client.network_client

            # Get public IP prefix details using SDK (replaces: az network public-ip prefix show)
            public_ip_prefix = network_client.public_ip_prefixes.get(resource_group, prefix_name)

            # Convert to dictionary and normalize keys to camelCase for compatibility
            from .azure_sdk_client import normalize_dict_keys

            return normalize_dict_keys(public_ip_prefix.as_dict())

        except (ResourceNotFoundError, HttpResponseError) as e:
            self.logger.debug(f"Error getting public IP prefix details for {prefix_id}: {e}")
            return None
        except Exception as e:
            self.logger.debug(f"Error parsing public IP prefix ID {prefix_id}: {e}")
            return None
