"""
Route Table Analyzer for AKS Network Diagnostics

This module analyzes User Defined Routes (UDRs) and Route Tables associated with AKS node subnets.
It identifies potential connectivity issues, categorizes routes by impact, and detects common
misconfigurations that could affect AKS cluster operations.

Key Features:
- Analyzes route tables associated with AKS node subnets
- Assesses route impact on AKS connectivity (critical, high, medium, low)
- Categorizes routes by type (default routes, virtual appliance, Azure services, etc.)
- Detects common issues like blackhole routes, Azure service blocking, MCR access issues
- Supports multiple agent pools with different subnet configurations
"""

import logging
from typing import Any, Dict, List, Optional, Set


class RouteTableAnalyzer:
    """
    Analyzes User Defined Routes (UDRs) and Route Tables for AKS clusters.

    This class examines route tables associated with AKS node subnets to identify
    potential connectivity issues and assess the impact of routes on cluster operations.
    """

    def __init__(self, agent_pools: List[Dict[str, Any]], azure_cli):
        """
        Initialize the RouteTableAnalyzer.

        Args:
            agent_pools: List of AKS agent pool configurations
            azure_cli: AzureCLIExecutor instance for making Azure CLI calls
        """
        self.agent_pools = agent_pools
        self.azure_cli = azure_cli
        self.logger = logging.getLogger("aks_net_diagnostics.route_table_analyzer")

    def analyze(self) -> Dict[str, Any]:
        """
        Analyze User Defined Routes on node subnets.

        Returns:
            Dictionary containing route table analysis results with structure:
            {
                "routeTables": [...],          # List of analyzed route tables
                "criticalRoutes": [...],        # Routes with critical/high impact
                "virtualApplianceRoutes": [...],# Routes through virtual appliances
                "internetRoutes": [...]         # Internet-bound routes
            }
        """
        self.logger.info("    Analyzing UDRs on node subnets...")

        udr_analysis = {"routeTables": [], "criticalRoutes": [], "virtualApplianceRoutes": [], "internetRoutes": []}

        # Get unique subnet IDs from agent pools
        subnet_ids = self._get_unique_subnet_ids()

        if not subnet_ids:
            self.logger.info("    No VNet-integrated node pools found")
            return udr_analysis

        # Analyze each subnet for route tables
        for subnet_id in subnet_ids:
            try:
                subnet_info = self._get_subnet_details(subnet_id)
                if not subnet_info:
                    continue

                route_table = subnet_info.get("routeTable")
                if route_table and route_table.get("id"):
                    route_table_id = route_table["id"]
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

    def _get_unique_subnet_ids(self) -> Set[str]:
        """
        Extract unique subnet IDs from agent pools.

        Returns:
            Set of subnet IDs (Azure resource IDs)
        """
        subnet_ids = set()
        for pool in self.agent_pools:
            subnet_id = pool.get("vnetSubnetId")
            if subnet_id and subnet_id != "null":
                subnet_ids.add(subnet_id)
        return subnet_ids

    def _get_subnet_details(self, subnet_id: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a subnet.

        Args:
            subnet_id: Azure resource ID of the subnet

        Returns:
            Subnet details dictionary or None if error occurs
        """
        try:
            # Parse subnet ID to extract components
            parts = subnet_id.split("/")
            if len(parts) < 11:
                return None

            subscription_id = parts[2]
            resource_group = parts[4]
            vnet_name = parts[8]
            subnet_name = parts[10]

            # Get subnet details
            cmd = [
                "network",
                "vnet",
                "subnet",
                "show",
                "--subscription",
                subscription_id,
                "-g",
                resource_group,
                "--vnet-name",
                vnet_name,
                "-n",
                subnet_name,
            ]

            return self.azure_cli.execute(cmd)

        except Exception as e:
            self.logger.info(f"    Error getting subnet details for {subnet_id}: {e}")
            return None

    def _analyze_route_table(self, route_table_id: str, subnet_id: str) -> Optional[Dict[str, Any]]:
        """
        Analyze a specific route table.

        Args:
            route_table_id: Azure resource ID of the route table
            subnet_id: Azure resource ID of the associated subnet

        Returns:
            Route table analysis dictionary or None if error occurs
        """
        try:
            # Parse route table ID
            parts = route_table_id.split("/")
            if len(parts) < 9:
                return None

            subscription_id = parts[2]
            resource_group = parts[4]
            route_table_name = parts[8]

            # Get route table details
            cmd = [
                "network",
                "route-table",
                "show",
                "--subscription",
                subscription_id,
                "-g",
                resource_group,
                "-n",
                route_table_name,
            ]

            route_table_info = self.azure_cli.execute(cmd)

            if not route_table_info:
                return None

            analysis = {
                "id": route_table_id,
                "name": route_table_name,
                "resourceGroup": resource_group,
                "associatedSubnet": subnet_id,
                "routes": [],
                "disableBgpRoutePropagation": route_table_info.get("disableBgpRoutePropagation", False),
            }

            # Analyze each route
            routes = route_table_info.get("routes", [])
            for route in routes:
                route_analysis = self._analyze_individual_route(route)
                if route_analysis:
                    analysis["routes"].append(route_analysis)

            self.logger.info(f"    Route table {route_table_name} has {len(routes)} route(s)")

            return analysis

        except Exception as e:
            self.logger.info(f"    Error analyzing route table {route_table_id}: {e}")
            return None

    def _analyze_individual_route(self, route: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Analyze an individual route.

        Args:
            route: Route configuration dictionary from Azure

        Returns:
            Route analysis dictionary or None if error occurs
        """
        try:
            next_hop_type = route.get("nextHopType", "")
            address_prefix = route.get("addressPrefix", "")
            next_hop_ip = route.get("nextHopIpAddress", "")
            route_name = route.get("name", "")

            analysis = {
                "name": route_name,
                "addressPrefix": address_prefix,
                "nextHopType": next_hop_type,
                "nextHopIpAddress": next_hop_ip,
                "provisioningState": route.get("provisioningState", ""),
                "impact": self._assess_route_impact(address_prefix, next_hop_type, next_hop_ip),
            }

            return analysis

        except Exception as e:
            self.logger.info(f"    Error analyzing route: {e}")
            return None

    def _assess_route_impact(self, address_prefix: str, next_hop_type: str, _next_hop_ip: str) -> Dict[str, Any]:
        """
        Assess the potential impact of a route on AKS connectivity.

        Args:
            address_prefix: CIDR range covered by the route
            next_hop_type: Azure next hop type (VirtualAppliance, Internet, None, etc.)
            _next_hop_ip: IP address of the next hop (reserved for future use)

        Returns:
            Dictionary containing severity, description, and affected traffic types
        """
        impact = {"severity": "info", "description": "", "affectedTraffic": []}

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

        # Check for container registry routes BEFORE Azure services (MCR ranges overlap with Azure)
        elif self._is_container_registry_prefix(address_prefix):
            if next_hop_type == "VirtualAppliance":
                impact["severity"] = "medium"
                impact["description"] = f"Container registry traffic ({address_prefix}) redirected to virtual appliance"
                impact["affectedTraffic"] = ["container_registry"]
            elif next_hop_type == "None":
                impact["severity"] = "high"
                impact["description"] = f"Container registry traffic ({address_prefix}) blocked"
                impact["affectedTraffic"] = ["container_registry"]

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

        # Check for private network routes
        elif self._is_private_network_prefix(address_prefix):
            if next_hop_type == "VirtualAppliance":
                impact["severity"] = "low"
                impact["description"] = f"Private network traffic ({address_prefix}) redirected to virtual appliance"
                impact["affectedTraffic"] = ["private_network"]

        return impact

    def _is_azure_service_prefix(self, address_prefix: str) -> bool:
        """
        Check if address prefix covers Azure service endpoints.

        Args:
            address_prefix: CIDR address prefix to check

        Returns:
            True if the prefix matches common Azure service ranges
        """
        # Common Azure service IP ranges (simplified check)
        azure_prefixes = ["13.", "20.", "23.", "40.", "52.", "104.", "168.", "191."]
        return any(address_prefix.startswith(prefix) for prefix in azure_prefixes)

    def _is_container_registry_prefix(self, address_prefix: str) -> bool:
        """
        Check if address prefix covers container registry endpoints.

        Args:
            address_prefix: CIDR address prefix to check

        Returns:
            True if the prefix matches Microsoft Container Registry ranges
        """
        # Microsoft Container Registry typically uses these ranges
        mcr_prefixes = ["20.81.", "20.117.", "52.159.", "52.168."]
        return any(address_prefix.startswith(prefix) for prefix in mcr_prefixes)

    def _is_private_network_prefix(self, address_prefix: str) -> bool:
        """
        Check if address prefix is for private networks (RFC 1918).

        Args:
            address_prefix: CIDR address prefix to check

        Returns:
            True if the prefix matches private network ranges
        """
        private_prefixes = [
            "10.",
            "172.16.",
            "172.17.",
            "172.18.",
            "172.19.",
            "172.20.",
            "172.21.",
            "172.22.",
            "172.23.",
            "172.24.",
            "172.25.",
            "172.26.",
            "172.27.",
            "172.28.",
            "172.29.",
            "172.30.",
            "172.31.",
            "192.168.",
        ]
        return any(address_prefix.startswith(prefix) for prefix in private_prefixes)

    def _categorize_route(self, route: Dict[str, Any], udr_analysis: Dict[str, Any]) -> None:
        """
        Categorize routes based on their impact and add to appropriate analysis lists.

        Args:
            route: Route analysis dictionary
            udr_analysis: Overall UDR analysis dictionary (modified in place)
        """
        impact = route.get("impact", {})
        severity = impact.get("severity", "info")
        next_hop_type = route.get("nextHopType", "")
        address_prefix = route.get("addressPrefix", "")

        # Critical routes (high impact on connectivity)
        if severity in ["critical", "high"]:
            udr_analysis["criticalRoutes"].append(
                {
                    "name": route.get("name", ""),
                    "addressPrefix": address_prefix,
                    "nextHopType": next_hop_type,
                    "impact": impact,
                }
            )

        # Virtual appliance routes
        if next_hop_type == "VirtualAppliance":
            udr_analysis["virtualApplianceRoutes"].append(
                {
                    "name": route.get("name", ""),
                    "addressPrefix": address_prefix,
                    "nextHopIpAddress": route.get("nextHopIpAddress", ""),
                    "impact": impact,
                }
            )

        # Internet routes
        if address_prefix == "0.0.0.0/0" or next_hop_type == "Internet":
            udr_analysis["internetRoutes"].append(
                {
                    "name": route.get("name", ""),
                    "addressPrefix": address_prefix,
                    "nextHopType": next_hop_type,
                    "impact": impact,
                }
            )
