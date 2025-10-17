"""
NSG Analyzer for AKS Network Diagnostics

This module analyzes Network Security Groups (NSGs) associated with AKS clusters,
checking for misconfigurations, blocking rules, and compliance with AKS requirements.
"""

from typing import Any, Dict, List, Set

from .base_analyzer import BaseAnalyzer
from .exceptions import AzureCLIError
from .models import Finding, FindingCode


class NSGAnalyzer(BaseAnalyzer):
    """Analyzes Network Security Group configurations for AKS clusters."""

    def __init__(self, azure_cli, cluster_info: Dict[str, Any], vmss_info: List[Dict[str, Any]]):
        """
        Initialize NSG Analyzer.

        Args:
            azure_cli: AzureCLIExecutor instance
            cluster_info: AKS cluster information
            vmss_info: VMSS information from VMSS analyzer
        """
        super().__init__(azure_cli, cluster_info)
        self.vmss_info = vmss_info
        self.nsg_analysis = {
            "subnetNsgs": [],
            "nicNsgs": [],
            "requiredRules": [],
            "blockingRules": [],
            "interNodeCommunication": {"status": "unknown", "issues": []},
        }

    def analyze(self) -> Dict[str, Any]:
        """
        Perform comprehensive NSG analysis.

        Returns:
            Dictionary containing NSG analysis results
        """
        self.logger.info("Analyzing NSG configuration...")

        # Determine if cluster is private
        is_private_cluster = self._is_private_cluster()

        # Get required AKS rules
        required_rules = self._get_required_aks_rules(is_private_cluster)
        self.nsg_analysis["requiredRules"] = required_rules

        # Analyze NSGs on subnets
        self._analyze_subnet_nsgs()

        # Analyze NSGs on NICs
        self._analyze_nic_nsgs()

        # Check inter-node communication
        self._analyze_inter_node_communication()

        # Check for blocking rules
        self._analyze_nsg_compliance()

        return self.nsg_analysis

    def _is_private_cluster(self) -> bool:
        """Check if cluster is private."""
        api_server_profile = self.cluster_info.get("apiServerAccessProfile")
        if api_server_profile:
            return api_server_profile.get("enablePrivateCluster", False)
        return False

    def _get_required_aks_rules(self, is_private_cluster: bool) -> Dict[str, List[Dict[str, str]]]:
        """
        Get required NSG rules for AKS based on cluster type.

        Args:
            is_private_cluster: Whether the cluster is private

        Returns:
            Dictionary of required inbound and outbound rules
        """
        rules = {
            "outbound": [
                {
                    "name": "AKS_Registry_Access",
                    "protocol": "TCP",
                    "destination": "MicrosoftContainerRegistry",
                    "ports": ["443"],
                    "description": "Access to Microsoft Container Registry",
                },
                {
                    "name": "AKS_Azure_Management",
                    "protocol": "TCP",
                    "destination": "AzureCloud",
                    "ports": ["443"],
                    "description": "Azure management endpoints",
                },
                {
                    "name": "AKS_DNS",
                    "protocol": "UDP",
                    "destination": "*",
                    "ports": ["53"],
                    "description": "DNS resolution",
                },
                {
                    "name": "AKS_NTP",
                    "protocol": "UDP",
                    "destination": "*",
                    "ports": ["123"],
                    "description": "Network Time Protocol",
                },
            ],
            "inbound": [
                {
                    "name": "AKS_Inter_Node_Communication",
                    "protocol": "*",
                    "source": "VirtualNetwork",
                    "ports": ["*"],
                    "description": "Communication between cluster nodes",
                },
                {
                    "name": "AKS_Load_Balancer",
                    "protocol": "*",
                    "source": "AzureLoadBalancer",
                    "ports": ["*"],
                    "description": "Azure Load Balancer health probes",
                },
            ],
        }

        if not is_private_cluster:
            # Public clusters need API server access
            rules["outbound"].append(
                {
                    "name": "AKS_API_Server_Access",
                    "protocol": "TCP",
                    "destination": "*",
                    "ports": ["443"],
                    "description": "Access to AKS API server",
                }
            )

        return rules

    def _analyze_subnet_nsgs(self) -> None:
        """Analyze NSGs associated with node subnets."""
        processed_subnets: Set[str] = set()

        for vmss in self.vmss_info:
            vmss_name = vmss.get("name", "unknown")
            vm_profile = vmss.get("virtualMachineProfile", {})
            network_profile = vm_profile.get("networkProfile", {})
            network_interfaces = network_profile.get("networkInterfaceConfigurations", [])

            for nic in network_interfaces:
                ip_configs = nic.get("ipConfigurations", [])
                for ip_config in ip_configs:
                    subnet = ip_config.get("subnet", {})
                    subnet_id = subnet.get("id")

                    if not subnet_id or subnet_id in processed_subnets:
                        continue

                    processed_subnets.add(subnet_id)

                    # Get subnet information
                    try:
                        subnet_info = self.azure_cli.execute(["network", "vnet", "subnet", "show", "--ids", subnet_id])

                        if not subnet_info or not isinstance(subnet_info, dict):
                            continue

                        nsg_info = subnet_info.get("networkSecurityGroup")
                        if nsg_info:
                            nsg_id = nsg_info.get("id")
                            nsg_name = nsg_id.split("/")[-1] if nsg_id else "unknown"

                            # Get NSG details
                            nsg_details = self.azure_cli.execute(["network", "nsg", "show", "--ids", nsg_id])

                            if nsg_details and isinstance(nsg_details, dict):
                                self.nsg_analysis["subnetNsgs"].append(
                                    {
                                        "subnetId": subnet_id,
                                        "subnetName": subnet_info.get("name", "unknown"),
                                        "nsgId": nsg_id,
                                        "nsgName": nsg_name,
                                        "rules": nsg_details.get("securityRules", []),
                                        "defaultRules": nsg_details.get("defaultSecurityRules", []),
                                    }
                                )

                                self.logger.info(f"  Found NSG on subnet {subnet_info.get('name')}: {nsg_name}")
                        else:
                            self.logger.info(f"  No NSG found on subnet {subnet_info.get('name')}")

                    except AzureCLIError as e:
                        self.logger.error(f"  Failed to analyze subnet {subnet_id}: {e}")

    def _analyze_nic_nsgs(self) -> None:
        """Analyze NSGs associated with node NICs."""
        for vmss in self.vmss_info:
            vmss_name = vmss.get("name")
            if not vmss_name:
                continue

            vm_profile = vmss.get("virtualMachineProfile", {})
            network_profile = vm_profile.get("networkProfile", {})
            network_interfaces = network_profile.get("networkInterfaceConfigurations", [])

            for nic_config in network_interfaces:
                nsg_info = nic_config.get("networkSecurityGroup")
                if nsg_info:
                    nsg_id = nsg_info.get("id")
                    nsg_name = nsg_id.split("/")[-1] if nsg_id else "unknown"

                    try:
                        # Get NSG details
                        nsg_details = self.azure_cli.execute(["network", "nsg", "show", "--ids", nsg_id])

                        if nsg_details and isinstance(nsg_details, dict):
                            self.nsg_analysis["nicNsgs"].append(
                                {
                                    "vmssName": vmss_name,
                                    "nicName": nic_config.get("name", "unknown"),
                                    "nsgId": nsg_id,
                                    "nsgName": nsg_name,
                                    "rules": nsg_details.get("securityRules", []),
                                    "defaultRules": nsg_details.get("defaultSecurityRules", []),
                                }
                            )

                            self.logger.info(f"  Found NSG on VMSS {vmss_name} NIC: {nsg_name}")

                    except AzureCLIError as e:
                        self.logger.error(f"  Failed to analyze NIC NSG {nsg_id}: {e}")
                else:
                    self.logger.info(f"  No NSG found on VMSS {vmss_name} NIC")

    def _analyze_inter_node_communication(self) -> None:
        """Analyze if NSG rules could block inter-node communication."""
        all_nsgs = self.nsg_analysis["subnetNsgs"] + self.nsg_analysis["nicNsgs"]
        issues = []

        for nsg in all_nsgs:
            blocking_rules = []
            all_rules = nsg.get("rules", []) + nsg.get("defaultRules", [])

            for rule in all_rules:
                if (
                    rule.get("access", "").lower() == "deny"
                    and rule.get("direction", "").lower() == "inbound"
                    and rule.get("priority", 0) < 65000
                ):

                    source = rule.get("sourceAddressPrefix", "")
                    if self._is_vnet_source(source):
                        blocking_rules.append(
                            {
                                "ruleName": rule.get("name", "unknown"),
                                "priority": rule.get("priority", 0),
                                "source": source,
                                "destination": rule.get("destinationAddressPrefix", ""),
                                "protocol": rule.get("protocol", ""),
                                "ports": rule.get("destinationPortRange", ""),
                            }
                        )

            if blocking_rules:
                issues.append(
                    {
                        "nsgName": nsg.get("nsgName"),
                        "location": "subnet" if "subnetId" in nsg else "nic",
                        "blockingRules": blocking_rules,
                    }
                )

        self.nsg_analysis["interNodeCommunication"] = {
            "status": "potential_issues" if issues else "ok",
            "issues": issues,
        }

        if issues:
            for issue in issues:
                self.add_finding(
                    Finding.create_warning(
                        FindingCode.NSG_INTER_NODE_BLOCKED,
                        message=f"NSG '{issue['nsgName']}' has rules that may block inter-node communication",
                        recommendation=f"Review blocking rules in NSG on {issue['location']}",
                        nsg_name=issue["nsgName"],
                        blocking_rules=issue["blockingRules"],
                    )
                )

    def _is_vnet_source(self, source: str) -> bool:
        """Check if source is VirtualNetwork or private IP range."""
        if source in ["*", "VirtualNetwork"]:
            return True
        # Check for private IP ranges
        if source.startswith("10.") or source.startswith("192.168.") or source.startswith("172."):
            return True
        return False

    def _analyze_nsg_compliance(self) -> None:
        """Analyze NSG compliance with AKS requirements."""
        all_nsgs = self.nsg_analysis["subnetNsgs"] + self.nsg_analysis["nicNsgs"]
        blocking_rules = []

        for nsg in all_nsgs:
            nsg_name = nsg.get("nsgName", "unknown")
            all_rules = nsg.get("rules", []) + nsg.get("defaultRules", [])

            # Sort by priority
            sorted_rules = sorted(all_rules, key=lambda x: x.get("priority", 65000))

            # Check for rules that might block AKS traffic
            for rule in sorted_rules:
                if rule.get("access", "").lower() == "deny" and rule.get("priority", 0) < 65000:
                    if rule.get("direction", "").lower() == "outbound":
                        dest = rule.get("destinationAddressPrefix", "")
                        ports = rule.get("destinationPortRange", "")
                        protocol = rule.get("protocol", "")

                        # Check if blocks essential AKS traffic
                        if self._blocks_aks_traffic(dest, ports, protocol):
                            is_overridden, overriding_rules = self._check_rule_precedence(rule, sorted_rules)

                            blocking_rule = {
                                "nsgName": nsg_name,
                                "ruleName": rule.get("name", "unknown"),
                                "priority": rule.get("priority", 0),
                                "direction": rule.get("direction", ""),
                                "protocol": protocol,
                                "destination": dest,
                                "ports": ports,
                                "impact": "Could block AKS management traffic",
                                "isOverridden": is_overridden,
                                "overriddenBy": overriding_rules,
                                "effectiveSeverity": "warning" if is_overridden else "critical",
                            }

                            blocking_rules.append(blocking_rule)

                            # Add finding
                            if is_overridden:
                                self.add_finding(
                                    Finding.create_warning(
                                        FindingCode.NSG_POTENTIAL_BLOCK,
                                        message=f"NSG rule '{rule.get('name')}' in '{nsg_name}' may block AKS traffic but is overridden",
                                        recommendation="Verify that override rules are correctly configured",
                                        **blocking_rule,
                                    )
                                )
                            else:
                                self.add_finding(
                                    Finding.create_critical(
                                        FindingCode.NSG_BLOCKING_AKS_TRAFFIC,
                                        message=f"NSG rule '{rule.get('name')}' in '{nsg_name}' may block AKS traffic",
                                        recommendation=f"Review NSG rule priority {rule.get('priority')} - Could block AKS management traffic",
                                        **blocking_rule,
                                    )
                                )

        self.nsg_analysis["blockingRules"] = blocking_rules

    def _blocks_aks_traffic(self, dest: str, ports: str, protocol: str) -> bool:
        """Check if rule blocks essential AKS traffic."""
        # Check destination
        if dest in ["*", "Internet"] or "MicrosoftContainerRegistry" in str(dest) or "AzureCloud" in str(dest):
            # Check ports and protocol
            if ("443" in str(ports) or "*" in str(ports)) and protocol.upper() in ["TCP", "*"]:
                return True
        return False

    def _check_rule_precedence(
        self, deny_rule: Dict[str, Any], sorted_rules: List[Dict[str, Any]]
    ) -> tuple[bool, List[Dict[str, str]]]:
        """
        Check if a deny rule is overridden by higher priority allow rules.

        Args:
            deny_rule: The deny rule to check
            sorted_rules: All rules sorted by priority

        Returns:
            Tuple of (is_overridden, overriding_rules)
        """
        deny_priority = deny_rule.get("priority", 65000)
        overriding_rules = []

        for rule in sorted_rules:
            rule_priority = rule.get("priority", 65000)

            if rule_priority >= deny_priority:
                break

            if (
                rule.get("access", "").lower() == "allow"
                and rule.get("direction", "").lower() == deny_rule.get("direction", "").lower()
            ):

                if self._rules_overlap(deny_rule, rule):
                    overriding_rules.append(
                        {
                            "ruleName": rule.get("name", "unknown"),
                            "priority": rule_priority,
                            "destination": rule.get("destinationAddressPrefix", ""),
                            "ports": rule.get("destinationPortRange", ""),
                            "protocol": rule.get("protocol", ""),
                        }
                    )

        return len(overriding_rules) > 0, overriding_rules

    def _rules_overlap(self, deny_rule: Dict[str, Any], allow_rule: Dict[str, Any]) -> bool:
        """
        Check if an allow rule overlaps with a deny rule for AKS traffic.

        This method now properly validates that the allow rule actually covers
        the specific traffic that AKS needs, not just that it has a higher priority.
        """
        # Check destination overlap with proper service tag semantics
        deny_dest = deny_rule.get("destinationAddressPrefix", "").lower()
        allow_dest = allow_rule.get("destinationAddressPrefix", "").lower()

        dest_overlap = False

        # Allow rule with '*' covers everything
        if allow_dest == "*":
            dest_overlap = True
        # Allow rule with same destination as deny
        elif allow_dest == deny_dest:
            dest_overlap = True
        # Special case: Internet traffic requirements
        elif deny_dest == "internet":
            # For Internet-blocking rules, only these service tags actually help:
            # - Internet (explicit allow)
            # - AzureContainerRegistry (covers MCR)
            # - * (covers everything)
            # NOTE: AzureCloud does NOT cover general Internet destinations like MCR
            if allow_dest in ["internet", "azurecontainerregistry"]:
                dest_overlap = True
        # If deny is wildcard, allow must also be wildcard
        elif deny_dest == "*":
            if allow_dest in ["*", "internet", "azurecloud", "azurecontainerregistry"]:
                dest_overlap = True
        # AzureCloud covers Azure-specific services but not general Internet
        elif deny_dest in ["azurecloud", "microsoftcontainerregistry", "azurecontainerregistry"]:
            if allow_dest in ["*", "azurecloud", "azurecontainerregistry"]:
                dest_overlap = True

        if not dest_overlap:
            return False

        # Check port overlap
        deny_ports = str(deny_rule.get("destinationPortRange", "")).lower()
        allow_ports = str(allow_rule.get("destinationPortRange", "")).lower()

        port_overlap = False
        if allow_ports == "*" or deny_ports == "*":
            port_overlap = True
        elif "443" in deny_ports and ("443" in allow_ports or "*" in allow_ports):
            port_overlap = True
        elif deny_ports == allow_ports:
            port_overlap = True

        if not port_overlap:
            return False

        # Check protocol overlap
        deny_protocol = deny_rule.get("protocol", "").upper()
        allow_protocol = allow_rule.get("protocol", "").upper()

        protocol_overlap = (
            allow_protocol == "*"
            or deny_protocol == "*"
            or deny_protocol == allow_protocol
            or (deny_protocol in ["TCP", "*"] and allow_protocol in ["TCP", "*"])
        )

        return protocol_overlap
