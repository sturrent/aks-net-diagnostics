"""
DNS Analyzer for AKS Network Diagnostics

This module analyzes DNS configuration for AKS clusters, including:
- Private DNS zone configuration
- DNS resolution validation
- Private IP validation for private clusters

Migrated from Azure CLI subprocess to Azure SDK for Python.
"""

import ipaddress
import logging
import re
from typing import Any, Dict, List

from azure.core.exceptions import HttpResponseError, ResourceNotFoundError

from .models import Finding


class DNSAnalyzer:
    """Analyzer for AKS DNS configuration and resolution"""

    def __init__(self, cluster_info: Dict[str, Any], azure_sdk_client=None):
        """
        Initialize DNS analyzer

        Args:
            cluster_info: AKS cluster information from Azure SDK
            azure_sdk_client: Optional AzureSDKClient instance for SDK operations
        """
        self.logger = logging.getLogger("aks_net_diagnostics.dns_analyzer")
        self.cluster_info = cluster_info
        self.sdk_client = azure_sdk_client
        self.dns_analysis: Dict[str, Any] = {}
        self.findings: List[Finding] = []
        self.vnet_dns_servers: List[str] = []

    def analyze(self) -> Dict[str, Any]:
        """
        Perform DNS analysis

        Returns:
            Dictionary containing DNS analysis results
        """
        self.logger.info("Analyzing DNS configuration...")

        # Analyze private DNS zone configuration
        self._analyze_private_dns_zone()

        # Analyze VNet DNS server configuration
        self._analyze_vnet_dns_servers()

        return self.dns_analysis

    def _analyze_private_dns_zone(self) -> None:
        """Analyze private DNS zone configuration for private clusters"""
        api_server_profile = self.cluster_info.get("apiServerAccessProfile")

        if not api_server_profile:
            self.dns_analysis = {
                "type": "none",
                "isPrivateCluster": False,
                "privateDnsZone": None,
                "analysis": "No API server access profile found - not a private cluster",
            }
            return

        is_private = api_server_profile.get("enablePrivateCluster", False)

        if not is_private:
            self.dns_analysis = {
                "type": "none",
                "isPrivateCluster": False,
                "privateDnsZone": None,
                "analysis": "Public cluster - private DNS not required",
            }
            return

        # Private cluster - analyze DNS configuration
        private_dns_zone = api_server_profile.get("privateDnsZone", "")

        if private_dns_zone and private_dns_zone != "system":
            # Custom private DNS zone
            self.dns_analysis = {
                "type": "custom",
                "isPrivateCluster": True,
                "privateDnsZone": private_dns_zone,
                "analysis": "Custom private DNS zone configured",
            }

            self.logger.info("  Custom private DNS zone: %s", private_dns_zone)

            # Add informational finding
            from .models import FindingCode

            self.findings.append(
                Finding.create_info(
                    code=FindingCode.PRIVATE_DNS_MISCONFIGURED,  # Using existing code
                    message=f"Cluster uses custom private DNS zone: {private_dns_zone}",
                    recommendation="Ensure VNet is linked to this private DNS zone for proper name resolution",
                    privateDnsZone=private_dns_zone,
                )
            )
        else:
            # System-managed private DNS zone
            self.dns_analysis = {
                "type": "system",
                "isPrivateCluster": True,
                "privateDnsZone": "system",
                "analysis": "System-managed private DNS zone",
            }

            self.logger.info("  System-managed private DNS zone")

    def _analyze_vnet_dns_servers(self) -> None:
        """Analyze VNet DNS server configuration and detect custom DNS that may impact private DNS resolution"""
        if not self.sdk_client:
            self.logger.debug("  No Azure SDK client available, skipping VNet DNS analysis")
            return

        try:
            # Get VNet subnet ID from cluster
            # Try networkProfile first, then agentPoolProfiles
            network_profile = self.cluster_info.get("networkProfile", {})
            vnet_subnet_id = network_profile.get("vnetSubnetId")

            if not vnet_subnet_id:
                # Try getting from first agent pool profile
                agent_pools = self.cluster_info.get("agentPoolProfiles", [])
                if agent_pools and len(agent_pools) > 0:
                    vnet_subnet_id = agent_pools[0].get("vnetSubnetId")

            if not vnet_subnet_id:
                self.logger.debug("  No VNet subnet ID found in cluster info")
                return

            self.logger.debug("  Found VNet subnet ID: %s", vnet_subnet_id)

            # Parse VNet resource ID from subnet ID using SDK helper
            # Format: /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/virtualNetworks/{vnet}/subnets/{subnet}
            try:
                parsed = self.sdk_client.parse_resource_id(vnet_subnet_id)
                vnet_rg = parsed["resource_group"]
                vnet_name = parsed["parent_name"]  # VNet is parent of subnet

                # Get VNet details including DNS servers using SDK
                # (replaces: az network vnet show)
                vnet = self.sdk_client.network_client.virtual_networks.get(vnet_rg, vnet_name)

                # Get DNS servers from VNet
                dhcp_options = vnet.dhcp_options
                dns_servers = dhcp_options.dns_servers if dhcp_options else []

                self.vnet_dns_servers = dns_servers or []
                self.dns_analysis["vnetDnsServers"] = self.vnet_dns_servers

            except (ResourceNotFoundError, HttpResponseError) as e:
                self.logger.warning("  Unable to retrieve VNet information for %s: %s", vnet_name, e)
                return
            except Exception as e:
                self.logger.warning("  Unable to parse VNet ID from subnet: %s: %s", vnet_subnet_id, e)
                return

            if not dns_servers:
                # Using Azure default DNS
                self.logger.info("  VNet '%s' using Azure default DNS (168.63.129.16)", vnet_name)
                self.dns_analysis["vnetDnsConfig"] = "azure-default"
                return

            self.logger.info("  VNet '%s' has custom DNS servers: %s", vnet_name, ", ".join(dns_servers))
            self.dns_analysis["vnetDnsConfig"] = "custom"

            # Check for potential issues with custom DNS
            is_private_cluster = self.dns_analysis.get("isPrivateCluster", False)
            azure_dns = "168.63.129.16"
            has_azure_dns = azure_dns in dns_servers
            non_azure_dns = [dns for dns in dns_servers if dns != azure_dns]

            if non_azure_dns and is_private_cluster:
                # Private cluster with custom DNS - high risk
                from .models import FindingCode

                self.findings.append(
                    Finding.create_critical(
                        code=FindingCode.PRIVATE_DNS_MISCONFIGURED,
                        message=f"Private cluster is using custom DNS servers ({', '.join(non_azure_dns)}) that cannot resolve Azure private DNS zones",
                        recommendation=(
                            f"For private clusters, ensure custom DNS servers forward Azure private DNS zone queries to Azure DNS (168.63.129.16). "
                            f"Current DNS servers: {', '.join(dns_servers)}. "
                            f"Either: (1) Configure DNS forwarding to 168.63.129.16 for '*.privatelink.*.azmk8s.io', "
                            f"(2) Use Azure DNS as primary DNS server, or "
                            f"(3) Configure conditional forwarding in your custom DNS solution."
                        ),
                        vnetName=vnet_name,
                        vnetResourceGroup=vnet_rg,
                        customDnsServers=non_azure_dns,
                        hasAzureDns=has_azure_dns,
                        privateDnsZone=self.dns_analysis.get("privateDnsZone"),
                    )
                )
                self.logger.warning("  [X] Custom DNS servers may prevent private DNS resolution")

            elif non_azure_dns and not is_private_cluster:
                # Public cluster with custom DNS - medium risk (CoreDNS may have issues)
                from .models import FindingCode

                self.findings.append(
                    Finding.create_warning(
                        code=FindingCode.DNS_RESOLUTION_FAILED,
                        message=f"VNet is using custom DNS servers ({', '.join(non_azure_dns)}) which may impact CoreDNS functionality",
                        recommendation=(
                            f"Custom DNS servers should forward Azure service queries to Azure DNS (168.63.129.16). "
                            f"Current DNS servers: {', '.join(dns_servers)}. "
                            f"If experiencing DNS resolution issues, verify that:\n"
                            f"1. Custom DNS can reach Azure DNS (168.63.129.16)\n"
                            f"2. Azure-specific domains are forwarded correctly\n"
                            f"3. DNS forwarding is configured for '*.azmk8s.io' and other Azure services"
                        ),
                        vnetName=vnet_name,
                        vnetResourceGroup=vnet_rg,
                        customDnsServers=non_azure_dns,
                        hasAzureDns=has_azure_dns,
                    )
                )
                self.logger.warning("  [!] Custom DNS may impact CoreDNS and Azure service resolution")

            elif has_azure_dns and len(dns_servers) > 1:
                # Mix of Azure DNS and custom DNS - informational
                self.logger.info("  VNet uses Azure DNS along with custom DNS servers")

        except Exception as e:
            self.logger.error("  Failed to analyze VNet DNS configuration: %s", e)

    def validate_private_dns_resolution(self, nslookup_output: str, hostname: str) -> bool:
        """
        Validate that DNS resolution returns a private IP address for private clusters

        Args:
            nslookup_output: Output from nslookup command
            hostname: The hostname that was resolved

        Returns:
            True if resolution is valid (returns private IP), False otherwise
        """
        try:
            # Convert compacted format back to regular format for parsing
            output_to_parse = nslookup_output.replace("\\n", "\n")

            # Check for DNS resolution failures first
            dns_error_patterns = [
                "nxdomain",
                "servfail",
                "refused",
                "can't find",
                "no servers could be reached",
                "communications error",
                "timed out",
            ]
            if any(error in output_to_parse.lower() for error in dns_error_patterns):
                self.logger.warning("DNS resolution failed for %s", hostname)
                return False  # DNS resolution failed completely

            # Parse nslookup output to extract IP addresses
            # Look for lines like "Address: 10.1.2.3" or "Addresses:  10.1.2.3"
            # But NOT lines like "Server: ..." or "Address: ...#53"
            ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
            found_ips = re.findall(ip_pattern, output_to_parse)

            if not found_ips:
                self.logger.warning("No IP addresses found in DNS response for %s", hostname)
                return False  # No IP addresses found

            # Filter out DNS server IPs more carefully
            # DNS server IPs appear in patterns like:
            # "Server:  dns-server.example.com"
            # "Address:  168.63.129.16" (immediately after Server line)
            # or "Address: 168.63.129.16#53"

            lines = output_to_parse.split("\n")
            dns_server_ips = set()
            in_server_section = False

            for line in lines:
                line_lower = line.lower()
                # Check if this line indicates DNS server info
                if "server:" in line_lower:
                    in_server_section = True
                    # Extract IP from this line if present
                    server_ips = re.findall(ip_pattern, line)
                    dns_server_ips.update(server_ips)
                elif in_server_section and "address:" in line_lower:
                    # This is the DNS server's address
                    server_ips = re.findall(ip_pattern, line)
                    dns_server_ips.update(server_ips)
                    in_server_section = False  # Only one address line expected
                elif "non-authoritative answer" in line_lower or "name:" in line_lower:
                    # Now we're in the actual answer section
                    in_server_section = False

            # Check resolved IPs (excluding DNS server IPs)
            resolved_ips = [ip for ip in found_ips if ip not in dns_server_ips]

            if not resolved_ips:
                self.logger.warning("Only DNS server IPs found for %s, no actual resolution", hostname)
                return False  # Only DNS server IPs found, no actual resolution

            # Check if any of the resolved IPs are private
            for ip_str in resolved_ips:
                try:
                    ip = ipaddress.ip_address(ip_str)
                    # Check if this is a private IP address
                    if ip.is_private:
                        # Additional validation: private IPs for AKS API servers are typically in specific ranges
                        # Common AKS private IP ranges: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
                        self.logger.info("DNS resolved %s to private IP: %s", hostname, ip_str)
                        return True
                except ValueError:
                    continue  # Skip invalid IP addresses

            # If we found IP addresses but none were private, this indicates the issue
            self.logger.warning("DNS resolved %s to public IP(s): %s", hostname, resolved_ips)

            # Create a finding for this issue
            from .models import FindingCode

            self.findings.append(
                Finding.create_critical(
                    code=FindingCode.PRIVATE_DNS_MISCONFIGURED,
                    message=f"DNS resolution for {hostname} returned public IP instead of private IP",
                    recommendation="Verify that the VNet is linked to the private DNS zone and that DNS records are correctly configured",
                    hostname=hostname,
                    resolvedIPs=resolved_ips,
                    expectedBehavior="Private cluster API server should resolve to private IP address",
                    possibleCauses=[
                        "Private DNS zone link is missing",
                        "Private DNS zone link is in wrong VNet",
                        "Private DNS zone records are incorrect",
                    ],
                )
            )

            return False

        except Exception as e:
            self.logger.error("Error validating DNS resolution for %s: %s", hostname, e)
            # If we can't parse the output, be conservative and check for any error indicators
            dns_error_patterns = [
                "nxdomain",
                "servfail",
                "refused",
                "can't find",
                "no servers could be reached",
                "communications error",
                "timed out",
            ]
            # Return False if any error patterns are found, True only if none are found
            return not any(error in nslookup_output.lower() for error in dns_error_patterns)

    def get_findings(self) -> List[Finding]:
        """
        Get all findings from DNS analysis

        Returns:
            List of Finding objects
        """
        return self.findings
