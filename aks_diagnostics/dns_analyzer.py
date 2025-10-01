"""
DNS Analyzer for AKS Network Diagnostics

This module analyzes DNS configuration for AKS clusters, including:
- Private DNS zone configuration
- DNS resolution validation
- Private IP validation for private clusters
"""

import logging
import re
import ipaddress
from typing import Dict, List, Any, Optional
from .models import Finding


class DNSAnalyzer:
    """Analyzer for AKS DNS configuration and resolution"""
    
    def __init__(self, cluster_info: Dict[str, Any]):
        """
        Initialize DNS analyzer
        
        Args:
            cluster_info: AKS cluster information from Azure CLI
        """
        self.logger = logging.getLogger("aks_net_diagnostics.dns_analyzer")
        self.cluster_info = cluster_info
        self.dns_analysis: Dict[str, Any] = {}
        self.findings: List[Finding] = []
    
    def analyze(self) -> Dict[str, Any]:
        """
        Perform DNS analysis
        
        Returns:
            Dictionary containing DNS analysis results
        """
        self.logger.info("Analyzing DNS configuration...")
        
        # Analyze private DNS zone configuration
        self._analyze_private_dns_zone()
        
        return self.dns_analysis
    
    def _analyze_private_dns_zone(self) -> None:
        """Analyze private DNS zone configuration for private clusters"""
        api_server_profile = self.cluster_info.get('apiServerAccessProfile')
        
        if not api_server_profile:
            self.dns_analysis = {
                "type": "none",
                "isPrivateCluster": False,
                "privateDnsZone": None,
                "analysis": "No API server access profile found - not a private cluster"
            }
            return
        
        is_private = api_server_profile.get('enablePrivateCluster', False)
        
        if not is_private:
            self.dns_analysis = {
                "type": "none",
                "isPrivateCluster": False,
                "privateDnsZone": None,
                "analysis": "Public cluster - private DNS not required"
            }
            return
        
        # Private cluster - analyze DNS configuration
        private_dns_zone = api_server_profile.get('privateDnsZone', '')
        
        if private_dns_zone and private_dns_zone != 'system':
            # Custom private DNS zone
            self.dns_analysis = {
                "type": "custom",
                "isPrivateCluster": True,
                "privateDnsZone": private_dns_zone,
                "analysis": "Custom private DNS zone configured"
            }
            
            self.logger.info(f"  Custom private DNS zone: {private_dns_zone}")
            
            # Add informational finding
            from .models import FindingCode
            self.findings.append(Finding.create_info(
                code=FindingCode.PRIVATE_DNS_MISCONFIGURED,  # Using existing code
                message=f"Cluster uses custom private DNS zone: {private_dns_zone}",
                recommendation="Ensure VNet is linked to this private DNS zone for proper name resolution",
                privateDnsZone=private_dns_zone
            ))
        else:
            # System-managed private DNS zone
            self.dns_analysis = {
                "type": "system",
                "isPrivateCluster": True,
                "privateDnsZone": "system",
                "analysis": "System-managed private DNS zone"
            }
            
            self.logger.info("  System-managed private DNS zone")
    
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
            output_to_parse = nslookup_output.replace('\\n', '\n')
            
            # Check for DNS resolution failures first
            dns_error_patterns = [
                'nxdomain', 'servfail', 'refused', "can't find", 
                'no servers could be reached', 'communications error', 'timed out'
            ]
            if any(error in output_to_parse.lower() for error in dns_error_patterns):
                self.logger.warning(f"DNS resolution failed for {hostname}")
                return False  # DNS resolution failed completely
            
            # Parse nslookup output to extract IP addresses
            # Look for lines like "Address: 10.1.2.3" or "Addresses:  10.1.2.3"
            # But NOT lines like "Server: ..." or "Address: ...#53"
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            found_ips = re.findall(ip_pattern, output_to_parse)
            
            if not found_ips:
                self.logger.warning(f"No IP addresses found in DNS response for {hostname}")
                return False  # No IP addresses found
            
            # Filter out DNS server IPs more carefully
            # DNS server IPs appear in patterns like:
            # "Server:  dns-server.example.com"
            # "Address:  168.63.129.16" (immediately after Server line)
            # or "Address: 168.63.129.16#53"
            
            lines = output_to_parse.split('\n')
            dns_server_ips = set()
            in_server_section = False
            
            for i, line in enumerate(lines):
                line_lower = line.lower()
                # Check if this line indicates DNS server info
                if 'server:' in line_lower:
                    in_server_section = True
                    # Extract IP from this line if present
                    server_ips = re.findall(ip_pattern, line)
                    dns_server_ips.update(server_ips)
                elif in_server_section and 'address:' in line_lower:
                    # This is the DNS server's address
                    server_ips = re.findall(ip_pattern, line)
                    dns_server_ips.update(server_ips)
                    in_server_section = False  # Only one address line expected
                elif 'non-authoritative answer' in line_lower or 'name:' in line_lower:
                    # Now we're in the actual answer section
                    in_server_section = False
            
            # Check resolved IPs (excluding DNS server IPs)
            resolved_ips = [ip for ip in found_ips if ip not in dns_server_ips]
            
            if not resolved_ips:
                self.logger.warning(f"Only DNS server IPs found for {hostname}, no actual resolution")
                return False  # Only DNS server IPs found, no actual resolution
            
            # Check if any of the resolved IPs are private
            for ip_str in resolved_ips:
                try:
                    ip = ipaddress.ip_address(ip_str)
                    # Check if this is a private IP address
                    if ip.is_private:
                        # Additional validation: private IPs for AKS API servers are typically in specific ranges
                        # Common AKS private IP ranges: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
                        self.logger.info(f"DNS resolved {hostname} to private IP: {ip_str}")
                        return True
                except ValueError:
                    continue  # Skip invalid IP addresses
            
            # If we found IP addresses but none were private, this indicates the issue
            self.logger.warning(f"DNS resolved {hostname} to public IP(s): {resolved_ips}")
            
            # Create a finding for this issue
            from .models import FindingCode
            self.findings.append(Finding.create_critical(
                code=FindingCode.PRIVATE_DNS_MISCONFIGURED,
                message=f"DNS resolution for {hostname} returned public IP instead of private IP",
                recommendation="Verify that the VNet is linked to the private DNS zone and that DNS records are correctly configured",
                hostname=hostname,
                resolvedIPs=resolved_ips,
                expectedBehavior="Private cluster API server should resolve to private IP address",
                possibleCauses=[
                    "Private DNS zone link is missing",
                    "Private DNS zone link is in wrong VNet",
                    "Private DNS zone records are incorrect"
                ]
            ))
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error validating DNS resolution for {hostname}: {e}")
            # If we can't parse the output, be conservative and check for any error indicators
            dns_error_patterns = [
                'nxdomain', 'servfail', 'refused', "can't find", 
                'no servers could be reached', 'communications error', 'timed out'
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
