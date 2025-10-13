"""
API Server Access Analyzer for AKS clusters

Analyzes API server access configuration including:
- Authorized IP ranges
- Private cluster settings
- Security best practices
- Access restrictions and implications
"""

import logging
import ipaddress
from typing import Dict, Any, List, Optional


class APIServerAccessAnalyzer:
    """Analyzes AKS API server access configuration and security settings"""
    
    def __init__(self, cluster_info: Dict[str, Any], outbound_ips: Optional[List[str]] = None, outbound_analysis: Optional[Dict[str, Any]] = None):
        """
        Initialize API Server Access Analyzer
        
        Args:
            cluster_info: AKS cluster information dictionary
            outbound_ips: List of cluster outbound IP addresses (optional)
            outbound_analysis: Outbound connectivity analysis results (optional)
        """
        self.cluster_info = cluster_info
        self.outbound_ips = outbound_ips or []
        self.outbound_analysis = outbound_analysis or {}
        self.logger = logging.getLogger("aks_net_diagnostics.api_server_analyzer")
        self.analysis_result = {}
    
    def analyze(self) -> Dict[str, Any]:
        """
        Perform comprehensive API server access analysis
        
        Returns:
            Dictionary containing analysis results with keys:
            - privateCluster: bool
            - authorizedIpRanges: list
            - disableRunCommand: bool
            - analysis: dict with detailed analysis
            - securityFindings: list of security findings
            - accessRestrictions: dict with access model and implications
        """
        api_server_profile = self.cluster_info.get('apiServerAccessProfile')
        
        if not api_server_profile:
            self.logger.info("  - No API server access profile found")
            return {
                "privateCluster": False,
                "authorizedIpRanges": [],
                "disableRunCommand": False,
                "analysis": {"ipRangeRestriction": "none"},
                "securityFindings": [],
                "accessRestrictions": {}
            }
        
        # Initialize analysis result
        self.analysis_result = {
            "privateCluster": api_server_profile.get('enablePrivateCluster', False),
            "authorizedIpRanges": api_server_profile.get('authorizedIpRanges', []),
            "disableRunCommand": api_server_profile.get('disableRunCommand', False),
            "analysis": {},
            "securityFindings": [],
            "accessRestrictions": {}
        }
        
        # Perform analysis steps
        self._analyze_authorized_ip_ranges()
        self._validate_api_security_configuration()
        self._analyze_access_restrictions()
        
        return self.analysis_result
    
    def _analyze_authorized_ip_ranges(self):
        """Analyze authorized IP ranges configuration"""
        authorized_ranges = self.analysis_result["authorizedIpRanges"]
        
        if not authorized_ranges:
            self.logger.info("  - No authorized IP ranges configured (unrestricted access)")
            self.analysis_result["analysis"]["ipRangeRestriction"] = "none"
            return
        
        self.logger.info(f"  - Found {len(authorized_ranges)} authorized IP range(s):")
        for range_cidr in authorized_ranges:
            self.logger.info(f"    * {range_cidr}")
        
        self.analysis_result["analysis"]["ipRangeRestriction"] = "enabled"
        self.analysis_result["analysis"]["rangeCount"] = len(authorized_ranges)
        
        # Add warning about authorized IP ranges being active
        self.analysis_result["securityFindings"].append({
            "severity": "warning",
            "issue": "API server access restricted",
            "description": f"API server has authorized IP ranges enabled with {len(authorized_ranges)} configured range(s). Only traffic from these IPs can access the API server.",
            "recommendation": "Verify all necessary IP ranges are included. Use --details to see the full list of authorized ranges."
        })
        
        # Analyze each range for security implications
        for range_cidr in authorized_ranges:
            self._analyze_ip_range_security(range_cidr)
    
    def _analyze_ip_range_security(self, range_cidr: str):
        """
        Analyze individual IP range for security implications
        
        Args:
            range_cidr: CIDR notation IP range to analyze
        """
        try:
            # Parse the CIDR range
            network = ipaddress.ip_network(range_cidr, strict=False)
            
            # Calculate range size
            num_addresses = network.num_addresses
            prefix_length = network.prefixlen
            
            # Security analysis based on range characteristics
            if range_cidr == "0.0.0.0/0":
                self.analysis_result["securityFindings"].append({
                    "severity": "critical",
                    "range": range_cidr,
                    "issue": "Complete unrestricted access",
                    "description": "0.0.0.0/0 allows access from any IP address on the internet",
                    "recommendation": "Replace with specific IP ranges or CIDR blocks for your organization"
                })
            elif prefix_length <= 8:  # /8 or larger (16M+ addresses)
                self.analysis_result["securityFindings"].append({
                    "severity": "high",
                    "range": range_cidr,
                    "issue": "Very broad IP range",
                    "description": f"Range contains {num_addresses:,} addresses (/{prefix_length})",
                    "recommendation": "Consider narrowing to more specific IP ranges"
                })
            elif prefix_length <= 16:  # /16 or larger (65K+ addresses)
                self.analysis_result["securityFindings"].append({
                    "severity": "medium",
                    "range": range_cidr,
                    "issue": "Broad IP range",
                    "description": f"Range contains {num_addresses:,} addresses (/{prefix_length})",
                    "recommendation": "Review if this broad range is necessary"
                })
            elif prefix_length >= 32:  # Single IP
                self.logger.debug(f"    [OK] Specific IP address: {range_cidr}")
            else:  # Reasonable range
                self.logger.debug(f"    [OK] Reasonable range: {range_cidr} ({num_addresses} addresses)")
            
            # Check for private IP ranges in authorized list
            if network.is_private:
                self.analysis_result["analysis"]["containsPrivateRanges"] = True
                self.logger.debug(f"    [NOTE] Private IP range detected: {range_cidr}")
            
        except Exception as e:
            self.analysis_result["securityFindings"].append({
                "severity": "warning",
                "range": range_cidr,
                "issue": "Invalid IP range format",
                "description": f"Could not parse IP range: {str(e)}",
                "recommendation": "Verify the CIDR notation is correct"
            })
    
    def _validate_api_security_configuration(self):
        """Validate API server security configuration"""
        # Check if run command is disabled
        disable_run_command = self.analysis_result["disableRunCommand"]
        if disable_run_command:
            self.logger.debug("  [OK] Run command is disabled (enhanced security)")
        else:
            self.logger.debug("  [NOTE] Run command is enabled")
        
        # Check private cluster configuration
        is_private = self.analysis_result["privateCluster"]
        authorized_ranges = self.analysis_result["authorizedIpRanges"]
        
        if is_private and authorized_ranges:
            self.analysis_result["securityFindings"].append({
                "severity": "info",
                "issue": "Redundant configuration",
                "description": "Both private cluster and authorized IP ranges are enabled",
                "recommendation": "Private clusters don't need authorized IP ranges since they're already isolated"
            })
        elif not is_private and not authorized_ranges:
            self.analysis_result["securityFindings"].append({
                "severity": "medium",
                "issue": "Unrestricted public access",
                "description": "API server is publicly accessible without IP restrictions",
                "recommendation": "Consider enabling authorized IP ranges or converting to a private cluster"
            })
    
    def _analyze_access_restrictions(self):
        """Analyze access restrictions and their implications"""
        authorized_ranges = self.analysis_result["authorizedIpRanges"]
        is_private = self.analysis_result["privateCluster"]
        
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
        
        self.analysis_result["accessRestrictions"] = {
            "model": access_model,
            "description": access_description,
            "implications": self._get_access_implications(access_model, authorized_ranges)
        }
    
    def _get_access_implications(self, access_model: str, authorized_ranges: List[str]) -> List[str]:
        """
        Get implications of the current access configuration
        
        Args:
            access_model: Type of access model (private, restricted_public, unrestricted_public)
            authorized_ranges: List of authorized IP ranges
            
        Returns:
            List of implication strings
        """
        implications = []
        
        if access_model == "private":
            implications.extend([
                "[OK] API server is isolated from the internet",
                "[OK] Access only from resources within the VNet or peered networks",
                "[NOTE] Requires VPN or ExpressRoute for external access",
                "[NOTE] Private DNS zone required for name resolution"
            ])
        elif access_model == "restricted_public":
            implications.extend([
                "[OK] API server access is restricted to specified IP ranges",
                "[!] API server is still exposed to the internet",
                "[NOTE] Users/services must access from authorized IP ranges",
                "[NOTE] Node-to-API traffic must originate from authorized ranges"
            ])
            
            # Check if outbound IPs are in authorized ranges
            if self.outbound_ips:
                outbound_implications = self._check_outbound_ip_authorization(authorized_ranges)
                implications.extend(outbound_implications)
                
        else:  # unrestricted_public
            implications.extend([
                "[!] API server is publicly accessible from any IP",
                "[!] No network-level access restrictions",
                "[NOTE] Security relies entirely on authentication and RBAC",
                "[NOTE] Consider implementing IP restrictions for enhanced security"
            ])
        
        return implications
    
    def _check_outbound_ip_authorization(self, authorized_ranges: List[str]) -> List[str]:
        """
        Check if cluster outbound IPs are included in authorized ranges
        
        Args:
            authorized_ranges: List of authorized IP ranges in CIDR notation
            
        Returns:
            List of implication strings related to outbound IP authorization
        """
        implications = []
        
        try:
            # Check if UDR overrides Load Balancer outbound
            udr_override = self._check_udr_override()
            
            if udr_override:
                # UDR scenario: Load Balancer IP is not used
                implications.append(
                    "[!] CRITICAL: User Defined Route (UDR) overrides Load Balancer outbound"
                )
                implications.append(
                    f"[!] Traffic is routed through virtual appliance: {udr_override['virtualApplianceIp']}"
                )
                implications.append(
                    "[!] The virtual appliance's PUBLIC IP must be in authorized ranges"
                )
                implications.append(
                    "[!] Load Balancer IPs are NOT effective due to UDR override"
                )
                implications.append(
                    "[!] Nodes cannot reach API server if firewall/appliance public IP is not authorized"
                )
                
                # Add critical security finding
                self.analysis_result["securityFindings"].append({
                    "severity": "critical",
                    "issue": "UDR overrides Load Balancer with authorized IP ranges enabled",
                    "description": f"Cluster uses User Defined Route (UDR) to route traffic through virtual appliance ({udr_override['virtualApplianceIp']}), which overrides the Load Balancer outbound. When authorized IP ranges are enabled, the virtual appliance's PUBLIC IP (not the Load Balancer IP) must be included in authorized ranges. Otherwise, nodes cannot reach the API server.",
                    "recommendation": f"IMMEDIATE ACTION REQUIRED: Add the public IP of the virtual appliance ({udr_override['virtualApplianceIp']}) to the authorized IP ranges. The Load Balancer IPs ({', '.join(self.outbound_ips)}) are not effective in this configuration."
                })
                
                return implications
            
            # Standard Load Balancer scenario (no UDR override)
            # Parse authorized ranges into ipaddress networks
            authorized_networks = []
            for range_cidr in authorized_ranges:
                try:
                    network = ipaddress.ip_network(range_cidr, strict=False)
                    authorized_networks.append(network)
                except Exception as e:
                    self.logger.debug(f"Could not parse authorized range {range_cidr}: {e}")
            
            # Check each outbound IP
            unauthorized_ips = []
            for ip_str in self.outbound_ips:
                # Handle IP ranges/prefixes in outbound_ips
                if '/' in ip_str or '(' in ip_str:
                    # Skip prefixes/ranges - just note them
                    implications.append(f"[NOTE] Outbound IP range detected: {ip_str}")
                    continue
                
                try:
                    ip = ipaddress.ip_address(ip_str)
                    is_authorized = any(ip in network for network in authorized_networks)
                    
                    if not is_authorized:
                        unauthorized_ips.append(ip_str)
                except Exception as e:
                    self.logger.debug(f"Could not parse outbound IP {ip_str}: {e}")
            
            # Report findings
            if unauthorized_ips:
                implications.append(
                    f"[NOTE] Outbound IP(s) not explicitly in authorized ranges: {', '.join(unauthorized_ips)}"
                )
                implications.append(
                    "[NOTE] AKS automatically allows cluster outbound IPs even if not explicitly listed"
                )
                
                # Add to security findings as informational (not critical)
                # Per AKS docs: cluster outbound IP is automatically allowed by default
                self.analysis_result["securityFindings"].append({
                    "severity": "info",
                    "issue": "Outbound IPs not explicitly in authorized ranges",
                    "description": f"Cluster outbound IPs ({', '.join(unauthorized_ips)}) are not explicitly listed in authorized IP ranges. However, AKS automatically allows the cluster's outbound IP by default when authorized IP ranges are enabled.",
                    "recommendation": "This is informational only. Consider explicitly adding outbound IPs to authorized ranges for clarity and documentation purposes."
                })
            else:
                if self.outbound_ips and authorized_networks:
                    implications.append(
                        f"[OK] All outbound IPs ({len(self.outbound_ips)}) are explicitly in authorized ranges"
                    )
        
        except Exception as e:
            self.logger.debug(f"Error checking outbound IP authorization: {e}")
            implications.append(f"[NOTE] Could not validate outbound IP authorization: {e}")
        
        return implications
    
    def _check_udr_override(self) -> Optional[Dict[str, str]]:
        """
        Check if User Defined Route overrides Load Balancer outbound
        
        Returns:
            Dictionary with UDR details if override detected, None otherwise
            Keys: 'virtualApplianceIp', 'routePrefix'
        """
        if not self.outbound_analysis:
            return None
        
        # Check outbound type
        outbound_type = self.outbound_analysis.get('type', '')
        if outbound_type != 'loadBalancer':
            return None
        
        # Check for UDR analysis
        udr_analysis = self.outbound_analysis.get('udrAnalysis', {})
        if not udr_analysis:
            return None
        
        # Look for virtual appliance routes that could override Load Balancer
        virtual_appliance_routes = udr_analysis.get('virtualApplianceRoutes', [])
        
        for route in virtual_appliance_routes:
            # Check if this is a default route (0.0.0.0/0) or broad route
            prefix = route.get('addressPrefix', '')
            next_hop = route.get('nextHopIpAddress', '')
            
            # Default route (0.0.0.0/0) or very broad routes override Load Balancer
            if prefix in ['0.0.0.0/0', '0.0.0.0/1', '128.0.0.0/1']:
                return {
                    'virtualApplianceIp': next_hop,
                    'routePrefix': prefix
                }
        
        return None
