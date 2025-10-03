"""
Unit tests for DNS Analyzer
"""

import unittest
from unittest.mock import Mock, patch
from aks_diagnostics.dns_analyzer import DNSAnalyzer
from aks_diagnostics.models import Finding, Severity


class TestDNSAnalyzer(unittest.TestCase):
    """Test cases for DNSAnalyzer class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.public_cluster_info = {
            "name": "test-cluster",
            "apiServerAccessProfile": {
                "enablePrivateCluster": False
            }
        }
        
        self.private_cluster_system_dns = {
            "name": "test-private-cluster",
            "apiServerAccessProfile": {
                "enablePrivateCluster": True,
                "privateDnsZone": "system"
            }
        }
        
        self.private_cluster_custom_dns = {
            "name": "test-private-cluster",
            "apiServerAccessProfile": {
                "enablePrivateCluster": True,
                "privateDnsZone": "/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.Network/privateDnsZones/privatelink.canadacentral.azmk8s.io"
            }
        }
        
        self.no_api_profile_cluster = {
            "name": "test-cluster"
        }
    
    def test_initialization(self):
        """Test DNSAnalyzer initialization"""
        analyzer = DNSAnalyzer(self.public_cluster_info)
        
        self.assertIsNotNone(analyzer.logger)
        self.assertEqual(analyzer.cluster_info, self.public_cluster_info)
        self.assertEqual(analyzer.dns_analysis, {})
        self.assertEqual(analyzer.findings, [])
    
    def test_public_cluster_analysis(self):
        """Test DNS analysis for public cluster"""
        analyzer = DNSAnalyzer(self.public_cluster_info)
        result = analyzer.analyze()
        
        self.assertEqual(result["type"], "none")
        self.assertFalse(result["isPrivateCluster"])
        self.assertIsNone(result["privateDnsZone"])
        self.assertIn("Public cluster", result["analysis"])
    
    def test_private_cluster_system_dns(self):
        """Test DNS analysis for private cluster with system-managed DNS"""
        analyzer = DNSAnalyzer(self.private_cluster_system_dns)
        result = analyzer.analyze()
        
        self.assertEqual(result["type"], "system")
        self.assertTrue(result["isPrivateCluster"])
        self.assertEqual(result["privateDnsZone"], "system")
        self.assertIn("System-managed", result["analysis"])
    
    def test_private_cluster_custom_dns(self):
        """Test DNS analysis for private cluster with custom DNS zone"""
        analyzer = DNSAnalyzer(self.private_cluster_custom_dns)
        result = analyzer.analyze()
        
        self.assertEqual(result["type"], "custom")
        self.assertTrue(result["isPrivateCluster"])
        self.assertIn("privatelink.canadacentral.azmk8s.io", result["privateDnsZone"])
        self.assertIn("Custom", result["analysis"])
        
        # Should have created an informational finding
        findings = analyzer.get_findings()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.INFO)
        self.assertIn("privatelink.canadacentral.azmk8s.io", findings[0].details.get("privateDnsZone", ""))
    
    def test_no_api_profile(self):
        """Test DNS analysis when API server profile is missing"""
        analyzer = DNSAnalyzer(self.no_api_profile_cluster)
        result = analyzer.analyze()
        
        self.assertEqual(result["type"], "none")
        self.assertFalse(result["isPrivateCluster"])
        self.assertIsNone(result["privateDnsZone"])
        self.assertIn("No API server access profile", result["analysis"])
    
    def test_validate_dns_with_private_ip(self):
        """Test DNS validation with private IP response"""
        analyzer = DNSAnalyzer(self.private_cluster_system_dns)
        
        nslookup_output = """Server:  dns-server.example.com
Address:  168.63.129.16

Non-authoritative answer:
Name:    test-api-server.privatelink.canadacentral.azmk8s.io
Address:  10.1.2.3
"""
        
        result = analyzer.validate_private_dns_resolution(nslookup_output, "test-api-server.privatelink.canadacentral.azmk8s.io")
        self.assertTrue(result)
        self.assertEqual(len(analyzer.get_findings()), 0)  # No findings for successful resolution
    
    def test_validate_dns_with_public_ip(self):
        """Test DNS validation with public IP response (should fail for private cluster)"""
        analyzer = DNSAnalyzer(self.private_cluster_system_dns)
        
        nslookup_output = """Server:  dns-server.example.com
Address:  168.63.129.16

Non-authoritative answer:
Name:    test-api-server.canadacentral.azmk8s.io
Address:  52.139.1.180
"""
        
        result = analyzer.validate_private_dns_resolution(nslookup_output, "test-api-server.canadacentral.azmk8s.io")
        self.assertFalse(result)
        
        # Should create a critical finding
        findings = analyzer.get_findings()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.CRITICAL)
        self.assertIn("52.139.1.180", str(findings[0].details))
    
    def test_validate_dns_resolution_failure(self):
        """Test DNS validation with resolution failure"""
        analyzer = DNSAnalyzer(self.private_cluster_system_dns)
        
        nslookup_output = """Server:  dns-server.example.com
Address:  168.63.129.16

** server can't find test-api-server.privatelink.canadacentral.azmk8s.io: NXDOMAIN
"""
        
        result = analyzer.validate_private_dns_resolution(nslookup_output, "test-api-server.privatelink.canadacentral.azmk8s.io")
        self.assertFalse(result)
    
    def test_validate_dns_timeout(self):
        """Test DNS validation with timeout"""
        analyzer = DNSAnalyzer(self.private_cluster_system_dns)
        
        nslookup_output = """;; connection timed out; no servers could be reached"""
        
        result = analyzer.validate_private_dns_resolution(nslookup_output, "test-api-server.privatelink.canadacentral.azmk8s.io")
        self.assertFalse(result)
    
    def test_validate_dns_servfail(self):
        """Test DNS validation with SERVFAIL response"""
        analyzer = DNSAnalyzer(self.private_cluster_system_dns)
        
        nslookup_output = """Server:  dns-server.example.com
Address:  168.63.129.16

** server can't find test-api-server.privatelink.canadacentral.azmk8s.io: SERVFAIL
"""
        
        result = analyzer.validate_private_dns_resolution(nslookup_output, "test-api-server.privatelink.canadacentral.azmk8s.io")
        self.assertFalse(result)
    
    def test_validate_dns_no_ips_found(self):
        """Test DNS validation with no IP addresses in response"""
        analyzer = DNSAnalyzer(self.private_cluster_system_dns)
        
        nslookup_output = """Server:  dns-server.example.com
Address:  168.63.129.16

No answer received
"""
        
        result = analyzer.validate_private_dns_resolution(nslookup_output, "test-api-server.privatelink.canadacentral.azmk8s.io")
        self.assertFalse(result)
    
    def test_validate_dns_multiple_private_ips(self):
        """Test DNS validation with multiple private IPs"""
        analyzer = DNSAnalyzer(self.private_cluster_system_dns)
        
        nslookup_output = """Server:  dns-server.example.com
Address:  168.63.129.16

Non-authoritative answer:
Name:    test-api-server.privatelink.canadacentral.azmk8s.io
Addresses:  10.1.2.3
           10.1.2.4
           10.1.2.5
"""
        
        result = analyzer.validate_private_dns_resolution(nslookup_output, "test-api-server.privatelink.canadacentral.azmk8s.io")
        self.assertTrue(result)
    
    def test_validate_dns_compacted_format(self):
        """Test DNS validation with compacted format (\\n instead of newlines)"""
        analyzer = DNSAnalyzer(self.private_cluster_system_dns)
        
        nslookup_output = "Server:  dns-server.example.com\\nAddress:  168.63.129.16\\n\\nNon-authoritative answer:\\nName:    test-api-server.privatelink.canadacentral.azmk8s.io\\nAddress:  10.1.2.3"
        
        result = analyzer.validate_private_dns_resolution(nslookup_output, "test-api-server.privatelink.canadacentral.azmk8s.io")
        self.assertTrue(result)
    
    def test_validate_dns_with_172_private_range(self):
        """Test DNS validation with 172.16.0.0/12 private IP range"""
        analyzer = DNSAnalyzer(self.private_cluster_system_dns)
        
        nslookup_output = """Server:  dns-server.example.com
Address:  168.63.129.16

Non-authoritative answer:
Name:    test-api-server.privatelink.canadacentral.azmk8s.io
Address:  172.18.5.100
"""
        
        result = analyzer.validate_private_dns_resolution(nslookup_output, "test-api-server.privatelink.canadacentral.azmk8s.io")
        self.assertTrue(result)
    
    def test_validate_dns_with_192_private_range(self):
        """Test DNS validation with 192.168.0.0/16 private IP range"""
        analyzer = DNSAnalyzer(self.private_cluster_system_dns)
        
        nslookup_output = """Server:  dns-server.example.com
Address:  168.63.129.16

Non-authoritative answer:
Name:    test-api-server.privatelink.canadacentral.azmk8s.io
Address:  192.168.10.50
"""
        
        result = analyzer.validate_private_dns_resolution(nslookup_output, "test-api-server.privatelink.canadacentral.azmk8s.io")
        self.assertTrue(result)
    
    def test_validate_dns_exception_handling(self):
        """Test DNS validation with malformed output that causes exceptions"""
        analyzer = DNSAnalyzer(self.private_cluster_system_dns)
        
        # This should not crash even with unexpected input
        result = analyzer.validate_private_dns_resolution("", "test-hostname")
        self.assertIsInstance(result, bool)
    
    def test_get_findings_empty(self):
        """Test getting findings when none exist"""
        analyzer = DNSAnalyzer(self.public_cluster_info)
        analyzer.analyze()
        
        findings = analyzer.get_findings()
        self.assertEqual(len(findings), 0)
    
    def test_get_findings_with_custom_dns(self):
        """Test getting findings for custom DNS configuration"""
        analyzer = DNSAnalyzer(self.private_cluster_custom_dns)
        analyzer.analyze()
        
        findings = analyzer.get_findings()
        self.assertGreater(len(findings), 0)
        self.assertTrue(all(isinstance(f, Finding) for f in findings))


if __name__ == '__main__':
    unittest.main()
