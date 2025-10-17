"""
Unit tests for API Server Access Analyzer
"""

import unittest
from unittest.mock import MagicMock

from aks_diagnostics.api_server_analyzer import APIServerAccessAnalyzer


class TestAPIServerAccessAnalyzer(unittest.TestCase):
    """Test cases for APIServerAccessAnalyzer"""

    def setUp(self):
        """Set up test fixtures"""
        self.base_cluster_info = {"name": "test-cluster", "location": "eastus"}

    def test_no_api_server_profile(self):
        """Test analysis when no API server profile exists"""
        analyzer = APIServerAccessAnalyzer(self.base_cluster_info)
        result = analyzer.analyze()

        self.assertFalse(result["privateCluster"])
        self.assertEqual(result["authorizedIpRanges"], [])
        self.assertFalse(result["disableRunCommand"])
        self.assertEqual(result["analysis"]["ipRangeRestriction"], "none")
        self.assertEqual(len(result["securityFindings"]), 0)

    def test_private_cluster(self):
        """Test analysis of private cluster"""
        cluster_info = {
            **self.base_cluster_info,
            "apiServerAccessProfile": {"enablePrivateCluster": True, "disableRunCommand": True},
        }

        analyzer = APIServerAccessAnalyzer(cluster_info)
        result = analyzer.analyze()

        self.assertTrue(result["privateCluster"])
        self.assertTrue(result["disableRunCommand"])
        self.assertEqual(result["accessRestrictions"]["model"], "private")
        self.assertIn(
            "API server is isolated from the internet", " ".join(result["accessRestrictions"]["implications"])
        )

    def test_unrestricted_public_cluster(self):
        """Test analysis of unrestricted public cluster"""
        cluster_info = {
            **self.base_cluster_info,
            "apiServerAccessProfile": {"enablePrivateCluster": False, "authorizedIpRanges": []},
        }

        analyzer = APIServerAccessAnalyzer(cluster_info)
        result = analyzer.analyze()

        self.assertFalse(result["privateCluster"])
        self.assertEqual(len(result["authorizedIpRanges"]), 0)
        self.assertEqual(result["accessRestrictions"]["model"], "unrestricted_public")

        # Should have security finding about unrestricted access
        security_findings = [f for f in result["securityFindings"] if f["issue"] == "Unrestricted public access"]
        self.assertEqual(len(security_findings), 1)
        self.assertEqual(security_findings[0]["severity"], "medium")

    def test_restricted_public_cluster(self):
        """Test analysis of public cluster with IP restrictions"""
        cluster_info = {
            **self.base_cluster_info,
            "apiServerAccessProfile": {
                "enablePrivateCluster": False,
                "authorizedIpRanges": ["203.0.113.0/24", "198.51.100.10/32"],
            },
        }

        analyzer = APIServerAccessAnalyzer(cluster_info)
        result = analyzer.analyze()

        self.assertFalse(result["privateCluster"])
        self.assertEqual(len(result["authorizedIpRanges"]), 2)
        self.assertEqual(result["analysis"]["ipRangeRestriction"], "enabled")
        self.assertEqual(result["analysis"]["rangeCount"], 2)
        self.assertEqual(result["accessRestrictions"]["model"], "restricted_public")

        # Should have warning about authorized IP ranges being active
        warning_findings = [
            f
            for f in result["securityFindings"]
            if f["severity"] == "warning" and "API server access restricted" in f["issue"]
        ]
        self.assertEqual(len(warning_findings), 1)
        self.assertIn("2 configured range(s)", warning_findings[0]["description"])

    def test_wildcard_ip_range_critical(self):
        """Test detection of 0.0.0.0/0 as critical security issue"""
        cluster_info = {
            **self.base_cluster_info,
            "apiServerAccessProfile": {"enablePrivateCluster": False, "authorizedIpRanges": ["0.0.0.0/0"]},
        }

        analyzer = APIServerAccessAnalyzer(cluster_info)
        result = analyzer.analyze()

        # Should have critical finding for 0.0.0.0/0
        critical_findings = [f for f in result["securityFindings"] if f["severity"] == "critical"]
        self.assertEqual(len(critical_findings), 1)
        self.assertEqual(critical_findings[0]["range"], "0.0.0.0/0")
        self.assertIn("unrestricted access", critical_findings[0]["issue"].lower())

    def test_very_broad_ip_range_high_severity(self):
        """Test detection of very broad IP ranges (/8) as high severity"""
        cluster_info = {
            **self.base_cluster_info,
            "apiServerAccessProfile": {"enablePrivateCluster": False, "authorizedIpRanges": ["10.0.0.0/8"]},
        }

        analyzer = APIServerAccessAnalyzer(cluster_info)
        result = analyzer.analyze()

        # Should have high severity finding for /8
        high_findings = [f for f in result["securityFindings"] if f["severity"] == "high"]
        self.assertEqual(len(high_findings), 1)
        self.assertEqual(high_findings[0]["range"], "10.0.0.0/8")
        self.assertIn("Very broad IP range", high_findings[0]["issue"])

    def test_broad_ip_range_medium_severity(self):
        """Test detection of broad IP ranges (/16) as medium severity"""
        cluster_info = {
            **self.base_cluster_info,
            "apiServerAccessProfile": {"enablePrivateCluster": False, "authorizedIpRanges": ["172.16.0.0/16"]},
        }

        analyzer = APIServerAccessAnalyzer(cluster_info)
        result = analyzer.analyze()

        # Should have medium severity finding for /16
        medium_findings = [f for f in result["securityFindings"] if f["severity"] == "medium" and "range" in f]
        self.assertEqual(len(medium_findings), 1)
        self.assertEqual(medium_findings[0]["range"], "172.16.0.0/16")
        self.assertIn("Broad IP range", medium_findings[0]["issue"])

    def test_private_ip_range_detection(self):
        """Test detection of private IP ranges"""
        cluster_info = {
            **self.base_cluster_info,
            "apiServerAccessProfile": {
                "enablePrivateCluster": False,
                "authorizedIpRanges": ["10.0.0.0/24", "192.168.1.0/24"],
            },
        }

        analyzer = APIServerAccessAnalyzer(cluster_info)
        result = analyzer.analyze()

        # Should detect private ranges
        self.assertTrue(result["analysis"].get("containsPrivateRanges", False))

    def test_invalid_ip_range_format(self):
        """Test handling of invalid IP range format"""
        cluster_info = {
            **self.base_cluster_info,
            "apiServerAccessProfile": {
                "enablePrivateCluster": False,
                "authorizedIpRanges": ["invalid-ip-range", "256.256.256.256/32"],
            },
        }

        analyzer = APIServerAccessAnalyzer(cluster_info)
        result = analyzer.analyze()

        # Should have warning findings for invalid ranges
        warning_findings = [f for f in result["securityFindings"] if f["severity"] == "warning"]
        self.assertGreaterEqual(len(warning_findings), 1)

    def test_private_cluster_with_authorized_ranges(self):
        """Test detection of redundant configuration"""
        cluster_info = {
            **self.base_cluster_info,
            "apiServerAccessProfile": {"enablePrivateCluster": True, "authorizedIpRanges": ["203.0.113.0/24"]},
        }

        analyzer = APIServerAccessAnalyzer(cluster_info)
        result = analyzer.analyze()

        # Should have info finding about redundant config
        info_findings = [f for f in result["securityFindings"] if f["severity"] == "info"]
        self.assertEqual(len(info_findings), 1)
        self.assertIn("Redundant", info_findings[0]["issue"])

    def test_outbound_ip_in_authorized_ranges(self):
        """Test checking if outbound IPs are in authorized ranges"""
        cluster_info = {
            **self.base_cluster_info,
            "apiServerAccessProfile": {"enablePrivateCluster": False, "authorizedIpRanges": ["203.0.113.0/24"]},
        }

        outbound_ips = ["203.0.113.50", "203.0.113.100"]
        analyzer = APIServerAccessAnalyzer(cluster_info, outbound_ips)
        result = analyzer.analyze()

        implications = result["accessRestrictions"]["implications"]
        # Should confirm outbound IPs are authorized
        authorized_message = [imp for imp in implications if "All outbound IPs" in imp and "[OK]" in imp]
        self.assertEqual(len(authorized_message), 1)

    def test_outbound_ip_not_in_authorized_ranges(self):
        """Test detection when outbound IPs are NOT explicitly in authorized ranges"""
        cluster_info = {
            **self.base_cluster_info,
            "apiServerAccessProfile": {"enablePrivateCluster": False, "authorizedIpRanges": ["203.0.113.0/24"]},
        }

        outbound_ips = ["198.51.100.50"]  # Not in authorized range
        analyzer = APIServerAccessAnalyzer(cluster_info, outbound_ips)
        result = analyzer.analyze()

        implications = result["accessRestrictions"]["implications"]
        # Should note that IPs are not explicitly listed (but AKS allows them automatically)
        unauthorized_message = [imp for imp in implications if "not explicitly in authorized ranges" in imp]
        self.assertEqual(len(unauthorized_message), 1)
        self.assertIn("198.51.100.50", unauthorized_message[0])

        # Should have informational finding (not critical) since AKS auto-allows outbound IPs
        info_findings = [
            f
            for f in result["securityFindings"]
            if f["severity"] == "info" and "not explicitly in authorized ranges" in f["issue"]
        ]
        self.assertEqual(len(info_findings), 1)

    def test_multiple_outbound_ips_mixed_authorization(self):
        """Test with some authorized and some unauthorized outbound IPs"""
        cluster_info = {
            **self.base_cluster_info,
            "apiServerAccessProfile": {
                "enablePrivateCluster": False,
                "authorizedIpRanges": ["203.0.113.0/24", "198.51.100.0/28"],
            },
        }

        outbound_ips = ["203.0.113.50", "192.0.2.100"]  # First OK, second not explicitly listed
        analyzer = APIServerAccessAnalyzer(cluster_info, outbound_ips)
        result = analyzer.analyze()

        implications = result["accessRestrictions"]["implications"]
        # Should note the IP not explicitly in ranges
        unauthorized_message = [imp for imp in implications if "not explicitly in authorized ranges" in imp]
        self.assertEqual(len(unauthorized_message), 1)
        self.assertIn("192.0.2.100", unauthorized_message[0])
        self.assertNotIn("203.0.113.50", unauthorized_message[0])

    def test_specific_single_ip_authorized(self):
        """Test /32 (single IP) in authorized ranges"""
        cluster_info = {
            **self.base_cluster_info,
            "apiServerAccessProfile": {"enablePrivateCluster": False, "authorizedIpRanges": ["203.0.113.50/32"]},
        }

        analyzer = APIServerAccessAnalyzer(cluster_info)
        result = analyzer.analyze()

        # /32 is specific, should not generate security finding
        range_findings = [f for f in result["securityFindings"] if "range" in f and f["range"] == "203.0.113.50/32"]
        self.assertEqual(len(range_findings), 0)

    def test_run_command_disabled(self):
        """Test when run command is disabled"""
        cluster_info = {
            **self.base_cluster_info,
            "apiServerAccessProfile": {"enablePrivateCluster": False, "disableRunCommand": True},
        }

        analyzer = APIServerAccessAnalyzer(cluster_info)
        result = analyzer.analyze()

        self.assertTrue(result["disableRunCommand"])

    def test_run_command_enabled(self):
        """Test when run command is enabled"""
        cluster_info = {
            **self.base_cluster_info,
            "apiServerAccessProfile": {"enablePrivateCluster": False, "disableRunCommand": False},
        }

        analyzer = APIServerAccessAnalyzer(cluster_info)
        result = analyzer.analyze()

        self.assertFalse(result["disableRunCommand"])

    def test_outbound_ip_range_in_list(self):
        """Test handling of outbound IP ranges/prefixes"""
        cluster_info = {
            **self.base_cluster_info,
            "apiServerAccessProfile": {"enablePrivateCluster": False, "authorizedIpRanges": ["203.0.113.0/24"]},
        }

        outbound_ips = ["203.0.113.0/28 (range)"]  # IP range
        analyzer = APIServerAccessAnalyzer(cluster_info, outbound_ips)
        result = analyzer.analyze()

        implications = result["accessRestrictions"]["implications"]
        # Should note the IP range
        range_message = [imp for imp in implications if "Outbound IP range detected" in imp]
        self.assertEqual(len(range_message), 1)

    def test_empty_outbound_ips(self):
        """Test with empty outbound IPs list"""
        cluster_info = {
            **self.base_cluster_info,
            "apiServerAccessProfile": {"enablePrivateCluster": False, "authorizedIpRanges": ["203.0.113.0/24"]},
        }

        analyzer = APIServerAccessAnalyzer(cluster_info, [])
        result = analyzer.analyze()

        # Should not crash, just not check outbound IPs
        self.assertIsNotNone(result["accessRestrictions"])

    def test_access_implications_private_cluster(self):
        """Test implications for private cluster"""
        cluster_info = {**self.base_cluster_info, "apiServerAccessProfile": {"enablePrivateCluster": True}}

        analyzer = APIServerAccessAnalyzer(cluster_info)
        result = analyzer.analyze()

        implications = result["accessRestrictions"]["implications"]

        # Check for expected implications
        self.assertTrue(any("isolated from the internet" in imp for imp in implications))
        self.assertTrue(any("VNet or peered networks" in imp for imp in implications))
        self.assertTrue(any("VPN or ExpressRoute" in imp for imp in implications))
        self.assertTrue(any("Private DNS zone" in imp for imp in implications))

    def test_access_implications_unrestricted_public(self):
        """Test implications for unrestricted public cluster"""
        cluster_info = {
            **self.base_cluster_info,
            "apiServerAccessProfile": {"enablePrivateCluster": False, "authorizedIpRanges": []},
        }

        analyzer = APIServerAccessAnalyzer(cluster_info)
        result = analyzer.analyze()

        implications = result["accessRestrictions"]["implications"]

        # Check for expected warnings
        self.assertTrue(any("publicly accessible from any IP" in imp for imp in implications))
        self.assertTrue(any("No network-level access restrictions" in imp for imp in implications))
        self.assertTrue(any("authentication and RBAC" in imp for imp in implications))

    def test_udr_override_with_authorized_ranges(self):
        """Test detection of UDR override scenario with authorized IP ranges"""
        cluster_info = {
            **self.base_cluster_info,
            "apiServerAccessProfile": {"enablePrivateCluster": False, "authorizedIpRanges": ["45.65.190.26/32"]},
        }

        outbound_ips = ["4.229.176.97"]

        outbound_analysis = {
            "type": "loadBalancer",
            "udrAnalysis": {
                "virtualApplianceRoutes": [
                    {"addressPrefix": "0.0.0.0/0", "nextHopIpAddress": "10.0.1.4", "nextHopType": "VirtualAppliance"}
                ]
            },
        }

        analyzer = APIServerAccessAnalyzer(cluster_info, outbound_ips, outbound_analysis)
        result = analyzer.analyze()

        implications = result["accessRestrictions"]["implications"]
        security_findings = result["securityFindings"]

        # Check for UDR override detection
        self.assertTrue(any("CRITICAL" in imp and "User Defined Route (UDR)" in imp for imp in implications))
        self.assertTrue(any("virtual appliance: 10.0.1.4" in imp for imp in implications))
        self.assertTrue(any("PUBLIC IP must be in authorized ranges" in imp for imp in implications))
        self.assertTrue(any("Load Balancer IPs are NOT effective" in imp for imp in implications))
        self.assertTrue(any("Nodes cannot reach API server" in imp for imp in implications))

        # Check for critical security finding
        critical_findings = [f for f in security_findings if f["severity"] == "critical"]
        self.assertEqual(len(critical_findings), 1)
        self.assertIn("UDR overrides Load Balancer", critical_findings[0]["issue"])
        self.assertIn("10.0.1.4", critical_findings[0]["description"])
        self.assertIn("4.229.176.97", critical_findings[0]["recommendation"])

    def test_udr_no_override_scenario(self):
        """Test that normal UDR scenarios don't trigger false positives"""
        cluster_info = {
            **self.base_cluster_info,
            "apiServerAccessProfile": {
                "enablePrivateCluster": False,
                "authorizedIpRanges": ["45.65.190.26/32", "52.139.1.0/24"],
            },
        }

        outbound_ips = ["52.139.1.180"]

        # UDR with specific routes, not default route
        outbound_analysis = {
            "type": "loadBalancer",
            "udrAnalysis": {
                "virtualApplianceRoutes": [
                    {"addressPrefix": "10.0.0.0/8", "nextHopIpAddress": "10.0.1.4", "nextHopType": "VirtualAppliance"}
                ]
            },
        }

        analyzer = APIServerAccessAnalyzer(cluster_info, outbound_ips, outbound_analysis)
        result = analyzer.analyze()

        implications = result["accessRestrictions"]["implications"]
        security_findings = result["securityFindings"]

        # Should NOT have UDR override critical warning (because it's not a default route)
        self.assertFalse(any("CRITICAL" in imp and "User Defined Route (UDR)" in imp for imp in implications))

        # Should NOT have critical security finding about UDR override
        critical_findings = [f for f in security_findings if f["severity"] == "critical"]
        self.assertEqual(len(critical_findings), 0)

        # But should show that IPs are in authorized ranges
        self.assertTrue(any("explicitly in authorized ranges" in imp for imp in implications))


if __name__ == "__main__":
    unittest.main()
