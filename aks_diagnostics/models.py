"""
Data models for AKS diagnostics
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from enum import Enum


class Severity(Enum):
    """Finding severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    WARNING = "warning"
    INFO = "info"


class FindingCode(Enum):
    """Standardized finding codes"""
    CLUSTER_STOPPED = "CLUSTER_STOPPED"
    CLUSTER_OPERATION_FAILURE = "CLUSTER_OPERATION_FAILURE"
    DNS_RESOLUTION_FAILED = "DNS_RESOLUTION_FAILED"
    NSG_BLOCKING_TRAFFIC = "NSG_BLOCKING_TRAFFIC"
    UDR_CONFLICT = "UDR_CONFLICT"
    API_ACCESS_RESTRICTED = "API_ACCESS_RESTRICTED"
    PRIVATE_DNS_MISCONFIGURED = "PRIVATE_DNS_MISCONFIGURED"


@dataclass
class VMSSInstance:
    """Represents a VMSS instance eligible for connectivity testing."""
    vmss_name: str
    resource_group: str
    instance_id: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    """Represents a diagnostic finding"""
    severity: Severity
    code: FindingCode
    message: str
    recommendation: str
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "severity": self.severity.value,
            "code": self.code.value,
            "message": self.message,
            "recommendation": self.recommendation,
            "details": self.details
        }
    
    @classmethod
    def create_critical(cls, code: FindingCode, message: str, recommendation: str, **details):
        """Factory method for critical findings"""
        return cls(Severity.CRITICAL, code, message, recommendation, details)
    
    @classmethod
    def create_warning(cls, code: FindingCode, message: str, recommendation: str, **details):
        """Factory method for warning findings"""
        return cls(Severity.WARNING, code, message, recommendation, details)
    
    @classmethod
    def create_info(cls, code: FindingCode, message: str, recommendation: str, **details):
        """Factory method for info findings"""
        return cls(Severity.INFO, code, message, recommendation, details)


@dataclass
class DiagnosticResult:
    """Container for all diagnostic results"""
    cluster_info: Dict[str, Any]
    agent_pools: List[Dict[str, Any]]
    vnets_analysis: List[Dict[str, Any]]
    outbound_analysis: Dict[str, Any]
    nsg_analysis: Dict[str, Any]
    private_dns_analysis: Dict[str, Any]
    api_server_access_analysis: Dict[str, Any]
    vmss_analysis: List[Dict[str, Any]]
    findings: List[Finding]
    api_probe_results: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "cluster_info": self.cluster_info,
            "agent_pools": self.agent_pools,
            "vnets_analysis": self.vnets_analysis,
            "outbound_analysis": self.outbound_analysis,
            "nsg_analysis": self.nsg_analysis,
            "private_dns_analysis": self.private_dns_analysis,
            "api_server_access_analysis": self.api_server_access_analysis,
            "vmss_analysis": self.vmss_analysis,
            "findings": [f.to_dict() for f in self.findings],
            "api_probe_results": self.api_probe_results
        }
