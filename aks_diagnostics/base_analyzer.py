"""
Base class for analyzers
"""

import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, List
from .azure_cli import AzureCLIExecutor
from .models import Finding


class BaseAnalyzer(ABC):
    """Base class for all analyzers"""
    
    def __init__(self, azure_cli: AzureCLIExecutor, cluster_info: Dict[str, Any]):
        """
        Initialize analyzer
        
        Args:
            azure_cli: Azure CLI executor instance
            cluster_info: AKS cluster information
        """
        self.azure_cli = azure_cli
        self.cluster_info = cluster_info
        self.logger = logging.getLogger(f"aks_net_diagnostics.{self.__class__.__name__}")
        self.findings: List[Finding] = []
    
    @abstractmethod
    def analyze(self) -> Dict[str, Any]:
        """
        Perform analysis
        
        Returns:
            Analysis results as dictionary
        """
        pass
    
    def add_finding(self, finding: Finding):
        """Add a finding to the results"""
        self.findings.append(finding)
        # Map severity to appropriate log level and symbol
        if finding.severity.value in ['critical', 'error']:
            self.logger.error(f"Finding: [X] {finding.message}")
        elif finding.severity.value == 'warning':
            self.logger.warning(f"Finding: [!] {finding.message}")
        else:
            self.logger.info(f"Finding: [i] {finding.message}")
    
    def get_findings(self) -> List[Finding]:
        """Get all findings from this analyzer"""
        return self.findings
    
    def get_cluster_property(self, *keys: str, default: Any = None) -> Any:
        """
        Safely get nested property from cluster info
        
        Args:
            *keys: Nested keys to traverse
            default: Default value if key not found
            
        Returns:
            Value at the specified path or default
        """
        result = self.cluster_info
        for key in keys:
            if isinstance(result, dict):
                result = result.get(key)
            else:
                return default
            if result is None:
                return default
        return result
