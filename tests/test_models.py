"""
Unit tests for models module
"""

import unittest
from aks_diagnostics.models import (
    VMSSInstance, Finding, DiagnosticResult, 
    Severity, FindingCode
)


class TestVMSSInstance(unittest.TestCase):
    """Test VMSSInstance dataclass"""
    
    def test_creation(self):
        """Test VMSSInstance creation"""
        instance = VMSSInstance(
            vmss_name='aks-nodepool1-vmss',
            resource_group='MC_test_rg',
            instance_id='0',
            metadata={'zone': '1'}
        )
        
        self.assertEqual(instance.vmss_name, 'aks-nodepool1-vmss')
        self.assertEqual(instance.resource_group, 'MC_test_rg')
        self.assertEqual(instance.instance_id, '0')
        self.assertEqual(instance.metadata, {'zone': '1'})
    
    def test_default_metadata(self):
        """Test default metadata is empty dict"""
        instance = VMSSInstance(
            vmss_name='test',
            resource_group='rg',
            instance_id='0'
        )
        
        self.assertEqual(instance.metadata, {})


class TestFinding(unittest.TestCase):
    """Test Finding dataclass"""
    
    def test_creation(self):
        """Test Finding creation"""
        finding = Finding(
            severity=Severity.CRITICAL,
            code=FindingCode.CLUSTER_STOPPED,
            message='Cluster is stopped',
            recommendation='Start the cluster',
            details={'state': 'Stopped'}
        )
        
        self.assertEqual(finding.severity, Severity.CRITICAL)
        self.assertEqual(finding.code, FindingCode.CLUSTER_STOPPED)
        self.assertEqual(finding.message, 'Cluster is stopped')
        self.assertEqual(finding.recommendation, 'Start the cluster')
        self.assertEqual(finding.details, {'state': 'Stopped'})
    
    def test_to_dict(self):
        """Test conversion to dictionary"""
        finding = Finding(
            severity=Severity.WARNING,
            code=FindingCode.UDR_CONFLICT,
            message='UDR conflict detected',
            recommendation='Review routing',
            details={'route': '0.0.0.0/0'}
        )
        
        result = finding.to_dict()
        
        self.assertEqual(result['severity'], 'warning')
        self.assertEqual(result['code'], 'UDR_CONFLICT')
        self.assertEqual(result['message'], 'UDR conflict detected')
        self.assertEqual(result['recommendation'], 'Review routing')
        self.assertEqual(result['details'], {'route': '0.0.0.0/0'})
    
    def test_factory_methods(self):
        """Test factory methods"""
        critical = Finding.create_critical(
            FindingCode.CLUSTER_OPERATION_FAILURE,
            'Critical error',
            'Fix immediately'
        )
        self.assertEqual(critical.severity, Severity.CRITICAL)
        
        warning = Finding.create_warning(
            FindingCode.NSG_BLOCKING_TRAFFIC,
            'Warning message',
            'Review NSG rules'
        )
        self.assertEqual(warning.severity, Severity.WARNING)
        
        info = Finding.create_info(
            FindingCode.API_ACCESS_RESTRICTED,
            'Info message',
            'No action needed'
        )
        self.assertEqual(info.severity, Severity.INFO)


class TestDiagnosticResult(unittest.TestCase):
    """Test DiagnosticResult dataclass"""
    
    def test_creation(self):
        """Test DiagnosticResult creation"""
        result = DiagnosticResult(
            cluster_info={'name': 'test-cluster'},
            agent_pools=[{'name': 'nodepool1'}],
            vnets_analysis=[],
            outbound_analysis={},
            nsg_analysis={},
            private_dns_analysis={},
            api_server_access_analysis={},
            vmss_analysis=[],
            findings=[]
        )
        
        self.assertEqual(result.cluster_info, {'name': 'test-cluster'})
        self.assertEqual(len(result.agent_pools), 1)
        self.assertEqual(result.findings, [])
    
    def test_to_dict(self):
        """Test conversion to dictionary"""
        finding = Finding.create_warning(
            FindingCode.UDR_CONFLICT,
            'Test finding',
            'Test recommendation'
        )
        
        result = DiagnosticResult(
            cluster_info={'name': 'test'},
            agent_pools=[],
            vnets_analysis=[],
            outbound_analysis={},
            nsg_analysis={},
            private_dns_analysis={},
            api_server_access_analysis={},
            vmss_analysis=[],
            findings=[finding],
            api_probe_results={'status': 'success'}
        )
        
        result_dict = result.to_dict()
        
        self.assertEqual(result_dict['cluster_info'], {'name': 'test'})
        self.assertEqual(len(result_dict['findings']), 1)
        self.assertEqual(result_dict['findings'][0]['severity'], 'warning')
        self.assertEqual(result_dict['api_probe_results'], {'status': 'success'})


if __name__ == '__main__':
    unittest.main()
