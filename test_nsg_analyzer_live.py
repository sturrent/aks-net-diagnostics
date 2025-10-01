"""
Live test script for NSG Analyzer with real AKS cluster.
Tests the NSG analyzer against an actual Azure environment.
"""

import json
import sys
from pathlib import Path
from aks_diagnostics.azure_cli import AzureCLIExecutor
from aks_diagnostics.cache import CacheManager
from aks_diagnostics.nsg_analyzer import NSGAnalyzer


def get_cluster_info(azure_cli, cluster_name, resource_group):
    """Get AKS cluster information."""
    print(f"📋 Fetching cluster info for {cluster_name}...")
    cluster_info = azure_cli.execute([
        'aks', 'show',
        '--name', cluster_name,
        '--resource-group', resource_group
    ])
    
    if not cluster_info:
        raise ValueError(f"Cluster {cluster_name} not found")
    
    print(f"   ✓ Cluster: {cluster_info.get('name')}")
    print(f"   ✓ Location: {cluster_info.get('location')}")
    print(f"   ✓ Provisioning State: {cluster_info.get('provisioningState')}")
    
    # Check if private cluster
    api_profile = cluster_info.get('apiServerAccessProfile', {}) or {}
    is_private = api_profile.get('enablePrivateCluster', False)
    print(f"   ✓ Cluster Type: {'Private' if is_private else 'Public'}")
    
    return cluster_info


def get_vmss_info(azure_cli, cluster_info):
    """Get VMSS information from node resource group."""
    node_rg = cluster_info.get('nodeResourceGroup')
    if not node_rg:
        print("   ⚠ No node resource group found")
        return []
    
    print(f"\n🖥️  Fetching VMSS info from {node_rg}...")
    
    vmss_list = azure_cli.execute([
        'vmss', 'list',
        '--resource-group', node_rg
    ])
    
    if not vmss_list:
        print("   ⚠ No VMSS found")
        return []
    
    vmss_info = []
    for vmss in vmss_list:
        vmss_name = vmss.get('name')
        print(f"   ✓ Found VMSS: {vmss_name}")
        
        # Get detailed VMSS info
        vmss_details = azure_cli.execute([
            'vmss', 'show',
            '--name', vmss_name,
            '--resource-group', node_rg
        ])
        
        if vmss_details:
            vmss_info.append(vmss_details)
    
    return vmss_info


def print_nsg_summary(nsg_analysis):
    """Print a summary of NSG analysis results."""
    print("\n" + "="*80)
    print("📊 NSG ANALYSIS SUMMARY")
    print("="*80)
    
    # Subnet NSGs
    subnet_nsgs = nsg_analysis.get('subnetNsgs', [])
    print(f"\n🔒 Subnet NSGs: {len(subnet_nsgs)}")
    for nsg in subnet_nsgs:
        print(f"   • {nsg['nsgName']} on {nsg['subnetName']}")
        print(f"     - Custom Rules: {len(nsg.get('rules', []))}")
        print(f"     - Default Rules: {len(nsg.get('defaultRules', []))}")
    
    # NIC NSGs
    nic_nsgs = nsg_analysis.get('nicNsgs', [])
    print(f"\n🔌 NIC NSGs: {len(nic_nsgs)}")
    for nsg in nic_nsgs:
        print(f"   • {nsg['nsgName']} on VMSS {nsg['vmssName']}")
        print(f"     - Custom Rules: {len(nsg.get('rules', []))}")
        print(f"     - Default Rules: {len(nsg.get('defaultRules', []))}")
    
    # Required Rules
    required_rules = nsg_analysis.get('requiredRules', {})
    print(f"\n✅ Required AKS Rules:")
    print(f"   • Outbound: {len(required_rules.get('outbound', []))} rules")
    for rule in required_rules.get('outbound', []):
        print(f"     - {rule['name']}: {rule['description']}")
    print(f"   • Inbound: {len(required_rules.get('inbound', []))} rules")
    for rule in required_rules.get('inbound', []):
        print(f"     - {rule['name']}: {rule['description']}")
    
    # Blocking Rules
    blocking_rules = nsg_analysis.get('blockingRules', [])
    if blocking_rules:
        print(f"\n⚠️  Blocking Rules: {len(blocking_rules)}")
        for rule in blocking_rules:
            severity_icon = "🔴" if rule['effectiveSeverity'] == 'critical' else "🟡"
            override_text = " (OVERRIDDEN)" if rule['isOverridden'] else ""
            print(f"   {severity_icon} {rule['ruleName']} in {rule['nsgName']}{override_text}")
            print(f"      Priority: {rule['priority']} | Direction: {rule['direction']}")
            print(f"      Protocol: {rule['protocol']} | Destination: {rule['destination']}")
            print(f"      Ports: {rule['ports']}")
            print(f"      Impact: {rule['impact']}")
            if rule['isOverridden']:
                print(f"      Overridden by: {', '.join([r['ruleName'] for r in rule['overriddenBy']])}")
    else:
        print(f"\n✅ No blocking rules detected")
    
    # Inter-node Communication
    inter_node = nsg_analysis.get('interNodeCommunication', {})
    status = inter_node.get('status', 'unknown')
    issues = inter_node.get('issues', [])
    
    print(f"\n🔄 Inter-node Communication: {status.upper()}")
    if issues:
        print(f"   ⚠️  {len(issues)} potential issue(s) found:")
        for issue in issues:
            print(f"   • NSG: {issue['nsgName']} ({issue['location']})")
            print(f"     Blocking Rules: {len(issue['blockingRules'])}")
            for rule in issue['blockingRules']:
                print(f"       - {rule['ruleName']} (priority {rule['priority']})")


def print_findings(findings):
    """Print diagnostic findings."""
    if not findings:
        print("\n✅ No issues found!")
        return
    
    print("\n" + "="*80)
    print("🔍 DIAGNOSTIC FINDINGS")
    print("="*80)
    
    # Group by severity
    by_severity = {}
    for finding in findings:
        severity = finding.severity.value
        if severity not in by_severity:
            by_severity[severity] = []
        by_severity[severity].append(finding)
    
    severity_icons = {
        'critical': '🔴',
        'high': '🟠',
        'warning': '🟡',
        'info': 'ℹ️'
    }
    
    for severity in ['critical', 'high', 'warning', 'info']:
        findings_list = by_severity.get(severity, [])
        if findings_list:
            icon = severity_icons.get(severity, '•')
            print(f"\n{icon} {severity.upper()} ({len(findings_list)}):")
            for finding in findings_list:
                print(f"   • [{finding.code.value}] {finding.message}")
                print(f"     Recommendation: {finding.recommendation}")


def main():
    """Main test function."""
    # Configuration
    cluster_name = "aks-overlay"
    resource_group = "aks-overlay-rg"
    
    print("="*80)
    print("🧪 NSG ANALYZER LIVE TEST")
    print("="*80)
    print(f"Cluster: {cluster_name}")
    print(f"Resource Group: {resource_group}")
    print()
    
    try:
        # Initialize components
        print("🔧 Initializing Azure CLI executor...")
        cache_manager = CacheManager(cache_dir=Path(".aks_cache"), default_ttl=3600, enabled=True)
        azure_cli = AzureCLIExecutor(cache_manager=cache_manager)
        
        # Check prerequisites
        print("🔍 Checking Azure CLI prerequisites...")
        azure_cli.check_prerequisites()
        print("   ✓ Azure CLI available")
        
        # Get cluster info
        cluster_info = get_cluster_info(azure_cli, cluster_name, resource_group)
        
        # Get VMSS info
        vmss_info = get_vmss_info(azure_cli, cluster_info)
        
        if not vmss_info:
            print("\n⚠️  No VMSS found - cannot analyze NSGs without node information")
            return 1
        
        # Create and run NSG analyzer
        print("\n🔍 Running NSG analysis...")
        nsg_analyzer = NSGAnalyzer(azure_cli, cluster_info, vmss_info)
        nsg_analysis = nsg_analyzer.analyze()
        
        # Print results
        print_nsg_summary(nsg_analysis)
        print_findings(nsg_analyzer.get_findings())
        
        # Save detailed results to file
        output_file = f"nsg_analysis_{cluster_name}.json"
        print(f"\n💾 Saving detailed results to {output_file}...")
        
        api_profile = cluster_info.get('apiServerAccessProfile', {}) or {}
        with open(output_file, 'w') as f:
            json.dump({
                'cluster_info': {
                    'name': cluster_info.get('name'),
                    'resourceGroup': cluster_info.get('resourceGroup'),
                    'location': cluster_info.get('location'),
                    'isPrivate': api_profile.get('enablePrivateCluster', False)
                },
                'nsg_analysis': nsg_analysis,
                'findings': [f.to_dict() for f in nsg_analyzer.get_findings()]
            }, f, indent=2)
        print(f"   ✓ Results saved to {output_file}")
        
        print("\n" + "="*80)
        print("✅ NSG ANALYSIS COMPLETE")
        print("="*80)
        
        return 0
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Test interrupted by user")
        return 130
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
