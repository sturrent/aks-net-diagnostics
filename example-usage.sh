#!/usr/bin/env bash

# Example usage scripts for AKS Network Diagnostics Tool

echo "AKS Network Diagnostics - Example Usage"
echo "========================================"
echo

# Check if script exists
SCRIPT_PATH="./aks-net-diagnostics.sh"
if [[ ! -f "${SCRIPT_PATH}" ]]; then
    echo "Error: aks-net-diagnostics.sh not found in current directory"
    exit 1
fi

# Example 1: Basic analysis
echo "Example 1: Basic cluster analysis"
echo "Command: ${SCRIPT_PATH} -n my-aks-cluster -g my-resource-group"
echo "Description: Performs basic read-only analysis of cluster network configuration"
echo

# Example 2: Full analysis with API probing
echo "Example 2: Full analysis with active connectivity testing"
echo "Command: ${SCRIPT_PATH} -n my-aks-cluster -g my-resource-group --probe-api"
echo "Description: Includes active connectivity tests from VMSS instances (requires explicit consent)"
echo

# Example 3: Analysis with JSON output
echo "Example 3: Analysis with structured JSON output"
echo "Command: ${SCRIPT_PATH} -n my-aks-cluster -g my-resource-group --json-out report.json"
echo "Description: Saves machine-readable report to JSON file for automation"
echo

# Example 4: Analysis with caching for faster re-runs
echo "Example 4: Analysis with caching enabled"
echo "Command: ${SCRIPT_PATH} -n my-aks-cluster -g my-resource-group --cache"
echo "Description: Caches Azure CLI responses for faster subsequent analysis"
echo

# Example 5: Cross-subscription analysis
echo "Example 5: Cross-subscription analysis"
echo "Command: ${SCRIPT_PATH} -n my-aks-cluster -g my-resource-group --subscription 12345678-1234-1234-1234-123456789012"
echo "Description: Analyzes cluster in different subscription than current context"
echo

# Example 6: Comprehensive analysis
echo "Example 6: Comprehensive analysis with all options"
echo "Command: ${SCRIPT_PATH} -n my-aks-cluster -g my-resource-group --subscription 12345678-1234-1234-1234-123456789012 --probe-api --json-out comprehensive-report.json --cache"
echo "Description: Full analysis with all features enabled"
echo

echo "Prerequisites:"
echo "- Azure CLI (az) must be installed and authenticated"
echo "- jq must be installed for JSON processing"
echo "- Sufficient permissions to read AKS cluster and network resources"
echo
echo "For help: ${SCRIPT_PATH} --help"
