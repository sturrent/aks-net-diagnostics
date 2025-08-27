#!/usr/bin/env bash
set -euo pipefail

# AKS Network Diagnostics Script
# Comprehensive read-only analysis of AKS cluster network configuration
# Author: Azure Networking Diagnostics Generator
# Version: 2.0

usage() {
  cat <<EOF
Usage: $0 -n <AKS_NAME> -g <AKS_RG> [OPTIONS]

REQUIRED:
  -n <AKS_NAME>           AKS cluster name
  -g <AKS_RG>             AKS resource group

OPTIONS:
  --subscription <SUB_ID> Azure subscription ID (overrides current context)
  --probe-api             Enable active connectivity checks from VMSS instances
                         WARNING: Executes commands inside cluster nodes
  --json-out <FILE>       Output JSON report to file (default: auto-generated filename)
  --no-json              Skip JSON report generation
  --verbose              Show detailed console output (default: summary only)
  --cache                Cache Azure CLI responses for faster re-runs
  -h, --help             Show this help message

DESCRIPTION:
  Performs comprehensive read-only analysis of AKS cluster network configuration:
  - Cluster type detection (public/private, VNet integration)
  - Outbound connectivity analysis (LoadBalancer/NAT Gateway/UDR)
  - VNet/subnet configuration and dependencies
  - Private DNS zone validation for private clusters
  - Network security group and route table analysis
  - Potential misconfiguration detection

EXAMPLES:
  $0 -n my-aks-cluster -g my-resource-group
  $0 -n my-cluster -g my-rg --subscription 12345678-1234-1234-1234-123456789012
  $0 -n my-cluster -g my-rg --probe-api --json-out custom-report.json
  $0 -n my-cluster -g my-rg --verbose --no-json

EOF
}

# Global variables
AKS_NAME=""
AKS_RG=""
SUB_ID=""
PROBE_API=0
JSON_OUT=""
NO_JSON=0
VERBOSE=0
CACHE=0

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    -n) 
      AKS_NAME="$2"
      shift 2
      ;;
    -g) 
      AKS_RG="$2"
      shift 2
      ;;
    --subscription) 
      SUB_ID="$2"
      shift 2
      ;;
    --probe-api) 
      PROBE_API=1
      shift
      ;;
    --json-out) 
      JSON_OUT="$2"
      shift 2
      ;;
    --no-json) 
      NO_JSON=1
      shift
      ;;
    --verbose) 
      VERBOSE=1
      shift
      ;;
    --cache) 
      CACHE=1
      shift
      ;;
    -h|--help) 
      usage
      exit 0
      ;;
    *) 
      echo "ERROR: Unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

# Validate required arguments
if [[ -z "${AKS_NAME}" || -z "${AKS_RG}" ]]; then
  echo "ERROR: Missing required arguments -n (AKS name) and/or -g (resource group)" >&2
  usage
  exit 2
fi

# Validate dependencies
if ! command -v az >/dev/null 2>&1; then
  echo "ERROR: Azure CLI (az) is required but not found" >&2
  echo "Install from: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required but not found" >&2
  echo "Install from: https://stedolan.github.io/jq/download/" >&2
  exit 1
fi

# Validate Azure CLI login and set subscription if provided
if ! az account show >/dev/null 2>&1; then
  echo "ERROR: Not logged into Azure CLI" >&2
  echo "Run: az login" >&2
  exit 1
fi

if [[ -n "${SUB_ID}" ]]; then
  echo "Setting subscription context to: ${SUB_ID}"
  az account set -s "${SUB_ID}" || {
    echo "ERROR: Failed to set subscription context" >&2
    exit 1
  }
fi

# Get current subscription for reporting
CURRENT_SUB="$(az account show --query id -o tsv)"
echo "Using Azure subscription: ${CURRENT_SUB}"

# Set up JSON output filename if not disabled
if [[ "${NO_JSON}" -eq 0 ]]; then
  if [[ -z "${JSON_OUT}" ]]; then
    # Auto-generate filename with timestamp
    TIMESTAMP="$(date +"%Y%m%d_%H%M%S")"
    JSON_OUT="aks-network-report_${AKS_NAME}_${TIMESTAMP}.json"
  fi
  echo "JSON report will be saved to: ${JSON_OUT}"
fi

echo

# Cache directory for Azure CLI responses
CACHE_DIR="${TMPDIR:-/tmp}/aks-net-check-${AKS_NAME}-$$"
mkdir -p "${CACHE_DIR}"

# Cleanup function
cleanup() {
  if [[ ${CACHE} -eq 0 ]]; then
    rm -rf "${CACHE_DIR}" 2>/dev/null || true
  else
    echo "Cache directory preserved: ${CACHE_DIR}"
  fi
}
trap cleanup EXIT

# Azure CLI with caching support
azc() {
  local cache_key
  cache_key="$(echo "$*" | sed 's#[^a-zA-Z0-9._-]#_#g')"
  local cache_file="${CACHE_DIR}/${cache_key}.json"
  
  if [[ ${CACHE} -eq 1 && -s "${cache_file}" ]]; then
    cat "${cache_file}"
  else
    if az "$@" -o json > "${cache_file}" 2>/dev/null; then
      cat "${cache_file}"
    else
      # If command fails, remove empty cache file and return empty JSON
      rm -f "${cache_file}"
      echo "{}"
    fi
  fi
}

# Helper function to resolve DNS server locations
resolve_dns_location() {
  local dns_ip="$1"
  local vnets_json="$2"
  
  # Check if DNS IP is in any VNet CIDR
  echo "${vnets_json}" | jq -r --arg ip "${dns_ip}" '
    .[] | select(
      (.cidrs // .addressSpace)[] | . as $cidr | 
      ($ip | split(".") | map(tonumber)) as $ip_parts |
      ($cidr | split("/")) as $cidr_parts |
      ($cidr_parts[0] | split(".") | map(tonumber)) as $net_parts |
      ($cidr_parts[1] | tonumber) as $prefix_len |
      # Simple CIDR check for IPv4
      if $prefix_len >= 8 and $prefix_len <= 32 then
        ($ip_parts[0] == $net_parts[0] and 
         ($prefix_len <= 8 or $ip_parts[1] == $net_parts[1]) and
         ($prefix_len <= 16 or $ip_parts[2] == $net_parts[2]) and
         ($prefix_len <= 24 or $ip_parts[3] == $net_parts[3]))
      else false end
    ) | .name'
}

# Helper function to get peered VNets and analyze their address spaces
get_peered_vnets_analysis() {
  local cluster_vnets_json="$1"
  local peered_vnets_analysis="[]"
  
  # For each cluster VNet, get its peered VNets
  for vnet_info in $(echo "${cluster_vnets_json}" | jq -r '.[] | @base64'); do
    vnet_decoded="$(echo "${vnet_info}" | base64 --decode)"
    vnet_name="$(echo "${vnet_decoded}" | jq -r '.name')"
    vnet_id="$(echo "${vnet_decoded}" | jq -r '.id')"
    peerings="$(echo "${vnet_decoded}" | jq -r '.peerings')"
    
    # For each peering, get the remote VNet details
    for peering_info in $(echo "${peerings}" | jq -r '.[] | @base64' 2>/dev/null); do
      if [[ -n "${peering_info}" ]]; then
        peering_decoded="$(echo "${peering_info}" | base64 --decode)"
        remote_vnet_id="$(echo "${peering_decoded}" | jq -r '.remoteVnetId')"
        remote_vnet_name="$(echo "${peering_decoded}" | jq -r '.remoteVnetName')"
        peering_state="$(echo "${peering_decoded}" | jq -r '.peeringState')"
        
        if [[ "${peering_state}" == "Connected" && -n "${remote_vnet_id}" ]]; then
          # Get the remote VNet details
          remote_vnet_json="$(az network vnet show --ids "${remote_vnet_id}" -o json 2>/dev/null || echo "{}")"
          if [[ "$(echo "${remote_vnet_json}" | jq -r '.name // empty')" != "" ]]; then
            remote_cidrs="$(echo "${remote_vnet_json}" | jq -r '.addressSpace.addressPrefixes')"
            
            peered_vnet_info="$(jq -n \
              --arg id "${remote_vnet_id}" \
              --arg name "${remote_vnet_name}" \
              --argjson cidrs "${remote_cidrs}" \
              --arg sourceVnet "${vnet_name}" \
              --arg peeringState "${peering_state}" \
              '{
                id: $id,
                name: $name,
                cidrs: $cidrs,
                sourceVnet: $sourceVnet,
                peeringState: $peeringState
              }')"
            
            peered_vnets_analysis="$(echo "${peered_vnets_analysis}" | jq --argjson vnet "${peered_vnet_info}" '. + [$vnet]')"
          fi
        fi
      fi
    done
  done
  
  echo "${peered_vnets_analysis}"
}

# Function to analyze route tables
analyze_route_table() {
  local route_table_id="$1"
  
  if [[ -z "${route_table_id}" || "${route_table_id}" == "null" ]]; then
    echo "null"
    return
  fi
  
  local rt_name
  rt_name="$(basename "${route_table_id}")"
  local rt_rg
  rt_rg="$(echo "${route_table_id}" | cut -d'/' -f5)"
  
  local routes
  routes="$(azc network route-table route list --route-table-name "${rt_name}" -g "${rt_rg}")"
  
  echo "${routes}" | jq '{
    id: "'${route_table_id}'",
    name: "'${rt_name}'",
    routes: [.[] | {
      name: .name,
      addressPrefix: .addressPrefix,
      nextHopType: .nextHopType,
      nextHopIpAddress: .nextHopIpAddress
    }],
    defaultRoute: [.[] | select(.addressPrefix=="0.0.0.0/0") | {
      nextHopType: .nextHopType,
      nextHopIpAddress: .nextHopIpAddress
    }][0] // null
  }'
}

# Function to analyze Network Security Groups
analyze_nsg() {
  local nsg_id="$1"
  
  if [[ -z "${nsg_id}" || "${nsg_id}" == "null" ]]; then
    echo "null"
    return
  fi
  
  local nsg_name
  nsg_name="$(basename "${nsg_id}")"
  local nsg_rg
  nsg_rg="$(echo "${nsg_id}" | cut -d'/' -f5)"
  
  local nsg_json
  nsg_json="$(azc network nsg show -g "${nsg_rg}" -n "${nsg_name}")"
  
  echo "${nsg_json}" | jq '{
    id: .id,
    name: .name,
    securityRules: [.securityRules[] | {
      name: .name,
      priority: .priority,
      direction: .direction,
      access: .access,
      protocol: .protocol,
      sourceAddressPrefix: .sourceAddressPrefix,
      destinationAddressPrefix: .destinationAddressPrefix,
      destinationPortRange: .destinationPortRange,
      sourcePortRange: .sourcePortRange
    }],
    relevantRules: {
      apiServer: [.securityRules[] | select(
        (.destinationPortRange | contains("443")) or 
        (.destinationPortRange == "*") or 
        (.destinationPortRange | test("443"))
      )],
      dns: [.securityRules[] | select(
        (.destinationPortRange | contains("53")) or
        (.destinationPortRange == "*") or 
        (.destinationPortRange | test("53"))
      )],
      ntp: [.securityRules[] | select(
        (.destinationPortRange | contains("123")) or
        (.destinationPortRange == "*") or 
        (.destinationPortRange | test("123"))
      )]
    }
  }'
}

echo "Analyzing AKS cluster: ${AKS_NAME} in resource group: ${AKS_RG}"
echo "=========================================================================="

# Step 1: Get cluster basic information
echo "Fetching cluster information..."
CLUSTER_JSON="$(azc aks show -g "${AKS_RG}" -n "${AKS_NAME}")" || {
  echo "ERROR: Failed to fetch cluster information. Check cluster name and resource group." >&2
  exit 3
}

# Extract cluster properties
PROVISIONING_STATE="$(echo "${CLUSTER_JSON}" | jq -r '.provisioningState // "unknown"')"
LOCATION="$(echo "${CLUSTER_JSON}" | jq -r '.location')"
NODE_RG="$(echo "${CLUSTER_JSON}" | jq -r '.nodeResourceGroup')"
OUTBOUND_TYPE="$(echo "${CLUSTER_JSON}" | jq -r '.networkProfile.outboundType // "loadBalancer"')"
NETWORK_PLUGIN="$(echo "${CLUSTER_JSON}" | jq -r '.networkProfile.networkPlugin // "kubenet"')"
SERVICE_CIDR="$(echo "${CLUSTER_JSON}" | jq -r '.networkProfile.serviceCidr // "10.0.0.0/16"')"
DNS_SERVICE_IP="$(echo "${CLUSTER_JSON}" | jq -r '.networkProfile.dnsServiceIp // "10.0.0.10"')"
POD_CIDR="$(echo "${CLUSTER_JSON}" | jq -r '.networkProfile.podCidr // "10.244.0.0/16"')"

# Analyze cluster failure details if in failed state
FAILURE_ANALYSIS="null"
if [[ "${PROVISIONING_STATE}" == "Failed" ]]; then
  echo "Cluster is in Failed state - analyzing failure details..."
  
  # Get cluster resource ID for activity log queries
  CLUSTER_RESOURCE_ID="$(echo "${CLUSTER_JSON}" | jq -r '.id')"
  
  # Get recent activity logs for the cluster (last 24 hours)
  echo "  - Fetching activity logs for failure analysis..."
  ACTIVITY_LOGS="$(az monitor activity-log list \
    --resource-id "${CLUSTER_RESOURCE_ID}" \
    --start-time "$(date -u -d '24 hours ago' '+%Y-%m-%dT%H:%M:%SZ')" \
    --end-time "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    --status Failed \
    -o json 2>/dev/null || echo "[]")"
  
  # Get the most recent failed operations
  RECENT_FAILURES="$(echo "${ACTIVITY_LOGS}" | jq '[.[] | select(.status.value == "Failed") | {
    timestamp: .eventTimestamp,
    operationName: .operationName.value,
    status: .status.value,
    subStatus: .subStatus.value,
    statusMessage: .status.localizedValue,
    correlationId: .correlationId,
    resourceId: .resourceId,
    properties: .properties
  }] | sort_by(.timestamp) | reverse | .[0:5]')"
  
  # Get power state information
  POWER_STATE="$(echo "${CLUSTER_JSON}" | jq -r '.powerState.code // "unknown"')"
  
  # Get any error details from the cluster status
  STATUS_DETAILS="$(echo "${CLUSTER_JSON}" | jq '.status // null')"
  
  # Check for common failure patterns in activity logs
  NETWORK_RELATED_FAILURES="$(echo "${ACTIVITY_LOGS}" | jq '[.[] | select(
    (.operationName.value | test("Microsoft.ContainerService/managedClusters"; "i")) and
    (.status.value == "Failed") and
    (
      (.properties.statusMessage // .subStatus.value // "" | test("network|dns|subnet|vnet|routing|connectivity"; "i")) or
      (.operationName.value | test("network|subnet|vnet"; "i"))
    )
  ) | {
    timestamp: .eventTimestamp,
    operation: .operationName.value,
    error: (.properties.statusMessage // .subStatus.value // "No details available"),
    correlationId: .correlationId
  }] | sort_by(.timestamp) | reverse | .[0:3]')"
  
  # Get node pool status for additional context
  NODE_POOL_STATUS="$(az aks nodepool list -g "${AKS_RG}" --cluster-name "${AKS_NAME}" \
    --query '[].{name: name, provisioningState: provisioningState, powerState: powerState.code}' \
    -o json 2>/dev/null || echo "[]")"
  
  # Compile failure analysis
  FAILURE_ANALYSIS="$(jq -n \
    --arg provisioningState "${PROVISIONING_STATE}" \
    --arg powerState "${POWER_STATE}" \
    --argjson statusDetails "${STATUS_DETAILS}" \
    --argjson recentFailures "${RECENT_FAILURES}" \
    --argjson networkFailures "${NETWORK_RELATED_FAILURES}" \
    --argjson nodePoolStatus "${NODE_POOL_STATUS}" \
    '{
      provisioningState: $provisioningState,
      powerState: $powerState,
      statusDetails: $statusDetails,
      recentFailures: $recentFailures,
      networkRelatedFailures: $networkFailures,
      nodePoolStatus: $nodePoolStatus,
      analysisTimestamp: now | strftime("%Y-%m-%dT%H:%M:%SZ")
    }')"
  
  echo "  - Found $(echo "${RECENT_FAILURES}" | jq 'length') recent failed operations"
  echo "  - Found $(echo "${NETWORK_RELATED_FAILURES}" | jq 'length') network-related failures"
fi

# Private cluster settings
PRIVATE_CLUSTER_ENABLED="$(echo "${CLUSTER_JSON}" | jq -r '.apiServerAccessProfile.enablePrivateCluster // false')"
PRIVATE_DNS_ZONE="$(echo "${CLUSTER_JSON}" | jq -r '.apiServerAccessProfile.privateDNSZone // "System"')"
AUTHORIZED_IP_RANGES="$(echo "${CLUSTER_JSON}" | jq -r '.apiServerAccessProfile.authorizedIPRanges // []')"
API_SERVER_VNET_INTEGRATION_ENABLED="$(echo "${CLUSTER_JSON}" | jq -r '.apiServerAccessProfile.enableVnetIntegration // false')"
VNET_INTEGRATION_SUBNET_ID="$(echo "${CLUSTER_JSON}" | jq -r '.apiServerAccessProfile.subnetId // null')"

# API endpoints
PUBLIC_FQDN="$(echo "${CLUSTER_JSON}" | jq -r '.fqdn // empty')"
PRIVATE_FQDN="$(echo "${CLUSTER_JSON}" | jq -r '.privateFqdn // empty')"

# Step 2: Analyze agent pools and their subnets
echo "Analyzing agent pools and network configuration..."
AGENT_POOLS="$(azc aks nodepool list -g "${AKS_RG}" --cluster-name "${AKS_NAME}")"

# Get unique subnet IDs using mapfile for proper array handling
mapfile -t SUBNET_IDS < <(echo "${AGENT_POOLS}" | jq -r '.[].vnetSubnetId | select(.!=null)' | sort -u)

if [[ ${#SUBNET_IDS[@]} -eq 0 ]]; then
  echo "Warning: No VNet-integrated node pools found. Using default Azure networking."
fi

# Step 3: Analyze VNets and their configuration
echo "Analyzing VNet configuration..."
declare -A VNETS_MAP
VNETS_ANALYSIS="[]"

for subnet_id in "${SUBNET_IDS[@]}"; do
  if [[ -n "${subnet_id}" && "${subnet_id}" != "null" ]]; then
    # Get subnet details
    subnet_json="$(azc network vnet subnet show --ids "${subnet_id}")"
    
    # Extract VNet ID
    vnet_id="$(echo "${subnet_json}" | jq -r '.id' | sed 's#/subnets/[^/]*$##')"
    
    # Skip if already processed
    if [[ -n "${VNETS_MAP[${vnet_id}]:-}" ]]; then
      continue
    fi
    VNETS_MAP["${vnet_id}"]=1
    
    # Get VNet details
    vnet_json="$(azc network vnet show --ids "${vnet_id}")"
    vnet_name="$(echo "${vnet_json}" | jq -r '.name')"
    vnet_cidrs="$(echo "${vnet_json}" | jq -r '.addressSpace.addressPrefixes')"
    vnet_dns_servers="$(echo "${vnet_json}" | jq -r '.dhcpOptions.dnsServers // []')"
    
    # Get VNet peerings (with error handling)
    vnet_rg="$(echo "${vnet_id}" | cut -d'/' -f5)"
    if peerings_raw="$(az network vnet peering list -g "${vnet_rg}" --vnet-name "${vnet_name}" -o json 2>/dev/null)"; then
      peerings="$(echo "${peerings_raw}" | jq '[.[] | {
        name: .name,
        peeringState: .peeringState,
        remoteVnetId: .remoteVirtualNetwork.id,
        remoteVnetName: (.remoteVirtualNetwork.id | split("/")[-1]),
        remoteAddressSpace: .remoteAddressSpace.addressPrefixes,
        allowVnetAccess: .allowVirtualNetworkAccess,
        allowForwardedTraffic: .allowForwardedTraffic,
        allowGatewayTransit: .allowGatewayTransit,
        useRemoteGateways: .useRemoteGateways
      }]')"
    else
      peerings="[]"
    fi
    
    # DNS analysis with improved location detection
    dns_analysis="[]"
    if [[ "$(echo "${vnet_dns_servers}" | jq '. | length')" -gt 0 ]]; then
      # First, get all peered VNets for better DNS location analysis
      current_vnet_json="$(jq -n \
        --arg id "${vnet_id}" \
        --arg name "${vnet_name}" \
        --argjson cidrs "${vnet_cidrs}" \
        --argjson dns "${vnet_dns_servers}" \
        --argjson peerings "${peerings}" \
        '{
          id: $id,
          name: $name,
          cidrs: $cidrs,
          dnsServers: $dns,
          peerings: $peerings
        }')"
      
      peered_vnets="$(get_peered_vnets_analysis "[${current_vnet_json}]")"
      
      for dns_ip in $(echo "${vnet_dns_servers}" | jq -r '.[]'); do
        # Check if DNS IP is in this VNet
        dns_in_current_vnet="$(resolve_dns_location "${dns_ip}" "[${current_vnet_json}]")"
        
        if [[ -n "${dns_in_current_vnet}" ]]; then
          dns_analysis="$(echo "${dns_analysis}" | jq --arg ip "${dns_ip}" --arg vnet "${dns_in_current_vnet}" '. + [{ip: $ip, locationType: "local", hostingVnet: $vnet}]')"
        else
          # Check if DNS IP is in any peered VNet
          dns_in_peered_vnet="$(resolve_dns_location "${dns_ip}" "${peered_vnets}")"
          
          if [[ -n "${dns_in_peered_vnet}" ]]; then
            dns_analysis="$(echo "${dns_analysis}" | jq --arg ip "${dns_ip}" --arg vnet "${dns_in_peered_vnet}" '. + [{ip: $ip, locationType: "peered", hostingVnet: $vnet}]')"
          else
            # External or unknown location
            dns_analysis="$(echo "${dns_analysis}" | jq --arg ip "${dns_ip}" '. + [{ip: $ip, locationType: "external", hostingVnet: ""}]')"
          fi
        fi
      done
    fi
    
    # Create VNet info object
    vnet_info="$(jq -n \
      --arg id "${vnet_id}" \
      --arg name "${vnet_name}" \
      --argjson cidrs "${vnet_cidrs}" \
      --argjson dns "${vnet_dns_servers}" \
      --argjson dns_analysis "${dns_analysis}" \
      --argjson peerings "${peerings}" \
      '{
        id: $id,
        name: $name,
        addressSpace: $cidrs,
        dnsServers: $dns,
        dnsAnalysis: $dns_analysis,
        peerings: $peerings
      }')"
    
    # Add to analysis array
    VNETS_ANALYSIS="$(echo "${VNETS_ANALYSIS}" | jq --argjson vnet "${vnet_info}" '. + [$vnet]')"
  fi
done

# Step 4: Analyze outbound connectivity and effective public IPs
echo "Analyzing outbound connectivity..."
OUTBOUND_IPS="[]"
OUTBOUND_ANALYSIS="null"

case "${OUTBOUND_TYPE}" in
  loadBalancer)
    echo "  - Analyzing Load Balancer outbound configuration..."
    # Get load balancers in the node resource group
    LBS_JSON="$(az network lb list -g "${NODE_RG}" -o json 2>/dev/null || echo "[]")"
    
    # Extract public IPs from frontend IP configurations
    # First, get all frontend IP configuration IDs from outbound rules
    FRONTEND_CONFIG_IDS="$(echo "${LBS_JSON}" | jq -r '
      [.[] | .outboundRules[]? | .frontendIPConfigurations[]?.id] | 
      map(select(.!=null)) | unique | .[]' 2>/dev/null || echo "")"
    
    # If no outbound rules, get all frontend IPs from the load balancer
    if [[ -z "${FRONTEND_CONFIG_IDS}" ]]; then
      FRONTEND_CONFIG_IDS="$(echo "${LBS_JSON}" | jq -r '
        [.[] | .frontendIPConfigurations[]? | .id] |
        map(select(.!=null)) | unique | .[]' 2>/dev/null || echo "")"
    fi
    
    # For each frontend IP configuration, get the public IP
    if [[ -n "${FRONTEND_CONFIG_IDS}" ]]; then
      while IFS= read -r config_id; do
        if [[ -n "${config_id}" ]]; then
          # Extract load balancer name and frontend config name from ID
          lb_name="$(echo "${config_id}" | cut -d'/' -f9)"
          config_name="$(echo "${config_id}" | cut -d'/' -f11)"
          
          # Get the frontend IP configuration details
          frontend_config="$(az network lb frontend-ip show -g "${NODE_RG}" --lb-name "${lb_name}" -n "${config_name}" -o json 2>/dev/null || echo "{}")"
          ip_id="$(echo "${frontend_config}" | jq -r '.publicIPAddress.id // empty' 2>/dev/null || echo "")"
          
          if [[ -n "${ip_id}" ]]; then
            ip_details="$(az network public-ip show --ids "${ip_id}" -o json 2>/dev/null || echo "{}")"
            ip_address="$(echo "${ip_details}" | jq -r '.ipAddress // empty' 2>/dev/null || echo "")"
            if [[ -n "${ip_address}" ]]; then
              OUTBOUND_IPS="$(echo "${OUTBOUND_IPS}" | jq ". + [\"${ip_address}\"]")"
              echo "    Found outbound IP: ${ip_address}"
            fi
          fi
        fi
      done <<< "${FRONTEND_CONFIG_IDS}"
    fi
    
    OUTBOUND_ANALYSIS="$(echo "${LBS_JSON}" | jq '{
      type: "loadBalancer",
      loadBalancers: [.[] | {
        name: .name,
        sku: .sku.name,
        frontendIPConfigurations: [.frontendIPConfigurations[]? | {
          name: .name,
          publicIPAddress: .publicIPAddress.id
        }],
        outboundRules: [.outboundRules[]? | {
          name: .name,
          frontendIpConfigurations: [.frontendIpConfigurations[]? | .id]
        }]
      }]
    }' 2>/dev/null || echo '{"type": "loadBalancer", "loadBalancers": []}')"
    ;;
    
  managedNATGateway|userAssignedNATGateway)
    echo "  - Analyzing NAT Gateway configuration..."
    # Get NAT Gateways from subnets
    NAT_GATEWAY_IDS=()
    for subnet_id in "${SUBNET_IDS[@]}"; do
      if [[ -n "${subnet_id}" && "${subnet_id}" != "null" ]]; then
        nat_id="$(azc network vnet subnet show --ids "${subnet_id}" | jq -r '.natGateway.id // empty')"
        if [[ -n "${nat_id}" ]]; then
          NAT_GATEWAY_IDS+=("${nat_id}")
        fi
      fi
    done
    
    # Remove duplicates using mapfile
    mapfile -t NAT_GATEWAY_IDS < <(printf '%s\n' "${NAT_GATEWAY_IDS[@]}" | sort -u)
    
    NAT_GATEWAYS_ANALYSIS="[]"
    for nat_id in "${NAT_GATEWAY_IDS[@]}"; do
      nat_json="$(azc network nat gateway show --ids "${nat_id}")"
      
      # Get public IPs and prefixes
      public_ip_ids="$(echo "${nat_json}" | jq -r '.publicIpAddresses[]?.id // empty')"
      public_prefix_ids="$(echo "${nat_json}" | jq -r '.publicIpPrefixes[]?.id // empty')"
      
      # Resolve IP addresses
      nat_ips="[]"
      if [[ -n "${public_ip_ids}" ]]; then
        while IFS= read -r ip_id; do
          if [[ -n "${ip_id}" ]]; then
            ip_details="$(azc network public-ip show --ids "${ip_id}")"
            ip_address="$(echo "${ip_details}" | jq -r '.ipAddress // empty')"
            if [[ -n "${ip_address}" ]]; then
              nat_ips="$(echo "${nat_ips}" | jq ". + [\"${ip_address}\"]")"
              OUTBOUND_IPS="$(echo "${OUTBOUND_IPS}" | jq ". + [\"${ip_address}\"]")"
            fi
          fi
        done <<< "${public_ip_ids}"
      fi
      
      NAT_GATEWAYS_ANALYSIS="$(echo "${NAT_GATEWAYS_ANALYSIS}" | jq --argjson nat '{
        id: "'${nat_id}'",
        name: "'"$(echo "${nat_json}" | jq -r '.name')"'",
        sku: "'"$(echo "${nat_json}" | jq -r '.sku.name')"'",
        publicIps: '${nat_ips}',
        publicIpPrefixes: "'"${public_prefix_ids}"'"
      }' '. + [$nat]')"
    done
    
    OUTBOUND_ANALYSIS="$(jq -n --argjson nats "${NAT_GATEWAYS_ANALYSIS}" '{
      type: "'${OUTBOUND_TYPE}'",
      natGateways: $nats
    }')"
    ;;
    
  userDefinedRouting)
    echo "  - Analyzing User Defined Routing configuration..."
    UDR_ANALYSIS="[]"
    
    for subnet_id in "${SUBNET_IDS[@]}"; do
      if [[ -n "${subnet_id}" && "${subnet_id}" != "null" ]]; then
        subnet_json="$(azc network vnet subnet show --ids "${subnet_id}")"
        rt_id="$(echo "${subnet_json}" | jq -r '.routeTable.id // empty')"
        
        if [[ -n "${rt_id}" ]]; then
          rt_analysis="$(analyze_route_table "${rt_id}")"
          UDR_ANALYSIS="$(echo "${UDR_ANALYSIS}" | jq --argjson rt "${rt_analysis}" '. + [$rt]')"
        fi
      fi
    done
    
    OUTBOUND_ANALYSIS="$(jq -n --argjson udrs "${UDR_ANALYSIS}" '{
      type: "userDefinedRouting",
      routeTables: $udrs
    }')"
    OUTBOUND_IPS="[]"  # UDR doesn't have effective public IPs from Azure resources
    ;;
esac

# Step 5: Analyze VMSS network configuration
echo "Analyzing VMSS network configuration..."
VMSS_LIST="$(az vmss list -g "${NODE_RG}" -o json 2>/dev/null || echo "[]")"
VMSS_ANALYSIS="[]"

# Process each VMSS
for vmss_name in $(echo "${VMSS_LIST}" | jq -r '.[].name' 2>/dev/null); do
  if [[ -n "${vmss_name}" ]]; then
    echo "  - Analyzing VMSS: ${vmss_name}"
    vmss_json="$(az vmss show -g "${NODE_RG}" -n "${vmss_name}" -o json 2>/dev/null || echo "{}")"
    
    # Get NIC configuration
    nic_config="$(echo "${vmss_json}" | jq '.virtualMachineProfile.networkProfile.networkInterfaceConfigurations[0]' 2>/dev/null || echo "{}")"
    subnet_id="$(echo "${nic_config}" | jq -r '.ipConfigurations[0].subnet.id // empty' 2>/dev/null || echo "")"
    
    if [[ -n "${subnet_id}" && "${subnet_id}" != "null" ]]; then
      # Analyze subnet's NSG and route table
      subnet_json="$(az network vnet subnet show --ids "${subnet_id}" -o json 2>/dev/null || echo "{}")"
      nsg_id="$(echo "${subnet_json}" | jq -r '.networkSecurityGroup.id // empty' 2>/dev/null || echo "")"
      rt_id="$(echo "${subnet_json}" | jq -r '.routeTable.id // empty' 2>/dev/null || echo "")"
      
      nsg_analysis="null"
      if [[ -n "${nsg_id}" ]]; then
        nsg_analysis="$(analyze_nsg "${nsg_id}")"
      fi
      
      rt_analysis="null"
      if [[ -n "${rt_id}" ]]; then
        rt_analysis="$(analyze_route_table "${rt_id}")"
      fi
      
      vmss_info="$(jq -n --arg name "${vmss_name}" --arg subnet "${subnet_id}" \
        --argjson nsg "${nsg_analysis}" --argjson rt "${rt_analysis}" '{
        name: $name,
        subnetId: $subnet,
        networkSecurityGroup: $nsg,
        routeTable: $rt
      }' 2>/dev/null || echo "{}")"
      
      VMSS_ANALYSIS="$(echo "${VMSS_ANALYSIS}" | jq --argjson vmss "${vmss_info}" '. + [$vmss]' 2>/dev/null || echo "[]")"
      echo "    Found subnet: $(basename "${subnet_id}")"
    else
      echo "    Warning: Could not determine subnet for VMSS ${vmss_name}"
    fi
  fi
done

# Step 6: Private DNS Zone analysis (for private clusters)
echo "Analyzing private DNS configuration..."
PRIVATE_DNS_ANALYSIS="null"

if [[ "${PRIVATE_CLUSTER_ENABLED}" == "true" ]]; then
  echo "  - Private cluster detected, analyzing private DNS zone..."
  
  if [[ "${PRIVATE_DNS_ZONE}" == "System" ]]; then
    # System-managed private DNS zone
    echo "    - Using system-managed private DNS zone"
    # List zones to find the correct one (stored for potential future use)
    azc network private-dns zone list -g "${NODE_RG}" >/dev/null
    
    # Find the zone that matches the private FQDN pattern
    API_ZONE=""
    if [[ -n "${PRIVATE_FQDN}" ]]; then
      # Extract domain from FQDN (everything after the first dot)
      API_ZONE="${PRIVATE_FQDN#*.}"
    fi
    
  else
    # BYO private DNS zone
    echo "    - Using bring-your-own private DNS zone: ${PRIVATE_DNS_ZONE}"
    # Get the zone information
    azc network private-dns zone show --ids "${PRIVATE_DNS_ZONE}" | jq -s '.' >/dev/null
    API_ZONE="$(basename "${PRIVATE_DNS_ZONE}")"
  fi
  
  # Get A record for the API server
  RECORD_IP=""
  if [[ -n "${API_ZONE}" && -n "${PRIVATE_FQDN}" ]]; then
    record_name="${PRIVATE_FQDN%%.*}"  # Everything before the first dot
    
    # Try to get the A record
    if [[ "${PRIVATE_DNS_ZONE}" == "System" ]]; then
      record_json="$(azc network private-dns record-set a show -g "${NODE_RG}" -z "${API_ZONE}" -n "${record_name}" 2>/dev/null || echo "null")"
    else
      pdns_rg="$(echo "${PRIVATE_DNS_ZONE}" | cut -d'/' -f5)"
      record_json="$(azc network private-dns record-set a show -g "${pdns_rg}" -z "${API_ZONE}" -n "${record_name}" 2>/dev/null || echo "null")"
    fi
    
    if [[ "${record_json}" != "null" ]]; then
      RECORD_IP="$(echo "${record_json}" | jq -r '.arecords[0].ipv4Address // empty')"
    fi
  fi
  
  # Get private endpoint IP
  PRIVATE_ENDPOINT_IP=""
  PE_LIST="$(azc network private-endpoint list -g "${NODE_RG}")"
  
  # Find the management private endpoint
  PRIVATE_ENDPOINT_IP="$(echo "${PE_LIST}" | jq -r '
    .[] | select(.privateLinkServiceConnections[]?.groupIds[]? == "management") |
    .networkInterfaces[0].ipConfigurations[0].privateIPAddress // empty' | head -n1)"
  
  # Get VNet links
  VNET_LINKS="[]"
  if [[ -n "${API_ZONE}" ]]; then
    if [[ "${PRIVATE_DNS_ZONE}" == "System" ]]; then
      VNET_LINKS="$(azc network private-dns link vnet list -g "${NODE_RG}" -z "${API_ZONE}")"
    else
      pdns_rg="$(echo "${PRIVATE_DNS_ZONE}" | cut -d'/' -f5)"
      VNET_LINKS="$(azc network private-dns link vnet list -g "${pdns_rg}" -z "${API_ZONE}")"
    fi
  fi
  
  PRIVATE_DNS_ANALYSIS="$(jq -n \
    --arg mode "${PRIVATE_DNS_ZONE}" \
    --arg zone "${API_ZONE}" \
    --arg fqdn "${PRIVATE_FQDN}" \
    --arg recordIp "${RECORD_IP}" \
    --arg peIp "${PRIVATE_ENDPOINT_IP}" \
    --argjson links "${VNET_LINKS}" \
    '{
      mode: $mode,
      zoneName: $zone,
      apiFqdn: $fqdn,
      recordIp: $recordIp,
      privateEndpointIp: $peIp,
      vnetLinks: $links,
      ipMatch: ($recordIp == $peIp)
    }')"
fi

# Step 7: Optional API connectivity probe
echo "Checking API connectivity..."
API_PROBE_RESULTS="null"

if [[ ${PROBE_API} -eq 1 ]]; then
  echo "  - WARNING: Executing connectivity probe on VMSS instances..."
  
  # Get the first VMSS instance
  VMSS_NAME="$(echo "${VMSS_LIST}" | jq -r '.[0].name // empty')"
  
  if [[ -n "${VMSS_NAME}" ]]; then
    # Determine target FQDN
    TARGET_FQDN="${PRIVATE_FQDN:-${PUBLIC_FQDN}}"
    
    if [[ -n "${TARGET_FQDN}" ]]; then
      echo "    - Probing ${TARGET_FQDN} from VMSS instance..."
      
      # Create probe script
      PROBE_SCRIPT="
set -e
echo '=== DNS Resolution Test ==='
if command -v nslookup >/dev/null 2>&1; then
  nslookup ${TARGET_FQDN} || echo 'nslookup failed'
elif command -v dig >/dev/null 2>&1; then
  dig ${TARGET_FQDN} || echo 'dig failed'
else
  echo 'No DNS tools available'
fi

echo '=== TCP Connectivity Test ==='
if command -v nc >/dev/null 2>&1; then
  timeout 10 nc -zv ${TARGET_FQDN} 443 && echo 'TCP 443 connection successful' || echo 'TCP 443 connection failed'
elif command -v telnet >/dev/null 2>&1; then
  timeout 10 telnet ${TARGET_FQDN} 443 && echo 'Telnet 443 successful' || echo 'Telnet 443 failed'
else
  echo 'No connectivity tools available'
fi

echo '=== Network Route Test ==='
if command -v ip >/dev/null 2>&1; then
  ip route get 8.8.8.8 || echo 'Route lookup failed'
else
  echo 'ip command not available'
fi
"
      
      # Execute probe on VMSS
      PROBE_OUTPUT="$(az vmss run-command invoke \
        -g "${NODE_RG}" \
        -n "${VMSS_NAME}" \
        --command-id RunShellScript \
        --scripts "${PROBE_SCRIPT}" \
        -o json 2>/dev/null || echo '{"value":[{"message":"Probe execution failed"}]}')"
      
      API_PROBE_RESULTS="$(echo "${PROBE_OUTPUT}" | jq '{
        vmssName: "'${VMSS_NAME}'",
        targetFqdn: "'${TARGET_FQDN}'",
        output: (.value[0].message // "No output"),
        exitCode: (.value[0].code // -1)
      }')"
    fi
  fi
fi

# Step 8: Generate findings and detect potential misconfigurations
echo "Analyzing potential misconfigurations..."
FINDINGS="[]"

# Analyze cluster failure state and correlate with network issues
if [[ "${PROVISIONING_STATE}" == "Failed" && "${FAILURE_ANALYSIS}" != "null" ]]; then
  echo "  - Analyzing cluster failure patterns..."
  
  # Check for network-related failures
  network_failure_count="$(echo "${FAILURE_ANALYSIS}" | jq '.networkRelatedFailures | length')"
  if [[ "${network_failure_count}" -gt 0 ]]; then
    # Get the most recent network failure details
    recent_network_error="$(echo "${FAILURE_ANALYSIS}" | jq -r '.networkRelatedFailures[0].error // "Network-related operation failed"')"
    recent_network_operation="$(echo "${FAILURE_ANALYSIS}" | jq -r '.networkRelatedFailures[0].operation // "Unknown operation"')"
    
    FINDINGS="$(echo "${FINDINGS}" | jq --arg error "${recent_network_error}" --arg operation "${recent_network_operation}" '. + [{
      severity: "error",
      code: "CLUSTER_NETWORK_FAILURE",
      message: "Cluster failed due to network-related issues. Recent failure: \($error) (Operation: \($operation))",
      recommendation: "Review network configuration including VNet integration, DNS settings, outbound connectivity, and private DNS zone links. Check Azure activity logs for detailed error information."
    }]')"
  fi
  
  # Check for general cluster failures that might be network-related
  recent_failure_count="$(echo "${FAILURE_ANALYSIS}" | jq '.recentFailures | length')"
  if [[ "${recent_failure_count}" -gt 0 && "${network_failure_count}" -eq 0 ]]; then
    recent_error="$(echo "${FAILURE_ANALYSIS}" | jq -r '.recentFailures[0].statusMessage // .recentFailures[0].subStatus // "Cluster operation failed"')"
    recent_operation="$(echo "${FAILURE_ANALYSIS}" | jq -r '.recentFailures[0].operationName // "Unknown operation"')"
    
    FINDINGS="$(echo "${FINDINGS}" | jq --arg error "${recent_error}" --arg operation "${recent_operation}" '. + [{
      severity: "error",
      code: "CLUSTER_OPERATION_FAILURE",
      message: "Cluster failed with error: \($error) (Operation: \($operation))",
      recommendation: "Review the specific error details and check if network configuration issues might be contributing to the failure."
    }]')"
  fi
  
  # Check for failed node pools
  failed_node_pools="$(echo "${FAILURE_ANALYSIS}" | jq '[.nodePoolStatus[] | select(.provisioningState == "Failed") | .name]')"
  if [[ "$(echo "${failed_node_pools}" | jq 'length')" -gt 0 ]]; then
    failed_pools_list="$(echo "${failed_node_pools}" | jq -r 'join(", ")')"
    FINDINGS="$(echo "${FINDINGS}" | jq --arg pools "${failed_pools_list}" '. + [{
      severity: "error", 
      code: "NODE_POOL_FAILURE",
      message: "Node pools in failed state: \($pools)",
      recommendation: "Check node pool configuration including subnet capacity, VM size availability, and network security group rules."
    }]')"
  fi
fi

# Check UDR configuration
if [[ "${OUTBOUND_TYPE}" == "userDefinedRouting" ]]; then
  # Check if any route table has a default route
  has_default_route=false
  for subnet_id in "${SUBNET_IDS[@]}"; do
    if [[ -n "${subnet_id}" && "${subnet_id}" != "null" ]]; then
      subnet_json="$(azc network vnet subnet show --ids "${subnet_id}")"
      rt_id="$(echo "${subnet_json}" | jq -r '.routeTable.id // empty')"
      
      if [[ -n "${rt_id}" ]]; then
        rt_name="$(basename "${rt_id}")"
        rt_rg="$(echo "${rt_id}" | cut -d'/' -f5)"
        default_routes="$(azc network route-table route list --route-table-name "${rt_name}" -g "${rt_rg}" | 
          jq '[.[] | select(.addressPrefix=="0.0.0.0/0")]')"
        
        if [[ "$(echo "${default_routes}" | jq 'length')" -gt 0 ]]; then
          has_default_route=true
          break
        fi
      fi
    fi
  done
  
  if [[ "${has_default_route}" == "false" ]]; then
    FINDINGS="$(echo "${FINDINGS}" | jq '. + [{
      severity: "error",
      code: "UDR_MISSING_DEFAULT_ROUTE",
      message: "Outbound type is userDefinedRouting but no 0.0.0.0/0 route found in any route table",
      recommendation: "Add a default route (0.0.0.0/0) to your route table with appropriate next hop"
    }]')"
  fi
fi

# Check NAT Gateway attachment for NAT Gateway outbound types
if [[ "${OUTBOUND_TYPE}" =~ ^(managedNATGateway|userAssignedNATGateway)$ ]]; then
  nat_attached=false
  for subnet_id in "${SUBNET_IDS[@]}"; do
    if [[ -n "${subnet_id}" && "${subnet_id}" != "null" ]]; then
      subnet_json="$(azc network vnet subnet show --ids "${subnet_id}")"
      nat_id="$(echo "${subnet_json}" | jq -r '.natGateway.id // empty')"
      
      if [[ -n "${nat_id}" ]]; then
        nat_attached=true
        break
      fi
    fi
  done
  
  if [[ "${nat_attached}" == "false" ]]; then
    FINDINGS="$(echo "${FINDINGS}" | jq '. + [{
      severity: "error",
      code: "NATGW_NOT_ATTACHED",
      message: "Outbound type expects NAT Gateway but no NAT Gateway is attached to node subnets",
      recommendation: "Attach a NAT Gateway to your node subnets or change outbound type"
    }]')"
  fi
fi

# Check private DNS configuration for private clusters
if [[ "${PRIVATE_CLUSTER_ENABLED}" == "true" && "${PRIVATE_DNS_ANALYSIS}" != "null" ]]; then
  # Check if A record matches private endpoint IP
  record_ip="$(echo "${PRIVATE_DNS_ANALYSIS}" | jq -r '.recordIp // empty')"
  pe_ip="$(echo "${PRIVATE_DNS_ANALYSIS}" | jq -r '.privateEndpointIp // empty')"
  
  if [[ -n "${record_ip}" && -n "${pe_ip}" && "${record_ip}" != "${pe_ip}" ]]; then
    FINDINGS="$(echo "${FINDINGS}" | jq --arg record "${record_ip}" --arg pe "${pe_ip}" '. + [{
      severity: "error",
      code: "PDNS_A_RECORD_MISMATCH",
      message: "Private DNS A record IP (\($record)) does not match Private Endpoint IP (\($pe))",
      recommendation: "Verify private DNS zone configuration and ensure A record points to correct private endpoint IP"
    }]')"
  fi
  
  # Enhanced VNet link validation for custom DNS scenarios
  if [[ "$(echo "${VNETS_ANALYSIS}" | jq '[.[] | select(.dnsServers | length > 0)] | length')" -gt 0 ]]; then
    # Custom DNS servers are configured, perform comprehensive VNet link analysis
    vnet_links="$(echo "${PRIVATE_DNS_ANALYSIS}" | jq -r '.vnetLinks[]? // empty')"
    api_zone="$(echo "${PRIVATE_DNS_ANALYSIS}" | jq -r '.zoneName // empty')"
    
    # Check each cluster VNet with custom DNS
    for vnet_info in $(echo "${VNETS_ANALYSIS}" | jq -r '.[] | select(.dnsServers | length > 0) | @base64'); do
      vnet_decoded="$(echo "${vnet_info}" | base64 --decode)"
      vnet_name="$(echo "${vnet_decoded}" | jq -r '.name')"
      vnet_id="$(echo "${vnet_decoded}" | jq -r '.id')"
      dns_analysis="$(echo "${vnet_decoded}" | jq '.dnsAnalysis')"
      
      # Check if this cluster VNet is linked to the private DNS zone
      cluster_vnet_linked=false
      if [[ -n "${vnet_links}" ]]; then
        if echo "${vnet_links}" | jq -e --arg vnet_id "${vnet_id}" '.virtualNetwork.id == $vnet_id' >/dev/null 2>&1; then
          cluster_vnet_linked=true
        fi
      fi
      
      if [[ "${cluster_vnet_linked}" == "false" ]]; then
        FINDINGS="$(echo "${FINDINGS}" | jq --arg vnet "${vnet_name}" --arg zone "${api_zone}" '. + [{
          severity: "error",
          code: "PDNS_CLUSTER_VNET_LINK_MISSING",
          message: "Cluster VNet \($vnet) with custom DNS servers is not linked to private DNS zone \($zone)",
          recommendation: "Add a virtual network link for VNet \($vnet) to private DNS zone \($zone) to enable proper DNS resolution"
        }]')"
      fi
      
      # Check for DNS servers in peered VNets that need DNS zone links
      for dns_entry in $(echo "${dns_analysis}" | jq -r '.[] | select(.locationType == "peered") | @base64'); do
        if [[ -n "${dns_entry}" ]]; then
          dns_decoded="$(echo "${dns_entry}" | base64 --decode)"
          dns_ip="$(echo "${dns_decoded}" | jq -r '.ip')"
          hosting_vnet="$(echo "${dns_decoded}" | jq -r '.hostingVnet')"
          
          # Find the hosting VNet ID from peering information
          hosting_vnet_id=""
          for peering_info in $(echo "${vnet_decoded}" | jq -r '.peerings[] | @base64' 2>/dev/null); do
            if [[ -n "${peering_info}" ]]; then
              peering_decoded="$(echo "${peering_info}" | base64 --decode)"
              remote_vnet_name="$(echo "${peering_decoded}" | jq -r '.remoteVnetName')"
              
              if [[ "${remote_vnet_name}" == "${hosting_vnet}" ]]; then
                hosting_vnet_id="$(echo "${peering_decoded}" | jq -r '.remoteVnetId')"
                break
              fi
            fi
          done
          
          # Check if the hosting VNet is linked to the private DNS zone
          if [[ -n "${hosting_vnet_id}" ]]; then
            hosting_vnet_linked=false
            if [[ -n "${vnet_links}" ]]; then
              if echo "${vnet_links}" | jq -e --arg vnet_id "${hosting_vnet_id}" '.virtualNetwork.id == $vnet_id' >/dev/null 2>&1; then
                hosting_vnet_linked=true
              fi
            fi
            
            if [[ "${hosting_vnet_linked}" == "false" ]]; then
              FINDINGS="$(echo "${FINDINGS}" | jq --arg dns_ip "${dns_ip}" --arg hosting_vnet "${hosting_vnet}" --arg zone "${api_zone}" --arg cluster_vnet "${vnet_name}" '. + [{
                severity: "error",
                code: "PDNS_DNS_HOST_VNET_LINK_MISSING",
                message: "DNS server \($dns_ip) is hosted in VNet \($hosting_vnet) but this VNet is not linked to private DNS zone \($zone). Cluster VNet \($cluster_vnet) uses this DNS server.",
                recommendation: "Add a virtual network link for VNet \($hosting_vnet) to private DNS zone \($zone) to enable the DNS server to resolve private cluster names"
              }]')"
            fi
          fi
        fi
      done
    done
    
    # Legacy check for backward compatibility
    node_vnet_linked=false
    for vnet_info in $(echo "${VNETS_ANALYSIS}" | jq -r '.[].id'); do
      vnet_name="$(basename "${vnet_info}")"
      if echo "${vnet_links}" | jq -e --arg name "${vnet_name}" '.virtualNetwork.id | contains($name)' >/dev/null 2>&1; then
        node_vnet_linked=true
        break
      fi
    done
    
    if [[ "${node_vnet_linked}" == "false" && "$(echo "${FINDINGS}" | jq '[.[] | select(.code == "PDNS_CLUSTER_VNET_LINK_MISSING")] | length')" -eq 0 ]]; then
      FINDINGS="$(echo "${FINDINGS}" | jq '. + [{
        severity: "warning",
        code: "PDNS_NODE_VNET_LINK_MISSING",
        message: "Private DNS zone may not be linked to node VNets",
        recommendation: "Ensure private DNS zone has virtual network links to all node VNets"
      }]')"
    fi
  fi
fi

# Check for NSG rules that might block essential traffic
for vmss_info in $(echo "${VMSS_ANALYSIS}" | jq -r '.[] | @base64'); do
  vmss_decoded="$(echo "${vmss_info}" | base64 --decode)"
  vmss_name="$(echo "${vmss_decoded}" | jq -r '.name')"
  nsg_analysis="$(echo "${vmss_decoded}" | jq '.networkSecurityGroup')"
  
  if [[ "${nsg_analysis}" != "null" ]]; then
    # Check for rules that might block API server access (443)
    blocking_api_rules="$(echo "${nsg_analysis}" | jq '[
      .securityRules[] | select(
        .direction == "Outbound" and 
        .access == "Deny" and
        (.destinationPortRange | contains("443") or . == "*" or . == "443")
      )
    ]')"
    
    if [[ "$(echo "${blocking_api_rules}" | jq 'length')" -gt 0 ]]; then
      FINDINGS="$(echo "${FINDINGS}" | jq --arg vmss "${vmss_name}" '. + [{
        severity: "warning",
        code: "NSG_BLOCKS_API_ACCESS",
        message: "NSG rules may block API server access (port 443) for VMSS: \($vmss)",
        recommendation: "Review NSG outbound rules to ensure port 443 is allowed for API server communication"
      }]')"
    fi
    
    # Check for rules that might block DNS (53)
    blocking_dns_rules="$(echo "${nsg_analysis}" | jq '[
      .securityRules[] | select(
        .direction == "Outbound" and 
        .access == "Deny" and
        (.destinationPortRange | contains("53") or . == "*" or . == "53")
      )
    ]')"
    
    if [[ "$(echo "${blocking_dns_rules}" | jq 'length')" -gt 0 ]]; then
      FINDINGS="$(echo "${FINDINGS}" | jq --arg vmss "${vmss_name}" '. + [{
        severity: "warning",
        code: "NSG_BLOCKS_DNS_ACCESS",
        message: "NSG rules may block DNS access (port 53) for VMSS: \($vmss)",
        recommendation: "Review NSG outbound rules to ensure port 53 is allowed for DNS resolution"
      }]')"
    fi
  fi
done

# Check for external DNS servers and custom DNS in peered VNets
for vnet_info in $(echo "${VNETS_ANALYSIS}" | jq -r '.[] | @base64'); do
  vnet_decoded="$(echo "${vnet_info}" | base64 --decode)"
  vnet_name="$(echo "${vnet_decoded}" | jq -r '.name')"
  dns_analysis="$(echo "${vnet_decoded}" | jq '.dnsAnalysis')"
  
  # Check for external DNS servers
  external_dns_count="$(echo "${dns_analysis}" | jq '[.[] | select(.locationType == "external")] | length')"
  if [[ "${external_dns_count}" -gt 0 ]]; then
    external_dns_ips="$(echo "${dns_analysis}" | jq -r '[.[] | select(.locationType == "external") | .ip] | join(", ")')"
    FINDINGS="$(echo "${FINDINGS}" | jq --arg vnet "${vnet_name}" --arg ips "${external_dns_ips}" '. + [{
      severity: "info",
      code: "EXTERNAL_DNS_SERVERS",
      message: "VNet \($vnet) uses external DNS servers: \($ips)",
      recommendation: "Ensure external DNS servers are reachable and can resolve private DNS zones if using private clusters"
    }]')"
  fi
  
  # Check for DNS servers in peered VNets (informational)
  peered_dns_count="$(echo "${dns_analysis}" | jq '[.[] | select(.locationType == "peered")] | length')"
  if [[ "${peered_dns_count}" -gt 0 ]]; then
    peered_dns_info="$(echo "${dns_analysis}" | jq -r '[.[] | select(.locationType == "peered") | "\(.ip) (in \(.hostingVnet))"] | join(", ")')"
    FINDINGS="$(echo "${FINDINGS}" | jq --arg vnet "${vnet_name}" --arg info "${peered_dns_info}" '. + [{
      severity: "info",
      code: "PEERED_VNET_DNS_SERVERS",
      message: "VNet \($vnet) uses DNS servers in peered VNets: \($info)",
      recommendation: "Ensure that peered VNets hosting DNS servers are properly linked to private DNS zones for correct resolution"
    }]')"
  fi
done

# Step 9: Generate comprehensive JSON report
echo "Generating comprehensive report..."

# Ensure all JSON variables are properly initialized before final report generation
echo "Validating JSON variables before report generation..."

# Check and fix any null or malformed JSON variables
if [[ -z "${VNETS_ANALYSIS}" || "${VNETS_ANALYSIS}" == "null" ]]; then
  VNETS_ANALYSIS="[]"
fi

if [[ -z "${OUTBOUND_IPS}" || "${OUTBOUND_IPS}" == "null" ]]; then
  OUTBOUND_IPS="[]"
fi

if [[ -z "${OUTBOUND_ANALYSIS}" || "${OUTBOUND_ANALYSIS}" == "null" ]]; then
  OUTBOUND_ANALYSIS="{}"
fi

if [[ -z "${PRIVATE_DNS_ANALYSIS}" || "${PRIVATE_DNS_ANALYSIS}" == "null" ]]; then
  PRIVATE_DNS_ANALYSIS="{}"
fi

if [[ -z "${VMSS_ANALYSIS}" || "${VMSS_ANALYSIS}" == "null" ]]; then
  VMSS_ANALYSIS="[]"
fi

if [[ -z "${API_PROBE_RESULTS}" || "${API_PROBE_RESULTS}" == "null" ]]; then
  API_PROBE_RESULTS="null"
fi

if [[ -z "${FAILURE_ANALYSIS}" || "${FAILURE_ANALYSIS}" == "null" ]]; then
  FAILURE_ANALYSIS="{\"enabled\": false}"
fi

if [[ -z "${FINDINGS}" || "${FINDINGS}" == "null" ]]; then
  FINDINGS="[]"
fi

FINAL_REPORT="$(jq -n \
  --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
  --arg aksName "${AKS_NAME}" \
  --arg resourceGroup "${AKS_RG}" \
  --arg subscription "${CURRENT_SUB}" \
  --arg provisioningState "${PROVISIONING_STATE}" \
  --arg location "${LOCATION}" \
  --arg nodeResourceGroup "${NODE_RG}" \
  --arg networkPlugin "${NETWORK_PLUGIN}" \
  --arg serviceCidr "${SERVICE_CIDR}" \
  --arg dnsServiceIp "${DNS_SERVICE_IP}" \
  --arg podCidr "${POD_CIDR}" \
  --arg outboundType "${OUTBOUND_TYPE}" \
  --arg privateClusterEnabled "${PRIVATE_CLUSTER_ENABLED}" \
  --arg privateDnsZone "${PRIVATE_DNS_ZONE}" \
  --argjson authorizedIpRanges "${AUTHORIZED_IP_RANGES}" \
  --arg apiServerVnetIntegration "${API_SERVER_VNET_INTEGRATION_ENABLED}" \
  --arg vnetIntegrationSubnet "${VNET_INTEGRATION_SUBNET_ID}" \
  --arg publicFqdn "${PUBLIC_FQDN}" \
  --arg privateFqdn "${PRIVATE_FQDN}" \
  --argjson vnets "${VNETS_ANALYSIS}" \
  --argjson outboundIps "${OUTBOUND_IPS}" \
  --argjson outboundAnalysis "${OUTBOUND_ANALYSIS}" \
  --argjson privateDns "${PRIVATE_DNS_ANALYSIS}" \
  --argjson vmssAnalysis "${VMSS_ANALYSIS}" \
  --argjson apiProbe "${API_PROBE_RESULTS}" \
  --argjson failureAnalysis "${FAILURE_ANALYSIS}" \
  --argjson findings "${FINDINGS}" \
  '{
    metadata: {
      timestamp: $timestamp,
      version: "2.0",
      generatedBy: "AKS Network Diagnostics Script"
    },
    cluster: {
      name: $aksName,
      resourceGroup: $resourceGroup,
      subscription: $subscription,
      provisioningState: $provisioningState,
      location: $location,
      nodeResourceGroup: $nodeResourceGroup,
      networkProfile: {
        networkPlugin: $networkPlugin,
        serviceCidr: $serviceCidr,
        dnsServiceIp: $dnsServiceIp,
        podCidr: $podCidr,
        outboundType: $outboundType
      },
      apiServerAccess: {
        privateClusterEnabled: ($privateClusterEnabled == "true"),
        privateDnsZone: $privateDnsZone,
        authorizedIpRanges: $authorizedIpRanges,
        vnetIntegrationEnabled: ($apiServerVnetIntegration == "true"),
        vnetIntegrationSubnetId: $vnetIntegrationSubnet,
        publicFqdn: $publicFqdn,
        privateFqdn: $privateFqdn
      }
    },
    networking: {
      vnets: $vnets,
      outbound: {
        type: $outboundType,
        effectivePublicIPs: $outboundIps,
        analysis: $outboundAnalysis
      },
      privateDns: $privateDns,
      vmssConfiguration: $vmssAnalysis
    },
    diagnostics: {
      apiConnectivityProbe: $apiProbe,
      failureAnalysis: $failureAnalysis,
      findings: $findings
    }
  }')"

# Step 10: Generate output
echo
echo "=========================================================================="

if [[ "${VERBOSE}" -eq 1 ]]; then
  # Detailed Markdown output
  echo "# AKS Network Assessment Report"
  echo
  echo "**Cluster:** ${AKS_NAME}"
  echo "**Resource Group:** ${AKS_RG}"
  echo "**Subscription:** ${CURRENT_SUB}"
  echo "**Generated:** $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
  echo

  echo "## Cluster Overview"
  echo
  echo "| Property | Value |"
  echo "|----------|-------|"
echo "| Provisioning State | ${PROVISIONING_STATE} |"
echo "| Location | ${LOCATION} |"
echo "| Network Plugin | ${NETWORK_PLUGIN} |"
echo "| Outbound Type | ${OUTBOUND_TYPE} |"
echo "| Private Cluster | ${PRIVATE_CLUSTER_ENABLED} |"
echo "| API Server VNet Integration | ${API_SERVER_VNET_INTEGRATION_ENABLED} |"
echo

echo "## Network Configuration"
echo
echo "### Service Network"
echo "- **Service CIDR:** ${SERVICE_CIDR}"
echo "- **DNS Service IP:** ${DNS_SERVICE_IP}"
echo "- **Pod CIDR:** ${POD_CIDR}"
echo

echo "### API Server Access"
if [[ "${PRIVATE_CLUSTER_ENABLED}" == "true" ]]; then
  echo "- **Type:** Private cluster"
  echo "- **Private FQDN:** ${PRIVATE_FQDN}"
  echo "- **Private DNS Zone:** ${PRIVATE_DNS_ZONE}"
else
  echo "- **Type:** Public cluster"
  echo "- **Public FQDN:** ${PUBLIC_FQDN}"
fi

if [[ "$(echo "${AUTHORIZED_IP_RANGES}" | jq 'length')" -gt 0 ]]; then
  echo "- **Authorized IP Ranges:**"
  echo "${AUTHORIZED_IP_RANGES}" | jq -r '.[] | "  - " + .'
fi
echo

# Add failure analysis section if cluster is in Failed state
if [[ "${PROVISIONING_STATE}" == "Failed" ]] && [[ "$(echo "${FAILURE_ANALYSIS}" | jq '.enabled')" == "true" ]]; then
  echo "## ⚠️ Cluster Failure Analysis"
  echo
  echo "The cluster is in **Failed** provisioning state. Analysis of recent failures:"
  echo
  
  # Recent failed operations
  if [[ "$(echo "${FAILURE_ANALYSIS}" | jq '.recentFailures | length')" -gt 0 ]]; then
    echo "### Recent Failed Operations"
    echo "$(echo "${FAILURE_ANALYSIS}" | jq -r '.recentFailures[] | "- **" + .timestamp + "** - " + .operationName + ": " + .status')"
    echo
  fi
  
  # Network-related failures
  if [[ "$(echo "${FAILURE_ANALYSIS}" | jq '.networkRelatedFailures | length')" -gt 0 ]]; then
    echo "### 🔗 Network-Related Failures"
    echo "$(echo "${FAILURE_ANALYSIS}" | jq -r '.networkRelatedFailures[] | "- **" + .operationName + "** (" + .timestamp + ")"')"
    echo
  fi
  
  # Node pool status
  if [[ "$(echo "${FAILURE_ANALYSIS}" | jq '.nodePoolStatus | length')" -gt 0 ]]; then
    echo "### Node Pool Status"
    echo "| Node Pool | Provisioning State | Power State |"
    echo "|-----------|-------------------|-------------|"
    echo "$(echo "${FAILURE_ANALYSIS}" | jq -r '.nodePoolStatus[] | "| " + .name + " | " + .provisioningState + " | " + .powerState + " |"')"
    echo
  fi
fi

echo "### Outbound Connectivity"
echo "- **Outbound Type:** ${OUTBOUND_TYPE}"
echo "- **Effective Public IPs:**"
if [[ "$(echo "${OUTBOUND_IPS}" | jq 'length')" -gt 0 ]]; then
  echo "${OUTBOUND_IPS}" | jq -r '.[] | "  - " + .'
else
  echo "  - None (UDR or configuration issue)"
fi
echo

echo "### Virtual Networks"
for vnet_info in $(echo "${VNETS_ANALYSIS}" | jq -r '.[] | @base64'); do
  vnet_decoded="$(echo "${vnet_info}" | base64 --decode)"
  vnet_name="$(echo "${vnet_decoded}" | jq -r '.name')"
  vnet_cidrs="$(echo "${vnet_decoded}" | jq -r '.addressSpace | join(", ")')"
  dns_servers="$(echo "${vnet_decoded}" | jq -r '.dnsServers')"
  
  echo "#### VNet: ${vnet_name}"
  echo "- **Address Space:** ${vnet_cidrs}"
  
  if [[ "$(echo "${dns_servers}" | jq 'length')" -gt 0 ]]; then
    echo "- **Custom DNS Servers:**"
    echo "${dns_servers}" | jq -r '.[] | "  - " + .'
    
    # Show DNS analysis with location details
    echo "- **DNS Server Analysis:**"
    echo "${vnet_decoded}" | jq -r '.dnsAnalysis[] | if .locationType == "local" then "  - \(.ip): Local (in same VNet)" elif .locationType == "peered" then "  - \(.ip): Peered VNet (\(.hostingVnet))" else "  - \(.ip): External" end'
  else
    echo "- **DNS:** Azure default"
  fi
  
  # Show peerings
  peering_count="$(echo "${vnet_decoded}" | jq '.peerings | length')"
  if [[ "${peering_count}" -gt 0 ]]; then
    echo "- **VNet Peerings:** ${peering_count}"
    echo "${vnet_decoded}" | jq -r '.peerings[] | "  - \(.name) → \(.remoteVnetName) (\(.peeringState))"'
  fi
  echo
done

echo "## Security Analysis"
echo
echo "### Network Security Groups"
for vmss_info in $(echo "${VMSS_ANALYSIS}" | jq -r '.[] | @base64'); do
  vmss_decoded="$(echo "${vmss_info}" | base64 --decode)"
  vmss_name="$(echo "${vmss_decoded}" | jq -r '.name')"
  nsg_analysis="$(echo "${vmss_decoded}" | jq '.networkSecurityGroup')"
  
  if [[ "${nsg_analysis}" != "null" ]]; then
    nsg_name="$(echo "${nsg_analysis}" | jq -r '.name')"
    echo "#### VMSS: ${vmss_name}"
    echo "- **NSG:** ${nsg_name}"
    
    # Show relevant rules
    api_rules_count="$(echo "${nsg_analysis}" | jq '.relevantRules.apiServer | length')"
    dns_rules_count="$(echo "${nsg_analysis}" | jq '.relevantRules.dns | length')"
    
    echo "- **Rules affecting API Server (443):** ${api_rules_count}"
    echo "- **Rules affecting DNS (53):** ${dns_rules_count}"
    echo
  fi
done

echo "### Route Tables"
for vmss_info in $(echo "${VMSS_ANALYSIS}" | jq -r '.[] | @base64'); do
  vmss_decoded="$(echo "${vmss_info}" | base64 --decode)"
  vmss_name="$(echo "${vmss_decoded}" | jq -r '.name')"
  rt_analysis="$(echo "${vmss_decoded}" | jq '.routeTable')"
  
  if [[ "${rt_analysis}" != "null" ]]; then
    rt_name="$(echo "${rt_analysis}" | jq -r '.name')"
    routes_count="$(echo "${rt_analysis}" | jq '.routes | length')"
    default_route="$(echo "${rt_analysis}" | jq '.defaultRoute')"
    
    echo "#### VMSS: ${vmss_name}"
    echo "- **Route Table:** ${rt_name}"
    echo "- **Total Routes:** ${routes_count}"
    
    if [[ "${default_route}" != "null" ]]; then
      next_hop_type="$(echo "${default_route}" | jq -r '.nextHopType')"
      next_hop_ip="$(echo "${default_route}" | jq -r '.nextHopIpAddress // "N/A"')"
      echo "- **Default Route:** ${next_hop_type} (${next_hop_ip})"
    else
      echo "- **Default Route:** Not configured"
    fi
    echo
  fi
done

if [[ ${PROBE_API} -eq 1 && "${API_PROBE_RESULTS}" != "null" ]]; then
  echo "## API Connectivity Probe Results"
  echo
  target_fqdn="$(echo "${API_PROBE_RESULTS}" | jq -r '.targetFqdn')"
  vmss_name="$(echo "${API_PROBE_RESULTS}" | jq -r '.vmssName')"
  exit_code="$(echo "${API_PROBE_RESULTS}" | jq -r '.exitCode')"
  
  echo "- **Target FQDN:** ${target_fqdn}"
  echo "- **Tested from VMSS:** ${vmss_name}"
  echo "- **Exit Code:** ${exit_code}"
  echo
  echo "### Probe Output"
  echo '```'
  echo "${API_PROBE_RESULTS}" | jq -r '.output'
  echo '```'
  echo
fi

echo "## Findings and Recommendations"
echo
findings_count="$(echo "${FINDINGS}" | jq 'length')"
if [[ "${findings_count}" -gt 0 ]]; then
  echo "${FINDINGS}" | jq -r '.[] | "### \(.severity | ascii_upcase): \(.code)\n\n**Issue:** \(.message)\n\n**Recommendation:** \(.recommendation)\n"'
else
  echo "✅ No issues detected in the current configuration."
  echo
fi

echo "## Next Steps & Documentation"
echo
echo "### Microsoft Learn Resources"
echo "- [AKS Outbound Types Overview](https://learn.microsoft.com/azure/aks/egress-outboundtype)"
echo "- [Private AKS Clusters](https://learn.microsoft.com/azure/aks/private-clusters)"
echo "- [Private DNS Zones](https://learn.microsoft.com/azure/dns/private-dns-overview)"
echo "- [User-Defined Routes](https://learn.microsoft.com/azure/virtual-network/virtual-networks-udr-overview)"
echo "- [NAT Gateway](https://learn.microsoft.com/azure/virtual-network/nat-gateway/)"
echo "- [Network Security Groups](https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview)"
echo "- [Effective Security Rules](https://learn.microsoft.com/azure/virtual-network/diagnose-network-traffic-filtering-problem)"
echo "- [AKS Network Concepts](https://learn.microsoft.com/azure/aks/concepts-network)"
echo

else
  # Summary output for non-verbose mode
  echo "# AKS Network Assessment Summary"
  echo
  echo "**Cluster:** ${AKS_NAME} (${PROVISIONING_STATE})"
  echo "**Resource Group:** ${AKS_RG}"
  echo "**Generated:** $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
  echo
  
  # Show key configuration
  echo "**Configuration:**"
  echo "- Network Plugin: ${NETWORK_PLUGIN}"
  echo "- Outbound Type: ${OUTBOUND_TYPE}"
  echo "- Private Cluster: ${PRIVATE_CLUSTER_ENABLED}"
  if [[ "${PRIVATE_CLUSTER_ENABLED}" == "true" ]]; then
    echo "- Private DNS Zone: ${PRIVATE_DNS_ZONE}"
  fi
  echo
  
  # Show outbound IPs if available
  if [[ "$(echo "${OUTBOUND_IPS}" | jq 'length')" -gt 0 ]]; then
    echo "**Outbound IPs:**"
    echo "${OUTBOUND_IPS}" | jq -r '.[] | "- " + .'
    echo
  fi
  
  # Show failure analysis summary if cluster is failed
  if [[ "${PROVISIONING_STATE}" == "Failed" ]] && [[ "$(echo "${FAILURE_ANALYSIS}" | jq '.enabled')" == "true" ]]; then
    echo "**⚠️ Cluster Failure Summary:**"
    if [[ "$(echo "${FAILURE_ANALYSIS}" | jq '.networkRelatedFailures | length')" -gt 0 ]]; then
      echo "- Network-related failures detected"
      primary_error="$(echo "${FAILURE_ANALYSIS}" | jq -r '.networkRelatedFailures[0].error' 2>/dev/null | jq -r '.error.details[0].code // .error.code // "Unknown"' 2>/dev/null || echo "Unknown")"
      echo "- Primary error: ${primary_error}"
    fi
    if [[ "$(echo "${FAILURE_ANALYSIS}" | jq '.nodePoolStatus | length')" -gt 0 ]]; then
      failed_pools="$(echo "${FAILURE_ANALYSIS}" | jq -r '.nodePoolStatus[] | select(.provisioningState == "Failed") | .name' | tr '\n' ' ')"
      if [[ -n "${failed_pools}" ]]; then
        echo "- Failed node pools: ${failed_pools}"
      fi
    fi
    echo
  fi
  
  # Show findings summary
  critical_count=$(echo "${FINDINGS}" | jq '[.[] | select(.severity == "critical" or .severity == "error")] | length')
  warning_count=$(echo "${FINDINGS}" | jq '[.[] | select(.severity == "warning")] | length')
  info_count=$(echo "${FINDINGS}" | jq '[.[] | select(.severity == "info")] | length')
  
  echo "**Findings Summary:**"
  if [[ "${critical_count}" -gt 0 ]]; then
    echo "- 🔴 ${critical_count} Critical/Error issue(s)"
  fi
  if [[ "${warning_count}" -gt 0 ]]; then
    echo "- 🟡 ${warning_count} Warning(s)"
  fi
  if [[ "${info_count}" -gt 0 ]]; then
    echo "- ℹ️ ${info_count} Informational finding(s)"
  fi
  
  if [[ "${critical_count}" -eq 0 && "${warning_count}" -eq 0 ]]; then
    echo "- ✅ No critical issues detected"
  fi
  echo
  
  # Show top critical findings
  if [[ "${critical_count}" -gt 0 ]]; then
    echo "**Critical Issues:**"
    echo "${FINDINGS}" | jq -r '.[] | select(.severity == "critical" or .severity == "error") | "- " + .code + ": " + .message' | head -3
    echo
  fi
  
  # Show API connectivity probe results if performed
  if [[ ${PROBE_API} -eq 1 && "${API_PROBE_RESULTS}" != "null" ]]; then
    echo "**🔍 API Connectivity Probe Results:**"
    target_fqdn="$(echo "${API_PROBE_RESULTS}" | jq -r '.targetFqdn')"
    vmss_name="$(echo "${API_PROBE_RESULTS}" | jq -r '.vmssName')"
    exit_code="$(echo "${API_PROBE_RESULTS}" | jq -r '.exitCode')"
    
    echo "- Target: ${target_fqdn}"
    echo "- Tested from: ${vmss_name}"
    if [[ "${exit_code}" == "0" ]]; then
      echo "- Result: ✅ SUCCESS (exit code: ${exit_code})"
    else
      echo "- Result: ❌ FAILED (exit code: ${exit_code})"
    fi
    echo "- Tip: Use --verbose for detailed probe output"
    echo
  fi
  
  echo "💡 **Tip:** Use --verbose flag for detailed analysis or check the JSON report for complete findings."
  echo
fi

# Output JSON report
if [[ "${NO_JSON}" -eq 0 ]]; then
  echo "${FINAL_REPORT}" > "${JSON_OUT}"
  echo "📄 JSON report saved to: ${JSON_OUT}"
  echo
fi

echo "✅ AKS network assessment completed successfully!"