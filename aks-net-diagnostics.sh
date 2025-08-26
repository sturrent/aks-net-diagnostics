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
  --json-out <FILE>       Output JSON report to file
  --cache                 Cache Azure CLI responses for faster re-runs
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
  $0 -n my-cluster -g my-rg --probe-api --json-out report.json

EOF
}

# Global variables
AKS_NAME=""
AKS_RG=""
SUB_ID=""
PROBE_API=0
JSON_OUT=""
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
    .[] | select(.cidrs[] | . as $cidr | 
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
    
    # DNS analysis (simplified for now)
    dns_analysis="[]"
    if [[ "$(echo "${vnet_dns_servers}" | jq '. | length')" -gt 0 ]]; then
      for dns_ip in $(echo "${vnet_dns_servers}" | jq -r '.[]'); do
        # Simplified DNS analysis - just mark as external for now
        dns_analysis="$(echo "${dns_analysis}" | jq --arg ip "${dns_ip}" '. + [{ip: $ip, locationType: "external", hostingVnet: ""}]')"
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
    LBS_JSON="$(azc network lb list -g "${NODE_RG}")"
    
    # Extract public IPs from outbound rules
    OUTBOUND_IP_IDS="$(echo "${LBS_JSON}" | jq -r '
      [.[] | .outboundRules[]? | .frontendIpConfigurations[]?.publicIpAddress.id] | 
      map(select(.!=null)) | unique | .[]')"
    
    if [[ -n "${OUTBOUND_IP_IDS}" ]]; then
      while IFS= read -r ip_id; do
        if [[ -n "${ip_id}" ]]; then
          ip_details="$(azc network public-ip show --ids "${ip_id}")"
          ip_address="$(echo "${ip_details}" | jq -r '.ipAddress // empty')"
          if [[ -n "${ip_address}" ]]; then
            OUTBOUND_IPS="$(echo "${OUTBOUND_IPS}" | jq ". + [\"${ip_address}\"]")"
          fi
        fi
      done <<< "${OUTBOUND_IP_IDS}"
    fi
    
    OUTBOUND_ANALYSIS="$(echo "${LBS_JSON}" | jq '{
      type: "loadBalancer",
      loadBalancers: [.[] | {
        name: .name,
        sku: .sku.name,
        outboundRules: [.outboundRules[]? | {
          name: .name,
          frontendIpConfigurations: [.frontendIpConfigurations[]? | .publicIpAddress.id]
        }]
      }]
    }')"
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
VMSS_LIST="$(azc vmss list -g "${NODE_RG}")"
VMSS_ANALYSIS="[]"

echo "${VMSS_LIST}" | jq -r '.[].name' | while IFS= read -r vmss_name; do
  if [[ -n "${vmss_name}" ]]; then
    vmss_json="$(azc vmss show -g "${NODE_RG}" -n "${vmss_name}")"
    
    # Get NIC configuration
    nic_config="$(echo "${vmss_json}" | jq '.virtualMachineProfile.networkProfile.networkInterfaceConfigurations[0]')"
    subnet_id="$(echo "${nic_config}" | jq -r '.ipConfigurations[0].subnet.id')"
    
    # Analyze subnet's NSG and route table
    subnet_json="$(azc network vnet subnet show --ids "${subnet_id}")"
    nsg_id="$(echo "${subnet_json}" | jq -r '.networkSecurityGroup.id // empty')"
    rt_id="$(echo "${subnet_json}" | jq -r '.routeTable.id // empty')"
    
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
    }')"
    
    VMSS_ANALYSIS="$(echo "${VMSS_ANALYSIS}" | jq --argjson vmss "${vmss_info}" '. + [$vmss]')"
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
  
  # Check VNet links for custom DNS
  if [[ "$(echo "${VNETS_ANALYSIS}" | jq '[.[] | select(.dnsServers | length > 0)] | length')" -gt 0 ]]; then
    # Custom DNS servers are configured, check VNet links
    node_vnet_linked=false
    
    vnet_links="$(echo "${PRIVATE_DNS_ANALYSIS}" | jq -r '.vnetLinks[] // empty')"
    
    # Check if node VNets are linked
    for vnet_info in $(echo "${VNETS_ANALYSIS}" | jq -r '.[].id'); do
      vnet_name="$(basename "${vnet_info}")"
      if echo "${vnet_links}" | jq -e --arg name "${vnet_name}" '.virtualNetwork.id | contains($name)' >/dev/null 2>&1; then
        node_vnet_linked=true
        break
      fi
    done
    
    if [[ "${node_vnet_linked}" == "false" ]]; then
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

# Check for external DNS servers without clear forwarding path
for vnet_info in $(echo "${VNETS_ANALYSIS}" | jq -r '.[] | @base64'); do
  vnet_decoded="$(echo "${vnet_info}" | base64 --decode)"
  vnet_name="$(echo "${vnet_decoded}" | jq -r '.name')"
  dns_analysis="$(echo "${vnet_decoded}" | jq '.dnsAnalysis')"
  
  external_dns_count="$(echo "${dns_analysis}" | jq '[.[] | select(.locationType == "external")] | length')"
  if [[ "${external_dns_count}" -gt 0 ]]; then
    FINDINGS="$(echo "${FINDINGS}" | jq --arg vnet "${vnet_name}" '. + [{
      severity: "info",
      code: "EXTERNAL_DNS_SERVERS",
      message: "VNet \($vnet) uses external DNS servers",
      recommendation: "Ensure external DNS servers are reachable and can resolve private DNS zones if using private clusters"
    }]')"
  fi
done

# Step 9: Generate comprehensive JSON report
echo "Generating comprehensive report..."

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
      findings: $findings
    }
  }')"

# Step 10: Generate Markdown output
echo
echo "=========================================================================="
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
    
    # Show DNS analysis
    echo "- **DNS Server Analysis:**"
    echo "${vnet_decoded}" | jq -r '.dnsAnalysis[] | "  - \(.ip): \(.locationType)" + (if .hostingVnet != "" then " (in \(.hostingVnet))" else "" end)'
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

# Output JSON report
if [[ -n "${JSON_OUT}" ]]; then
  echo "${FINAL_REPORT}" > "${JSON_OUT}"
  echo "📄 JSON report saved to: ${JSON_OUT}"
else
  echo "## JSON Report"
  echo
  echo '```json'
  echo "${FINAL_REPORT}" | jq '.'
  echo '```'
fi

echo
echo "✅ AKS network assessment completed successfully!"