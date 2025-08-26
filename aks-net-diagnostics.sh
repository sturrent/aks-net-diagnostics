#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<EOF
Usage: $0 -n <AKS_NAME> -g <AKS_RG> [--subscription <SUB_ID>] [--probe-api] [--json-out <file>] [--cache]
Read-only AKS network assessment with Azure CLI + jq.
EOF
}

AKS_NAME=""; AKS_RG=""; SUB_ID=""; PROBE_API=0; JSON_OUT=""; CACHE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    -n) AKS_NAME="$2"; shift 2;;
    -g) AKS_RG="$2"; shift 2;;
    --subscription) SUB_ID="$2"; shift 2;;
    --probe-api) PROBE_API=1; shift;;
    --json-out) JSON_OUT="$2"; shift 2;;
    --cache) CACHE=1; shift;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2;;
  esac
done
[[ -z "${AKS_NAME}" || -z "${AKS_RG}" ]] && { echo "Missing -n/-g"; usage; exit 2; }

command -v az >/dev/null || { echo "Azure CLI (az) is required"; exit 1; }
command -v jq >/dev/null || { echo "jq is required"; exit 1; }
if [[ -n "${SUB_ID}" ]]; then az account set -s "${SUB_ID}"; fi

# Simple cache helper
CACHE_DIR="${TMPDIR:-/tmp}/aks-net-check-${AKS_NAME}"
mkdir -p "${CACHE_DIR}"
azc() {
  local key="$(echo "$*" | sed 's#[^a-zA-Z0-9._-]#_#g')"
  local file="${CACHE_DIR}/${key}.json"
  if [[ ${CACHE} -eq 1 && -s "${file}" ]]; then cat "${file}"
  else az "$@" -o json | tee "${file}" >/dev/null; fi
}

# 1) Cluster facts
CLUSTER_JSON="$(azc aks show -g "${AKS_RG}" -n "${AKS_NAME}")" || { echo "Cluster not found or access denied"; exit 3; }
STATE="$(echo "${CLUSTER_JSON}" | jq -r '.provisioningState // "unknown"')"
LOC="$(echo "${CLUSTER_JSON}" | jq -r '.location')"
NODE_RG="$(echo "${CLUSTER_JSON}" | jq -r '.nodeResourceGroup')"
OUT_TYPE="$(echo "${CLUSTER_JSON}" | jq -r '.networkProfile.outboundType // "loadBalancer"')"
NET_PLUGIN="$(echo "${CLUSTER_JSON}" | jq -r '.networkProfile.networkPlugin // "unknown"')"
PRIVATE_ENABLED="$(echo "${CLUSTER_JSON}" | jq -r '.apiServerAccessProfile.enablePrivateCluster // false')"
PDNS_MODE="$(echo "${CLUSTER_JSON}" | jq -r '.apiServerAccessProfile.privateDNSZone // "System"')"
PUB_FQDN="$(echo "${CLUSTER_JSON}" | jq -r '.fqdn // empty')"
PRIV_FQDN="$(echo "${CLUSTER_JSON}" | jq -r '.privateFqdn // empty')"

# 2) Agent pool subnets → VNETs
AP_POOLS="$(azc aks nodepool list -g "${AKS_RG}" --cluster-name "${AKS_NAME}")"
SUBNET_IDS="$(echo "${AP_POOLS}" | jq -r '.[].vnetSubnetId | select(.!=null)' | sort -u)"
declare -A VNETS
for SUB in ${SUBNET_IDS}; do
  SUB_JSON="$(azc network vnet subnet show --ids "${SUB}")"
  VNET_ID="$(echo "${SUB_JSON}" | jq -r '.id' | sed 's#/subnets/[^/]*$##')"
  VNETS["${VNET_ID}"]=1
done

# 3) VNET details (+ DNS, NSG, RT, NATGW)
VNET_REPORT="[]"
for VNET_ID in "${!VNETS[@]}"; do
  VJ="$(azc network vnet show --ids "${VNET_ID}")"
  NAME="$(echo "${VJ}" | jq -r '.name')"
  CIDRS="$(echo "${VJ}" | jq -r '.addressSpace.addressPrefixes')"
  DNS_SERVERS="$(echo "${VJ}" | jq -r '.dhcpOptions.dnsServers // []')"
  PEERS="$(azc network vnet peering list --ids "${VNET_ID}" | jq '[.[] | {name, remoteAddressSpace: .remoteAddressSpace.addressPrefixes, remoteVnetId: .remoteVirtualNetwork.id}]')"
  VNET_REPORT="$(jq -n --argjson rep "${VNET_REPORT}" --arg id "${VNET_ID}" --arg name "${NAME}" \
    --argjson cidrs "${CIDRS}" --argjson dns "${DNS_SERVERS}" --argjson peers "${PEERS}" \
    '$rep + [{id:$id,name:$name,cidrs:$cidrs,dnsServers:$dns,peerings:$peers}]')"
done

# 4) Outbound effective IPs
OUTBOUND_IPS="[]"
case "${OUT_TYPE}" in
  loadBalancer)
    # Look for LB in node RG with outbound rules
    LBS="$(azc network lb list -g "${NODE_RG}")"
    # naive pick: any outboundRule with public IPs
    OUTBOUND_IPS="$(echo "${LBS}" | jq '[.[] | . as $lb | ($lb | .outboundRules[]? | .frontendIpConfigurations[]?.publicIpAddress.id) ] | map(select(.!=null)) | unique | .[]? | @sh' | xargs -r -n1 azc network public-ip show --ids | jq -s '[.[].ipAddress]')"
    ;;
  managedNATGateway|userAssignedNATGateway)
    # From subnets: natGateway.id -> publicIPs/publicIPPrefixes
    NAT_IDS="$(for SUB in ${SUBNET_IDS}; do azc network vnet subnet show --ids "${SUB}" | jq -r '.natGateway.id // empty'; done | sort -u)"
    OUTBOUND_IPS="$(for N in ${NAT_IDS}; do azc network nat gateway show --ids "${N}" | jq -r '.publicIpAddresses[]?.id, .publicIpPrefixes[]?.id'; done \
      | xargs -r -n1 azc network public-ip show --ids | jq -s '[.[].ipAddress]')"
    ;;
  userDefinedRouting)
    # Check UDR on subnet for 0.0.0.0/0
    ROUTE_NEXT_HOPS="$(for SUB in ${SUBNET_IDS}; do
      SJ="$(azc network vnet subnet show --ids "${SUB}")"
      RT_ID="$(echo "${SJ}" | jq -r '.routeTable.id // empty')"
      if [[ -n "${RT_ID}" ]]; then azc network route-table route list --route-table-name "$(basename "${RT_ID}")" -g "$(echo "${RT_ID}" | awk -F/ '{print $5}')" \
        | jq -r '.[] | select(.addressPrefix=="0.0.0.0/0") | "\(.nextHopType) \(.nextHopIpAddress // "")"';
      fi
    done)"
    OUTBOUND_IPS="[]"
    ;;
esac

# 5) Private DNS validation (only if private cluster)
PDNS_REPORT="null"
if [[ "${PRIVATE_ENABLED}" == "true" ]]; then
  # Detect zone & record for the private FQDN
  if [[ "${PDNS_MODE}" == "System" ]]; then
    # Heuristic: PDNS lives in node RG; find zone ending with .privatelink.${LOC}.azmk8s.io
    ZONES="$(azc network private-dns zone list -g "${NODE_RG}")"
  else
    ZONES="$(azc network private-dns zone show --ids "${PDNS_MODE}" | jq -s '.')"
  fi
  API_FQDN="${PRIV_FQDN}"
  # A record look-up
  RECORD_IP="$(echo "${ZONES}" | jq -r --arg name "${API_FQDN%%.*}" --arg zone "${API_FQDN#*.}" \
    '.. | objects | select(.name?==$zone and .type?=="Microsoft.Network/privateDnsZones") as $z
     | $z | $z.name as $zn | $zn | . and empty' 2>/dev/null || true)"
  # Fallback: enumerate all A records and match FQDN
  RECSETS="$(echo "${ZONES}" | jq -r '.[].name' | xargs -r -I{} azc network private-dns record-set a list -g "${NODE_RG:-IGNORED}" -z {} | jq -s 'add')"
  RECORD_IP="$(echo "${RECSETS}" | jq -r --arg fqdn "${API_FQDN}." '.[] | select(.fqdn==$fqdn) | .arecords[0].ipv4Address // empty')"

  # Private endpoint IP for control plane
  PEs="$(azc network private-endpoint list -g "${NODE_RG}")"
  PE_IP="$(echo "${PEs}" | jq -r '.[] | select(.privateLinkServiceConnections[]?.groupIds[]?=="management") 
         | .networkInterfaces[0].ipConfigurations[0].privateIPAddress' | head -n1)"

  # VNet links
  LINKS="$(echo "${ZONES}" | jq -r '.[].name' | xargs -r -I{} azc network private-dns link vnet list -g "${NODE_RG:-IGNORED}" -z {} | jq -s 'add')"

  PDNS_REPORT="$(jq -n --arg mode "${PDNS_MODE}" --arg apiFqdn "${API_FQDN}" --arg recordIp "${RECORD_IP:-}" --arg peIp "${PE_IP:-}" \
    --argjson links "${LINKS:-[]}" '{mode:$mode, apiFqdn:$apiFqdn, recordIp:$recordIp, privateEndpointIp:$peIp, links:$links}')"
fi

# 6) Optional: API probe via VMSS run-command
API_PROBE="null"
if [[ ${PROBE_API} -eq 1 && -n "${PRIV_FQDN}${PUB_FQDN}" ]]; then
  VMSS="$(azc vmss list -g "${NODE_RG}" | jq -r '.[0].name // empty')"
  if [[ -n "${VMSS}" ]]; then
    CMD="set -e; which nslookup >/dev/null 2>&1 && nslookup ${PRIV_FQDN:-$PUB_FQDN} || true; (command -v nc >/dev/null && nc -vz ${PRIV_FQDN:-$PUB_FQDN} 443 -w 5) || true"
    OUT="$(az vmss run-command invoke -g "${NODE_RG}" -n "${VMSS}" --command-id RunShellScript --scripts "${CMD}" -o json || true)"
    API_PROBE="$(echo "${OUT}" | jq '{code:.status, message:(.value[0].message // "")}')"
  fi
fi

# 7) Findings & Markdown/JSON output (truncate for brevity)
FINDINGS="[]"
if [[ "${OUT_TYPE}" == "userDefinedRouting" && -z "${ROUTE_NEXT_HOPS}" ]]; then
  FINDINGS="$(jq -n --argjson f "${FINDINGS}" '$f + [{severity:"error",code:"UDR_NoDefaultRoute",message:"OutboundType is userDefinedRouting but no 0.0.0.0/0 route found"}]')"
fi
if [[ "${PRIVATE_ENABLED}" == "true" && -n "${PE_IP:-}" && -n "${RECORD_IP:-}" && "${PE_IP}" != "${RECORD_IP}" ]]; then
  FINDINGS="$(jq -n --argjson f "${FINDINGS}" --arg pe "${PE_IP}" --arg rec "${RECORD_IP}" \
    '$f + [{severity:"error",code:"PDNS_A_Record_Mismatch",message:"Private DNS A record does not match Private Endpoint IP", details:{privateEndpointIp:$pe, aRecord:$rec}}]')"
fi

REPORT="$(jq -n \
  --arg state "${STATE}" --arg location "${LOC}" --arg nodeRg "${NODE_RG}" --arg outType "${OUT_TYPE}" --arg netPlugin "${NET_PLUGIN}" \
  --argjson vnets "${VNET_REPORT}" --argjson outboundIps "${OUTBOUND_IPS:-[]}" --argjson pdns "${PDNS_REPORT}" --argjson probe "${API_PROBE}" --argjson findings "${FINDINGS}" \
  '{cluster:{state:$state, location:$location, nodeResourceGroup:$nodeRg, networkPlugin:$netPlugin, outboundType:$outType},
    vnets:$vnets, outbound:{effectivePublicIPs:$outboundIps}, privateDns:$pdns, apiProbe:$probe, findings:$findings }')"

echo "## AKS Network Assessment: ${AKS_NAME}"
echo ""
echo "- **Provisioning state**: ${STATE}"
echo "- **Outbound type**: ${OUT_TYPE}"
echo "- **Network plugin**: ${NET_PLUGIN}"
echo "- **Node resource group**: ${NODE_RG}"
echo ""
echo "### Effective egress public IPs"
echo "${OUTBOUND_IPS}" | jq -r '.[]? // "(none)"' | sed 's/^/- /'
echo ""
echo "### Findings"
echo "${FINDINGS}" | jq -r '.[]? | "- [" + .severity + "] " + .code + ": " + .message'
echo ""
echo "### Docs & next steps"
echo "- Outbound types overview: https://learn.microsoft.com/azure/aks/egress-outboundtype"
echo "- Private clusters & DNS: https://learn.microsoft.com/azure/aks/private-clusters"
echo "- Private DNS zones: https://learn.microsoft.com/azure/dns/private-dns-overview"
echo "- UDR & next hops: https://learn.microsoft.com/azure/virtual-network/virtual-networks-udr-overview"
echo ""
[[ -n "${JSON_OUT}" ]] && echo "${REPORT}" > "${JSON_OUT}" || { echo "```json"; echo "${REPORT}" | jq '.'; echo "```"; }