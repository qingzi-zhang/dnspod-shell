#!/usr/bin/env sh
#
# dnspod-shell: A DDNS Shell Script: ddnspod.sh

AGENT="https://github.com/qingzi-zhang/dnspod-shell"

LOG_LEVEL_ERROR=0
LOG_LEVEL_VERBOSE=1
LOG_SIZE=1000000 # Bytes
TAG="ddnspod"

DEFAULT_CFG_FILE="/etc/config/ddnspod"
DEFAULT_LOG_FILE="/var/log/ddnspod/ddnspod.log"
DEFAULT_LOG_LEVEL="${LOG_LEVEL_ERROR}"

config_file="${DEFAULT_CFG_FILE}"
force_update=0
log_file="${DEFAULT_LOG_FILE}"
log_level="${DEFAULT_LOG_LEVEL}"

# Tencent API 3.0 DescribeRecordList and ModifyDynamicDNS current version: 2021-03-23
# https://cloud.tencent.com/document/api/1427/56166, https://cloud.tencent.com/document/api/1427/56158
algorithm="TC3-HMAC-SHA256"
host="dnspod.tencentcloudapi.com"
region="" # Common Params. This parameter is not required for this API. (optional)
service="dnspod"
version="2021-03-23"

# Function to write messages into the log file
log_msg() {
  # Check if arguments title ($1) and message ($2) are provided
  if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Error: [log_msg] Missing one or more required arguments."
    # Return a non-zero exit status to indicate an error occurred
    return 1
  fi

  # Check if log file exists or create one
  if [ ! -f "${log_file}" ]; then
    umask 0077
    mkdir -p "$(dirname "${log_file}")"
    # Log a warning message if the log file creation fails
    if ! touch "${log_file}" >/dev/null 2>&1 ; then
      logger -p warn -s -t "${TAG}" "Failed to create '${log_file}', please check it out"
      return 1
    fi
  fi

  # Rotate log file if size exceeds limit
  log_file_size="$(du -b "${log_file}" | cut -f1)"
  if [ "${log_file_size}" -gt "${LOG_SIZE}" ]; then
    mv -f "${log_file}" "${log_file}".bak
  fi

  # Log the messages with timestamp
  log_time="$(date "+%Y-%m-%d %H:%M:%S")"
  printf -- "----- %s [%s] -----\n%s\n" "${log_time}" "$1" "$2" >> "${log_file}"
}

# Function to get the network interface IP address via ip command
query_interface_ip() {
  if [ "${rec_type}" = "A" ]; then
    # https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
    # [RFC791] "This network" 0.0.0.0/8
    ip4_filter="^0\.(25[0-5]|2[0-4][0-9]|[01]?[0-9]{1,2}\.)"
    # [RFC1122] "This host on this network" 127.0.0.0/8
    ip4_filter="${ip4_filter}|^127\."
    # [RFC6598] Shared Address Space 100.64.0.0/10
    ip4_filter="${ip4_filter}|^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7]\.)"
    # [RFC3927] Link Local 169.254.0.0/16
    ip4_filter="${ip4_filter}|^169\.254\."
    # [RFC1918] Private-Use 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    ip4_filter="${ip4_filter}|^10\."
    ip4_filter="${ip4_filter}|^172\.(1[6-9]|2[0-9]|3[01]\.)"
    ip4_filter="${ip4_filter}|^192\.168\."
    # [RFC1112] Reserved Address Block 240.0.0.0/4
    ip4_filter="${ip4_filter}|^240\."
    # [RFC2544] Benchmarking Address Blocks 198.18.0.0/15
    ip4_filter="${ip4_filter}|^198\.1[8-9]\."
    # [RFC5737] IPv4 Address Blocks Reserved for Documentation 198.51.100.0/24, 203.0.113.0/24
    ip4_filter="${ip4_filter}|^198\.51\.100\.|^203\.0\.113\."

    # Fetches and filters IPv4 address from the specific interface
    ip_addr="$(ip -4 address show dev "${interface}" | sed -n 's/.*inet \([0-9.]\+\).\+scope global.*/\1/p' | grep -Ev "${ip4_filter}")"
  else
    # https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
    # [RFC4291] Unspecified Address ::/128
    ip6_filter="^::$"
    # [RFC4291] Loopback Address ::1/128
    ip6_filter="${ip6_filter}|^::1$"
    # [RFC6052] IPv4-IPv6 Translat 64:ff9b::/96
    # [RFC8215] IPv4-IPv6 Translat 64:ff9b:1::/48
    ip6_filter="${ip6_filter}|^64:[fF][fF]9[bB]:"
    # [RFC6666] Discard-Only Address Block 100::/64
    ip6_filter="${ip6_filter}|^100::"
    # [RFC5180][RFC Errata 1752] Benchmarking 2001:2::/48
    ip6_filter="${ip6_filter}|^2001:2:"
    # [RFC4193][RFC8190] Unique-Local fc00::/7
    ip6_filter="${ip6_filter}|^[fF][cdCD][0-9a-fA-F]{2}:"
    # [RFC4291] Link-Local Unicast fe80::/10
    ip6_filter="${ip6_filter}|^[fF][eE][8-9a-bA-B][0-9a-fA-F]:"

    # Fetches and filters IPv6 address from the specific interface
    ip_addr="$(ip -6 address show dev "${interface}" | sed -n 's/.*inet6 \([0-9a-fA-F:]\+\)\/64 scope global dynamic.*/\1/p' | grep -Ev "${ip6_filter}" | head -n 1)"
  fi

  # Validate IP address extraction
  if [ -z "${ip_addr}" ]; then
    logger -p error -s -t "${TAG}" "${domain_full_name} interface '${interface}' ${ip_version} address extraction failed"
    return 1
  fi

  # Adds specific custom suffix
  [ -z "${suffix}" ] || ip_addr="${ip_addr%::*}:${suffix}"
}

# Function to get the dynamic DNS IP via nslookup
query_nslookup_ip() {
  # Perform nslookup for the specified domain and record type
  cmd_result="$(nslookup -type="${rec_type}" "${domain_full_name}")"

  # Check for error indicator in the result
  if echo "${cmd_result}" | grep -q "\*\*" ; then
    # Extract error message
    err_msg="$(echo "${cmd_result}" | grep '\*')"
    logger -p error -s -t "${TAG}" "${domain_full_name} ${rec_type} [nslookup]: ${err_msg}"
    return 1
  fi

  # Extract IP address from the result
  ns_ip_addr="$(echo "${cmd_result}" | sed -n 's/.*Address: \([0-9a-fA-F.:]\+\).*/\1/p')"

  # Check if IP address extraction was successful
  if [ -z "${ns_ip_addr}" ]; then
    logger -p error -s -t "${TAG}" "${domain_full_name} ${rec_type} [nslookup]: IP address extraction failed"
    return 1
  fi
}

# Function to handle Tencent API errors
tencent_api_err() {
  # Extract error code from the API response
  err_code="$(echo "${api_response}" | sed -n 's/.*"Code":"\([^"]\+\)".*/\1/p')"

  if [ -n "${err_code}" ]; then
    # Extract the error message
    err_msg="$(echo "${api_response}" | sed 's/.*"Message":"\([^"]\+\)".*/\1/')"
    logger -p error -s -t "${TAG}" "${domain_full_name} ${rec_type} [${action}]: ${err_code}, ${err_msg}"
    return 1
  fi
}

# Function to call Tencent Cloud DNSPod API 3.0 services
# This function is based on the example provided by the external API
# Source: https://github.com/TencentCloud/signature-process-demo/tree/main/signature-v3/bash/signv3_no_xdd.sh
tencent_api_req() {
  # ************* 步骤 1：拼接规范请求串 | Step 1: Concatenate the standardized request string *************
  http_request_method="POST"
  canonical_uri="/"
  canonical_querystring=""
  canonical_headers="content-type:application/json; charset=utf-8\nhost:${host}\nx-tc-action:$(echo "${action}" | awk '{print tolower($0)}')\n"
  signed_headers="content-type;host;x-tc-action"
  hashed_request_payload="$(printf -- "%s" "${payload}" | openssl sha256 -hex | awk '{print $2}')"
  canonical_request="${http_request_method}\n${canonical_uri}\n${canonical_querystring}\n${canonical_headers}\n${signed_headers}\n${hashed_request_payload}"

  timestamp="$(date +%s)"
  date="$(date -u -d @"${timestamp}" +"%Y-%m-%d")"
  # ************* 步骤 2：拼接待签名字符串 | Step 2: Assemble the string to be signed *************
  credential_scope="${date}/${service}/tc3_request"
  hashed_canonical_request="$(printf -- "%b" "${canonical_request}" | openssl sha256 -hex | awk '{print $2}')"
  string_to_sign="$algorithm\n${timestamp}\n${credential_scope}\n${hashed_canonical_request}"

  # ************* 步骤 3：计算签名 | Step 3: Calculate the signature *************
  secret_date="$(printf -- "%b" "${date}" | openssl sha256 -hmac "TC3${secret_key}" | awk '{print $2}')"
  # 转二进制 | Convert to binary
  secret_service="$(printf -- "%s" ${service} | openssl dgst -sha256 -mac hmac -macopt hexkey:"${secret_date}" | awk '{print $2}')"
  secret_signing="$(printf -- "%s" "tc3_request" | openssl dgst -sha256 -mac hmac -macopt hexkey:"${secret_service}" | awk '{print $2}')"
  signature="$(printf -- "%b" "${string_to_sign}" | openssl dgst -sha256 -mac hmac -macopt hexkey:"${secret_signing}" | awk '{print $2}')"

  # ************* 步骤 4：拼接 Authorization | Step 4: Concatenate Authorization *************
  authorization="$algorithm Credential=$secret_id/$credential_scope, SignedHeaders=${signed_headers}, Signature=${signature}"

  # ************* 步骤 5：构造并发起请求 | Step 5: Construct and initiate the request *************
  curl -A "${AGENT}" -XPOST "https://${host}" -d "${payload}" \
    -H "Authorization: ${authorization}" \
    -H "Content-Type: application/json; charset=utf-8" \
    -H "Host: ${host}" \
    -H "X-TC-Action: ${action}" \
    -H "X-TC-Timestamp: ${timestamp}" \
    -H "X-TC-Version: ${version}" \
    -H "X-TC-Region: ${region}"
  return $?
}

# Function to query a DDNS record
rec_query() {
  action="DescribeRecordList"
  payload="$(printf -- '{"Domain":"%s","Subdomain":"%s","RecordType":"%s"}' "${domain}" "${subdomain}" "${rec_type}")"
  log_msg "${action} request" "${payload}"
  api_response="$(tencent_api_req)"
  log_msg "${action} response" "${api_response}"
  domain_full_name="${domain_full_name:-${subdomain}.${domain}}"
  tencent_api_err "${domain_full_name}" "${rec_type}" "${action}" "${api_response}" || return 1
}

# Function to update a DDNS record
rec_update() {
  action="ModifyDynamicDNS"
  payload="$(printf -- '{"Domain":"%s","RecordId":%d,"RecordLine":"%s","Value":"%s","SubDomain":"%s"}' "${domain}" "${record_id}" "${record_line}" "${ip_addr}" "${subdomain}")"
  log_msg "$action request" "${payload}"
  api_response="$(tencent_api_req)"
  log_msg "${action} response" "${api_response}"
  domain_full_name="${domain_full_name:-${subdomain}.${domain}}"
  tencent_api_err "${domain_full_name}" "${rec_type}" "${action}" "${api_response}" || return 1
}

# Function to synchronize a DDNS record
sync_ddns_rec() {
  # Validate required fields
  if [ -z "${domain}" ]; then
    logger -p error -s -t "${TAG}" "Missing required field 'domain' in the config file '${config_file}', check it out."
    return 1
  fi

  # Set subdomain to @ if not specified in the config file
  subdomain="${subdomain:-@}"
  # Set full domain name
  if [ "${subdomain}" = "@" ]; then
    # Top-level domain
    domain_full_name="${domain}"
  else
    # Second-level domain
    domain_full_name="${subdomain}.${domain}"
  fi

  # Validate network interface
  if ! ip link ls dev "${interface}" >/dev/null 2>&1 ; then
    logger -p error -s -t "${TAG}" "${domain_full_name} interface '${interface}' is invalid not available"
    return 1
  fi

  # Set IP version to IPv6 if not specified in the config file
  ip_version="${ip_version:-'IPv6'}"
  # Convert to special format (IPv4/IPv6)
  ip_version="$(echo "${ip_version}" | sed 's/[iI][pP][vV]/IPv/')"
  # Convert to record type (A/AAAA)
  if [ "${ip_version}" = "IPv4" ]; then
    rec_type="A"
  else
    rec_type="AAAA"
  fi

  # Get network interface IP address
  query_interface_ip "${rec_type}" "${interface}" "${suffix}" || return 1
  # Get nslookup IP address
  query_nslookup_ip "${domain_full_name}" "${rec_type}" || return 1

  # Check if the local IP address is the same as the server IP address
  if [ "${ip_addr}" = "${ns_ip_addr}" ]; then
    [ "${log_level}" -eq "${LOG_LEVEL_VERBOSE}" ] \
      && logger -p info -s -t "${TAG}" "${domain_full_name} ${ip_version} address ${ip_addr} is up to date" \
      || echo "${domain_full_name} ${ip_version} address ${ip_addr} is up to date"

    # Skip when a force-update is not enabled (The IP address is already the latest)
    [ "$force_update" -eq 0 ] && return 0
  fi

  # Get DDNS record information via DNSPod API
  rec_query "${domain}" "${subdomain}" "${rec_type}" || return 1

  # Extract RecordId and IP address via DNSPod API
  record_id="$(echo "${api_response}" | sed 's/.*"RecordId":\([0-9]\+\).*/\1/')"
  record_ip="$(echo "${api_response}" | sed 's/.*"Value":"\([0-9a-fA-F.:]\+\)".*/\1/')"

  if [ -z "${record_id}" ] || [ -z "${record_ip}" ]; then
    logger -p error -s -t "${TAG}" "Fail attempt to extract RecordId or IP address for ${domain_full_name} ${rec_type} from DNSPod API response"
    return 1
  fi

  # If the IP address is up to date here, it means the local DNS cache is out of date
  if [ "${ip_addr}" = "${record_ip}" ]; then
    [ "${log_level}" -lt "${LOG_LEVEL_ERROR}" ] || logger -p info -s -t "${TAG}" "${domain_full_name} cache of ${ip_version} address ${ip_addr} is up to date"
    # Skip when a force-update is not enabled (The IP address cache is already up to date)
    [ "$force_update" -eq 0 ] && return 0
  fi

  # Set record line to default, unicode is "\u9ed8\u8ba4"
  record_line="默认"

  # Update DDNS (DNSPod API: ModifyDynamicDNS)
  rec_update "${domain}" "${record_id}" "${record_line}" "${ip_addr}" "${subdomain}" || return 1

  logger -p notice -s -t "${TAG}" "${domain_full_name} ${ip_version} address has been updated to ${ip_addr}"
}

# Function to parse command line arguments
parse_command() {
  # Parse command line arguments
  while [ "$#" -gt 0 ]; do
    case "$1" in
      -h|--help)
        show_help
        return 1
        ;;
      --config=*)
        config_file="${1#*=}"
        shift
        ;;
      --force-update)
        force_update=1
        shift
        ;;
      --log-level=*)
        log_level="${1#*=}"
        shift
        ;;
      *)
        echo "Unknown option: $1"
        show_help
        return 1
        ;;
    esac
  done

  if [ "${force_update}" -eq 1 ] && [ "${log_level}" -eq "${LOG_LEVEL_VERBOSE}" ]; then
    logger -p info -s -t "${TAG}" "Processing with force update is enabled"
  fi
}

# Function to synchronize dynamic DNS records
proc_ddns_records() {
  # Function to extract field from a DDNS record
  get_ddns_field() {
    echo "${record}" | cut -d ',' -f "$1"
  }

  # Process each DDNS record found in the config file
  grep "DDNS" "${config_file}" | while read -r record ; do
    # Remove all horizontal or vertical whitespace and 'DDNS=' prefix
    record="$(printf -- '%s' "${record}" | sed -E 's/\s+//g; s/^DDNS=//')"

    # Extract DDNS fields
    domain="$(get_ddns_field 1)"
    subdomain="$(get_ddns_field 2)"
    ip_version="$(get_ddns_field 3)"
    interface="$(get_ddns_field 4)"
    suffix="$(get_ddns_field 5)"

    # Synchronize the DDNS recordsync_ddns_record
    sync_ddns_rec "${domain}" "${subdomain}" "${ip_version}" "${interface}" "${suffix}"
  done
}

# Function to display help information
show_help() {
  echo "${AGENT}
Usage:
  $(basename "$0") [options]

Options:
  -h, --help           Print this help message
  --config=<file>      Read config from a file
  --force-update       Proceed with the update regardless of IP status
  --log-level=<0|1>    Set the log level to 0 or 1 (0: Error, 1: Verbose)"
}

# Function to validate the configuration file
validate_config() {
  config_file="${config_file:=${DEFAULT_CFG_FILE}}"
  # Validate the configuration file
  if [ ! -f "${config_file}" ]; then
    logger -p error -s -t "${TAG}" "Configuration file '${config_file}' not found."
    return 1
  fi

 # Validate the DDNS records
  if ! grep -q "DDNS" "${config_file}" ; then
    logger -p warn -s -t "${TAG}" "No DDNS records in '${config_file}'."
    return 1
  fi

  log_level="${log_level:-${DEFAULT_LOG_LEVEL}}"
  # Validate the log level
  if ! echo "${log_level}" | grep -q "^[01]$" ; then
    logger -p error -s -t "${TAG}" "Invalid log level '${log_level}', Use 0 (Error) or 1 (Verbose)"
    return 1
  fi

  # Function to extract configuration fields
  extract_config() {
    awk -F= -v "key=$1" '$1 == key { gsub(/\s/, ""); print $2 }' "${config_file}"
  }

  # Extract the SecretId and SecretKey
  secret_id="$(extract_config SecretId)"
  secret_key="$(extract_config SecretKey)"
  # Validate the API credentials
  if [ -z "${secret_id}" ] || [ -z "${secret_key}" ]; then
    logger -p error -s -t "${TAG}" "API credentials fields 'SecretId' or 'SecretKey' are missing in '${config_file}'."
    return 1
  fi

  # Extract the log file
  log_file="$(extract_config LogFile)"
  # Validate the log file
  if [ -z "${log_file}" ]; then
    log_file="${DEFAULT_LOG_FILE}"
    logger -p warn -s -t "${TAG}" "Log file field 'LogFile' not found in '${config_file}'"
  fi
}

# Function main is entry point of the program
main() {
  parse_command "$@" || return 1
  validate_config    || return 1
  proc_ddns_records  || return 1
}

main "$@"
