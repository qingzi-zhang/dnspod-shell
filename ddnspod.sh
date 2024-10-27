#!/usr/bin/env sh

# dnspod-shell: An shell script for DDNS with DNSPod API 3.0
AGENT="https://github.com/qingzi-zhang/dnspod-shell"
CONF_FILE="/etc/config/ddnspod"

FORCE_UPDATE=0

LOG_FILE="/var/log/ddnspod/ddnspod.log"
LOG_LEVEL=1
LOG_LEVEL_INFO=0
LOG_SIZE=1000000 # 1M Bytes
LOG_TAG="ddnspod"

algorithm="TC3-HMAC-SHA256"
host="dnspod.tencentcloudapi.com"
service="dnspod"
region="" # Common Params. This parameter is not required for this API.

# Current version for the DNSPod API 3.0 DescribeRecord and ModifyDynamicDNS: 2021-03-23
# https://cloud.tencent.com/document/api/1427/56166, https://cloud.tencent.com/document/api/1427/56158
version="2021-03-23"

# Function adopted from DNSPod API 3.0
# This function is based on the example provided by the external API.
# Source: https://github.com/TencentCloud/signature-process-demo/tree/main/signature-v3/bash/signv3_no_xdd.sh
dp_api_req() {
  # ************* 步骤 1：拼接规范请求串 | Step 1: Concatenate the standardized request string *************
  http_request_method="POST"
  canonical_uri="/"
  canonical_querystring=""
  canonical_headers="content-type:application/json; charset=utf-8\nhost:$host\nx-tc-action:$(echo $action | awk '{print tolower($0)}')\n"
  signed_headers="content-type;host;x-tc-action"
  hashed_request_payload=$(printf -- "%s" "$payload" | openssl sha256 -hex | awk '{print $2}')
  canonical_request="$http_request_method\n$canonical_uri\n$canonical_querystring\n$canonical_headers\n$signed_headers\n$hashed_request_payload"

  # ************* 步骤 2：拼接待签名字符串 | Step 2: Assemble the string to be signed *************
  credential_scope="$date/$service/tc3_request"
  hashed_canonical_request=$(printf -- "%b" "$canonical_request" | openssl sha256 -hex | awk '{print $2}')
  string_to_sign="$algorithm\n$timestamp\n$credential_scope\n$hashed_canonical_request"

  # ************* 步骤 3：计算签名 | Step 3: Calculate the signature *************
  secret_date=$(printf -- "%b" "$date" | openssl sha256 -hmac "TC3$secret_key" | awk '{print $2}')
  # 转二进制 | Convert to binary
  secret_service=$(printf -- "%s" $service | openssl dgst -sha256 -mac hmac -macopt hexkey:"$secret_date" | awk '{print $2}')
  secret_signing=$(printf -- "%s" "tc3_request" | openssl dgst -sha256 -mac hmac -macopt hexkey:"$secret_service" | awk '{print $2}')
  signature=$(printf -- "%b" "$string_to_sign" | openssl dgst -sha256 -mac hmac -macopt hexkey:"$secret_signing" | awk '{print $2}')

  # ************* 步骤 4：拼接 Authorization | Step 4: Concatenate Authorization *************
  authorization="$algorithm Credential=$secret_id/$credential_scope, SignedHeaders=$signed_headers, Signature=$signature"

  curl -A "$AGENT" -XPOST "https://$host" -d "$payload"\
    -H "Authorization: $authorization"\
    -H "Content-Type: application/json; charset=utf-8"\
    -H "Host: $host"\
    -H "X-TC-Action: $action"\
    -H "X-TC-Timestamp: $timestamp"\
    -H "X-TC-Version: $version"\
    -H "X-TC-Region: $region"
  return $?
}

# Parse error information from API response
dp_api_err() {
  # Extract field from API response
  extract_field() {
    echo "$response" | sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p"
  }

  err_code="$(extract_field Code)"
  if [ -n "$err_code" ]; then
    err_msg="$(extract_field Message)"
    logger -p error -s -t $LOG_TAG "$domain_full_name <$rec_type> [$action]: $err_code, $err_msg"
    return 1
  fi
}

# Log to file
dp_logger() {
  # $1 The title of the document or message
  # $2 The main content or body text of the document or message
  title="$1" body="$2"

  if [ -z "$title" ] || [ -z "$body" ]; then
    echo "Error: Missing required arguments <title> or <body>"
    return 74
  fi

  # Attempt to create the log file if it does not exist
  if [ ! -e "$LOG_FILE" ]; then
    mkdir -p "$(dirname "$LOG_FILE")"
    if ! touch "$LOG_FILE" >/dev/null 2>&1 ; then
      logger -p warning -s -t $LOG_TAG "Failed to create $LOG_FILE, please check it out"
      return 73
    fi
    chmod 600 "$LOG_FILE"
  fi

  log_file_size="$(du -b "$LOG_FILE" | awk '{print $1}')"
  if [ "$log_file_size" -gt "$LOG_SIZE" ]; then
    mv -f "$LOG_FILE" "$LOG_FILE".bak
  fi

  log_time="$(date "+%Y-%m-%d %H:%M:%S")"
  printf -- "----- %s %s -----\n%s\n" "$log_time" "$title" "$body" >> "$LOG_FILE"
}

# Synchronize the DDNS record
dp_sync_ddns() {
  if [ -z "$domain" ]; then
    echo "Info: Domain name is missing, please check the config file '$CONF_FILE'."
    return 78
  fi

  # Validate device
  if ! ip link show dev "$device" >/dev/null 2>&1 ; then
    echo "Error: Invalid interface '$device' or unavailable"
    return 78
  fi

  # if subdomain is empty, set it to "@" which means the root domain
  subdomain=${subdomain:-"@"}
  if [ "$subdomain" = "@" ]; then
    domain_full_name="$domain"
  else
    domain_full_name="$subdomain.$domain"
  fi

  # If ip_type is not specified, default to IPv6
  ip_type=${ip_type:-"IPv6"}
  # Convert to standard format
  ip_type=$(echo "$ip_type" | sed 's/[iI][pP][vV]/IPv/')
  if [ "$ip_type" = "IPv4" ]; then
    rec_type="A"
  else
    rec_type="AAAA"
  fi

  # Get the IP address of the specified device by command 'ip'
  ip_addr_show || return 74

  # Get the IP address of the specified device by command 'nslookup'
  ip_nslookup || return 74

  # Check if the IP address has changed
  if [ "$ns_ip_addr" = "$ip_addr" ]; then
    if [ "$LOG_LEVEL" -eq "$LOG_LEVEL_INFO" ]; then
      logger -p info -s -t $LOG_TAG "$domain_full_name $ip_type address $ip_addr is up to date"
    else
      echo "$domain_full_name $ip_type address $ip_addr is up to date"
    fi

    if [ "$FORCE_UPDATE" -ne 1 ]; then
      # Force update is not enabled and IP address is up to date
      return 0
    fi
  fi

  timestamp=$(date +%s)
  date=$(date -u -d @"$timestamp" +"%Y-%m-%d")
  # Retrieve the list of domain name resolution records (dnspod API: DescribeRecordList)
  response="$(dp_rec_query "$domain" "$subdomain" "$rec_type")"

  # Validate response
  dp_api_err || return 1

  # Extract the record ID and record IP address from the DNSPOD API result
  record_id="$(echo "$response" | sed 's/.*"RecordId":\([0-9]*\).*/\1/')"
  record_ip="$(echo "$response" | sed -n 's/.*"Value":"\([0-9a-fA-F.:]*\)".*/\1/p')"
  if [ -z "$record_id" ] || [ -z "$record_ip" ]; then
    echo "Error: The attempt to extract the record ID or record IP address for $domain_full_name from DNSPOD api response has failed."
    return 65
  fi

  # The IP addresses remain the same due to the local DNS cache not being updated
  if [ "$ip_addr" = "$record_ip" ]; then
    logger -p info -s -t $LOG_TAG "$domain_full_name [$device] $ip_type address $ip_addr is up to date"
    [ "$FORCE_UPDATE" -eq 0 ] && return 0
  fi

  record_line="默认" # Line of default , unicode="\u9ed8\u8ba4"

  # Update the dynamic DNS record (dnspod API: ModifyDynamicDNS)
  response="$(dp_rec_update "$domain" "$record_id" "$record_line" "$ip_addr" "$subdomain")"

  # Validate response
  dp_api_err || return 1

  logger -p notice -s -t $LOG_TAG "$domain_full_name $ip_type address has been updated to $ip_addr"
}

# Use DNSPod API to get the DNS records of a domain
dp_rec_query() {
  action="DescribeRecordList"
  payload="$(printf -- '{"Domain":"%s","Subdomain":"%s","RecordType":"%s"}' "$domain" "$subdomain" "$rec_type")"
  dp_logger "$action request" "$payload"
  response="$(dp_api_req)"
  dp_logger "$action response" "$response"
  echo "$response"
}

# Use DNSPod API to modify a record
dp_rec_update() {
  action="ModifyDynamicDNS"
  payload="$(printf -- '{"Domain":"%s","RecordId":%d,"RecordLine":"%s","Value":"%s","SubDomain":"%s"}' "$domain" "$record_id" "$record_line" "$ip_addr" "$subdomain")"
  dp_logger "$action request" "$payload"
  response="$(dp_api_req)"
  dp_logger "$action response" "$response"
  echo "$response"
}

# Use the 'ip' command to get the IP address of the specified network interface
ip_addr_show() {
  if [ "$ip_type" = "IPv4" ]; then
    ip_addr="$(ip -4 address show dev "$device" | sed -n 's/.*inet \([0-9.]\+\).*/\1/p')"
  else
    # Please note the updates on https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml

    # [RFC4291] Unspecified Address ::/128
    ip6_filter="^::$"
    # [RFC4291] Loopback Address ::1/128
    ip6_filter="$ip6_filter|^::1$"
    # [RFC6052] IPv4-IPv6 Translat 64:ff9b::/96
    # [RFC8215] IPv4-IPv6 Translat 64:ff9b:1::/48
    ip6_filter="$ip6_filter|^64:[fF][fF]9[bB]:"
    # [RFC6666] Discard-Only Address Block 100::/64
    ip6_filter="$ip6_filter|^100::"
    # [RFC5180][RFC Errata 1752] Benchmarking 2001:2::/48
    ip6_filter="$ip6_filter|^2001:2:"
    # [RFC4193][RFC8190] Unique-Local fc00::/7
    ip6_filter="$ip6_filter|^[fF][cdCD][0-9a-fA-F]{2}:"
    # [RFC4291] Link-Local Unicast fe80::/10
    ip6_filter="$ip6_filter|^[fF][eE][89a-bA-B][0-9a-fA-F]:"

    # Get the IPv6 address of the specified device by ip command
    ip_addr="$(ip -6 address show dev "$device" | sed -n 's/.*inet6 \([0-9a-fA-F:]\+\)\/64.*scope global dynamic.*/\1/p' | grep -Ev "$ip6_filter" | head -n 1)"
  fi

  if [ -z "$ip_addr" ]; then
    logger -p error -s -t $LOG_TAG "The attempt to retrieve the $ip_type address for $domain_full_name by command 'ip' from $device has failed."
    return 1
  fi

  # Adds the specific custom suffix
  [ -z "$suffix" ] || ip_addr="${ip_addr%::*}:$suffix"
}

# Use the 'nslookup' command to get the IP address
ip_nslookup() {
  response="$(nslookup -type="$rec_type" "$domain_full_name")"
  # Attempt to get error message from the result
  err_code=$(echo "$response" | grep -c "**")
  # Error handling
  if [ "$err_code" -ne 0 ]; then
    err_msg="$(printf -- '%s\n' "$response" | grep -E '^\*{2}')"
    #err_msg=$(printf -- '%s\n' "$response" | sed -n 's/^\*\* //p')
    logger -p error -s -t $LOG_TAG "$domain_full_name <$rec_type> [nslookup]: $err_msg"
    return 1
  fi

  # Extract the IP address from the result
  ns_ip_addr="$(echo "$response" | sed -n 's/.*Address: \([0-9a-fA-F.:]\+\).*/\1/p')"

  # Validate the IP address format
  if [ -z "$ns_ip_addr" ]; then
    logger -p error -s -t $LOG_TAG "$domain_full_name <$rec_type> [nslookup]: '$ns_ip_addr' format is invalid."
    return 1
  fi
}

# Parse arguments and process command
parse_command() {
  while [ ${#} -gt 0 ]; do
    case "${1}" in
      --help | -h)
        show_help
        return 1
        ;;
      --config=*)
        CONF_FILE="${1#*=}"
        shift
        ;;
      --force-update)
        FORCE_UPDATE=1
        shift
        ;;
      --log-level=*)
        LOG_LEVEL="${1#*=}"
        shift
        ;;
      *)
        echo "Unknown option: ${1}"
        show_help
        return 1
        ;;
    esac
  done
}

# Process synchronized DDNS records from config file
proc_ddns_records() {
  # Read DDNS records from config file
  rec_cnt=$(grep -c "DDNS" "$CONF_FILE")
  if [ "$rec_cnt" -eq 0 ]; then
    echo "Info: No DDNS records found in '$CONF_FILE'."
    return 1
  fi

  # Process each DDNS record
  grep "DDNS" "$CONF_FILE" | while read -r "record"; do
    # Extract DDNS record information
    domain=$(echo "$record" | awk -F '[=,]' '{print $2}')
    subdomain=$(echo "$record" | awk -F '[=,]' '{print $3}')
    ip_type=$(echo "$record" | awk -F '[=,]' '{print $4}')
    device=$(echo "$record" | awk -F '[=,]' '{print $5}')
    suffix=$(echo "$record" | awk -F '[=,]' '{print $6}')
    # Synchronize the DDNS record
    dp_sync_ddns
  done
}

show_help() {
  echo "$AGENT
Usage:
  $(basename "$0") [options]

Options:
  -h, --help           Show help.
  --config=<file>      Specify the config file
  --force-update       Proceed update regardless of IP status
  --log-level=<0|1>    Log level 0 (info), 1 (notice)
  "
}

# Validate configration
validate_config() {
  # Check if the config file exists
  [ -f "$CONF_FILE" ] || {
    echo "Error: Config file '$CONF_FILE' does not exist."
    return 1
  }

  # Validate LOG_LEVEL
  if ! echo "$LOG_LEVEL" | grep -q "^[01]$" ; then
    echo "Error: Invalid log level '$LOG_LEVEL', Use 0 (info) or 1 (notice)."
    return 1
  fi

  # Read configration values
  read_config_value() {
    awk -F= -v key="$1" '$1 == key {gsub(/[ \t]+/, "", $2); print$2}' "$CONF_FILE"
  }

  secret_id=$(read_config_value "SecretId")
  secret_key=$(read_config_value "SecretKey")
  # Validate secret_id and secret_key
  if [ -z "$secret_id" ] || [ -z "$secret_key" ]; then
    echo "Error: SecretId or SecretKey is missing, please verify the configration in '$CONF_FILE'."
    return 1
  fi

  # Validate log_file
  log_file=$(read_config_value "LogFile")
  [ -n "$log_file" ] || echo "Info: Missed 'LogFile=<file>' in '$CONF_FILE'"
  # Set the LOG_FILE variable to the value from the config file or keep it as the default value
  [ -z "$log_file" ] || LOG_FILE="$log_file"
}

main() {
  parse_command "$@" || return 1
  validate_config    || return 1
  proc_ddns_records
}

main "$@"
