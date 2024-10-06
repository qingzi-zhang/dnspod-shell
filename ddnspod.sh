#!/usr/bin/env sh

AGENT="https://github.com/qingzi-zhang/dnspod-shell"
CONF_FILE="/etc/config/ddnspod"
DESC="Synchronize the IP address of DDNS with Tencent DNSPOD API v3.0 in OpenWrt"

LOG_FILE="/tmp/log/ddnspod.log"
LOG_LEVEL_NOTICE=1
LOG_LEVEL_INFO=2
LOG_LEVEL=$LOG_LEVEL_NOTICE
LOG_TAG="ddnspod"
LOG_SIZE=1000000 # 1MB

###### https://github.com/TencentCloud/signature-process-demo/tree/main/signature-v3/bash
algorithm="TC3-HMAC-SHA256"
host="dnspod.tencentcloudapi.com"
service="dnspod"

dp_api_v3_req() {
  # ************* 步骤 1：拼接规范请求串 ************* / Step 1: Splicing specification request string
  http_request_method="POST"
  canonical_uri="/"
  canonical_querystring=""
  canonical_headers="content-type:application/json; charset=utf-8\nhost:$host\nx-tc-action:$(echo $action | awk '{print tolower($0)}')\n"
  signed_headers="content-type;host;x-tc-action"
  hashed_request_payload=$(echo -n "$payload" | openssl sha256 -hex | awk '{print $2}')
  canonical_request="$http_request_method\n$canonical_uri\n$canonical_querystring\n$canonical_headers\n$signed_headers\n$hashed_request_payload"
  #echo "$canonical_request"

  timestamp=$(date +%s)
  date=$(date -u -d @$timestamp +"%Y-%m-%d")
  # ************* 步骤 2：拼接待签名字符串 ************* / Step 2: Combine the reception signature string
  credential_scope="$date/$service/tc3_request"
  hashed_canonical_request=$(printf "$canonical_request" | openssl sha256 -hex | awk '{print $2}')
  string_to_sign="$algorithm\n$timestamp\n$credential_scope\n$hashed_canonical_request"
  #echo "$string_to_sign"

  # ************* 步骤 3：计算签名 ************* / Step 3: Calculate Signature
  secret_date=$(printf "$date" | openssl sha256 -hmac "TC3$secret_key" | awk '{print $2}')
  #echo $secret_date
  secret_service=$(printf $service | openssl dgst -sha256 -mac hmac -macopt hexkey:"$secret_date" | awk '{print $2}')
  #echo $secret_service
  secret_signing=$(printf "tc3_request" | openssl dgst -sha256 -mac hmac -macopt hexkey:"$secret_service" | awk '{print $2}')
  #echo $secret_signing
  signature=$(printf "$string_to_sign" | openssl dgst -sha256 -mac hmac -macopt hexkey:"$secret_signing" | awk '{print $2}')
  #echo "$signature"

  # ************* 步骤 4：拼接 Authorization ************* / Step 4: Splicing Authorization
  authorization="$algorithm Credential=$secret_id/$credential_scope, SignedHeaders=$signed_headers, Signature=$signature"
  #echo $authorization

  # ************* 步骤 5：构造并发起请求 ************* / Step 5: Construct and initiate request
  curl -A "$AGENT" -XPOST "https://$host" -d "$payload"\
    -H "Authorization: $authorization"\
    -H "Content-Type: application/json; charset=utf-8"\
    -H "Host: $host"\
    -H "X-TC-Action: $action"\
    -H "X-TC-Timestamp: $timestamp"\
    -H "X-TC-Version: $version"\
    -H "X-TC-Region: $region"\
    -H "X-TC-Token: $token"
  return $?
}
######

dp_api_err() {
  err_code="$(echo "$response" | sed -n 's/.*"Code":"\([^"]*\)".*/\1/p')"
  if [ -n "$err_code" ]; then
    logger -p error -s -t $LOG_TAG "$domain_full_name,$ip_type: $err_code"
    return 1
  fi
}

dp_logger() {
  # $1: title - The title of the document or message
  # $2: body - The main content or body text of the document or message
  if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Error: Missing required arguments"
    return 1
  fi

  if [ -e "$LOG_FILE" ]; then
    log_file_size="$(du -b "$LOG_FILE" | awk '{print $1}')"
  else
    log_file_size=0
    mkdir -p "$(dirname "$LOG_FILE")"
  fi

  if [ "$log_file_size" -gt "$LOG_SIZE" ]; then
    mv -f "$LOG_FILE" "$LOG_FILE".bak
  fi

  if [ -z "$log_time" ]; then
    log_time="$(date "+%Y-%m-%d %H:%M:%S")"
  fi

  printf -- "----- %s %s -----\n%s\n" "$log_time" "$1" "$2" >> "$LOG_FILE"
}

dp_rec_list() {
  # This API is used to get the DNS records of a domain
  action="DescribeRecordList"
  payload="$(printf -- '{"Domain":"%s","Subdomain":"%s","RecordType":"%s"}' "$domain" "$subdomain" "$record_type")"
  dp_logger "$action request" "$payload"
  response="$(dp_api_v3_req)"
  dp_logger "$action response" "$response"
  echo "$response"
}

dp_rec_update() {
  # This API is used to modify a DNS record
  action="ModifyDynamicDNS"
  payload="$(printf -- '{"Domain":"%s","RecordId":%d,"RecordLine":"%s","Value":"%s","SubDomain":"%s"}' "$domain" "$record_id" "$record_line" "$ip_addr" "$subdomain")"
  dp_logger "$action request" "$payload"
  response="$(dp_api_v3_req)"
  dp_logger "$action response" "$response"
  echo "$response"
}

ip6_ula() {
    # IPv6 Unique Local Addresses (ULAs)
    ip6_ulas="(^$)"
    ip6_ulas="$ip6_ulas|(^::1$)"                            # RFC4291
    ip6_ulas="$ip6_ulas|(^64:[fF][fF]9[bB]:)"               # RFC6052, RFC8215
    ip6_ulas="$ip6_ulas|(^100::)"                           # RFC6666
    ip6_ulas="$ip6_ulas|(^2001:2:0?:)"                      # RFC5180
    ip6_ulas="$ip6_ulas|(^2001:[dD][bB]8:)"                 # RFC3849
    ip6_ulas="$ip6_ulas|(^[fF][cdCD][0-9a-fA-F]{2}:)"       # RFC4193 Unique local addresses
    ip6_ulas="$ip6_ulas|(^[fF][eE][8-9a-bA-B][0-9a-fA-F]:)" # RFC4291 Link-local addresses
    echo $ip6_ulas
}

ip_addr_show() {
  if [ "$ip_type" = "IPv4" ]; then
    address="$(ip -4 address show dev "$device" | sed -n 's/.*inet \([0-9.]\+\).*/\1/p')"
  else
    ip6_filter=$(ip6_ula)
    address="$(ip -6 address show dev "$device" | sed -n 's/.*inet6 \([0-9a-fA-F:]\+\)\/64.*scope global dynamic.*/\1/p' | grep -Ev "$ip6_filter")"
  fi

  if [ -z "$address" ]; then
    logger -p error -s -t $LOG_TAG "$domain_full_name failed to show $device $ip_type address"
    return 1
  fi
  # Replace custom suffix if defined
  [ -n "$suffix" ] &&  address="${address%::*}:$suffix"

  echo "$address"
}

ip_addr_nslookup() {
  address="$(nslookup -type="$record_type" "$domain_full_name" | sed -n 's/.*Address: \([0-9a-fA-F.:]\+\).*/\1/p')"
  if [ -z "$address" ]; then
    logger -p error -s -t $LOG_TAG "$domain_full_name failed to lookup $ip_type address"
    return 1
  fi
  echo "$address"
}

dp_sync_ddns() {
  if [ -z "$domain" ]; then
    echo "Error: The 'domain' variable is not set. Please check your configuration."
    return 78
  fi

  if [ ! "$(ip link show dev "$device")" ]; then
    echo "Error: Invalid interface '$device' or unavailable"
    return 78
  fi

  # Set the subdomain to '@' if empty of the configuration file
  subdomain=${subdomain:-"@"}
  if [ "$subdomain" = "@" ]; then
    domain_full_name="$domain"
  else
    domain_full_name="$subdomain.$domain"
  fi

  # Set the IP type to 'IPv6' if not set
  ip_type="$(echo "${ip_type:-"IPv6"}" | sed 's/[iI][pP][vV]/IPv/')"
  # If the IP type is not A (IPv4), default to AAAA (IPv6).
  if [ "$ip_type" = "IPv4" ]; then
    suffix=""
    record_type="A"
  else
    ip_type="IPv6"
    record_type="AAAA"
  fi

  ip_addr="$(ip_addr_show)"
  ns_ip_addr="$(ip_addr_nslookup)"
  if [ -z "$ip_addr" ] || [ -z "$ns_ip_addr" ]; then
    echo "Error: Failed to obtain the IP address for $domain_full_name"
    return 65
  fi

  # Check if the IP addresses are the same between the device and the nslookup
  if [ "$ns_ip_addr" = "$ip_addr" ]; then
    if [ "$LOG_LEVEL" -eq "$LOG_LEVEL_INFO" ]; then
      logger -p info -s -t $LOG_TAG "$domain_full_name $ip_type address $ip_addr is up to date"
    else
      echo "$domain_full_name $ip_type address $ip_addr is up to date"
    fi
    return 0
  fi

  log_time="$(date "+%Y-%m-%d %H:%M:%S")"
  # Retrieve the list of domain name resolution records (dnspod API: DescribeRecordList)
  response="$(dp_rec_list "$domain" "$subdomain" "$record_type")"
  if ! dp_api_err "$response"; then
    return 1
  fi
  record_id="$(echo "$response" | sed 's/.*"RecordId":\([0-9]*\).*/\1/')"
  record_ip="$(echo "$response" | sed -n 's/.*"Value":"\([0-9a-fA-F.:]*\)".*/\1/p')"
  if [ -z "$record_id" ] || [ -z "$record_ip" ]; then
    echo "Error: Failed to extract one or more values from DNSPOD api result for $domain_full_name"
    return 65
  fi
  # If the IP addresses are the same due to the local DNS cache not being updated
  if [ "$ip_addr" = "$record_ip" ]; then
    logger -p info -s -t $LOG_TAG "device $device: $domain_full_name $ip_type address $ip_addr is up to date"
    return 0
  fi

  record_line="默认" # Line of default , unicode="\u9ed8\u8ba4"
  # Update the dynamic DNS record (dnspod API: ModifyDynamicDNS)
  response="$(dp_rec_update "$domain" "$record_id" "$record_line" "$ip_addr" "$subdomain")"
  if ! dp_api_err "$response"; then
    return 1
  fi

  logger -p notice -s -t $LOG_TAG "$domain_full_name $ip_type address has been updated to $ip_addr"
}

process_sync_ddns() {
  if [ ! -e "$CONF_FILE" ]; then
    echo "Error: $CONF_FILE does not exist"
    return 1
  fi

  version="$(awk -F= '/ApiVersion=/ {print $2}' $CONF_FILE)"
  secret_id="$(awk -F= '/SecretId=/ {print $2}' $CONF_FILE)"
  secret_key="$(awk -F= '/SecretKey=/ {print $2}' $CONF_FILE)"
  log_file="$(awk -F= '/LogFile=/ {print $2}' $CONF_FILE)"

  rec_cnt="$(grep "DDNS" $CONF_FILE | wc -l)"
  if [ "$rec_cnt" -eq 0 ]; then
    echo "Error: DDNS records not found in $CONF_FILE"
    return 1
  fi

  if [ -n "$log_file" ]; then
    LOG_FILE="$log_file"
  fi

  grep "DDNS" $CONF_FILE | while read -r "dp_conf"; do
    domain="$(echo "$dp_conf" | awk -F '[=,]' '{print $2}')"
    subdomain="$(echo "$dp_conf" | awk -F '[=,]' '{print $3}')"
    ip_type="$(echo "$dp_conf" | awk -F '[=,]' '{print $4}')"
    device="$(echo "$dp_conf" | awk -F '[=,]' '{print $5}')"
    suffix="$(echo "$dp_conf" | awk -F '[=,]' '{print $6}')"
    dp_sync_ddns # "$domain" "$subdomain" "$ip_type" "$device" "$suffix"
  done
}

main() {
  if [ "$1" = "log_level_info" ]; then
    LOG_LEVEL=$LOG_LEVEL_INFO
  fi
  process_sync_ddns
}

main "$@"
