#!/usr/bin/env sh

# https://github.com/qingzi-zhang/dnspod-shell

# This script is used to generate a markdown text with instructions
# for understanding how to use the ddnspod.sh script.

TAG="$(basename "$0")"

conf_file="ddnspod.conf"
log_file="/var/log/ddnspod/ddnspod.log"

# Function to print a markdown code block opening and closing tildas.
code_mark() {
  echo "\`\`\`"
}

# Function to print the contents of a file between two markdown code blocks.
show_file() {
  code_mark
  if [ "$1" = "${log_file}" ]; then
    tail -n 12 "$1"
  else
    cat "$1"
  fi
  code_mark
}

main() {
  # Define configuration and log files, and the script's tag based on filename.
  printf -- "\n> [!TIP]\n> %s: Start\n" "${TAG}"

  # Generate configuration file with placeholders for SecretId and SecretKey, 
  # along with sample DDNS configurations.
  cat > "${conf_file}" <<EOM
LogFile=${log_file}
SecretId=***Replace_API_SecretID_pair***
SecretKey=***Replace_API_SecretKey_pair***

# Sample dynamic DNS configurations
DDNS=top_level_domain.net,@,ipv4,eno1,
DDNS=top_level_domain.org,,ipv6,eno1,
DDNS=top_level_domain.com,www,,eno1,
EOM
  # Print the contents of the configuration file.
  echo "## Generate configration file: ${conf_file}"
  show_file "${conf_file}"

  # Print command to execute ddnspod.sh with the generated configuration and parameters.
  echo "## ddnspod.sh --config=${conf_file} --log-level=1 --force-update"

  # Execute ddnspod.sh with the generated configuration and parameters.
  code_mark
  ddnspod.sh --config=${conf_file} --log-level=1 --force-update
  code_mark

  # Print log file viewing information, contents of the log file if it exists,
  # or a message indicating its non-existence.
  echo "## ${log_file}"
  if [ -f "${log_file}" ]; then
    show_file "${log_file}"
  else
    code_mark
    echo "Log file: ${log_file} not exist"
    code_mark
  fi

  # Print end information.
  printf -- "> [!TIP]\n> %s: End\n" "${TAG}"
}

main "$@"
