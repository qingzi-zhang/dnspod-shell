<div align="center">
  <h1>An shell script for DDNS with dnspod</h1>
</div>

<p align="center">
  <a href="https://github.com/qingzi-zhang/dnspod-shell/blob/main/LICENSE">
    <img alt="Apache License Version 2.0" src="https://img.shields.io/github/license/qingzi-zhang/dnspod-shell">
  </a>
</p>

Synchronize the IP address of DDNS with Tencent DNSPOD API 3.0 / 同步 DNSPod API 3.0 动态域名的地址

## Install
Clone this project and launch installation:
```
git clone https://github.com/qingzi-zhang/dnspod-shell
sudo cp dnspod-shell/ddnspod /etc/config/ddnspod
sudo ln -s dnspod-shell/ddnspod.sh /usr/bin/ddnspod.sh
sudo chmod 600 /usr/bin/ddnspod.sh
```
### Configuration
Adjust based on your DDNS information in config file: /etc/config/ddnspod
- SecretId
- SecretKey
- DDNS

## Usage
```
ddnspod.sh --help
```
Usage: ddnspod.sh [options]

Options:

  -h, --help          Display this help message

  -f, --force-update  Force update even if the IP address is up to date

  --log-file=FILE     Set LOG_FILE to FILE

  --log-level=0|1     Set LOG_LEVEL to 0 (info), 1 (notice)
