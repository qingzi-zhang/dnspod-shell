<div align="center">
  <h1>A DDNS Shell Script: ddnspod.sh</h1>
</div>

<p align="center">
  <a href="https://github.com/qingzi-zhang/dnspod-shell/blob/main/LICENSE">
    <img alt="Apache License Version 2.0" src="https://img.shields.io/github/license/qingzi-zhang/dnspod-shell">
  </a>
</p>

🔁 **Synchronize DDNS via DNSPod API 3.0**

![diagram](ddnspod.svg)

## Installation
Clone & Setup:
```
git clone https://github.com/qingzi-zhang/dnspod-shell
sudo cp dnspod-shell/ddnspod /etc/config/ddnspod
sudo chmod 0555 dnspod-shell/ddnspod.sh
sudo ln -s dnspod-shell/ddnspod.sh /usr/bin/ddnspod.sh
```

## Configuration
Replace the DDNS configuration in the file: `/etc/config/ddnspod`
- LogFile=`/var/log/ddnspod.log`
- SecretId=`AKIDz8krbsJ5yKBZQpn74WFkmLPx3*******`
- SecretKey=`Gu5t9xGARNpq86cd98joQYCN3*******`
- DDNS=`domain,subdomain,type,interface`
- DDNS=`domain.ai,www,IPv6,pppoe-wan`

## Usage
```
Usage:
  ddnspod.sh [options]

Options:
  -h, --help           Print this help message
  --config=<file>      Read config from a file
  --force-update       Proceed with the update regardless of IP status
  --log-level=<0|1>    Set the log level to 0 or 1 (0: Error, 1: Verbose)
```
