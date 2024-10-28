<div align="center">
  <h1>A DDNS Shell Script: ddnspod.sh</h1>
</div>

<p align="center">
  <a href="https://github.com/qingzi-zhang/dnspod-shell/blob/main/LICENSE">
    <img alt="Apache License Version 2.0" src="https://img.shields.io/github/license/qingzi-zhang/dnspod-shell">
  </a>
</p>

[English](README.md) | 中文

**:~$ 同步基于DDNPod 3.0的动态域名**

## 安装
Clone & installation:
```
git clone https://github.com/qingzi-zhang/dnspod-shell
sudo cp dnspod-shell/ddnspod /etc/config/ddnspod
sudo ln -s dnspod-shell/ddnspod.sh /usr/bin/ddnspod.sh
sudo chmod 600 /usr/bin/ddnspod.sh
```

## 配置
修改配置文件: `/etc/config/ddnspod`
- SecretId=`AKIDz8krbsJ5yKBZQpn74WFkmLPx3*******`
- SecretKey=`Gu5t9xGARNpq86cd98joQYCN3*******`
- DDNS=`domain,subdomain,type,interface`
- DDNS=`domain.ai,www,IPv6,pppoe-wan`

## 使用
```
执行指令:
  ddnspod.sh [默认不带参数]

Options:
  -h, --help           Show help.
  --config=<file>      Specify the config file
  --force-update       Proceed update regardless of IP status
  --log-level=<0|1>    Log level 0 (info), 1 (notice)
```