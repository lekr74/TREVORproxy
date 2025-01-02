# TREVORproxy

A powerful SOCKS proxy in Python that randomizes source IP addresses. Rotate traffic through SSH tunnels or leverage billions of unique IPv6 addresses.

[![License](https://img.shields.io/badge/license-GPLv3-blue.svg)](https://raw.githubusercontent.com/blacklanternsecurity/nmappalyzer/master/LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.6+-blue)](https://www.python.org)

## Key Features

- **Subnet Proxy Mode**: Utilize Linux AnyIP to send traffic from an entire IPv6 subnet
- **SSH Proxy Mode**: Round-robin traffic through multiple SSH tunnels
- **High Scalability**: Support for over 18 quintillion unique IPv6 addresses (with /64 subnet)
- **WAF Bypass**: Rotate source IPs to avoid rate limiting and blocking
- **Clean Traffic**: Maintains full SOCKS functionality for legitimate return traffic

## Quick Start

### Installation

```bash
sudo apt update && sudo apt install iptables
sudo pip install git+https://github.com/lekr74/trevorproxy --break-system-packages
```

### Post-Installation Setup

1. Modify `cli.py` in `/usr/local/lib/python3.X/dist-packages/trevorproxy` to configure:
   - Username
   - Password
   - Listening IP

2. Install service file in `/etc/systemd/system/`

## Usage Examples

### IPv6 Subnet Mode

```bash
# Start proxy with single subnet
sudo trevorproxy subnet -s dead:beef::0/64 -i eth0

# Use multiple subnets
sudo trevorproxy subnet -s subnet1::/64 -s subnet2::/64 -i lo

# Test the connection
curl --proxy socks5://127.0.0.1:1080 -6 api64.ipify.org
```

### SSH Tunnel Mode

```bash
# Configure proxychains
echo "socks5 127.0.0.1 1080" >> /etc/proxychains.conf

# Start proxy with multiple SSH hosts
trevorproxy ssh root@1.2.3.4 root@4.3.2.1

# Test the connection
proxychains curl ifconfig.me
```

## Command Line Interface

### Global Options
```
-p PORT           SOCKS server port (default: 1080)
-l ADDRESS        Listen address (default: 127.0.0.1)
-q, --quiet       Quiet mode
-v, --debug       Verbose mode
```

### Subnet Mode Options
```
-i INTERFACE      Network interface
-s SUBNET         Source subnet(s)
```

### SSH Mode Options
```
-k KEY            SSH key file
--base-port PORT  Base port for SOCKS proxies (default: 32482)
ssh_hosts         SSH hosts (user@host format)
```

## Architecture

![TREVORproxy IPv6 Subnet Proxy Diagram](https://user-images.githubusercontent.com/20261699/149545633-a2f14f3a-1abc-4f9a-b589-3a52385ba635.png)

## Demo

![Subnet Proxy Demo](https://user-images.githubusercontent.com/20261699/142468206-4e9a46db-b18b-4969-8934-19d1f3837300.gif)

---

Created by [@thetechr0mancer](https://twitter.com/thetechr0mancer)

For more details, check out our [Blog Post](https://github.com/blacklanternsecurity/TREVORspray/blob/trevorspray-v2/blogpost.md)

![Trevor](https://user-images.githubusercontent.com/20261699/92336575-27071380-f070-11ea-8dd4-5ba42c7d04b7.jpeg)

`#trevorforget`
