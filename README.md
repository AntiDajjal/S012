# S012 Shodan Scanner

A network reconnaissance tool that leverages the Shodan search engine for authorized security assessment and research.

## Features

- Multi-API key support with automatic rotation
- Rate limiting and error handling
- Multiple output formats (JSON, CSV, TXT)
- Real-time progress monitoring
- Interactive command-line interface

## Installation

```bash
git clone https://github.com/Antidajjal/S012.git
cd S012
pip install -r requirements.txt
```

## Configuration

Configure your Shodan API keys on first run:

```bash
python S012.py
```

API keys are stored in `api_keys.txt` for subsequent use.

## Usage

Run the scanner in interactive mode:

```bash
python S012.py
```

Menu options:
1. Start Search - Begin a new Shodan search
2. Manage API Keys - Add, remove, or validate API keys
3. View Statistics - Display session statistics
4. Exit - Quit application

## Output Formats

### JSON
```json
{
  "metadata": {
    "scan_date": "20250706_143022",
    "total_results": 1500,
    "query": "apache"
  },
  "results": [
    {
      "ip": "192.168.1.1",
      "port": 80,
      "organization": "Example ISP",
      "country": "United States",
      "vulnerabilities": ["CVE-2023-1234"]
    }
  ]
}
```

### CSV
```
IP,Port,Protocol,Organization,Country,City,Domains,Vulnerabilities
192.168.1.1,80,http,Example ISP,United States,New York,example.com,CVE-2023-1234
```

### TXT
```
IP: 192.168.1.1
Port: 80
Organization: Example ISP
Location: New York, United States
Vulnerabilities: CVE-2023-1234
------------------------------------------------------------
```

## Shodan Search Dorks

### Web Services
```
apache
nginx
IIS
"Server: Apache"
"Server: nginx"
"Microsoft-IIS"
```

### Databases
```
mysql
mongodb
redis
elasticsearch
"MongoDB Server Information"
"mysql_native_password"
"Redis server"
```

### Remote Access
```
ssh
rdp
vnc
telnet
port:22
port:3389
port:5900
port:23
```

### IoT and Embedded Devices
```
"Server: gSOAP"
"Hikvision-Webs"
"Web Server"
"webcam"
"DVR"
"IP Camera"
"router"
"printer"
```

### Industrial Control Systems
```
"Schneider Electric"
"Siemens"
"Allen-Bradley"
"Modbus"
"DNP3"
"BACnet"
scada
```

### Cloud Services
```
"Amazon S3"
"Google Cloud"
"Microsoft Azure"
"Docker"
"Kubernetes"
"Jenkins"
```

### Vulnerabilities
```
vuln:CVE-2017-0144
vuln:CVE-2021-44228
vuln:CVE-2014-0160
vuln:CVE-2017-5638
```

### Geographic Targeting
```
country:US
country:CN
country:RU
city:"New York"
city:"London"
```

### Port-Specific Searches
```
port:80
port:443
port:21
port:22
port:23
port:25
port:53
port:110
port:143
port:993
port:995
port:1433
port:3306
port:5432
port:6379
port:9200
port:27017
```

### Organization-Specific
```
org:"Google"
org:"Amazon"
org:"Microsoft"
org:"Facebook"
net:8.8.8.8/24
```

### Combined Searches
```
apache country:US
nginx ssl:true
mongodb country:CN
"default password" port:80
ssh country:RU
rdp country:US
```

### Security Research
```
"default password"
"admin:admin"
"root:root"
"guest:guest"
"login"
"password"
"authentication"
```

## Examples

**Web Server Discovery**
```
Query: apache country:US
Max Results: 1000
Output: apache_servers.csv
```

**Vulnerability Research**
```
Query: vuln:CVE-2023-1234
Max Results: 500
Output: cve_affected.json
```

**IoT Device Discovery**
```
Query: "Server: gSOAP" port:80
Max Results: unlimited
Output: iot_devices.json
```

**Database Exposure**
```
Query: mongodb country:CN
Max Results: 2000
Output: mongodb_exposed.txt
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Invalid API key | Verify key at shodan.io/account |
| Rate limit reached | Add multiple API keys |
| Connection timeout | Check internet connection |
| High memory usage | Use result limits |

## Requirements

- Python 3.6+
- Valid Shodan API key
- Internet connection

## Legal Notice

This tool is for authorized security testing and educational purposes only. Users are responsible for compliance with applicable laws and obtaining proper authorization before scanning networks.

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Support

- Issues: [GitHub Issues](https://github.com/Antidajjal/S012/issues)
- Website: [m012.info](https://m012.info)
