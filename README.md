# PortBlitz

**PortBlitz** is a powerful and versatile port scanning script designed to provide comprehensive information about open ports, services, and operating systems on target hosts. Utilizing the robust Nmap library, **PortBlitz** supports custom and full-range port scans, service detection, OS identification, verbose output, results saving (JSON/CSV), multiple targets, banner grabbing, timing templates, and DNS resolution.
### Features

* **Scan Specific Ports**: Scan a list of user-specified ports.
* **Scan All Ports**: Option to scan all ports (0-65535).
* **Service Detection**: Identify services running on open ports.
* **Operating System Detection**: Detect the operating system of the target host.
* **Verbose Output**: Provide detailed output for each scan.
* **Output to File**: Save results to a file in JSON or CSV format.
* **Multiple Target Support**: Scan multiple targets simultaneously.
* **Banner Grabbing**: Retrieve banners from open ports.
* **Timing Templates**: Choose different timing templates for faster or more stealthy scans.
* **DNS Resolution**: Resolve hostnames to IP addresses.
* **UDP Scanning**: Perform UDP scans to detect UDP services (requires root/sudo).
* **IPv6 Support**: Scan IPv6 addresses and networks.
* **CIDR Notation**: Scan entire network ranges using CIDR notation (e.g., 192.168.1.0/24).
* **Target List Files**: Read targets from a file for batch scanning.

### Usage
```
PortBlitz.py [-h] [-p PORTS [PORTS ...]] [-a] [-s] [-o] [-v] [-f OUTPUT_FILE] 
             [-t {0,1,2,3,4,5}] [-u] [-iL INPUT_FILE] [--ipv6] [target ...]


positional arguments:
  target                Target IP address(es), hostname(s), or CIDR notation to scan

optional arguments:
  -h, --help            show this help message and exit
  -p PORTS [PORTS ...], --ports PORTS [PORTS ...]
                        List of ports to scan (e.g., 21 22 80)
  -a, --all-ports       Scan all ports (0-65535)
  -s, --services        Detect services on open ports
  -o, --os              Detect operating system (requires root/sudo)
  -v, --verbose         Verbose output
  -f OUTPUT_FILE, --output-file OUTPUT_FILE
                        Save results to a file
  -t {0,1,2,3,4,5}, --timing {0,1,2,3,4,5}
                        Timing template (0-5, default: 3)
  -u, --udp             Perform UDP scan instead of TCP (requires root/sudo)
  -iL INPUT_FILE, --input-file INPUT_FILE
                        Read target list from file (one target per line)
  --ipv6                Enable IPv6 scanning

```

### Requirements
* **Python**: Version 3.x
* **python-nmap**: A Python library that allows interaction with Nmap
* **Nmap**: The Nmap tool must be installed on your system from [official Nmap website](https://nmap.org/download)

Run the following command to install the dependencies:
```
pip install -r requirements.txt
```

### Examples

#### Basic Scanning
```bash
# Scan default ports on a single target
python PortBlitz.py 192.168.1.1

# Scan specific ports
python PortBlitz.py 192.168.1.1 -p 80 443 8080

# Scan all ports
python PortBlitz.py 192.168.1.1 -a
```

#### Advanced Scanning
```bash
# UDP scan (requires root/sudo)
sudo python PortBlitz.py 192.168.1.1 -u -p 53 161 514

# Scan with service detection
python PortBlitz.py 192.168.1.1 -s -p 21 22 80 443

# OS detection with verbose output (requires root/sudo)
sudo python PortBlitz.py 192.168.1.1 -o -v
```

#### Network Range Scanning
```bash
# Scan entire subnet using CIDR notation
python PortBlitz.py 192.168.1.0/24 -p 80 443

# Scan multiple CIDR ranges
python PortBlitz.py 192.168.1.0/24 10.0.0.0/24 -s
```

#### Batch Scanning with Target Files
```bash
# Create a target list file
echo "192.168.1.1" > targets.txt
echo "192.168.1.10" >> targets.txt
echo "scanme.nmap.org" >> targets.txt

# Scan targets from file
python PortBlitz.py -iL targets.txt -p 80 443 -s
```

#### IPv6 Scanning
```bash
# Scan IPv6 address
python PortBlitz.py 2001:db8::1 --ipv6 -p 80 443

# Scan IPv6 CIDR range
python PortBlitz.py 2001:db8::/64 --ipv6 -s
```

#### Combined Features
```bash
# Comprehensive scan with all features
sudo python PortBlitz.py 192.168.1.0/24 -a -s -o -v -f results.txt

# Fast UDP service scan from file
sudo python PortBlitz.py -iL targets.txt -u -s -t 4 -f udp_scan.txt
```

### Important Notes
- **Root/Sudo Required**: UDP scans (`-u`) and OS detection (`-o`) require root privileges
- **CIDR Notation**: Supports both IPv4 (192.168.1.0/24) and IPv6 (2001:db8::/64) ranges
- **Target Files**: One target per line, supports comments with `#`
- **Timing Templates**: Range from 0 (paranoid) to 5 (insane), default is 3 (normal)

