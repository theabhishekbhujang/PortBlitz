# PortBlitz

PortBlitz is a powerful and versatile port scanning script designed to provide comprehensive information about open ports, services, and operating systems on target hosts. Utilizing the robust Nmap library, PortBlitz supports custom and full-range port scans, service detection, OS identification, verbose output, results saving (JSON/CSV), multiple targets, banner grabbing, timing templates, and DNS resolution.
### Features

* Scan Specific Ports: Scan a list of user-specified ports.
* Scan All Ports: Option to scan all ports (0-65535).
* Service Detection: Identify services running on open ports.
* Operating System Detection: Detect the operating system of the target host.
* Verbose Output: Provide detailed output for each scan.
* Output to File: Save results to a file in JSON or CSV format.
* Multiple Target Support: Scan multiple targets simultaneously.
* Banner Grabbing: Retrieve banners from open ports.
* Timing Templates: Choose different timing templates for faster or more stealthy scans.
* DNS Resolution: Resolve hostnames to IP addresses.

### Usage
```
PortBlitz.py [-h] [-p PORTS [PORTS ...]][-a] [-s] [-o] [-v] [-f OUTPUT_FILE] [-t {0,1,2,3,4,5}] target[target ...]


positional arguments:
  target                Target IP address(es) or hostname(s) to scan

optional arguments:
  -h, --help            show this help message and exit
  -p PORTS [PORTS ...], --ports PORTS [PORTS ...]
                        List of ports to scan (e.g., 21 22 80)
  -a, --all-ports       Scan all ports (0-65535)
  -s, --services        Detect services on open ports
  -o, --os              Detect operating system
  -v, --verbose         Verbose output
  -f OUTPUT_FILE, --output-file OUTPUT_FILE
                        Save results to a file (JSON or CSV)
  -t {0,1,2,3,4,5}, --timing {0,1,2,3,4,5}
                        Timing template (0-5)

```

### Requirements
* Python: Version 3.x
* python-nmap: A Python library that allows interaction with Nmap
* Nmap: The Nmap tool must be installed on your system from [official Nmap website](https://nmap.org/download)

Run the following command to install the dependencies:
```
pip install -r requirements.txt
```

