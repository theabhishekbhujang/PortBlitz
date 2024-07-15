# PortBlitz
PortBlitz is a sleek and efficient port scanning script designed to quickly identify open ports on a target IP address. Utilizing the powerful Nmap library, PortBlitz scans a predefined set of common ports, providing immediate feedback on their status.

### Features

* Scans common ports: 21 (FTP), 22 (SSH), 80 (HTTP), 139 (NetBIOS), 443 (HTTPS), 8080 (HTTP Alternative)
* Outputs port status and overall host state
* Simple to use: Just provide the target IP address as a command-line argument
* Built on Nmap: Leveraging the capabilities of the Nmap library, PortBlitz ensures reliable and accurate port scanning.

### Usage
```
python portblitz.py ip_address
```

### Requirements
* Python: Version 3.x
* python-nmap: A Python library that allows interaction with Nmap
* Nmap: The Nmap tool must be installed on your system from [official Nmap website](https://nmap.org/download)

Run the following command to install the dependencies:
```
pip install -r requirements.txt
```

