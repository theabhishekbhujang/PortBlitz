import nmap
import argparse
import socket
import ipaddress
import os

print(r"""
  _____           _   ____  _ _ _       
 |  __ \         | | |  _ \| (_) |      
 | |__) |__  _ __| |_| |_) | |_| |_ ____
 |  ___/ _ \| '__| __|  _ <| | | __|_  /
 | |  | (_) | |  | |_| |_) | | | |_ / / 
 |_|   \___/|_|   \__|____/|_|_|\__/___|
      
      By: Abhishek Bhujang                                   
""")

def parse_arguments():
    parser = argparse.ArgumentParser(description='Advanced port scanner using nmap')
    parser.add_argument('target', nargs='*', help='Target IP address(es), hostname(s), or CIDR notation to scan')
    parser.add_argument('-p', '--ports', nargs='+', default=None, help='List of ports to scan (e.g., 21 22 80)')
    parser.add_argument('-a', '--all-ports', action='store_true', help='Scan all ports (0-65535)')
    parser.add_argument('-s', '--services', action='store_true', help='Detect services on open ports')
    parser.add_argument('-o', '--os', action='store_true', help='Detect operating system')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-f', '--output-file', help='Save results to a text file')
    parser.add_argument('-t', '--timing', type=int, choices=range(0, 6), default=3, help='Timing template (0-5)')
    parser.add_argument('-u', '--udp', action='store_true', help='Perform UDP scan instead of TCP')
    parser.add_argument('-iL', '--input-file', help='Read target list from file (one target per line)')
    parser.add_argument('--ipv6', action='store_true', help='Enable IPv6 scanning')
    return parser.parse_args()

def resolve_hostname(target):
    if validate_ip(target):
        return target
    try:
        return socket.gethostbyname(target)
    except socket.error:
        return target

def validate_ip(ip_string):
    """Validate if a string is a valid IPv4 address."""
    try:
        parts = ip_string.split('.')
        return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
    except (AttributeError, ValueError):
        return False

def validate_ipv6(ip_string):
    """Validate if a string is a valid IPv6 address."""
    try:
        ipaddress.IPv6Address(ip_string)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False

def is_cidr_notation(target):
    """Check if target is in CIDR notation."""
    return '/' in target

def expand_cidr_to_hosts(cidr):
    """Expand CIDR notation to list of individual host IPs."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()] or [str(network.network_address)]
    except ValueError as e:
        print(f"Invalid CIDR notation '{cidr}': {e}")
        return []

def read_targets_from_file(filename):
    """Read targets from a file (one per line)."""
    if not os.path.exists(filename):
        print(f"Error: Target file '{filename}' not found.")
        return []
    
    targets = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):  # Skip empty lines and comments
                    targets.append(line)
        return targets
    except Exception as e:
        print(f"Error reading target file: {e}")
        return []

def save_results(results, filename):
    with open(filename, 'w') as f:
        for result in results:
            f.write(f"\nHost {result['host']} is {result['status']}\n")
            for port in result['ports']:
                f.write(f"Port {port['port']} is {port['state']}\n")


def build_scan_args(services, os_detect, timing_template, udp=False, ipv6=False):
    """Construct the nmap scan argument string from flags."""
    args = f"-T{timing_template}"
    if udp:
        args += ' -sU'  # UDP scan
    if services:
        args += ' -sV'
    if os_detect:
        args += ' -O'
    if ipv6:
        args += ' -6'  # Enable IPv6
    return args

def determine_ports_range(all_ports, ports):
    """Return port range string based on flags and provided ports."""
    if all_ports:
        return '0-65535'
    return ','.join(ports) if ports else '1-1024'

def is_port_open(port_entry):
    """Return True if a parsed port entry indicates an open port."""
    state = str(port_entry.get('state', '')).lower()
    return state == 'open'

def format_port_output(port, service=None):
    """Format port information for display."""
    if service and service != 'unknown':
        return f"Port {port} is open - Service: {service}"
    return f"Port {port} is open"

def generate_scan_summary(results):
    """Generate a comprehensive summary of scan results with statistics."""
    total_hosts = len(results)
    total_ports_scanned = 0
    open_ports_count = 0
    closed_ports_count = 0
    filtered_ports_count = 0
    
    summary_lines = []
    summary_lines.append("\n" + "="*60)
    summary_lines.append("SCAN SUMMARY REPORT")
    summary_lines.append("="*60)
    
    for result in results:
        host_ports = len(result['ports'])
        total_ports_scanned += host_ports
        
        host_open = 0
        host_closed = 0
        host_filtered = 0
        
        for port in result['ports']:
            if port['state'] == 'open':
                open_ports_count += 1
                host_open += 1
            elif port['state'] == 'closed':
                closed_ports_count += 1
                host_closed += 1
            elif port['state'] == 'filtered':
                filtered_ports_count += 1
                host_filtered += 1
        
        summary_lines.append(f"\nHost: {result['host']} ({result['status']})")
        summary_lines.append(f"  Total ports scanned: {host_ports}")
        summary_lines.append(f"  Open ports: {host_open}")
        summary_lines.append(f"  Closed ports: {host_closed}")
        summary_lines.append(f"  Filtered ports: {host_filtered}")
    
    summary_lines.append(f"\nOVERALL STATISTICS:")
    summary_lines.append(f"  Total hosts scanned: {total_hosts}")
    summary_lines.append(f"  Total ports scanned: {total_ports_scanned}")
    summary_lines.append(f"  Open ports found: {open_ports_count}")
    summary_lines.append(f"  Closed ports: {closed_ports_count}")
    summary_lines.append(f"  Filtered ports: {filtered_ports_count}")
    
    if total_ports_scanned > 0:
        open_percentage = (open_ports_count / total_ports_scanned) * 100
        summary_lines.append(f"  Open port percentage: {open_percentage:.2f}%")
    
    summary_lines.append("="*60)
    
    return "\n".join(summary_lines)


def main():
    args = parse_arguments()
    
    # Initialize variables first
    ports = args.ports if not args.all_ports else None  # Added None to indicate all ports
    services = args.services
    os_detect = args.os
    verbose = args.verbose
    output_file = args.output_file
    timing_template = args.timing
    udp_scan = args.udp
    ipv6_enabled = args.ipv6
    
    # Handle target input from file or command line
    targets = []
    if args.input_file:
        targets = read_targets_from_file(args.input_file)
        if not targets:
            print("No valid targets found in file. Exiting.")
            return
    elif args.target:
        targets = args.target
    else:
        print("Error: No targets specified. Use target arguments or -iL to specify a target file.")
        return
    
    # Expand CIDR notation targets
    expanded_targets = []
    for target in targets:
        if is_cidr_notation(target):
            if verbose:
                print(f"Expanding CIDR notation: {target}")
            expanded = expand_cidr_to_hosts(target)
            expanded_targets.extend(expanded)
            if verbose:
                print(f"  Found {len(expanded)} hosts in range")
        else:
            expanded_targets.append(target)
    
    targets = expanded_targets

    scan_v = nmap.PortScanner()
    results = []
    
    if verbose:
        scan_type = "UDP" if udp_scan else "TCP"
        print(f"\nStarting {scan_type} scan on {len(targets)} target(s)...")
        if ipv6_enabled:
            print("IPv6 scanning enabled")

    for target in targets:
        target_ip = resolve_hostname(target)
        try:
            # Prepare scan arguments with new features
            scan_args = build_scan_args(services, os_detect, timing_template, udp_scan, ipv6_enabled)

            # If scanning all ports, Nmap will use 0-65535 range
            if args.all_ports:
                ports_range = '0-65535'
                if verbose:
                    print(f"\nScanning {target_ip} for all ports...")
            else:
                ports_range = ','.join(ports) if ports else '1-1024'
                if verbose:
                    scan_type = "UDP" if udp_scan else "TCP"
                    print(f"\nScanning {target_ip} for {scan_type} ports {ports_range}...\n")

            # Perform the scan
            portscan = scan_v.scan(target_ip, ports_range, arguments=scan_args)

            # Process the results
            for host in portscan['scan']:
                result = {'host': host, 'status': portscan['scan'][host]['status']['state'], 'ports': []}
                
                # Determine which protocol to check based on scan type
                protocol = 'udp' if udp_scan else 'tcp'
                
                if protocol in portscan['scan'][host]:
                    for port in portscan['scan'][host][protocol]:
                        state = portscan['scan'][host][protocol][port]['state']
                        service_info = portscan['scan'][host][protocol][port].get('name', 'unknown') if services else 'unknown'
                        result['ports'].append({'port': port, 'state': state, 'service': service_info, 'protocol': protocol.upper()})

                results.append(result)

                if os_detect and 'osmatch' in portscan['scan'][host]:
                    for os_match in portscan['scan'][host]['osmatch']:
                        if verbose:
                            print(f"OS: {os_match['name']} (accuracy: {os_match['accuracy']}%)")

        except Exception as e:
            print(f"An error occurred while scanning {target_ip}: {e}")

    # Print results to the terminal
    for result in results:
        print(f"\nHost {result['host']} is {result['status']}\n")
        for port in result['ports']:
          protocol = port.get('protocol', 'TCP')
          if port['state'] == 'open':
            service = port.get('service', 'unknown')
            if service and service != 'unknown':
                print(f"Port {port['port']}/{protocol} is open - Service: {service}")
            else:
                print(f"Port {port['port']}/{protocol} is open")
          else:
            print(f"Port {port['port']}/{protocol} is {port['state']}")
    if results:
        print(generate_scan_summary(results))
    # Save results to a file
    if output_file:
        save_results(results, output_file)

if __name__ == "__main__":
    main()






