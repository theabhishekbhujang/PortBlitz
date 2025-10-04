import nmap
import argparse
import socket

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
    parser.add_argument('target', nargs='+', help='Target IP address(es) or hostname(s) to scan')
    parser.add_argument('-p', '--ports', nargs='+', default=None, help='List of ports to scan (e.g., 21 22 80)')
    parser.add_argument('-a', '--all-ports', action='store_true', help='Scan all ports (0-65535)')
    parser.add_argument('-s', '--services', action='store_true', help='Detect services on open ports')
    parser.add_argument('-o', '--os', action='store_true', help='Detect operating system')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-f', '--output-file', help='Save results to a text file')
    parser.add_argument('-t', '--timing', type=int, choices=range(0, 6), default=3, help='Timing template (0-5)')
    return parser.parse_args()

def resolve_hostname(target):
    try:
        return socket.gethostbyname(target)
    except socket.error:
        return target

def save_results(results, filename):
    with open(filename, 'w') as f:
        for result in results:
            f.write(f"\nHost {result['host']} is {result['status']}\n")
            for port in result['ports']:
                f.write(f"Port {port['port']} is {port['state']}\n")


def build_scan_args(services, os_detect, timing_template):
    """Construct the nmap scan argument string from flags."""
    args = f"-T{timing_template}"
    if services:
        args += ' -sV'
    if os_detect:
        args += ' -O'
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
    targets = args.target
    ports = args.ports if not args.all_ports else None  # Added None to indicate all ports
    services = args.services
    os_detect = args.os
    verbose = args.verbose
    output_file = args.output_file
    timing_template = args.timing

    scan_v = nmap.PortScanner()
    results = []

    for target in targets:
        target_ip = resolve_hostname(target)
        try:
            # Prepare scan arguments
            scan_args = f"-T{timing_template}"
            if services:
                scan_args += ' -sV'  # Added to detect services
            if os_detect:
                scan_args += ' -O'

            # If scanning all ports, Nmap will use 0-65535 range
            if args.all_ports:
                ports_range = '0-65535'
                if verbose:
                    print(f"\nScanning {target_ip} for all ports...")
            else:
                ports_range = ','.join(ports) if ports else '1-1024'
                if verbose:
                    print(f"\nScanning {target_ip} for ports {ports_range}...\n")

            # Perform the scan
            portscan = scan_v.scan(target_ip, ports_range, arguments=scan_args)

            # Process the results
            for host in portscan['scan']:
                result = {'host': host, 'status': portscan['scan'][host]['status']['state'], 'ports': []}
                if 'tcp' in portscan['scan'][host]:
                    for port in portscan['scan'][host]['tcp']:
                        state = portscan['scan'][host]['tcp'][port]['state']
                        service_info = portscan['scan'][host]['tcp'][port].get('name', 'unknown') if services else 'unknown'
                        result['ports'].append({'port': port, 'state': state})

                results.append(result)

                if os_detect and 'osmatch' in portscan['scan'][host]:
                    for os_match in portscan['scan'][host]['osmatch']:
                        if verbose:
                            print(f"OS: {os_match['name']} (accuracy: {os_match['accuracy']}%)")

        except Exception as e:
            print(f"An error occurred: {e}")

    # Print results to the terminal
    for result in results:
        print(f"\nHost {result['host']} is {result['status']}\n")
        for port in result['ports']:
            print(f"Port {port['port']} is {port['state']}")

    # Save results to a file
    if output_file:
        save_results(results, output_file)

if __name__ == "__main__":
    main()



