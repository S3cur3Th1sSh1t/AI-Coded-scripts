#!/usr/bin/env python3
"""
Nessus to Nmap XML Converter
Converts .nessus (XML) files to Nmap XML format, extracting open ports information.
"""

import xml.etree.ElementTree as ET
import argparse
import sys
from datetime import datetime
from collections import defaultdict


def parse_nessus_file(nessus_file):
    """Parse Nessus XML file and extract host and port information."""
    try:
        tree = ET.parse(nessus_file)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"Error parsing Nessus file: {e}", file=sys.stderr)
        sys.exit(1)
    
    hosts_data = defaultdict(lambda: {
        'name': '',
        'hostnames': [],
        'os': '',
        'mac': '',
        'ports': []
    })
    
    # Find all ReportHost elements
    for report in root.findall('.//Report'):
        for report_host in report.findall('ReportHost'):
            host_name = report_host.get('name', '')
            
            # Extract host properties
            host_properties = report_host.find('HostProperties')
            if host_properties is not None:
                for tag in host_properties.findall('tag'):
                    tag_name = tag.get('name', '')
                    tag_value = tag.text or ''
                    
                    if tag_name == 'host-ip':
                        hosts_data[host_name]['name'] = tag_value
                    elif tag_name == 'host-fqdn' or tag_name == 'hostname':
                        if tag_value and tag_value not in hosts_data[host_name]['hostnames']:
                            hosts_data[host_name]['hostnames'].append(tag_value)
                    elif tag_name == 'operating-system':
                        hosts_data[host_name]['os'] = tag_value
                    elif tag_name == 'mac-address':
                        hosts_data[host_name]['mac'] = tag_value
            
            # If name wasn't found in properties, use the ReportHost name attribute
            if not hosts_data[host_name]['name']:
                hosts_data[host_name]['name'] = host_name
            
            # Extract port information from ReportItems
            for report_item in report_host.findall('ReportItem'):
                port_num = report_item.get('port', '0')
                protocol = report_item.get('protocol', 'tcp')
                svc_name = report_item.get('svc_name', '')
                plugin_id = report_item.get('pluginID', '')
                
                # Skip port 0 (general findings not related to specific ports)
                if port_num == '0':
                    continue
                
                # Look for open port indicators
                # Plugin ID 10335 is "Nessus SYN scanner" which reports open ports
                # We also check for any findings on ports, as Nessus typically only reports on open ports
                port_info = {
                    'port': port_num,
                    'protocol': protocol,
                    'service': svc_name if svc_name else 'unknown',
                    'state': 'open'  # Nessus typically only reports open ports
                }
                
                # Check if this port is already in the list
                port_key = f"{port_num}/{protocol}"
                existing_ports = [p for p in hosts_data[host_name]['ports'] 
                                if f"{p['port']}/{p['protocol']}" == port_key]
                
                if not existing_ports:
                    hosts_data[host_name]['ports'].append(port_info)
                elif svc_name and not existing_ports[0]['service']:
                    # Update service name if we have more info
                    existing_ports[0]['service'] = svc_name
    
    return hosts_data


def create_nmap_xml(hosts_data, output_file, nessus_filename):
    """Create Nmap-compatible XML output."""
    
    # Create root element
    nmaprun = ET.Element('nmaprun')
    nmaprun.set('scanner', 'nessus2nmap')
    nmaprun.set('args', f'nessus2nmap conversion from {nessus_filename}')
    nmaprun.set('start', str(int(datetime.now().timestamp())))
    nmaprun.set('startstr', datetime.now().strftime('%a %b %d %H:%M:%S %Y'))
    nmaprun.set('version', '1.0')
    nmaprun.set('xmloutputversion', '1.04')
    
    # Add scaninfo
    scaninfo = ET.SubElement(nmaprun, 'scaninfo')
    scaninfo.set('type', 'syn')
    scaninfo.set('protocol', 'tcp')
    
    # Add verbose and debugging level
    verbose = ET.SubElement(nmaprun, 'verbose')
    verbose.set('level', '0')
    debugging = ET.SubElement(nmaprun, 'debugging')
    debugging.set('level', '0')
    
    # Process each host
    for host_key, host_data in hosts_data.items():
        if not host_data['ports']:
            continue  # Skip hosts with no open ports
        
        host = ET.SubElement(nmaprun, 'host')
        host.set('starttime', str(int(datetime.now().timestamp())))
        host.set('endtime', str(int(datetime.now().timestamp())))
        
        # Status
        status = ET.SubElement(host, 'status')
        status.set('state', 'up')
        status.set('reason', 'syn-ack')
        status.set('reason_ttl', '0')
        
        # Address
        address = ET.SubElement(host, 'address')
        address.set('addr', host_data['name'])
        address.set('addrtype', 'ipv4')
        
        # MAC address if available
        if host_data['mac']:
            mac_address = ET.SubElement(host, 'address')
            mac_address.set('addr', host_data['mac'])
            mac_address.set('addrtype', 'mac')
        
        # Hostnames
        hostnames_elem = ET.SubElement(host, 'hostnames')
        for hostname in host_data['hostnames']:
            hostname_elem = ET.SubElement(hostnames_elem, 'hostname')
            hostname_elem.set('name', hostname)
            hostname_elem.set('type', 'user')
        
        # Ports
        ports_elem = ET.SubElement(host, 'ports')
        
        # Sort ports for cleaner output
        sorted_ports = sorted(host_data['ports'], 
                            key=lambda x: (x['protocol'], int(x['port'])))
        
        for port_info in sorted_ports:
            port = ET.SubElement(ports_elem, 'port')
            port.set('protocol', port_info['protocol'])
            port.set('portid', port_info['port'])
            
            # State
            state = ET.SubElement(port, 'state')
            state.set('state', port_info['state'])
            state.set('reason', 'syn-ack')
            state.set('reason_ttl', '0')
            
            # Service
            service = ET.SubElement(port, 'service')
            service.set('name', port_info['service'])
            service.set('method', 'table')
            service.set('conf', '3')
        
        # OS information if available
        if host_data['os']:
            os_elem = ET.SubElement(host, 'os')
            osmatch = ET.SubElement(os_elem, 'osmatch')
            osmatch.set('name', host_data['os'])
            osmatch.set('accuracy', '100')
    
    # Add runstats
    runstats = ET.SubElement(nmaprun, 'runstats')
    finished = ET.SubElement(runstats, 'finished')
    finished.set('time', str(int(datetime.now().timestamp())))
    finished.set('timestr', datetime.now().strftime('%a %b %d %H:%M:%S %Y'))
    
    hosts = ET.SubElement(runstats, 'hosts')
    hosts.set('up', str(len([h for h in hosts_data.values() if h['ports']])))
    hosts.set('down', '0')
    hosts.set('total', str(len(hosts_data)))
    
    # Create tree and write to file
    tree = ET.ElementTree(nmaprun)
    ET.indent(tree, space='  ')  # Pretty print (Python 3.9+)
    
    try:
        with open(output_file, 'wb') as f:
            f.write(b'<?xml version="1.0" encoding="UTF-8"?>\n')
            f.write(b'<!DOCTYPE nmaprun>\n')
            tree.write(f, encoding='utf-8', xml_declaration=False)
        print(f"Successfully converted {nessus_filename} to {output_file}")
    except Exception as e:
        print(f"Error writing output file: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description='Convert Nessus .nessus (XML) files to Nmap XML format',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s scan.nessus
  %(prog)s scan.nessus -o output.xml
  %(prog)s scan.nessus --output nmap_results.xml
        '''
    )
    
    parser.add_argument('nessus_file', 
                       help='Input Nessus .nessus file')
    parser.add_argument('-o', '--output',
                       help='Output Nmap XML file (default: input_file.nmap.xml)',
                       default=None)
    
    args = parser.parse_args()
    
    # Set default output filename
    if args.output is None:
        if args.nessus_file.endswith('.nessus'):
            args.output = args.nessus_file[:-7] + '.nmap.xml'
        else:
            args.output = args.nessus_file + '.nmap.xml'
    
    print(f"Parsing Nessus file: {args.nessus_file}")
    hosts_data = parse_nessus_file(args.nessus_file)
    
    if not hosts_data:
        print("No hosts found in Nessus file", file=sys.stderr)
        sys.exit(1)
    
    total_hosts = len(hosts_data)
    hosts_with_ports = len([h for h in hosts_data.values() if h['ports']])
    total_ports = sum(len(h['ports']) for h in hosts_data.values())
    
    print(f"Found {total_hosts} host(s)")
    print(f"Found {hosts_with_ports} host(s) with open ports")
    print(f"Found {total_ports} open port(s) total")
    
    print(f"Creating Nmap XML: {args.output}")
    create_nmap_xml(hosts_data, args.output, args.nessus_file)


if __name__ == '__main__':
    main()
