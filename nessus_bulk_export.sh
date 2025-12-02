#!/usr/bin/env python3
"""
Extract HTTP/HTTPS URLs from Nessus or Nmap XML files
Outputs a list of URLs in the format http(s)://host:port
"""

import xml.etree.ElementTree as ET
import argparse
import sys
from collections import defaultdict


# Common HTTP/HTTPS service names and ports
HTTP_SERVICES = {
    'http', 'www', 'http-proxy', 'http-alt', 'https', 'https-alt',
    'ssl/http', 'ssl/https', 'http?', 'https?', 'www-http', 'web',
    'http-rpc-epmap', 'apache', 'nginx', 'iis', 'tomcat', 'webserver',
    'lighttpd', 'httpd', 'http-wmap', 'ssl|http'
}

HTTPS_PORTS = {443, 8443, 9443, 10443, 4443, 8834, 3443, 7443}


def is_http_service(service_name, port_num):
    """Determine if a service is HTTP/HTTPS based on name and port."""
    service_lower = service_name.lower()
    
    # Check if service name indicates HTTP
    if any(http_svc in service_lower for http_svc in HTTP_SERVICES):
        return True
    
    # Check common HTTP ports
    if port_num in [80, 8080, 8000, 8008, 8888, 9000, 9090, 3000, 5000, 8081, 8082, 8083]:
        return True
    
    # Check common HTTPS ports
    if port_num in HTTPS_PORTS:
        return True
    
    return False


def is_https(service_name, port_num):
    """Determine if the service uses HTTPS/SSL."""
    service_lower = service_name.lower()
    
    # Explicit HTTPS indicators in service name
    if 'https' in service_lower or 'ssl' in service_lower or 'tls' in service_lower:
        return True
    
    # Standard HTTPS ports
    if port_num in HTTPS_PORTS:
        return True
    
    return False


def parse_nmap_file(xml_file):
    """Parse Nmap XML file and extract HTTP/HTTPS services."""
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"Error parsing XML file: {e}", file=sys.stderr)
        sys.exit(1)
    
    http_services = []
    
    # Check if it's an Nmap XML file
    if root.tag == 'nmaprun':
        for host in root.findall('.//host'):
            # Get host status
            status = host.find('status')
            if status is not None and status.get('state') != 'up':
                continue
            
            # Get host address
            address_elem = host.find("address[@addrtype='ipv4']")
            if address_elem is None:
                address_elem = host.find("address[@addrtype='ipv6']")
            if address_elem is None:
                continue
            
            host_addr = address_elem.get('addr')
            
            # Try to get hostname
            hostname = None
            hostnames = host.find('hostnames')
            if hostnames is not None:
                hostname_elem = hostnames.find('hostname')
                if hostname_elem is not None:
                    hostname = hostname_elem.get('name')
            
            # Use hostname if available, otherwise use IP
            host_name = hostname if hostname else host_addr
            
            # Check all ports
            ports = host.find('ports')
            if ports is not None:
                for port in ports.findall('port'):
                    state = port.find('state')
                    if state is not None and state.get('state') != 'open':
                        continue
                    
                    port_num = int(port.get('portid'))
                    protocol = port.get('protocol')
                    
                    # Only process TCP ports
                    if protocol != 'tcp':
                        continue
                    
                    service = port.find('service')
                    service_name = ''
                    if service is not None:
                        service_name = service.get('name', '')
                        # Check for SSL tunnel attribute
                        ssl_tunnel = service.get('tunnel', '')
                        if ssl_tunnel == 'ssl':
                            service_name = f"ssl/{service_name}"
                    
                    # Check if it's an HTTP service
                    if is_http_service(service_name, port_num):
                        is_ssl = is_https(service_name, port_num)
                        protocol_str = 'https' if is_ssl else 'http'
                        url = f"{protocol_str}://{host_name}:{port_num}"
                        http_services.append(url)
    
    return http_services


def parse_nessus_file(xml_file):
    """Parse Nessus XML file and extract HTTP/HTTPS services."""
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"Error parsing XML file: {e}", file=sys.stderr)
        sys.exit(1)
    
    http_services = []
    hosts_checked = set()
    
    # Check if it's a Nessus XML file
    if root.tag == 'NessusClientData_v2':
        for report in root.findall('.//Report'):
            for report_host in report.findall('ReportHost'):
                host_name = report_host.get('name', '')
                
                # Try to get FQDN
                host_properties = report_host.find('HostProperties')
                fqdn = None
                if host_properties is not None:
                    for tag in host_properties.findall('tag'):
                        if tag.get('name') == 'host-fqdn':
                            fqdn = tag.text
                            break
                        elif tag.get('name') == 'hostname' and not fqdn:
                            fqdn = tag.text
                
                # Use FQDN if available, otherwise IP
                display_name = fqdn if fqdn else host_name
                
                # Track ports for this host
                host_ports = defaultdict(lambda: {'service': '', 'ssl': False})
                
                # Extract port information from ReportItems
                for report_item in report_host.findall('ReportItem'):
                    port_num = report_item.get('port', '0')
                    if port_num == '0':
                        continue
                    
                    port_num = int(port_num)
                    protocol = report_item.get('protocol', 'tcp')
                    
                    # Only process TCP ports
                    if protocol != 'tcp':
                        continue
                    
                    svc_name = report_item.get('svc_name', '')
                    plugin_name = report_item.get('pluginName', '')
                    plugin_id = report_item.get('pluginID', '')
                    
                    # Check for SSL/TLS indicators
                    if 'ssl' in plugin_name.lower() or 'tls' in plugin_name.lower():
                        host_ports[port_num]['ssl'] = True
                    
                    # Update service name if we have one
                    if svc_name:
                        if not host_ports[port_num]['service']:
                            host_ports[port_num]['service'] = svc_name
                        # If we see 'www' service, update it
                        elif svc_name in ['www', 'http', 'https']:
                            host_ports[port_num]['service'] = svc_name
                
                # Process collected ports
                for port_num, info in host_ports.items():
                    service_name = info['service']
                    has_ssl = info['ssl']
                    
                    # Check if it's an HTTP service
                    if is_http_service(service_name, port_num):
                        is_ssl = has_ssl or is_https(service_name, port_num)
                        protocol_str = 'https' if is_ssl else 'http'
                        url = f"{protocol_str}://{display_name}:{port_num}"
                        
                        # Avoid duplicates
                        if url not in hosts_checked:
                            http_services.append(url)
                            hosts_checked.add(url)
    
    return http_services


def detect_file_type(xml_file):
    """Detect if the file is Nmap or Nessus format."""
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        
        if root.tag == 'nmaprun':
            return 'nmap'
        elif root.tag == 'NessusClientData_v2':
            return 'nessus'
        else:
            return None
    except Exception as e:
        print(f"Error detecting file type: {e}", file=sys.stderr)
        return None


def main():
    parser = argparse.ArgumentParser(
        description='Extract HTTP/HTTPS URLs from Nessus or Nmap XML files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s scan.nmap.xml
  %(prog)s scan.nessus -o urls.txt
  %(prog)s scan.xml --sort
  %(prog)s scan.xml --unique
        '''
    )
    
    parser.add_argument('input_file',
                       help='Input Nessus (.nessus) or Nmap (.xml) file')
    parser.add_argument('-o', '--output',
                       help='Output file for URLs (default: stdout)',
                       default=None)
    parser.add_argument('-s', '--sort',
                       help='Sort URLs alphabetically',
                       action='store_true')
    parser.add_argument('-u', '--unique',
                       help='Remove duplicate URLs',
                       action='store_true')
    parser.add_argument('--http-only',
                       help='Only output HTTP URLs (no HTTPS)',
                       action='store_true')
    parser.add_argument('--https-only',
                       help='Only output HTTPS URLs (no HTTP)',
                       action='store_true')
    
    args = parser.parse_args()
    
    # Detect file type
    file_type = detect_file_type(args.input_file)
    
    if file_type is None:
        print("Error: Unable to detect file type. File must be Nmap or Nessus XML format.", 
              file=sys.stderr)
        sys.exit(1)
    
    print(f"Detected {file_type.upper()} file format", file=sys.stderr)
    print(f"Parsing: {args.input_file}", file=sys.stderr)
    
    # Parse the file
    if file_type == 'nmap':
        http_services = parse_nmap_file(args.input_file)
    else:  # nessus
        http_services = parse_nessus_file(args.input_file)
    
    if not http_services:
        print("No HTTP/HTTPS services found", file=sys.stderr)
        sys.exit(0)
    
    # Filter by protocol if requested
    if args.http_only:
        http_services = [url for url in http_services if url.startswith('http://')]
    elif args.https_only:
        http_services = [url for url in http_services if url.startswith('https://')]
    
    # Remove duplicates if requested
    if args.unique:
        http_services = list(set(http_services))
    
    # Sort if requested
    if args.sort:
        http_services.sort()
    
    print(f"Found {len(http_services)} HTTP/HTTPS service(s)", file=sys.stderr)
    
    # Output results
    output_content = '\n'.join(http_services) + '\n'
    
    if args.output:
        try:
            with open(args.output, 'w') as f:
                f.write(output_content)
            print(f"URLs written to: {args.output}", file=sys.stderr)
        except Exception as e:
            print(f"Error writing output file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print(output_content, end='')


if __name__ == '__main__':
    main()
