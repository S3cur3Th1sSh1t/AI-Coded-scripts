#!/usr/bin/env python3
"""
Nessus .nessus XML Parser
"""

import xml.etree.ElementTree as ET
import sys
import argparse
from pathlib import Path
import os

def find_hosts_by_cve(nessus_file, cve):
    """Find all hosts affected by a specific CVE"""
    tree = ET.parse(nessus_file)
    root = tree.getroot()
    
    results = []
    
    for report_host in root.findall('.//ReportHost'):
        hostname = report_host.get('name')
        host_ip = report_host.find('.//tag[@name="host-ip"]')
        ip = host_ip.text if host_ip is not None else hostname
        
        for item in report_host.findall('.//ReportItem'):
            cve_elements = item.findall('.//cve')
            
            for cve_elem in cve_elements:
                if cve.upper() in cve_elem.text.upper():
                    results.append({
                        'hostname': hostname,
                        'ip': ip,
                        'plugin_id': item.get('pluginID'),
                        'plugin_name': item.get('pluginName'),
                        'severity': item.get('severity'),
                        'cve': cve_elem.text
                    })
    
    return results

def find_hosts_by_description(nessus_file, keyword):
    """Find hosts by vulnerability description"""
    tree = ET.parse(nessus_file)
    root = tree.getroot()
    
    results = []
    
    for report_host in root.findall('.//ReportHost'):
        hostname = report_host.get('name')
        host_ip = report_host.find('.//tag[@name="host-ip"]')
        ip = host_ip.text if host_ip is not None else hostname
        
        for item in report_host.findall('.//ReportItem'):
            description = item.find('.//description')
            synopsis = item.find('.//synopsis')
            plugin_name = item.get('pluginName', '')
            
            desc_text = description.text if description is not None else ""
            syn_text = synopsis.text if synopsis is not None else ""
            
            if (keyword.lower() in desc_text.lower() or 
                keyword.lower() in syn_text.lower() or 
                keyword.lower() in plugin_name.lower()):
                
                results.append({
                    'hostname': hostname,
                    'ip': ip,
                    'plugin_id': item.get('pluginID'),
                    'plugin_name': plugin_name,
                    'severity': item.get('severity'),
                })
    
    return results

def find_by_plugin_id(nessus_file, plugin_id):
    """Find hosts by Plugin ID"""
    tree = ET.parse(nessus_file)
    root = tree.getroot()
    
    results = []
    
    for report_host in root.findall('.//ReportHost'):
        hostname = report_host.get('name')
        host_ip = report_host.find('.//tag[@name="host-ip"]')
        ip = host_ip.text if host_ip is not None else hostname
        
        for item in report_host.findall(f'.//ReportItem[@pluginID="{plugin_id}"]'):
            results.append({
                'hostname': hostname,
                'ip': ip,
                'plugin_id': item.get('pluginID'),
                'plugin_name': item.get('pluginName'),
                'severity': item.get('severity'),
            })
    
    return results

def find_nessus_files(directory):
    """Find all .nessus files in directory"""
    nessus_files = []
    
    if os.path.isfile(directory):
        # Single file provided
        if directory.endswith('.nessus'):
            return [directory]
        else:
            print(f"[-] File {directory} is not a .nessus file", file=sys.stderr)
            return []
    
    # Directory provided
    path = Path(directory)
    
    if not path.exists():
        print(f"[-] Directory/file not found: {directory}", file=sys.stderr)
        return []
    
    if not path.is_dir():
        print(f"[-] {directory} is not a directory", file=sys.stderr)
        return []
    
    # Find all .nessus files (recursive)
    nessus_files = list(path.glob('**/*.nessus'))
    
    # Remove duplicates and convert to strings
    nessus_files = [str(f) for f in set(nessus_files)]
    
    return sorted(nessus_files)

def parse_multiple_files(files, search_func, search_term):
    """Parse multiple Nessus files and aggregate results"""
    all_results = []
    
    for nessus_file in files:
        print(f"\n[*] Parsing: {os.path.basename(nessus_file)}", file=sys.stderr)
        
        try:
            results = search_func(nessus_file, search_term)
            
            # Add source file to results
            for r in results:
                r['source_file'] = os.path.basename(nessus_file)
            
            all_results.extend(results)
            print(f"    [+] Found {len(results)} result(s)", file=sys.stderr)
            
        except ET.ParseError as e:
            print(f"    [-] XML Parse Error: {e}", file=sys.stderr)
        except Exception as e:
            print(f"    [-] Error: {e}", file=sys.stderr)
    
    return all_results

def main():
    parser = argparse.ArgumentParser(
        description='Parse Nessus .nessus files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List unique IPs with HIGH Apache vulnerabilities
  python search.py ./nessus_exports/ --keyword Apache --criticality HIGH --ip-only
  
  # List CRITICAL Siemens vulnerabilities with details
  python search.py ./nessus_exports/ --keyword Siemens --criticality CRITICAL
  
  # CSV output with severity filter
  python search.py ./nessus_exports/ --cve CVE-2020-14517 --criticality HIGH --csv
  
  # Only IPs (one per line, for scripting)
  python search.py ./nessus_exports/ --keyword "remote code" --criticality CRITICAL --ip-only
        """
    )
    
    parser.add_argument('file', help='Nessus .nessus file or directory')
    parser.add_argument('--cve', help='Search by CVE (e.g., CVE-2020-14517)')
    parser.add_argument('--keyword', help='Search by keyword in description')
    parser.add_argument('--plugin', help='Search by Plugin ID (e.g., 149307)')
    
    # NEW: Criticality filter (more intuitive than numeric severity)
    parser.add_argument('--criticality', '-c', 
                       choices=['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
                       help='Filter by criticality level')
    
    # Keep old --severity for backward compatibility
    parser.add_argument('--severity', choices=['0','1','2','3','4'], 
                       help='Filter by severity (0=Info, 1=Low, 2=Medium, 3=High, 4=Critical)')
    
    parser.add_argument('--csv', action='store_true', help='Output as CSV')
    parser.add_argument('--unique', action='store_true', help='Remove duplicate hosts (default: True)')
    parser.add_argument('--ip-only', action='store_true', help='Output only unique IP addresses (one per line)')
    
    args = parser.parse_args()
    
    # Find all .nessus files
    nessus_files = find_nessus_files(args.file)
    
    if not nessus_files:
        print("[-] No .nessus files found", file=sys.stderr)
        sys.exit(1)
    
    print(f"[*] Found {len(nessus_files)} .nessus file(s)", file=sys.stderr)
    
    # Determine search function
    if args.cve:
        search_func = find_hosts_by_cve
        search_term = args.cve
    elif args.keyword:
        search_func = find_hosts_by_description
        search_term = args.keyword
    elif args.plugin:
        search_func = find_by_plugin_id
        search_term = args.plugin
    else:
        print("[-] Please specify --cve, --keyword, or --plugin", file=sys.stderr)
        sys.exit(1)
    
    # Parse all files
    results = parse_multiple_files(nessus_files, search_func, search_term)
    
    # Map criticality to severity number
    criticality_map = {
        'INFO': '0',
        'LOW': '1',
        'MEDIUM': '2',
        'HIGH': '3',
        'CRITICAL': '4'
    }
    
    # Filter by criticality (new) or severity (old)
    if args.criticality:
        severity_filter = criticality_map[args.criticality]
        results = [r for r in results if r['severity'] == severity_filter]
        print(f"[*] Filtering for {args.criticality} vulnerabilities", file=sys.stderr)
    elif args.severity:
        results = [r for r in results if r['severity'] == args.severity]
    
    # Always remove duplicates by default (or explicit --unique)
    if args.unique or args.ip_only or True:  # Default behavior
        seen_ips = set()
        unique_results = []
        for r in results:
            if r['ip'] not in seen_ips:
                seen_ips.add(r['ip'])
                unique_results.append(r)
        
        if len(results) != len(unique_results):
            print(f"[*] Removed {len(results) - len(unique_results)} duplicate(s), {len(unique_results)} unique host(s) remaining", file=sys.stderr)
        
        results = unique_results
    
    # IP-only output (for scripting)
    if args.ip_only:
        for r in results:
            print(r['ip'])
        sys.exit(0)
    
    # CSV output
    if args.csv:
        print("Hostname,IP,PluginID,PluginName,Severity,SourceFile")
        for r in results:
            sev_num = r['severity']
            sev_name = {v: k for k, v in criticality_map.items()}.get(sev_num, sev_num)
            print(f"{r['hostname']},{r['ip']},{r['plugin_id']},{r['plugin_name']},{sev_name},{r.get('source_file', 'N/A')}")
        sys.exit(0)
    
    # Standard output
    print(f"\n[+] Found {len(results)} unique affected host(s) across {len(nessus_files)} file(s):\n", file=sys.stderr)
    
    # Group by source file
    by_file = {}
    for r in results:
        source = r.get('source_file', 'Unknown')
        if source not in by_file:
            by_file[source] = []
        by_file[source].append(r)
    
    for source_file, file_results in by_file.items():
        print(f"\n{'='*70}")
        print(f"Source: {source_file} ({len(file_results)} results)")
        print('='*70)
        
        for r in file_results:
            sev_map = {'0':'Info', '1':'Low', '2':'Medium', '3':'High', '4':'Critical'}
            severity = sev_map.get(r['severity'], r['severity'])
            print(f"\n[{severity}] {r['hostname']} ({r['ip']})")
            print(f"  Plugin: {r['plugin_id']} - {r['plugin_name']}")

if __name__ == '__main__':
    main()
