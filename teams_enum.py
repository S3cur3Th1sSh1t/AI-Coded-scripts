#!/usr/bin/env python3
"""
Teams Email Enumerator
======================

Python-Port von TeamsFiltration's Enumerate-Modul mit erweiterten Features:
- Teams API E-Mail-Validierung
- Username/Password Authentication
- Device Code Flow Authentication
- Proxy Support (HTTP/HTTPS/SOCKS4/SOCKS5)

Basiert auf: https://github.com/Flangvik/TeamFiltration

Now the teams endpoint domain changed and BR encoding is used, both is considered here.
"""

import argparse
import sys
import json
import time
import requests
from requests.auth import HTTPProxyAuth
from urllib.parse import urlparse
import uuid
from datetime import datetime, timedelta
from pathlib import Path
import csv


class TeamsEnumerator:
    def __init__(self, proxy=None, proxy_auth=None, debug=False):
        """
        Initialisiert den Teams Enumerator
        
        Args:
            proxy: Proxy-URL (http://..., https://..., socks4://..., socks5://...)
            proxy_auth: Tuple (username, password) für Proxy-Authentifizierung
            debug: Aktiviert Debug-Ausgaben
        """
        self.debug = debug
        self.proxy = proxy
        self.proxy_auth = proxy_auth
        self.session = self._create_session()
        
        # Microsoft OAuth2 Endpoints
        self.oauth_base = "https://login.microsoftonline.com"
        self.teams_api_base = "https://teams.microsoft.com/api/mt"
        self.teams_auth_base = "https://authsvc.teams.microsoft.com"  # Neuer Endpoint!
        
        # Client IDs für verschiedene Resources
        self.client_ids = {
            'teams': '1fec8e78-bce4-4aaf-ab1b-5451cc387264',
            'skype': '1fec8e78-bce4-4aaf-ab1b-5451cc387264',
            'graph': '00000003-0000-0000-c000-000000000000'
        }
        
        # Tokens speichern
        self.access_token = None
        self.skype_token = None
        self.teams_object_ids = set()
        
    def _create_session(self):
        """Erstellt eine Session mit Proxy-Support"""
        session = requests.Session()
        
        if self.proxy:
            # Parse Proxy-URL
            parsed = urlparse(self.proxy)
            
            # SOCKS Proxy Support (benötigt requests[socks])
            if parsed.scheme in ['socks4', 'socks5', 'socks5h']:
                try:
                    import socks
                    from urllib3.contrib.socks import SOCKSProxyManager
                    
                    proxies = {
                        'http': self.proxy,
                        'https': self.proxy
                    }
                    session.proxies.update(proxies)
                    
                except ImportError:
                    self._log("WARNUNG: SOCKS-Support benötigt 'requests[socks]': pip install requests[socks]", "WARNING")
                    sys.exit(1)
            
            # HTTP/HTTPS Proxy
            else:
                proxies = {
                    'http': self.proxy,
                    'https': self.proxy
                }
                session.proxies.update(proxies)
            
            # Proxy-Authentifizierung
            if self.proxy_auth:
                session.auth = HTTPProxyAuth(self.proxy_auth[0], self.proxy_auth[1])
        
        # Standard Headers - vollständiger User-Agent um Blockierung zu vermeiden
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
            'Accept': 'application/json',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br'
        })
        
        return session
    
    def _log(self, message, level="INFO"):
        """Logging-Funktion"""
        if level == "DEBUG" and not self.debug:
            return
        
        colors = {
            "INFO": "\033[94m",
            "SUCCESS": "\033[92m",
            "WARNING": "\033[93m",
            "ERROR": "\033[91m",
            "DEBUG": "\033[90m"
        }
        
        reset = "\033[0m"
        color = colors.get(level, "")
        
        prefix = {
            "INFO": "[i]",
            "SUCCESS": "[✓]",
            "WARNING": "[!]",
            "ERROR": "[✗]",
            "DEBUG": "[d]"
        }
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{color}{prefix.get(level, '[?]')} [{timestamp}] {message}{reset}", file=sys.stderr)
    
    def authenticate_password(self, username, password, resource='skype'):
        """
        Authentifizierung mit Username/Password (Resource Owner Password Credentials Flow)
        
        Args:
            username: E-Mail-Adresse
            password: Passwort
            resource: Resource-Typ ('teams', 'skype', 'graph')
        
        Returns:
            dict mit Tokens oder None
        """
        self._log(f"Authentifiziere mit Username/Password für {resource}...", "DEBUG")
        
        url = f"{self.oauth_base}/common/oauth2/token"
        
        # Resource-URLs
        resources = {
            'teams': 'https://api.spaces.skype.com/',
            'skype': 'https://api.spaces.skype.com/',
            'graph': 'https://graph.microsoft.com'
        }
        
        data = {
            'grant_type': 'password',
            'username': username,
            'password': password,
            'client_id': self.client_ids.get(resource, self.client_ids['skype']),
            'resource': resources.get(resource, resources['skype']),
            'scope': 'openid'
        }
        
        try:
            response = self.session.post(url, data=data, timeout=30)
            
            if response.status_code == 200:
                token_data = response.json()
                self.access_token = token_data.get('access_token')
                self._log(f"Authentifizierung erfolgreich!", "SUCCESS")
                return token_data
            
            elif response.status_code == 400:
                error_data = response.json()
                error_code = error_data.get('error')
                error_desc = error_data.get('error_description', '')
                
                self._log(f"Auth-Fehler: {error_code} - {error_desc}", "ERROR")
                return None
            
            else:
                self._log(f"HTTP {response.status_code}: {response.text}", "ERROR")
                return None
                
        except Exception as e:
            self._log(f"Authentifizierungs-Fehler: {e}", "ERROR")
            return None
    
    def authenticate_device_code(self, resource='skype'):
        """
        Authentifizierung mit Device Code Flow (interactive)
        
        Args:
            resource: Resource-Typ ('teams', 'skype', 'graph')
        
        Returns:
            dict mit Tokens oder None
        """
        self._log(f"Starte Device Code Flow für {resource}...", "INFO")
        
        # Schritt 1: Device Code anfordern
        device_code_url = f"{self.oauth_base}/common/oauth2/devicecode"
        
        resources = {
            'teams': 'https://api.spaces.skype.com/',
            'skype': 'https://api.spaces.skype.com/',
            'graph': 'https://graph.microsoft.com'
        }
        
        data = {
            'client_id': self.client_ids.get(resource, self.client_ids['skype']),
            'resource': resources.get(resource, resources['skype'])
        }
        
        try:
            response = self.session.post(device_code_url, data=data, timeout=30)
            
            if response.status_code != 200:
                self._log(f"Device Code Anfrage fehlgeschlagen: {response.text}", "ERROR")
                return None
            
            device_data = response.json()
            device_code = device_data.get('device_code')
            user_code = device_data.get('user_code')
            verification_url = device_data.get('verification_url')
            expires_in = int(device_data.get('expires_in', 900))  # Ensure integer
            interval = int(device_data.get('interval', 5))  # Ensure integer
            
            # Zeige Anweisungen an
            print("\n" + "="*70)
            print("  DEVICE CODE AUTHENTIFIZIERUNG")
            print("="*70)
            print(f"\n  1. Öffnen Sie in Ihrem Browser: {verification_url}")
            print(f"  2. Geben Sie folgenden Code ein: {user_code}")
            print(f"  3. Melden Sie sich mit Ihrem Microsoft-Konto an")
            print(f"\n  Warte auf Authentifizierung (läuft ab in {expires_in//60} Minuten)...")
            print("="*70 + "\n")
            
            # Schritt 2: Polling für Token
            token_url = f"{self.oauth_base}/common/oauth2/token"
            token_data = {
                'grant_type': 'device_code',
                'code': device_code,
                'client_id': self.client_ids.get(resource, self.client_ids['skype'])
            }
            
            start_time = time.time()
            
            while time.time() - start_time < expires_in:
                time.sleep(interval)
                
                token_response = self.session.post(token_url, data=token_data, timeout=30)
                
                if token_response.status_code == 200:
                    token_result = token_response.json()
                    self.access_token = token_result.get('access_token')
                    self._log("Device Code Authentifizierung erfolgreich!", "SUCCESS")
                    return token_result
                
                elif token_response.status_code == 400:
                    error_data = token_response.json()
                    error_code = error_data.get('error')
                    
                    if error_code == 'authorization_pending':
                        self._log("Warte auf Benutzer-Authentifizierung...", "DEBUG")
                        continue
                    
                    elif error_code == 'authorization_declined':
                        self._log("Authentifizierung vom Benutzer abgelehnt", "ERROR")
                        return None
                    
                    elif error_code == 'expired_token':
                        self._log("Device Code abgelaufen", "ERROR")
                        return None
                    
                    else:
                        self._log(f"Unbekannter Fehler: {error_code}", "ERROR")
                        return None
            
            self._log("Device Code Flow Timeout", "ERROR")
            return None
            
        except Exception as e:
            self._log(f"Device Code Flow Fehler: {e}", "ERROR")
            return None
    
    def get_skype_token(self):
        """
        Holt Skype-Token über neuen Teams Auth Endpoint (benötigt für Teams API)
        
        Returns:
            str: Skype-Token oder None
        """
        if not self.access_token:
            self._log("Kein Access-Token vorhanden!", "ERROR")
            return None
        
        self._log("Hole Skype-Token über Teams Auth Service...", "DEBUG")
        
        # Neuer Microsoft Endpoint (authsvc.teams.microsoft.com)
        url = f"{self.teams_auth_base}/v1.0/authz"
        
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
            'Origin': 'https://teams.microsoft.com',
            'Referer': 'https://teams.microsoft.com/_',
            'x-ms-client-caller': 'x-ms-client-caller',
            'x-ms-client-version': '27/1.0.0.2021011237'
        }
        
        try:
            # POST Request mit leerem Body (kein Content-Type: application/json!)
            response = self.session.post(url, headers=headers, data=None, timeout=30)
            
            self._log(f"Response Status: {response.status_code}", "DEBUG")
            self._log(f"Response Content-Encoding: {response.headers.get('Content-Encoding', 'none')}", "DEBUG")
            
            if response.status_code == 200:
                try:
                    # requests sollte automatisch dekomprimieren, aber zur Sicherheit:
                    data = response.json()
                    self._log(f"JSON erfolgreich geparst, Keys: {list(data.keys())}", "DEBUG")
                except json.JSONDecodeError as e:
                    # Fallback: Versuche manuell zu dekomprimieren
                    self._log(f"JSON Parse Fehler: {e}", "DEBUG")
                    self._log(f"Versuche manuelle Dekompression...", "DEBUG")
                    
                    try:
                        import brotli
                        # Hole rohe Bytes
                        raw_content = response.content
                        decompressed = brotli.decompress(raw_content)
                        data = json.loads(decompressed.decode('utf-8'))
                        self._log(f"Brotli-Dekompression erfolgreich!", "DEBUG")
                    except ImportError:
                        self._log("Brotli-Modul fehlt! Installieren Sie: pip install brotli", "ERROR")
                        return None
                    except Exception as decode_err:
                        self._log(f"Dekompression fehlgeschlagen: {decode_err}", "ERROR")
                        self._log(f"Raw response (first 200 bytes): {response.content[:200]}", "DEBUG")
                        return None
                
                # Response-Struktur prüfen
                # Mögliche Strukturen:
                # 1. {"tokens": {"skypeToken": "..."}}
                # 2. {"skypeToken": "..."}
                # 3. Direkt der Token als String
                
                if isinstance(data, dict):
                    if 'tokens' in data and 'skypeToken' in data['tokens']:
                        self.skype_token = data['tokens']['skypeToken']
                    elif 'skypeToken' in data:
                        self.skype_token = data['skypeToken']
                    elif 'authToken' in data:
                        self.skype_token = data['authToken']
                    else:
                        self._log(f"Unerwartete Response-Struktur: {list(data.keys())}", "ERROR")
                        return None
                    
                    self._log("Skype-Token erfolgreich geholt!", "SUCCESS")
                    return self.skype_token
                else:
                    self._log(f"Unerwarteter Response-Typ: {type(data)}", "ERROR")
                    return None
            
            else:
                self._log(f"Skype-Token Fehler HTTP {response.status_code}: {response.text}", "ERROR")
                return None
                
        except json.JSONDecodeError as e:
            self._log(f"JSON Parse Fehler: {e}", "ERROR")
            return None
        except Exception as e:
            self._log(f"Skype-Token Fehler: {e}", "ERROR")
            return None
    
    def enum_user_teams(self, email):
        """
        Validiert E-Mail über Teams API (wie TeamsFiltration)
        
        Args:
            email: E-Mail-Adresse zum Validieren
        
        Returns:
            dict mit Validierungs-Informationen oder None
        """
        if not self.skype_token:
            self._log("Kein Skype-Token! Bitte erst authentifizieren.", "ERROR")
            return None
        
        self._log(f"Validiere E-Mail über Teams API: {email}", "DEBUG")
        
        # Teams API Endpoint für User-Suche
        url = f"{self.teams_api_base}/emea/beta/users/{email}/externalsearchv3"
        
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'X-Skypetoken': self.skype_token,
            'Authentication': f'skypetoken={self.skype_token}',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
            'Origin': 'https://teams.microsoft.com',
            'Referer': 'https://teams.microsoft.com/_',
            'x-ms-client-caller': 'x-ms-client-caller',
            'x-ms-client-version': '27/1.0.0.2021011237',
            'ClientInfo': 'os=Android; osVer=7.1.2; proc=x86; lcid=en-US; deviceType=2; country=US; clientName=microsoftteams; clientVer=1416/1.0.0.2021012201; utcOffset=+01:00'
        }
        
        # Query-Parameter wie in TeamsFiltration
        params = {
            'includeTFLUsers': 'true'
        }
        
        try:
            response = self.session.get(url, headers=headers, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                # Prüfe ob User gefunden wurde
                if data and len(data) > 0:
                    user_data = data[0]
                    object_id = user_data.get('mri', '').replace('8:', '')  # Format: "8:orgid:uuid"
                    display_name = user_data.get('displayName', '')
                    
                    result = {
                        'is_valid': True,
                        'email': email,
                        'object_id': object_id,
                        'display_name': display_name,
                        'raw_data': user_data
                    }
                    
                    self._log(f"✓ VALID: {email} (Display: {display_name})", "SUCCESS")
                    return result
                
                else:
                    self._log(f"✗ INVALID: {email}", "DEBUG")
                    return {
                        'is_valid': False,
                        'email': email,
                        'object_id': None,
                        'display_name': None
                    }
            
            elif response.status_code == 404:
                self._log(f"✗ INVALID: {email} (404)", "DEBUG")
                return {
                    'is_valid': False,
                    'email': email,
                    'object_id': None,
                    'display_name': None
                }
            
            else:
                self._log(f"API-Fehler {response.status_code}: {response.text}", "WARNING")
                return None
                
        except Exception as e:
            self._log(f"Fehler bei {email}: {e}", "ERROR")
            return None
    
    def enumerate_users_from_file(self, input_file, output_file):
        """
        Enumeriert Benutzer aus einer Datei
        
        Args:
            input_file: Pfad zur Eingabe-Datei (eine E-Mail pro Zeile)
            output_file: Pfad zur Ausgabe-CSV
        """
        self._log(f"Lese E-Mails aus {input_file}...", "INFO")
        
        # Lese E-Mails
        with open(input_file, 'r', encoding='utf-8') as f:
            emails = [line.strip() for line in f if line.strip() and '@' in line.strip()]
        
        self._log(f"Gefunden: {len(emails)} E-Mail-Adressen", "INFO")
        
        # Erstelle Ausgabe-CSV
        results = []
        valid_count = 0
        invalid_count = 0
        error_count = 0
        
        for idx, email in enumerate(emails, 1):
            self._log(f"[{idx}/{len(emails)}] Prüfe: {email}", "INFO")
            
            result = self.enum_user_teams(email)
            
            if result:
                if result['is_valid']:
                    valid_count += 1
                else:
                    invalid_count += 1
                
                results.append(result)
            else:
                error_count += 1
            
            # Rate-Limiting (300 req/min wie in TeamsFiltration)
            time.sleep(0.2)
        
        # Schreibe Ergebnisse
        self._log(f"\nSchreibe Ergebnisse nach {output_file}...", "INFO")
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            fieldnames = ['email', 'is_valid', 'display_name', 'object_id']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for result in results:
                writer.writerow({
                    'email': result['email'],
                    'is_valid': result['is_valid'],
                    'display_name': result.get('display_name', ''),
                    'object_id': result.get('object_id', '')
                })
        
        # Zusammenfassung
        self._log("\n" + "="*70, "INFO")
        self._log("ZUSAMMENFASSUNG", "INFO")
        self._log("="*70, "INFO")
        self._log(f"Gesamt geprüft: {len(emails)}", "INFO")
        self._log(f"✓ Gültig: {valid_count}", "SUCCESS")
        self._log(f"✗ Ungültig: {invalid_count}", "WARNING")
        self._log(f"⚠ Fehler: {error_count}", "ERROR")
        self._log(f"\nErgebnisse gespeichert: {output_file}", "SUCCESS")


def main():
    parser = argparse.ArgumentParser(
        description='Teams Email Enumerator - Validiert E-Mails über Microsoft Teams API',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Authentifizierungs-Methoden:
  1. Username/Password:
     python teams-enum.py -u user@company.com -p Password123 -i emails.txt -o results.csv
  
  2. Device Code (Interactive):
     python teams-enum.py --device-code -i emails.txt -o results.csv

Proxy-Support:
  # HTTP/HTTPS Proxy
  python teams-enum.py -u user@company.com -p Password123 -i emails.txt -o results.csv --proxy http://127.0.0.1:8080
  
  # SOCKS5 Proxy
  python teams-enum.py --device-code -i emails.txt -o results.csv --proxy socks5://127.0.0.1:1080
  
  # Mit Authentifizierung
  python teams-enum.py -u user@company.com -p Password123 -i emails.txt -o results.csv --proxy http://127.0.0.1:8080 --proxy-user admin --proxy-pass secret

Hinweise:
  - Benötigt gültiges Microsoft 365-Konto für "Sacrificial Account"
  - Rate-Limit: ~300 Anfragen/Minute
  - SOCKS-Support benötigt: pip install requests[socks]
        """
    )
    
    # Authentifizierung
    auth_group = parser.add_mutually_exclusive_group(required=True)
    auth_group.add_argument('-u', '--username',
                           help='Microsoft 365 Username (E-Mail)')
    auth_group.add_argument('--device-code', action='store_true',
                           help='Verwende Device Code Flow (interactive)')
    
    parser.add_argument('-p', '--password',
                       help='Microsoft 365 Passwort (bei Username/Password)')
    
    # Dateien
    parser.add_argument('-i', '--input', required=True,
                       help='Eingabe-Datei mit E-Mails (eine pro Zeile)')
    parser.add_argument('-o', '--output', required=True,
                       help='Ausgabe-CSV-Datei')
    
    # Proxy
    parser.add_argument('--proxy',
                       help='Proxy-URL (http://, https://, socks4://, socks5://)')
    parser.add_argument('--proxy-user',
                       help='Proxy Username')
    parser.add_argument('--proxy-pass',
                       help='Proxy Passwort')
    
    # Debug
    parser.add_argument('--debug', action='store_true',
                       help='Aktiviert Debug-Ausgaben')
    
    args = parser.parse_args()
    
    # Validierung
    if not Path(args.input).exists():
        print(f"✗ Fehler: Eingabe-Datei nicht gefunden: {args.input}", file=sys.stderr)
        sys.exit(1)
    
    if args.username and not args.password:
        print("✗ Fehler: Passwort erforderlich bei Username/Password Auth", file=sys.stderr)
        sys.exit(1)
    
    # Proxy-Auth
    proxy_auth = None
    if args.proxy_user and args.proxy_pass:
        proxy_auth = (args.proxy_user, args.proxy_pass)
    
    # Initialisiere Enumerator
    enumerator = TeamsEnumerator(
        proxy=args.proxy,
        proxy_auth=proxy_auth,
        debug=args.debug
    )
    
    # Authentifizierung
    if args.device_code:
        token_data = enumerator.authenticate_device_code('skype')
    else:
        token_data = enumerator.authenticate_password(args.username, args.password, 'skype')
    
    if not token_data:
        print("\n✗ Authentifizierung fehlgeschlagen!", file=sys.stderr)
        sys.exit(1)
    
    # Hole Skype-Token
    if not enumerator.get_skype_token():
        print("\n✗ Skype-Token konnte nicht geholt werden!", file=sys.stderr)
        sys.exit(1)
    
    # Enumerate Users
    enumerator.enumerate_users_from_file(args.input, args.output)


if __name__ == '__main__':
    main()
