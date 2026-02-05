#!/usr/bin/env python3
"""
When you only can reach LDAP but not the PKI server this script will tell you at least about a few potential PKI vulnerabilities.

Authentication methods supported:
- Password authentication
- NTLM hash authentication (LM:NT format)
- Kerberos authentication (with ticket cache)
- Simple BIND authentication
"""

import argparse
import enum
import json
import socket
import ssl
import sys
from datetime import datetime
from getpass import getpass
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import ldap3
from dns.resolver import Resolver
from impacket.krb5.ccache import CCache
from impacket.ldap import ldaptypes
from impacket.ntlm import NTLMSSP_NEGOTIATE_SEAL, NTLMAuthChallenge
from impacket.uuid import bin_to_string
from ldap3.core.results import RESULT_SUCCESS
from ldap3.operation.bind import bind_operation
from ldap3.protocol import rfc4511
from ldap3.protocol.formatters.formatters import format_sid
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.utils.asn1 import encode as _ldap3_encode
from pyasn1.codec.ber.encoder import Encoder

ldap3_encode = Encoder(_ldap3_encode)

# Import Certipy modules for authentication
try:
    from certipy.lib.channel_binding import get_channel_binding_data_from_ssl_socket
    from certipy.lib.kerberos import KerberosCipher, get_kerberos_type1
    from certipy.lib.ntlm import NTLMCipher, ntlm_authenticate, ntlm_negotiate
except ImportError:
    print("Error: This script requires Certipy to be installed for authentication modules.")
    print("Please run: pip install certipy-ad")
    sys.exit(1)


# =============================================================================
# Constants and Flags
# =============================================================================

class IntFlag(enum.IntFlag):
    """Enhanced IntFlag with smart string representation."""

    def to_list(self) -> List["IntFlag"]:
        """Decompose flag into list of individual flags."""
        if not self._value_:
            return []
        return [
            flag for flag in self.__class__ if flag.value and flag.value & self._value_
        ]

    def to_str_list(self) -> List[str]:
        """Return list of flag names in PascalCase."""
        return [
            to_pascal_case(flag.name)
            for flag in self.to_list()
            if flag.name is not None
        ]

    def __str__(self) -> str:
        """Human-readable string representation."""
        if self.name is not None:
            return to_pascal_case(self.name)
        if not self._value_:
            return ""
        flags = self.to_list()
        if not flags:
            return repr(self._value_)
        return ", ".join(
            to_pascal_case(flag.name) for flag in flags if flag.name is not None
        )


def to_pascal_case(name: str) -> str:
    """Convert SCREAMING_SNAKE_CASE to PascalCase."""
    if not name:
        return ""
    return "".join(word.capitalize() for word in name.split("_"))


# Enrollment flags from MS-CRTD 2.26
class EnrollmentFlag(IntFlag):
    """Flags controlling certificate enrollment behavior."""
    NONE = 0x00000000
    INCLUDE_SYMMETRIC_ALGORITHMS = 0x00000001
    PEND_ALL_REQUESTS = 0x00000002
    PUBLISH_TO_KRA_CONTAINER = 0x00000004
    PUBLISH_TO_DS = 0x00000008
    AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE = 0x00000010
    AUTO_ENROLLMENT = 0x00000020
    CT_FLAG_DOMAIN_AUTHENTICATION_NOT_REQUIRED = 0x00000080
    PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT = 0x00000040
    USER_INTERACTION_REQUIRED = 0x00000100
    ADD_TEMPLATE_NAME = 0x00000200
    REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE = 0x00000400
    ALLOW_ENROLL_ON_BEHALF_OF = 0x00000800
    ADD_OCSP_NOCHECK = 0x00001000
    ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL = 0x00002000
    NOREVOCATIONINFOINISSUEDCERTS = 0x00004000
    INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS = 0x00008000
    ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT = 0x00010000
    ISSUANCE_POLICIES_FROM_REQUEST = 0x00020000
    SKIP_AUTO_RENEWAL = 0x00040000
    NO_SECURITY_EXTENSION = 0x00080000


# Private key flags from MS-CRTD 2.27
class PrivateKeyFlag(IntFlag):
    """Flags controlling certificate private key behavior."""
    NONE = 0x00000000
    REQUIRE_PRIVATE_KEY_ARCHIVAL = 0x00000001
    EXPORTABLE_KEY = 0x00000010
    STRONG_KEY_PROTECTION_REQUIRED = 0x00000020
    REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM = 0x00000040
    REQUIRE_SAME_KEY_RENEWAL = 0x00000080
    USE_LEGACY_PROVIDER = 0x00000100
    EK_TRUST_ON_USE = 0x00000200
    EK_VALIDATE_CERT = 0x00000400
    EK_VALIDATE_KEY = 0x00000800
    ATTEST_NONE = 0x00000000
    ATTEST_PREFERRED = 0x00001000
    ATTEST_REQUIRED = 0x00002000
    ATTESTATION_WITHOUT_POLICY = 0x00004000
    HELLO_LOGON_KEY = 0x00200000


# Certificate name flags from MS-CRTD 2.28
class CertificateNameFlag(IntFlag):
    """Flags controlling certificate subject name creation."""
    NONE = 0x00000000
    ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
    ADD_EMAIL = 0x00000002
    ADD_OBJ_GUID = 0x00000004
    OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME = 0x00000008
    ADD_DIRECTORY_PATH = 0x00000100
    ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x00010000
    SUBJECT_ALT_REQUIRE_DOMAIN_DNS = 0x00400000
    SUBJECT_ALT_REQUIRE_SPN = 0x00800000
    SUBJECT_ALT_REQUIRE_DIRECTORY_GUID = 0x01000000
    SUBJECT_ALT_REQUIRE_UPN = 0x02000000
    SUBJECT_ALT_REQUIRE_EMAIL = 0x04000000
    SUBJECT_ALT_REQUIRE_DNS = 0x08000000
    SUBJECT_REQUIRE_DNS_AS_CN = 0x10000000
    SUBJECT_REQUIRE_EMAIL = 0x20000000
    SUBJECT_REQUIRE_COMMON_NAME = 0x40000000
    SUBJECT_REQUIRE_DIRECTORY_PATH = 0x80000000


# Active Directory rights
class ActiveDirectoryRights(IntFlag):
    """Active Directory access rights."""
    READ_PROPERTY = 16
    WRITE_PROPERTY = 32
    EXTENDED_RIGHT = 256
    GENERIC_READ = 131220
    GENERIC_WRITE = 131112
    GENERIC_EXECUTE = 131076
    GENERIC_ALL = 983551
    WRITE_DACL = 262144
    WRITE_OWNER = 524288


# Certificate-specific rights (alias for compatibility)
CertificateRights = ActiveDirectoryRights


# OID to string mappings
OID_TO_STR_MAP = {
    "1.3.6.1.5.5.7.3.1": "Server Authentication",
    "1.3.6.1.5.5.7.3.2": "Client Authentication",
    "1.3.6.1.5.5.7.3.3": "Code Signing",
    "1.3.6.1.5.5.7.3.4": "Secure Email",
    "1.3.6.1.5.5.7.3.8": "Time Stamping",
    "1.3.6.1.5.5.7.3.9": "OCSP Signing",
    "1.3.6.1.4.1.311.20.2.1": "Certificate Request Agent",
    "1.3.6.1.4.1.311.20.2.2": "Smart Card Logon",
    "1.3.6.1.4.1.311.10.3.4": "Encrypting File System",
    "1.3.6.1.4.1.311.10.3.12": "Document Signing",
    "1.3.6.1.5.2.3.4": "PKINIT Client Authentication",
    "1.3.6.1.5.2.3.5": "KDC Authentication",
    "2.5.29.37.0": "Any Purpose",
}

# Extended rights mappings
EXTENDED_RIGHTS_MAP = {
    "0e10c968-78fb-11d2-90d4-00c04f79dc55": "Enroll",
    "a05b8cc2-17bc-4802-a710-e7c15ab866a2": "AutoEnroll",
    "00000000-0000-0000-0000-000000000000": "All-Extended-Rights",
}

EXTENDED_RIGHTS_NAME_MAP = {v: k for k, v in EXTENDED_RIGHTS_MAP.items()}

# ACE flags
INHERITED_ACE = 0x10


# =============================================================================
# Helper Classes
# =============================================================================

class LDAPEntry(Dict[str, Any]):
    """Dictionary-like class representing an LDAP entry."""

    def get(self, key: str, default: Any = None) -> Any:
        """Get an attribute value from the LDAP entry."""
        if key not in self.__getitem__("attributes").keys():
            return default
        item = self.__getitem__("attributes").__getitem__(key)
        if isinstance(item, list) and len(item) == 0:
            return default
        return item

    def set(self, key: str, value: Any) -> None:
        """Set an attribute value in the LDAP entry."""
        return self.__getitem__("attributes").__setitem__(key, value)

    def get_raw(self, key: str) -> Any:
        """Get the raw (unprocessed) attribute value."""
        if key not in self.__getitem__("raw_attributes").keys():
            return None
        return self.__getitem__("raw_attributes").__getitem__(key)


class Target:
    """Class representing an authentication target with connection details."""

    def __init__(
        self,
        domain: str = "",
        username: str = "",
        password: Optional[str] = None,
        remote_name: str = "",
        hashes: Optional[str] = None,
        lmhash: str = "",
        nthash: str = "",
        do_kerberos: bool = False,
        do_simple: bool = False,
        aes: Optional[str] = None,
        dc_ip: Optional[str] = None,
        target_ip: Optional[str] = None,
        timeout: int = 5,
        ldap_scheme: str = "ldaps",
        ldap_port: Optional[int] = None,
        ldap_channel_binding: bool = True,
        ldap_signing: bool = True,
    ) -> None:
        self.domain = domain
        self.username = username
        self.password = password
        self.remote_name = remote_name
        self.hashes = hashes
        self.lmhash = lmhash
        self.nthash = nthash
        self.do_kerberos = do_kerberos
        self.do_simple = do_simple
        self.aes = aes
        self.dc_ip = dc_ip
        self.target_ip = target_ip
        self.timeout = timeout
        self.ldap_scheme = ldap_scheme
        self.ldap_port = ldap_port if ldap_port else (636 if ldap_scheme == "ldaps" else 389)
        self.ldap_channel_binding = ldap_channel_binding
        self.ldap_signing = ldap_signing


class DnsResolver:
    """DNS resolver with caching capabilities."""

    def __init__(self, nameserver: Optional[str] = None):
        self.resolver = Resolver()
        if nameserver:
            self.resolver.nameservers = [nameserver]
        self.mappings: Dict[str, str] = {}

    def resolve(self, hostname: str) -> str:
        """Resolve hostname to IP address."""
        if hostname in self.mappings:
            return self.mappings[hostname]
        if is_ip(hostname):
            return hostname
        try:
            answers = self.resolver.resolve(hostname)
            if answers:
                ip_addr = str(answers[0])
                self.mappings[hostname] = ip_addr
                return ip_addr
        except Exception:
            pass
        try:
            ip_addr = socket.gethostbyname(hostname)
            self.mappings[hostname] = ip_addr
            return ip_addr
        except Exception:
            return hostname


def is_ip(hostname: Optional[str]) -> bool:
    """Check if the given hostname is an IP address."""
    if hostname is None:
        return False
    try:
        socket.inet_aton(hostname)
        return True
    except Exception:
        return False


# =============================================================================
# Security Descriptor Parsing
# =============================================================================

class CertificateSecurity:
    """Parser for certificate template security descriptors."""

    def __init__(self, security_descriptor: bytes):
        """Parse security descriptor."""
        self.sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
        self.sd.fromString(security_descriptor)

        # Extract owner SID
        self.owner = format_sid(self.sd["OwnerSid"].getData())

        # Dictionary to store ACEs by SID
        self.aces: Dict[str, Dict[str, Any]] = {}
        self._parse_aces()

    def _parse_aces(self) -> None:
        """Parse access control entries from security descriptor."""
        if self.sd["Dacl"] is None:
            return

        aces = self.sd["Dacl"]["Data"]

        for ace in aces:
            try:
                sid = format_sid(ace["Ace"]["Sid"].getData())

                # Initialize entry for this SID
                if sid not in self.aces:
                    self.aces[sid] = {
                        "rights": CertificateRights(0),
                        "extended_rights": [],
                        "inherited": bool(ace["AceFlags"] & INHERITED_ACE),
                        "has_standard_control_access": False,
                    }

                # Process standard ACCESS_ALLOWED_ACE
                if ace["AceType"] == ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE:
                    mask = CertificateRights(ace["Ace"]["Mask"]["Mask"])
                    self.aces[sid]["rights"] |= mask

                    # Check for EXTENDED_RIGHT flag
                    if mask & ActiveDirectoryRights.EXTENDED_RIGHT:
                        self.aces[sid]["has_standard_control_access"] = True

                # Process object-specific ACE
                elif ace["AceType"] == ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE:
                    mask = CertificateRights(ace["Ace"]["Mask"]["Mask"])
                    self.aces[sid]["rights"] |= mask

                    # Try to extract ObjectType GUID (extended right)
                    # Use a defensive approach for different impacket versions
                    uuid = None
                    try:
                        # Try to get ObjectType field
                        obj_type = ace["Ace"]["ObjectType"]
                        if obj_type:
                            uuid = bin_to_string(obj_type).lower()
                    except (KeyError, AttributeError, TypeError):
                        # If ObjectType not available, assume all extended rights
                        pass

                    # If no specific ObjectType, it means all extended rights
                    if not uuid:
                        uuid = EXTENDED_RIGHTS_NAME_MAP.get("All-Extended-Rights", "")

                    if uuid:
                        self.aces[sid]["extended_rights"].append(uuid)

            except Exception as e:
                # Skip ACEs that we can't parse
                continue


# =============================================================================
# Extended LDAP Connection Classes
# =============================================================================

class ExtendedLdapConnection(ldap3.Connection):
    """Extended LDAP Connection class with NTLM and Kerberos support."""

    def __init__(self, target: Target, *args, **kwargs):
        self.target = target
        self.should_encrypt = False
        self.ntlm_cipher = None
        self.kerberos_cipher = None
        super().__init__(*args, **kwargs)


# =============================================================================
# LDAP Connection Class
# =============================================================================

class LDAPConnection:
    """Manages LDAP/LDAPS connections to Active Directory."""

    def __init__(self, target: Target):
        self.target = target
        self.use_ssl = target.ldap_scheme == "ldaps"
        self.port = target.ldap_port

        self.ldap_server: Optional[ldap3.Server] = None
        self.ldap_conn: Optional[ldap3.Connection] = None
        self.default_path: Optional[str] = None
        self.configuration_path: Optional[str] = None

        # Cache for SID to name resolution
        self.sid_cache: Dict[str, str] = {}

        # Well-known SIDs that don't need LDAP lookup
        self.wellknown_sids = {
            "S-1-1-0": "Everyone",
            "S-1-5-11": "Authenticated Users",
            "S-1-5-7": "Anonymous",
            "S-1-5-32-544": "Administrators",
            "S-1-5-32-545": "Users",
            "S-1-5-32-546": "Guests",
            "S-1-5-32-547": "Power Users",
            "S-1-5-32-548": "Account Operators",
            "S-1-5-32-549": "Server Operators",
            "S-1-5-32-550": "Print Operators",
            "S-1-5-32-551": "Backup Operators",
            "S-1-5-9": "Enterprise Domain Controllers",
        }

    def connect(self) -> None:
        """Connect to the LDAP server with authentication."""
        if self.target.target_ip is None:
            raise Exception("Target IP is not set")

        # Format user credentials
        user = f"{self.target.domain}\\{self.target.username}"
        user_upn = f"{self.target.username}@{self.target.domain}"

        # Create server object
        if self.use_ssl:
            tls = ldap3.Tls(
                validate=ssl.CERT_NONE,
                version=ssl.PROTOCOL_TLS_CLIENT,
                ciphers="ALL:@SECLEVEL=0",
                ssl_options=[ssl.OP_ALL],
            )
            ldap_server = ldap3.Server(
                self.target.target_ip,
                use_ssl=True,
                port=self.port,
                get_info=ldap3.ALL,
                tls=tls,
                connect_timeout=self.target.timeout,
            )
        else:
            ldap_server = ldap3.Server(
                self.target.target_ip,
                use_ssl=False,
                port=self.port,
                get_info=ldap3.ALL,
                connect_timeout=self.target.timeout,
            )

        # Authenticate
        if self.target.do_kerberos:
            print("[*] Authenticating via Kerberos...")
            receive_timeout = min(self.target.timeout * 3, 120)
            ldap_conn = ExtendedLdapConnection(
                self.target,
                ldap_server,
                receive_timeout=receive_timeout,
            )
            self._kerberos_login(ldap_conn)
        else:
            auth_method = "SIMPLE" if self.target.do_simple else "NTLM"
            print(f"[*] Authenticating via {auth_method}...")

            if self.target.hashes is not None:
                ldap_pass = f"{self.target.lmhash}:{self.target.nthash}"
            else:
                ldap_pass = self.target.password

            receive_timeout = min(self.target.timeout * 3, 120)
            ldap_conn = ldap3.Connection(
                ldap_server,
                user=user_upn if self.target.do_simple else user,
                password=ldap_pass,
                authentication=ldap3.SIMPLE if self.target.do_simple else ldap3.NTLM,
                auto_referrals=False,
                receive_timeout=receive_timeout,
            )

        # Perform bind
        if not ldap_conn.bound:
            try:
                bind_result = ldap_conn.bind()
                if not bind_result:
                    error_msg = ldap_conn.result.get('description', 'Unknown error')
                    error_detail = ldap_conn.result.get('message', '')
                    raise Exception(f"LDAP bind failed: {error_msg}. {error_detail}")
            except Exception as e:
                raise Exception(f"LDAP bind failed: {e}")

        # Get schema information
        if ldap_server.schema is None:
            ldap_server.get_info_from_server(ldap_conn)
            if ldap_conn.result["result"] != RESULT_SUCCESS:
                raise Exception("Failed to get LDAP schema")

        print(f"[+] Successfully bound to {ldap_server}")

        # Store connection objects
        self.ldap_conn = ldap_conn
        self.ldap_server = ldap_server

        self.default_path = self.ldap_server.info.other["defaultNamingContext"][0]
        self.configuration_path = self.ldap_server.info.other["configurationNamingContext"][0]

        print(f"[*] Default naming context: {self.default_path}")
        print(f"[*] Configuration naming context: {self.configuration_path}")

    def _kerberos_login(self, connection: ExtendedLdapConnection) -> None:
        """Perform Kerberos authentication."""
        channel_binding_data = None
        if self.target.ldap_channel_binding and connection.server.ssl:
            channel_binding_data = get_channel_binding_data_from_ssl_socket(connection.socket)

        cipher, session_key, blob, username = get_kerberos_type1(
            self.target,
            target_name=self.target.remote_name or "",
            channel_binding_data=channel_binding_data,
            signing=self.target.ldap_signing and not connection.server.ssl,
        )

        request = bind_operation(
            connection.version,
            ldap3.SASL,
            username,
            None,
            "GSS-SPNEGO",
            blob,
        )

        connection.sasl_in_progress = True
        response = connection.post_send_single_response(
            connection.send("bindRequest", request, None)
        )
        connection.sasl_in_progress = False

        result = response[0]["protocolOp"]["bindResponse"]
        result_dict = {
            "result": int(result["resultCode"]),
            "description": str(result["resultCode"]),
            "message": str(result.get("diagnosticMessage", "")),
        }

        if result_dict["result"] != RESULT_SUCCESS:
            raise Exception(f"Kerberos authentication failed: {result_dict}")

        if self.target.ldap_signing and not connection.server.ssl:
            connection.kerberos_cipher = KerberosCipher(cipher, session_key)
            connection.should_encrypt = True

        connection.bound = True

    def search(
        self,
        search_filter: str,
        attributes: Union[str, List[str]] = ldap3.ALL_ATTRIBUTES,
        search_base: Optional[str] = None,
        query_sd: bool = False,
    ) -> List[LDAPEntry]:
        """Search the LDAP directory."""
        if search_base is None:
            search_base = self.default_path

        if query_sd:
            controls = security_descriptor_control(sdflags=0x5)
        else:
            controls = None

        if self.ldap_conn is None:
            raise Exception("LDAP connection is not established")

        # Perform paged search
        results = self.ldap_conn.extend.standard.paged_search(
            search_base=search_base,
            search_filter=search_filter,
            attributes=attributes,
            controls=controls,
            paged_size=200,
            generator=True,
        )

        if self.ldap_conn.result["result"] != 0:
            print(f"[!] LDAP search failed: {self.ldap_conn.result}")
            return []

        # Convert to LDAPEntry objects
        entries = list(
            map(
                lambda entry: LDAPEntry(**entry),
                filter(lambda entry: entry["type"] == "searchResEntry", results),
            )
        )
        return entries

    def resolve_sid(self, sid: str) -> str:
        """Resolve a SID to a name via LDAP lookup."""
        # Check cache first
        if sid in self.sid_cache:
            return self.sid_cache[sid]

        # Check well-known SIDs
        if sid in self.wellknown_sids:
            name = self.wellknown_sids[sid]
            self.sid_cache[sid] = name
            return name

        # Special handling for domain-specific well-known SIDs
        if sid.endswith("-512"):
            name = "Domain Admins"
        elif sid.endswith("-519"):
            name = "Enterprise Admins"
        elif sid.endswith("-518"):
            name = "Schema Admins"
        elif sid.endswith("-513"):
            name = "Domain Users"
        elif sid.endswith("-515"):
            name = "Domain Computers"
        elif sid.endswith("-516"):
            name = "Domain Controllers"
        elif sid.endswith("-521"):
            name = "Read-Only Domain Controllers"
        elif sid.endswith("-498"):
            name = "Enterprise Read-Only Domain Controllers"
        else:
            # Query LDAP for the SID
            try:
                # Create LDAP filter to search by objectSid
                # The SID needs to be in the correct format for LDAP search
                results = self.search(
                    f"(objectSid={sid})",
                    attributes=["sAMAccountName", "cn", "name", "distinguishedName"],
                    search_base=self.default_path,
                )

                if results and len(results) > 0:
                    entry = results[0]
                    # Try to get the best name
                    name = (
                        entry.get("sAMAccountName")
                        or entry.get("cn")
                        or entry.get("name")
                        or sid
                    )
                else:
                    name = sid
            except Exception:
                name = sid

        self.sid_cache[sid] = name
        return name


# =============================================================================
# Template Processing Functions
# =============================================================================

def process_template_flags(template: LDAPEntry) -> None:
    """Process template flag attributes."""
    # Process certificate name flags
    certificate_name_flag = template.get("msPKI-Certificate-Name-Flag")
    if certificate_name_flag is not None:
        certificate_name_flag = CertificateNameFlag(int(certificate_name_flag))
    else:
        certificate_name_flag = CertificateNameFlag(0)
    template.set("certificate_name_flag", certificate_name_flag.to_list())
    template.set("certificate_name_flag_str", certificate_name_flag.to_str_list())

    # Process enrollment flags
    enrollment_flag = template.get("msPKI-Enrollment-Flag")
    if enrollment_flag is not None:
        enrollment_flag = EnrollmentFlag(int(enrollment_flag))
    else:
        enrollment_flag = EnrollmentFlag(0)
    template.set("enrollment_flag", enrollment_flag.to_list())
    template.set("enrollment_flag_str", enrollment_flag.to_str_list())

    # Process private key flags
    private_key_flag = template.get("msPKI-Private-Key-Flag")
    if private_key_flag is not None:
        private_key_flag = PrivateKeyFlag(int(private_key_flag))
    else:
        private_key_flag = PrivateKeyFlag(0)
    template.set("private_key_flag", private_key_flag.to_list())
    template.set("private_key_flag_str", private_key_flag.to_str_list())

    # Process schema version
    schema_version = template.get("msPKI-Template-Schema-Version")
    if schema_version is not None:
        schema_version = int(schema_version)
    else:
        schema_version = 1
    template.set("schema_version", schema_version)

    # Process RA signature requirement
    authorized_signatures_required = template.get("msPKI-RA-Signature")
    if authorized_signatures_required is not None:
        authorized_signatures_required = int(authorized_signatures_required)
    else:
        authorized_signatures_required = 0
    template.set("authorized_signatures_required", authorized_signatures_required)


def process_template_policies(template: LDAPEntry) -> None:
    """Process template policy attributes and extended key usage."""
    # Process application policies
    application_policies = template.get_raw("msPKI-RA-Application-Policies")
    if not isinstance(application_policies, list):
        application_policies = (
            [] if application_policies is None else [application_policies]
        )

    # Convert from bytes to strings and resolve OIDs
    application_policies = [p.decode() if isinstance(p, bytes) else p for p in application_policies]
    application_policies = [OID_TO_STR_MAP.get(p, p) for p in application_policies]
    template.set("application_policies", application_policies)

    # Process extended key usage (EKU)
    eku = template.get_raw("pKIExtendedKeyUsage")
    if not isinstance(eku, list):
        eku = [] if eku is None else [eku]

    # Convert from bytes to strings and resolve OIDs
    eku = [e.decode() if isinstance(e, bytes) else e for e in eku]
    extended_key_usage = [OID_TO_STR_MAP.get(e, e) for e in eku]
    template.set("extended_key_usage", extended_key_usage)

    # Determine template capabilities
    determine_template_capabilities(template, extended_key_usage)


def determine_template_capabilities(template: LDAPEntry, extended_key_usage: List[str]) -> None:
    """Determine template capabilities from EKU and flags."""
    # Check for "any purpose" EKU
    any_purpose = "Any Purpose" in extended_key_usage or not extended_key_usage
    template.set("any_purpose", any_purpose)

    # Check for client authentication capability
    client_auth_ekus = [
        "Client Authentication",
        "Smart Card Logon",
        "PKINIT Client Authentication",
    ]
    client_authentication = any_purpose or any(
        eku in extended_key_usage for eku in client_auth_ekus
    )
    template.set("client_authentication", client_authentication)

    # Check for enrollment agent capability
    enrollment_agent = (
        any_purpose or "Certificate Request Agent" in extended_key_usage
    )
    template.set("enrollment_agent", enrollment_agent)

    # Check if enrollee can supply subject
    certificate_name_flag = template.get("certificate_name_flag", [])
    enrollee_supplies_subject = any(
        CertificateNameFlag.ENROLLEE_SUPPLIES_SUBJECT == flag
        for flag in certificate_name_flag
    )
    template.set("enrollee_supplies_subject", enrollee_supplies_subject)

    # Check if template requires manager approval
    enrollment_flag = template.get("enrollment_flag", [])
    requires_manager_approval = EnrollmentFlag.PEND_ALL_REQUESTS in enrollment_flag
    template.set("requires_manager_approval", requires_manager_approval)

    # Check if template has no security extension
    no_security_extension = EnrollmentFlag.NO_SECURITY_EXTENSION in enrollment_flag
    template.set("no_security_extension", no_security_extension)


def analyze_permissions(template: LDAPEntry, connection: Optional[LDAPConnection] = None, user_sids: Optional[Set[str]] = None) -> Dict[str, Any]:
    """Analyze permissions on template."""
    perms = {
        "owner": None,
        "owner_name": None,
        "permissions": {},
        "enrollable_sids": [],
        "enrollable_principals": []
    }

    sd_bytes = template.get_raw("nTSecurityDescriptor")
    if not sd_bytes:
        return perms

    security = CertificateSecurity(sd_bytes[0] if isinstance(sd_bytes, list) else sd_bytes)
    perms["owner"] = security.owner

    # Resolve owner SID to name
    if connection:
        perms["owner_name"] = connection.resolve_sid(security.owner)

    for sid, rights in security.aces.items():
        perms["permissions"][sid] = {
            "rights": rights["rights"].to_str_list() if hasattr(rights["rights"], "to_str_list") else str(rights["rights"]),
            "extended_rights": [EXTENDED_RIGHTS_MAP.get(guid, guid) for guid in rights["extended_rights"]],
            "inherited": rights["inherited"],
        }

        # Check if can enroll
        has_object_enroll = (
            EXTENDED_RIGHTS_NAME_MAP["Enroll"] in rights["extended_rights"]
            and rights["rights"] & ActiveDirectoryRights.EXTENDED_RIGHT
        )
        has_all_extended = (
            EXTENDED_RIGHTS_NAME_MAP.get("All-Extended-Rights", "") in rights["extended_rights"]
            and rights["rights"] & ActiveDirectoryRights.EXTENDED_RIGHT
        )
        has_standard_control_access = rights.get("has_standard_control_access", False)

        if has_object_enroll or has_all_extended or has_standard_control_access:
            perms["enrollable_sids"].append(sid)
            # Resolve SID to name
            if connection:
                name = connection.resolve_sid(sid)
                perms["enrollable_principals"].append({"sid": sid, "name": name})

    return perms


def detect_vulnerabilities(template: LDAPEntry) -> List[str]:
    """Detect common certificate template vulnerabilities."""
    vulns = []

    # ESC1: Client authentication + enrollee-supplied subject
    if template.get("enrollee_supplies_subject") and template.get("client_authentication"):
        if not template.get("requires_manager_approval"):
            vulns.append("ESC1: Enrollee supplies subject + Client authentication")

    # ESC2: Any Purpose EKU
    if template.get("any_purpose"):
        if not template.get("requires_manager_approval"):
            vulns.append("ESC2: Template allows Any Purpose EKU")

    # ESC3: Certificate Request Agent
    if template.get("enrollment_agent"):
        vulns.append("ESC3: Template has Certificate Request Agent EKU")

    # ESC9: No security extension with client authentication
    if template.get("no_security_extension") and template.get("client_authentication"):
        if not template.get("requires_manager_approval"):
            vulns.append("ESC9: No security extension + Client authentication (CVE-2022-26923)")

    # ESC15: Schema v1 with enrollee-supplied subject (CVE-2024-49019)
    if template.get("enrollee_supplies_subject") and template.get("schema_version") == 1:
        vulns.append("ESC15: Schema v1 + Enrollee supplies subject (CVE-2024-49019)")

    return vulns


def get_certificate_templates(connection: LDAPConnection) -> List[LDAPEntry]:
    """Query LDAP for all certificate templates."""
    print("\n[*] Querying certificate templates...")

    templates = connection.search(
        "(objectclass=pKICertificateTemplate)",
        search_base=f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{connection.configuration_path}",
        attributes=[
            "cn",
            "name",
            "displayName",
            "pKIExpirationPeriod",
            "pKIOverlapPeriod",
            "msPKI-Enrollment-Flag",
            "msPKI-Private-Key-Flag",
            "msPKI-Certificate-Name-Flag",
            "msPKI-Certificate-Policy",
            "msPKI-Minimal-Key-Size",
            "msPKI-RA-Signature",
            "msPKI-Template-Schema-Version",
            "msPKI-RA-Application-Policies",
            "pKIExtendedKeyUsage",
            "nTSecurityDescriptor",
            "objectGUID",
            "whenCreated",
            "whenChanged",
        ],
        query_sd=True,
    )

    print(f"[+] Found {len(templates)} certificate templates")
    return templates


def get_certificate_authorities(connection: LDAPConnection) -> List[LDAPEntry]:
    """Query LDAP for certificate authorities."""
    print("[*] Querying certificate authorities...")

    cas = connection.search(
        "(&(objectClass=pKIEnrollmentService))",
        search_base=f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{connection.configuration_path}",
        attributes=[
            "cn",
            "name",
            "dNSHostName",
            "certificateTemplates",
        ],
    )

    print(f"[+] Found {len(cas)} certificate authorities")
    return cas


def link_templates_to_cas(templates: List[LDAPEntry], cas: List[LDAPEntry]) -> None:
    """Link templates to CAs and determine if they're enabled."""
    print("[*] Linking templates to certificate authorities...")

    # Build a mapping of template names to templates
    template_map = {t.get("name"): t for t in templates if t.get("name")}

    # For each CA, link the templates it supports
    for ca in cas:
        ca_name = ca.get("name", "Unknown CA")
        ca_templates = ca.get("certificateTemplates")

        if not ca_templates:
            continue

        # certificateTemplates can be a list or single value
        if not isinstance(ca_templates, list):
            ca_templates = [ca_templates]

        for template_name in ca_templates:
            if template_name in template_map:
                template = template_map[template_name]

                # Get or initialize CAs list
                cas_list = template.get("_cas")
                if cas_list is None:
                    cas_list = []
                    template.set("_cas", cas_list)

                # Add CA name to template
                cas_list.append(ca_name)

    # Mark templates as enabled if they have CAs
    enabled_count = 0
    for template in templates:
        cas_list = template.get("_cas", [])
        is_enabled = len(cas_list) > 0
        template.set("_enabled", is_enabled)
        template.set("_ca_count", len(cas_list))
        if is_enabled:
            enabled_count += 1

    print(f"[+] {enabled_count} templates are enabled (linked to CAs)")
    print(f"[+] {len(templates) - enabled_count} templates are disabled (not linked to any CA)")


def format_template_output(template: LDAPEntry, verbose: bool = False) -> None:
    """Format and print a single template."""
    name = template.get("name", "Unknown")
    print(f"\n{'='*80}")
    print(f"Template: {name}")
    print(f"{'='*80}")

    # Basic information
    print(f"  Display Name                : {template.get('displayName', 'N/A')}")
    print(f"  CN                          : {template.get('cn', 'N/A')}")

    # Enabled status
    is_enabled = template.get("_enabled", False)
    ca_count = template.get("_ca_count", 0)
    if is_enabled:
        print(f"  Status                      : ENABLED (linked to {ca_count} CA(s))")
        if verbose:
            cas = template.get("_cas", [])
            for ca_name in cas:
                print(f"    - {ca_name}")
    else:
        print(f"  Status                      : DISABLED (not linked to any CA)")

    print(f"  Schema Version              : {template.get('schema_version', 'N/A')}")

    # Flags (human-readable)
    enrollment_flags = template.get("enrollment_flag_str", [])
    if enrollment_flags:
        print(f"  Enrollment Flags            : {', '.join(enrollment_flags)}")
    else:
        print(f"  Enrollment Flags            : None")

    private_key_flags = template.get("private_key_flag_str", [])
    if private_key_flags:
        print(f"  Private Key Flags           : {', '.join(private_key_flags)}")
    else:
        print(f"  Private Key Flags           : None")

    cert_name_flags = template.get("certificate_name_flag_str", [])
    if cert_name_flags:
        print(f"  Certificate Name Flags      : {', '.join(cert_name_flags)}")
    else:
        print(f"  Certificate Name Flags      : None")

    # Key properties
    print(f"  Minimal Key Size            : {template.get('msPKI-Minimal-Key-Size', 'N/A')}")
    print(f"  RA Signature Required       : {template.get('authorized_signatures_required', 0)}")

    # Extended Key Usage
    eku = template.get("extended_key_usage", [])
    if eku:
        print(f"  Extended Key Usage          : {', '.join(eku)}")
    else:
        print(f"  Extended Key Usage          : None")

    # Capabilities
    print(f"  Client Authentication       : {template.get('client_authentication', False)}")
    print(f"  Enrollment Agent            : {template.get('enrollment_agent', False)}")
    print(f"  Any Purpose                 : {template.get('any_purpose', False)}")
    print(f"  Enrollee Supplies Subject   : {template.get('enrollee_supplies_subject', False)}")
    print(f"  Requires Manager Approval   : {template.get('requires_manager_approval', False)}")

    # Permissions
    perms = template.get("_permissions", {})
    if perms:
        owner = perms.get("owner", "N/A")
        owner_name = perms.get("owner_name")
        if owner_name and owner_name != owner:
            print(f"  Owner                       : {owner_name} ({owner})")
        else:
            print(f"  Owner                       : {owner}")

        enrollable_principals = perms.get("enrollable_principals", [])
        if enrollable_principals:
            print(f"  Enrollable Principals       : {len(enrollable_principals)} principal(s) can enroll")
            if verbose:
                # Show first 10 in verbose mode
                for principal in enrollable_principals[:10]:
                    name = principal.get("name", "")
                    sid = principal.get("sid", "")
                    if name and name != sid:
                        print(f"    - {name} ({sid})")
                    else:
                        print(f"    - {sid}")
                if len(enrollable_principals) > 10:
                    print(f"    ... and {len(enrollable_principals) - 10} more")
            else:
                # Show first 5 in normal mode
                for principal in enrollable_principals[:5]:
                    name = principal.get("name", "")
                    sid = principal.get("sid", "")
                    if name and name != sid:
                        print(f"    - {name} ({sid})")
                    else:
                        print(f"    - {sid}")
                if len(enrollable_principals) > 5:
                    print(f"    ... and {len(enrollable_principals) - 5} more")

    # Vulnerabilities
    vulns = template.get("_vulnerabilities", [])
    if vulns:
        print(f"  [!] VULNERABILITIES:")
        for vuln in vulns:
            print(f"      - {vuln}")

    # Timestamps
    print(f"  Created                     : {template.get('whenCreated', 'N/A')}")
    print(f"  Modified                    : {template.get('whenChanged', 'N/A')}")


# =============================================================================
# Main Function
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Enhanced LDAP Certificate Template Enumerator with Full Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Authentication options
    parser.add_argument("-u", "--username", required=True, help="Username (user@DOMAIN or DOMAIN\\user)")
    parser.add_argument("-p", "--password", help="Password")
    parser.add_argument("-hashes", help="NTLM hashes (LM:NT or :NT)")
    parser.add_argument("-k", "--kerberos", action="store_true", help="Use Kerberos authentication")
    parser.add_argument("-aes", help="AES key for Kerberos")
    parser.add_argument("--no-pass", action="store_true", help="No password")

    # Target options
    parser.add_argument("-dc-ip", required=True, help="Domain Controller IP")
    parser.add_argument("-dc-host", help="Domain Controller hostname")
    parser.add_argument("-ns", help="Nameserver")
    parser.add_argument("--timeout", type=int, default=5, help="Timeout (default: 5)")

    # LDAP options
    parser.add_argument("-scheme", "--ldap-scheme", choices=["ldap", "ldaps"], default="ldaps", help="LDAP scheme")
    parser.add_argument("-port", "--ldap-port", type=int, help="LDAP port")
    parser.add_argument("--no-ldap-channel-binding", action="store_true", help="Disable channel binding")
    parser.add_argument("--no-ldap-signing", action="store_true", help="Disable LDAP signing")
    parser.add_argument("--ldap-simple-auth", action="store_true", help="Use SIMPLE authentication")

    # Output options
    parser.add_argument("-o", "--output", help="Output JSON file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-vulnerable", "--vulnerable", action="store_true", help="Show only vulnerable templates")

    args = parser.parse_args()

    # Parse username and domain
    if "@" in args.username:
        parts = args.username.split("@")
        username = "@".join(parts[:-1])
        domain = parts[-1]
    elif "\\" in args.username:
        domain, username = args.username.split("\\", 1)
    else:
        print("[!] Username must be in format user@DOMAIN or DOMAIN\\user")
        sys.exit(1)

    domain = domain.upper()
    username = username.upper()

    # Handle password
    password = args.password
    if not password and not args.hashes and not args.kerberos and not args.no_pass:
        password = getpass("Password: ")

    # Parse hashes
    lmhash = ""
    nthash = ""
    if args.hashes:
        if ":" in args.hashes:
            lmhash, nthash = args.hashes.split(":", 1)
            if not lmhash:
                lmhash = nthash
        else:
            nthash = args.hashes
            lmhash = nthash

    # Setup DNS resolver
    resolver = DnsResolver(args.ns or args.dc_ip)

    # Resolve target IP
    target_ip = args.dc_ip
    if not is_ip(target_ip):
        print(f"[*] Resolving {target_ip}...")
        target_ip = resolver.resolve(target_ip)
        print(f"[+] Resolved to {target_ip}")

    # Create target object
    target = Target(
        domain=domain,
        username=username,
        password=password,
        remote_name=args.dc_host or target_ip,
        hashes=args.hashes,
        lmhash=lmhash,
        nthash=nthash,
        do_kerberos=args.kerberos,
        do_simple=args.ldap_simple_auth,
        aes=args.aes,
        dc_ip=args.dc_ip,
        target_ip=target_ip,
        timeout=args.timeout,
        ldap_scheme=args.ldap_scheme,
        ldap_port=args.ldap_port,
        ldap_channel_binding=not args.no_ldap_channel_binding,
        ldap_signing=not args.no_ldap_signing,
    )

    try:
        # Connect to LDAP
        print(f"\n[*] Connecting to LDAP server at {target_ip}:{target.ldap_port} ({target.ldap_scheme.upper()})...")
        connection = LDAPConnection(target)
        connection.connect()

        # Query certificate templates
        templates = get_certificate_templates(connection)

        # Query certificate authorities
        cas = get_certificate_authorities(connection)

        # Link templates to CAs to determine enabled status
        link_templates_to_cas(templates, cas)

        # Process each template
        print("\n[*] Processing templates...")
        for template in templates:
            process_template_flags(template)
            process_template_policies(template)

            # Analyze permissions (with SID resolution)
            perms = analyze_permissions(template, connection=connection)
            template.set("_permissions", perms)

            # Detect vulnerabilities
            vulns = detect_vulnerabilities(template)
            template.set("_vulnerabilities", vulns)

        # Filter templates if requested
        if args.vulnerable:
            filtered_templates = [t for t in templates if t.get("_vulnerabilities")]
            print(f"\n[*] Filtering to show only vulnerable templates...")
            print(f"[+] {len(filtered_templates)} vulnerable templates found out of {len(templates)} total")
        else:
            filtered_templates = templates

        # Display results
        print("\n" + "="*80)
        print(f"CERTIFICATE TEMPLATE ANALYSIS - {len(filtered_templates)} Templates" +
              (" (VULNERABLE ONLY)" if args.vulnerable else ""))
        print("="*80)

        if not args.vulnerable:
            enabled_count = sum(1 for t in templates if t.get("_enabled"))
            disabled_count = len(templates) - enabled_count
            print(f"\n[*] Template Status:")
            print(f"    - {enabled_count} templates are ENABLED (linked to CAs)")
            print(f"    - {disabled_count} templates are DISABLED (not linked to any CA)")

        vuln_count = sum(1 for t in templates if t.get("_vulnerabilities"))
        if vuln_count > 0:
            print(f"\n[!] Found {vuln_count} templates with potential vulnerabilities!")

        for template in filtered_templates:
            format_template_output(template, verbose=args.verbose)

        # Save to JSON if requested
        if args.output:
            # Prepare JSON-serializable output
            output_data = []
            for template in filtered_templates:
                perms = template.get("_permissions", {})
                template_data = {
                    "Name": template.get("name"),
                    "Display Name": template.get("displayName"),
                    "CN": template.get("cn"),
                    "Enabled": template.get("_enabled", False),
                    "Certificate Authorities": template.get("_cas", []),
                    "Schema Version": template.get("schema_version"),
                    "Enrollment Flags": template.get("enrollment_flag_str"),
                    "Private Key Flags": template.get("private_key_flag_str"),
                    "Certificate Name Flags": template.get("certificate_name_flag_str"),
                    "Minimal Key Size": template.get("msPKI-Minimal-Key-Size"),
                    "RA Signature Required": template.get("authorized_signatures_required"),
                    "Extended Key Usage": template.get("extended_key_usage"),
                    "Client Authentication": template.get("client_authentication"),
                    "Enrollment Agent": template.get("enrollment_agent"),
                    "Any Purpose": template.get("any_purpose"),
                    "Enrollee Supplies Subject": template.get("enrollee_supplies_subject"),
                    "Requires Manager Approval": template.get("requires_manager_approval"),
                    "Owner": perms.get("owner_name") or perms.get("owner"),
                    "Owner SID": perms.get("owner"),
                    "Enrollable Principals": perms.get("enrollable_principals", []),
                    "Vulnerabilities": template.get("_vulnerabilities"),
                    "Created": str(template.get("whenCreated")),
                    "Modified": str(template.get("whenChanged")),
                }
                output_data.append(template_data)

            with open(args.output, 'w') as f:
                json.dump(output_data, f, indent=2, default=str)
            print(f"\n[+] Results saved to {args.output}")

        print(f"\n[+] Analysis complete!")

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        error_msg = str(e)
        print(f"\n[!] Error: {error_msg}")

        # Provide helpful suggestions
        if "NTLM authentication failed" in error_msg or "protocolOp" in error_msg:
            print("\n[*] NTLM authentication troubleshooting:")
            print("    1. Try using LDAPS: -scheme ldaps -port 636")
            print("    2. Try Simple BIND: --ldap-simple-auth")
            print("    3. Verify credentials are correct")
        elif "bind failed" in error_msg.lower():
            print("\n[*] Authentication troubleshooting:")
            print("    1. Verify username/password")
            print("    2. Check domain name format")
            print("    3. Ensure DC IP is correct")

        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
