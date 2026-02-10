#!/usr/bin/env python3
"""
sessionview.py - Remote Windows Session Enumerator

Enumerates logged-on users and active sessions on remote Windows hosts
using MSRPC (srvsvc NetSessionEnum / wkssvc NetWkstaUserEnum).
Supports NTLM (password/hash) and Kerberos authentication.

Impacket-style CLI interface with multi-target threading.
"""

import sys
import csv
import logging
import argparse
import threading
import concurrent.futures

from impacket.examples import logger
from impacket.dcerpc.v5 import transport, srvs, wkst
from impacket.dcerpc.v5.dtypes import NULL


class SessionEnumerator:
    def __init__(self, username, password, domain, lmhash, nthash,
                 do_kerberos=False, dc_ip=None, aes_key=None, port=445):
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = lmhash
        self.nthash = nthash
        self.do_kerberos = do_kerberos
        self.dc_ip = dc_ip
        self.aes_key = aes_key
        self.port = port

    def _connect_rpc(self, target, pipe):
        """Establish DCE/RPC connection over a named pipe."""
        string_binding = r'ncacn_np:%s[\pipe\%s]' % (target, pipe)
        rpc_transport = transport.DCERPCTransportFactory(string_binding)
        rpc_transport.set_dport(self.port)

        if hasattr(rpc_transport, 'set_credentials'):
            rpc_transport.set_credentials(
                self.username, self.password, self.domain,
                self.lmhash, self.nthash, self.aes_key
            )

        if self.do_kerberos:
            rpc_transport.set_kerberos(True, self.dc_ip)

        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        return dce

    def enum_sessions(self, target):
        """Enumerate active sessions via srvsvc NetSessionEnum (level 10, fallback level 1)."""
        sessions = []

        # Try level 10 first (doesn't require admin on older systems)
        try:
            dce = self._connect_rpc(target, 'srvsvc')
            dce.bind(srvs.MSRPC_UUID_SRVS)

            resp = srvs.hNetrSessionEnum(dce, NULL, NULL, 10)

            for session in resp['InfoStruct']['SessionInfo']['Level10']['Buffer']:
                sessions.append({
                    'computer':  session['sesi10_cname'][:-1],
                    'username':  session['sesi10_username'][:-1],
                    'time':      session['sesi10_time'],
                    'idle':      session['sesi10_idle_time'],
                })
            dce.disconnect()
            return sessions

        except Exception as e:
            logging.debug(f"[{target}] NetSessionEnum level 10 failed: {e}")

        # Fallback to level 1 (needs admin, but returns more info)
        try:
            dce = self._connect_rpc(target, 'srvsvc')
            dce.bind(srvs.MSRPC_UUID_SRVS)

            resp = srvs.hNetrSessionEnum(dce, NULL, NULL, 1)

            for session in resp['InfoStruct']['SessionInfo']['Level1']['Buffer']:
                sessions.append({
                    'computer':    session['sesi1_cname'][:-1],
                    'username':    session['sesi1_username'][:-1],
                    'time':        session['sesi1_time'],
                    'idle':        session['sesi1_idle_time'],
                    'num_opens':   session['sesi1_num_opens'],
                    'user_flags':  session['sesi1_user_flags'],
                })
            dce.disconnect()

        except Exception as e:
            logging.debug(f"[{target}] NetSessionEnum level 1 failed: {e}")

        return sessions

    def enum_loggedon(self, target):
        """Enumerate locally logged-on users via wkssvc NetWkstaUserEnum (level 1, fallback level 0)."""
        users = []

        # Try level 1 (returns domain, logon server)
        try:
            dce = self._connect_rpc(target, 'wkssvc')
            dce.bind(wkst.MSRPC_UUID_WKST)

            resp = wkst.hNetrWkstaUserEnum(dce, 1)

            for user in resp['UserInfo']['WkstaUserInfo']['Level1']['Buffer']:
                users.append({
                    'username':     user['wkui1_username'][:-1],
                    'logon_domain': user['wkui1_logon_domain'][:-1],
                    'logon_server': user['wkui1_logon_server'][:-1],
                    'oth_domains':  user['wkui1_oth_domains'][:-1],
                })
            dce.disconnect()
            return users

        except Exception as e:
            logging.debug(f"[{target}] NetWkstaUserEnum level 1 failed: {e}")

        # Fallback to level 0 (username only)
        try:
            dce = self._connect_rpc(target, 'wkssvc')
            dce.bind(wkst.MSRPC_UUID_WKST)

            resp = wkst.hNetrWkstaUserEnum(dce, 0)

            for user in resp['UserInfo']['WkstaUserInfo']['Level0']['Buffer']:
                users.append({
                    'username': user['wkui0_username'][:-1],
                })
            dce.disconnect()

        except Exception as e:
            logging.debug(f"[{target}] NetWkstaUserEnum level 0 failed: {e}")

        return users

    def enumerate_target(self, target):
        """Full enumeration of a single target."""
        result = {
            'target':   target,
            'sessions': [],
            'loggedon': [],
            'error':    None,
        }

        try:
            logging.info(f"[*] Enumerating {target}")
            result['loggedon'] = self.enum_loggedon(target)
            result['sessions'] = self.enum_sessions(target)
        except Exception as e:
            result['error'] = str(e)
            logging.error(f"[-] {target}: {e}")

        return result


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _fmt_time(seconds):
    """Format seconds into a human-readable duration string."""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    else:
        h = seconds // 3600
        m = (seconds % 3600) // 60
        return f"{h}h {m}m"


class ResultWriter:
    """Thread-safe incremental result writer supporting text, grep, and CSV output."""

    CSV_HEADERS = [
        'target', 'type', 'username', 'domain', 'source_host',
        'logon_server', 'other_domains', 'active_time', 'idle_time', 'error'
    ]

    def __init__(self, output_file=None, grep_mode=False, csv_mode=False):
        self.output_file = output_file
        self.grep_mode = grep_mode
        self.csv_mode = csv_mode
        self._lock = threading.Lock()
        self._results = []
        self._csv_writer = None
        self._fh = None

        # Open file handle and write CSV header if needed
        if self.output_file:
            self._fh = open(self.output_file, 'w', newline='', encoding='utf-8')
            if self.csv_mode:
                self._csv_writer = csv.writer(self._fh)
                self._csv_writer.writerow(self.CSV_HEADERS)
                self._fh.flush()

    def write_result(self, result):
        """Write a single host result incrementally (thread-safe)."""
        with self._lock:
            self._results.append(result)
            self._print_console(result)
            if self._fh:
                if self.csv_mode:
                    self._write_csv_rows(result)
                else:
                    self._write_text_rows(result)
                self._fh.flush()

    def _print_console(self, r):
        """Print result to console."""
        target = r['target']

        if r['error']:
            if self.grep_mode:
                print(f"{target}\tERROR\t{r['error']}")
            else:
                print(f"\n[-] {target}: ERROR - {r['error']}")
            return

        if not r['loggedon'] and not r['sessions']:
            if not self.grep_mode:
                print(f"\n[-] {target}: No sessions found")
            return

        if self.grep_mode:
            seen = set()
            for u in r['loggedon']:
                domain = u.get('logon_domain', '')
                user   = u.get('username', '?')
                tag    = f"{domain}\\{user}" if domain else user
                if tag not in seen:
                    print(f"{target}\tloggedon\t{tag}")
                    seen.add(tag)
            for s in r['sessions']:
                user = s.get('username', '?')
                src  = s.get('computer', '?')
                print(f"{target}\tsession\t{user}\tfrom:{src}\t"
                      f"active:{_fmt_time(s.get('time', 0))}\t"
                      f"idle:{_fmt_time(s.get('idle', 0))}")
        else:
            print(f"\n{'=' * 60}")
            print(f"[+] {target}")
            print(f"{'=' * 60}")

            if r['loggedon']:
                print(f"\n  Logged-on Users ({len(r['loggedon'])}):")
                print(f"  {'-' * 45}")
                for u in r['loggedon']:
                    domain = u.get('logon_domain', '')
                    user   = u.get('username', '?')
                    tag    = f"{domain}\\{user}" if domain else user
                    print(f"    {tag}")
                    server = u.get('logon_server', '')
                    if server:
                        print(f"      Logon Server : {server}")
                    oth = u.get('oth_domains', '')
                    if oth:
                        print(f"      Other Domains: {oth}")

            if r['sessions']:
                print(f"\n  Active Sessions ({len(r['sessions'])}):")
                print(f"  {'-' * 45}")
                for s in r['sessions']:
                    user = s.get('username', '?')
                    src  = s.get('computer', '?')
                    act  = _fmt_time(s.get('time', 0))
                    idle = _fmt_time(s.get('idle', 0))
                    print(f"    {user:<20s} from {src}")
                    print(f"      Active: {act}  |  Idle: {idle}")

    def _write_csv_rows(self, r):
        """Write CSV rows for a single host result."""
        target = r['target']

        if r['error']:
            self._csv_writer.writerow([target, 'error', '', '', '', '', '', '', '', r['error']])
            return

        for u in r['loggedon']:
            self._csv_writer.writerow([
                target, 'loggedon',
                u.get('username', ''),
                u.get('logon_domain', ''),
                '',
                u.get('logon_server', ''),
                u.get('oth_domains', ''),
                '', '', ''
            ])

        for s in r['sessions']:
            self._csv_writer.writerow([
                target, 'session',
                s.get('username', ''),
                '',
                s.get('computer', ''),
                '', '',
                s.get('time', 0),
                s.get('idle', 0),
                ''
            ])

    def _write_text_rows(self, r):
        """Write text output for a single host result to file."""
        target = r['target']

        if r['error']:
            self._fh.write(f"[-] {target}: ERROR - {r['error']}\n")
            return

        if not r['loggedon'] and not r['sessions']:
            self._fh.write(f"[-] {target}: No sessions found\n")
            return

        self._fh.write(f"{'=' * 60}\n")
        self._fh.write(f"[+] {target}\n")
        self._fh.write(f"{'=' * 60}\n")

        for u in r['loggedon']:
            domain = u.get('logon_domain', '')
            user   = u.get('username', '?')
            tag    = f"{domain}\\{user}" if domain else user
            self._fh.write(f"  loggedon: {tag}\n")

        for s in r['sessions']:
            user = s.get('username', '?')
            src  = s.get('computer', '?')
            self._fh.write(f"  session: {user} from {src} "
                           f"(active: {_fmt_time(s.get('time', 0))}, "
                           f"idle: {_fmt_time(s.get('idle', 0))})\n")

        self._fh.write('\n')

    @property
    def results(self):
        return self._results

    def close(self):
        if self._fh:
            self._fh.close()
            print(f"\n[*] Results written to {self.output_file}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='Remote Windows Session Enumerator — '
                    'enumerate logged-on users and active sessions across multiple hosts.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=r"""
examples:
  # NTLM auth with password
  %(prog)s -u admin -p 'P@ss' -d CORP -tf targets.txt

  # Pass-the-hash
  %(prog)s -u admin -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 -d CORP -tf targets.txt

  # Kerberos auth
  %(prog)s -u admin -k -dc-ip 10.0.0.1 -d CORP -tf targets.txt

  # Kerberos with AES-256 key
  %(prog)s -u admin -aesKey <key> -k -dc-ip 10.0.0.1 -d CORP -tf targets.txt

  # Single target
  %(prog)s -u admin -p 'P@ss' -d CORP -t 10.0.0.5

  # Grep-friendly output
  %(prog)s -u admin -p 'P@ss' -d CORP -tf targets.txt --grep

  # CSV output (written incrementally per host)
  %(prog)s -u admin -p 'P@ss' -d CORP -tf targets.txt -o results --csv
"""
    )

    # --- targets ---
    tgt = parser.add_argument_group('target')
    tgt.add_argument('-t',  '--target',      help='Single target IP or hostname')
    tgt.add_argument('-tf', '--target-file',  help='File containing targets (one per line)')

    # --- authentication ---
    auth = parser.add_argument_group('authentication')
    auth.add_argument('-u', '--username',  default='', help='Username')
    auth.add_argument('-p', '--password',  default='', help='Password')
    auth.add_argument('-d', '--domain',    default='', help='Domain name')
    auth.add_argument('-H', '--hashes',    metavar='LM:NT', help='NTLM hash (LM:NT or :NT)')
    auth.add_argument('-k', '--kerberos',  action='store_true', help='Use Kerberos authentication')
    auth.add_argument('-aesKey',           metavar='KEY', help='AES key for Kerberos auth')
    auth.add_argument('-dc-ip',            metavar='IP', help='Domain controller IP (for Kerberos)')
    auth.add_argument('-port',             type=int, default=445, help='Target SMB port (default: 445)')

    # --- output ---
    out = parser.add_argument_group('output')
    out.add_argument('-o', '--output',   help='Write results to file (text or csv based on --csv)')
    out.add_argument('--csv',            action='store_true', help='Output in CSV format (requires -o)')
    out.add_argument('-w', '--workers',  type=int, default=10, help='Concurrent threads (default: 10)')
    out.add_argument('--grep',           action='store_true', help='Grep-friendly tab-separated output')
    out.add_argument('-v', '--verbose',  action='store_true', help='Verbose logging')
    out.add_argument('--debug',          action='store_true', help='Debug logging')

    args = parser.parse_args()

    # --- logging ---
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.verbose:
        logging.getLogger().setLevel(logging.INFO)
    else:
        logging.getLogger().setLevel(logging.WARNING)
    logger.init()

    # --- parse hashes ---
    lmhash = nthash = ''
    if args.hashes:
        parts = args.hashes.split(':')
        if len(parts) == 2:
            lmhash, nthash = parts
        else:
            nthash = parts[0]

    # --- build target list ---
    targets = []
    if args.target:
        targets.append(args.target.strip())
    if args.target_file:
        try:
            with open(args.target_file) as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        targets.append(line)
        except FileNotFoundError:
            print(f"[!] Target file not found: {args.target_file}", file=sys.stderr)
            sys.exit(1)

    if not targets:
        parser.error('No targets specified — use -t or -tf')

    # deduplicate while preserving order
    targets = list(dict.fromkeys(targets))

    dc_ip = getattr(args, 'dc_ip', None)
    auth_method = 'Kerberos' if args.kerberos else 'NTLM'
    identity = f"{args.domain}\\{args.username}" if args.domain else args.username or '(anonymous)'

    print(f"[*] SessionView — Remote Session Enumerator")
    print(f"[*] Targets : {len(targets)}")
    print(f"[*] Auth    : {auth_method} as {identity}")
    print(f"[*] Workers : {args.workers}")

    # --- auto-append .csv extension if --csv and -o doesn't have it ---
    if args.csv and args.output and not args.output.lower().endswith('.csv'):
        args.output += '.csv'

    enumerator = SessionEnumerator(
        username=args.username,
        password=args.password,
        domain=args.domain,
        lmhash=lmhash,
        nthash=nthash,
        do_kerberos=args.kerberos,
        dc_ip=dc_ip,
        aes_key=args.aesKey,
        port=args.port,
    )

    writer = ResultWriter(
        output_file=args.output,
        grep_mode=args.grep,
        csv_mode=args.csv,
    )

    # --- threaded enumeration with incremental output ---
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
            future_map = {pool.submit(enumerator.enumerate_target, t): t for t in targets}
            for future in concurrent.futures.as_completed(future_map):
                t = future_map[future]
                try:
                    result = future.result()
                except Exception as exc:
                    result = {'target': t, 'sessions': [], 'loggedon': [], 'error': str(exc)}
                writer.write_result(result)
    except KeyboardInterrupt:
        print("\n[!] Interrupted — partial results saved")
    finally:
        writer.close()

    # --- summary ---
    results = writer.results
    total_loggedon  = sum(len(r['loggedon'])  for r in results)
    total_sessions  = sum(len(r['sessions'])  for r in results)
    errors          = sum(1 for r in results if r['error'])
    hosts_with_data = sum(1 for r in results if r['loggedon'] or r['sessions'])

    print(f"\n[*] Done — {hosts_with_data}/{len(targets)} hosts returned data | "
          f"{total_loggedon} logged-on users | {total_sessions} sessions | {errors} errors")


if __name__ == '__main__':
    main()
