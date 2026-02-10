#!/usr/bin/env python3
import argparse
import ldap3
import sys


def parse_args():
    parser = argparse.ArgumentParser(description="Unlock an AD account via LDAP")
    parser.add_argument("-u", "--user", required=True, help="Auth username (plain, DOMAIN\\user, or user@domain)")
    parser.add_argument("-p", "--password", required=True, help="Auth password")
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g. domain.local)")
    parser.add_argument("-t", "--target", required=True, help="sAMAccountName of locked account")
    parser.add_argument("--dc", help="DC IP or hostname (default: auto-resolve domain)")
    parser.add_argument("--use-ldaps", action="store_true", default=False, help="Use LDAPS (636)")
    return parser.parse_args()


def get_base_dn(domain):
    return ",".join(f"DC={part}" for part in domain.split("."))


def format_user(user, domain):
    if "\\" not in user and "@" not in user:
        domain_short = domain.split(".")[0].upper()
        return f"{domain_short}\\{user}"
    return user


def main():
    args = parse_args()
    base_dn = get_base_dn(args.domain)
    dc = args.dc or args.domain
    auth_user = format_user(args.user, args.domain)

    scheme = "ldaps" if args.use_ldaps else "ldap"
    port = 636 if args.use_ldaps else 389
    server = ldap3.Server(f"{scheme}://{dc}:{port}", get_info=ldap3.ALL)

    print(f"[*] Connecting to {dc}:{port} as {auth_user}")
    conn = ldap3.Connection(server, user=auth_user, password=args.password, authentication=ldap3.NTLM)

    if not conn.bind():
        print(f"[-] Bind failed: {conn.result}")
        sys.exit(1)

    print(f"[+] Authenticated as {auth_user}")

    # Find the target account
    search_filter = f"(sAMAccountName={args.target})"
    conn.search(
        search_base=base_dn,
        search_filter=search_filter,
        search_scope=ldap3.SUBTREE,
        attributes=["distinguishedName", "lockoutTime", "badPwdCount", "userAccountControl"],
    )

    if not conn.entries:
        print(f"[-] Account '{args.target}' not found in {base_dn}")
        sys.exit(1)

    entry = conn.entries[0]
    print(f"[*] Found: {entry.entry_dn}")
    print(f"    lockoutTime:        {entry.lockoutTime}")
    print(f"    badPwdCount:        {entry.badPwdCount}")
    print(f"    userAccountControl: {entry.userAccountControl}")

    lockout_time = entry.lockoutTime.value
    if lockout_time is None or str(lockout_time) == "0":
        print(f"[*] Account '{args.target}' is not locked out")
        sys.exit(0)

    # Unlock
    print(f"[*] Unlocking {args.target}...")
    conn.modify(entry.entry_dn, {"lockoutTime": [(ldap3.MODIFY_REPLACE, [0])]})

    if conn.result["result"] == 0:
        print(f"[+] Successfully unlocked '{args.target}'")
    else:
        print(f"[-] Failed to unlock: {conn.result}")

    conn.unbind()


if __name__ == "__main__":
    main()
