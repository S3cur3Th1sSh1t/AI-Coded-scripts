import smtplib
import dns.resolver
import socket
import ssl
import sys
import os

'''
For this script to work without getting listet on spam lists you need to correctly configure SPF, have a valid domain, a PTR lookup for the IP
And an MX Entry for your Mail server pointing to that IP.
Otherwise youre blacklisted pretty fast.
'''

def get_mx_servers(domain):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        mx_records = sorted([(r.preference, str(r.exchange).rstrip('.')) for r in answers])
        return [mx for _, mx in mx_records]
    except Exception as e:
        print(f"[!] MX lookup failed for {domain}: {e}")
        return []

def verify_email_smtp(email, mx_servers, from_address="info@yourdomain", timeout=10):
    for mx in mx_servers:
        try:
            print(f"  [i] Connecting to {mx} ...")
            server = smtplib.SMTP(mx, 25, timeout=timeout)
            server.ehlo("mxentry.yourdomain")
            if server.has_extn('STARTTLS'):
                context = ssl.create_default_context()
                server.starttls(context=context)
                server.ehlo("mxentry.yourdomain")
            code, _ = server.mail(from_address)
            if code != 250:
                print(f"    [✗] MAIL FROM rejected: {code}")
                server.quit()
                continue
            code, msg = server.rcpt(email)
            server.quit()
            if code == 250 or code == 251:
                print(f"    [✓] {email} is valid (RCPT TO accepted by {mx})")
                return True
            elif code == 550:
                print(f"    [✗] {email} is invalid (RCPT TO rejected by {mx})")
                return False
            else:
                print(f"    [?] {email} got code {code} ({msg}) from {mx}")
        except (smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError, socket.timeout, ConnectionRefusedError) as e:
            print(f"    [!] Connection to {mx} failed: {e}")
        except Exception as e:
            print(f"    [!] Error with {mx}: {e}")
    print(f"    [?] {email} could not be verified (all MX failed or ambiguous response)")
    return None

def main():
    if len(sys.argv) > 1:
        input_file = sys.argv[1]
    else:
        input_file = input("E-Mail-Liste (eine Adresse pro Zeile): ").strip()
    with open(input_file, encoding='utf-8') as f:
        emails = [line.strip() for line in f if line.strip() and '@' in line]

    valid_path = os.path.join(os.getcwd(), "valid.txt")
    with open(valid_path, "w", encoding="utf-8") as valid_file:
        for email in emails:
            print(f"\n=== Prüfe: {email} ===")
            domain = email.split('@')[-1].lower()
            mx_servers = get_mx_servers(domain)
            if not mx_servers:
                print(f"  [!] Keine MX-Server für {domain} gefunden.")
                continue
            result = verify_email_smtp(email, mx_servers)
            if result is True:
                print(f"[RESULT] {email}: VALID")
                valid_file.write(email + "\n")
            elif result is False:
                print(f"[RESULT] {email}: INVALID")
            else:
                print(f"[RESULT] {email}: UNVERIFIED")

if __name__ == '__main__':
    main()
