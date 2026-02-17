#!/usr/bin/env python3
"""
CVE-2025-55182 Passive Scanner (React2Shell) - Enhanced
Stealth detection of React Server Components RCE vulnerability without RCE payloads.

Features:
- Error pattern fingerprinting (no code execution)
- Framework version detection with patched version awareness
- RSC endpoint discovery (robots.txt, sitemap, common paths)
- Header-based fingerprinting
- RSC Accept header probing
- Multiple WAF-friendly probes
- Reachability pre-checks
- Rate limiting with jitter
- Mass scanning with structured output (JSON/CSV/TXT)

Usage:
  python3 react2shell_passive.py -u http://target.com
  python3 react2shell_passive.py -l targets.txt --threads 50 -o results.json
  python3 react2shell_passive.py -u https://app.com --proxy http://127.0.0.1:8080 --delay 1 --jitter 0.5
"""

import requests
import argparse
import sys
import uuid
import re
import urllib3
import json
import csv
import time
import random
import concurrent.futures
from xml.etree import ElementTree
from urllib.parse import urlparse, urljoin
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timezone

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── ANSI Colors ─────────────────────────────────────────────────────────────

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

BANNER = f"""
{CYAN}{BOLD}
  ██████╗  █████╗ ███████╗███████╗██╗██╗   ██╗███████╗
  ██╔══██╗██╔══██╗██╔════╝██╔════╝██║██║   ██║██╔════╝
  ██████╔╝███████║███████╗███████╗██║██║   ██║█████╗  
  ██╔═══╝ ██╔══██║╚════██║╚════██║██║╚██╗ ██╔╝██╔══╝  
  ██║     ██║  ██║███████║███████║██║ ╚████╔╝ ███████╗
  ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝  ╚══════╝
{RESET}
{DIM}  React2Shell Passive Scanner v2.0  │  CVE-2025-55182 stealth detection{RESET}
{YELLOW}  ⚠  Behavioral testing only — no code execution{RESET}
"""

# ─── Known Patched Versions ─────────────────────────────────────────────────
# Map: major -> (min_minor, min_patch) that is patched.
# Anything below these in the same major line is considered vulnerable.
# Update these as new patches are released.

PATCHED_VERSIONS = {
    14: (3, 2),    # 14.3.2+ is patched
    15: (2, 4),    # 15.2.4+ is patched
}

# ─── RSC Probes ──────────────────────────────────────────────────────────────
# Multiple deserialization probes to increase detection rate.
# Ordered from least to most likely to trigger WAF rules.

RSC_PROBES = [
    {
        "name": "broken_flight_ref",
        "parts": {
            "0": '["$","div",null,{"children":"$L1"}]',
            "1": '"$undefined"',
        },
    },
    {
        "name": "invalid_promise",
        "parts": {
            "0": '{"status":"fulfilled","value":"$undefined"}',
            "1": '"$@0"',
        },
    },
    {
        "name": "constructor_ref",
        "parts": {
            "0": '{"then": "$1:constructor:then", "status": "pending"}',
            "1": '"$@0"',
        },
    },
    {
        "name": "proto_ref",
        "parts": {
            "0": '{"then": "$1:__proto__:then", "status": "pending"}',
            "1": '"$@0"',
        },
    },
]

# ─── Common Paths for Endpoint Discovery ─────────────────────────────────────

COMMON_APP_PATHS = [
    "/",
    "/dashboard",
    "/login",
    "/auth",
    "/api",
    "/app",
    "/admin",
    "/settings",
    "/account",
    "/profile",
    "/search",
]


# ═════════════════════════════════════════════════════════════════════════════
class React2ShellDetector:
    """Passive scanner for CVE-2025-55182 (React2Shell)."""

    def __init__(
        self,
        session: requests.Session,
        timeout: int = 10,
        verify_ssl: bool = True,
        delay: float = 0.0,
        jitter: float = 0.0,
        verbose: bool = False,
    ):
        self.session = session
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.delay = delay
        self.jitter = jitter
        self.verbose = verbose

    # ── Helpers ───────────────────────────────────────────────────────────

    def _throttle(self):
        """Apply rate-limiting delay with optional jitter."""
        if self.delay > 0:
            wait = self.delay + random.uniform(0, self.jitter)
            time.sleep(wait)

    def _log(self, msg: str):
        """Verbose logging."""
        if self.verbose:
            print(f"{DIM}    [debug] {msg}{RESET}")

    @staticmethod
    def generate_boundary() -> str:
        return "WebKitFormBoundary" + uuid.uuid4().hex[:16]

    # ── Reachability ─────────────────────────────────────────────────────

    def is_reachable(self, url: str) -> bool:
        """Quick reachability check before running full scan battery."""
        try:
            resp = self.session.head(
                url, timeout=5, verify=self.verify_ssl, allow_redirects=True
            )
            return resp.status_code < 500
        except Exception:
            return False

    # ── Endpoint Discovery ───────────────────────────────────────────────

    def discover_endpoints(self, url: str) -> List[str]:
        """Discover potential RSC / server-action endpoints."""
        candidates = set()
        base = url.rstrip("/")

        # 1. Always include the base URL itself
        candidates.add(base + "/")

        # 2. Common application paths
        for path in COMMON_APP_PATHS:
            candidates.add(urljoin(base + "/", path))

        # 3. robots.txt
        candidates.update(self._parse_robots(base))

        # 4. sitemap.xml
        candidates.update(self._parse_sitemap(base))

        self._log(f"Discovered {len(candidates)} candidate endpoints")
        return list(candidates)

    def _parse_robots(self, base: str) -> set:
        """Extract paths from robots.txt."""
        paths = set()
        try:
            resp = self.session.get(
                base + "/robots.txt", timeout=5, verify=self.verify_ssl
            )
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith(("allow:", "disallow:")):
                        path = line.split(":", 1)[1].strip()
                        # Skip wildcard / empty / root-only
                        if path and path != "/" and "*" not in path:
                            paths.add(urljoin(base + "/", path))
                    elif line.lower().startswith("sitemap:"):
                        sitemap_url = line.split(":", 1)[1].strip()
                        paths.update(self._parse_sitemap_url(sitemap_url))
                self._log(f"robots.txt yielded {len(paths)} paths")
        except Exception:
            pass
        return paths

    def _parse_sitemap(self, base: str) -> set:
        """Extract paths from sitemap.xml."""
        return self._parse_sitemap_url(base + "/sitemap.xml")

    def _parse_sitemap_url(self, sitemap_url: str) -> set:
        """Parse a single sitemap URL for <loc> entries."""
        paths = set()
        try:
            resp = self.session.get(sitemap_url, timeout=5, verify=self.verify_ssl)
            if resp.status_code == 200 and "xml" in resp.headers.get("Content-Type", ""):
                root = ElementTree.fromstring(resp.content)
                # Handle both sitemap index and urlset
                ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
                for loc in root.iter():
                    if loc.tag.endswith("loc") and loc.text:
                        paths.add(loc.text.strip())
                self._log(f"Sitemap yielded {len(paths)} URLs")
        except Exception:
            pass
        return paths

    # ── Header-Based Fingerprinting ──────────────────────────────────────

    def check_response_headers(self, url: str) -> Dict:
        """Detect framework and RSC via response headers (lightweight HEAD)."""
        signals = {}
        try:
            resp = self.session.head(
                url, timeout=5, verify=self.verify_ssl, allow_redirects=True
            )

            # X-Powered-By
            powered_by = resp.headers.get("X-Powered-By", "")
            if "next" in powered_by.lower():
                signals["x_powered_by"] = powered_by

            # Server header
            server = resp.headers.get("Server", "")
            if any(x in server.lower() for x in ["next", "vercel"]):
                signals["server"] = server

            # Next.js-specific headers
            for h in [
                "x-nextjs-cache",
                "x-nextjs-matched-path",
                "x-middleware-rewrite",
                "x-middleware-next",
            ]:
                val = resp.headers.get(h)
                if val:
                    signals[h] = val

            # RSC content type
            ct = resp.headers.get("Content-Type", "")
            if "text/x-component" in ct:
                signals["rsc_content_type"] = ct

        except Exception as e:
            self._log(f"Header check failed: {e}")
        return signals

    # ── RSC Accept Header Probing ────────────────────────────────────────

    def probe_rsc_accept(self, url: str) -> Tuple[bool, str]:
        """
        Send an RSC-style Accept header and see if the server responds
        differently from a normal HTML request.  A divergence means
        the server is RSC-aware.
        """
        try:
            normal = self.session.get(
                url,
                timeout=5,
                verify=self.verify_ssl,
                headers={"Accept": "text/html"},
                allow_redirects=False,
            )
            self._throttle()

            rsc = self.session.get(
                url,
                timeout=5,
                verify=self.verify_ssl,
                headers={"Accept": "text/x-component", "RSC": "1"},
                allow_redirects=False,
            )

            status_diff = normal.status_code != rsc.status_code
            ct_diff = normal.headers.get("Content-Type", "") != rsc.headers.get(
                "Content-Type", ""
            )
            # RSC streams often contain 0: prefix lines
            body_is_flight = bool(re.match(r"^[0-9]+:", rsc.text[:64]))

            if body_is_flight:
                return True, "RSC Flight stream detected via Accept probe"
            if status_diff:
                return True, (
                    f"Status divergence: HTML={normal.status_code} RSC={rsc.status_code}"
                )
            if ct_diff:
                return True, (
                    f"Content-Type divergence: HTML={normal.headers.get('Content-Type','')} "
                    f"RSC={rsc.headers.get('Content-Type','')}"
                )

            return False, "No divergence on RSC Accept probe"

        except Exception as e:
            return False, f"Accept probe failed: {e}"

    # ── RSC Error-Pattern Probing (multiple probes) ──────────────────────

    def test_rsc_error_patterns(self, url: str) -> Tuple[bool, str, Optional[str]]:
        """
        Send multiple RSC deserialization probes and look for error
        signatures. Returns (detected, reason, matched_probe_name).
        """
        indicators = [
            'E{"digest"',
            '"digest":"NEXT_REDIRECT',
            "__NEXT_DATA__",
            "react-server-dom",
            "Flight protocol",
            "Unexpected server",
            "Server Functions cannot",
        ]

        for probe in RSC_PROBES:
            self._throttle()
            try:
                boundary = self.generate_boundary()

                # Build multipart body from probe parts
                body_parts = []
                for name, value in probe["parts"].items():
                    body_parts.append(
                        f"------{boundary}\r\n"
                        f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
                        f"{value}\r\n"
                    )
                body = "".join(body_parts) + f"------{boundary}--\r\n"

                headers = {
                    "Content-Type": f"multipart/form-data; boundary=----{boundary}",
                    "Next-Action": "x",
                    "User-Agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36"
                    ),
                }

                resp = self.session.post(
                    url,
                    data=body,
                    headers=headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=False,
                )

                text_lower = resp.text.lower()

                # Check body indicators
                for ind in indicators:
                    if ind.lower() in text_lower:
                        return True, f"RSC error pattern: {ind}", probe["name"]

                # Check response headers for RSC leaks
                for hdr, val in resp.headers.items():
                    if any(
                        x in val.lower()
                        for x in ["next-action", "rsc-", "flight", "text/x-component"]
                    ):
                        return True, f"RSC header: {hdr}={val}", probe["name"]

            except Exception as e:
                self._log(f"Probe '{probe['name']}' failed: {e}")
                continue

        return False, "No RSC error patterns detected", None

    # ── Version Detection ────────────────────────────────────────────────

    def detect_nextjs_version(self, url: str) -> Optional[str]:
        """Try to extract Next.js version from build artefacts."""
        paths = [
            "/_next/static/chunks/main.js",
            "/_next/static/chunks/pages/_app.js",
            "/_next/static/chunks/webpack.js",
            "/_next/static/chunks/framework.js",
            "/_next/BUILD_ID",
            "/api/_build",
        ]

        version_patterns = [
            r'next["\']?\s*:\s*["\']([0-9]+\.[0-9]+\.[0-9]+)',
            r'version["\']?\s*:\s*["\']([0-9]+\.[0-9]+\.[0-9]+)',
            r"Next\.js\s+v?([0-9]+\.[0-9]+\.[0-9]+)",
            r'__NEXT_DATA__.*?"buildId"\s*:\s*"([^"]+)"',
        ]

        for path in paths:
            self._throttle()
            try:
                resp = self.session.get(
                    urljoin(url, path), timeout=5, verify=self.verify_ssl
                )
                if resp.status_code == 200:
                    for pat in version_patterns:
                        m = re.search(pat, resp.text, re.IGNORECASE)
                        if m:
                            return m.group(1)
            except Exception:
                continue
        return None

    # ── App Router Detection ─────────────────────────────────────────────

    def detect_app_router(self, url: str) -> Tuple[bool, str]:
        """Detect App Router (vulnerable) vs Pages Router (safe)."""
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=self.verify_ssl)
            text = resp.text

            app_signs = [
                "/_next/static/chunks/app/",
                '"appDir":true',
                "server-action",
                "use server",
            ]
            pages_signs = [
                "/_next/static/chunks/pages/",
                '"appDir":false',
            ]

            for s in app_signs:
                if s.lower() in text.lower():
                    return True, f"App Router detected: {s}"
            for s in pages_signs:
                if s.lower() in text.lower():
                    return False, f"Pages Router detected: {s}"

            return False, "Router type unknown"
        except Exception as e:
            return False, f"Detection failed: {e}"

    # ── Framework Fingerprinting ─────────────────────────────────────────

    def fingerprint_react(self, url: str) -> Dict:
        """Comprehensive React / Next.js fingerprinting."""
        fp: Dict = {
            "framework": "unknown",
            "version": None,
            "rsc_enabled": False,
            "app_router": False,
            "header_signals": {},
            "indicators": [],
        }

        try:
            # Header-based detection first (cheap HEAD request)
            header_signals = self.check_response_headers(url)
            fp["header_signals"] = header_signals

            if header_signals:
                fp["indicators"].append(
                    f"Headers: {', '.join(f'{k}={v}' for k, v in header_signals.items())}"
                )
                if any(
                    k in header_signals
                    for k in ["x_powered_by", "server", "x-nextjs-cache"]
                ):
                    fp["framework"] = "Next.js"
                if "rsc_content_type" in header_signals:
                    fp["rsc_enabled"] = True

            # Body-based detection
            self._throttle()
            resp = self.session.get(url, timeout=self.timeout, verify=self.verify_ssl)
            text = resp.text

            if any(x in text for x in ["_next/static", "__NEXT_DATA__", "Next.js"]):
                fp["framework"] = "Next.js"
            elif any(x in text for x in ["react-dom", "React.createElement"]):
                fp["framework"] = "React"

            if fp["framework"] == "Next.js":
                fp["version"] = self.detect_nextjs_version(url)
                app_router, reason = self.detect_app_router(url)
                fp["app_router"] = app_router
                fp["indicators"].append(reason)

            # RSC body indicators
            rsc_keywords = [
                "react-server-dom",
                "server-action",
                "use server",
                "Next-Action",
                "Flight",
            ]
            for kw in rsc_keywords:
                if kw.lower() in text.lower():
                    fp["rsc_enabled"] = True
                    fp["indicators"].append(f"RSC keyword: {kw}")

        except Exception as e:
            fp["error"] = str(e)

        return fp

    # ── Version Vulnerability Check ──────────────────────────────────────

    @staticmethod
    def is_vulnerable_version(version: str) -> Tuple[bool, str]:
        """
        Check whether the detected version falls in the vulnerable range.
        Returns (is_vulnerable, reason).
        """
        try:
            parts = list(map(int, version.split(".")[:3]))
            major = parts[0]
            minor = parts[1] if len(parts) > 1 else 0
            patch = parts[2] if len(parts) > 2 else 0

            if major in PATCHED_VERSIONS:
                fixed_minor, fixed_patch = PATCHED_VERSIONS[major]
                if minor > fixed_minor or (
                    minor == fixed_minor and patch >= fixed_patch
                ):
                    return False, f"{version} is patched (>= {major}.{fixed_minor}.{fixed_patch})"
                return True, f"{version} is below patched version {major}.{fixed_minor}.{fixed_patch}"

            # Major 16 has no known patch yet — assume vulnerable
            if major == 16:
                return True, f"{version} — no known patch for major {major}"

            return False, f"{version} not in known vulnerable range"
        except Exception:
            return False, f"Could not parse version: {version}"

    # ── Full Target Scan ─────────────────────────────────────────────────

    def scan_target(self, url: str) -> Dict:
        """Run the complete passive-scan pipeline on one target."""
        result: Dict = {
            "url": url,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "reachable": False,
            "vulnerable": False,
            "confidence": "none",
            "details": {
                "fingerprint": {},
                "header_signals": {},
                "rsc_error_test": {},
                "rsc_accept_probe": {},
                "version_check": {},
                "endpoints_tested": [],
            },
        }

        # ── 0. Reachability ──────────────────────────────────────────────
        print(f"{DIM}[*] Scanning: {url}{RESET}")

        if not self.is_reachable(url):
            print(f"{RED}[!] Unreachable: {url}{RESET}\n")
            return result

        result["reachable"] = True

        # ── 1. Framework fingerprinting ──────────────────────────────────
        fingerprint = self.fingerprint_react(url)
        result["details"]["fingerprint"] = fingerprint
        result["details"]["header_signals"] = fingerprint.get("header_signals", {})

        # ── 2. RSC Accept-header probe on base URL ───────────────────────
        accept_hit, accept_reason = self.probe_rsc_accept(url)
        result["details"]["rsc_accept_probe"] = {
            "detected": accept_hit,
            "reason": accept_reason,
        }
        if accept_hit:
            fingerprint["rsc_enabled"] = True

        # ── 3. Discover and test endpoints for RSC errors ────────────────
        endpoints = self.discover_endpoints(url)
        rsc_error_found = False
        rsc_error_reason = ""
        matched_probe = None

        for ep in endpoints:
            self._throttle()
            hit, reason, probe_name = self.test_rsc_error_patterns(ep)
            result["details"]["endpoints_tested"].append(
                {"url": ep, "detected": hit, "reason": reason, "probe": probe_name}
            )
            if hit:
                rsc_error_found = True
                rsc_error_reason = reason
                matched_probe = probe_name
                self._log(f"RSC error on {ep} via probe '{probe_name}': {reason}")
                break  # One confirmed hit is enough

        result["details"]["rsc_error_test"] = {
            "detected": rsc_error_found,
            "reason": rsc_error_reason,
            "probe": matched_probe,
        }

        # ── 4. Version vulnerability assessment ──────────────────────────
        version = fingerprint.get("version")
        version_vuln = False
        version_reason = "No version detected"

        if version:
            version_vuln, version_reason = self.is_vulnerable_version(version)
        result["details"]["version_check"] = {
            "version": version,
            "vulnerable": version_vuln,
            "reason": version_reason,
        }

        # ── 5. Confidence scoring ────────────────────────────────────────
        score = 0
        reasons = []

        if rsc_error_found:
            score += 40
            reasons.append("RSC error pattern confirmed")
        if accept_hit:
            score += 20
            reasons.append("RSC Accept divergence")
        if fingerprint.get("framework") == "Next.js":
            score += 5
            reasons.append("Next.js detected")
        if fingerprint.get("app_router"):
            score += 10
            reasons.append("App Router in use")
        if fingerprint.get("rsc_enabled"):
            score += 10
            reasons.append("RSC indicators present")
        if version_vuln:
            score += 15
            reasons.append(f"Version {version} in vulnerable range")

        if score >= 50:
            result["vulnerable"] = True
            result["confidence"] = "high"
        elif score >= 25:
            result["vulnerable"] = True
            result["confidence"] = "medium"
        elif score >= 10:
            result["vulnerable"] = True
            result["confidence"] = "low"
        else:
            result["vulnerable"] = False
            result["confidence"] = "none"

        result["details"]["score"] = score
        result["details"]["score_reasons"] = reasons

        return result


# ═════════════════════════════════════════════════════════════════════════════
# Output / Reporting
# ═════════════════════════════════════════════════════════════════════════════

def print_result(result: Dict) -> None:
    """Pretty-print a single scan result to the terminal."""
    vuln = result["vulnerable"]
    conf = result["confidence"].upper()
    url = result["url"]

    if not result["reachable"]:
        return  # Already printed unreachable message

    if vuln and conf == "HIGH":
        color = RED
    elif vuln:
        color = GREEN
    else:
        color = DIM

    tag = "VULNERABLE" if vuln else "LIKELY SAFE"
    print(f"{color}{BOLD}[{tag}]{RESET} {color}{url}  (confidence: {conf}){RESET}")

    fp = result["details"].get("fingerprint", {})
    if fp.get("framework") != "unknown":
        ver = fp.get("version") or "unknown"
        print(f"  ├─ Framework : {fp['framework']} {ver}")

    vc = result["details"].get("version_check", {})
    if vc.get("version"):
        sym = "✗" if vc["vulnerable"] else "✓"
        print(f"  ├─ Version   : {vc['reason']}  [{sym}]")

    if fp.get("app_router"):
        print(f"  ├─ Router    : App Router (server actions enabled)")

    hdr = result["details"].get("header_signals", {})
    if hdr:
        print(f"  ├─ Headers   : {', '.join(f'{k}={v}' for k, v in hdr.items())}")

    rsc_acc = result["details"].get("rsc_accept_probe", {})
    if rsc_acc.get("detected"):
        print(f"  ├─ RSC Probe : {rsc_acc['reason']}")

    rsc_err = result["details"].get("rsc_error_test", {})
    if rsc_err.get("detected"):
        print(f"  ├─ RSC Error : {rsc_err['reason']} (probe: {rsc_err['probe']})")

    score = result["details"].get("score", 0)
    reasons = result["details"].get("score_reasons", [])
    if reasons:
        print(f"  └─ Score     : {score}/100 — {'; '.join(reasons)}")

    print()


def save_results(results: List[Dict], path: str, fmt: str) -> None:
    """Write scan results to file in the chosen format."""
    if fmt == "json":
        with open(path, "w") as f:
            json.dump(results, f, indent=2)

    elif fmt == "csv":
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "url", "reachable", "vulnerable", "confidence", "score",
                "framework", "version", "version_vulnerable", "app_router",
                "rsc_error", "rsc_accept", "timestamp",
            ])
            for r in results:
                fp = r["details"].get("fingerprint", {})
                vc = r["details"].get("version_check", {})
                writer.writerow([
                    r["url"],
                    r["reachable"],
                    r["vulnerable"],
                    r["confidence"],
                    r["details"].get("score", 0),
                    fp.get("framework", ""),
                    fp.get("version", ""),
                    vc.get("vulnerable", ""),
                    fp.get("app_router", ""),
                    r["details"].get("rsc_error_test", {}).get("detected", ""),
                    r["details"].get("rsc_accept_probe", {}).get("detected", ""),
                    r.get("timestamp", ""),
                ])

    elif fmt == "txt":
        with open(path, "w") as f:
            for r in results:
                status = "VULNERABLE" if r["vulnerable"] else "SAFE"
                conf = r["confidence"].upper()
                f.write(f"[{status}] {r['url']} — confidence: {conf}\n")

    print(f"{CYAN}[*] Results saved to {path} ({fmt}){RESET}")


# ═════════════════════════════════════════════════════════════════════════════
# Scan Orchestration
# ═════════════════════════════════════════════════════════════════════════════

def scan_single(detector: React2ShellDetector, url: str) -> Dict:
    """Scan a single target, print, and return result."""
    result = detector.scan_target(url)
    print_result(result)
    return result


def scan_multiple(
    detector: React2ShellDetector, urls: List[str], threads: int
) -> List[Dict]:
    """Scan multiple targets with threading."""
    print(f"{CYAN}[*] Scanning {len(urls)} targets with {threads} threads{RESET}\n")
    results: List[Dict] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(scan_single, detector, u): u for u in urls}
        for future in concurrent.futures.as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                print(f"{RED}[!] Thread error for {futures[future]}: {e}{RESET}")

    return results


# ═════════════════════════════════════════════════════════════════════════════
# CLI
# ═════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="CVE-2025-55182 Passive Scanner (React2Shell) — Enhanced",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single target
  python3 react2shell_passive.py -u http://target.com

  # Mass scan with JSON output
  python3 react2shell_passive.py -l targets.txt --threads 20 -o results.json

  # With proxy, rate limiting, and verbose output
  python3 react2shell_passive.py -u https://app.com \\
      --proxy http://127.0.0.1:8080 --delay 1 --jitter 0.5 -v

  # CSV output for spreadsheet analysis
  python3 react2shell_passive.py -l targets.txt -o scan.csv --format csv
        """,
    )

    target = parser.add_argument_group("target")
    target.add_argument("-u", "--url", help="Single target URL")
    target.add_argument("-l", "--list", help="File containing target URLs (one per line)")

    output = parser.add_argument_group("output")
    output.add_argument("-o", "--output", help="Output file path")
    output.add_argument(
        "--format",
        choices=["json", "csv", "txt"],
        default="json",
        help="Output format (default: json)",
    )

    tuning = parser.add_argument_group("tuning")
    tuning.add_argument(
        "-t", "--threads", type=int, default=10,
        help="Thread count for mass scanning (default: 10)",
    )
    tuning.add_argument(
        "--timeout", type=int, default=10,
        help="Per-request timeout in seconds (default: 10)",
    )
    tuning.add_argument(
        "--delay", type=float, default=0.0,
        help="Base delay between requests per thread, in seconds (default: 0)",
    )
    tuning.add_argument(
        "--jitter", type=float, default=0.0,
        help="Random jitter added to delay, in seconds (default: 0)",
    )

    network = parser.add_argument_group("network")
    network.add_argument("--proxy", help="HTTP/S proxy (e.g. http://127.0.0.1:8080)")
    network.add_argument(
        "--no-verify", action="store_true", help="Disable SSL certificate verification"
    )

    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Verbose debug output"
    )

    args = parser.parse_args()

    if not args.url and not args.list:
        parser.error("Specify either --url or --list")

    print(BANNER)

    # Session
    session = requests.Session()
    if args.proxy:
        session.proxies = {"http": args.proxy, "https": args.proxy}

    detector = React2ShellDetector(
        session=session,
        timeout=args.timeout,
        verify_ssl=not args.no_verify,
        delay=args.delay,
        jitter=args.jitter,
        verbose=args.verbose,
    )

    # Run
    results: List[Dict] = []

    if args.url:
        results.append(scan_single(detector, args.url))
    else:
        try:
            with open(args.list, "r") as f:
                urls = [
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]
            results = scan_multiple(detector, urls, args.threads)
        except FileNotFoundError:
            print(f"{RED}[!] File not found: {args.list}{RESET}")
            sys.exit(1)

    # Summary
    total = len(results)
    vuln = sum(1 for r in results if r["vulnerable"])
    high = sum(1 for r in results if r["confidence"] == "high")
    med = sum(1 for r in results if r["confidence"] == "medium")
    low = sum(1 for r in results if r["confidence"] == "low")
    unreachable = sum(1 for r in results if not r["reachable"])

    print(f"{CYAN}{'─' * 60}{RESET}")
    print(
        f"{BOLD}Summary:{RESET}  {total} scanned  │  "
        f"{RED}{vuln} vulnerable{RESET}  "
        f"({high} high, {med} medium, {low} low)  │  "
        f"{DIM}{unreachable} unreachable{RESET}"
    )
    print(f"{CYAN}{'─' * 60}{RESET}")

    # Save
    if args.output:
        save_results(results, args.output, args.format)


if __name__ == "__main__":
    main()
