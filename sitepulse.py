#!/usr/bin/env python3
"""
SitePulse — Website Health Checker
Checks availability, response time, HTTPS certificate, and security headers.
For authorized targets only.
"""

import ssl
import socket
import time
import argparse
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS not set — vulnerable to protocol downgrade attacks.",
    "Content-Security-Policy": "CSP missing — XSS risk.",
    "X-Content-Type-Options": "X-Content-Type-Options missing — MIME sniffing risk.",
    "X-Frame-Options": "X-Frame-Options missing — clickjacking risk.",
    "Referrer-Policy": "Referrer-Policy missing — referrer leakage possible.",
    "Permissions-Policy": "Permissions-Policy missing — browser features unrestricted.",
}


def normalize_url(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return "https://" + target
    return target


def check_availability(url: str, timeout: int = 10) -> dict:
    """Return status code and response time."""
    result = {"url": url, "status": None, "response_ms": None, "error": None}
    try:
        start = time.perf_counter()
        resp = requests.get(url, timeout=timeout, allow_redirects=True)
        elapsed = (time.perf_counter() - start) * 1000
        result["status"] = resp.status_code
        result["response_ms"] = round(elapsed, 2)
        result["headers"] = dict(resp.headers)
    except requests.exceptions.SSLError as e:
        result["error"] = f"SSL error: {e}"
    except requests.exceptions.ConnectionError as e:
        result["error"] = f"Connection error: {e}"
    except requests.exceptions.Timeout:
        result["error"] = f"Timed out after {timeout}s"
    except Exception as e:
        result["error"] = str(e)
    return result


def check_ssl(hostname: str, port: int = 443) -> dict:
    """Return certificate expiry info and days remaining."""
    info = {"hostname": hostname, "expires": None, "days_left": None, "error": None}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        not_after = not_after.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        info["expires"] = not_after.strftime("%Y-%m-%d %H:%M:%S UTC")
        info["days_left"] = (not_after - now).days
    except Exception as e:
        info["error"] = str(e)
    return info


def check_security_headers(headers: dict) -> dict:
    """Return which security headers are present / missing."""
    findings = {}
    for header, tip in SECURITY_HEADERS.items():
        value = headers.get(header)
        findings[header] = {"present": bool(value), "value": value, "tip": tip}
    return findings


def print_report(url: str, avail: dict, ssl_info: dict, header_findings: dict) -> None:
    print("=" * 60)
    print(f"  SitePulse Report — {url}")
    print("=" * 60)

    # Availability
    print("\n[ Availability ]")
    if avail["error"]:
        print(f"  ✗ Error: {avail['error']}")
    else:
        print(f"  ✓ HTTP Status : {avail['status']}")
        print(f"  ✓ Response Time: {avail['response_ms']} ms")

    # SSL
    print("\n[ HTTPS Certificate ]")
    if ssl_info["error"]:
        print(f"  ✗ Error: {ssl_info['error']}")
    else:
        print(f"  ✓ Expires  : {ssl_info['expires']}")
        days = ssl_info["days_left"]
        if days is not None:
            marker = "✓" if days > 30 else "⚠"
            print(f"  {marker} Days Left: {days}")

    # Security headers
    print("\n[ Security Headers ]")
    for header, data in header_findings.items():
        if data["present"]:
            print(f"  ✓ {header}: {data['value']}")
        else:
            print(f"  ✗ {header}: MISSING — {data['tip']}")

    print("\n" + "=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="SitePulse — Website Health Checker. For authorized targets only."
    )
    parser.add_argument("target", help="Domain or URL to check (e.g. example.com)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    args = parser.parse_args()

    url = normalize_url(args.target)
    hostname = urlparse(url).hostname

    print(f"\n🔎 Checking {url} ...\n")

    avail = check_availability(url, args.timeout)
    ssl_info = check_ssl(hostname) if hostname else {"error": "No hostname"}
    header_findings = check_security_headers(avail.get("headers", {}))

    print_report(url, avail, ssl_info, header_findings)


if __name__ == "__main__":
    main()
