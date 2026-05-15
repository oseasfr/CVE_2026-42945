#!/usr/bin/env python3
"""
nginx_scanner.py — CVE-2026-42945 (NGINX RIFT) Detection Tool
--------------------------------------------------------------
Scans one or more targets for Nginx instances vulnerable to CVE-2026-42945.
Accepts individual IPs, CIDR ranges, and ASN numbers as input.

Usage examples:
  python nginx_scanner.py --ip 192.168.1.10
  python nginx_scanner.py --cidr 10.0.0.0/24 172.16.0.0/16
  python nginx_scanner.py --asn AS15169
  python nginx_scanner.py --cidr 10.0.0.0/8 --asn AS13335 AS15169
  python nginx_scanner.py --file targets.txt

targets.txt format (one entry per line, mix of IPs, CIDRs, ASNs):
  192.168.1.10
  10.0.0.0/24
  AS15169

Requirements:
  pip install requests packaging urllib3
"""

import requests
import re
import os
import sys
import time
import socket
import csv
import argparse
import ipaddress
import urllib3
from datetime import datetime
from packaging import version
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- ANSI Colors -------------------------------------------------------------
RED        = '\033[0;31m'
GREEN      = '\033[0;32m'
YELLOW     = '\033[1;33m'
CYAN       = '\033[0;36m'
BOLD       = '\033[1m'
RESET      = '\033[0m'
GREEN_DARK = '\033[38;2;26;122;58m'   # #1a7a3a — banner ASCII art

# --- CVE Config --------------------------------------------------------------
CVE_ID          = "CVE-2026-42945"
CVE_NAME        = "NGINX RIFT"
FIXED_VERSION   = "1.30.1"

# --- Output paths ------------------------------------------------------------
LOG_DIR   = "./logs"
TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE  = f"{LOG_DIR}/nginx_scan_{TIMESTAMP}.log"
LOG_VULN  = f"{LOG_DIR}/nginx_scan_{TIMESTAMP}_vulnerable.txt"
LOG_CSV   = f"{LOG_DIR}/nginx_scan_{TIMESTAMP}_results.csv"


# =============================================================================
# Logging
# =============================================================================

def log(level, msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    colors = {
        "OK":   f"{GREEN}[SAFE]{RESET}",
        "VULN": f"{RED}[VULN]{RESET}",
        "INFO": f"{CYAN}[INFO]{RESET}",
        "WARN": f"{YELLOW}[WARN]{RESET}",
        "ERR":  f"{RED}[ERR]{RESET}",
        "HEAD": "",
    }
    if level == "HEAD":
        line = f"{BOLD}{CYAN}{msg}{RESET}"
    else:
        line = f"{ts} {colors.get(level, '')}     {msg}"

    print(line)
    clean = re.sub(r'\033\[[0-9;]*m', '', line)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(clean + "\n")


# =============================================================================
# Target resolution
# =============================================================================

def resolve_asn(asn: str) -> list[str]:
    """
    Fetches CIDR prefixes announced by an ASN using the bgp.tools API.
    Accepts formats: 'AS15169', 'as15169', '15169'.
    """
    asn_number = asn.upper().lstrip("AS")
    url = f"https://bgp.tools/table.jsonl?asn={asn_number}"

    log("INFO", f"Resolving {asn.upper()} via bgp.tools ...")
    try:
        resp = requests.get(url, timeout=15, headers={"User-Agent": "nginx-scanner/1.0"})
        resp.raise_for_status()
        prefixes = []
        for line in resp.text.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                import json
                entry = json.loads(line)
                prefix = entry.get("CIDR") or entry.get("prefix") or entry.get("cidr")
                if prefix:
                    # Skip IPv6
                    if ":" not in prefix:
                        prefixes.append(prefix)
            except Exception:
                # Fallback: plain-text CIDR per line
                try:
                    ipaddress.ip_network(line, strict=False)
                    if ":" not in line:
                        prefixes.append(line)
                except ValueError:
                    pass

        if not prefixes:
            # Fallback to stat.ripe.net
            prefixes = resolve_asn_ripe(asn_number)

        log("INFO", f"{asn.upper()} — {len(prefixes)} IPv4 prefix(es) found")
        return prefixes

    except Exception as e:
        log("WARN", f"bgp.tools failed for {asn}: {e}. Trying RIPE ...")
        return resolve_asn_ripe(asn_number)


def resolve_asn_ripe(asn_number: str) -> list[str]:
    """Fallback ASN resolver using RIPE stat API."""
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_number}"
    try:
        resp = requests.get(url, timeout=15, headers={"User-Agent": "nginx-scanner/1.0"})
        resp.raise_for_status()
        data = resp.json()
        prefixes = [
            p["prefix"] for p in data.get("data", {}).get("prefixes", [])
            if ":" not in p.get("prefix", ":")  # skip IPv6
        ]
        log("INFO", f"AS{asn_number} — {len(prefixes)} IPv4 prefix(es) found via RIPE")
        return prefixes
    except Exception as e:
        log("ERR", f"RIPE fallback also failed for AS{asn_number}: {e}")
        return []


def expand_targets(ips=None, cidrs=None, asns=None, file=None) -> list[str]:
    """
    Resolves all input sources into a deduplicated, sorted list of CIDR strings.
    Single IPs are normalised to /32.
    """
    all_prefixes: list[str] = []

    if ips:
        for ip in ips:
            try:
                ipaddress.ip_address(ip)
                all_prefixes.append(f"{ip}/32")
            except ValueError:
                log("WARN", f"Invalid IP ignored: {ip}")

    if cidrs:
        for cidr in cidrs:
            try:
                ipaddress.ip_network(cidr, strict=False)
                all_prefixes.append(cidr)
            except ValueError:
                log("WARN", f"Invalid CIDR ignored: {cidr}")

    if asns:
        for asn in asns:
            all_prefixes.extend(resolve_asn(asn))

    if file:
        try:
            with open(file, encoding="utf-8") as fh:
                for raw in fh:
                    entry = raw.strip()
                    if not entry or entry.startswith("#"):
                        continue
                    upper = entry.upper()
                    if upper.startswith("AS") or upper.isdigit():
                        all_prefixes.extend(resolve_asn(entry))
                    elif "/" in entry:
                        try:
                            ipaddress.ip_network(entry, strict=False)
                            all_prefixes.append(entry)
                        except ValueError:
                            log("WARN", f"Invalid CIDR in file ignored: {entry}")
                    else:
                        try:
                            ipaddress.ip_address(entry)
                            all_prefixes.append(f"{entry}/32")
                        except ValueError:
                            log("WARN", f"Invalid entry in file ignored: {entry}")
        except FileNotFoundError:
            log("ERR", f"File not found: {file}")
            sys.exit(1)

    # Deduplicate preserving order
    seen = set()
    unique = []
    for p in all_prefixes:
        if p not in seen:
            seen.add(p)
            unique.append(p)

    return unique


# =============================================================================
# Scanner
# =============================================================================

def get_hostname(ip: str) -> str:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return "N/A"


def get_nginx_version(ip: str, timeout: float = 2.0) -> str | None:
    """Probes HTTP and HTTPS on standard ports. Returns Server header or None."""
    for proto, port in [("http", 80), ("https", 443)]:
        url = f"{proto}://{ip}:{port}"
        try:
            resp = requests.get(
                url,
                timeout=timeout,
                verify=False,
                allow_redirects=False,
                headers={"User-Agent": "nginx-scanner/1.0"},
            )
            server = resp.headers.get("Server", "")
            if "nginx" in server.lower():
                return server
        except Exception:
            continue
    return None


def check_vulnerability(server_string: str) -> tuple:
    """
    Returns (status, version_string).
    status values: True (vulnerable), False (safe), 'Possibly' (hidden version), 'Undetermined'
    """
    match = re.search(r"nginx/([\d.]+)", server_string, re.IGNORECASE)
    if match:
        ver_str = match.group(1)
        try:
            if version.parse(ver_str) < version.parse(FIXED_VERSION):
                return True, ver_str
            return False, ver_str
        except Exception:
            return "Undetermined", ver_str

    if "nginx" in server_string.lower():
        return "Possibly", "Hidden"

    return False, "N/A"


def scan_ip(ip: str) -> dict | None:
    server_header = get_nginx_version(ip)
    if server_header is None:
        return None
    is_vuln, ver = check_vulnerability(server_header)
    hostname = get_hostname(ip)
    return {
        "ip":         ip,
        "hostname":   hostname,
        "server":     server_header,
        "vulnerable": is_vuln,
        "version":    ver,
    }


# =============================================================================
# Main
# =============================================================================

def parse_args():
    parser = argparse.ArgumentParser(
        description=f"Nginx {CVE_ID} ({CVE_NAME}) — vulnerability scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --ip 93.184.216.34
  %(prog)s --cidr 10.0.0.0/24 192.168.1.0/24
  %(prog)s --asn AS15169
  %(prog)s --asn AS13335 AS15169 --cidr 10.0.0.0/8
  %(prog)s --file targets.txt
  %(prog)s --cidr 10.0.0.0/8 --workers 100 --timeout 3
        """,
    )
    parser.add_argument("--ip",      nargs="+", metavar="IP",   help="One or more individual IP addresses")
    parser.add_argument("--cidr",    nargs="+", metavar="CIDR", help="One or more CIDR ranges")
    parser.add_argument("--asn",     nargs="+", metavar="ASN",  help="One or more ASNs (e.g. AS15169 or 15169)")
    parser.add_argument("--file",    metavar="FILE",            help="File with IPs, CIDRs, and/or ASNs (one per line)")
    parser.add_argument("--workers", type=int, default=60,      help="Number of concurrent threads (default: 60)")
    parser.add_argument("--timeout", type=float, default=2.0,   help="HTTP request timeout in seconds (default: 2.0)")
    parser.add_argument("--no-confirm", action="store_true",    help="Skip confirmation prompt")
    return parser.parse_args()


def main():
    args = parse_args()

    if not any([args.ip, args.cidr, args.asn, args.file]):
        print(f"\n{RED}[ERR]{RESET} No targets specified. Use --ip, --cidr, --asn, or --file.\n")
        print("Run with --help for usage examples.")
        sys.exit(1)

    os.makedirs(LOG_DIR, exist_ok=True)

    # Banner
    print(f"""{GREEN_DARK}
 ███╗   ██╗ ██████╗ ██╗███╗   ██╗██╗  ██╗    ██████╗ ██╗███████╗████████╗
 ████╗  ██║██╔════╝ ██║████╗  ██║╚██╗██╔╝    ██╔══██╗██║██╔════╝╚══██╔══╝
 ██╔██╗ ██║██║  ███╗██║██╔██╗ ██║ ╚███╔╝     ██████╔╝██║█████╗     ██║
 ██║╚██╗██║██║   ██║██║██║╚██╗██║ ██╔██╗     ██╔══██╗██║██╔══╝     ██║
 ██║ ╚████║╚██████╔╝██║██║ ╚████║██╔╝ ██╗    ██║  ██║██║██║        ██║
 ╚═╝  ╚═══╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝        ╚═╝{RESET}""")
    print(f" \033[90m{'─' * 77}\033[0m")
    print(f"  {YELLOW}{CVE_ID}{RESET}  \033[90m│\033[0m  {CYAN}{CVE_NAME}{RESET}  \033[90m│\033[0m  Nginx < {FIXED_VERSION} — Scanner de Vulnerabilidade")
    print(f" \033[90m{'─' * 77}\033[0m\n")

    # Resolve all targets to CIDR list
    prefixes = expand_targets(
        ips=args.ip,
        cidrs=args.cidr,
        asns=args.asn,
        file=args.file,
    )

    if not prefixes:
        log("ERR", "No valid targets found after resolution. Aborting.")
        sys.exit(1)

    # Summary before scan
    total_hosts = sum(
        ipaddress.ip_network(p, strict=False).num_addresses - (2 if ipaddress.ip_network(p, strict=False).prefixlen < 31 else 0)
        for p in prefixes
    )

    print(f" {BOLD}Targets resolved:{RESET} {len(prefixes)} prefix(es) / ~{total_hosts:,} host(s)\n")
    for p in prefixes:
        net = ipaddress.ip_network(p, strict=False)
        print(f"   {CYAN}•{RESET} {p:<20}  ({net.num_addresses} addr)")
    print()

    if not args.no_confirm:
        confirm = input(f" {BOLD}Start scan? [y/N]:{RESET} ").strip().lower()
        if confirm != "y":
            print(" Cancelled.")
            sys.exit(0)

    # Initialise output files
    with open(LOG_VULN, "w", encoding="utf-8") as f:
        f.write(f"# NGINX VULNERABLE — {CVE_ID} | {TIMESTAMP}\n")
        f.write(f"{'IP':<18} {'HOSTNAME':<35} {'VERSION':<12} STATUS\n")
        f.write(f"{'='*18} {'='*35} {'='*12} {'='*20}\n")

    fieldnames = ["IP", "HOSTNAME", "NGINX_VERSION", "VULNERABILITY_STATUS"]
    with open(LOG_CSV, "w", newline="", encoding="utf-8") as f:
        csv.DictWriter(f, fieldnames=fieldnames).writeheader()

    log("HEAD", "══════════════════════════════════════════════════════")
    log("INFO", f"Start:    {datetime.now()}")
    log("INFO", f"Prefixes: {len(prefixes)}")
    log("INFO", f"Workers:  {args.workers}")
    log("INFO", f"Timeout:  {args.timeout}s")
    log("INFO", f"Log:      {LOG_FILE}")
    log("INFO", f"CSV:      {LOG_CSV}")
    log("HEAD", "══════════════════════════════════════════════════════")

    count_vuln  = 0
    count_warn  = 0
    count_safe  = 0
    count_total = 0
    start_time  = time.time()

    for prefix in prefixes:
        try:
            network = ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            log("WARN", f"Skipping invalid prefix: {prefix}")
            continue

        ips = [str(ip) for ip in network.hosts()] or [str(network.network_address)]

        log("HEAD", f"[ {prefix} ] — scanning {len(ips)} host(s) ...")

        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {executor.submit(scan_ip, ip): ip for ip in ips}
            for future in as_completed(futures):
                res = future.result()
                if res is None:
                    continue

                count_total += 1
                ip       = res["ip"]
                hostname = res["hostname"]
                ver      = res["version"]
                is_vuln  = res["vulnerable"]
                info     = f"{ip:<15} | {hostname:<30} | Ver: {ver}"

                if is_vuln is True:
                    status = "VULNERABLE"
                    log("VULN", f"{info} → {status}")
                    with open(LOG_VULN, "a", encoding="utf-8") as f:
                        f.write(f"{ip:<18} {hostname:<35} {ver:<12} {status}\n")
                    count_vuln += 1
                elif is_vuln == "Possibly":
                    status = "WARNING (Hidden Version)"
                    log("WARN", f"{info} → {status}")
                    count_warn += 1
                elif is_vuln == "Undetermined":
                    status = "UNDETERMINED"
                    log("WARN", f"{info} → {status}")
                    count_warn += 1
                else:
                    status = "SAFE"
                    log("OK", f"{info} → {status}")
                    count_safe += 1

                with open(LOG_CSV, "a", newline="", encoding="utf-8") as f:
                    csv.DictWriter(f, fieldnames=fieldnames).writerow({
                        "IP":                   ip,
                        "HOSTNAME":             hostname,
                        "NGINX_VERSION":        ver,
                        "VULNERABILITY_STATUS": status,
                    })

    elapsed = int(time.time() - start_time)
    log("HEAD", "══════════════════════════════════════════════════════")
    log("INFO", f"End:            {datetime.now()}")
    log("INFO", f"Elapsed:        {elapsed}s")
    log("INFO", f"Nginx hosts:    {count_total}")
    log("INFO", f"Vulnerable:     {count_vuln}")
    log("INFO", f"Warnings:       {count_warn}")
    log("INFO", f"Safe:           {count_safe}")
    log("INFO", f"Full log:       {LOG_FILE}")
    log("INFO", f"Vulnerable list:{LOG_VULN}")
    log("INFO", f"CSV results:    {LOG_CSV}")
    log("HEAD", "══════════════════════════════════════════════════════")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n Interrupted.")
        sys.exit(0)
