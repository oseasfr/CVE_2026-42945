#!/usr/bin/env python3
"""
nginx_scanner.py — CVE-2026-42945 (NGINX RIFT) — Ferramenta de Detecção
------------------------------------------------------------------------
Varre um ou mais alvos em busca de instâncias Nginx vulneráveis ao CVE-2026-42945.
Aceita IPs individuais, faixas CIDR e números de ASN como entrada.

Exemplos de uso:
  python nginx_scanner.py --ip 192.168.1.10
  python nginx_scanner.py --cidr 10.0.0.0/24 172.16.0.0/16
  python nginx_scanner.py --asn AS15169
  python nginx_scanner.py --cidr 10.0.0.0/8 --asn AS13335 AS15169
  python nginx_scanner.py --file alvos.txt

Formato do arquivo de alvos (um por linha, pode misturar IPs, CIDRs e ASNs):
  192.168.1.10
  10.0.0.0/24
  AS15169

Dependências:
  pip install requests packaging urllib3 dnspython
"""

import json
import requests
import re
import os
import sys
import time
import csv
import argparse
import ipaddress
import urllib3
from datetime import datetime
from functools import lru_cache
from packaging import version
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import dns.resolver
    import dns.reversename
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    import socket
    HAS_DNSPYTHON = False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- ANSI Colors -------------------------------------------------------------
RED        = '\033[0;31m'
GREEN      = '\033[0;32m'
YELLOW     = '\033[1;33m'
CYAN       = '\033[0;36m'
BOLD       = '\033[1m'
RESET      = '\033[0m'
GREEN_DARK = '\033[38;2;26;122;58m'

# --- Configuração CVE --------------------------------------------------------
CVE_ID        = "CVE-2026-42945"
CVE_NAME      = "NGINX RIFT"
FIXED_VERSION = "1.30.1"

# --- Configuração DNS ---------------------------------------------------------
DNS_WORKERS  = 200   # threads dedicadas à resolução DNS (I/O puro)
DNS_TIMEOUT  = 1.5   # segundos por query PTR

# --- Caminhos de saída -------------------------------------------------------
LOG_DIR   = "./logs"
TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE  = f"{LOG_DIR}/nginx_scan_{TIMESTAMP}.log"
LOG_VULN  = f"{LOG_DIR}/nginx_scan_{TIMESTAMP}_vulneraveis.txt"
LOG_CSV   = f"{LOG_DIR}/nginx_scan_{TIMESTAMP}_resultados.csv"


# =============================================================================
# Log
# =============================================================================

def log(level, msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    colors = {
        "OK":   f"{GREEN}[SEGURO]{RESET}",
        "VULN": f"{RED}[VULN]{RESET}",
        "INFO": f"{CYAN}[INFO]{RESET}",
        "WARN": f"{YELLOW}[AVISO]{RESET}",
        "ERR":  f"{RED}[ERRO]{RESET}",
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
# DNS — resolução reversa em batch paralelo
# =============================================================================

def _resolve_ptr_dnspython(ip: str) -> str:
    """Resolução PTR usando dnspython com timeout controlado."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = DNS_TIMEOUT
        rev = dns.reversename.from_address(ip)
        answer = resolver.resolve(rev, "PTR")
        return str(answer[0]).rstrip(".")
    except Exception:
        return "SEM-PTR"


def _resolve_ptr_socket(ip: str) -> str:
    """Fallback usando socket padrão do sistema."""
    try:
        import socket as _socket
        hostname, _, _ = _socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return "SEM-PTR"


@lru_cache(maxsize=65536)
def get_hostname(ip: str) -> str:
    """Resolve PTR de um IP com cache — evita consultas duplicadas."""
    if HAS_DNSPYTHON:
        return _resolve_ptr_dnspython(ip)
    return _resolve_ptr_socket(ip)


def resolve_hostnames_batch(ips: list[str]) -> dict[str, str]:
    """
    Resolve PTR de uma lista de IPs em paralelo com DNS_WORKERS threads.
    Retorna dict {ip: hostname}.
    """
    results: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=DNS_WORKERS) as executor:
        futures = {executor.submit(get_hostname, ip): ip for ip in ips}
        for future in as_completed(futures):
            ip = futures[future]
            results[ip] = future.result()
    return results


# =============================================================================
# Resolução de alvos (ASN / CIDR / IP)
# =============================================================================

def resolve_asn(asn: str) -> list[str]:
    """Resolve prefixos IPv4 originados por um ASN via RIPE Stat, com fallback para bgp.tools."""
    asn_number = asn.upper().lstrip("AS")

    log("INFO", f"Resolvendo {asn.upper()} via RIPE Stat (prefixos originados) ...")
    prefixes = resolve_asn_ripe(asn_number)

    if prefixes:
        log("INFO", f"{asn.upper()} — {len(prefixes)} prefixo(s) IPv4 originado(s) encontrado(s)")
        return prefixes

    log("WARN", f"RIPE Stat não retornou prefixos para {asn.upper()}. Tentando bgp.tools ...")
    url = f"https://bgp.tools/table.jsonl?asn={asn_number}"
    try:
        resp = requests.get(url, timeout=15, headers={"User-Agent": "nginx-scanner/1.0"})
        resp.raise_for_status()
        prefixes = []
        for line in resp.text.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                prefix = entry.get("CIDR") or entry.get("prefix") or entry.get("cidr")
                origin = str(entry.get("ASN") or entry.get("origin_asn") or entry.get("origin") or "")
                if prefix and ":" not in prefix and origin == asn_number:
                    prefixes.append(prefix)
            except Exception:
                try:
                    ipaddress.ip_network(line, strict=False)
                    if ":" not in line:
                        prefixes.append(line)
                except ValueError:
                    pass

        log("INFO", f"{asn.upper()} — {len(prefixes)} prefixo(s) IPv4 encontrado(s) via bgp.tools")
        return prefixes

    except Exception as e:
        log("ERR", f"bgp.tools também falhou para {asn.upper()}: {e}")
        return []


def resolve_asn_ripe(asn_number: str) -> list[str]:
    """Resolve prefixos IPv4 originados por um ASN via RIPE Stat API."""
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_number}"
    try:
        resp = requests.get(url, timeout=15, headers={"User-Agent": "nginx-scanner/1.0"})
        resp.raise_for_status()
        data = resp.json()
        prefixes = [
            p["prefix"] for p in data.get("data", {}).get("prefixes", [])
            if ":" not in p.get("prefix", ":")
        ]
        log("INFO", f"AS{asn_number} — {len(prefixes)} prefixo(s) originado(s) encontrado(s) via RIPE")
        return prefixes
    except Exception as e:
        log("ERR", f"RIPE Stat falhou para AS{asn_number}: {e}")
        return []


def expand_targets(ips=None, cidrs=None, asns=None, file=None) -> list[str]:
    """Resolve todas as fontes de entrada em uma lista deduplicada de CIDRs."""
    all_prefixes: list[str] = []

    if ips:
        for ip in ips:
            try:
                ipaddress.ip_address(ip)
                all_prefixes.append(f"{ip}/32")
            except ValueError:
                if "/" in ip:
                    log("WARN", f"'{ip}' parece um CIDR — use --cidr em vez de --ip  (ex: --cidr {ip})")
                else:
                    log("WARN", f"Endereço IP inválido ignorado: '{ip}'")

    if cidrs:
        for cidr in cidrs:
            try:
                ipaddress.ip_network(cidr, strict=False)
                all_prefixes.append(cidr)
            except ValueError:
                if "/" not in cidr:
                    log("WARN", f"'{cidr}' não tem prefixo — tente '{cidr}/24' ou use --ip para um IP único")
                else:
                    log("WARN", f"CIDR inválido ignorado: '{cidr}'")

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
                            log("WARN", f"CIDR inválido no arquivo ignorado: {entry}")
                    else:
                        try:
                            ipaddress.ip_address(entry)
                            all_prefixes.append(f"{entry}/32")
                        except ValueError:
                            log("WARN", f"Entrada inválida no arquivo ignorada: {entry}")
        except FileNotFoundError:
            log("ERR", f"Arquivo não encontrado: {file}")
            sys.exit(1)

    seen = set()
    unique = []
    for p in all_prefixes:
        if p not in seen:
            seen.add(p)
            unique.append(p)
    return unique


# =============================================================================
# Scanner HTTP/HTTPS
# =============================================================================

def get_nginx_version(ip: str, timeout: float = 2.0) -> str | None:
    """Sonda HTTP e HTTPS nas portas padrão. Retorna cabeçalho Server ou None."""
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
    Retorna (status, versão).
    status: True (vulnerável), False (seguro), 'Possibly' (versão oculta), 'Undetermined'
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


def scan_ip(ip: str, hostname: str, timeout: float) -> dict | None:
    """Sonda um IP e retorna resultado ou None se não houver Nginx."""
    server_header = get_nginx_version(ip, timeout)
    if server_header is None:
        return None
    is_vuln, ver = check_vulnerability(server_header)
    return {
        "ip":         ip,
        "hostname":   hostname,
        "server":     server_header,
        "vulnerable": is_vuln,
        "version":    ver,
    }


# =============================================================================
# CLI
# =============================================================================

def parse_args():
    parser = argparse.ArgumentParser(
        description=f"Nginx {CVE_ID} ({CVE_NAME}) — scanner de vulnerabilidade",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  %(prog)s --ip 93.184.216.34
  %(prog)s --cidr 10.0.0.0/24 192.168.1.0/24
  %(prog)s --asn AS15169
  %(prog)s --asn AS13335 AS15169 --cidr 10.0.0.0/8
  %(prog)s --file alvos.txt
  %(prog)s --cidr 10.0.0.0/8 --workers 100 --timeout 3
        """,
    )
    parser.add_argument("--ip",         nargs="+", metavar="IP",      help="Um ou mais IPs individuais")
    parser.add_argument("--cidr",       nargs="+", metavar="CIDR",    help="Uma ou mais faixas CIDR")
    parser.add_argument("--asn",        nargs="+", metavar="ASN",     help="Um ou mais ASNs (ex: AS15169 ou 15169)")
    parser.add_argument("--file",       metavar="ARQUIVO",            help="Arquivo com IPs, CIDRs e/ou ASNs (um por linha)")
    parser.add_argument("--workers",    type=int,   default=60,       help="Threads para scan HTTP (padrão: 60)")
    parser.add_argument("--dns-workers",type=int,   default=DNS_WORKERS, help=f"Threads para resolução DNS (padrão: {DNS_WORKERS})")
    parser.add_argument("--timeout",    type=float, default=2.0,      help="Timeout das requisições HTTP em segundos (padrão: 2.0)")
    parser.add_argument("--dns-timeout",type=float, default=DNS_TIMEOUT, help=f"Timeout das queries DNS em segundos (padrão: {DNS_TIMEOUT})")
    parser.add_argument("--no-confirm", action="store_true",          help="Pula confirmação antes de iniciar")
    return parser.parse_args()


def normalize_argv():
    """Normaliza flags para lowercase, tolerando --CIDR, --IP, --ASN etc."""
    normalized = []
    for arg in sys.argv[1:]:
        if arg.startswith("--") and not arg.startswith("--no"):
            normalized.append(arg.lower())
        else:
            normalized.append(arg)
    sys.argv[1:] = normalized


# =============================================================================
# Main
# =============================================================================

def main():
    normalize_argv()
    args = parse_args()

    if not any([args.ip, args.cidr, args.asn, args.file]):
        print(f"\n{RED}[ERR]{RESET} Nenhum alvo especificado.")
        print(f"\n  Use um ou mais dos argumentos abaixo:")
        print(f"    {CYAN}--ip{RESET}    <IP>         IP individual        ex: --ip 192.168.1.10")
        print(f"    {CYAN}--cidr{RESET}  <CIDR>       Faixa de rede        ex: --cidr 10.0.0.0/24")
        print(f"    {CYAN}--asn{RESET}   <ASN>        Sistema autônomo     ex: --asn AS15169")
        print(f"    {CYAN}--file{RESET}  <arquivo>    Arquivo com alvos    ex: --file alvos.txt")
        print(f"\n  Execute com {BOLD}--help{RESET} para ver todos os parâmetros.\n")
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

    if not HAS_DNSPYTHON:
        print(f"  {YELLOW}[AVISO]{RESET} dnspython não instalado — usando socket padrão para DNS (mais lento).")
        print(f"          Instale com: {CYAN}pip install dnspython{RESET}\n")

    # Resolve alvos
    prefixes = expand_targets(
        ips=args.ip,
        cidrs=args.cidr,
        asns=args.asn,
        file=args.file,
    )

    if not prefixes:
        print(f"\n{RED}[ERR]{RESET} Nenhum alvo válido encontrado após resolução.")
        print(f"\n  Verifique:")
        print(f"    - IPs devem ser passados com {CYAN}--ip{RESET}, não --cidr   ex: --ip 192.168.1.10")
        print(f"    - CIDRs devem incluir prefixo                    ex: --cidr 10.0.0.0{YELLOW}/24{RESET}")
        print(f"    - ASNs devem seguir o formato AS + número        ex: --asn {YELLOW}AS15169{RESET}")
        print(f"    - Arquivos devem ter uma entrada por linha       ex: --file alvos.txt\n")
        sys.exit(1)

    total_hosts = sum(
        ipaddress.ip_network(p, strict=False).num_addresses - (2 if ipaddress.ip_network(p, strict=False).prefixlen < 31 else 0)
        for p in prefixes
    )

    print(f" {BOLD}Alvos resolvidos:{RESET} {len(prefixes)} prefixo(s) / ~{total_hosts:,} host(s)\n")
    for p in prefixes:
        net = ipaddress.ip_network(p, strict=False)
        print(f"   {CYAN}•{RESET} {p:<20}  ({net.num_addresses} addr)")
    print()

    if not args.no_confirm:
        confirm = input(f" {BOLD}Iniciar varredura? [s/N]:{RESET} ").strip().lower()
        if confirm != "s":
            print(" Cancelado.")
            sys.exit(0)

    # Inicializa arquivos de saída
    with open(LOG_VULN, "w", encoding="utf-8") as f:
        f.write(f"# NGINX VULNERABLE — {CVE_ID} | {TIMESTAMP}\n")
        f.write(f"{'IP':<18} {'HOSTNAME':<40} {'VERSAO':<12} STATUS\n")
        f.write(f"{'='*18} {'='*40} {'='*12} {'='*25}\n")

    fieldnames = ["IP", "HOSTNAME", "VERSAO_NGINX", "STATUS_VULNERABILIDADE"]
    with open(LOG_CSV, "w", newline="", encoding="utf-8") as f:
        csv.DictWriter(f, fieldnames=fieldnames).writeheader()

    log("HEAD", "══════════════════════════════════════════════════════")
    log("INFO", f"Início:       {datetime.now()}")
    log("INFO", f"Prefixos:     {len(prefixes)}")
    log("INFO", f"Workers HTTP: {args.workers}")
    log("INFO", f"Workers DNS:  {args.dns_workers}")
    log("INFO", f"Timeout HTTP: {args.timeout}s")
    log("INFO", f"Timeout DNS:  {args.dns_timeout}s")
    log("INFO", f"Log:          {LOG_FILE}")
    log("INFO", f"CSV:          {LOG_CSV}")
    log("INFO", f"Backend DNS:  {'dnspython' if HAS_DNSPYTHON else 'socket (fallback)'}")
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
            log("WARN", f"Prefixo inválido ignorado: {prefix}")
            continue

        ips = [str(ip) for ip in network.hosts()] or [str(network.network_address)]
        log("HEAD", f"[ {prefix} ] — resolvendo DNS de {len(ips)} host(s) ...")

        # Fase 1 — resolução DNS em batch, antes do scan HTTP
        dns_map = resolve_hostnames_batch(ips)

        log("HEAD", f"[ {prefix} ] — escaneando {len(ips)} host(s) ...")

        # Fase 2 — scan HTTP paralelo, com hostname já resolvido
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {
                executor.submit(scan_ip, ip, dns_map.get(ip, "N/A"), args.timeout): ip
                for ip in ips
            }
            for future in as_completed(futures):
                res = future.result()
                if res is None:
                    continue

                count_total += 1
                ip       = res["ip"]
                hostname = res["hostname"]
                ver      = res["version"]
                is_vuln  = res["vulnerable"]
                info     = f"{ip:<15} | {hostname:<35} | Ver: {ver}"

                if is_vuln is True:
                    status = "VULNERÁVEL"
                    log("VULN", f"{info} → {status}")
                    with open(LOG_VULN, "a", encoding="utf-8") as f:
                        f.write(f"{ip:<18} {hostname:<40} {ver:<12} {status}\n")
                    count_vuln += 1
                elif is_vuln == "Possibly":
                    status = "AVISO (Versão Oculta)"
                    log("WARN", f"{info} → {status}")
                    count_warn += 1
                elif is_vuln == "Undetermined":
                    status = "INDETERMINADO"
                    log("WARN", f"{info} → {status}")
                    count_warn += 1
                else:
                    status = "SEGURO"
                    log("OK", f"{info} → {status}")
                    count_safe += 1

                with open(LOG_CSV, "a", newline="", encoding="utf-8") as f:
                    csv.DictWriter(f, fieldnames=fieldnames).writerow({
                        "IP":                    ip,
                        "HOSTNAME":              hostname,
                        "VERSAO_NGINX":          ver,
                        "STATUS_VULNERABILIDADE": status,
                    })

    elapsed = int(time.time() - start_time)
    log("HEAD", "══════════════════════════════════════════════════════")
    log("INFO", f"Fim:             {datetime.now()}")
    log("INFO", f"Tempo total:     {elapsed}s")
    log("INFO", f"Hosts Nginx:     {count_total}")
    log("INFO", f"Vulneráveis:     {count_vuln}")
    log("INFO", f"Avisos:          {count_warn}")
    log("INFO", f"Seguros:         {count_safe}")
    log("INFO", f"Log completo:    {LOG_FILE}")
    log("INFO", f"Lista vulneráv.: {LOG_VULN}")
    log("INFO", f"Resultados CSV:  {LOG_CSV}")
    log("HEAD", "══════════════════════════════════════════════════════")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n Interrompido.")
        sys.exit(0)
