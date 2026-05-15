# CVE_2026-42945

Scanner for detecting Nginx instances vulnerable to **CVE-2026-42945 (NGINX RIFT)**.  
Accepts individual IPs, CIDR ranges, and ASNs as input.

---

## About

CVE-2026-42945 affects all Nginx versions prior to **1.30.1**.  
This tool probes HTTP and HTTPS on standard ports, reads the `Server` response header, and classifies each host as vulnerable, safe, or potentially affected (hidden version).

Results are saved to a timestamped log, a plain-text list of vulnerable hosts, and a CSV file for further processing.

---

## Requirements

```bash
pip install requests packaging urllib3
```

---

## Usage

```bash
# Single IP
python nginx_scanner.py --ip 93.184.216.34

# CIDR range
python nginx_scanner.py --cidr 10.0.0.0/24

# Multiple CIDRs
python nginx_scanner.py --cidr 10.0.0.0/24 192.168.1.0/24

# ASN (prefixes resolved automatically via bgp.tools / RIPE)
python nginx_scanner.py --asn AS15169

# Mix of inputs
python nginx_scanner.py --asn AS13335 --cidr 10.0.0.0/8 --ip 1.2.3.4

# From a file (one IP, CIDR, or ASN per line)
python nginx_scanner.py --file targets.txt
```

### Optional flags

| Flag | Default | Description |
|------|---------|-------------|
| `--workers` | 60 | Number of concurrent threads |
| `--timeout` | 2.0 | HTTP request timeout in seconds |
| `--no-confirm` | — | Skip confirmation prompt (useful for automation) |

---

## Output

All results are written to `./logs/`:

| File | Content |
|------|---------|
| `nginx_scan_<timestamp>.log` | Full scan log |
| `nginx_scan_<timestamp>_vulnerable.txt` | Vulnerable hosts only |
| `nginx_scan_<timestamp>_results.csv` | All hosts with status |

### Status values

| Status | Meaning |
|--------|---------|
| `VULNERABLE` | Version confirmed below 1.30.1 |
| `SAFE` | Version confirmed at 1.30.1 or above |
| `WARNING (Hidden Version)` | Nginx detected but version not exposed — not confirmed safe |
| `UNDETERMINED` | Version string could not be parsed |

---

## Remediation

Update Nginx to **1.30.1 or later** using the official nginx.org repository for your distribution.

```bash
# Ubuntu / Debian
curl https://nginx.org/keys/nginx_signing.key | gpg --dearmor \
  | tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null

echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
http://nginx.org/packages/mainline/ubuntu $(lsb_release -cs) nginx" \
  | tee /etc/apt/sources.list.d/nginx.list

echo -e "Package: *\nPin: origin nginx.org\nPin-Priority: 900" \
  | tee /etc/apt/preferences.d/99nginx

apt update && apt install --only-upgrade nginx
nginx -v
```

For other distributions, refer to the [official Nginx install docs](https://nginx.org/en/linux_packages.html).

---

## References

- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-42945
- Nginx changelog: https://nginx.org/en/CHANGES

---

## Disclaimer

This tool is intended for use on infrastructure you own or have explicit authorization to scan.  
Unauthorized scanning may violate applicable laws.
