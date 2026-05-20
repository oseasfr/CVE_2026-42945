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
