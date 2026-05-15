<img width="719" height="191" alt="image" src="https://github.com/user-attachments/assets/51cc8913-dd14-4b52-a2e7-cef2051d0b97" />

Scanner para detecção de instâncias Nginx vulneráveis ao **CVE-2026-42945 (NGINX RIFT)**.  
Aceita IPs individuais, faixas CIDR e ASNs como entrada.


## Sobre

O CVE-2026-42945 afeta todas as versões do Nginx anteriores à **1.30.1**.  
A ferramenta sonda HTTP e HTTPS nas portas padrão, lê o cabeçalho `Server` da resposta e classifica cada host como vulnerável, seguro ou potencialmente afetado (versão oculta).

Os resultados são salvos em um log com timestamp, uma lista de hosts vulneráveis e um CSV para processamento posterior.


## Requisitos

```bash
pip install requests packaging urllib3
```

## Uso

```bash
# IP individual
python nginx_scanner.py --ip 93.184.216.34

# Faixa CIDR
python nginx_scanner.py --cidr 10.0.0.0/24

# Múltiplos CIDRs
python nginx_scanner.py --cidr 10.0.0.0/24 192.168.1.0/24

# ASN (prefixes resolvidos automaticamente via bgp.tools / RIPE)
python nginx_scanner.py --asn AS15169

# Combinação de entradas
python nginx_scanner.py --asn AS13335 --cidr 10.0.0.0/8 --ip 1.2.3.4

# A partir de um arquivo (um IP, CIDR ou ASN por linha)
python nginx_scanner.py --file alvos.txt
```

### Parâmetros opcionais

| Parâmetro | Padrão | Descrição |
|-----------|--------|-----------|
| `--workers` | 60 | Número de threads simultâneas |
| `--timeout` | 2.0 | Timeout das requisições HTTP em segundos |
| `--no-confirm` | — | Pula a confirmação antes de iniciar (útil em automações) |

## Saída

Todos os resultados são gravados em `./logs/`:

| Arquivo | Conteúdo |
|---------|----------|
| `nginx_scan_<timestamp>.log` | Log completo da varredura |
| `nginx_scan_<timestamp>_vulnerable.txt` | Apenas hosts vulneráveis |
| `nginx_scan_<timestamp>_results.csv` | Todos os hosts com status |

### Valores de status

| Status | Significado |
|--------|-------------|
| `VULNERÁVEL` | Versão confirmada abaixo de 1.30.1 |
| `SEGURO` | Versão confirmada em 1.30.1 ou superior |
| `AVISO (Versão Oculta)` | Nginx detectado mas versão não exposta — não confirmado seguro |
| `INDETERMINADO` | Versão não pôde ser interpretada |

## Remediação

Atualize o Nginx para a versão **1.30.1 ou superior** usando o repositório oficial do nginx.org.

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

Para outras distribuições, consulte a [documentação oficial do Nginx](https://nginx.org/en/linux_packages.html).

## Referências

- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-42945
- Changelog do Nginx: https://nginx.org/en/CHANGES

---

## Aviso Legal

Esta ferramenta é destinada ao uso em infraestrutura própria ou sob autorização explícita.  
A varredura não autorizada pode violar legislações aplicáveis.
