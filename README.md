<img width="719" height="191" alt="image" src="https://github.com/user-attachments/assets/51cc8913-dd14-4b52-a2e7-cef2051d0b97" />

Scanner para detecção de instâncias Nginx vulneráveis ao **CVE-2026-42945 (NGINX RIFT)**.  
Aceita IPs individuais, faixas CIDR e ASNs como entrada.

## Sobre

O CVE-2026-42945 afeta todas as versões do Nginx anteriores à **1.30.1**.  

A ferramenta sonda HTTP e HTTPS nas portas padrão, faz a leitura do cabeçalho `Server` da resposta e classifica cada host como vulnerável, seguro ou potencialmente afetado (versão oculta).

Os resultados são salvos em log, com uma lista dos hosts vulneráveis à CVE e ao final um arquivo .CSV detalhado.

## Requisitos

```bash
pip install requests packaging urllib3 dnspython
```

## Utilização

```bash
# IP individual
python nginx_scanner.py --ip 93.184.216.34

# Faixa CIDR
python nginx_scanner.py --cidr 10.0.0.0/24

# Múltiplos CIDRs
python nginx_scanner.py --cidr 10.0.0.0/24 192.168.1.0/24

# ASN (prefixos originados resolvidos via RIPE Stat, fallback para bgp.tools)
python nginx_scanner.py --asn AS15169

# Combinação de entradas
python nginx_scanner.py --asn AS13335 --cidr 10.0.0.0/8 --ip 1.2.3.4

# A partir de um arquivo (um IP, CIDR ou ASN por linha)
python nginx_scanner.py --file alvos.txt
```

Exemplo de SCAN IP:

<img width="979" height="780" alt="image" src="https://github.com/user-attachments/assets/4eb0254a-732c-405f-b14f-0860ee2f848e" />

Exemplo de SCAN CIDR:

<img width="1035" height="871" alt="image" src="https://github.com/user-attachments/assets/4a36ef8f-b940-4837-85f6-3f1213c8af4e" />

Exemplo de SCAN ASN:

<img width="822" height="582" alt="image" src="https://github.com/user-attachments/assets/4550e199-287e-49b8-ba72-f520ebf18f6d" />

### Parâmetros opcionais

| Parâmetro | Padrão | Descrição |
|-----------|--------|-----------|
| `--workers` | 60 | Número de threads simultâneas para o scan HTTP |
| `--timeout` | 2.0 | Timeout das requisições HTTP em segundos |
| `--dns-workers` | 200 | Número de threads simultâneas para resolução DNS reversa |
| `--dns-timeout` | 1.5 | Timeout das queries DNS em segundos |
| `--no-confirm` | — | Pula a confirmação antes de iniciar (útil em automações) |

> A resolução DNS é executada em lote antes do scan HTTP, usando uma fila dedicada de threads (`--dns-workers`), evitando que a latência do DNS impacte no desempenho da varredura.

## Saída

Todos os resultados são gravados em `./logs/`:

| Arquivo | Conteúdo |
|---------|----------|
| `nginx_scan_<timestamp>.log` | Log completo da varredura |
| `nginx_scan_<timestamp>_vulneraveis.txt` | Apenas hosts vulneráveis |
| `nginx_scan_<timestamp>_resultados.csv` | Todos os hosts com status |

### Valores de status

| Status | Significado |
|--------|-------------|
| `VULNERÁVEL` | Versão confirmada abaixo de 1.30.1 |
| `SEGURO` | Versão confirmada em 1.30.1 ou superior |
| `AVISO (Versão Oculta)` | Nginx detectado mas versão não exposta — não confirmado seguro |
| `INDETERMINADO` | Versão não pôde ser interpretada |

---

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

## Se Liga

Este script é destinado ao uso em sua própria infraestrutura ou sob autorização explícita.  
A varredura não autorizada pode violar diversas legislações, então use com cautela.

No mais, se tiver alguma sugestão de melhoria das funcionalidades ou bugs, fique à vontade para abrir uma issue e me enviar um Pull Request.

Toda contribuição é bem-vinda ! 🚀🚀
