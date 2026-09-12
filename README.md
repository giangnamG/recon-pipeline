# recon-pipeline

A complete automated recon pipeline for penetration testing.

## Pipeline

| Step | Script | Description |
|------|--------|-------------|
| 01 | 01_subdomain.sh | Passive (subfinder/amass/crt.sh) + Active (gobuster) subdomain enumeration |
| 02 | 02_resolve.sh | DNS resolution with puredns wildcard filter + dnsx |
| 03 | 03_cdncheck.sh | CDN/WAF/Cloud IP classification |
| 04 | 04_vhost.sh | Virtual host discovery (curl/ffuf/SNItch/ripgen) |
| 05 | 05_portscan.sh | Port scanning with naabu (fallback: nmap) |
| 06 | 06_service.sh | Service detection with nmap -sV -sC + CDN banner filter |
| 07 | 07_httpx.sh | HTTP probing with tech detection |
| 08 | 08_triage.sh | Target tiering + JS endpoint extraction + secret scanning |

## Usage

```bash
# Full run
./recon.sh <domain>

# Resume from a specific step
./recon.sh <domain> --from 05

# Run only one step
./recon.sh <domain> --only 07
```

## Output Structure

```
output/<domain>/
├── subdomains.txt
├── resolved.txt / unresolved.txt / all_ips.txt
├── origin_ips.txt / cdn_ips.txt
├── vhosts/
├── ports/
├── services/
├── http/
├── triage/report.md
└── logs/
```

## Requirements

- dnsx, subfinder, amass, gobuster
- cdncheck, naabu, httpx
- nmap, ffuf
- puredns (optional), SNItch (optional), ripgen (optional), katana (optional)
