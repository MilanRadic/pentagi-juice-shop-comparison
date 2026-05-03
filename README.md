# PentAGI vs OWASP ZAP — Juice Shop pentest comparison

Magistrska naloga (Milan Krka) — primerjava avtomatiziranih penetracijskih testov **OWASP Juice Shop** s tradicionalnim DAST orodjem (OWASP ZAP) ter dvema LLM-driven agentnima sistemoma (PentAGI z OpenAI GPT-5 in Google Gemini 2.5 Flash).

> ⚠️ **Cilj testiranja:** namerno ranljiva spletna aplikacija OWASP Juice Shop (`v17.1.1`) na lastnem VPS-u. Vsi pravi IP-ji in hostnames so v repu **maskirani** (`<TARGET_IP>`, `<TARGET_HOSTNAME>`).

---

## Cilji primerjave

1. Kakšna je **pokritost** (število različnih ranljivosti) vsakega pristopa?
2. Kako se odzivajo na **multi-step** scenariji (npr. dostop do `/ftp/` → KeePass DB → hash extraction)?
3. Kakšna je **kakovost poročanja** (Markdown reporti, evidence, recommendations)?
4. Kakšen je **stroški/čas** posameznega scana?

## Setup

| Komponenta | Različica | Vloga |
|---|---|---|
| OWASP Juice Shop | v17.1.1 | tarča (port 80) |
| OWASP ZAP | (Docker) | DAST baseline scan |
| PentAGI | latest (vxcontrol/pentagi) | LLM agent orchestrator (port 8080) |
| OpenAI GPT-5 | gpt-5 | LLM #1 |
| Google Gemini | gemini-2.5-flash | LLM #2 |
| Ollama Llama 3.1 8B | llama3.1:8b | LLM #3 (early test, brez ohranjenih artefaktov) |

---

## Struktura repoja

```
pentagi-juice-shop-comparison/
├── owasp-zap/                                              # 6 datotek (3 runs × HTML+XML)
│   ├── ZAP_Run1.html / .xml
│   ├── ZAP_Run2.html / .xml
│   └── ZAP_Run3.html / .xml
├── pentagi-openai-gpt5/
│   ├── scan-1-juice-shop-pentest-terminal-51/             # 13.2.2026 21:58
│   │   ├── scans/                                          # nmap (XML + .nmap)
│   │   ├── evidence/TARGET_IP/go-mgmt/{8080,11434}/       # endpoint enumeration
│   │   ├── baseline/TARGET_IP/{80,8080,11434}/            # recon
│   │   └── local-baseline-and-reports/                     # mirror iz /root/pentagi-work/
│   └── scan-2-full-assessment-terminal-52/                # 14.2.2026 09:40
│       └── reports/TARGET_IP/
│           ├── full_vulnerability_report.md  ⭐
│           ├── README.md
│           ├── scans/                                      # tcp_conservative_*
│           ├── evidence/{,confirmed/,auth/,assets/}/
│           ├── notes/{findings_overview.md, auth_summary.md, ...}
│           └── logs/{http_requests.log (514 req), reconcile_*}/
└── pentagi-gemini-2.5-flash/
    └── scan-3-assess-security-terminal-58/                # 14.3.2026 13:18
        └── reports/TARGET_IP_gemini/
            ├── full_vulnerability_report.md  ⭐
            ├── parse_nmap.py
            └── evidence/
                ├── nmap_scan_results.nmap
                ├── nikto_port_{80,8080}.txt
                ├── gobuster_port_{80,8080}_*.txt
                ├── ftp_directory_listing_port_80.txt       (👈 IDOR find)
                ├── incident_support_kdbx_port_80.kdbx      (👈 KeePass DB exfil)
                ├── keepass_hash.txt                        (keepass2john output)
                └── lfi_etc_passwd_attempt_port_80.txt
```

---

## Hitri povzetki za Claude (priporočene first-fetch datoteke)

Če te datoteke prebereš, dobiš celotno sliko v ~2 minutah:

- **OWASP ZAP alerts (XML)** — strojno berljivi alerti, vsi 3 teki dajo skoraj identične rezultate:
  - [`owasp-zap/ZAP_Run1.xml`](./owasp-zap/ZAP_Run1.xml)

- **OpenAI GPT-5 — Scan #2 — full vulnerability report** (najbolj strukturiran):
  - [`pentagi-openai-gpt5/scan-2-full-assessment-terminal-52/reports/TARGET_IP/full_vulnerability_report.md`](./pentagi-openai-gpt5/scan-2-full-assessment-terminal-52/reports/TARGET_IP/full_vulnerability_report.md)
  - [`.../notes/findings_overview.md`](./pentagi-openai-gpt5/scan-2-full-assessment-terminal-52/reports/TARGET_IP/notes/findings_overview.md)

- **Google Gemini 2.5 Flash — Scan #3 — full vulnerability report** (najbolj impactful, IDOR + KeePass exfil):
  - [`pentagi-gemini-2.5-flash/scan-3-assess-security-terminal-58/reports/TARGET_IP_gemini/full_vulnerability_report.md`](./pentagi-gemini-2.5-flash/scan-3-assess-security-terminal-58/reports/TARGET_IP_gemini/full_vulnerability_report.md)

---

## Findings comparison (high-level)

| Finding | OWASP ZAP | OpenAI GPT-5 | Gemini 2.5 Flash |
|---|:-:|:-:|:-:|
| Backup File Disclosure (CWE-530) | ✅ count=31 | — | partial |
| CORS Misconfiguration (CWE-942) | ✅ | ✅ | ✅ |
| CSP / X-Frame / HSTS Headers Missing | ✅ | ✅ | ✅ |
| HTTP-only (no HTTPS) | ✅ | ✅ | ✅ |
| Cross-Domain JS Inclusion | ✅ | — | — |
| Exposed `/debug/vars`, `/debug/pprof`, `/metrics` (PentAGI :8080) | — | ✅ | — |
| Insecure session/token (Bearer in localStorage) | — | ✅ | — |
| **IDOR → `/ftp/` directory listing → KeePass DB exfiltration** ⭐ | — | — | ✅ **(critical)** |
| LFI poskus `/jqueryFileTree.php?root=/etc/` | — | — | ✅ (failed/patched) |

**Kratko opažanje:** ZAP pokaže največ low-level header/cookie alertov; GPT-5 najbolje izkoristi PentAGI lasten container (debug endpoints); Gemini najbolj “human-like” pokaže multi-step exfiltration verigo (robots.txt → /ftp/ → kdbx → keepass2john).

---

## Metodologija (kratko)

1. **OWASP ZAP** — baseline scan prek Docker (`zaproxy/zap-stable`), 3 teki za ponovljivost.
2. **PentAGI** — vsak LLM scan se izvaja v izoliranem `vxcontrol/kali-linux` containerju, ki ima dovoljene non-destructive tools (`nmap`, `nikto`, `gobuster`, `curl`, `keepass2john`, ipd.). Rate limit ≤3 rps.
3. **Mapiranje** flow → LLM provider: PentAGI Postgres baza, tabela `flows` (stolpci `model_provider_name`, `model`).

## Licenca / opozorilo

Repo vsebuje samo izhode iz testiranja **lastne** ranljive instance OWASP Juice Shop. KeePass DB (`incident_support_kdbx_port_80.kdbx`) je javno znan CTF artefakt iz Juice Shop challenge "Reset Bjoern's Password (Standard)". Ne uporabljaj teh tehnik proti tujim sistemom brez avtorizacije.
