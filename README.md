# Authorized External Recon Framework

A menu-driven Python 3 framework for the **identification-only** phases of an authorized external penetration test. It inventories open services, fingerprints web/TLS exposure, performs conservative content discovery, correlates versions with offline Exploit-DB data, runs tightly filtered Nuclei checks, and generates an offline HTML report with evidence and exact recheck commands.

## Safety model

Every execution starts with an unavoidable authorization gate. The operator must type:

```text
I CONFIRM AUTHORIZATION
```

No flag or config value bypasses it. The framework does not launch exploits, brute-force credentials, deliver payloads, modify target-side data, run Nmap `vuln`/`exploit`/`dos` categories, or enable Nuclei fuzz/DAST. Nmap defaults to `-T3 --max-retries 2 --host-timeout 15m`; T4 requires a second literal confirmation and T5 is unsupported.

Nuclei is constrained to identification-oriented tags and explicitly excludes DoS, fuzzing, intrusive/exploit, brute-force/default-login/auth-bypass, RCE/command injection, SQLi, SSRF, LFI/RFI, and file-upload tags. OAST/Interactsh is disabled. Non-HTTP Nuclei probing is **off by default** because protocol templates can be more active than simple HTTP/TLS identification.

Web discovery defaults to 20 threads, a configurable delay/rate limit, chunked wordlists, and adaptive backoff. After each chunk the framework checks response error rates and target latency. If the target degrades, it halves threads and increases delay for subsequent chunks.

CIDRs are accepted but expanded into per-host scans and capped at 256 hosts by default. This keeps report structure predictable and avoids accidentally turning a single command into an unbounded sweep.

## Setup

Recommended on Kali/Debian:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 main.py
```

On first launch, **after** the authorization confirmation, the framework runs a dependency health check and attempts to install missing tools with `apt`, Homebrew, or safe user-local installers where practical. It prints exact manual commands when automatic installation is not reliable.

Dependencies checked:

- nmap
- gobuster and/or feroxbuster
- EyeWitness
- WhatWeb
- Nikto
- testssl.sh, with sslscan/sslyze fallback
- Nuclei, including a first-run template update
- Searchsploit / Exploit-DB
- SecLists
- Python: rich, python-nmap, Jinja2, pandas

## Usage

Run:

```bash
python3 main.py
```

The launch menu is intentionally limited to:

```text
[1] Enter a single target (domain or IP)
[2] Load a list of targets from file (IPs/domains, one per line)
[3] Install / verify dependencies & run environment health check
```

For scans, choose one Nmap profile:

```text
[1] Top 100 ports   (--top-ports 100)
[2] Top 1000 ports  (default nmap behavior)
[3] Full port range (-p-)
```

You can also choose raft-small, raft-medium, or raft-large for web content discovery. The medium list is the default.

## Output

Each validated host receives:

```text
output/<target>/
  nmap/           raw .nmap/.xml/.gnmap + nmap_results.csv
  web/            fingerprints, content-discovery CSV, Nikto CSVs, screenshots
  tls/            tls_results.csv + raw TLS scanner output
  vuln/           per-port CSVs + evidence.json + safe NSE/Searchsploit/Nuclei raw output
  logs/           commands.log + errors.log
  report.html     self-contained offline report (screenshots embedded)
```

`logs/commands.log` is JSON Lines. Every subprocess command records the full command, timestamp, exit code, and duration. Internal HTTP health probes/adaptive-throttle events are logged there too so the audit trail explains rate changes.

## Configuration

Edit `config.json` to change thread counts, delay, adaptive-backoff thresholds, Nuclei rate limits, CIDR safety cap, report behavior, and wordlist paths. `T5` is rejected. Setting `nmap_timing` to `T4` still requires the literal runtime confirmation `I UNDERSTAND T4 RISK`.

The safest default is to leave `nuclei.scan_non_http_services` set to `false`.

## Notes on findings

Searchsploit results are reported as **unverified version correlations** with informational severity unless another detector supplies stronger evidence. A public Exploit-DB entry does not prove the target is vulnerable. The report preserves manual recheck commands and evidence snippets so the tester can validate each result without auto-exploitation.

TLS grades in the HTML report are a simple local summary based on the highest TLS finding severity. They are explicitly labeled as heuristic and are not SSL Labs grades.

See `WORDLISTS.md` for SecLists locations and manual installation.
