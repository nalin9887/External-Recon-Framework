from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from .models import Finding, ServiceRecord
from .nmap_phase import is_http_service, is_tls_service
from .utils import CommandRunner, display_command, format_host_for_url, save_json, which_any, write_csv


FINDING_FIELDS = [
    "port",
    "service",
    "version",
    "possible_cve",
    "severity",
    "source",
    "manual_recheck_command",
]
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
SAFE_TEMPLATE_CONDITION = "!(contains(http_method,'POST') || contains(http_method,'PUT') || contains(http_method,'PATCH') || contains(http_method,'DELETE') || contains(http_method,'CONNECT'))"


def _service_version(service: ServiceRecord) -> str:
    return " ".join(x for x in [service.product, service.version] if x).strip() or service.service


def _reference_for(identifier: str) -> str:
    upper = identifier.upper()
    if upper.startswith("CVE-"):
        return f"https://nvd.nist.gov/vuln/detail/{upper}"
    if upper.startswith("EDB-"):
        edb = upper.removeprefix("EDB-")
        if edb.isdigit():
            return f"https://www.exploit-db.com/exploits/{edb}"
    return ""


def _run_safe_nse(
    target: str,
    services: list[ServiceRecord],
    target_dir: Path,
    runner: CommandRunner,
    config: dict[str, Any],
    timing: str,
    nmap_bin: str,
) -> None:
    non_web = sorted({s.port for s in services if not is_http_service(s)})
    if not non_web:
        return
    safety = config.get("safety", {})
    output_base = target_dir / "vuln" / "safe_nse"
    cmd = [
        nmap_bin,
        "-sV",
        "--open",
        "--script", "default,safe,version",
        f"-{timing}",
        "--max-retries", str(int(safety.get("max_retries", 2))),
        "--host-timeout", str(safety.get("host_timeout", "15m")),
        "-p", ",".join(str(p) for p in non_web),
        "-oA", str(output_base),
        target,
    ]
    # No 'vuln', 'exploit', 'dos', 'brute', or auth-guessing NSE categories are used.
    runner.run(cmd, timeout=20 * 60, phase="Safe NSE service validation")


def _parse_searchsploit_json(text: str) -> list[dict[str, str]]:
    try:
        data = json.loads(text)
    except Exception:
        return []
    rows: list[dict[str, str]] = []
    if not isinstance(data, dict):
        return rows
    for key in ("RESULTS_EXPLOIT", "RESULTS_SHELLCODE"):
        for item in data.get(key, []) or []:
            if not isinstance(item, dict):
                continue
            rows.append({
                "title": str(item.get("Title") or item.get("title") or ""),
                "edb_id": str(item.get("EDB-ID") or item.get("EDB_ID") or item.get("id") or ""),
                "codes": str(item.get("Codes") or item.get("codes") or ""),
            })
    return rows


def _searchsploit_findings(
    services: list[ServiceRecord],
    target_dir: Path,
    runner: CommandRunner,
) -> list[Finding]:
    tool = which_any(["searchsploit"])
    findings: list[Finding] = []
    if not tool:
        runner.log_error("searchsploit not installed; offline exploit/CVE correlation skipped")
        return findings

    nmap_xmls = sorted((target_dir / "nmap").glob("*_scan.xml"))
    if nmap_xmls:
        runner.run(
            [tool, "--nmap", str(nmap_xmls[0])],
            timeout=5 * 60,
            stdout_path=target_dir / "vuln" / "searchsploit_nmap.txt",
            phase="Searchsploit Nmap correlation",
        )

    for service in services:
        query = _service_version(service)
        # Avoid useless generic lookups that create noisy false positives.
        if not service.product and not service.version:
            continue
        result = runner.run([tool, "--json", query], timeout=90, phase=f"Searchsploit port {service.port}")
        if result.returncode != 0:
            continue
        for item in _parse_searchsploit_json(result.stdout):
            identifiers = [m.upper() for m in CVE_RE.findall(item["codes"] + " " + item["title"])]
            if not identifiers and item["edb_id"].isdigit():
                identifiers = [f"EDB-{item['edb_id']}"]
            for identifier in identifiers[:10]:
                manual = display_command([tool, "--json", query])
                findings.append(
                    Finding(
                        port=service.port,
                        service=service.service,
                        version=query,
                        possible_cve=identifier,
                        severity="info",
                        source="searchsploit correlation (unverified)",
                        manual_recheck_command=manual,
                        evidence=item["title"][:1000],
                        reference_url=_reference_for(identifier),
                    )
                )
    return findings


def _nuclei_target(service: ServiceRecord) -> str:
    host = format_host_for_url(service.host)
    if is_http_service(service):
        scheme = "https" if is_tls_service(service) or service.port in {443, 8443} else "http"
        if (scheme == "http" and service.port == 80) or (scheme == "https" and service.port == 443):
            return f"{scheme}://{host}/"
        return f"{scheme}://{host}:{service.port}/"
    return f"{host}:{service.port}"


def _safe_nuclei_base(tool: str, config: dict[str, Any]) -> list[str]:
    cfg = config.get("nuclei", {})
    tags = ",".join(str(x) for x in cfg.get("tags", []))
    exclude_tags = ",".join(str(x) for x in cfg.get("exclude_tags", []))
    exclude_types = ",".join(str(x) for x in cfg.get("exclude_types", []))
    cmd = [
        tool,
        "-duc",  # do not update templates implicitly during a target scan
        "-ni",   # no Interactsh / OAST callbacks
        "-tags", tags,
        "-etags", exclude_tags,
        "-ept", exclude_types,
        "-tc", SAFE_TEMPLATE_CONDITION,
        "-rl", str(int(cfg.get("rate_limit", 10))),
        "-c", str(int(cfg.get("concurrency", 5))),
        "-bs", str(int(cfg.get("bulk_size", 5))),
        "-timeout", str(int(cfg.get("timeout_seconds", 8))),
        "-retries", str(int(cfg.get("retries", 0))),
        "-silent",
    ]
    return cmd


def _sanitized_response_headers(raw_response: str, limit: int = 1000) -> str:
    if not raw_response:
        return ""
    header_block = raw_response.split("\r\n\r\n", 1)[0].split("\n\n", 1)[0]
    redacted: list[str] = []
    sensitive = {"authorization", "proxy-authorization", "cookie", "set-cookie"}
    for line in header_block.splitlines():
        if ":" in line:
            name = line.split(":", 1)[0].strip().lower()
            if name in sensitive:
                redacted.append(f"{line.split(':', 1)[0]}: [REDACTED]")
                continue
        redacted.append(line)
    return "\n".join(redacted)[:limit]


def _parse_nuclei_jsonl(
    path: Path,
    service: ServiceRecord,
    manual_base: list[str],
) -> list[Finding]:
    findings: list[Finding] = []
    if not path.exists():
        return findings
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except Exception:
            continue
        info = item.get("info") if isinstance(item.get("info"), dict) else {}
        template_id = str(item.get("template-id") or item.get("template_id") or "")
        name = str(info.get("name") or template_id or "Nuclei finding")
        severity = str(info.get("severity") or "info").lower()
        matched_at = str(item.get("matched-at") or item.get("matched_at") or "")
        extracted = item.get("extracted-results") or item.get("extracted_results") or []
        if not isinstance(extracted, list):
            extracted = [str(extracted)]
        evidence = f"{name}; matched_at={matched_at}"
        if extracted:
            evidence += "; extracted=" + ", ".join(str(x) for x in extracted[:10])
        response_headers = _sanitized_response_headers(str(item.get("response") or ""))
        if response_headers:
            evidence += "\nResponse header evidence:\n" + response_headers
        identifiers = [x.upper() for x in CVE_RE.findall(template_id + " " + name)]
        identifier = identifiers[0] if identifiers else template_id or name
        manual = display_command([*manual_base, "-id", template_id]) if template_id else display_command(manual_base)
        findings.append(
            Finding(
                port=service.port,
                service=service.service,
                version=_service_version(service),
                possible_cve=identifier,
                severity=severity if severity in {"critical", "high", "medium", "low", "info"} else "info",
                source=f"nuclei:{template_id or 'template'}",
                manual_recheck_command=manual,
                evidence=evidence[:1500],
                reference_url=_reference_for(identifier),
            )
        )
    return findings


def _nuclei_findings(
    services: list[ServiceRecord],
    target_dir: Path,
    runner: CommandRunner,
    config: dict[str, Any],
) -> list[Finding]:
    tool = which_any(["nuclei"])
    findings: list[Finding] = []
    if not tool:
        runner.log_error("nuclei not installed; non-intrusive template checks skipped")
        return findings

    scan_non_http = bool(config.get("nuclei", {}).get("scan_non_http_services", False))
    raw_dir = target_dir / "vuln" / "nuclei_raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    for service in services:
        if not is_http_service(service) and not (scan_non_http and is_tls_service(service)):
            continue
        target = _nuclei_target(service)
        out = raw_dir / f"{service.port}.jsonl"
        base = [*_safe_nuclei_base(tool, config), "-u", target]
        cmd = [*base, "-j", "-o", str(out)]
        result = runner.run(cmd, timeout=20 * 60, phase=f"Nuclei non-intrusive checks port {service.port}")
        if result.returncode not in {0, 1}:
            runner.log_error(f"Nuclei returned {result.returncode} on port {service.port}; partial output retained")
        findings.extend(_parse_nuclei_jsonl(out, service, base))
    return findings


def _tls_cve_findings(
    services: list[ServiceRecord],
    tls_rows: list[dict[str, str | int]],
) -> list[Finding]:
    by_port = {s.port: s for s in services}
    findings: list[Finding] = []
    testssl = which_any(["testssl.sh", "testssl"])
    for row in tls_rows:
        cves = [m.upper() for m in CVE_RE.findall(str(row.get("cve", "")) + " " + str(row.get("finding", "")))]
        if not cves:
            continue
        port = int(row.get("port") or 0)
        service = by_port.get(port)
        if not service:
            continue
        target = f"{format_host_for_url(service.host)}:{port}"
        manual = display_command([testssl, "--quiet", "--ids-friendly", target]) if testssl else f"Re-run TLS scanner against {target}"
        severity = str(row.get("severity") or "info").lower()
        for cve in cves:
            findings.append(
                Finding(
                    port=port,
                    service=service.service,
                    version=_service_version(service),
                    possible_cve=cve,
                    severity=severity if severity in {"critical", "high", "medium", "low", "info"} else "info",
                    source="testssl.sh detection",
                    manual_recheck_command=manual,
                    evidence=str(row.get("finding", ""))[:1500],
                    reference_url=_reference_for(cve),
                )
            )
    return findings


def run_vuln_phase(
    target: str,
    services: list[ServiceRecord],
    tls_rows: list[dict[str, str | int]],
    target_dir: Path,
    runner: CommandRunner,
    config: dict[str, Any],
    timing: str,
    nmap_bin: str,
) -> list[Finding]:
    vuln_dir = target_dir / "vuln"
    vuln_dir.mkdir(parents=True, exist_ok=True)
    try:
        _run_safe_nse(target, services, target_dir, runner, config, timing, nmap_bin)
    except KeyboardInterrupt:
        raise
    except Exception as exc:
        runner.log_error(f"safe NSE phase failed: {exc!r}")

    findings: list[Finding] = []
    for producer in (
        lambda: _searchsploit_findings(services, target_dir, runner),
        lambda: _nuclei_findings(services, target_dir, runner, config),
        lambda: _tls_cve_findings(services, tls_rows),
    ):
        try:
            findings.extend(producer())
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            runner.log_error(f"vulnerability correlation subphase failed: {exc!r}")

    # De-duplicate identical source/identifier/port rows while retaining evidence separately.
    deduped: list[Finding] = []
    seen: set[tuple[int, str, str]] = set()
    for finding in findings:
        key = (finding.port, finding.possible_cve, finding.source)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)

    by_port: dict[int, list[Finding]] = defaultdict(list)
    for finding in deduped:
        by_port[finding.port].append(finding)
    for service in services:
        rows = [f.csv_dict() for f in by_port.get(service.port, [])]
        write_csv(vuln_dir / f"{service.port}_findings.csv", rows, FINDING_FIELDS)

    save_json(
        vuln_dir / "evidence.json",
        [
            {
                **f.csv_dict(),
                "evidence": f.evidence,
                "reference_url": f.reference_url,
            }
            for f in deduped
        ],
    )
    return deduped
