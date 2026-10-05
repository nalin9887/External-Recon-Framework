from __future__ import annotations

import csv
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from .models import ServiceRecord
from .nmap_phase import is_tls_service
from .utils import CommandRunner, format_host_for_url, which_any, write_csv


TLS_FIELDS = ["port", "identifier", "severity", "finding", "cve", "cwe", "source"]


def _flatten_testssl_json(path: Path, port: int) -> list[dict[str, str | int]]:
    rows: list[dict[str, str | int]] = []
    if not path.exists():
        return rows
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return rows

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            if "id" in value and ("finding" in value or "severity" in value):
                rows.append({
                    "port": int(value.get("port") or port),
                    "identifier": str(value.get("id") or ""),
                    "severity": str(value.get("severity") or "INFO").lower(),
                    "finding": str(value.get("finding") or value.get("findingLong") or ""),
                    "cve": str(value.get("cve") or ""),
                    "cwe": str(value.get("cwe") or ""),
                    "source": "testssl.sh",
                })
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(data)
    return rows


def _parse_sslscan_xml(path: Path, port: int) -> list[dict[str, str | int]]:
    rows: list[dict[str, str | int]] = []
    if not path.exists():
        return rows
    try:
        root = ET.parse(path).getroot()
    except Exception:
        return rows

    for cipher in root.findall(".//cipher"):
        status = cipher.attrib.get("status", "")
        sslversion = cipher.attrib.get("sslversion", "")
        bits = cipher.attrib.get("bits", "")
        cipher_name = cipher.attrib.get("cipher", "")
        severity = "info"
        finding = f"{sslversion} {cipher_name} {bits} bits status={status}".strip()
        if sslversion in {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}:
            severity = "medium"
        rows.append({
            "port": port,
            "identifier": "cipher",
            "severity": severity,
            "finding": finding,
            "cve": "",
            "cwe": "",
            "source": "sslscan",
        })
    for cert in root.findall(".//certificate"):
        rows.append({
            "port": port,
            "identifier": "certificate",
            "severity": "info",
            "finding": " ".join(f"{k}={v}" for k, v in cert.attrib.items()),
            "cve": "",
            "cwe": "",
            "source": "sslscan",
        })
    return rows


def _parse_sslyze_json(path: Path, port: int) -> list[dict[str, str | int]]:
    rows: list[dict[str, str | int]] = []
    if not path.exists():
        return rows
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return rows
    text = json.dumps(data, ensure_ascii=False)
    weak_protocols = []
    for proto in ["SSL_2_0", "SSL_3_0", "TLS_1_0", "TLS_1_1"]:
        if proto in text and '"is_supported": true' in text.lower():
            weak_protocols.append(proto)
    for proto in weak_protocols:
        rows.append({
            "port": port,
            "identifier": proto,
            "severity": "medium",
            "finding": f"Legacy protocol appears supported: {proto}",
            "cve": "",
            "cwe": "",
            "source": "sslyze",
        })
    return rows


def run_tls_phase(
    services: list[ServiceRecord],
    target_dir: Path,
    runner: CommandRunner,
) -> list[dict[str, str | int]]:
    tls_dir = target_dir / "tls"
    tls_dir.mkdir(parents=True, exist_ok=True)
    tls_services = [service for service in services if is_tls_service(service)]
    all_rows: list[dict[str, str | int]] = []
    if not tls_services:
        write_csv(tls_dir / "tls_results.csv", [], TLS_FIELDS)
        return all_rows

    testssl = which_any(["testssl.sh", "testssl"])
    sslscan = which_any(["sslscan"])
    sslyze = which_any(["sslyze"])

    for service in tls_services:
        target = f"{format_host_for_url(service.host)}:{service.port}"
        try:
            if testssl:
                json_out = tls_dir / f"testssl_{service.port}.json"
                raw_out = tls_dir / f"testssl_{service.port}.log"
                cmd = [
                    testssl,
                    "--quiet",
                    "--warnings", "batch",
                    "--color", "0",
                    "--ids-friendly",
                    "--jsonfile", str(json_out),
                    "--logfile", str(raw_out),
                    target,
                ]
                runner.run(cmd, timeout=20 * 60, phase=f"TLS assessment port {service.port}")
                all_rows.extend(_flatten_testssl_json(json_out, service.port))
            elif sslscan:
                xml_out = tls_dir / f"sslscan_{service.port}.xml"
                raw_out = tls_dir / f"sslscan_{service.port}.txt"
                cmd = [sslscan, "--no-colour", "--show-certificate", f"--xml={xml_out}", target]
                runner.run(cmd, timeout=10 * 60, phase=f"TLS assessment port {service.port}", stdout_path=raw_out)
                all_rows.extend(_parse_sslscan_xml(xml_out, service.port))
            elif sslyze:
                json_out = tls_dir / f"sslyze_{service.port}.json"
                cmd = [sslyze, "--json_out", str(json_out), target]
                runner.run(cmd, timeout=10 * 60, phase=f"TLS assessment port {service.port}")
                all_rows.extend(_parse_sslyze_json(json_out, service.port))
            else:
                runner.log_error("No TLS scanner installed (testssl.sh/sslscan/sslyze); TLS phase skipped")
                break
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            runner.log_error(f"TLS phase failed for port {service.port}: {exc!r}")

    write_csv(tls_dir / "tls_results.csv", all_rows, TLS_FIELDS)
    return all_rows
