from __future__ import annotations

import csv
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from .models import ServiceRecord
from .utils import CommandRunner, write_csv


WEB_PORTS = {80, 443, 8000, 8080, 8443, 8888}
TLS_PORTS = {443, 465, 636, 853, 989, 990, 992, 993, 994, 995, 8443}


def build_nmap_command(
    nmap_bin: str,
    target: str,
    output_base: Path,
    profile: str,
    timing: str,
    max_retries: int,
    host_timeout: str,
) -> list[str]:
    timing = timing.upper()
    if timing not in {"T3", "T4"}:
        raise ValueError("Nmap timing is hard-capped to T3/T4; T5 is unsupported.")

    cmd = [
        nmap_bin,
        "-sV",
        "-sC",
        "--open",
        f"-{timing}",
        "--max-retries",
        str(max_retries),
        "--host-timeout",
        host_timeout,
    ]
    if profile == "top100":
        cmd += ["--top-ports", "100"]
    elif profile == "top1000":
        pass  # Nmap default port selection is intentionally used.
    elif profile == "full":
        cmd += ["-p-"]
    else:
        raise ValueError(f"unknown scan profile: {profile}")
    cmd += ["-oA", str(output_base), target]
    return cmd


def parse_nmap_xml(xml_path: Path, fallback_target: str) -> list[ServiceRecord]:
    services: list[ServiceRecord] = []
    if not xml_path.exists():
        return services
    try:
        root = ET.parse(xml_path).getroot()
    except (ET.ParseError, OSError):
        return services

    for host in root.findall("host"):
        host_addr = fallback_target
        addr = host.find("address")
        if addr is not None and addr.attrib.get("addr"):
            host_addr = addr.attrib["addr"]
        ports = host.find("ports")
        if ports is None:
            continue
        for port_el in ports.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.attrib.get("state") != "open":
                continue
            svc = port_el.find("service")
            attrs: dict[str, str] = svc.attrib if svc is not None else {}
            version_parts = [attrs.get("version", ""), attrs.get("extrainfo", "")]
            version = " ".join(part for part in version_parts if part).strip()
            try:
                port_id = int(port_el.attrib.get("portid", "0"))
            except ValueError:
                continue
            services.append(
                ServiceRecord(
                    host=host_addr,
                    port=port_id,
                    protocol=port_el.attrib.get("protocol", "tcp"),
                    state="open",
                    service=attrs.get("name", "unknown"),
                    version=version,
                    product=attrs.get("product", ""),
                    tunnel=attrs.get("tunnel", ""),
                )
            )
    return services


def is_http_service(service: ServiceRecord) -> bool:
    name = service.service.lower()
    return service.port in WEB_PORTS or "http" in name or name in {"http-proxy", "webcache"}


def is_tls_service(service: ServiceRecord) -> bool:
    name = service.service.lower()
    tunnel = service.tunnel.lower()
    return (
        service.port in TLS_PORTS
        or tunnel == "ssl"
        or "https" in name
        or name.endswith("s") and name in {"smtps", "imaps", "pop3s", "ldaps"}
        or "ssl" in name
        or "tls" in name
    )


def run_nmap_phase(
    target: str,
    target_dir: Path,
    runner: CommandRunner,
    config: dict[str, Any],
    profile: str,
    timing: str,
    nmap_bin: str,
) -> list[ServiceRecord]:
    nmap_dir = target_dir / "nmap"
    nmap_dir.mkdir(parents=True, exist_ok=True)
    output_base = nmap_dir / f"{target_dir.name}_scan"
    safety = config["safety"]
    cmd = build_nmap_command(
        nmap_bin=nmap_bin,
        target=target,
        output_base=output_base,
        profile=profile,
        timing=timing,
        max_retries=int(safety.get("max_retries", 2)),
        host_timeout=str(safety.get("host_timeout", "15m")),
    )
    result = runner.run(cmd, timeout=20 * 60, phase="Nmap service discovery")
    if result.returncode not in {0, 1}:
        runner.log_error("Nmap did not complete successfully; partial XML will still be parsed if present.")

    xml_path = output_base.with_suffix(".xml")
    services = parse_nmap_xml(xml_path, target)
    rows = [
        {
            "port": service.port,
            "protocol": service.protocol,
            "state": service.state,
            "service": service.service,
            "version": service.version,
            "product": service.product,
        }
        for service in services
    ]
    write_csv(
        nmap_dir / "nmap_results.csv",
        rows,
        ["port", "protocol", "state", "service", "version", "product"],
    )
    return services
