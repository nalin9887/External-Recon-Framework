from __future__ import annotations

from pathlib import Path
from typing import Any

from .models import ServiceRecord
from .nmap_phase import is_http_service, is_tls_service, run_nmap_phase
from .report import generate_report
from .tls_phase import run_tls_phase
from .utils import CommandRunner, safe_folder_name, save_json, utc_now, which_any
from .vuln_phase import run_vuln_phase
from .web_phase import run_web_phase


def _ensure_layout(target_dir: Path) -> None:
    for name in ("nmap", "web", "tls", "vuln", "logs"):
        (target_dir / name).mkdir(parents=True, exist_ok=True)


def scan_target(
    target: str,
    config: dict[str, Any],
    scan_profile: str,
    timing: str,
    wordlist_profile: str,
    console: Any | None = None,
) -> Path:
    output_root = Path(str(config.get("output_root", "output"))).expanduser()
    target_dir = output_root / safe_folder_name(target)
    _ensure_layout(target_dir)
    runner = CommandRunner(target_dir / "logs", console=console)

    metadata: dict[str, Any] = {
        "target": target,
        "started_at": utc_now(),
        "scan_profile": scan_profile,
        "timing": timing,
        "wordlist_profile": wordlist_profile,
        "embed_screenshots": bool(config.get("report", {}).get("embed_screenshots", True)),
        "web_note": "Not yet evaluated.",
        "tls_note": "Not yet evaluated.",
        "vuln_note": "Not yet evaluated.",
        "interrupted": False,
    }
    save_json(target_dir / "scan_metadata.json", metadata)

    services: list[ServiceRecord] = []
    tls_rows: list[dict[str, str | int]] = []
    nmap_bin = which_any(["nmap"])

    try:
        if not nmap_bin:
            runner.log_error("nmap is not installed; target scan cannot proceed")
            metadata["web_note"] = "closed — skipped: Nmap results unavailable."
            metadata["tls_note"] = "closed — skipped: Nmap results unavailable."
            metadata["vuln_note"] = "skipped: service inventory unavailable because Nmap did not run."
        else:
            services = run_nmap_phase(target, target_dir, runner, config, scan_profile, timing, nmap_bin)

            http_ports = sorted({s.port for s in services if is_http_service(s)})
            if http_ports:
                metadata["web_note"] = "Web services detected on port(s): " + ", ".join(map(str, http_ports)) + "."
                save_json(target_dir / "scan_metadata.json", metadata)
                run_web_phase(services, target_dir, runner, config, wordlist_profile)
            else:
                metadata["web_note"] = "closed — skipped: no open HTTP/HTTPS service was detected by Nmap."
                # Create stable empty artifacts for the report.
                run_web_phase([], target_dir, runner, config, wordlist_profile)

            tls_ports = sorted({s.port for s in services if is_tls_service(s)})
            if tls_ports:
                metadata["tls_note"] = "TLS-wrapped service(s) detected on port(s): " + ", ".join(map(str, tls_ports)) + "."
                save_json(target_dir / "scan_metadata.json", metadata)
                tls_rows = run_tls_phase(services, target_dir, runner)
            else:
                metadata["tls_note"] = "closed — skipped: no TLS-wrapped service was detected by Nmap."
                tls_rows = run_tls_phase([], target_dir, runner)

            if services:
                non_http_nuclei = bool(config.get("nuclei", {}).get("scan_non_http_services", False))
                metadata["vuln_note"] = (
                    "Identification only: safe/default/version NSE, offline Searchsploit version correlation, "
                    "TLS CVE detection, and rate-limited Nuclei with DoS/fuzz/intrusive/exploit-adjacent tags excluded. "
                    + ("Non-HTTP Nuclei probing is enabled by config." if non_http_nuclei else "Non-HTTP Nuclei probing is disabled by default.")
                )
                save_json(target_dir / "scan_metadata.json", metadata)
                run_vuln_phase(target, services, tls_rows, target_dir, runner, config, timing, nmap_bin)
            else:
                metadata["vuln_note"] = "skipped: no open services were recorded."

    except KeyboardInterrupt:
        metadata["interrupted"] = True
        metadata["interrupted_at"] = utc_now()
        runner.log_error("Scan interrupted by operator; partial results retained and report generation attempted.")
        raise
    except Exception as exc:
        runner.log_error(f"Unhandled target pipeline error: {exc!r}; continuing to partial report")
        metadata["pipeline_error"] = repr(exc)
    finally:
        metadata["finished_at"] = utc_now()
        save_json(target_dir / "scan_metadata.json", metadata)
        try:
            generate_report(target_dir)
        except Exception as exc:
            runner.log_error(f"Report generation failed: {exc!r}")

    return target_dir
