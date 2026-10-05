from __future__ import annotations

import csv
import json
import math
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .models import ServiceRecord
from .nmap_phase import is_http_service, is_tls_service
from .utils import (
    CommandRunner,
    format_host_for_url,
    http_health_probe,
    redirect_stays_in_scope,
    which_any,
    write_csv,
)


GOBUSTER_LINE_RE = re.compile(r"^(?P<path>\S+)\s+\(Status:\s*(?P<status>\d{3})\)\s*(?:\[Size:\s*(?P<size>\d+)\])?")
FEROX_LINE_RE = re.compile(
    r"^(?P<status>\d{3})\s+\w+\s+(?:(?P<lines>\d+)l\s+)?(?:(?P<words>\d+)w\s+)?(?:(?P<size>\d+)c\s+)?(?P<url>https?://\S+)$"
)


def web_endpoints(services: list[ServiceRecord]) -> list[tuple[ServiceRecord, str]]:
    endpoints: list[tuple[ServiceRecord, str]] = []
    seen: set[str] = set()
    for service in services:
        if not is_http_service(service):
            continue
        scheme = "https" if is_tls_service(service) or service.port in {443, 8443} else "http"
        host = format_host_for_url(service.host)
        if (scheme == "http" and service.port == 80) or (scheme == "https" and service.port == 443):
            url = f"{scheme}://{host}/"
        else:
            url = f"{scheme}://{host}:{service.port}/"
        if url not in seen:
            endpoints.append((service, url))
            seen.add(url)
    return endpoints


def resolve_wordlist(config: dict[str, Any], profile: str) -> Path | None:
    candidates = config.get("web", {}).get("wordlists", {}).get(profile, [])
    for candidate in candidates:
        path = Path(str(candidate)).expanduser()
        if path.exists() and path.is_file():
            return path
    return None


def _write_whatweb_csv(rows: list[dict[str, str]], web_dir: Path) -> None:
    write_csv(web_dir / "whatweb_results.csv", rows, ["url", "fingerprint"])


def run_whatweb(endpoints: list[tuple[ServiceRecord, str]], web_dir: Path, runner: CommandRunner) -> None:
    tool = which_any(["whatweb"])
    rows: list[dict[str, str]] = []
    if not tool:
        runner.log_error("whatweb not installed; web fingerprinting skipped")
        _write_whatweb_csv(rows, web_dir)
        return
    raw_dir = web_dir / "whatweb_raw"
    raw_dir.mkdir(exist_ok=True)
    help_result = runner.run([tool, "--help"], timeout=30, phase="Inspect WhatWeb CLI")
    help_text = (help_result.stdout + help_result.stderr).lower()
    for service, url in endpoints:
        cmd = [tool, "--no-errors", "-a", "1"]
        if "--max-redirects" in help_text:
            cmd.append("--max-redirects=0")
        cmd.append(url)
        result = runner.run(cmd, timeout=120, phase=f"WhatWeb {service.port}")
        fingerprint = (result.stdout or result.stderr).strip().replace("\n", " ")[:4000]
        (raw_dir / f"{service.port}.txt").write_text(result.stdout or result.stderr, encoding="utf-8", errors="replace")
        rows.append({"url": url, "fingerprint": fingerprint})
        _write_whatweb_csv(rows, web_dir)
    _write_whatweb_csv(rows, web_dir)


def _eyewitness_csv(eyewitness_dir: Path, web_dir: Path) -> None:
    rows: list[dict[str, str]] = []
    screenshots = []
    if eyewitness_dir.exists():
        for path in eyewitness_dir.rglob("*"):
            if path.is_file() and path.suffix.lower() in {".png", ".jpg", ".jpeg", ".webp"}:
                screenshots.append(path)
    for path in sorted(screenshots):
        rows.append({"screenshot": str(path.relative_to(web_dir)), "source": "EyeWitness"})
    write_csv(web_dir / "eyewitness_results.csv", rows, ["screenshot", "source"])


def run_eyewitness(endpoints: list[tuple[ServiceRecord, str]], web_dir: Path, runner: CommandRunner, config: dict[str, Any]) -> None:
    tool = which_any(["eyewitness", "eyewitness.sh", "EyeWitness.py"])
    ew_dir = web_dir / "eyewitness"
    ew_dir.mkdir(exist_ok=True)
    if not tool:
        runner.log_error("EyeWitness not installed; screenshot capture skipped")
        _eyewitness_csv(ew_dir, web_dir)
        return

    safe_endpoints = [
        (service, url)
        for service, url in endpoints
        if redirect_stays_in_scope(url, timeout=6, runner=runner)
    ]
    if not safe_endpoints:
        runner.log_error("EyeWitness skipped: redirect preflight could not confirm any endpoint stays on the authorized hostname")
        _eyewitness_csv(ew_dir, web_dir)
        return

    urls_file = web_dir / "urls.txt"
    urls_file.write_text("\n".join(url for _, url in safe_endpoints) + "\n", encoding="utf-8")

    # EyeWitness has changed its CLI over time. Detect legacy flags rather than assuming them.
    help_result = runner.run([tool, "--help"], timeout=30, phase="Inspect EyeWitness CLI")
    help_text = (help_result.stdout + help_result.stderr).lower()
    cmd = [tool, "-f", str(urls_file), "-d", str(ew_dir)]
    ew_cfg = config.get("eyewitness", {})
    if "--threads" in help_text:
        cmd += ["--threads", str(int(ew_cfg.get("threads", 5)))]
    if "--timeout" in help_text:
        cmd += ["--timeout", str(int(ew_cfg.get("timeout_seconds", 20)))]
    if "--delay" in help_text:
        cmd += ["--delay", str(int(ew_cfg.get("delay_seconds", 1)))]
    if "--web" in help_text:
        cmd.append("--web")
    if "--no-prompt" in help_text:
        cmd.append("--no-prompt")
    runner.run(cmd, timeout=20 * 60, phase="EyeWitness screenshots", capture=True)
    _eyewitness_csv(ew_dir, web_dir)


def _split_wordlist(wordlist: Path, chunk_size: int, temp_dir: Path) -> list[Path]:
    chunks: list[Path] = []
    current: list[str] = []
    index = 0
    with wordlist.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            word = line.strip()
            if not word or word.startswith("#"):
                continue
            current.append(word)
            if len(current) >= chunk_size:
                chunk = temp_dir / f"chunk_{index:04d}.txt"
                chunk.write_text("\n".join(current) + "\n", encoding="utf-8")
                chunks.append(chunk)
                current = []
                index += 1
    if current:
        chunk = temp_dir / f"chunk_{index:04d}.txt"
        chunk.write_text("\n".join(current) + "\n", encoding="utf-8")
        chunks.append(chunk)
    return chunks


def _parse_gobuster_output(path: Path, base_url: str) -> list[dict[str, str | int]]:
    rows: list[dict[str, str | int]] = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = GOBUSTER_LINE_RE.search(line.strip())
        if not match:
            continue
        found_path = match.group("path")
        url = base_url.rstrip("/") + "/" + found_path.lstrip("/")
        rows.append({
            "url": url,
            "status": int(match.group("status")),
            "size": int(match.group("size") or 0),
            "source": "gobuster",
        })
    return rows


def _parse_ferox_output(path: Path) -> list[dict[str, str | int]]:
    rows: list[dict[str, str | int]] = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # Newer feroxbuster can emit JSON lines. Fall back to human-output parsing.
        try:
            item = json.loads(stripped)
            if isinstance(item, dict):
                url = str(item.get("url") or item.get("target") or "")
                status = int(item.get("status") or item.get("status_code") or 0)
                if url and status:
                    rows.append({
                        "url": url,
                        "status": status,
                        "size": int(item.get("content_length") or item.get("size") or 0),
                        "source": "feroxbuster",
                    })
                    continue
        except Exception:
            pass
        match = FEROX_LINE_RE.match(stripped)
        if match:
            rows.append({
                "url": match.group("url"),
                "status": int(match.group("status")),
                "size": int(match.group("size") or 0),
                "source": "feroxbuster",
            })
    return rows


def _error_rate(rows: list[dict[str, str | int]]) -> float:
    if not rows:
        return 0.0
    errors = sum(1 for row in rows if int(row.get("status", 0)) == 429 or int(row.get("status", 0)) >= 500)
    return errors / len(rows)


def _run_fuzzer_for_url(
    tool_name: str,
    tool_path: str,
    url: str,
    port: int,
    wordlist: Path,
    web_dir: Path,
    runner: CommandRunner,
    config: dict[str, Any],
    aggregate_rows: list[dict[str, str | int]],
    checkpoint_path: Path,
) -> list[dict[str, str | int]]:
    web_cfg = config.get("web", {})
    threads = int(web_cfg.get("threads", 20))
    min_threads = int(web_cfg.get("min_threads", 5))
    delay_ms = int(web_cfg.get("delay_ms", 300))
    max_delay_ms = int(web_cfg.get("max_delay_ms", 2400))
    chunk_size = max(100, int(web_cfg.get("chunk_size", 2000)))
    threshold = float(web_cfg.get("error_rate_threshold", 0.35))
    latency_multiplier = float(web_cfg.get("latency_multiplier", 2.5))
    max_backoffs = int(web_cfg.get("max_backoff_steps", 3))
    probe_count = int(web_cfg.get("health_probe_count", 3))
    probe_timeout = float(web_cfg.get("health_probe_timeout_seconds", 6))
    extension_list = [str(x) for x in web_cfg.get("extensions", [])]
    extensions = ",".join(extension_list)

    baseline = http_health_probe(url, count=probe_count, timeout=probe_timeout, runner=runner)
    baseline_latency = max(0.05, baseline["avg_latency"])

    combined_rows: list[dict[str, str | int]] = []
    raw_dir = web_dir / f"{tool_name}_raw_{port}"
    raw_dir.mkdir(parents=True, exist_ok=True)
    chunk_root = web_dir / ".chunks"
    chunk_root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f"{port}_", dir=str(chunk_root)) as tmp:
        chunks = _split_wordlist(wordlist, chunk_size, Path(tmp))
        backoff_steps = 0
        for idx, chunk in enumerate(chunks):
            raw_path = raw_dir / f"chunk_{idx:04d}.txt"
            if tool_name == "feroxbuster":
                # Global rate limit is derived from delay_ms. This is intentionally more conservative
                # than simply multiplying thread count by per-thread throughput.
                rate_limit = max(1, math.floor(1000 / max(1, delay_ms)))
                cmd = [
                    tool_path,
                    "-u", url,
                    "-w", str(chunk),
                    "-t", str(threads),
                    "--rate-limit", str(rate_limit),
                    "--scan-limit", "1",
                    "--no-recursion",
                    "--dont-extract-links",
                    "--json",
                    "--no-state",
                    "-s", "200,204,301,302,307,308,400,401,403,405,408,409,429,500,502,503,504",
                    "-o", str(raw_path),
                    "--silent",
                ]
                for ext in extension_list:
                    cmd += ["-x", ext]
            else:
                cmd = [
                    tool_path,
                    "dir",
                    "-u", url,
                    "-w", str(chunk),
                    "-t", str(threads),
                    "--delay", f"{delay_ms}ms",
                    "-x", extensions,
                    "--no-error",
                    "-o", str(raw_path),
                ]

            result = runner.run(cmd, timeout=20 * 60, phase=f"{tool_name} content discovery port {port} chunk {idx + 1}/{len(chunks)}")
            if result.returncode not in {0, 1}:
                runner.log_error(f"{tool_name} chunk {idx} exited {result.returncode}; continuing conservatively")

            chunk_rows = _parse_ferox_output(raw_path) if tool_name == "feroxbuster" else _parse_gobuster_output(raw_path, url)
            combined_rows.extend(chunk_rows)
            aggregate_rows.extend(chunk_rows)
            write_csv(checkpoint_path, aggregate_rows, ["url", "status", "size", "source"])
            health = http_health_probe(url, count=probe_count, timeout=probe_timeout, runner=runner)
            observed_error = max(_error_rate(chunk_rows), health["failure_rate"], health["server_error_rate"])
            latency_degraded = health["avg_latency"] > baseline_latency * latency_multiplier
            if (observed_error >= threshold or latency_degraded) and backoff_steps < max_backoffs:
                old_threads, old_delay = threads, delay_ms
                threads = max(min_threads, threads // 2)
                delay_ms = min(max_delay_ms, delay_ms * 2)
                backoff_steps += 1
                reason = (
                    f"adaptive backoff #{backoff_steps}: error_rate={observed_error:.2f}, "
                    f"latency={health['avg_latency']:.2f}s baseline={baseline_latency:.2f}s; "
                    f"threads {old_threads}->{threads}, delay {old_delay}ms->{delay_ms}ms"
                )
                runner.log_error(reason)
                runner.log_internal("ADAPTIVE_THROTTLE " + reason, 0, 0.0)

    return combined_rows


def run_content_discovery(
    endpoints: list[tuple[ServiceRecord, str]],
    web_dir: Path,
    runner: CommandRunner,
    config: dict[str, Any],
    wordlist_profile: str,
) -> None:
    web_cfg = config.get("web", {})
    preferred = str(web_cfg.get("preferred_fuzzer", "auto")).lower()
    ferox = which_any(["feroxbuster"])
    gobuster = which_any(["gobuster"])
    if preferred == "gobuster" and gobuster:
        tool_name, tool_path = "gobuster", gobuster
    elif preferred == "feroxbuster" and ferox:
        tool_name, tool_path = "feroxbuster", ferox
    elif ferox:
        tool_name, tool_path = "feroxbuster", ferox
    elif gobuster:
        tool_name, tool_path = "gobuster", gobuster
    else:
        runner.log_error("Neither feroxbuster nor gobuster is installed; content discovery skipped")
        write_csv(web_dir / "content_discovery.csv", [], ["url", "status", "size", "source"])
        return

    wordlist = resolve_wordlist(config, wordlist_profile)
    if not wordlist:
        runner.log_error(
            f"SecLists raft-{wordlist_profile}-words wordlist not found. Install SecLists or update config.json paths."
        )
        write_csv(web_dir / "content_discovery.csv", [], ["url", "status", "size", "source"])
        return

    all_rows: list[dict[str, str | int]] = []
    tool_csv = web_dir / f"{tool_name}_results.csv"
    interrupted = False
    try:
        for service, url in endpoints:
            try:
                _run_fuzzer_for_url(
                    tool_name, tool_path, url, service.port, wordlist, web_dir, runner, config,
                    all_rows, tool_csv,
                )
            except KeyboardInterrupt:
                interrupted = True
                raise
            except Exception as exc:
                runner.log_error(f"content discovery failed for {url}: {exc!r}")
    finally:
        write_csv(tool_csv, all_rows, ["url", "status", "size", "source"])
        # Stable alias used by the report regardless of which fuzzer was selected.
        write_csv(web_dir / "content_discovery.csv", all_rows, ["url", "status", "size", "source"])
    if interrupted:
        raise KeyboardInterrupt


def run_nikto(endpoints: list[tuple[ServiceRecord, str]], web_dir: Path, runner: CommandRunner) -> None:
    tool = which_any(["nikto"])
    aggregate: list[dict[str, str]] = []
    if not tool:
        runner.log_error("nikto not installed; safe web checks skipped")
        write_csv(web_dir / "nikto_results.csv", aggregate, ["url", "raw_csv"])
        return

    for service, url in endpoints:
        out = web_dir / f"nikto_{service.port}.csv"
        # Tuning 1/2/3/b = interesting files, misconfiguration, information disclosure,
        # and software identification. We intentionally exclude DoS (6), injection/SQLi (4/9),
        # command execution (8), auth bypass (a), and other exploit-adjacent categories.
        cmd = [
            tool,
            "-h", url,
            "-Tuning", "123b",
            "-Format", "csv",
            "-output", str(out),
            "-nointeractive",
            "-maxtime", "10m",
        ]
        runner.run(cmd, timeout=12 * 60, phase=f"Nikto safe checks port {service.port}")
        raw = out.read_text(encoding="utf-8", errors="replace")[:12000] if out.exists() else ""
        aggregate.append({"url": url, "raw_csv": raw})
        write_csv(web_dir / "nikto_results.csv", aggregate, ["url", "raw_csv"])
    write_csv(web_dir / "nikto_results.csv", aggregate, ["url", "raw_csv"])


def run_web_phase(
    services: list[ServiceRecord],
    target_dir: Path,
    runner: CommandRunner,
    config: dict[str, Any],
    wordlist_profile: str,
) -> list[tuple[ServiceRecord, str]]:
    web_dir = target_dir / "web"
    web_dir.mkdir(parents=True, exist_ok=True)
    endpoints = web_endpoints(services)
    if not endpoints:
        write_csv(web_dir / "whatweb_results.csv", [], ["url", "fingerprint"])
        write_csv(web_dir / "content_discovery.csv", [], ["url", "status", "size", "source"])
        write_csv(web_dir / "nikto_results.csv", [], ["url", "raw_csv"])
        write_csv(web_dir / "eyewitness_results.csv", [], ["screenshot", "source"])
        return []

    for fn, args in [
        (run_whatweb, (endpoints, web_dir, runner)),
        (run_eyewitness, (endpoints, web_dir, runner, config)),
        (run_content_discovery, (endpoints, web_dir, runner, config, wordlist_profile)),
        (run_nikto, (endpoints, web_dir, runner)),
    ]:
        try:
            fn(*args)
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            runner.log_error(f"web subphase {fn.__name__} failed: {exc!r}")
    return endpoints
