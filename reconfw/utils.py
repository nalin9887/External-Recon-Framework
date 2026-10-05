from __future__ import annotations

import csv
import ipaddress
import json
import os
import re
import shlex
import signal
import ssl
import subprocess
import sys
import threading
import time
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPHandler, HTTPRedirectHandler, HTTPSHandler, Request, build_opener


HOST_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
SAFE_FOLDER_RE = re.compile(r"[^A-Za-z0-9._-]+")


def utc_now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def validate_target(raw: str) -> str:
    """Return a canonical IP/CIDR/hostname or raise ValueError.

    We reject URLs, shell metacharacters, wildcards, and option-like values. Even though
    subprocesses are always invoked with shell=False, strict validation prevents argument
    injection into tools that interpret leading dashes as options.
    """
    value = raw.strip()
    if not value:
        raise ValueError("empty target")
    if len(value) > 255:
        raise ValueError("target is too long")
    if "://" in value or any(ch in value for ch in " \\;|&`$<>\n\r\t*?[]{}()\""):
        raise ValueError("target must be a bare hostname, IP, or CIDR; URLs and metacharacters are rejected")
    if value.startswith("-"):
        raise ValueError("target may not begin with '-'")

    if "/" in value:
        # A slash is accepted only as CIDR notation, never as a hostname/path separator.
        if value.count("/") != 1:
            raise ValueError("invalid CIDR syntax")
        try:
            return str(ipaddress.ip_network(value, strict=True))
        except ValueError as exc:
            raise ValueError(f"invalid CIDR: {exc}") from exc

    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass

    host = value.rstrip(".")
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("invalid internationalized hostname") from exc
    if len(ascii_host) > 253:
        raise ValueError("hostname is too long")
    labels = ascii_host.split(".")
    if len(labels) < 2 and ascii_host.lower() != "localhost":
        # Single-label hosts are intentionally rejected for an external assessment tool.
        raise ValueError("hostname must be fully qualified")
    if not all(HOST_LABEL_RE.fullmatch(label) for label in labels):
        raise ValueError("invalid hostname syntax")
    return ascii_host.lower()


def expand_target(target: str, max_hosts: int) -> list[str]:
    if "/" not in target:
        return [target]
    network = ipaddress.ip_network(target, strict=True)
    host_count = max(1, network.num_addresses - (2 if network.version == 4 and network.prefixlen <= 30 else 0))
    if host_count > max_hosts:
        raise ValueError(
            f"CIDR expands to {host_count} hosts, above safety cap {max_hosts}. "
            "Split the scope into smaller authorized ranges instead of bypassing the cap."
        )
    hosts = [str(ip) for ip in network.hosts()]
    return hosts or [str(network.network_address)]


def safe_folder_name(target: str) -> str:
    return SAFE_FOLDER_RE.sub("_", target).strip("._") or "target"


def format_host_for_url(host: str) -> str:
    try:
        addr = ipaddress.ip_address(host)
        return f"[{host}]" if addr.version == 6 else host
    except ValueError:
        return host


def display_command(argv: Sequence[str]) -> str:
    if os.name == "nt":
        return subprocess.list2cmdline(list(argv))
    return shlex.join(list(argv))


class ProcessRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._procs: set[subprocess.Popen[str]] = set()

    def add(self, proc: subprocess.Popen[str]) -> None:
        with self._lock:
            self._procs.add(proc)

    def discard(self, proc: subprocess.Popen[str]) -> None:
        with self._lock:
            self._procs.discard(proc)

    def terminate_all(self) -> None:
        with self._lock:
            procs = list(self._procs)
        for proc in procs:
            terminate_process_tree(proc)


PROCESS_REGISTRY = ProcessRegistry()


def terminate_process_tree(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        else:
            proc.terminate()
        proc.wait(timeout=4)
    except Exception:
        try:
            if os.name == "posix":
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            else:
                proc.kill()
        except Exception:
            pass


class CommandRunner:
    """Run subprocesses safely and append a complete audit record for each command."""

    def __init__(self, logs_dir: Path, console: Any | None = None) -> None:
        self.logs_dir = logs_dir
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.commands_log = logs_dir / "commands.log"
        self.errors_log = logs_dir / "errors.log"
        self.console = console

    def _append_command_log(self, record: dict[str, Any]) -> None:
        with self.commands_log.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    def log_internal(self, description: str, exit_code: int, duration_s: float, detail: str = "") -> None:
        self._append_command_log({
            "timestamp": utc_now(),
            "command": description,
            "exit_code": exit_code,
            "duration_s": round(duration_s, 3),
            "internal": True,
            "detail": detail,
        })

    def log_error(self, message: str) -> None:
        with self.errors_log.open("a", encoding="utf-8") as handle:
            handle.write(f"[{utc_now()}] {message}\n")

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        timeout: float | None = None,
        stdout_path: Path | None = None,
        env: dict[str, str] | None = None,
        phase: str = "command",
        capture: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        if not argv or not all(isinstance(arg, str) and "\x00" not in arg for arg in argv):
            raise ValueError("invalid subprocess argument vector")

        command_text = display_command(argv)
        started = time.monotonic()
        start_time = utc_now()
        stdout_handle = None
        stderr_data = ""
        stdout_data = ""
        creationflags = 0
        popen_kwargs: dict[str, Any] = {}
        if os.name == "posix":
            popen_kwargs["start_new_session"] = True
        elif os.name == "nt":
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]

        spinner_ctx = None
        if self.console is not None:
            try:
                spinner_ctx = self.console.status(f"[cyan]{phase}[/cyan]: {command_text}", spinner="dots")
                spinner_ctx.__enter__()
            except Exception:
                spinner_ctx = None

        try:
            if stdout_path is not None:
                stdout_path.parent.mkdir(parents=True, exist_ok=True)
                stdout_handle = stdout_path.open("w", encoding="utf-8", errors="replace")
            proc = subprocess.Popen(
                list(argv),
                cwd=str(cwd) if cwd else None,
                env=env,
                stdout=stdout_handle if stdout_handle else (subprocess.PIPE if capture else None),
                stderr=subprocess.PIPE,
                text=True,
                errors="replace",
                creationflags=creationflags,
                **popen_kwargs,
            )
            PROCESS_REGISTRY.add(proc)
            try:
                stdout_data, stderr_data = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                terminate_process_tree(proc)
                stdout_data, stderr_data = proc.communicate()
                stderr_data = (stderr_data or "") + f"\nFramework timeout after {timeout}s"
            finally:
                PROCESS_REGISTRY.discard(proc)

            rc = int(proc.returncode if proc.returncode is not None else 124)
            duration = time.monotonic() - started
            self._append_command_log({
                "timestamp": start_time,
                "command": command_text,
                "exit_code": rc,
                "duration_s": round(duration, 3),
                "cwd": str(cwd) if cwd else "",
            })
            if rc != 0:
                self.log_error(f"exit={rc} phase={phase} command={command_text}\nstderr={stderr_data[-4000:]}")
            return subprocess.CompletedProcess(list(argv), rc, stdout_data or "", stderr_data or "")
        except KeyboardInterrupt:
            PROCESS_REGISTRY.terminate_all()
            duration = time.monotonic() - started
            self._append_command_log({
                "timestamp": start_time,
                "command": command_text,
                "exit_code": 130,
                "duration_s": round(duration, 3),
                "interrupted": True,
            })
            raise
        except Exception as exc:
            duration = time.monotonic() - started
            self._append_command_log({
                "timestamp": start_time,
                "command": command_text,
                "exit_code": -1,
                "duration_s": round(duration, 3),
                "error": repr(exc),
            })
            self.log_error(f"phase={phase} command={command_text} exception={exc!r}")
            return subprocess.CompletedProcess(list(argv), -1, "", str(exc))
        finally:
            if stdout_handle is not None:
                stdout_handle.close()
            if spinner_ctx is not None:
                try:
                    spinner_ctx.__exit__(None, None, None)
                except Exception:
                    pass


def which_any(candidates: Iterable[str]) -> str | None:
    import shutil

    for candidate in candidates:
        found = shutil.which(candidate)
        if found:
            return found
    return None


def write_csv(path: Path, rows: Iterable[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            if is_dataclass(row):
                writer.writerow(asdict(row))
            else:
                writer.writerow(row)


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", newline="", encoding="utf-8", errors="replace") as handle:
        return list(csv.DictReader(handle))


def load_json(path: Path, default: Any = None) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return default


def save_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, ensure_ascii=False)




class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


def _no_redirect_opener() -> Any:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return build_opener(HTTPHandler(), HTTPSHandler(context=ctx), _NoRedirect())


def redirect_stays_in_scope(url: str, *, timeout: float, runner: CommandRunner) -> bool:
    """Preflight a URL without following redirects.

    EyeWitness uses a real browser and can follow redirects. To avoid accidentally browsing a
    third-party host that is outside the authorized target, screenshotting is skipped when an
    initial redirect changes the hostname. Network errors also fail closed.
    """
    req = Request(
        url,
        method="GET",
        headers={"User-Agent": "Authorized-Recon-Framework/1.0", "Range": "bytes=0-0"},
    )
    started = time.monotonic()
    status = 0
    location = ""
    try:
        with _no_redirect_opener().open(req, timeout=timeout) as response:
            status = int(getattr(response, "status", 200))
            location = str(response.headers.get("Location") or "")
            response.read(1)
    except HTTPError as exc:
        status = int(exc.code)
        location = str(exc.headers.get("Location") or "")
    except (URLError, TimeoutError, ssl.SSLError, OSError) as exc:
        elapsed = time.monotonic() - started
        runner.log_internal(f"INTERNAL_REDIRECT_SCOPE_CHECK GET {url}", 1, elapsed, detail=f"error={exc!r}")
        return False

    elapsed = time.monotonic() - started
    allowed = True
    detail = f"status={status}"
    if 300 <= status <= 399 and location:
        resolved = urljoin(url, location)
        source_host = (urlparse(url).hostname or "").lower()
        dest_host = (urlparse(resolved).hostname or "").lower()
        allowed = bool(source_host and dest_host and source_host == dest_host)
        detail += f" location={resolved} same_host={allowed}"
    runner.log_internal(f"INTERNAL_REDIRECT_SCOPE_CHECK GET {url}", 0 if allowed else 1, elapsed, detail=detail)
    return allowed


def http_health_probe(
    url: str,
    *,
    count: int,
    timeout: float,
    runner: CommandRunner,
) -> dict[str, float]:
    latencies: list[float] = []
    failures = 0
    server_errors = 0
    opener = _no_redirect_opener()

    for _ in range(max(1, count)):
        req = Request(
            url,
            method="GET",
            headers={
                "User-Agent": "Authorized-Recon-Framework/1.0",
                "Range": "bytes=0-0",
                "Accept": "*/*",
            },
        )
        started = time.monotonic()
        status = 0
        try:
            with opener.open(req, timeout=timeout) as response:
                status = int(getattr(response, "status", 200))
                response.read(1)
        except HTTPError as exc:
            status = int(exc.code)
        except (URLError, TimeoutError, ssl.SSLError, OSError):
            failures += 1
        elapsed = time.monotonic() - started
        latencies.append(elapsed)
        if status == 429 or 500 <= status <= 599:
            server_errors += 1
        runner.log_internal(
            f"INTERNAL_HTTP_PROBE GET {url}",
            0 if status or failures == 0 else 1,
            elapsed,
            detail=f"status={status or 'error'}",
        )
        time.sleep(0.2)

    total = max(1, len(latencies))
    return {
        "avg_latency": sum(latencies) / total,
        "failure_rate": failures / total,
        "server_error_rate": server_errors / total,
    }
