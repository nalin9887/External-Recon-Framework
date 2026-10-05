from __future__ import annotations

import importlib.util
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from .utils import CommandRunner, display_command, utc_now, which_any


PYTHON_LIBS = {
    "rich": "rich",
    "python-nmap": "nmap",
    "jinja2": "jinja2",
    "pandas": "pandas",
}

TOOL_SPECS: dict[str, dict[str, Any]] = {
    "nmap": {"bins": ["nmap"], "apt": "nmap", "brew": "nmap", "version": ["--version"]},
    "gobuster": {"bins": ["gobuster"], "apt": "gobuster", "brew": "gobuster", "version": ["version"]},
    "feroxbuster": {"bins": ["feroxbuster"], "apt": "feroxbuster", "brew": "feroxbuster", "version": ["--version"]},
    "eyewitness": {"bins": ["eyewitness", "eyewitness.sh", "EyeWitness.py"], "apt": "eyewitness", "brew": None, "version": ["--help"]},
    "whatweb": {"bins": ["whatweb"], "apt": "whatweb", "brew": "whatweb", "version": ["--version"]},
    "nikto": {"bins": ["nikto"], "apt": "nikto", "brew": "nikto", "version": ["-Version"]},
    "testssl": {"bins": ["testssl.sh", "testssl"], "apt": "testssl.sh", "brew": "testssl", "version": ["--version"]},
    "sslscan": {"bins": ["sslscan"], "apt": "sslscan", "brew": "sslscan", "version": ["--version"]},
    "sslyze": {"bins": ["sslyze"], "apt": "sslyze", "brew": None, "version": ["--version"]},
    "nuclei": {"bins": ["nuclei"], "apt": "nuclei", "brew": "nuclei", "version": ["-version"]},
    "searchsploit": {"bins": ["searchsploit"], "apt": "exploitdb", "brew": None, "version": ["-h"]},
}


def _state_path() -> Path:
    return Path.home() / ".external_recon_framework" / "state.json"


def is_first_launch() -> bool:
    state = _state_path()
    if not state.exists():
        return True
    try:
        data = json.loads(state.read_text(encoding="utf-8"))
        return not bool(data.get("bootstrap_complete"))
    except Exception:
        return True


def mark_bootstrap_complete() -> None:
    state = _state_path()
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text(json.dumps({"bootstrap_complete": True, "timestamp": utc_now()}, indent=2), encoding="utf-8")


def detect_package_manager() -> str:
    if platform.system() == "Darwin" and shutil.which("brew"):
        return "brew"
    if shutil.which("apt-get"):
        return "apt"
    return "generic"


def _sudo_prefix() -> list[str]:
    if os.name != "posix":
        return []
    geteuid = getattr(os, "geteuid", None)
    if geteuid and geteuid() == 0:
        return []
    return ["sudo"] if shutil.which("sudo") else []


def _manual_install(tool: str, pm: str) -> str:
    if tool == "eyewitness":
        return (
            "git clone https://github.com/RedSiege/EyeWitness.git ~/tools/EyeWitness && "
            "cd ~/tools/EyeWitness/setup && sudo ./setup.sh && "
            "sudo ln -sf ~/tools/EyeWitness/eyewitness.sh /usr/local/bin/eyewitness"
        )
    if tool == "searchsploit":
        return (
            "git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git ~/.local/opt/exploitdb && "
            "mkdir -p ~/.local/bin && ln -sf ~/.local/opt/exploitdb/searchsploit ~/.local/bin/searchsploit"
        )
    if tool == "testssl":
        return (
            "git clone --depth 1 https://github.com/testssl/testssl.sh.git ~/.local/opt/testssl.sh && "
            "mkdir -p ~/.local/bin && ln -sf ~/.local/opt/testssl.sh/testssl.sh ~/.local/bin/testssl.sh"
        )
    if tool == "nuclei":
        return "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    if tool == "gobuster":
        return "go install github.com/OJ/gobuster/v3@latest"
    if tool == "feroxbuster":
        return "cargo install feroxbuster"
    if tool == "whatweb":
        return "git clone https://github.com/urbanadventurer/WhatWeb.git ~/tools/WhatWeb"
    if tool == "nikto":
        return "git clone https://github.com/sullo/nikto.git ~/tools/nikto"
    if tool == "sslscan":
        return "Install sslscan from your OS package manager or https://github.com/rbsec/sslscan"
    if tool == "sslyze":
        return "python3 -m pip install --user sslyze"
    if tool == "nmap":
        return "Install Nmap from https://nmap.org/download.html"
    return f"Install {tool} using the vendor's official instructions."


def _install_python_libs(runner: CommandRunner) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    missing = [package for package, import_name in PYTHON_LIBS.items() if importlib.util.find_spec(import_name) is None]
    if missing:
        argv = [sys.executable, "-m", "pip", "install"]
        in_venv = sys.prefix != getattr(sys, "base_prefix", sys.prefix)
        if not in_venv:
            argv.append("--user")
        argv.extend(missing)
        result = runner.run(argv, timeout=900, phase="Install Python libraries")
        if result.returncode != 0:
            runner.log_error(
                "Python dependency installation failed. Recommended manual fallback: "
                "python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt"
            )

    for package, import_name in PYTHON_LIBS.items():
        ok = importlib.util.find_spec(import_name) is not None
        rows.append({
            "component": f"python:{package}",
            "status": "OK" if ok else "MISSING",
            "version": _python_package_version(package) if ok else "",
            "manual": "" if ok else "python3 -m pip install -r requirements.txt",
        })
    return rows


def _python_package_version(package: str) -> str:
    try:
        from importlib.metadata import version
        return version(package)
    except Exception:
        return "installed"


def _apt_install(package: str, runner: CommandRunner) -> bool:
    argv = _sudo_prefix() + ["apt-get", "install", "-y", package]
    return runner.run(argv, timeout=1200, phase=f"Install {package}").returncode == 0


def _brew_install(package: str, runner: CommandRunner) -> bool:
    return runner.run(["brew", "install", package], timeout=1200, phase=f"Install {package}").returncode == 0


def _try_generic_install(tool: str, runner: CommandRunner) -> bool:
    home = Path.home()
    local_bin = home / ".local" / "bin"
    local_bin.mkdir(parents=True, exist_ok=True)

    if tool == "nuclei" and shutil.which("go"):
        return runner.run(
            ["go", "install", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"],
            timeout=1200,
            phase="Install nuclei",
        ).returncode == 0
    if tool == "gobuster" and shutil.which("go"):
        return runner.run(
            ["go", "install", "github.com/OJ/gobuster/v3@latest"], timeout=1200, phase="Install gobuster"
        ).returncode == 0
    if tool == "feroxbuster" and shutil.which("cargo"):
        return runner.run(["cargo", "install", "feroxbuster"], timeout=1200, phase="Install feroxbuster").returncode == 0
    if tool == "testssl" and shutil.which("git"):
        dest = home / ".local" / "opt" / "testssl.sh"
        dest.parent.mkdir(parents=True, exist_ok=True)
        if not dest.exists():
            result = runner.run(
                ["git", "clone", "--depth", "1", "https://github.com/testssl/testssl.sh.git", str(dest)],
                timeout=1200,
                phase="Install testssl.sh",
            )
            if result.returncode != 0:
                return False
        link = local_bin / "testssl.sh"
        try:
            if link.exists() or link.is_symlink():
                link.unlink()
            link.symlink_to(dest / "testssl.sh")
            return True
        except OSError:
            return False
    if tool == "sslyze":
        argv = [sys.executable, "-m", "pip", "install"]
        if sys.prefix == getattr(sys, "base_prefix", sys.prefix):
            argv.append("--user")
        argv.append("sslyze")
        return runner.run(argv, timeout=1200, phase="Install sslyze").returncode == 0
    if tool == "searchsploit" and shutil.which("git"):
        dest = home / ".local" / "opt" / "exploitdb"
        dest.parent.mkdir(parents=True, exist_ok=True)
        if not dest.exists():
            result = runner.run(
                ["git", "clone", "--depth", "1", "https://gitlab.com/exploit-database/exploitdb.git", str(dest)],
                timeout=1800,
                phase="Install searchsploit database",
            )
            if result.returncode != 0:
                return False
        link = local_bin / "searchsploit"
        try:
            if link.exists() or link.is_symlink():
                link.unlink()
            link.symlink_to(dest / "searchsploit")
            return True
        except OSError:
            return False
    return False


def ensure_seclists(pm: str, runner: CommandRunner) -> dict[str, str]:
    candidates = [
        Path("/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt"),
        Path("/opt/homebrew/share/seclists/Discovery/Web-Content/raft-medium-words.txt"),
        Path.home() / ".local/share/SecLists/Discovery/Web-Content/raft-medium-words.txt",
    ]
    for path in candidates:
        if path.exists():
            return {"component": "SecLists", "status": "OK", "version": str(path), "manual": ""}

    installed = False
    if pm == "apt":
        installed = _apt_install("seclists", runner)
    elif pm == "brew":
        # SecLists is not consistently available as a Homebrew formula across environments.
        if shutil.which("git"):
            dest = Path.home() / ".local/share/SecLists"
            dest.parent.mkdir(parents=True, exist_ok=True)
            installed = runner.run(
                ["git", "clone", "--depth", "1", "https://github.com/danielmiessler/SecLists.git", str(dest)],
                timeout=1800,
                phase="Install SecLists",
            ).returncode == 0
    elif shutil.which("git"):
        dest = Path.home() / ".local/share/SecLists"
        dest.parent.mkdir(parents=True, exist_ok=True)
        installed = runner.run(
            ["git", "clone", "--depth", "1", "https://github.com/danielmiessler/SecLists.git", str(dest)],
            timeout=1800,
            phase="Install SecLists",
        ).returncode == 0

    for path in candidates:
        if path.exists():
            return {"component": "SecLists", "status": "OK", "version": str(path), "manual": ""}
    manual = "git clone --depth 1 https://github.com/danielmiessler/SecLists.git ~/.local/share/SecLists"
    return {"component": "SecLists", "status": "MISSING", "version": "", "manual": manual}


def _tool_path(spec: dict[str, Any]) -> str | None:
    found = which_any(spec["bins"])
    if found:
        return found
    # User-local fallback paths used by the generic bootstrapper.
    fallback_dirs = [
        Path.home() / ".local/bin",
        Path.home() / "go/bin",
        Path.home() / ".cargo/bin",
    ]
    for directory in fallback_dirs:
        for name in spec["bins"]:
            path = directory / name
            if path.exists() and os.access(path, os.X_OK):
                return str(path)
    return None


def _version_text(path: str, args: list[str], runner: CommandRunner) -> str:
    result = runner.run([path, *args], timeout=30, phase=f"Verify {Path(path).name}")
    text = (result.stdout or result.stderr).strip().splitlines()
    return text[0][:180] if text else f"exit {result.returncode}"


def dependency_health_check(output_root: Path, *, auto_install: bool, first_launch: bool) -> list[dict[str, str]]:
    logs_dir = output_root / "_bootstrap" / "logs"
    runner = CommandRunner(logs_dir)
    pm = detect_package_manager()
    rows = _install_python_libs(runner)

    if pm == "apt" and auto_install:
        # One package-index refresh is more predictable than repeating it per dependency.
        runner.run(_sudo_prefix() + ["apt-get", "update"], timeout=900, phase="Refresh apt package index")

    for tool, spec in TOOL_SPECS.items():
        path = _tool_path(spec)
        if not path and auto_install:
            package = spec.get(pm)
            installed = False
            if pm == "apt" and package:
                installed = _apt_install(str(package), runner)
            elif pm == "brew" and package:
                installed = _brew_install(str(package), runner)
            elif pm == "generic":
                installed = _try_generic_install(tool, runner)

            # Some Debian/Ubuntu/Homebrew repositories do not carry every offensive-security
            # utility. Fall back to the vendor/user-local installer where it is deterministic.
            if not installed and pm in {"apt", "brew"} and tool in {"nuclei", "gobuster", "feroxbuster", "testssl", "searchsploit", "sslyze"}:
                installed = _try_generic_install(tool, runner)
            if installed:
                path = _tool_path(spec)

        if path:
            version = _version_text(path, list(spec.get("version", [])), runner)
            rows.append({"component": tool, "status": "OK", "version": version, "manual": ""})
        else:
            rows.append({
                "component": tool,
                "status": "MISSING",
                "version": "",
                "manual": _manual_install(tool, pm),
            })

    rows.append(ensure_seclists(pm, runner) if auto_install else ensure_seclists("none", runner))

    nuclei = _tool_path(TOOL_SPECS["nuclei"])
    if nuclei and first_launch:
        # Template update is intentionally only automatic during the authorized first-run bootstrap.
        runner.run([nuclei, "-update-templates"], timeout=1200, phase="Update nuclei templates")

    return rows


def print_health_table(rows: list[dict[str, str]]) -> None:
    try:
        from rich.console import Console
        from rich.table import Table

        console = Console()
        table = Table(title="Environment health check")
        table.add_column("Component")
        table.add_column("Status")
        table.add_column("Version / path")
        table.add_column("Manual action if missing")
        for row in rows:
            status = "[green]✅ OK[/green]" if row["status"] == "OK" else "[red]❌ Missing[/red]"
            table.add_row(row["component"], status, row["version"], row["manual"])
        console.print(table)
    except Exception:
        for row in rows:
            mark = "OK" if row["status"] == "OK" else "MISSING"
            print(f"{row['component']:<20} {mark:<8} {row['version']} {row['manual']}")
