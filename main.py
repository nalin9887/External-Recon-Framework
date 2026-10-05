#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from reconfw.bootstrap import (
    dependency_health_check,
    is_first_launch,
    mark_bootstrap_complete,
    print_health_table,
)
from reconfw.config import load_config
from reconfw.pipeline import scan_target
from reconfw.report import generate_report
from reconfw.utils import PROCESS_REGISTRY, expand_target, validate_target


AUTH_PHRASE = "I CONFIRM AUTHORIZATION"
T4_PHRASE = "I UNDERSTAND T4 RISK"


def authorization_gate() -> None:
    banner = r"""
==========================================================================
 AUTHORIZED EXTERNAL RECON & VULNERABILITY-IDENTIFICATION FRAMEWORK
==========================================================================
 Use only against systems for which you have explicit written permission.
 This framework performs network reconnaissance, service fingerprinting,
 rate-limited web enumeration, TLS checks, and identification-only CVE
 correlation. It does NOT authorize testing by itself.

 No command-line flag, config value, or environment variable bypasses this gate.
==========================================================================
"""
    print(banner)
    confirmation = input(f"Type exactly '{AUTH_PHRASE}' to continue: ").strip()
    if confirmation != AUTH_PHRASE:
        print("Authorization confirmation not provided. Exiting without network activity.")
        raise SystemExit(2)


def _console() -> Any | None:
    try:
        from rich.console import Console
        return Console()
    except Exception:
        return None


def _print(console: Any | None, text: str) -> None:
    if console:
        console.print(text)
    else:
        print(text)


def entry_menu() -> str:
    print("[1] Enter a single target (domain or IP)")
    print("[2] Load a list of targets from file (IPs/domains, one per line)")
    print("[3] Install / verify dependencies & run environment health check")
    return input("Select [1-3]: ").strip()


def _collect_single(config: dict[str, Any]) -> list[str]:
    raw = input("Target (hostname, IP, or CIDR): ").strip()
    canonical = validate_target(raw)
    return expand_target(canonical, int(config["safety"].get("max_cidr_hosts", 256)))


def _collect_file(config: dict[str, Any], console: Any | None) -> list[str]:
    path = Path(input("Target list file: ").strip()).expanduser()
    if not path.is_file():
        raise ValueError(f"target list does not exist: {path}")
    targets: list[str] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        try:
            canonical = validate_target(value)
            targets.extend(expand_target(canonical, int(config["safety"].get("max_cidr_hosts", 256))))
        except ValueError as exc:
            _print(console, f"[yellow]Skipping invalid target on line {line_no}: {value!r} ({exc})[/yellow]" if console else f"Skipping invalid target on line {line_no}: {value!r} ({exc})")
    # Preserve order while removing duplicates.
    return list(dict.fromkeys(targets))


def choose_scan_profile() -> str:
    print("\nNmap scan profile:")
    print("[1] Top 100 ports   (--top-ports 100)")
    print("[2] Top 1000 ports  (default nmap behavior)")
    print("[3] Full port range (-p-)")
    choice = input("Select [1-3], default 2: ").strip() or "2"
    mapping = {"1": "top100", "2": "top1000", "3": "full"}
    if choice not in mapping:
        raise ValueError("invalid Nmap profile selection")
    return mapping[choice]


def choose_wordlist_profile() -> str:
    print("\nWeb content wordlist (used only if an HTTP service is found):")
    print("[1] raft-small-words")
    print("[2] raft-medium-words (default)")
    print("[3] raft-large-words")
    choice = input("Select [1-3], default 2: ").strip() or "2"
    mapping = {"1": "small", "2": "medium", "3": "large"}
    if choice not in mapping:
        raise ValueError("invalid wordlist selection")
    return mapping[choice]


def choose_timing(config: dict[str, Any]) -> str:
    configured = str(config.get("safety", {}).get("nmap_timing", "T3")).upper()
    if configured == "T4":
        print("\nconfig.json requests Nmap T4. T4 is never used without an explicit risk confirmation.")
        if input(f"Type exactly '{T4_PHRASE}' to permit T4 for this run: ").strip() == T4_PHRASE:
            return "T4"
        print("T4 confirmation not provided; falling back to T3.")
        return "T3"

    request = input("\nUse faster Nmap T4 instead of safe default T3? [y/N]: ").strip().lower()
    if request == "y":
        if not bool(config.get("safety", {}).get("allow_t4_with_explicit_confirmation", True)):
            print("T4 is disabled by config; using T3.")
            return "T3"
        confirmation = input(f"Type exactly '{T4_PHRASE}' to permit T4 for this run: ").strip()
        if confirmation == T4_PHRASE:
            return "T4"
        print("T4 confirmation not provided; using T3.")
    return "T3"


def main() -> int:
    # This must be the first interactive action. Nothing before it performs network I/O.
    authorization_gate()
    config = load_config()
    console = _console()
    output_root = Path(str(config.get("output_root", "output"))).expanduser()

    first = is_first_launch()
    choice = entry_menu()
    if choice == "3":
        rows = dependency_health_check(output_root, auto_install=True, first_launch=first)
        print_health_table(rows)
        if first:
            mark_bootstrap_complete()
        return 0

    if first and choice in {"1", "2"}:
        _print(console, "[cyan]First launch: running the dependency bootstrap after authorization confirmation.[/cyan]" if console else "First launch: running the dependency bootstrap after authorization confirmation.")
        rows = dependency_health_check(output_root, auto_install=True, first_launch=True)
        print_health_table(rows)
        mark_bootstrap_complete()
        # Rich may have been installed during bootstrap.
        console = _console()
    if choice not in {"1", "2"}:
        print("Invalid selection.")
        return 2

    try:
        targets = _collect_single(config) if choice == "1" else _collect_file(config, console)
    except ValueError as exc:
        _print(console, f"[red]{exc}[/red]" if console else str(exc))
        return 2
    if not targets:
        print("No valid targets supplied.")
        return 2

    scan_profile = choose_scan_profile()
    wordlist_profile = choose_wordlist_profile()
    timing = choose_timing(config)

    _print(console, f"\n[bold]Validated targets:[/bold] {len(targets)}" if console else f"\nValidated targets: {len(targets)}")
    completed: list[Path] = []
    try:
        for index, target in enumerate(targets, start=1):
            _print(console, f"\n[bold cyan]Target {index}/{len(targets)}: {target}[/bold cyan]" if console else f"\nTarget {index}/{len(targets)}: {target}")
            target_dir = scan_target(target, config, scan_profile, timing, wordlist_profile, console=console)
            completed.append(target_dir)
            report = target_dir / "report.html"
            _print(console, f"[green]Report:[/green] {report}" if console else f"Report: {report}")
    except KeyboardInterrupt:
        PROCESS_REGISTRY.terminate_all()
        print("\nInterrupted. Child processes terminated; partial target results were retained and report generation was attempted.")
        return 130
    finally:
        PROCESS_REGISTRY.terminate_all()

    print(f"\nCompleted {len(completed)} target(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
