from __future__ import annotations

import json
from pathlib import Path
from typing import Any


DEFAULT_CONFIG = Path(__file__).resolve().parent.parent / "config.json"


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    config_path = Path(path) if path else DEFAULT_CONFIG
    with config_path.open("r", encoding="utf-8") as handle:
        cfg = json.load(handle)

    timing = str(cfg.get("safety", {}).get("nmap_timing", "T3")).upper()
    if timing not in {"T3", "T4"}:
        raise ValueError("safety.nmap_timing must be T3 or T4. T5 is intentionally unsupported.")

    max_cidr_hosts = int(cfg.get("safety", {}).get("max_cidr_hosts", 256))
    if not 1 <= max_cidr_hosts <= 4096:
        raise ValueError("safety.max_cidr_hosts must be between 1 and 4096.")

    threads = int(cfg.get("web", {}).get("threads", 20))
    if not 1 <= threads <= 50:
        raise ValueError("web.threads must be between 1 and 50.")

    return cfg
