from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any


@dataclass
class ServiceRecord:
    host: str
    port: int
    protocol: str
    state: str
    service: str
    version: str
    product: str
    tunnel: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    port: int
    service: str
    version: str
    possible_cve: str
    severity: str
    source: str
    manual_recheck_command: str
    evidence: str = ""
    reference_url: str = ""

    def csv_dict(self) -> dict[str, str | int]:
        return {
            "port": self.port,
            "service": self.service,
            "version": self.version,
            "possible_cve": self.possible_cve,
            "severity": self.severity,
            "source": self.source,
            "manual_recheck_command": self.manual_recheck_command,
        }
