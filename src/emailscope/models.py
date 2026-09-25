"""Shared result types passed between collection modules and the report layer."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITY_ORDER = {"hit": 0, "info": 1, "unknown": 2, "skip": 3, "error": 4}


@dataclass
class Finding:
    """One collected result from a module.

    ``status`` drives how the report renders the block:
    ``hit`` data was found, ``info`` the module ran but found nothing notable,
    ``skip`` the module was disabled or lacks credentials, ``error`` it failed.
    """

    module: str
    title: str
    status: str = "info"
    summary: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    links: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Case:
    """Everything known about one investigated email address."""

    email: str
    findings: list[Finding] = field(default_factory=list)

    def add(self, finding: Finding) -> Finding:
        self.findings.append(finding)
        return finding

    def get(self, module: str) -> Finding | None:
        for finding in self.findings:
            if finding.module == module:
                return finding
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "email": self.email,
            "findings": [f.to_dict() for f in self.findings],
        }
