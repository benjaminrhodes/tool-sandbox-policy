"""Policy engine for sandboxed tool access."""

import fnmatch
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, List


@dataclass
class PolicyViolation:
    """Result of a policy access check."""

    allowed: bool
    resource_type: str
    resource_path: str
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "resource_type": self.resource_type,
            "resource_path": self.resource_path,
            "reason": self.reason,
        }


class Policy:
    """Defines sandbox access policies."""

    def __init__(
        self,
        name: str = "default",
        allowed_file_paths: Optional[List[str]] = None,
        allowed_domains: Optional[List[str]] = None,
        strict: bool = False,
    ):
        self.name = name
        self.allowed_file_paths = allowed_file_paths or []
        self.allowed_domains = allowed_domains or []
        self.strict = strict

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "allowed_file_paths": self.allowed_file_paths,
            "allowed_domains": self.allowed_domains,
            "strict": self.strict,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Policy":
        name = data.get("name", "default")
        if not isinstance(name, str):
            raise ValueError(f"Policy name must be a string, got {type(name).__name__}")
        return cls(
            name=name,
            allowed_file_paths=data.get("allowed_file_paths", []),
            allowed_domains=data.get("allowed_domains", []),
            strict=data.get("strict", False),
        )

    def save(self, path: Path) -> None:
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load(cls, path: Path) -> "Policy":
        with open(path) as f:
            data = json.load(f)
        return cls.from_dict(data)


class PolicyEngine:
    """Validates tool access requests against policies."""

    def __init__(self, policy: Policy):
        self.policy = policy

    def _match_file_pattern(self, path: str, pattern: str) -> bool:
        if "**" in pattern:
            prefix = pattern.split("**")[0]
            return path.startswith(prefix) or fnmatch.fnmatch(path, pattern)
        if "*" in pattern and "**" not in pattern:
            prefix = pattern.rstrip("*").rstrip("/")
            if not path.startswith(prefix):
                return False
            return True
        return fnmatch.fnmatch(path, pattern)

    def check_file_access(self, path: str) -> PolicyViolation:
        if not self.policy.allowed_file_paths:
            return PolicyViolation(
                allowed=False,
                resource_type="file",
                resource_path=path,
                reason="No file paths allowed in policy",
            )

        for allowed in self.policy.allowed_file_paths:
            if self._match_file_pattern(path, allowed):
                return PolicyViolation(
                    allowed=True,
                    resource_type="file",
                    resource_path=path,
                )

        return PolicyViolation(
            allowed=False,
            resource_type="file",
            resource_path=path,
            reason="Path not allowed",
        )

    def _match_domain(self, domain: str, pattern: str) -> bool:
        base_pattern = pattern.rstrip(":").rstrip("0-9")
        if pattern.startswith("*."):
            base = base_pattern[2:]
            return domain == base or domain.endswith("." + base)
        return domain == base_pattern or domain.startswith(base_pattern + ":")

    def check_network_access(self, target: str) -> PolicyViolation:
        if not self.policy.allowed_domains:
            return PolicyViolation(
                allowed=False,
                resource_type="network",
                resource_path=target,
                reason="No domains allowed in policy",
            )

        domain = target.split(":")[0]

        for allowed in self.policy.allowed_domains:
            if self._match_domain(domain, allowed):
                return PolicyViolation(
                    allowed=True,
                    resource_type="network",
                    resource_path=target,
                )

        return PolicyViolation(
            allowed=False,
            resource_type="network",
            resource_path=target,
            reason="Domain not allowed",
        )
