"""Base engine protocol and utilities."""

from __future__ import annotations

from pathlib import Path
from abc import ABC, abstractmethod

from ..models import Finding, TargetType


class BaseEngine(ABC):
    """Abstract base for all detection engines."""

    name: str = "base"

    @abstractmethod
    def scan(self, file_path: Path, content: str, target: TargetType) -> list[Finding]:
        ...
