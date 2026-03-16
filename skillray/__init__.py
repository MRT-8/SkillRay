"""SkillRay — AI Skill Security Scanner."""

__all__ = ["__version__", "scan"]
__version__ = "2.0.0"

from .scanner import scan_path as scan
