"""Shared test fixtures."""

from pathlib import Path

import pytest


@pytest.fixture
def samples_dir() -> Path:
    return Path(__file__).parent / "samples"


@pytest.fixture
def malicious_dir(samples_dir: Path) -> Path:
    return samples_dir / "malicious"


@pytest.fixture
def benign_dir(samples_dir: Path) -> Path:
    return samples_dir / "benign"
