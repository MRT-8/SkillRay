"""Tests for the entropy engine."""

from pathlib import Path

from skillray.engines.entropy_engine import EntropyEngine
from skillray.models import TargetType


def test_detects_aws_key():
    engine = EntropyEngine()
    content = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'
    findings = engine.scan(Path("config.py"), content, TargetType.SCRIPT)
    rule_ids = [f.rule_id for f in findings]
    assert "SR-CRED-005" in rule_ids


def test_detects_github_token():
    engine = EntropyEngine()
    content = 'token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"'
    findings = engine.scan(Path("config.py"), content, TargetType.SCRIPT)
    rule_ids = [f.rule_id for f in findings]
    assert "SR-CRED-005" in rule_ids


def test_detects_openai_key():
    engine = EntropyEngine()
    content = 'OPENAI_KEY = "sk-abcdefghijklmnopqrstuvwxyz"'
    findings = engine.scan(Path("config.py"), content, TargetType.SCRIPT)
    rule_ids = [f.rule_id for f in findings]
    assert "SR-CRED-005" in rule_ids


def test_detects_private_key():
    engine = EntropyEngine()
    content = '-----BEGIN RSA PRIVATE KEY-----\nMIIE...'
    findings = engine.scan(Path("key.pem"), content, TargetType.ANY)
    rule_ids = [f.rule_id for f in findings]
    assert "SR-CRED-001" in rule_ids


def test_benign_no_secrets():
    engine = EntropyEngine()
    content = '''
name = "my-project"
version = "1.0.0"
debug = True
count = 42
'''
    findings = engine.scan(Path("config.py"), content, TargetType.SCRIPT)
    assert len(findings) == 0


def test_detects_high_entropy_secret():
    engine = EntropyEngine()
    content = 'api_key = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0"'
    findings = engine.scan(Path("config.py"), content, TargetType.SCRIPT)
    # Should detect as high-entropy secret
    assert any(f.rule_id in ("SR-CRED-001", "SR-CRED-005") for f in findings)


def test_masks_evidence():
    engine = EntropyEngine()
    content = 'token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"'
    findings = engine.scan(Path("config.py"), content, TargetType.SCRIPT)
    for f in findings:
        # Evidence should be masked
        assert "****" in f.evidence or "**" in f.evidence
