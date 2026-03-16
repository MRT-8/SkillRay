"""Tests for the AST engine."""

from pathlib import Path

from skillray.engines.ast_engine import ASTEngine
from skillray.models import TargetType


def test_detects_eval_with_variable():
    engine = ASTEngine()
    content = '''
user_input = input("cmd: ")
eval(user_input)
'''
    findings = engine.scan(Path("test.py"), content, TargetType.SCRIPT)
    rule_ids = [f.rule_id for f in findings]
    assert "SR-EXEC-001" in rule_ids


def test_detects_shell_true_dynamic():
    engine = ASTEngine()
    content = '''
import subprocess
cmd = f"ls {user_dir}"
subprocess.run(cmd, shell=True)
'''
    findings = engine.scan(Path("test.py"), content, TargetType.SCRIPT)
    rule_ids = [f.rule_id for f in findings]
    assert "SR-EXEC-002" in rule_ids


def test_detects_os_system():
    engine = ASTEngine()
    content = '''
import os
os.system("ls -la")
'''
    findings = engine.scan(Path("test.py"), content, TargetType.SCRIPT)
    rule_ids = [f.rule_id for f in findings]
    assert "SR-EXEC-001" in rule_ids


def test_detects_dynamic_import():
    engine = ASTEngine()
    content = '''
module_name = input("module: ")
__import__(module_name)
'''
    findings = engine.scan(Path("test.py"), content, TargetType.SCRIPT)
    rule_ids = [f.rule_id for f in findings]
    assert "SR-EXEC-004" in rule_ids


def test_ignores_non_python():
    engine = ASTEngine()
    content = "echo hello"
    findings = engine.scan(Path("test.sh"), content, TargetType.SCRIPT)
    assert len(findings) == 0


def test_benign_python_no_findings():
    engine = ASTEngine()
    content = '''
import json
from pathlib import Path

def load_config(path: str) -> dict:
    with open(path) as f:
        return json.load(f)

config = load_config("config.json")
print(config)
'''
    findings = engine.scan(Path("test.py"), content, TargetType.SCRIPT)
    assert len(findings) == 0


def test_eval_with_literal_ok():
    """eval with a string literal is less dangerous."""
    engine = ASTEngine()
    content = 'result = eval("2 + 2")'
    findings = engine.scan(Path("test.py"), content, TargetType.SCRIPT)
    # String literal args should NOT be flagged
    assert not any(f.rule_id == "SR-EXEC-001" and "eval" in f.title for f in findings)


def test_subprocess_fstring():
    engine = ASTEngine()
    content = '''
import subprocess
user = "admin"
subprocess.run(f"whoami {user}", shell=True)
'''
    findings = engine.scan(Path("test.py"), content, TargetType.SCRIPT)
    rule_ids = [f.rule_id for f in findings]
    assert "SR-EXEC-002" in rule_ids
