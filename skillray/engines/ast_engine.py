"""Python AST-based analysis engine."""

from __future__ import annotations

import ast
from pathlib import Path

from .base import BaseEngine
from ..models import Finding, TargetType, Severity, ThreatCategory


class ASTEngine(BaseEngine):
    name = "ast"

    def scan(self, file_path: Path, content: str, target: TargetType) -> list[Finding]:
        if target not in (TargetType.SCRIPT, TargetType.ANY):
            return []
        if not str(file_path).endswith(".py"):
            return []

        try:
            tree = ast.parse(content, filename=str(file_path))
        except SyntaxError:
            return []

        findings: list[Finding] = []
        visitor = _SecurityVisitor(str(file_path), findings)
        visitor.visit(tree)
        return findings


class _SecurityVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str, findings: list[Finding]):
        self.file_path = file_path
        self.findings = findings

    def visit_Call(self, node: ast.Call) -> None:
        self._check_eval_exec(node)
        self._check_shell_true(node)
        self._check_os_system(node)
        self._check_dynamic_import(node)
        self._check_subprocess_fstring(node)
        self.generic_visit(node)

    def _check_eval_exec(self, node: ast.Call) -> None:
        func = node.func
        name = None
        if isinstance(func, ast.Name):
            name = func.id
        elif isinstance(func, ast.Attribute):
            name = func.attr

        if name in ("eval", "exec"):
            # Check if the argument is a variable (user-controllable)
            if node.args:
                arg = node.args[0]
                if isinstance(arg, (ast.Name, ast.JoinedStr, ast.BinOp, ast.Call)):
                    self.findings.append(Finding(
                        rule_id="SR-EXEC-001",
                        category=ThreatCategory.CODE_EXECUTION,
                        severity=Severity.CRITICAL,
                        title="eval/exec with potentially user-controllable input",
                        file=self.file_path,
                        line=node.lineno,
                        evidence=f"{name}() call with dynamic argument",
                        recommendation="Replace eval/exec with structured parsing or dispatch.",
                        engine="ast",
                    ))

    def _check_shell_true(self, node: ast.Call) -> None:
        func = node.func
        if not isinstance(func, ast.Attribute):
            return
        if not isinstance(func.value, ast.Name) or func.value.id != "subprocess":
            return
        if func.attr not in ("run", "Popen", "call", "check_call", "check_output"):
            return

        for kw in node.keywords:
            if kw.arg == "shell":
                if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    # Check if command is dynamic
                    if node.args:
                        arg = node.args[0]
                        if isinstance(arg, (ast.JoinedStr, ast.BinOp, ast.Name)):
                            self.findings.append(Finding(
                                rule_id="SR-EXEC-002",
                                category=ThreatCategory.CODE_EXECUTION,
                                severity=Severity.HIGH,
                                title="subprocess with shell=True and dynamic command",
                                file=self.file_path,
                                line=node.lineno,
                                evidence=f"subprocess.{func.attr}(..., shell=True) with variable input",
                                recommendation="Use argument lists instead of shell=True with string commands.",
                                engine="ast",
                            ))

    def _check_os_system(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name) and func.value.id == "os" and func.attr == "system":
                self.findings.append(Finding(
                    rule_id="SR-EXEC-001",
                    category=ThreatCategory.CODE_EXECUTION,
                    severity=Severity.HIGH,
                    title="os.system() call detected",
                    file=self.file_path,
                    line=node.lineno,
                    evidence="os.system() — prefer subprocess with argument list",
                    recommendation="Use subprocess.run() with argument lists instead of os.system().",
                    engine="ast",
                ))

    def _check_dynamic_import(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Name) and func.id == "__import__":
            if node.args and isinstance(node.args[0], (ast.Name, ast.JoinedStr, ast.BinOp)):
                self.findings.append(Finding(
                    rule_id="SR-EXEC-004",
                    category=ThreatCategory.CODE_EXECUTION,
                    severity=Severity.HIGH,
                    title="Dynamic import from untrusted source",
                    file=self.file_path,
                    line=node.lineno,
                    evidence="__import__() with dynamic module name",
                    recommendation="Use static imports or validated importlib.import_module().",
                    engine="ast",
                ))

    def _check_subprocess_fstring(self, node: ast.Call) -> None:
        func = node.func
        if not isinstance(func, ast.Attribute):
            return
        if not isinstance(func.value, ast.Name) or func.value.id != "subprocess":
            return
        if func.attr not in ("run", "Popen", "call", "check_call", "check_output"):
            return

        if node.args and isinstance(node.args[0], ast.JoinedStr):
            self.findings.append(Finding(
                rule_id="SR-EXEC-002",
                category=ThreatCategory.CODE_EXECUTION,
                severity=Severity.HIGH,
                title="Command built dynamically with f-string before execution",
                file=self.file_path,
                line=node.lineno,
                evidence=f"subprocess.{func.attr}(f'...') — dynamic command construction",
                recommendation="Build command tokens explicitly; avoid f-string commands.",
                engine="ast",
            ))

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._check_suspicious_import(alias.name, node.lineno)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            self._check_suspicious_import(node.module, node.lineno)
        self.generic_visit(node)

    def _check_suspicious_import(self, module: str, lineno: int) -> None:
        suspicious = {
            "ctypes": "Low-level memory access via ctypes",
            "pickle": "Insecure deserialization via pickle",
        }
        if module in suspicious:
            self.findings.append(Finding(
                rule_id="SR-SUPPLY-004",
                category=ThreatCategory.SUPPLY_CHAIN,
                severity=Severity.MEDIUM,
                title=suspicious[module],
                file=self.file_path,
                line=lineno,
                evidence=f"import {module}",
                recommendation="Ensure usage of this module is necessary and inputs are trusted.",
                engine="ast",
            ))
