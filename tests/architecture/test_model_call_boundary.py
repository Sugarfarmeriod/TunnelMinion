"""锁定迁移前模型调用清单，防止新增未登记的 Provider 直调。"""

from __future__ import annotations

import ast
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).parents[2]
SOURCE = ROOT / "src" / "tunnelminion"

_RAW_PROVIDER_BOUNDARY = Counter({("agent/context_runtime.py", "invoke"): 1})
_MODEL_REQUEST_BOUNDARY = Counter({("agent/context_runtime.py", "build"): 1})


class _CallVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.functions: list[str] = []
        self.provider_calls: Counter[tuple[str, str]] = Counter()
        self.request_constructions: Counter[tuple[str, str]] = Counter()
        self.relative_path = ""

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.functions.append(node.name)
        self.generic_visit(node)
        self.functions.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.functions.append(node.name)
        self.generic_visit(node)
        self.functions.pop()

    def visit_Call(self, node: ast.Call) -> None:
        function = self.functions[-1] if self.functions else "<module>"
        if isinstance(node.func, ast.Attribute) and node.func.attr == "complete":
            self.provider_calls[(self.relative_path, function)] += 1
        if isinstance(node.func, ast.Name) and node.func.id == "ModelRequest":
            self.request_constructions[(self.relative_path, function)] += 1
        self.generic_visit(node)


def test_production_provider_calls_match_migration_inventory() -> None:
    visitor = _CallVisitor()
    for path in SOURCE.rglob("*.py"):
        visitor.relative_path = path.relative_to(SOURCE).as_posix()
        visitor.visit(ast.parse(path.read_text(encoding="utf-8")))

    assert visitor.provider_calls == _RAW_PROVIDER_BOUNDARY
    assert visitor.request_constructions == _MODEL_REQUEST_BOUNDARY


def test_scripted_model_is_isolated_from_production_runtime() -> None:
    occurrences: list[str] = []
    for path in ROOT.rglob("*.py"):
        if any(part in {".venv", ".git"} for part in path.parts):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        if any(
            isinstance(node, ast.ClassDef) and node.name == "FakeModel" for node in ast.walk(tree)
        ):
            occurrences.append(path.relative_to(ROOT).as_posix())

    assert occurrences == ["src/tunnelminion/evaluation/fakes.py"]
