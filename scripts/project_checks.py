"""Static release checks that do not require third-party analyzers."""

from __future__ import annotations

import argparse
import ast
import io
import tokenize
from collections import defaultdict
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src"


def module_name(path: Path) -> str:
    """Convert a source path to its importable module name."""

    relative = path.relative_to(PROJECT_ROOT).with_suffix("")
    parts = list(relative.parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def local_import_graph() -> dict[str, set[str]]:
    """Build an import graph containing only modules under ``src``."""

    paths = list(SOURCE_ROOT.rglob("*.py"))
    modules = {module_name(path): path for path in paths}
    graph: dict[str, set[str]] = {name: set() for name in modules}

    for name, path in modules.items():
        tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
        for node in ast.walk(tree):
            candidates: list[str] = []
            if isinstance(node, ast.Import):
                candidates.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                candidates.append(node.module)
            for candidate in candidates:
                while candidate:
                    if candidate in modules and candidate != name:
                        graph[name].add(candidate)
                        break
                    candidate = candidate.rpartition(".")[0]
    return graph


def find_import_cycles() -> list[tuple[str, ...]]:
    """Return normalized cycles from the local source import graph."""

    graph = local_import_graph()
    active: list[str] = []
    active_set: set[str] = set()
    visited: set[str] = set()
    cycles: set[tuple[str, ...]] = set()

    def visit(node: str) -> None:
        if node in active_set:
            start = active.index(node)
            cycle = active[start:]
            rotations = [
                tuple(cycle[index:] + cycle[:index]) for index in range(len(cycle))
            ]
            cycles.add(min(rotations))
            return
        if node in visited:
            return
        active.append(node)
        active_set.add(node)
        for dependency in sorted(graph[node]):
            visit(dependency)
        active.pop()
        active_set.remove(node)
        visited.add(node)

    for module in sorted(graph):
        visit(module)
    return sorted(cycles)


def find_unresolved_comments() -> list[tuple[Path, int, str]]:
    """Locate unresolved maintenance markers in Python comments."""

    markers = ("TO" + "DO", "FIX" + "ME")
    findings: list[tuple[Path, int, str]] = []
    for path in SOURCE_ROOT.rglob("*.py"):
        source = path.read_text(encoding="utf-8-sig")
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type == tokenize.COMMENT and any(
                marker in token.string.upper() for marker in markers
            ):
                findings.append(
                    (path.relative_to(PROJECT_ROOT), token.start[0], token.string)
                )
    return findings


def find_missing_public_docstrings() -> list[tuple[Path, int, str]]:
    """Report public top-level classes and functions without docstrings."""

    findings: list[tuple[Path, int, str]] = []
    for path in SOURCE_ROOT.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
        for node in tree.body:
            if not isinstance(
                node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
            ):
                continue
            if node.name.startswith("_") or ast.get_docstring(node):
                continue
            findings.append((path.relative_to(PROJECT_ROOT), node.lineno, node.name))
    return findings


def main(argv: list[str] | None = None) -> int:
    """Run release checks and print actionable findings."""

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--strict-docstrings",
        action="store_true",
        help="treat missing public API docstrings as an error",
    )
    arguments = parser.parse_args(argv)
    failures: dict[str, list[object]] = defaultdict(list)
    failures["import cycles"].extend(find_import_cycles())
    failures["maintenance comments"].extend(find_unresolved_comments())
    if arguments.strict_docstrings:
        failures["public docstrings"].extend(find_missing_public_docstrings())

    active_failures = {name: values for name, values in failures.items() if values}
    if not active_failures:
        print("Project checks passed")
        return 0
    for name, values in active_failures.items():
        print(f"{name}:")
        for value in values:
            print(f"  {value}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
