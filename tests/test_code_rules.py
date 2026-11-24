import ast
from collections.abc import Iterator
from itertools import chain
from pathlib import Path
import textwrap

ROOT = Path(__file__).resolve().parents[1]
SOURCE_FILES = tuple(
    chain.from_iterable((ROOT / name).rglob("*.py") for name in ("fastapi_fin", "examples"))
)

_LOOP_NODES = (
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.ListComp,
    ast.SetComp,
    ast.DictComp,
    ast.GeneratorExp,
)
_SCOPE_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)


def nested_loop_lines(source: str) -> list[int]:
    """Line numbers of loops nested in loops, and of comprehensions with several ``for``."""
    return list(_walk(ast.parse(source), depth=0))


def _walk(node: ast.AST, depth: int) -> Iterator[int]:
    if isinstance(node, _SCOPE_NODES):
        depth = 0  # A nested function body runs on its own call, not once per iteration.
    if isinstance(node, _LOOP_NODES):
        if depth > 0 or len(getattr(node, "generators", ())) > 1:
            yield node.lineno
        depth += 1
    yield from chain.from_iterable(_walk(child, depth) for child in ast.iter_child_nodes(node))


def _offenders_in(path: Path) -> list[str]:
    lines = nested_loop_lines(path.read_text(encoding="utf-8"))
    return [f"{path.relative_to(ROOT)}:{line}" for line in lines]


def test_nested_loop_detector_flags_inner_loops_and_multi_clause_comprehensions() -> None:
    source = textwrap.dedent(
        """\
        for a in b:
            for c in d:
                pass
        values = [x for x in a for y in b]
        def outer():
            for a in b:
                pass
        """
    )

    assert nested_loop_lines(source) == [2, 4]


def test_library_and_examples_have_no_nested_loops() -> None:
    offenders = list(chain.from_iterable(map(_offenders_in, SOURCE_FILES)))

    assert offenders == []
