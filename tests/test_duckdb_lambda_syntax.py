"""DuckDB 2.0 rejects single-arrow list lambdas (``x -> expr``) by default.

Two guards:

* hand-written SQL in the package must use ``lambda x: expr``;
* ``Case.table()`` hands out ibis tables, and ibis (12.x) still compiles array
  ``.map()`` / ``.filter()`` to the arrow form, so its connection must accept it.
"""

import re
from pathlib import Path

import pyarrow as pa
import pytest

from memdiver.analysis.case import Case

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
SCANNED_DIRS = ("analysis", "core", "app", "api", "mcp_server", "cli")
#: ``list_filter(xs, x -> ...)``, ``list_transform(xs, (x, i) -> ...)`` and friends.
ARROW_LAMBDA = re.compile(r"\blist_\w+\s*\([^()]*,\s*(\w+|\(\s*\w+(\s*,\s*\w+)*\s*\))\s*->",
                          re.IGNORECASE)


def _code_lines(path: Path):
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        code = line.split("#", 1)[0]
        if code.strip():
            yield number, code


def test_arrow_lambda_pattern_matches_known_forms():
    assert ARROW_LAMBDA.search("list_filter(xs, x -> x > 1)")
    assert ARROW_LAMBDA.search("LIST_APPLY(xs, (x, i) -> x + i)")
    assert not ARROW_LAMBDA.search("list_filter(xs, lambda x: x > 1)")
    assert not ARROW_LAMBDA.search("def f(xs) -> list:")


def test_package_sql_uses_lambda_keyword_syntax():
    offenders = [
        f"{path.relative_to(PACKAGE_ROOT)}:{number}"
        for folder in SCANNED_DIRS
        for path in sorted((PACKAGE_ROOT / folder).rglob("*.py"))
        for number, code in _code_lines(path)
        if ARROW_LAMBDA.search(code)
    ]
    assert not offenders, f"use `lambda x: expr`, not `x -> expr`: {offenders}"


@pytest.fixture
def list_case(tmp_path):
    pytest.importorskip("ibis")
    case = Case.init(tmp_path / "c")
    table = pa.table({"vals": pa.array([[1, 2, 3], [4]], pa.list_(pa.int64()))})
    case.register_table("t", table, capture_id="c", producer="x")
    return case


def test_ibis_array_map_runs_on_case_table(list_case):
    vals = list_case.table("t").vals
    assert vals.map(lambda x: x + 1).name("r").execute().tolist() == [[2, 3, 4], [5]]


def test_ibis_array_filter_runs_on_case_table(list_case):
    vals = list_case.table("t").vals
    assert vals.filter(lambda x: x > 1).name("r").execute().tolist() == [[2, 3], [4]]
