"""Tests for the case data lake (plan T1.8): ``analysis/case.py``."""

import json

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from memdiver.analysis.case import Case, _check_name, _fetch_arrow, snake_case_columns
from memdiver.analysis.record import AnalysisEntry
from memdiver.core.service_errors import CapabilityError, ErrorCategory

KVA = 0xFFFFFFFF82000A20
#: A tables/ directory name that, spliced into CREATE VIEW, runs extra statements.
EVIL_TABLE_DIR = "t AS SELECT 1; CREATE TABLE pwn AS SELECT 42 AS x; CREATE VIEW u"
VOL3_HEADER = ["OFFSET (V)", "PID", "TID", "PPID", "COMM", "UID", "GID", "EUID",
               "EGID", "CREATION TIME", "File output"]


@pytest.fixture
def case(tmp_path):
    return Case.init(tmp_path / "c")


def _procs(pids, sha="aa"):
    return pa.table({"pid": pids, "comm": [f"p{p}" for p in pids]})


def test_init_open_idempotent(tmp_path):
    c = Case.init(tmp_path / "c")
    manifest = (tmp_path / "c" / "case.json").read_text()
    for sub in ("tables", "annotations", "views", "plugins", "isf"):
        assert (tmp_path / "c" / sub).is_dir()
    Case.init(tmp_path / "c")
    assert (tmp_path / "c" / "case.json").read_text() == manifest
    assert Case.open(tmp_path / "c").manifest()["v"] == 1
    assert list(json.loads(manifest)) == ["v", "name", "created"]
    assert c.name == "c"


def test_open_requires_manifest(tmp_path):
    with pytest.raises(CapabilityError) as e:
        Case.open(tmp_path)
    assert e.value.category is ErrorCategory.INVALID_INPUT


def test_bare_name_uses_cases_root(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    c = Case.init("mycase")
    assert c.dir == (tmp_path / "memdiver" / "cases" / "mycase").resolve()


def test_snake_case_vol3_header():
    assert snake_case_columns(VOL3_HEADER) == [
        "offset_v", "pid", "tid", "ppid", "comm", "uid", "gid", "euid", "egid",
        "creation_time", "file_output"]
    assert snake_case_columns(["A b", "a_b", "1x", "!!"]) == [
        "a_b", "a_b_2", "c_1x", "col"]


def test_register_adds_and_casts_standard_columns(case):
    t = pa.table({"PID": pa.array([1, 2], pa.int32()), "Name": ["a", "b"]})
    ref = case.register_table("t", t, capture_id="cap", producer="x",
                              image_sha256="s")
    got = pq.read_table(ref.path)
    assert got.column_names[:7] == ["capture_id", "image_sha256", "pid", "space",
                                    "addr", "size", "run_id"]
    assert got.schema.field("pid").type == pa.int64()
    assert got.schema.field("addr").type == pa.uint64()
    assert got.column("capture_id").to_pylist() == ["cap", "cap"]
    assert got.column("addr").null_count == 2
    assert got.column("run_id").to_pylist() == [ref.run_id] * 2


def test_incompatible_standard_column_renamed(case):
    t = pa.table({"space": [1, 2]})
    ref = case.register_table("t", t, capture_id="c", producer="x")
    got = pq.read_table(ref.path)
    assert got.column("space_src").to_pylist() == [1, 2]
    assert got.column("space").null_count == 2


def test_bad_cast_names_column(case):
    t = pa.table({"addr": pa.array([-1], pa.int64())})
    with pytest.raises(CapabilityError, match="addr"):
        case.register_table("t", t, capture_id="c", producer="x")


def test_bad_table_name_and_space(case):
    t = pa.table({"x": [1]})
    with pytest.raises(CapabilityError):
        case.register_table("Bad-Name", t, capture_id="c", producer="x")
    with pytest.raises(CapabilityError):
        case.register_table("t", t, capture_id="c", producer="x",
                            locations={"x": "nonsense"})


def test_check_name_uses_full_match():
    _check_name("vol3__linux_pslist")
    for bad in ("ok\n", "annotations", "", "Bad", "a" * 97):
        with pytest.raises(CapabilityError):
            _check_name(bad)


def test_invalid_table_dir_is_skipped_not_spliced_into_sql(case):
    case.register_table("ok", _procs([1]), capture_id="c", producer="x")
    run_dir = case.dir / "tables" / EVIL_TABLE_DIR / "r1"
    run_dir.mkdir(parents=True)
    pq.write_table(_procs([9]), run_dir / "evil.parquet")
    assert case.tables() == ["ok"]
    assert case.query("SELECT 1 AS x").table.to_pylist() == [{"x": 1}]
    catalog = case.query("SELECT table_name FROM information_schema.tables ORDER BY 1")
    assert [r["table_name"] for r in catalog.table.to_pylist()] == ["ok"]
    with pytest.raises(CapabilityError):
        case.query("SELECT x FROM pwn")


def test_runs_rejects_names_that_leave_the_tables_dir(case):
    case.register_table("ok", _procs([1]), capture_id="c", producer="x")
    assert len(case.runs("ok")) == 1
    assert case.runs("../tables/ok") == []
    assert case.runs("..") == []


def test_kernel_va_roundtrips(case):
    t = pa.table({"Offset (V)": pa.array([KVA], pa.uint64()),
                  "addr": pa.array([KVA], pa.uint64())})
    ref = case.register_table("p", t, capture_id="c", producer="x",
                              locations={"Offset (V)": "kernel_va"})
    got = pq.read_table(ref.path)
    assert got.column("offset_v").to_pylist() == [KVA]
    assert got.column("addr").to_pylist() == [KVA]
    res = case.query("SELECT addr, offset_v FROM p")
    assert res.table.to_pylist() == [{"addr": KVA, "offset_v": KVA}]
    assert res.to_dict()["rows"] == [[KVA, KVA]]


def test_metadata_and_sidecar(case):
    t = pa.table({"Offset (V)": pa.array([KVA], pa.uint64())})
    ref = case.register_table("vol3__x", t, capture_id="c", producer="vol3",
                              image_sha256="s", file_stem="linux.pslist.PsList",
                              locations={"Offset (V)": "kernel_va"},
                              meta={"k": 1})
    assert ref.path.endswith(f"vol3__x/{ref.run_id}/linux.pslist.PsList.parquet")
    kv = pq.read_schema(ref.path).metadata
    assert json.loads(kv[b"memdiver.locations"]) == {"offset_v": "kernel_va"}
    info = json.loads(kv[b"memdiver.meta"])
    assert info["producer"] == "vol3" and info["v"] == 1
    assert info["meta"] == {"k": 1} and info["image_sha256"] == "s"
    side = json.loads(open(ref.path[:-len(".parquet")] + ".meta.json").read())
    assert side["row_count"] == 1 and "offset_v" in side["columns"]
    assert side["producer"] == "vol3" and side["run_id"] == ref.run_id


def test_two_runs_union(case):
    case.register_table("t", _procs([1]), capture_id="c", producer="x", run_id="r1")
    case.register_table("t", _procs([2, 3]), capture_id="c", producer="x", run_id="r2")
    assert [r.run_id for r in case.runs("t")] == ["r1", "r2"]
    res = case.query("SELECT count(*) AS n, count(DISTINCT run_id) AS r FROM t")
    assert res.table.to_pylist() == [{"n": 3, "r": 2}]


def test_cross_table_join(case):
    case.register_table("a", _procs([1, 2]), capture_id="c", producer="x")
    case.register_table("b", pa.table({"pid": [2, 3], "k": ["x", "y"]}),
                        capture_id="c", producer="x")
    res = case.query("SELECT a.comm, b.k FROM a JOIN b USING (pid)")
    assert res.table.to_pylist() == [{"comm": "p2", "k": "x"}]


def test_group_by_image(case):
    for sha, pids in (("s1", [1, 2]), ("s2", [1])):
        case.register_table("ps", _procs(pids), capture_id=sha,
                            image_sha256=sha, producer="x")
    res = case.query("SELECT image_sha256, count(*) AS n FROM ps "
                     "GROUP BY image_sha256 ORDER BY 1")
    assert res.table.to_pylist() == [{"image_sha256": "s1", "n": 2},
                                     {"image_sha256": "s2", "n": 1}]


@pytest.mark.parametrize("sql", [
    "INSERT INTO t VALUES (1)", "COPY t TO '/tmp/x.csv'",
    "ATTACH '/tmp/x.db'", "SET threads=1", "PRAGMA version",
    "/* c */ PRAGMA version", "-- c\nATTACH '/tmp/x.db'",
    "CREATE TABLE z (a int)", "SELECT 1; SELECT 2", "SELECT 1; DROP VIEW t",
    "", "DROP VIEW t",
])
def test_statement_guard(case, sql):
    case.register_table("t", _procs([1]), capture_id="c", producer="x")
    with pytest.raises(CapabilityError) as e:
        case.query(sql)
    assert e.value.category is ErrorCategory.INVALID_INPUT


@pytest.mark.parametrize("sql", [
    "SELECT 1; -- x\nSELECT 2", "SELECT 1; /* x */ DROP VIEW t",
    "SELECT 1 /* unterminated", "SELECT 1; -- x\nDROP VIEW t",
])
def test_statement_guard_comments_cannot_hide_a_second_statement(case, sql):
    case.register_table("t", _procs([1]), capture_id="c", producer="x")
    with pytest.raises(CapabilityError) as e:
        case.query(sql)
    assert e.value.category is ErrorCategory.INVALID_INPUT
    assert case.query("SELECT count(*) AS n FROM t").table.to_pylist() == [{"n": 1}]


@pytest.mark.parametrize("sql", [
    "SELECT 1 AS x -- note",
    "SELECT 1 AS x; -- note",
    "SELECT 1 AS x;",
    "SELECT 1 AS x ; ;",
    "/* block */ SELECT 1 AS x /* trailing */",
    "/* block */ SELECT 1 AS x; /* after */",
    "SELECT 1 AS x -- one\n-- two\n;  -- three",
    # DuckDB 2.0 tokenizes comments and drops leading ones from the parsed query
    "SELECT 1 AS x /* c */ ;",
    "  SELECT 1 AS x  ",
    "\n-- lead\n  SELECT 1 AS x;",
])
def test_trailing_semicolons_and_comments_are_accepted(case, sql):
    assert case.query(sql).table.to_pylist() == [{"x": 1}]


def test_semicolons_inside_literals_are_kept(case):
    rows = case.query("SELECT 'a;--' AS \"ü;\"; -- é").table.to_pylist()
    assert rows == [{"ü;": "a;--"}]


def test_file_escape_blocked_but_views_work(case, tmp_path):
    case.register_table("t", _procs([1]), capture_id="c", producer="x")
    outside = tmp_path / "outside.csv"
    outside.write_text("a\n1\n")
    assert case.query("SELECT count(*) AS n FROM t").table.to_pylist() == [{"n": 1}]
    for target in ("/etc/passwd", str(outside)):
        with pytest.raises(CapabilityError):
            case.query(f"SELECT * FROM read_csv('{target}')")
    with pytest.raises(CapabilityError):
        case.query("SELECT * FROM read_text('/etc/passwd')")


def test_truncation_flag(case):
    res = case.query("SELECT * FROM range(10)", limit=4)
    assert res.truncated and res.table.num_rows == 4
    assert res.to_dict(max_rows=2)["truncated"] is True
    res = case.query("SELECT * FROM range(4)", limit=4)
    assert not res.truncated and res.table.num_rows == 4


def test_timeout(case):
    with pytest.raises(CapabilityError) as e:
        case.query("SELECT count(*) FROM range(100000) a, range(100000) b, "
                   "range(100000) c", timeout_s=0.2)
    assert e.value.code == "case.query_timeout"


def test_to_dict_json_safe(case):
    res = case.query("SELECT 'ab'::BLOB AS b, TIMESTAMP '2026-01-01 00:00:00' AS ts, "
                     "18446744073709551615::UBIGINT AS u")
    out = res.to_dict()
    assert out["rows"] == [["6162", "2026-01-01T00:00:00", 18446744073709551615]]
    json.dumps(out)


def test_annotations_view(case):
    entries = [AnalysisEntry(capture_id="cap1", kind="annotation", author="human",
                             label=f"n{i}") for i in range(2)]
    path = case.dir / "annotations" / "cap1.jsonl"
    path.write_text("\n".join(e.to_json_line() for e in entries) + "\n")
    res = case.query("SELECT label FROM annotations ORDER BY label")
    assert [r["label"] for r in res.table.to_pylist()] == ["n0", "n1"]
    assert case.schema()["annotations"]["files"] == 1
    assert any(c["name"] == "label" for c in case.schema()["annotations"]["columns"])


def test_schema_shape(case):
    t = pa.table({"Offset (V)": pa.array([KVA], pa.uint64())})
    case.register_table("p", t, capture_id="c", producer="x", run_id="r1",
                        locations={"Offset (V)": "kernel_va"})
    case.register_table("p", t, capture_id="c", producer="x", run_id="r2",
                        locations={"Offset (V)": "kernel_va"})
    sch = case.schema()
    p = sch["tables"]["p"]
    assert p["runs"] == 2 and p["rows"] == 2
    assert p["locations"] == {"offset_v": "kernel_va"}
    assert {"name": "addr", "type": "uint64"} in p["columns"]
    assert sch["annotations"] == {"files": 0, "columns": []}
    assert case.tables() == ["p"]


def test_ibis_table(case):
    case.register_table("t", _procs([1, 2, 3]), capture_id="c", producer="x")
    assert case.table("t").count().execute() == 3
    with pytest.raises(CapabilityError):
        case.table("missing")


def test_query_binds_positional_params_without_formatting(tmp_path):
    case = Case.init(tmp_path / "c")
    case.register_table("t", pa.table({"addr": pa.array([0xFFFFFFFF82000A20, 16], pa.uint64())}),
                        capture_id="cap", producer="test")
    hit = case.query("SELECT addr FROM t WHERE addr = ?", params=[0xFFFFFFFF82000A20])
    assert hit.table.column("addr").to_pylist() == [0xFFFFFFFF82000A20]
    none = case.query("SELECT addr FROM t WHERE capture_id = ?", params=["cap' OR 1=1 --"])
    assert none.table.num_rows == 0


class _NewResult:
    def to_arrow_table(self):
        return "new"


class _OldResult:
    def fetch_arrow_table(self):
        return "old"


@pytest.mark.parametrize("result, expected", [(_NewResult(), "new"), (_OldResult(), "old")])
def test_fetch_arrow_uses_the_spelling_the_duckdb_version_has(result, expected):
    assert _fetch_arrow(result) == expected
