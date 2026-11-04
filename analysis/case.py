"""Case data lake: every tabular output of a case is a Parquet table (plan T1.8, D11).

A *case* is a directory::

    case.json       manifest {"v", "name", "created"}
    tables/<name>/<run_id>/<file_stem>.parquet (+ .meta.json sidecar)
    annotations/    analysis-record JSONL (written by ``analysis.record_store``,
                    read-only here, exposed as the ``annotations`` SQL view)
    views/ plugins/ isf/

Every registered table carries the **standard columns** ``capture_id,
image_sha256, pid, space, addr, size, run_id``. Addresses are ``uint64`` --
never ``int64`` -- because kernel VAs (``0xffff...``) overflow a signed
column. The column -> :class:`~memdiver.core.location.AddressSpace` mapping is
stored as Parquet key-value metadata (``memdiver.locations``) so a table
carries its own coordinate systems (P2).

Two read paths exist: :meth:`Case.query` is the hardened, read-only SQL
surface for agents and transports; :meth:`Case.table` is the trusted
in-process Ibis API for notebooks and is deliberately not hardened.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import date, datetime, time as dtime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

import duckdb
import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq

from memdiver.analysis.record import utc_now
from memdiver.core.artifact_util import atomic_write_text
from memdiver.core.constants import memdiver_home
from memdiver.core.location import AddressSpace
from memdiver.core.path_sandbox import is_bare_case_name
from memdiver.core.service_errors import CapabilityError, ErrorCategory

#: Format version of the manifest, sidecars and Parquet metadata.
CASE_VERSION = 1
MANIFEST = "case.json"
_SUBDIRS = ("tables", "annotations", "views", "plugins", "isf")
_TABLE_NAME = re.compile(r"^[a-z][a-z0-9_]{0,95}$")
_RESERVED_NAMES = frozenset({"annotations"})
_KEY_LOCATIONS = b"memdiver.locations"
_KEY_META = b"memdiver.meta"

#: Standard columns, in table order, with their Arrow types.
STANDARD_COLUMNS: Dict[str, pa.DataType] = {
    "capture_id": pa.string(), "image_sha256": pa.string(), "pid": pa.int64(),
    "space": pa.string(), "addr": pa.uint64(), "size": pa.uint64(),
    "run_id": pa.string(),
}


def cases_root() -> Path:
    """Directory that bare case names resolve into (``<memdiver home>/cases``)."""
    return memdiver_home() / "cases"


def case_path(dir_or_name: "str | Path") -> Path:
    """Where a case lives: a bare name means ``cases_root()/<name>``, else the path.

    The bare-name rule is :func:`is_bare_case_name` (shared with the REST routers
    and the MCP guard). A blank value is neither and is refused, and so is a
    backslash name that is no path on this platform (:func:`_is_ambiguous_backslash_name`).
    """
    text = str(dir_or_name)
    if not text.strip():
        raise _invalid("a case name or case directory is required")
    if _is_ambiguous_backslash_name(text):
        raise _invalid(
            f"backslashes are not allowed in case names ({text!r}); use a plain "
            "name, or a forward-slash path for a case directory")
    return cases_root() / text if is_bare_case_name(text) else Path(text).expanduser()


def _is_ambiguous_backslash_name(text: str) -> bool:
    """True for ``lab\\run1`` on POSIX: not a bare name, yet no real path either.

    ``\\`` is refused in bare names (cross-platform parity with REST) but is no
    separator here, so treating it as a path would file the case relative to the
    server's cwd. On Windows ``\\`` is ``os.sep`` and such a value is a real path.
    """
    separators = [sep for sep in (os.sep, os.altsep) if sep]
    return ("\\" in text and not any(sep in text for sep in separators)
            and not text.startswith(("~", ".")))


def resolve_case_dir(dir_or_name: "str | Path") -> Path:
    """The directory :meth:`Case.open` would open for *dir_or_name* (no I/O beyond stat).

    A bare name is tried relative to the current directory first (an existing
    ``<cwd>/<name>/case.json`` wins), then under ``cases_root()``; a path is used
    as given. Lets a caller (the sandbox guard) judge the REAL target; an
    ambiguous backslash name is judged as the cwd-relative path it would hit
    (:func:`case_path` itself refuses to create it).
    """
    root = Path(dir_or_name).expanduser()
    if (root / MANIFEST).is_file() or _is_ambiguous_backslash_name(str(dir_or_name)):
        return root
    return case_path(dir_or_name)


def __getattr__(name: str) -> Any:  # pragma: no cover - trivial
    if name == "CASES_ROOT":  # resolved lazily so XDG_DATA_HOME changes apply
        return cases_root()
    raise AttributeError(name)


def _invalid(message: str, code: str = "case.invalid") -> CapabilityError:
    return CapabilityError(message, category=ErrorCategory.INVALID_INPUT, code=code)


def new_run_id() -> str:
    """A sortable run id: UTC timestamp + short uuid."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return f"{stamp}-{uuid.uuid4().hex[:6]}"


def snake_case_columns(names: Iterable[str]) -> List[str]:
    """Normalize column names: ``"Offset (V)"`` -> ``offset_v``.

    Strip, lowercase, non-alphanumerics -> ``_``, collapse, trim; a leading
    digit gets a ``c_`` prefix; an empty result becomes ``col``; collisions get
    ``_2``, ``_3``... in order of appearance.
    """
    seen: Dict[str, int] = {}
    out: List[str] = []
    for raw in names:
        base = re.sub(r"[^a-z0-9]+", "_", str(raw).strip().lower()).strip("_") or "col"
        if base[0].isdigit():
            base = "c_" + base
        count = seen.get(base, 0) + 1
        seen[base] = count
        out.append(base if count == 1 else f"{base}_{count}")
    return out


@dataclass(frozen=True)
class TableRef:
    """One registered run of a table."""

    name: str
    run_id: str
    path: str
    row_count: int
    locations: Dict[str, str] = field(default_factory=dict)
    truncated: bool = False
    stop_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "run_id": self.run_id, "path": self.path,
                "row_count": self.row_count, "locations": dict(self.locations),
                "truncated": self.truncated, "stop_reason": self.stop_reason}


def _json_safe(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if isinstance(value, (datetime, date, dtime)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    return value


@dataclass
class QueryResult:
    """Rows of a :meth:`Case.query`, capped at ``limit``."""

    table: pa.Table
    truncated: bool
    elapsed_s: float

    def to_dict(self, max_rows: Optional[int] = None) -> Dict[str, Any]:
        """JSON-safe form: uint64 stay ints, binary -> hex, timestamps -> isoformat."""
        rows = self.table.to_pylist()
        cut = max_rows is not None and len(rows) > max_rows
        if cut:
            rows = rows[:max_rows]
        cols = self.table.column_names
        return {"columns": cols,
                "rows": [[_json_safe(r[c]) for c in cols] for r in rows],
                "truncated": bool(self.truncated or cut)}


def _is_table_name(name: str) -> bool:
    """A snake slug that is safe to splice into SQL as a bare identifier."""
    return bool(_TABLE_NAME.fullmatch(name or "")) and name not in _RESERVED_NAMES


def _check_name(name: str) -> None:
    if not _is_table_name(name):
        raise _invalid(f"invalid table name {name!r}: use a snake slug "
                       "(e.g. 'vol3__linux_pslist'); 'annotations' is reserved")


def _is_int(t: pa.DataType) -> bool:
    return pa.types.is_integer(t)


def _is_str(t: pa.DataType) -> bool:
    return pa.types.is_string(t) or pa.types.is_large_string(t)


def _compatible(have: pa.DataType, want: pa.DataType) -> bool:
    if pa.types.is_null(have):
        return True
    return _is_int(want) and _is_int(have) or _is_str(want) and _is_str(have)


def _cast(col: pa.ChunkedArray, to: pa.DataType, name: str) -> pa.ChunkedArray:
    try:
        return pc.cast(col, to)
    except (pa.ArrowInvalid, pa.ArrowNotImplementedError) as exc:
        raise _invalid(f"column {name!r} cannot be cast to {to}: {exc}",
                       "case.bad_column") from exc


def _normalize_columns(table: pa.Table) -> "tuple[pa.Table, Dict[str, str]]":
    """snake_case the names, resolving standard-column collisions.

    Returns the renamed table and a map original-name -> final name.
    """
    snake = snake_case_columns(table.column_names)
    final: Dict[str, str] = {}
    for orig, new in zip(table.column_names, snake):
        want = STANDARD_COLUMNS.get(new)
        if want is not None and not _compatible(table.schema.field(orig).type, want):
            new = f"{new}_src"
        final[orig] = new
    names = snake_case_columns(final[c] for c in table.column_names)
    return table.rename_columns(names), dict(zip(table.column_names, names))


def _standard_constant(name: str, value: Optional[str], rows: int) -> pa.Array:
    return pa.array([value] * rows, type=STANDARD_COLUMNS[name])


def _apply_standard(table: pa.Table, consts: Dict[str, Optional[str]]) -> pa.Table:
    """Add missing standard columns, cast present ones, put them first."""
    rows = table.num_rows
    cols: Dict[str, Any] = {}
    for name, typ in STANDARD_COLUMNS.items():
        if name in table.column_names:
            cols[name] = _cast(table.column(name), typ, name)
        elif name in consts:
            cols[name] = _standard_constant(name, consts[name], rows)
        else:
            cols[name] = pa.nulls(rows, type=typ)
    rest = [c for c in table.column_names if c not in cols]
    return pa.table({**cols, **{c: table.column(c) for c in rest}})


def _resolve_locations(table: pa.Table, locations: Dict[str, str],
                       renamed: Dict[str, str]) -> Dict[str, str]:
    """Validate spaces/columns; cast location columns to uint64."""
    valid = {s.value for s in AddressSpace}
    out: Dict[str, str] = {}
    for col, space in (locations or {}).items():
        if space not in valid:
            raise _invalid(f"unknown address space {space!r} for column {col!r}",
                           "case.bad_location")
        final = renamed.get(col, col)
        if final not in table.column_names:
            raise _invalid(f"location column {col!r} is not in the table",
                           "case.bad_location")
        out[final] = space
    return out


def _cast_location_columns(table: pa.Table, locs: Dict[str, str]) -> pa.Table:
    for col in locs:
        idx = table.column_names.index(col)
        typ = table.schema.field(col).type
        if not (_is_int(typ) or pa.types.is_null(typ)):
            raise _invalid(f"location column {col!r} must be integer, got {typ}",
                           "case.bad_column")
        table = table.set_column(idx, col, _cast(table.column(col), pa.uint64(), col))
    return table


def _glob(case_dir: Path, name: str) -> str:
    return str(case_dir / "tables" / name / "*" / "*.parquet")


def _allow_arrow_lambdas(con: Any) -> None:
    """Let an ibis DuckDB connection run ibis's ``x -> expr`` list lambdas.

    ibis (12.x) compiles array ``.map()`` / ``.filter()`` to the single-arrow
    form, which DuckDB 2.0 rejects by default. ``lambda x: expr`` keeps
    working with the setting on; DuckDB builds without it are left alone.
    """
    try:
        con.raw_sql("SET lambda_syntax = 'ENABLE_SINGLE_ARROW'")
    except duckdb.Error:
        pass


def _quote(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


def _fetch_arrow(result: Any) -> pa.Table:
    """The executed result as an Arrow table on every supported DuckDB.

    ``to_arrow_table()`` arrived in 1.5 and is the only spelling 2.0 keeps;
    before 1.5 the same call is ``fetch_arrow_table()``.
    """
    fetch = getattr(result, "to_arrow_table", None) or result.fetch_arrow_table
    return fetch()


def _without_trailing_semicolons(statement: str) -> str:
    """``statement`` cut before its trailing ``;`` tokens (and anything after them).

    DuckDB's tokenizer never reports a ``;`` inside a comment or string, so
    only real terminators are cut; a comment after the last one goes with it.
    DuckDB 2.0 reports comments as tokens (1.x skips them), so they are passed
    over. Token positions are UTF-8 byte offsets, hence the bytes round-trip.
    """
    encoded = statement.encode("utf-8")
    end = len(encoded)
    for position, token_type in reversed(duckdb.tokenize(statement)):
        if token_type == duckdb.token_type.comment:
            continue
        if token_type != duckdb.token_type.operator or encoded[position:position + 1] != b";":
            break
        end = position
    return encoded[:end].decode("utf-8").strip()


def _from_first_code_token(sql: str) -> str:
    """``sql`` without its leading whitespace and comments.

    DuckDB 2.0 drops them from ``extract_statements(...).query`` (1.x keeps
    them), so this is the other faithful form of a single statement.
    """
    encoded = sql.encode("utf-8")
    for position, token_type in duckdb.tokenize(sql):
        if token_type != duckdb.token_type.comment:
            return encoded[position:].decode("utf-8")
    return ""


class Case:
    """A case directory holding Parquet tables and the analysis record."""

    def __init__(self, directory: Path) -> None:
        self.dir = Path(directory).resolve()

    # -- lifecycle -------------------------------------------------------
    @classmethod
    def init(cls, dir_or_name: "str | Path") -> "Case":
        """Create (or re-open) a case. A bare name means ``cases_root()/<name>``."""
        root = case_path(dir_or_name)
        root.mkdir(parents=True, exist_ok=True)
        for sub in _SUBDIRS:
            (root / sub).mkdir(exist_ok=True)
        manifest = root / MANIFEST
        if not manifest.exists():
            body = {"v": CASE_VERSION, "name": root.name, "created": utc_now()}
            atomic_write_text(manifest, json.dumps(body, indent=2) + "\n")
        return cls(root)

    @classmethod
    def open(cls, directory: "str | Path") -> "Case":
        """Open an existing case; ``case.json`` must exist."""
        root = Path(directory).expanduser()
        if not (root / MANIFEST).is_file():
            # A bare name opens the case `init` filed under cases_root().
            root = case_path(directory)
        if not (root / MANIFEST).is_file():
            raise _invalid(f"not a case directory (no {MANIFEST}): {root}",
                           "case.not_a_case")
        return cls(root)

    @property
    def name(self) -> str:
        return str(self.manifest().get("name", self.dir.name))

    def manifest(self) -> Dict[str, Any]:
        return json.loads((self.dir / MANIFEST).read_text(encoding="utf-8"))

    # -- registration ----------------------------------------------------
    def register_table(
        self, name: str, table: pa.Table, *, capture_id: str,
        run_id: Optional[str] = None, image_sha256: Optional[str] = None,
        producer: str, file_stem: Optional[str] = None,
        locations: Optional[Dict[str, str]] = None,
        meta: Optional[Dict[str, Any]] = None,
    ) -> TableRef:
        """Normalize ``table`` to the case schema and write it as one Parquet run."""
        _check_name(name)
        run_id = run_id or new_run_id()
        table, renamed = _normalize_columns(table)
        locs = _resolve_locations(table, locations or {}, renamed)
        table = _cast_location_columns(table, locs)
        table = _apply_standard(table, {"capture_id": capture_id,
                                        "image_sha256": image_sha256,
                                        "run_id": run_id})
        info = self._meta_block(producer, run_id, capture_id, image_sha256, meta)
        return self._write_run(name, table, run_id, file_stem or name, locs, info)

    @staticmethod
    def _meta_block(producer: str, run_id: str, capture_id: str,
                    image_sha256: Optional[str],
                    extra: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        return {"producer": producer, "run_id": run_id, "capture_id": capture_id,
                "image_sha256": image_sha256, "created": utc_now(),
                "v": CASE_VERSION, "meta": dict(extra or {})}

    def _write_run(self, name: str, table: pa.Table, run_id: str, stem: str,
                   locs: Dict[str, str], info: Dict[str, Any]) -> TableRef:
        if not re.match(r"^[A-Za-z0-9_.\-]{1,128}$", stem):
            raise _invalid(f"invalid file stem {stem!r}")
        run_dir = self.dir / "tables" / name / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        path = run_dir / f"{stem}.parquet"
        schema_meta = {_KEY_LOCATIONS: json.dumps(locs).encode(),
                       _KEY_META: json.dumps(info).encode()}
        table = table.replace_schema_metadata(schema_meta)
        tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex[:8]}.tmp")
        pq.write_table(table, tmp)
        os.replace(tmp, path)
        sidecar = {**info, "row_count": table.num_rows,
                   "columns": table.column_names, "locations": locs}
        atomic_write_text(path.with_name(f"{stem}.meta.json"),
                           json.dumps(sidecar, indent=2) + "\n")
        extra = info.get("meta") or {}
        return TableRef(name, run_id, str(path), table.num_rows, locs,
                        bool(extra.get("truncated")), extra.get("stop_reason"))

    # -- listing ---------------------------------------------------------
    def tables(self) -> List[str]:
        """Names of tables that have at least one registered run.

        A directory whose name is not a valid table name is skipped: the name is
        spliced into ``CREATE VIEW`` SQL by :meth:`_connect`, so it must never
        come from the filesystem unvalidated.
        """
        root = self.dir / "tables"
        if not root.is_dir():
            return []
        return sorted(p.name for p in root.iterdir()
                      if _is_table_name(p.name) and p.is_dir()
                      and any(p.glob("*/*.parquet")))

    def runs(self, name: str) -> List[TableRef]:
        """Runs of ``name`` (oldest first), read from the sidecars."""
        if not _is_table_name(name):  # never let a caller's name walk out of tables/
            return []
        refs: List[TableRef] = []
        for side in sorted((self.dir / "tables" / name).glob("*/*.meta.json")):
            data = json.loads(side.read_text(encoding="utf-8"))
            parquet = side.with_name(side.name[: -len(".meta.json")] + ".parquet")
            if parquet.is_file():
                extra = data.get("meta") or {}
                refs.append(TableRef(name, data["run_id"], str(parquet),
                                     int(data["row_count"]),
                                     dict(data.get("locations", {})),
                                     bool(extra.get("truncated")),
                                     extra.get("stop_reason")))
        return refs

    def schema(self) -> Dict[str, Any]:
        """Per table: columns+types (newest run), locations, run count, rows."""
        out: Dict[str, Any] = {"case": self.name, "tables": {}}
        for name in self.tables():
            out["tables"][name] = self._table_schema(name)
        out["annotations"] = self._annotations_schema()
        return out

    def _table_schema(self, name: str) -> Dict[str, Any]:
        runs = self.runs(name)
        arrow = pq.read_schema(runs[-1].path)
        return {"columns": [{"name": f.name, "type": str(f.type)} for f in arrow],
                "locations": dict(runs[-1].locations), "runs": len(runs),
                "rows": sum(r.row_count for r in runs),
                "truncated_runs": [{"run_id": r.run_id, "stop_reason": r.stop_reason}
                                   for r in runs if r.truncated]}

    def _annotations_schema(self) -> Dict[str, Any]:
        files = sorted((self.dir / "annotations").glob("*.jsonl"))
        info: Dict[str, Any] = {"files": len(files), "columns": []}
        if files:
            conn = self._connect(harden=False)
            try:
                rows = conn.execute("DESCRIBE annotations").fetchall()
            finally:
                conn.close()
            info["columns"] = [{"name": r[0], "type": r[1]} for r in rows]
        return info

    # -- query -----------------------------------------------------------
    def _connect(self, *, harden: bool) -> "duckdb.DuckDBPyConnection":
        conn = duckdb.connect()
        for name in self.tables():
            # B608: tables() yields only _is_table_name() slugs; the glob is _quote()d.
            conn.execute(f"CREATE VIEW {name} AS SELECT * FROM read_parquet("  # nosec B608
                         f"{_quote(_glob(self.dir, name))}, union_by_name=true)")
        if any((self.dir / "annotations").glob("*.jsonl")):
            pattern = _quote(str(self.dir / "annotations" / "*.jsonl"))
            # B608: fixed view name; the only interpolation is the _quote()d glob.
            conn.execute("CREATE VIEW annotations AS SELECT * FROM read_json_auto("  # nosec B608
                         f"{pattern}, format='newline_delimited', union_by_name=true)")
        if harden:
            self._harden(conn)
        return conn

    def _harden(self, conn: "duckdb.DuckDBPyConnection") -> None:
        """Confine the connection to the case dir, then freeze its settings."""
        conn.execute(f"SET allowed_directories=[{_quote(str(self.dir))}]")
        conn.execute("SET enable_external_access=false")
        conn.execute("SET lock_configuration=true")

    @staticmethod
    def _guard(sql: str) -> str:
        """Allow exactly one SELECT statement; return it without trailing ';'s.

        The returned text is the statement exactly as DuckDB parsed it, so the
        guarded SQL and the executed SQL are the same. A statement DuckDB rewrote
        while parsing (``PRAGMA x`` -> ``SELECT * FROM pragma_x()``) is refused;
        only the leading comments DuckDB 2.0 drops may differ.
        """
        try:
            stmts = duckdb.extract_statements(sql)
        except duckdb.Error as exc:
            raise _invalid(f"SQL does not parse: {exc}", "case.bad_sql") from exc
        if (len(stmts) != 1 or stmts[0].type != duckdb.StatementType.SELECT
                or stmts[0].query not in (sql, _from_first_code_token(sql))):
            raise _invalid("only a single SELECT statement is allowed",
                           "case.read_only")
        return _without_trailing_semicolons(stmts[0].query)

    def query(self, sql: str, *, limit: int = 10_000, timeout_s: float = 30.0,
              params: Optional[Sequence[Any]] = None) -> QueryResult:
        """Run one read-only SELECT over the case tables and annotations.

        ``params`` binds positional ``?`` placeholders (never format values
        into ``sql``).
        """
        inner = self._guard(sql)
        conn = self._connect(harden=True)
        timer = threading.Timer(timeout_s, conn.interrupt)
        start = time.monotonic()
        timer.start()
        try:
            # B608: running the caller's SQL is the point of query(); _guard() admits
            # exactly one SELECT, the connection is hardened (case dir only, config
            # locked), values bind as ? params and the LIMIT is an int(). The newline
            # before ')' keeps a trailing ``--`` comment in ``inner`` from eating it.
            arrow = _fetch_arrow(conn.execute(
                f"SELECT * FROM ({inner}\n) AS q LIMIT {int(limit) + 1}",  # nosec B608
                list(params or ()),
            ))
        except duckdb.InterruptException as exc:
            raise CapabilityError(
                f"query exceeded {timeout_s}s and was cancelled",
                category=ErrorCategory.PRECONDITION, code="case.query_timeout",
            ) from exc
        except duckdb.Error as exc:
            raise _invalid(f"query failed: {exc}", "case.query_failed") from exc
        finally:
            timer.cancel()
            conn.close()
        truncated = arrow.num_rows > limit
        return QueryResult(arrow.slice(0, limit), truncated, time.monotonic() - start)

    # -- notebook API ----------------------------------------------------
    def table(self, name: str) -> Any:
        """All runs of ``name`` as an ``ibis.Table``.

        Trusted in-process API for notebooks: the connection is NOT hardened
        and may read anything the process can. Use :meth:`query` for
        untrusted SQL.
        """
        import ibis

        if name not in self.tables():
            raise CapabilityError(f"no such table {name!r}",
                                  category=ErrorCategory.NOT_FOUND,
                                  code="case.no_table")
        con = ibis.duckdb.connect()
        _allow_arrow_lambdas(con)
        return con.read_parquet(_glob(self.dir, name), table_name=name,
                                union_by_name=True)
