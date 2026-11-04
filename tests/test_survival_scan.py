"""Tests for engine/survival_scan.py — the corpus sweep's per-dump worker.

The module freezes a write-once contract (a field discovered missing after an
18,917-unit sweep means re-running the sweep), so these tests pin the contract
itself, not just the happy path:

* ``DumpObservation.to_row()`` against the PRODUCTION ``survival`` column list,
  in both directions, so the dataclass and the schema cannot drift;
* ``status`` / ``present`` for all three statuses, including that ``error``
  writes no row;
* the ``hit_count <= 1`` cap that ``find_first`` guarantees;
* the empty-needle guard (no absence is claimed for a needle never searched);
* the non-raw format refusal, its explicit opt-in, and that it is NOT recorded
  as ``unreadable`` (CONTRACT 3 of ``project_db``'s status vocabulary);
* ``elapsed_s`` on the ENVELOPE, measured around the scan and not the keylog
  parse (CONTRACT 4);
* the survival DENOMINATOR being a distinct-``secret_type`` count rather than a
  raw entry count, proven on a keylog that declares one type twice (CONTRACT 5);
* picklability of the worker AND of its return value, since both cross a
  process boundary;
* one corpus-gated proof on a REAL dump, against the offset
  ``tests/test_truth_labels.py`` already pins.
"""

from __future__ import annotations

import dataclasses
import pickle
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import memdiver.engine.survival_scan as scan_survival  # noqa: E402
from memdiver.core.dump_source import RawDumpSource, open_dump  # noqa: E402
from memdiver.core.models import CryptoSecret  # noqa: E402
from memdiver.core.keylog import (  # noqa: E402
    KEYLOG_STATUS_MISSING,
    KEYLOG_STATUS_OK,
)
from memdiver.engine.project_db import (  # noqa: E402
    HAS_DUCKDB,
    METHOD_KEYLOG_SUBSTRING,
    SURVIVAL_STATUS_ERROR,
    SURVIVAL_STATUS_SEARCHED,
    SURVIVAL_STATUS_UNREADABLE,
    _all_columns,
)
from memdiver.engine.sweep_plan import SWEEP_SCHEMA_VERSION  # noqa: E402
from memdiver.engine.survival_scan import (  # noqa: E402
    ELAPSED_PRECISION,
    MAX_HIT_COUNT,
    OBSERVATION_COLUMNS,
    OBSERVATION_RECORD_VERSION,
    SCAN_OUTCOME_ERROR,
    SCAN_OUTCOME_NO_KEYLOG,
    SCAN_OUTCOME_OK,
    SCAN_OUTCOME_UNREADABLE,
    SCAN_OUTCOME_UNSUPPORTED_FORMAT,
    SCAN_OUTCOMES,
    SUPPORTED_FORMATS,
    VIEW_MODES,
    DumpObservation,
    DumpScanResult,
    _searchable_groups,
    scan_dump_unit,
)

if HAS_DUCKDB:
    from memdiver.engine.project_db import ProjectDB

needs_duckdb = pytest.mark.skipif(not HAS_DUCKDB, reason="duckdb not installed")

SWEEP = "sweep-1"

#: Real secret-type labels. ``core.keylog`` only accepts names from its known
#: vocabulary, so an invented label parses as a MALFORMED row rather than as a
#: secret -- which would make these tests pass for the wrong reason.
CTS0 = "CLIENT_TRAFFIC_SECRET_0"
STS0 = "SERVER_TRAFFIC_SECRET_0"

#: The real corpus anchor, identical to tests/test_truth_labels.py. Kept as a
#: literal copy rather than an import so a change on either side is visible as
#: a diff on both.
REAL_RUN_RELPATH = Path(
    "TLS13/100_iterations_Abort_KeyUpdate/openssl/openssl_run_13_1")
REAL_DUMP_NAME = "20251020_171845_606711_pre_server_key_update.dump"
REAL_CLIENT_TRAFFIC_SECRET_0_OFFSET = 585084


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def make_run(tmp_path: Path, *, secrets: list[tuple[str, bytes]],
             blob: bytes, name: str = "run") -> Path:
    """A minimal run directory: one real-shaped keylog.csv plus one dump."""
    run = tmp_path / name
    run.mkdir()
    lines = "".join(
        f"{i},{label} {'ab' * 32} {value.hex()}\n"
        for i, (label, value) in enumerate(secrets, start=1)
    )
    (run / "keylog.csv").write_text("id,line\n" + lines)
    (run / "d.dump").write_bytes(blob)
    return run


def observation(**kw: object) -> DumpObservation:
    """A valid searched-and-absent observation, overridable per test."""
    base: dict = {
        "sweep_id": SWEEP, "dump_path": "/x/d.dump",
        "secret_type": "CLIENT_TRAFFIC_SECRET_0",
        "status": SURVIVAL_STATUS_SEARCHED, "present": False,
    }
    base.update(kw)
    return DumpObservation(**base)


class FakeSource:
    """Duck-typed DumpSource with a caller-chosen ``format_name``."""

    def __init__(self, fmt: str = "msl", data: bytes = b"", size: int = 0):
        self.format_name = fmt
        self._data = data
        self.size = size or len(data)

    def size_for(self, view: str = "vas") -> int:
        return self.size

    def find_first(self, needle: bytes, view: str = "vas"):
        idx = self._data.find(needle, 0)
        return None if idx == -1 else idx

    def find_all(self, needle: bytes, view: str = "vas") -> list:
        return [] if not needle else [
            i for i in range(len(self._data)) if self._data.startswith(needle, i)
        ]

    def __enter__(self) -> "FakeSource":
        return self

    def __exit__(self, *exc: object) -> None:
        return None


# --------------------------------------------------------------------------- #
# CONTRACT 1 — DumpObservation IS the survival row
# --------------------------------------------------------------------------- #

def test_observation_columns_are_exactly_the_survival_schema():
    """Asserted against the PRODUCTION constant so the two cannot drift."""
    expected = tuple(
        c for c in _all_columns("survival")
        if c not in ("survival_id", "created_at")
    )
    assert OBSERVATION_COLUMNS == expected


def test_to_row_keys_are_exactly_the_survival_schema_minus_the_writer_columns():
    row = observation().to_row()
    schema = set(_all_columns("survival"))
    assert set(row) == schema - {"survival_id", "created_at"}
    # Order too: the row is rendered in schema order.
    assert list(row) == list(OBSERVATION_COLUMNS)


def test_to_row_carries_no_unit_key():
    """Omitting it pins survival_id to (sweep_id, dump_path, secret_type).

    ``_survival_payload_row`` keys on ``unit_key or dump_path or dump_id``, so
    a ``unit_key`` in the row would make the primary key and the
    ``survival_cell_unique`` index two DIFFERENT keys.
    """
    assert "unit_key" not in observation().to_row()


def test_observation_defaults_match_the_schema_defaults():
    row = DumpObservation(sweep_id=SWEEP, dump_path="/x/d.dump",
                          secret_type=CTS0, present=False).to_row()
    assert row["library_version"] == "unknown"
    assert row["method"] == METHOD_KEYLOG_SUBSTRING
    assert row["run_number"] == 0
    assert row["size_for_view"] == 0
    assert row["format_name"] == ""


def test_observation_is_frozen():
    obs = observation()
    with pytest.raises(dataclasses.FrozenInstanceError):
        obs.present = True  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# CONTRACT 2 — the record version
# --------------------------------------------------------------------------- #

def test_record_version_is_folded_under_the_sweep_schema_version():
    """Not a sibling constant: a shape change must force a re-sweep.

    ``SWEEP_SCHEMA_VERSION`` is inside ``config_digest``, so aliasing it here
    is what makes an observation-shape change invalidate every stored digest
    instead of letting two shapes merge into one pile.
    """
    assert OBSERVATION_RECORD_VERSION == SWEEP_SCHEMA_VERSION
    assert DumpScanResult().record_version == SWEEP_SCHEMA_VERSION
    assert DumpScanResult().to_dict()["record_version"] == SWEEP_SCHEMA_VERSION


# --------------------------------------------------------------------------- #
# CONTRACT 3 — hit_count is capped at 1
# --------------------------------------------------------------------------- #

def test_hit_count_cap_is_one():
    assert MAX_HIT_COUNT == 1


def test_hit_count_above_the_cap_is_rejected():
    """A larger value means someone swapped find_first for find_all."""
    with pytest.raises(ValueError, match="presence probe"):
        observation(present=True, first_offset=0, hit_count=2)


def test_hit_count_is_never_more_than_one_on_a_real_hit(tmp_path):
    """The same secret occurring four times still reports one hit."""
    key = bytes(range(0x40, 0x60))
    run = make_run(tmp_path, secrets=[(CTS0, key)],
                   blob=b"\x00" * 8 + (key * 4))

    result = scan_dump_unit(run / "d.dump", run, sweep_id=SWEEP)

    assert [o.hit_count for o in result.observations] == [1]
    assert result.observations[0].first_offset == 8


def test_negative_hit_count_is_rejected():
    with pytest.raises(ValueError, match="outside 0"):
        observation(hit_count=-1)


# --------------------------------------------------------------------------- #
# status / present interaction, for all three statuses
# --------------------------------------------------------------------------- #

def test_searched_requires_a_non_null_present():
    """SQL NULL is excluded by BOTH `WHERE present` and `WHERE NOT present`."""
    with pytest.raises(ValueError, match="requires a non-NULL present"):
        observation(status=SURVIVAL_STATUS_SEARCHED, present=None)


def test_searched_accepts_both_readings_and_writes_a_row():
    hit = observation(present=True, first_offset=17, hit_count=1)
    miss = observation(present=False)
    assert hit.writes_row and miss.writes_row
    assert hit.to_row()["present"] is True
    assert miss.to_row()["present"] is False


def test_unreadable_must_leave_present_null_but_still_writes_a_row():
    """The 'no data WITH A REASON' cell — not a false absence."""
    obs = observation(status=SURVIVAL_STATUS_UNREADABLE, present=None)
    assert obs.to_row()["present"] is None
    assert obs.writes_row
    with pytest.raises(ValueError, match="must leave present NULL"):
        observation(status=SURVIVAL_STATUS_UNREADABLE, present=False)


def test_error_writes_no_row():
    """An errored attempt is not an observation."""
    obs = observation(status=SURVIVAL_STATUS_ERROR, present=None)
    assert obs.writes_row is False
    assert DumpScanResult(observations=(obs,)).rows() == []


def test_unknown_status_is_rejected():
    with pytest.raises(ValueError, match="unknown survival status"):
        observation(status="looked_a_bit")


def test_present_must_agree_with_first_offset_and_hit_count():
    with pytest.raises(ValueError, match="contradicts first_offset"):
        observation(present=True, first_offset=None, hit_count=1)
    with pytest.raises(ValueError, match="contradicts hit_count"):
        observation(present=True, first_offset=3, hit_count=0)


# --------------------------------------------------------------------------- #
# Real-bytes presence / absence on synthetic dumps
# --------------------------------------------------------------------------- #

def test_a_present_secret_is_found_at_its_real_offset(tmp_path):
    key = bytes(range(0x20, 0x40))
    run = make_run(tmp_path, secrets=[(CTS0, key)],
                   blob=b"\x00" * 16 + key + b"\xff" * 16)

    result = scan_dump_unit(run / "d.dump", run, sweep_id=SWEEP,
                            unit_key="u2/x", library="openssl",
                            protocol_version="13", run_number=1,
                            phase="pre_server_key_update",
                            canonical_phase="key_update")

    assert result.outcome == SCAN_OUTCOME_OK
    assert result.keylog_status == KEYLOG_STATUS_OK
    assert result.secrets_available == 1
    assert result.secret_types_available == 1
    assert result.secret_types_searched == 1
    assert result.unit_key == "u2/x"
    (obs,) = result.observations
    assert obs.present is True
    assert obs.first_offset == 16
    assert obs.hit_count == 1
    assert obs.status == SURVIVAL_STATUS_SEARCHED
    assert obs.method == METHOD_KEYLOG_SUBSTRING
    assert obs.secret_type == "CLIENT_TRAFFIC_SECRET_0"
    assert obs.library == "openssl"
    assert obs.canonical_phase == "key_update"
    # The bytes at the reported offset really are the key.
    assert (run / "d.dump").read_bytes()[16:48] == key


def test_an_absent_secret_is_a_positive_record_of_absence(tmp_path):
    key = bytes(range(0x20, 0x40))
    run = make_run(tmp_path, secrets=[(CTS0, key)],
                   blob=b"\x00" * 128)

    result = scan_dump_unit(run / "d.dump", run, sweep_id=SWEEP)

    assert result.outcome == SCAN_OUTCOME_OK
    (obs,) = result.observations
    assert obs.present is False
    assert obs.first_offset is None
    assert obs.hit_count == 0
    assert obs.status == SURVIVAL_STATUS_SEARCHED


def test_every_observation_records_the_format_and_the_searched_size(tmp_path):
    """So a format-caused absence is always distinguishable from a real one."""
    key = b"K" * 32
    run = make_run(tmp_path, secrets=[(CTS0, key)], blob=b"\x00" * 64)

    result = scan_dump_unit(run / "d.dump", run, sweep_id=SWEEP)

    assert result.format_name == "raw"
    assert result.size_for_view == 64
    assert all(o.format_name == "raw" and o.size_for_view == 64
               for o in result.observations)


def test_one_row_per_secret_type_even_when_two_secrets_share_a_type(tmp_path):
    """The survival grain is (sweep_id, dump_path, secret_type).

    Two rows would collapse onto one indexed row while the writer counted both.
    """
    a, b = b"A" * 32, b"B" * 32
    run = make_run(tmp_path, secrets=[(CTS0, a), (CTS0, b)],
                   blob=b"\x00" * 8 + b + b"\x00" * 8)

    result = scan_dump_unit(run / "d.dump", run, sweep_id=SWEEP)

    assert [o.secret_type for o in result.observations] == [CTS0]
    assert result.observations[0].present is True
    assert result.observations[0].first_offset == 8


def test_observations_are_in_deterministic_secret_type_order(tmp_path):
    run = make_run(tmp_path, secrets=[(STS0, b"z" * 32), (CTS0, b"a" * 32)],
                   blob=b"\x00" * 64)

    result = scan_dump_unit(run / "d.dump", run, sweep_id=SWEEP)

    assert [o.secret_type for o in result.observations] == [CTS0, STS0]


# --------------------------------------------------------------------------- #
# The empty-needle guard
# --------------------------------------------------------------------------- #

def test_searchable_groups_drops_an_empty_needle_and_counts_it():
    """A needle never searched must not become `present = FALSE`.

    ``find_first_offset`` already refuses ``b""`` (it returns ``None``, not
    offset 0), so an empty secret cannot fake a HIT -- but recording it as a
    miss would be a positive claim of absence for a search that never ran.
    """
    groups, skipped = _searchable_groups([
        CryptoSecret(secret_type=CTS0, identifier=b"\xab", secret_value=b""),
        CryptoSecret(secret_type=STS0, identifier=b"\xab",
                     secret_value=b"K" * 32),
    ])
    assert [t for t, _g in groups] == [STS0]
    assert skipped == 1


def test_an_empty_secret_claims_no_absence_and_writes_no_row(tmp_path,
                                                             monkeypatch):
    """End to end: the empty secret produces no cell at all."""
    run = make_run(tmp_path, secrets=[(CTS0, b"K" * 32)], blob=b"\x00" * 64)
    monkeypatch.setattr(
        "memdiver.engine.survival_scan.keylog_secrets_for_run",
        lambda run_dir, **kw: (
            [CryptoSecret(secret_type=CTS0, identifier=b"\xab",
                          secret_value=b"")],
            KEYLOG_STATUS_OK))

    result = scan_dump_unit(run / "d.dump", run, sweep_id=SWEEP)

    assert result.observations == ()
    assert result.rows() == []
    assert result.secrets_available == 1
    assert result.secrets_skipped_empty == 1


def test_an_empty_secret_does_not_suppress_its_siblings(tmp_path, monkeypatch):
    key = b"K" * 32
    run = make_run(tmp_path, secrets=[(CTS0, key)], blob=b"\x00" * 8 + key)
    monkeypatch.setattr(
        "memdiver.engine.survival_scan.keylog_secrets_for_run",
        lambda run_dir, **kw: (
            [CryptoSecret(secret_type=STS0, identifier=b"\xab",
                          secret_value=b""),
             CryptoSecret(secret_type=CTS0, identifier=b"\xab",
                          secret_value=key)],
            KEYLOG_STATUS_OK))

    result = scan_dump_unit(run / "d.dump", run, sweep_id=SWEEP)

    assert [o.secret_type for o in result.observations] == [CTS0]
    assert result.observations[0].present is True
    assert result.secrets_skipped_empty == 1


# --------------------------------------------------------------------------- #
# Format refusal — the ET_DYN accident
# --------------------------------------------------------------------------- #

def test_a_plain_dump_really_does_resolve_to_the_raw_source(tmp_path):
    """Pins the accident the refusal exists to protect."""
    path = tmp_path / "d.dump"
    path.write_bytes(b"\x00" * 64)
    with open_dump(path) as source:
        assert isinstance(source, RawDumpSource)
        assert source.format_name == "raw"
    assert SUPPORTED_FORMATS == ("raw",)


def test_raw_source_accepts_vas_and_va_as_raw_aliases(tmp_path):
    """A flat dump's views coincide; a TYPO is still a loud ValueError."""
    assert set(VIEW_MODES) == {"raw", "vas", "va"}
    key = b"K" * 32
    run = make_run(tmp_path, secrets=[(CTS0, key)], blob=b"\x00" * 8 + key)
    for view in ("raw", "vas", "va"):
        result = scan_dump_unit(run / "d.dump", run, sweep_id=SWEEP, view=view)
        assert result.observations[0].present is True, view


def test_an_unknown_view_is_rejected_eagerly_before_any_io(tmp_path):
    """One loud failure, not 18,917 quiet `unreadable` rows."""
    with pytest.raises(ValueError, match="unknown view"):
        scan_dump_unit(tmp_path / "nope.dump", tmp_path, sweep_id=SWEEP,
                       view="vsa")


def test_a_non_raw_format_is_refused_and_writes_no_row(tmp_path, monkeypatch):
    key = b"K" * 32
    run = make_run(tmp_path, secrets=[(CTS0, key)], blob=b"\x00" * 8 + key)
    monkeypatch.setattr(
        "memdiver.engine.survival_scan.open_dump",
        lambda path: FakeSource("msl", b"\x00" * 8 + key))

    result = scan_dump_unit(run / "d.dump", run, sweep_id=SWEEP)

    assert result.outcome == SCAN_OUTCOME_UNSUPPORTED_FORMAT
    assert result.observations == ()
    assert result.rows() == []
    assert result.format_name == "msl"
    assert result.size_for_view == 40
    assert "msl" in result.detail


def test_a_refused_format_is_not_recorded_as_unreadable(tmp_path, monkeypatch):
    """"Not attempted" (no row), never ``unreadable`` (a row saying we failed).

    ``project_db``'s comment used to list "unsupported format" under
    ``SURVIVAL_STATUS_UNREADABLE``, contradicting this module. This module
    wins: ``unreadable`` asserts we opened the RIGHT byte stream and it would
    not yield, while a refused format means we never established which stream a
    search would have covered — a stronger claim than the evidence supports.
    """
    key = b"K" * 32
    run = make_run(tmp_path, secrets=[(CTS0, key)], blob=b"\x00" * 8 + key)
    monkeypatch.setattr(
        "memdiver.engine.survival_scan.open_dump",
        lambda path: FakeSource("msl", b"\x00" * 8 + key))

    result = scan_dump_unit(run / "d.dump", run, sweep_id=SWEEP)

    assert result.outcome == SCAN_OUTCOME_UNSUPPORTED_FORMAT
    assert result.outcome != SURVIVAL_STATUS_UNREADABLE
    # No row at all — not one carrying `status = 'unreadable'`.
    assert result.observations == ()
    assert not any(o.status == SURVIVAL_STATUS_UNREADABLE
                   for o in result.observations)
    assert result.rows() == []
    # ...and the refusal is still fully explained, so "not attempted" is never
    # mistaken for "never reached".
    assert result.format_name == "msl"
    assert "msl" in result.detail


def test_a_non_raw_format_can_be_opted_into_explicitly(tmp_path, monkeypatch):
    key = b"K" * 32
    run = make_run(tmp_path, secrets=[(CTS0, key)], blob=b"\x00" * 8 + key)
    monkeypatch.setattr(
        "memdiver.engine.survival_scan.open_dump",
        lambda path: FakeSource("msl", b"\x00" * 8 + key))

    result = scan_dump_unit(run / "d.dump", run, sweep_id=SWEEP,
                            allowed_formats=("raw", "msl"))

    assert result.outcome == SCAN_OUTCOME_OK
    assert result.observations[0].present is True
    assert result.observations[0].format_name == "msl"


# --------------------------------------------------------------------------- #
# CONTRACT 4 — elapsed_s lives on the ENVELOPE, measured around the SCAN
# --------------------------------------------------------------------------- #

def test_elapsed_s_is_on_the_envelope_and_never_on_a_row():
    """A row field would need a `survival` timing column, which does not exist.

    ``to_row()`` must equal ``_all_columns("survival")`` minus the two writer
    columns; putting a duration on the row would therefore have required a
    schema change this module is not allowed to make.
    """
    assert "elapsed_s" in DumpScanResult.__dataclass_fields__
    assert "elapsed_s" not in DumpObservation.__dataclass_fields__
    assert "elapsed_s" not in observation().to_row()
    assert not any(c.startswith("elapsed") for c in _all_columns("survival"))


def test_elapsed_s_reaches_the_results_jsonl_line(tmp_path):
    """3f publishes it in ``ProgressEvent.extra`` beside ``tried``/``total``."""
    import json

    key = b"K" * 32
    run = make_run(tmp_path, secrets=[(CTS0, key)], blob=b"\x00" * 8 + key)

    result = scan_dump_unit(run / "d.dump", run, sweep_id=SWEEP)

    assert result.outcome == SCAN_OUTCOME_OK
    assert result.elapsed_s > 0.0
    assert json.loads(json.dumps(result.to_dict()))["elapsed_s"] == \
        result.elapsed_s


def test_elapsed_s_excludes_the_per_run_keylog_parse(tmp_path, monkeypatch):
    """It times open+probe only, so one run's parse is not charged to one dump.

    The keylog parse is per-RUN work amortised over that run's ~7 dumps.
    Charging it to whichever dump was scanned first would skew both a cost
    comparison and the progress ETA that divides by this number.
    """
    key = b"K" * 32
    run = make_run(tmp_path, secrets=[(CTS0, key)], blob=b"\x00" * 8 + key)
    real = scan_survival.keylog_secrets_for_run

    def slow_parse(run_dir, **kw):
        out = real(run_dir, **kw)
        time.sleep(0.25)
        return out

    monkeypatch.setattr(
        "memdiver.engine.survival_scan.keylog_secrets_for_run", slow_parse)

    wall_start = time.perf_counter()
    result = scan_dump_unit(run / "d.dump", run, sweep_id=SWEEP)
    wall = time.perf_counter() - wall_start

    assert wall >= 0.25, "the injected parse delay really did happen"
    # Relative to this call's own wall time, not an absolute budget: the parse
    # slept >= 0.25 s inside ``wall``, so a scan timer that excludes it leaves
    # at least that much (minus one rounding step) unaccounted for, however
    # slowly a loaded box ran the scan itself.
    rounding = 10 ** -ELAPSED_PRECISION
    assert result.elapsed_s <= wall - 0.25 + rounding, (
        "elapsed_s must exclude the keylog parse; it timed the whole call",
        result.elapsed_s, wall)


def test_elapsed_s_is_rounded_and_never_negative(tmp_path):
    """Rounded so a results.jsonl line carries no float noise."""
    key = b"K" * 32
    run = make_run(tmp_path, secrets=[(CTS0, key)], blob=b"\x00" * 8 + key)

    result = scan_dump_unit(run / "d.dump", run, sweep_id=SWEEP)

    assert result.elapsed_s >= 0.0
    assert result.elapsed_s == round(result.elapsed_s, ELAPSED_PRECISION)


def test_an_unreadable_unit_still_reports_the_time_it_spent(tmp_path):
    """The dump WAS opened, so there is a scan to time."""
    key = b"K" * 32
    run = make_run(tmp_path, secrets=[(CTS0, key)], blob=b"")

    result = scan_dump_unit(run / "d.dump", run, sweep_id=SWEEP)

    assert result.outcome == SCAN_OUTCOME_UNREADABLE
    assert result.elapsed_s > 0.0


def test_a_unit_that_never_opened_the_dump_reports_no_elapsed_time(tmp_path):
    """No keylog means no scan at all — 0.0, not the parse's duration."""
    run = tmp_path / "run"
    run.mkdir()
    (run / "d.dump").write_bytes(b"\x00" * 64)

    result = scan_dump_unit(run / "d.dump", run, sweep_id=SWEEP)

    assert result.outcome == SCAN_OUTCOME_NO_KEYLOG
    assert result.elapsed_s == 0.0


def test_an_errored_unit_reports_no_elapsed_time(tmp_path, monkeypatch):
    """A partial duration off a half-finished scan is not a unit's cost."""
    key = b"K" * 32
    run = make_run(tmp_path, secrets=[(CTS0, key)], blob=b"\x00" * 8 + key)

    def boom(*_a, **_kw):
        raise RuntimeError("worker exploded")

    monkeypatch.setattr("memdiver.engine.survival_scan._probe", boom)

    result = scan_dump_unit(run / "d.dump", run, sweep_id=SWEEP)

    assert result.outcome == SCAN_OUTCOME_ERROR
    assert result.elapsed_s == 0.0


# --------------------------------------------------------------------------- #
# CONTRACT 5 — the denominator counts SECRET TYPES, not secret entries
# --------------------------------------------------------------------------- #

def test_a_repeated_secret_type_makes_the_two_counts_diverge(tmp_path):
    """THE decision this contract exists for.

    Two entries of one type produce ONE cell, because the unique index is
    ``(sweep_id, dump_path, secret_type)``. A matrix using the ENTRY count as
    its denominator would divide a 1-row numerator by 2 and under-state the
    fraction. On today's corpus the two never diverge (a TLS1.2 keylog declares
    exactly ``{CLIENT_RANDOM}`` and a TLS1.3 keylog exactly five types, with no
    repeats), which is why it had to be settled before the sweep rather than
    discovered from the data.
    """
    a, b = b"A" * 32, b"B" * 32
    run = make_run(tmp_path, secrets=[(CTS0, a), (CTS0, b)],
                   blob=b"\x00" * 8 + b + b"\x00" * 8)

    result = scan_dump_unit(run / "d.dump", run, sweep_id=SWEEP)

    assert result.secrets_available == 2, "two raw keylog ENTRIES"
    assert result.secret_types_available == 1, "one distinct secret TYPE"
    assert result.secret_types_searched == 1
    # The denominator is the one that matches the row count; the entry count
    # does not.
    assert result.secret_types_available == len(result.rows())
    assert result.secrets_available != result.secret_types_available


def test_the_denominator_matches_the_row_count_on_every_ok_unit(tmp_path):
    """Numerator and denominator must be at the same grain, always."""
    run = make_run(tmp_path, secrets=[(STS0, b"z" * 32), (CTS0, b"a" * 32),
                                      (CTS0, b"c" * 32)],
                   blob=b"\x00" * 64)

    result = scan_dump_unit(run / "d.dump", run, sweep_id=SWEEP)

    assert result.secrets_available == 3
    assert result.secret_types_available == 2
    assert len(result.rows()) == result.secret_types_available


def test_an_empty_needle_leaves_the_denominator_at_the_row_grain(tmp_path,
                                                                 monkeypatch):
    """A never-searched needle is in neither the numerator nor the denominator.

    It is still visible as ``secrets_available`` minus
    ``secret_types_available``, and named outright by
    ``secrets_skipped_empty``.
    """
    key = b"K" * 32
    run = make_run(tmp_path, secrets=[(CTS0, key)], blob=b"\x00" * 8 + key)
    monkeypatch.setattr(
        "memdiver.engine.survival_scan.keylog_secrets_for_run",
        lambda run_dir, **kw: (
            [CryptoSecret(secret_type=STS0, identifier=b"\xab",
                          secret_value=b""),
             CryptoSecret(secret_type=CTS0, identifier=b"\xab",
                          secret_value=key)],
            KEYLOG_STATUS_OK))

    result = scan_dump_unit(run / "d.dump", run, sweep_id=SWEEP)

    assert result.secrets_available == 2
    assert result.secrets_skipped_empty == 1
    assert result.secret_types_available == 1
    assert len(result.rows()) == 1


def test_the_denominator_survives_a_unit_that_was_never_searched(tmp_path):
    """"Could have looked" and "did look" are different numbers.

    An unreadable unit still knows how many cells it WOULD have carried, so the
    matrix can render the gap instead of silently shrinking the corpus.
    """
    run = make_run(tmp_path, secrets=[(CTS0, b"a" * 32), (STS0, b"z" * 32)],
                   blob=b"")

    result = scan_dump_unit(run / "d.dump", run, sweep_id=SWEEP)

    assert result.outcome == SCAN_OUTCOME_UNREADABLE
    assert result.secret_types_available == 2
    assert result.secret_types_searched == 0


def test_a_refused_format_still_reports_what_it_would_have_covered(
        tmp_path, monkeypatch):
    key = b"K" * 32
    run = make_run(tmp_path, secrets=[(CTS0, key)], blob=b"\x00" * 8 + key)
    monkeypatch.setattr(
        "memdiver.engine.survival_scan.open_dump",
        lambda path: FakeSource("msl", b"\x00" * 8 + key))

    result = scan_dump_unit(run / "d.dump", run, sweep_id=SWEEP)

    assert result.outcome == SCAN_OUTCOME_UNSUPPORTED_FORMAT
    assert result.secret_types_available == 1
    assert result.secret_types_searched == 0


def test_a_no_keylog_unit_has_a_zero_denominator(tmp_path):
    """No truth means NO DENOMINATOR — not a denominator of zero survivors."""
    run = tmp_path / "run"
    run.mkdir()
    (run / "d.dump").write_bytes(b"\x00" * 64)

    result = scan_dump_unit(run / "d.dump", run, sweep_id=SWEEP)

    assert result.outcome == SCAN_OUTCOME_NO_KEYLOG
    assert result.secret_types_available == 0
    assert result.secret_types_searched == 0


def test_the_denominator_is_on_the_results_jsonl_line(tmp_path):
    """The matrix reads it from the sidecar, so it must serialise."""
    run = make_run(tmp_path, secrets=[(CTS0, b"a" * 32), (CTS0, b"b" * 32)],
                   blob=b"\x00" * 64)

    payload = scan_dump_unit(run / "d.dump", run, sweep_id=SWEEP).to_dict()

    assert payload["secrets_available"] == 2
    assert payload["secret_types_available"] == 1
    assert payload["secret_types_searched"] == 1


# --------------------------------------------------------------------------- #
# The other typed outcomes
# --------------------------------------------------------------------------- #

def test_scan_outcomes_is_the_closed_documented_set():
    assert SCAN_OUTCOMES == (
        SCAN_OUTCOME_OK, SCAN_OUTCOME_UNREADABLE,
        SCAN_OUTCOME_UNSUPPORTED_FORMAT, SCAN_OUTCOME_NO_KEYLOG,
        SCAN_OUTCOME_ERROR,
    )


def test_a_missing_keylog_is_a_typed_outcome_not_a_silent_zero(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    (run / "d.dump").write_bytes(b"\x00" * 64)

    result = scan_dump_unit(run / "d.dump", run, sweep_id=SWEEP)

    assert result.outcome == SCAN_OUTCOME_NO_KEYLOG
    assert result.keylog_status == KEYLOG_STATUS_MISSING
    assert result.observations == ()


def test_an_unreadable_keylog_is_not_a_genuine_zero(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    (run / "keylog.csv").write_text("not a csv header at all")
    (run / "d.dump").write_bytes(b"\x00" * 64)

    result = scan_dump_unit(run / "d.dump", run, sweep_id=SWEEP)

    assert result.outcome == SCAN_OUTCOME_NO_KEYLOG
    assert result.secrets_available == 0


def test_a_clean_but_empty_keylog_is_ok_not_no_keylog(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    (run / "keylog.csv").write_text("id,line\n")
    (run / "d.dump").write_bytes(b"\x00" * 64)

    result = scan_dump_unit(run / "d.dump", run, sweep_id=SWEEP)

    assert result.outcome == SCAN_OUTCOME_OK
    assert result.keylog_status == KEYLOG_STATUS_OK
    assert result.observations == ()


def test_an_empty_dump_is_unreadable_not_a_corpus_wide_absence(tmp_path):
    """A zero-byte view answers every find_first with None — a FALSE absence."""
    key = b"K" * 32
    run = make_run(tmp_path, secrets=[(CTS0, key)], blob=b"")

    result = scan_dump_unit(run / "d.dump", run, sweep_id=SWEEP)

    assert result.outcome == SCAN_OUTCOME_UNREADABLE
    (obs,) = result.observations
    assert obs.status == SURVIVAL_STATUS_UNREADABLE
    assert obs.present is None
    assert obs.secret_type == CTS0
    assert obs.writes_row


def test_a_missing_dump_is_unreadable_and_claims_nothing(tmp_path):
    key = b"K" * 32
    run = make_run(tmp_path, secrets=[(CTS0, key)], blob=b"\x00" * 32)
    (run / "d.dump").unlink()

    result = scan_dump_unit(run / "d.dump", run, sweep_id=SWEEP)

    assert result.outcome == SCAN_OUTCOME_UNREADABLE
    assert all(o.present is None for o in result.observations)


def test_a_raising_worker_writes_no_rows(tmp_path, monkeypatch):
    key = b"K" * 32
    run = make_run(tmp_path, secrets=[(CTS0, key)], blob=b"\x00" * 32)

    def boom(path):
        raise RuntimeError("detector exploded")

    monkeypatch.setattr("memdiver.engine.survival_scan.open_dump", boom)

    result = scan_dump_unit(run / "d.dump", run, sweep_id=SWEEP)

    assert result.outcome == SCAN_OUTCOME_ERROR
    assert result.observations == ()
    assert result.rows() == []
    assert "RuntimeError" in result.detail


# --------------------------------------------------------------------------- #
# Picklability — the worker and its return value both cross a process boundary
# --------------------------------------------------------------------------- #

def test_the_worker_is_module_level_and_pickles_by_reference():
    """A bound method would pickle `self`, dragging a DuckDB connection along.

    Mirrors why ``engine/batch.py::_execute_batch_job`` is module-level.
    """
    assert pickle.loads(pickle.dumps(scan_dump_unit)) is scan_dump_unit
    assert scan_dump_unit.__qualname__ == "scan_dump_unit"


def test_the_worker_arguments_pickle(tmp_path):
    args = (str(tmp_path / "d.dump"), str(tmp_path))
    kwargs = {
        "sweep_id": SWEEP, "unit_key": "u2/corpus/13/s/openssl/unknown/0001/d.dump",
        "run_id": "r1", "library": "openssl", "protocol_version": "13",
        "library_version": "unknown", "scenario": "s", "run_number": 1,
        "phase": "pre_abort", "canonical_phase": "abort",
        "allowed_formats": ("raw",), "view": None,
    }
    assert pickle.loads(pickle.dumps((args, kwargs))) == (args, kwargs)


def test_the_result_round_trips_through_pickle(tmp_path):
    key = bytes(range(0x20, 0x40))
    run = make_run(tmp_path, secrets=[(CTS0, key)],
                   blob=b"\x00" * 16 + key)

    result = scan_dump_unit(run / "d.dump", run, sweep_id=SWEEP)
    restored = pickle.loads(pickle.dumps(result))

    assert restored == result
    assert restored.to_dict() == result.to_dict()
    assert restored.rows() == result.rows()


def test_the_result_is_json_serialisable(tmp_path):
    """It is one `results.jsonl` line."""
    import json

    key = b"K" * 32
    run = make_run(tmp_path, secrets=[(CTS0, key)], blob=b"\x00" * 8 + key)
    result = scan_dump_unit(run / "d.dump", run, sweep_id=SWEEP)

    line = json.dumps(result.to_dict())
    assert json.loads(line)["observations"][0]["present"] is True


# --------------------------------------------------------------------------- #
# The row really is what the writer accepts
# --------------------------------------------------------------------------- #

@needs_duckdb
def test_rows_are_accepted_verbatim_by_add_survival_batch(tmp_path):
    """End-to-end proof that the frozen shape needs no adapter."""
    key = bytes(range(0x20, 0x40))
    run = make_run(tmp_path, secrets=[(CTS0, key)],
                   blob=b"\x00" * 16 + key)
    result = scan_dump_unit(run / "d.dump", run, sweep_id=SWEEP,
                            library="openssl", protocol_version="13")

    with ProjectDB(tmp_path / "p.db") as db:
        written = db.add_survival_batch("run-1", result.rows(), sweep_id=SWEEP)
        # Re-submitting the identical batch is an UPDATE of one row, not a
        # duplicate: the resume path.
        db.add_survival_batch("run-1", result.rows(), sweep_id=SWEEP)

    assert written == 1


@needs_duckdb
def test_unreadable_rows_are_accepted_with_a_null_present(tmp_path):
    key = b"K" * 32
    run = make_run(tmp_path, secrets=[(CTS0, key)], blob=b"")
    result = scan_dump_unit(run / "d.dump", run, sweep_id=SWEEP)

    with ProjectDB(tmp_path / "p.db") as db:
        assert db.add_survival_batch("run-1", result.rows(),
                                     sweep_id=SWEEP) == 1


# --------------------------------------------------------------------------- #
# Real corpus (bounded: one dump, one run) — NOT marked slow.
# --------------------------------------------------------------------------- #

@pytest.mark.requires_dataset
def test_scan_finds_a_known_real_secret_at_its_pinned_offset(dataset_root):
    """One real dump, one real keylog, the offset test_truth_labels pins."""
    run_dir = dataset_root / REAL_RUN_RELPATH
    dump_path = run_dir / REAL_DUMP_NAME
    if not dump_path.is_file() or not (run_dir / "keylog.csv").is_file():
        pytest.skip(f"real corpus run not present under {dataset_root}")

    result = scan_dump_unit(dump_path, run_dir, sweep_id=SWEEP,
                            library="openssl", protocol_version="13",
                            run_number=1, phase="pre_server_key_update")

    assert result.outcome == SCAN_OUTCOME_OK
    assert result.format_name == "raw", "corpus dumps are ET_DYN -> RawDumpSource"
    assert result.size_for_view == dump_path.stat().st_size
    assert result.keylog_status == KEYLOG_STATUS_OK
    assert result.secrets_available >= 1

    by_type = {o.secret_type: o for o in result.observations}
    hit = by_type["CLIENT_TRAFFIC_SECRET_0"]
    assert hit.present is True
    assert hit.first_offset == REAL_CLIENT_TRAFFIC_SECRET_0_OFFSET
    assert hit.hit_count == MAX_HIT_COUNT
    assert hit.status == SURVIVAL_STATUS_SEARCHED
    assert hit.method == METHOD_KEYLOG_SUBSTRING
    # Every cell is a positive record: found or looked-and-absent, never NULL.
    assert all(o.present is not None for o in result.observations)
