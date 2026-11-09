"""Tests for the pipeline stage abstraction + ordered registry.

These lock in that the *default* composed pipeline matches the pre-refactor
hardcoded sequence and that a newly registered stage is both composed into
the correct position and actually invoked by the execution loop.
"""

from __future__ import annotations

import contextlib

import memdiver.app.pipeline.pipeline_runner as pr


# Canonical order the pipeline had before the Stage/registry refactor.
_EXPECTED_DEFAULT_ORDER = [
    "consensus",
    "search_reduce",
    "brute_force",
    "escalate",
    "nsweep",
    "emit_plugin",
]


@contextlib.contextmanager
def _isolated_registry():
    """Snapshot and restore the module-global registry around a test.

    ``register_stage`` mutates a module global; without this every test that
    registers a stage would leak into the others (and into the real worker).
    """
    saved = list(pr._STAGE_REGISTRY)
    try:
        yield
    finally:
        pr._STAGE_REGISTRY[:] = saved


class _FakeCtx:
    """Minimal WorkerContext stand-in: never cancelled, records emits."""

    def __init__(self, cancelled: bool = False):
        self._cancelled = cancelled
        self.emitted: list = []

    def is_cancelled(self) -> bool:
        return self._cancelled

    def emit(self, kind, **kwargs) -> None:  # pragma: no cover - unused here
        self.emitted.append((kind, kwargs))


def _make_state(cancelled: bool = False) -> pr.PipelineState:
    return pr.PipelineState(
        ctx=_FakeCtx(cancelled=cancelled),
        artifact_dir=__import__("pathlib").Path("."),
        reduce_kwargs={},
        oracle_path=__import__("pathlib").Path("oracle"),
        bf_kwargs={},
        nsweep_params=None,
        emit_params=None,
    )


def test_default_pipeline_order_matches_pre_refactor_sequence():
    names = [s.name for s in pr.get_pipeline_stages()]
    assert names == _EXPECTED_DEFAULT_ORDER


def test_default_gating_flags_preserved():
    stages = {s.name: s for s in pr.get_pipeline_stages()}
    # consensus checked cancellation only inside its fold loop historically.
    assert stages["consensus"].check_cancel_before is False
    for name in ("search_reduce", "brute_force", "nsweep", "emit_plugin"):
        assert stages[name].check_cancel_before is True
    # nsweep / emit are the two optional stages.
    state = _make_state()
    assert stages["search_reduce"].enabled(state) is True
    assert stages["nsweep"].enabled(state) is False
    assert stages["emit_plugin"].enabled(state) is False
    # escalate is opt-in: disabled by default (escalate=False on the state).
    assert stages["escalate"].enabled(state) is False
    state.nsweep_params = {"n_values": [1]}
    state.emit_params = {"name": "x"}
    assert stages["nsweep"].enabled(state) is True
    assert stages["emit_plugin"].enabled(state) is True


def test_register_stage_appears_in_composed_order():
    with _isolated_registry():
        dummy = pr.Stage("dummy", lambda state: None)
        pr.register_stage(dummy, after="brute_force")
        names = [s.name for s in pr.get_pipeline_stages()]
        assert names == [
            "consensus",
            "search_reduce",
            "brute_force",
            "dummy",
            "escalate",
            "nsweep",
            "emit_plugin",
        ]


def test_register_stage_before_and_index():
    with _isolated_registry():
        pr.register_stage(pr.Stage("first", lambda s: None), index=0)
        pr.register_stage(pr.Stage("pre_bf", lambda s: None), before="brute_force")
        names = [s.name for s in pr.get_pipeline_stages()]
        assert names[0] == "first"
        assert names[names.index("pre_bf") + 1] == "brute_force"


def test_registered_stage_run_is_invoked():
    calls: list = []
    dummy = pr.Stage("dummy", lambda state: calls.append(state))
    state = _make_state()
    pr._execute_stages(state, [dummy])
    assert calls == [state]


def test_disabled_stage_is_not_invoked():
    calls: list = []
    dummy = pr.Stage(
        "dummy",
        lambda state: calls.append("ran"),
        enabled=lambda state: False,
    )
    pr._execute_stages(_make_state(), [dummy])
    assert calls == []


def test_cancel_guard_raises_before_guarded_stage():
    calls: list = []
    guarded = pr.Stage("guarded", lambda s: calls.append("ran"))
    try:
        pr._execute_stages(_make_state(cancelled=True), [guarded])
    except pr._CancelledByContext:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected _CancelledByContext")
    assert calls == []


def test_unguarded_stage_runs_even_when_cancelled():
    calls: list = []
    unguarded = pr.Stage(
        "unguarded",
        lambda s: calls.append("ran"),
        check_cancel_before=False,
    )
    pr._execute_stages(_make_state(cancelled=True), [unguarded])
    assert calls == ["ran"]


def test_register_stage_twice_is_idempotent():
    """Registering the same stage name twice must not double-execute it.

    Guards the replace-by-name semantics in ``register_stage`` (double import,
    plugin setup invoked twice, hot-reload): the registry keeps exactly one
    entry, and running it executes the stage exactly once (last write wins).
    """
    with _isolated_registry():
        calls: list = []
        pr.register_stage(
            pr.Stage("dup", lambda s: calls.append("first")), after="brute_force"
        )
        pr.register_stage(
            pr.Stage("dup", lambda s: calls.append("second")), after="brute_force"
        )

        names = [s.name for s in pr.get_pipeline_stages()]
        assert names.count("dup") == 1  # deduplicated, not appended twice

        # Executing the composed registry's "dup" stage runs it exactly once,
        # and it is the second (replacing) registration that survives.
        dup_stages = [s for s in pr.get_pipeline_stages() if s.name == "dup"]
        pr._execute_stages(_make_state(), dup_stages)
        assert calls == ["second"]


def test_a_scudo_run_only_turns_off_the_consensus_stage():
    """The stage stays registered, so positions relative to it keep working."""
    stages = {s.name: s for s in pr.get_pipeline_stages()}
    state = _make_state()
    assert stages["consensus"].enabled(state) is True

    state.scudo_params = {"allocator": "auto"}

    assert stages["consensus"].enabled(state) is False
    assert stages["search_reduce"].enabled(state) is True
    assert stages["brute_force"].enabled(state) is True
    assert [s.name for s in pr.get_pipeline_stages()] == _EXPECTED_DEFAULT_ORDER
