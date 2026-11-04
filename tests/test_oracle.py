"""Tests for engine.oracle — BYO oracle loader."""

import os
import stat
import sys
import tempfile
import time
from pathlib import Path

import pytest

from memdiver.engine import oracle as oracle_mod
from memdiver.engine.oracle import (
    OracleLoadError,
    load_oracle,
    load_oracle_config,
    validate_oracle_sandboxed,
)


def _write(path: Path, content: str, mode: int = 0o644) -> Path:
    path.write_text(content)
    os.chmod(path, mode)
    return path


def test_shape1_stateless_function(tmp_path):
    src = _write(tmp_path / "o.py", "def verify(c): return c == b'yes'\n")
    verify = load_oracle(src)
    assert verify(b"yes") is True
    assert verify(b"no") is False


def test_load_oracle_emits_sha256_audit_at_warning(tmp_path, caplog):
    """Security audit: loading an oracle executes arbitrary user Python, so the
    sha256 'loaded oracle' notice must be visible at the DEFAULT WARNING level
    (the MCP server / non-verbose CLI default the root logger to WARNING, which
    would drop an ``info`` record). Regression for the code-review finding that a
    ``print``→``logger.info`` change silently suppressed this audit trail."""
    import logging

    src = _write(tmp_path / "o.py", "def verify(c): return True\n")
    with caplog.at_level(logging.WARNING, logger="memdiver.engine.oracle"):
        load_oracle(src)
    assert any(
        "loaded oracle" in r.getMessage() and r.levelno == logging.WARNING
        for r in caplog.records
    ), "oracle-load audit line not emitted at WARNING"


def test_shape2_stateful_factory(tmp_path):
    src = _write(
        tmp_path / "o.py",
        "def build_oracle(cfg):\n"
        "    return O(cfg['target'])\n"
        "class O:\n"
        "    def __init__(self, t): self.t = t\n"
        "    def verify(self, c): return c == self.t\n",
    )
    verify = load_oracle(src, {"target": b"hit"})
    assert verify(b"hit") is True
    assert verify(b"miss") is False


def test_shape2_preferred_over_shape1(tmp_path):
    """When both exports exist, build_oracle wins (explicit over implicit)."""
    src = _write(
        tmp_path / "o.py",
        "def verify(c): return True\n"
        "def build_oracle(cfg):\n"
        "    return O()\n"
        "class O:\n"
        "    def verify(self, c): return False\n",
    )
    verify = load_oracle(src, {})
    assert verify(b"anything") is False


def test_missing_exports_raises(tmp_path):
    src = _write(tmp_path / "o.py", "x = 1\n")
    with pytest.raises(OracleLoadError, match="must export"):
        load_oracle(src)


def test_build_oracle_without_verify_raises(tmp_path):
    src = _write(
        tmp_path / "o.py",
        "def build_oracle(cfg): return object()\n",
    )
    with pytest.raises(OracleLoadError, match="no verify"):
        load_oracle(src)


def test_refuses_world_writable_file(tmp_path):
    src = _write(tmp_path / "o.py", "def verify(c): return True\n", mode=0o666)
    with pytest.raises(OracleLoadError, match="world-writable"):
        load_oracle(src)


def test_refuses_group_writable_file(tmp_path):
    """Regression: a group-writable oracle is hijackable on a shared host."""
    src = _write(tmp_path / "o.py", "def verify(c): return True\n", mode=0o664)
    with pytest.raises(OracleLoadError, match="writable oracle"):
        load_oracle(src)


def test_refuses_group_writable_parent_dir(tmp_path):
    """Regression: a group-writable parent dir lets the file be replaced."""
    sub = tmp_path / "sub"
    sub.mkdir()
    src = _write(sub / "o.py", "def verify(c): return True\n", mode=0o644)
    os.chmod(sub, 0o775)
    with pytest.raises(OracleLoadError, match="writable directory"):
        load_oracle(src)


def test_missing_file_raises(tmp_path):
    with pytest.raises(OracleLoadError, match="not found"):
        load_oracle(tmp_path / "nonexistent.py")


def test_import_error_wrapped(tmp_path):
    src = _write(tmp_path / "o.py", "raise RuntimeError('boom')\n")
    with pytest.raises(OracleLoadError, match="failed to import"):
        load_oracle(src)


def test_load_config_missing_returns_empty_for_none():
    assert load_oracle_config(None) == {}


def test_load_config_missing_file_raises(tmp_path):
    with pytest.raises(OracleLoadError, match="not found"):
        load_oracle_config(tmp_path / "missing.toml")


def test_load_config_toml_roundtrip(tmp_path):
    cfg = tmp_path / "cfg.toml"
    cfg.write_text('target = "foo"\nnumber = 42\n')
    out = load_oracle_config(cfg)
    assert out == {"target": "foo", "number": 42}


# ---------- load-time sandbox ----------


def test_sandbox_accepts_good_shape1(tmp_path):
    """A well-behaved Shape-1 oracle validates without raising."""
    src = _write(tmp_path / "o.py", "def verify(c): return c == b'yes'\n")
    # Returns None (no raise).
    assert validate_oracle_sandboxed(src, {}) is None


def test_sandbox_accepts_good_shape2(tmp_path):
    """A Shape-2 oracle whose build_oracle succeeds validates cleanly."""
    src = _write(
        tmp_path / "o.py",
        "def build_oracle(cfg):\n"
        "    return O()\n"
        "class O:\n"
        "    def verify(self, c): return True\n",
    )
    assert validate_oracle_sandboxed(src, {}) is None


def test_sandbox_rejects_hang_at_import(tmp_path):
    """A module-top-level infinite loop is killed by the wall-clock timeout."""
    src = _write(
        tmp_path / "o.py",
        "while True:\n    pass\n\ndef verify(c): return True\n",
    )
    t0 = time.monotonic()
    # cpu_s kept well above the wall budget so the wall-clock join is the
    # deterministic trigger (not a racing SIGXCPU during spawn bootstrap).
    with pytest.raises(OracleLoadError, match="wall-clock"):
        validate_oracle_sandboxed(src, {}, timeout_s=0.5, cpu_s=30)
    # Must fail fast — the short wall-clock timeout, not the 10s default.
    assert time.monotonic() - t0 < 5.0


def test_sandbox_rejects_hang_in_build_oracle(tmp_path):
    """A hang inside build_oracle() is caught by the wall-clock timeout."""
    src = _write(
        tmp_path / "o.py",
        "def build_oracle(cfg):\n"
        "    while True:\n"
        "        pass\n",
    )
    t0 = time.monotonic()
    with pytest.raises(OracleLoadError, match="wall-clock"):
        validate_oracle_sandboxed(src, {}, timeout_s=0.5, cpu_s=30)
    assert time.monotonic() - t0 < 5.0


def test_sandbox_rejects_build_oracle_that_raises(tmp_path):
    """A normal exception in build_oracle surfaces as a load failure."""
    src = _write(
        tmp_path / "o.py",
        "def build_oracle(cfg):\n"
        "    raise ValueError('boom')\n",
    )
    with pytest.raises(OracleLoadError, match="failed to load"):
        validate_oracle_sandboxed(src, {}, timeout_s=5.0)


def test_sandbox_rejects_import_error(tmp_path):
    """A module that raises at import surfaces as a load failure."""
    src = _write(tmp_path / "o.py", "raise RuntimeError('nope')\n")
    with pytest.raises(OracleLoadError, match="failed to load"):
        validate_oracle_sandboxed(src, {}, timeout_s=5.0)


@pytest.mark.skipif(
    sys.platform == "darwin",
    reason="RLIMIT_AS is unreliable on macOS; wall-clock hang test is the "
    "portable guarantee",
)
def test_sandbox_rejects_memory_bomb_at_import(tmp_path):
    """A large allocation at import trips RLIMIT_AS (Linux)."""
    src = _write(tmp_path / "o.py", "x = bytearray(4 * 1024**3)\n")
    with pytest.raises(OracleLoadError):
        validate_oracle_sandboxed(
            src, {}, timeout_s=5.0, cpu_s=5, mem_bytes=256 * 1024**2
        )


def test_load_oracle_runs_sandbox_by_default(tmp_path, monkeypatch):
    """load_oracle probes via the sandbox on the default path."""
    called = {}

    def _spy(path, config, timeout_s, cpu_s, mem_bytes):
        called["path"] = Path(path)
        return ("ok", None)

    monkeypatch.setattr(oracle_mod, "_sandbox_probe", _spy)
    src = _write(tmp_path / "o.py", "def verify(c): return True\n")
    load_oracle(src)
    assert called["path"] == src.resolve()


def test_sandbox_ok_result_is_memoized_until_file_changes(tmp_path, monkeypatch):
    """A successful validation of an unchanged file is not re-spawned; touching
    the file's mtime/size busts the cache and re-spawns (TOCTOU re-check)."""
    spawns = {"n": 0}

    def _counting_spawn(path, config, timeout_s, cpu_s, mem_bytes):
        spawns["n"] += 1
        return ("ok", None)

    monkeypatch.setattr(oracle_mod, "_sandbox_probe_spawn", _counting_spawn)
    monkeypatch.setattr(oracle_mod, "_SANDBOX_OK_CACHE", {})

    src = _write(tmp_path / "o.py", "def verify(c): return True\n")
    validate_oracle_sandboxed(src, {})
    assert spawns["n"] == 1
    # Second validation of the identical file hits the cache — no new spawn.
    validate_oracle_sandboxed(src, {})
    assert spawns["n"] == 1

    # Modify the file (new content → different size + mtime) → cache miss.
    _write(src, "def verify(c): return c == b'x'\n")
    validate_oracle_sandboxed(src, {})
    assert spawns["n"] == 2


def test_sandbox_cache_is_content_addressed_not_mtime_size(tmp_path, monkeypatch):
    """FIX #4: a same-length content swap with a forged (identical) mtime must
    still bust the ok-cache, because the key folds in the file's sha256. A
    (mtime, size)-only key would falsely hit and skip re-validation."""
    spawns = {"n": 0}

    def _counting_spawn(path, config, timeout_s, cpu_s, mem_bytes):
        spawns["n"] += 1
        return ("ok", None)

    monkeypatch.setattr(oracle_mod, "_sandbox_probe_spawn", _counting_spawn)
    monkeypatch.setattr(oracle_mod, "_SANDBOX_OK_CACHE", {})

    src = tmp_path / "o.py"
    # Two distinct 400-byte bodies (same length, different content).
    body_a = b"# benign\n" + b"def verify(c): return True\n"
    body_b = b"# EVIL!!\n" + b"def verify(c): return True\n"
    body_a = body_a + b"#" * (400 - len(body_a)) + b"\n"
    body_b = body_b + b"#" * (400 - len(body_b)) + b"\n"
    assert len(body_a) == len(body_b)

    src.write_bytes(body_a)
    os.chmod(src, 0o644)
    st = src.stat()
    validate_oracle_sandboxed(src, {})
    assert spawns["n"] == 1

    # Swap content but forge identical mtime + size (same length) — the classic
    # TOCTOU evasion a (mtime,size)-only key would miss.
    src.write_bytes(body_b)
    os.utime(src, ns=(st.st_atime_ns, st.st_mtime_ns))
    assert src.stat().st_size == st.st_size
    assert src.stat().st_mtime_ns == st.st_mtime_ns

    validate_oracle_sandboxed(src, {})
    # sha256 differs → cache miss → re-spawn. Without FIX #4 this stays 1.
    assert spawns["n"] == 2


def test_sandbox_err_with_huge_repr_is_fast_not_a_hang(tmp_path):
    """FIX #3: a build_oracle raising an exception with a multi-MB repr() must be
    classified as 'err' (fast), NOT starve the pipe send and be misclassified as
    a wall-clock 'hang'. The child truncates the detail so the send never blocks."""
    src = _write(
        tmp_path / "o.py",
        "def build_oracle(cfg):\n"
        "    raise ValueError('X' * 5_000_000)\n",
    )
    # The timeout is the yardstick, not a guess at machine speed: the fixed cost
    # here is spawning a Python child (~1-2 s idle, 4+ s on a loaded box), so a
    # 5 s timeout let load alone push the honest err path into the hang branch.
    # A starved pipe send blocks until the deadline, so a regression still
    # takes the full ``timeout_s`` and fails both checks below.
    timeout_s = 30.0
    t0 = time.monotonic()
    with pytest.raises(OracleLoadError, match="failed to load") as ei:
        validate_oracle_sandboxed(src, {}, timeout_s=timeout_s)
    elapsed = time.monotonic() - t0
    # Fast err path, well under the timeout — and NOT the hang message.
    assert elapsed < timeout_s / 2, elapsed
    assert "wall-clock" not in str(ei.value)


def test_load_oracle_sandbox_false_skips_validation(tmp_path, monkeypatch):
    """sandbox=False opts out of validation (the hot-path re-load case).

    Bounded/safe: rather than actually hanging, we monkeypatch the probe to blow
    up if called — proving sandbox=False never invokes it, while a valid oracle
    still loads exactly as before.
    """
    def _boom(*a, **k):  # pragma: no cover - must never run
        raise AssertionError("_sandbox_probe called with sandbox=False")

    monkeypatch.setattr(oracle_mod, "_sandbox_probe", _boom)
    src = _write(tmp_path / "o.py", "def verify(c): return c == b'ok'\n")
    verify = load_oracle(src, sandbox=False)
    assert verify(b"ok") is True
    assert verify(b"no") is False


# ---------------------------------------------------------------------------
# assert_oracle_not_hostile — the lenient half of the sandbox policy
#
# Containment (hang / resource-kill) is non-negotiable; a reproducible
# exception is not a containment failure, it is an unconfigured oracle. These
# pin both halves, because a lenient probe that quietly stopped blocking would
# look identical to a working one on every happy-path test.
# ---------------------------------------------------------------------------


def test_assert_not_hostile_allows_a_reproducible_build_error(tmp_path):
    """A Shape-2 oracle probed before it has been configured must pass.

    This is the bundled gocryptfs example's exact shape: a bare ``cfg[...]``
    lookup that raises KeyError under an empty config. The strict validator
    rejects it (see below); the lenient one must not.
    """
    src = _write(
        tmp_path / "o.py",
        "def build_oracle(cfg):\n"
        "    return O(cfg['sample_ciphertext'])\n"
        "class O:\n"
        "    def __init__(self, p): self.p = p\n"
        "    def verify(self, c): return True\n",
    )
    assert oracle_mod.assert_oracle_not_hostile(src, {}) is None
    # ...and the strict policy still refuses it, unchanged.
    with pytest.raises(OracleLoadError, match="sample_ciphertext"):
        validate_oracle_sandboxed(src, {})


def test_assert_not_hostile_allows_an_import_error(tmp_path):
    src = _write(tmp_path / "o.py", "raise RuntimeError('nope')\n")
    assert oracle_mod.assert_oracle_not_hostile(src, {}, timeout_s=5.0) is None


def test_assert_not_hostile_still_rejects_hang_at_import(tmp_path):
    """Same oracle body as ``test_sandbox_rejects_hang_at_import``."""
    src = _write(
        tmp_path / "o.py",
        "while True:\n    pass\n\ndef verify(c): return True\n",
    )
    t0 = time.monotonic()
    with pytest.raises(OracleLoadError, match="wall-clock"):
        oracle_mod.assert_oracle_not_hostile(src, {}, timeout_s=0.5, cpu_s=30)
    assert time.monotonic() - t0 < 5.0


def test_assert_not_hostile_still_rejects_hang_in_build_oracle(tmp_path):
    """The case the relaxation actually touches, so the one that proves it.

    ``build_oracle`` is exactly where a tolerated exception now falls through;
    a hang in the same function must still be blocked, or the lenient probe
    would be a no-op dressed as a guard. Body reused from
    ``test_sandbox_rejects_hang_in_build_oracle``.
    """
    src = _write(
        tmp_path / "o.py",
        "def build_oracle(cfg):\n"
        "    while True:\n"
        "        pass\n",
    )
    t0 = time.monotonic()
    with pytest.raises(OracleLoadError, match="wall-clock"):
        oracle_mod.assert_oracle_not_hostile(src, {}, timeout_s=0.5, cpu_s=30)
    assert time.monotonic() - t0 < 5.0


def test_assert_not_hostile_accepts_a_good_oracle(tmp_path):
    src = _write(tmp_path / "o.py", "def verify(c): return True\n")
    assert oracle_mod.assert_oracle_not_hostile(src) is None


def test_build_error_is_an_oracle_load_error_subclass(tmp_path):
    """Additive by construction: existing ``except OracleLoadError`` still wins.

    The split only exists so a caller can opt into the distinction by naming
    OracleBuildError; anything that raises a bare OracleLoadError must keep
    reading as "not known to be benign".
    """
    src = _write(tmp_path / "o.py", "def build_oracle(cfg):\n    raise ValueError('x')\n")
    with pytest.raises(oracle_mod.OracleBuildError) as excinfo:
        validate_oracle_sandboxed(src, {}, timeout_s=5.0)
    assert isinstance(excinfo.value, OracleLoadError)
    assert str(excinfo.value).startswith("oracle failed to load:")


def test_hang_does_not_raise_the_benign_subclass(tmp_path):
    """A containment failure must never be mistaken for a mere build error."""
    src = _write(tmp_path / "o.py", "while True:\n    pass\n")
    with pytest.raises(OracleLoadError) as excinfo:
        validate_oracle_sandboxed(src, {}, timeout_s=0.5, cpu_s=30)
    assert not isinstance(excinfo.value, oracle_mod.OracleBuildError)


def test_sandbox_probe_writes_no_bytecode_next_to_the_oracle(tmp_path):
    """The spawned probe must not leave a ``__pycache__`` beside the oracle.

    The sandbox child is a *fresh* interpreter: it never constructs an
    ``OracleRegistry``, so the ``sys.dont_write_bytecode = True`` that the
    registry sets in the parent does not apply there. Before the fix, probing
    an oracle in the 0700 ``~/.memdiver/oracles/`` dir dropped a 0755
    ``__pycache__/`` holding a .pyc of the user's oracle — defeating the
    registry's own purge and re-opening the stale-bytecode shadowing hole
    (a .pyc can shadow an edited .py, so what executes is not what was
    hashed and armed).
    """
    oracle_dir = tmp_path / "oracles"
    oracle_dir.mkdir()
    src = _write(
        oracle_dir / "no_bytecode_probe.py",
        "MARKER = 'sandbox-bytecode-probe'\n\ndef verify(c): return c == b'yes'\n",
    )

    kind, detail = oracle_mod._sandbox_probe(src, {}, 10.0, 10, 2 * 1024**3)

    # Guard against a vacuous pass: the probe must actually have run and
    # imported the module, otherwise "no .pyc" proves nothing.
    assert (kind, detail) == ("ok", None)

    assert not (oracle_dir / "__pycache__").exists(), (
        "sandbox probe created a __pycache__ next to the oracle"
    )
    assert list(oracle_dir.rglob("*.pyc")) == []


def test_reserved_table_never_reaches_build_oracle(tmp_path: Path) -> None:
    """``[memdiver]`` is our automation metadata, not the oracle's config.

    Surface-parity guard. The web surface strips the reserved table when it
    builds a config_template, but the CLI's ``--oracle-config`` hands
    ``load_oracle_config``'s raw dict straight to ``build_oracle`` -- so an
    oracle that validates its config strictly used to work in the browser and
    raise on the command line, for the same ``.toml``. Stripping happens at the
    boundary into user code, so every surface passes the same keys.
    """
    oracle_path = tmp_path / "strict.py"
    oracle_path.write_text(
        "class _O:\n"
        "    def __init__(self, cfg):\n"
        "        unknown = set(cfg) - {'sample'}\n"
        "        if unknown:\n"
        "            raise KeyError(f'unexpected config keys: {sorted(unknown)}')\n"
        "        self.sample = cfg['sample']\n"
        "    def verify(self, candidate):\n"
        "        return candidate == self.sample.encode()\n"
        "\n"
        "def build_oracle(config):\n"
        "    return _O(config)\n"
    )
    oracle_path.chmod(0o600)

    config = {
        "sample": "hit",
        "memdiver": {"requires_cipher": "aes"},
    }
    verify = load_oracle(oracle_path, config=config, sandbox=False)

    assert verify(b"hit") is True
    assert verify(b"miss") is False
    # The caller's dict is never mutated -- it belongs to them.
    assert "memdiver" in config


def test_load_oracle_writes_no_bytecode_beside_user_source(tmp_path: Path) -> None:
    """A sandbox-less load must not drop a ``.pyc`` next to the analyst's oracle.

    Found by accident: a verification script called ``load_oracle(...,
    sandbox=False)`` and left a ``__pycache__`` in the oracle directory, which
    the sandbox-child fix did not cover. The registry sets
    ``sys.dont_write_bytecode`` for the WEB server's process and the spawn child
    sets it for its own, so a CLI ``--oracle mine.py`` run and every library
    caller still wrote bytecode beside the user's source -- where a stale
    ``.pyc`` can shadow an edited ``.py``, making what runs differ from what was
    hashed and armed.
    """
    oracle_path = tmp_path / "plain.py"
    oracle_path.write_text("def verify(candidate):\n    return candidate == b'k'\n")
    oracle_path.chmod(0o600)

    verify = load_oracle(oracle_path, config={}, sandbox=False)

    assert verify(b"k") is True
    assert not (tmp_path / "__pycache__").exists()
    assert list(tmp_path.rglob("*.pyc")) == []


def test_load_oracle_restores_the_bytecode_flag(tmp_path: Path) -> None:
    """``sys.dont_write_bytecode`` is process-global; MemDiver is a library too.

    Leaving it set would silently disable bytecode caching for whatever
    application imported MemDiver, long after the oracle finished loading.
    """
    oracle_path = tmp_path / "plain.py"
    oracle_path.write_text("def verify(candidate):\n    return True\n")
    oracle_path.chmod(0o600)

    before = sys.dont_write_bytecode
    load_oracle(oracle_path, config={}, sandbox=False)
    assert sys.dont_write_bytecode is before
