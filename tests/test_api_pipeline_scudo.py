"""``POST /api/pipeline/run`` with the Android Scudo method.

The request either runs the chain the CLI runs or is refused before a worker
starts: an option that only means something for the positional consensus must
never be dropped silently, and asking for a Volatility plugin says why that is
not supported yet. A request without ``scudo`` reaches the worker unchanged.
"""

from __future__ import annotations

import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest
from fastapi.testclient import TestClient

from memdiver.api.config import get_settings
from memdiver.api.main import create_app
from memdiver.api.services.task_manager import TaskManager
from tests.fixtures.generate_scudo_msl_fixtures import (
    SECRET_SIZE,
    secret_value,
    write_scudo_msl_fixtures,
)

PLUGIN_MESSAGE_FRAGMENT = "Volatility 3 plugin generation is not supported yet"
BRUTE_FORCE = {"key_sizes": [SECRET_SIZE], "stride": 1, "jobs": 1}


@pytest.fixture
def client(tmp_path: Path, monkeypatch):
    for name, sub in (("MEMDIVER_ORACLE_DIR", "oracles"), ("MEMDIVER_TASK_ROOT", "tasks")):
        (tmp_path / sub).mkdir()
        monkeypatch.setenv(name, str(tmp_path / sub))
    monkeypatch.setenv("MEMDIVER_TASK_QUOTA_BYTES", "10485760")
    monkeypatch.setenv("MEMDIVER_PIPELINE_MAX_WORKERS", "1")
    get_settings.cache_clear()
    with TestClient(create_app()) as test_client:
        yield test_client
    get_settings.cache_clear()


@pytest.fixture
def scudo_runs(tmp_path: Path) -> List[str]:
    return [str(p) for p in write_scudo_msl_fixtures(tmp_path / "runs", 3)]


@pytest.fixture
def oracle_id(client: TestClient) -> str:
    source = (f"TARGET = bytes.fromhex({secret_value(0).hex()!r})\n"
              "def verify(candidate):\n"
              "    return candidate == TARGET\n")
    uploaded = client.post(
        "/api/oracles/upload", files={"file": ("t.py", source.encode(), "text/x-python")})
    assert uploaded.status_code == 200, uploaded.text
    body = uploaded.json()
    armed = client.post(f"/api/oracles/{body['id']}/arm", json={"sha256": body["sha256"]})
    assert armed.status_code == 200, armed.text
    return body["id"]


@pytest.fixture
def submitted(monkeypatch) -> Dict[str, Any]:
    captured: Dict[str, Any] = {}

    def _fake_submit(_self, **kwargs):
        captured.update(kwargs)
        return SimpleNamespace(task_id="captured", status=SimpleNamespace(value="pending"))

    monkeypatch.setattr(TaskManager, "submit", _fake_submit)
    return captured


def _run(client: TestClient, paths: List[str], oracle: str, **body: Any):
    return client.post("/api/pipeline/run", json={
        "source_paths": paths, "oracle_id": oracle, "brute_force": BRUTE_FORCE,
        "scudo": {"allocator": "scudo"}, **body,
    })


def _wait_terminal(client: TestClient, task_id: str, timeout: float = 60.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        record = client.get(f"/api/pipeline/runs/{task_id}").json()
        if record["status"] in ("succeeded", "failed", "cancelled"):
            return record
        time.sleep(0.1)
    raise AssertionError(f"task {task_id} never reached a terminal state")


# ---------------------------------------------------------------------------
# What reaches the worker
# ---------------------------------------------------------------------------


def test_a_scudo_run_skips_the_consensus_stage(client, scudo_runs, oracle_id, submitted):
    response = _run(client, scudo_runs, oracle_id)
    assert response.status_code == 200, response.text
    assert submitted["params"]["scudo"] == {"allocator": "scudo"}
    assert submitted["stage_names"] == ["search_reduce", "brute_force"]


def test_auto_is_the_default_allocator(client, scudo_runs, oracle_id, submitted):
    assert _run(client, scudo_runs, oracle_id, scudo={}).status_code == 200
    assert submitted["params"]["scudo"] == {"allocator": "auto"}


def test_a_positional_run_is_unchanged(client, scudo_runs, oracle_id, submitted):
    response = client.post("/api/pipeline/run", json={
        "source_paths": scudo_runs, "oracle_id": oracle_id,
    })
    assert response.status_code == 200, response.text
    assert "scudo" not in submitted["params"]
    assert submitted["stage_names"] == ["consensus", "search_reduce", "brute_force"]


# ---------------------------------------------------------------------------
# Refusals, before a worker starts
# ---------------------------------------------------------------------------


def test_a_plugin_request_says_it_is_not_supported_yet(
    client, scudo_runs, oracle_id, submitted,
):
    response = _run(client, scudo_runs, oracle_id, emit={"name": "plugin"})
    assert response.status_code == 400, response.text
    body = response.json()
    assert body["code"] == "scudo.plugin_unsupported"
    assert PLUGIN_MESSAGE_FRAGMENT in body["error"]
    assert not submitted


@pytest.mark.parametrize(("extra", "option"), [
    ({"nsweep": {"n_values": [2]}}, "nsweep"),
    ({"escalate": True}, "escalate"),
    ({"region_filter": "heap"}, "region_filter"),
    ({"reduce": {"min_variance": 1.0}}, "reduce"),
    ({"reduce": {"heap_policy": "mask"}}, "reduce"),
])
def test_a_positional_option_is_refused_by_name(
    client, scudo_runs, oracle_id, submitted, extra, option,
):
    response = _run(client, scudo_runs, oracle_id, **extra)
    assert response.status_code == 400, response.text
    body = response.json()
    assert body["code"] == "scudo.unsupported_option"
    assert option in body["error"]
    assert not submitted


def test_an_empty_reduce_block_is_not_an_option(client, scudo_runs, oracle_id, submitted):
    assert _run(client, scudo_runs, oracle_id, reduce={}).status_code == 200
    assert submitted


def test_one_dump_is_refused(client, scudo_runs, oracle_id, submitted):
    response = _run(client, scudo_runs[:1], oracle_id)
    assert response.status_code == 400
    assert response.json()["code"] == "scudo.too_few_dumps"
    assert not submitted


def test_a_non_msl_dump_is_refused(client, scudo_runs, oracle_id, submitted, tmp_path):
    raw = tmp_path / "raw.bin"
    raw.write_bytes(b"\x00" * 64)
    response = _run(client, [*scudo_runs, str(raw)], oracle_id)
    assert response.status_code >= 400
    assert response.json()["code"] == "scudo.not_msl"
    assert not submitted


def test_a_dump_named_twice_is_refused(client, scudo_runs, oracle_id, submitted):
    response = _run(client, [*scudo_runs, scudo_runs[0]], oracle_id)
    assert response.status_code == 400
    assert response.json()["code"] == "scudo.duplicate_dumps"
    assert not submitted


def test_invalid_key_sizes_are_refused(client, scudo_runs, oracle_id, submitted):
    response = _run(client, scudo_runs, oracle_id, brute_force={"key_sizes": [0]})
    assert response.status_code == 400
    assert response.json()["code"] == "scudo.invalid_key_sizes"
    assert not submitted


def test_an_unknown_allocator_fails_validation(client, scudo_runs, oracle_id):
    response = _run(client, scudo_runs, oracle_id, scudo={"allocator": "ptmalloc2"})
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# The whole loop, through a real worker
# ---------------------------------------------------------------------------


def test_a_real_worker_finds_the_reference_runs_secret(client, scudo_runs, oracle_id):
    response = _run(client, scudo_runs, oracle_id)
    assert response.status_code == 200, response.text
    task_id = response.json()["task_id"]

    record = _wait_terminal(client, task_id)

    assert record["status"] == "succeeded", record
    assert {a["name"] for a in record["artifacts"]} == {"candidates", "hits"}
    assert [s["name"] for s in record["stages"]] == ["search_reduce", "brute_force"]
    for spec in record["artifacts"]:
        download = client.get(f"/api/pipeline/runs/{task_id}/artifacts/{spec['name']}")
        assert download.status_code == 200, (spec, download.text)
        assert len(download.content) == spec["size"]
    hits = client.get(f"/api/pipeline/runs/{task_id}/artifacts/hits").json()
    assert [h["key_hex"] for h in hits["hits"]] == [secret_value(0).hex()]

    # Refine and the neighborhood read need the Welford state this run lacks.
    refine = client.post(f"/api/pipeline/runs/{task_id}/refine",
                         json={"additional_paths": [scudo_runs[1]]})
    assert refine.status_code == 400
    neighborhood = client.get(f"/api/pipeline/runs/{task_id}/neighborhood",
                              params={"offset": 0})
    assert neighborhood.status_code == 400


def test_a_worker_refusal_reaches_the_task_record(client, scudo_runs, oracle_id):
    """These minimal fixtures are not detected as Scudo."""
    response = _run(client, scudo_runs, oracle_id, scudo={"allocator": "auto"})
    assert response.status_code == 200, response.text

    record = _wait_terminal(client, response.json()["task_id"])

    assert record["status"] == "failed"
    assert "Scudo" in record["error"]
