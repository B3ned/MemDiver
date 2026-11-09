"""search-reduce (Scudo mode): brute-force candidates from a Scudo chunk consensus.

The Android Scudo pipeline is the chain ``consensus-begin --allocator
scudo/auto`` -> ``consensus-add`` xN -> ``search-reduce --state`` ->
``brute-force``: search-reduce keeps its generic CLI surface (--state
--reference-dump -o) and the collected session's kind selects the Scudo
producer. The flagship (T1) runs exactly that chain on runs whose secret Scudo
moved every run (another slot, another base VA) and must find, for EVERY choice
of reference, that run's OWN secret at the offset the candidates name. Around it
the mode is held to what makes the chain trustworthy:

* **Partition.** Every chunk of the reference gets exactly one verdict, so the
  funnel always adds up to the chunks the reference holds.
* **One to one.** The kept set is the selection rule -- rebuilt below from the
  JSON provenance, independently of the classifier -- deduplicated and nothing
  else.
* **The bytes contract.** Every region, sliced out of the reference exactly as
  brute-force reads it (``read_all()``), is the chunk the consensus judged.
* **Refusals instead of silent wrong answers**: a dump named twice, a
  reference outside the dumps, a locked or truncated dump, a non-``.msl``.
* **memdiver's own allocator detection.** An ``auto`` session defers the
  allocator decision to search-reduce, which runs ``detect_allocator`` on the
  reference and proceeds only for Scudo.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.app.tools_pipeline import brute_force  # noqa: E402
from memdiver.app.tools_pipeline_android import (  # noqa: E402
    CANDIDATES_EMPTY_CODE,
    DUMP_NOT_FOUND_CODE,
    DUPLICATE_DUMPS_CODE,
    INVALID_KEY_SIZES_CODE,
    NOT_JUDGED_CODE,
    NOT_MSL_CODE,
    PLUGIN_UNSUPPORTED_CODE,
    REFERENCE_NOT_IN_DUMPS_CODE,
    REFERENCE_TRUNCATED_CODE,
    SCOPE_FALLBACK_CODE,
    TOO_FEW_DUMPS_CODE,
    WRONG_ALLOCATOR_CODE,
    search_reduce_android,
)
from memdiver.core.dump_source import open_dump  # noqa: E402
from memdiver.core.service_errors import (  # noqa: E402
    CapabilityError,
    EncryptedDumpLockedError,
    ErrorCategory,
)
from memdiver.engine.brute_force import count_candidate_slices  # noqa: E402
from memdiver.engine.scudo_candidates import (  # noqa: E402
    KEEP_VERDICTS,
    SCUDO_CANDIDATES_VERSION,
    VERDICT_CONTENT_INVARIANT,
    VERDICT_CONTENT_SHARED,
    VERDICT_DYNAMIC_CANDIDATE,
    VERDICT_DYNAMIC_RESIDUE,
    VERDICT_MISSING,
    VERDICT_SIGNATURE_INVARIANT,
    VERDICT_SIGNATURE_UNIQUE,
    VERDICTS,
    classify_chunks,
    verdict_funnel,
)
from memdiver.engine.scudo_chunk_consensus import (  # noqa: E402
    ALIGNMENT_SCUDO_CHUNK,
    CHUNK_CONSENSUS_VERSION,
    build_chunk_consensus,
)
from tests.fixtures.generate_msl_fixtures import PAGE_SIZE  # noqa: E402
from tests.fixtures.generate_scudo_msl_fixtures import (  # noqa: E402
    BLOCK_C3,
    CONST_FILL,
    CONST_SIG,
    CONST_SIZE,
    FILLER_SIG,
    HEADER_SIZE,
    MISSING_SIG,
    NEW_FILL,
    NEW_SIG,
    ORIGIN_NEW,
    PRIMARY_NAME,
    SECRET_CLASS,
    SECRET_SIG,
    SECRET_SIZE,
    content_dynamic_user,
    content_dynamic_user_va,
    content_heap_base,
    heap_base,
    neighbour_secret_user_va,
    place_chunk_at,
    secret_user_va,
    secret_value,
    vas_entry,
    write_content_runs,
    write_neighbour_run,
    write_neighbour_runs,
    write_scudo_msl,
    write_scudo_msl_fixtures,
)

N_RUNS = 3

#: Four fixture families, one per way a chunk can be kept or dropped:
#: ``signature`` -- a signature-unique secret that moves every run, two
#:   identical fillers (one ambiguous, repeated group) and a signature missing
#:   from the last run; no VAS map, so the scan takes the all-RW fallback;
#: ``neighbour`` -- three signature-unique chunks, two of them constant;
#: ``residue`` -- one over-full signature that content alignment fully
#:   resolves: a static chunk (content-invariant) and one dynamic per run;
#: ``crowded`` -- the same signature with TWO dynamic chunks per run (unpaired
#:   candidates) and two identical constant chunks (shared content).
FAMILIES = {
    "signature": lambda root: write_scudo_msl_fixtures(root, N_RUNS),
    "neighbour": lambda root: write_neighbour_runs(root, N_RUNS, vas=True),
    "residue": lambda root: write_content_runs(root, N_RUNS, statics=1, dynamics=1),
    "crowded": lambda root: write_content_runs(root, N_RUNS, statics=1, dynamics=2,
                                               repeated=2),
}


def _paths(written) -> list:
    return [str(p) for p in written]


@pytest.fixture(params=sorted(FAMILIES))
def family_runs(request, tmp_path):
    return request.param, _paths(FAMILIES[request.param](tmp_path / request.param))


@pytest.fixture
def scudo_runs(tmp_path):
    return _paths(FAMILIES["signature"](tmp_path / "signature"))


@pytest.fixture
def neighbour_runs(tmp_path):
    return _paths(FAMILIES["neighbour"](tmp_path / "neighbour"))


@pytest.fixture
def residue_runs(tmp_path):
    return _paths(FAMILIES["residue"](tmp_path / "residue"))


@pytest.fixture
def crowded_runs(tmp_path):
    return _paths(FAMILIES["crowded"](tmp_path / "crowded"))


@pytest.fixture
def aes_key():
    from memdiver.msl import crypto
    from memdiver.msl.enums import EncAlgo

    if not crypto.cipher_is_available(EncAlgo.AES_256_GCM):
        pytest.skip("AES-256-GCM backend not installed")
    return os.urandom(32)


def _reduce(paths, tmp_path, ref: int = 0, name: str = "out", **kw):
    """``(result, candidates)`` of one producer run with ``paths[ref]`` as reference.

    Forces ``allocator="scudo"`` by default: the synthetic fixtures are minimal
    and allocator detection does not classify them as Scudo, so the tests that
    exercise the reduction itself skip detection. The ``auto``-detection gate is
    covered separately (with a monkeypatched detector).
    """
    kw.setdefault("key_sizes", (SECRET_SIZE,))
    kw.setdefault("allocator", "scudo")
    result = search_reduce_android(dump_paths=paths, reference_path=paths[ref],
                                    output_dir=str(tmp_path / name), **kw)
    return result, json.loads(Path(result["candidates_path"]).read_text())


def _verdicts(paths, ref: int = 0):
    return classify_chunks(build_chunk_consensus(paths), ref)


def _by_va(verdicts):
    return {v.va: v for v in verdicts}


def _oracle(tmp_path, target: bytes) -> str:
    """A BYO brute-force oracle that confirms exactly ``target``."""
    path = tmp_path / "oracle.py"
    path.write_text(f"TARGET = bytes.fromhex({target.hex()!r})\n"
                    "def verify(candidate):\n"
                    "    return candidate == TARGET\n")
    os.chmod(path, 0o644)
    return str(path)


def _brute_force(candidates_path, reference, oracle, tmp_path, name="bf"):
    return brute_force(candidates_path=candidates_path, reference_path=reference,
                       oracle_path=oracle, output_dir=str(tmp_path / name),
                       key_sizes=(SECRET_SIZE,), stride=1)


def _reference_bytes(path, **km) -> bytes:
    """The reference exactly as brute-force reads it (``_read_reference_bytes``)."""
    with open_dump(Path(path), **km) as source:
        source.open()
        return source.read_all()


def _selection_rule(provenance: dict, dump_index: int) -> set:
    """The selection rule, computed independently from the JSON provenance.

    Aligned rows tagged ``dynamic_residue``, ``signature_unique`` rows whose
    (two-decimal) mean variance is above zero, and every dynamic candidate of
    the dump -- as ``(va, length)`` pairs, which deduplicates a residue chunk
    that is listed in both places.
    """
    out = set()
    for row in provenance["aligned_signatures"]:
        cls = row["content_class"]
        if cls == "dynamic_residue" or (cls == "signature_unique"
                                        and row["mean_variance"] > 0):
            out.add((int(row["user_vas"][dump_index], 16), row["length"]))
    per_signature = provenance["content_alignment"].get("per_signature", {})
    for entry in per_signature.values():
        for cand in entry["dynamic_candidates"][dump_index]:
            out.add((int(cand["va"], 16), cand["size"]))
    return out


# ---------------------------------------------------------------------------
# T1: the chain, end to end -- every run's own secret, wherever Scudo put it
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("ref", range(N_RUNS))
def test_t1_the_chain_finds_each_runs_own_secret(scudo_runs, tmp_path, ref):
    """search-reduce -> brute-force recovers THIS run's moved secret.

    The secret sits in a different slot at a different base VA every run, so
    no positional overlay pairs it; the candidates must still name exactly its
    bytes in the chosen reference, and the oracle must confirm them there.
    """
    result, cand = _reduce(scudo_runs, tmp_path, ref=ref)
    (region,) = cand["regions"]
    assert int(region["va"], 16) == secret_user_va(ref)
    assert region["signature"] == SECRET_SIG

    hits = _brute_force(result["candidates_path"], scudo_runs[ref],
                        _oracle(tmp_path, secret_value(ref)), tmp_path)["hits"]
    (hit,) = hits
    assert hit["offset"] == region["offset"]
    assert hit["confirmed_by"] == "oracle"
    data = _reference_bytes(scudo_runs[ref])
    assert data[hit["offset"]:hit["offset"] + SECRET_SIZE] == secret_value(ref)


@pytest.mark.parametrize("ref", range(N_RUNS))
def test_t1_an_unpaired_dynamic_candidate_is_found_too(crowded_runs, tmp_path, ref):
    """Two per-run chunks content alignment cannot pair: both are candidates,
    and brute-force picks out the one the oracle knows."""
    result, cand = _reduce(crowded_runs, tmp_path, ref=ref)
    assert {r["selected_as"] for r in cand["regions"]} == {VERDICT_DYNAMIC_CANDIDATE}
    assert {int(r["va"], 16) for r in cand["regions"]} == {
        content_dynamic_user_va(ref, statics=1, k=k) for k in (0, 1)}

    target = content_dynamic_user(ref, 1)
    (hit,) = _brute_force(result["candidates_path"], crowded_runs[ref],
                          _oracle(tmp_path, target), tmp_path)["hits"]
    data = _reference_bytes(crowded_runs[ref])
    assert data[hit["offset"]:hit["offset"] + SECRET_SIZE] == target


# ---------------------------------------------------------------------------
# Engine: one verdict per chunk, and the selection rule one to one
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("ref", range(N_RUNS))
def test_verdicts_partition_the_reference_chunks(family_runs, ref):
    _name, paths = family_runs
    scc = build_chunk_consensus(paths)
    verdicts = classify_chunks(scc, ref)
    chunks = scc.per_dump_chunks[ref]
    assert [v.chunk for v in verdicts] == chunks
    funnel = verdict_funnel(verdicts)
    assert list(funnel) == list(VERDICTS)
    assert sum(b["chunks"] for b in funnel.values()) == len(chunks)
    assert sum(b["bytes"] for b in funnel.values()) == sum(len(c.data) for c in chunks)


@pytest.mark.parametrize("ref", range(N_RUNS))
def test_the_kept_set_is_the_selection_rule_one_to_one(family_runs, ref):
    """The classifier's kept chunks == the selection rule over the same build,
    read from the JSON-serialised provenance."""
    _name, paths = family_runs
    scc = build_chunk_consensus(paths)
    provenance = json.loads(json.dumps(scc.alignment_provenance()))
    kept = {(v.va, v.length) for v in classify_chunks(scc, ref) if v.kept}
    assert kept == _selection_rule(provenance, ref)
    assert kept, "every family carries at least one per-run chunk"


def test_signature_family_verdicts(scudo_runs):
    verdicts = _verdicts(scudo_runs, ref=0)
    by_sig = {}
    for v in verdicts:
        by_sig.setdefault(v.chunk.sig, []).append(v.verdict)
    assert by_sig[SECRET_SIG] == [VERDICT_SIGNATURE_UNIQUE]
    assert by_sig[FILLER_SIG] == [VERDICT_CONTENT_SHARED] * 2
    assert by_sig[MISSING_SIG] == [VERDICT_MISSING]
    # The last run lacks the class-1 chunk: as reference it has nothing unjudged.
    assert VERDICT_MISSING not in {v.verdict for v in _verdicts(scudo_runs, ref=2)}


def test_neighbour_family_verdicts(neighbour_runs):
    by_sig = {v.chunk.sig: v for v in _verdicts(neighbour_runs, ref=1)}
    secret = by_sig[SECRET_SIG]
    assert secret.verdict == VERDICT_SIGNATURE_UNIQUE
    assert secret.va == neighbour_secret_user_va(1)
    assert secret.row_key == SECRET_SIG and secret.mean_variance > 0
    for constant in (CONST_SIG, NEW_SIG):
        assert by_sig[constant].verdict == VERDICT_SIGNATURE_INVARIANT
        assert by_sig[constant].mean_variance == 0.0


def test_residue_family_verdicts_list_the_residue_once(residue_runs):
    """The provenance names the dynamic residue TWICE -- as a ``#dynamic`` row
    and as its signature's one dynamic candidate. The lab script emitted it
    twice; one chunk is one verdict here."""
    scc = build_chunk_consensus(residue_runs)
    ref = 0
    residue_va = content_dynamic_user_va(ref, statics=1, k=0)
    (entry,) = scc.content.per_signature.values()
    assert [int(c["va"], 16) for c in entry["dynamic_candidates"][ref]] == [residue_va]
    assert residue_va in {row.user_vas[ref] for row in scc.signatures}

    by_va = _by_va(classify_chunks(scc, ref))
    assert by_va[residue_va].verdict == VERDICT_DYNAMIC_RESIDUE
    assert by_va[residue_va].row_key == f"{SECRET_SIG}#dynamic"
    static_va = content_heap_base(ref) + HEADER_SIZE
    assert by_va[static_va].verdict == VERDICT_CONTENT_INVARIANT
    assert [v.verdict for v in by_va.values() if v.kept] == [VERDICT_DYNAMIC_RESIDUE]


def test_crowded_family_verdicts(crowded_runs):
    verdicts = _verdicts(crowded_runs, ref=0)
    counts = {verdict: 0 for verdict in VERDICTS}
    for v in verdicts:
        counts[v.verdict] += 1
    assert counts[VERDICT_DYNAMIC_CANDIDATE] == 2
    assert counts[VERDICT_CONTENT_INVARIANT] == 1
    assert counts[VERDICT_CONTENT_SHARED] == 2
    assert all(v.row_key is None and v.mean_variance is None
               for v in verdicts if v.verdict == VERDICT_DYNAMIC_CANDIDATE)


def test_a_consensus_without_content_alignment_cannot_be_judged(scudo_runs):
    """Ambiguous signatures never compared by content: refusing beats guessing."""
    scc = build_chunk_consensus(scudo_runs, content_alignment=False)
    assert scc.ambiguous
    with pytest.raises(ValueError, match="content-aligned"):
        classify_chunks(scc, 0)


def test_nothing_ambiguous_needs_no_content_block(neighbour_runs):
    """With nothing ambiguous the build carries no content block either way."""
    scc = build_chunk_consensus(neighbour_runs)
    assert scc.content is None and not scc.ambiguous
    assert [v.verdict for v in classify_chunks(scc, 0)].count(VERDICT_SIGNATURE_UNIQUE) == 1


def test_a_dump_index_outside_the_build_is_refused(scudo_runs):
    scc = build_chunk_consensus(scudo_runs)
    with pytest.raises(ValueError, match="outside"):
        classify_chunks(scc, N_RUNS)


# ---------------------------------------------------------------------------
# The candidates.json contract brute-force reads
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("ref", range(N_RUNS))
def test_every_region_is_the_chunk_in_brute_forces_view(family_runs, tmp_path, ref):
    _name, paths = family_runs
    by_va = _by_va(_verdicts(paths, ref))
    _result, cand = _reduce(paths, tmp_path, ref=ref)
    data = _reference_bytes(paths[ref])
    assert cand["regions"]
    for region in cand["regions"]:
        chunk = by_va[int(region["va"], 16)].chunk
        assert region["length"] == len(chunk.data)
        assert data[region["offset"]:region["offset"] + region["length"]] == chunk.data


def test_candidates_json_carries_the_contract(scudo_runs, tmp_path):
    result, cand = _reduce(scudo_runs, tmp_path)
    assert cand["source"] == "search-reduce:scudo"
    assert cand["version"] == SCUDO_CANDIDATES_VERSION
    assert cand["consensus"]["method"] == ALIGNMENT_SCUDO_CHUNK
    assert cand["consensus"]["version"] == CHUNK_CONSENSUS_VERSION
    assert cand["N"] == N_RUNS and cand["dumps"] == scudo_runs
    assert cand["reference_dump"] == scudo_runs[0] and cand["reference_index"] == 0
    # Offsets are in the UNFILTERED view: no filter may be handed downstream.
    assert "region_filter" not in cand
    offsets = [r["offset"] for r in cand["regions"]]
    assert offsets == sorted(offsets)
    for region in cand["regions"]:
        assert isinstance(region["offset"], int) and isinstance(region["length"], int)
        assert region["selected_as"] in KEEP_VERDICTS
        assert ("row" in region) == ("mean_variance" in region)
    assert result["num_regions"] == len(cand["regions"]) == cand["totals"]["regions"]
    assert {k: v for k, v in result.items()
            if k not in ("candidates_path", "num_regions")} == \
        {k: v for k, v in cand.items() if k != "regions"}


def test_unpaired_regions_carry_no_null_brute_force_would_choke_on(crowded_runs, tmp_path):
    """brute-force ranks a zero-hit run with ``float(r.get("mean_variance", 0.0))``:
    an explicit null would crash it, so an unpaired region omits the key."""
    result, cand = _reduce(crowded_runs, tmp_path)
    assert all("mean_variance" not in r and "row" not in r for r in cand["regions"])
    bf = _brute_force(result["candidates_path"], crowded_runs[0],
                      _oracle(tmp_path, b"\x00" * SECRET_SIZE), tmp_path)
    assert bf["verified_count"] == 0
    assert bf["total_candidates"] == 2


def test_the_window_estimate_is_brute_forces_own_count(family_runs, tmp_path):
    _name, paths = family_runs
    for sizes in ((SECRET_SIZE,), (8, 16, SECRET_SIZE)):
        result, cand = _reduce(paths, tmp_path, key_sizes=sizes, name=f"k{len(sizes)}")
        expected = count_candidate_slices(cand["regions"], _reference_bytes(paths[0]),
                                          sizes, 1)
        assert result["totals"]["windows"] == expected
        assert result["totals"]["key_sizes"] == sorted(sizes)


def test_key_sizes_change_only_the_estimate(scudo_runs, tmp_path):
    small, cand_small = _reduce(scudo_runs, tmp_path, key_sizes=(8,), name="a")
    large, cand_large = _reduce(scudo_runs, tmp_path, key_sizes=(64,), name="b")
    assert cand_small["regions"] == cand_large["regions"]
    assert small["totals"]["windows"] == SECRET_SIZE - 8 + 1
    assert large["totals"]["windows"] == 0   # a 64-byte key cannot fit a 40-byte chunk


def test_the_artifact_is_deterministic(scudo_runs, tmp_path):
    first, _ = _reduce(scudo_runs, tmp_path, name="one")
    second, _ = _reduce(scudo_runs, tmp_path, name="two")
    assert Path(first["candidates_path"]).read_bytes() == \
        Path(second["candidates_path"]).read_bytes()


def test_the_artifact_holds_no_chunk_bytes_and_no_key(tmp_path, aes_key):
    paths = _paths(write_neighbour_runs(tmp_path / "enc", N_RUNS, key=aes_key, vas=True))
    key_file = tmp_path / "content.key"
    key_file.write_bytes(aes_key)
    result, cand = _reduce(paths, tmp_path, key_file=str(key_file))
    text = Path(result["candidates_path"]).read_text()
    assert aes_key.hex() not in text
    for run in range(N_RUNS):
        assert secret_value(run).hex() not in text
    (region,) = cand["regions"]
    data = _reference_bytes(paths[0], key=aes_key)
    assert data[region["offset"]:region["offset"] + SECRET_SIZE] == secret_value(0)


# ---------------------------------------------------------------------------
# Honest reporting: not judged, fallback scope, an empty answer
# ---------------------------------------------------------------------------


def test_unjudged_chunks_are_reported_not_hidden(scudo_runs, tmp_path):
    result, cand = _reduce(scudo_runs, tmp_path, ref=0)
    assert cand["not_judged"] == {"chunks": 1, "bytes": 8, "signatures": [MISSING_SIG]}
    (diag,) = [d for d in cand["diagnostics"] if d["code"] == NOT_JUDGED_CODE]
    assert diag["severity"] == "info"
    assert MISSING_SIG not in {r["signature"] for r in cand["regions"]}

    last, _ = _reduce(scudo_runs, tmp_path, ref=2, name="last")
    assert last["not_judged"]["chunks"] == 0
    assert NOT_JUDGED_CODE not in {d["code"] for d in last["diagnostics"]}


def test_a_scan_without_vas_map_is_flagged(scudo_runs, neighbour_runs, tmp_path):
    result, _ = _reduce(scudo_runs, tmp_path, name="novas")
    (diag,) = [d for d in result["diagnostics"] if d["code"] == SCOPE_FALLBACK_CODE]
    assert diag["severity"] == "warning"
    assert diag["details"]["dumps"] == scudo_runs
    assert result["region_scope"]["kind"] == "all_rw_fallback"

    named, _ = _reduce(neighbour_runs, tmp_path, name="vas")
    assert SCOPE_FALLBACK_CODE not in {d["code"] for d in named["diagnostics"]}
    assert named["region_scope"]["kind"] == "vas:scudo_primary"


def _write_runs(root, page_for_run) -> list:
    """Runs whose single primary-named region holds ``page_for_run(run)``."""
    root.mkdir(parents=True, exist_ok=True)
    paths = []
    for run in range(N_RUNS):
        base = heap_base(run)
        paths.append(str(write_scudo_msl(
            root / f"run_{run + 1}.msl", [(base, page_for_run(run), {})],
            pid=7000 + run, vas_entries=[vas_entry(base, PAGE_SIZE, PRIMARY_NAME)])))
    return paths


def _constant_page(run: int) -> bytes:
    """Two constant chunks that move every run: nothing per-run to find."""
    page = bytearray(PAGE_SIZE)
    slot = (run * 7 + 3) % 40
    place_chunk_at(page, slot * BLOCK_C3, SECRET_CLASS, CONST_SIZE,
                   bytes([CONST_FILL] * CONST_SIZE))
    place_chunk_at(page, ((slot + 9) % 40) * BLOCK_C3, SECRET_CLASS, CONST_SIZE,
                   bytes([NEW_FILL] * CONST_SIZE), origin=ORIGIN_NEW)
    return bytes(page)


def test_an_empty_answer_says_why_and_brute_force_takes_it(tmp_path):
    paths = _write_runs(tmp_path / "const", _constant_page)
    result, cand = _reduce(paths, tmp_path)
    assert cand["regions"] == [] and result["num_regions"] == 0
    assert result["funnel"][VERDICT_SIGNATURE_INVARIANT]["chunks"] == 2
    (diag,) = [d for d in result["diagnostics"] if d["code"] == CANDIDATES_EMPTY_CODE]
    assert "none of the reference's 2 chunk(s)" in diag["message"]

    bf = _brute_force(result["candidates_path"], paths[0],
                      _oracle(tmp_path, b"\x00" * SECRET_SIZE), tmp_path)
    assert bf["verified_count"] == 0 and bf["total_candidates"] == 0


def test_no_chunk_at_all_is_named_as_such(tmp_path):
    paths = _write_runs(tmp_path / "zero", lambda run: bytes(PAGE_SIZE))
    result, _ = _reduce(paths, tmp_path)
    (diag,) = [d for d in result["diagnostics"] if d["code"] == CANDIDATES_EMPTY_CODE]
    assert "no Scudo primary chunk" in diag["message"]


# ---------------------------------------------------------------------------
# Refusals
# ---------------------------------------------------------------------------


def _refused(paths, reference, tmp_path, **kw) -> CapabilityError:
    kw.setdefault("allocator", "scudo")
    with pytest.raises(CapabilityError) as excinfo:
        search_reduce_android(dump_paths=paths, reference_path=reference,
                               output_dir=str(tmp_path / "refused"), **kw)
    assert not (tmp_path / "refused").exists()
    return excinfo.value


def test_a_single_dump_is_refused(scudo_runs, tmp_path):
    err = _refused(scudo_runs[:1], scudo_runs[0], tmp_path)
    assert err.code == TOO_FEW_DUMPS_CODE
    assert err.category is ErrorCategory.INVALID_INPUT


def test_a_reference_outside_the_dumps_is_refused_before_the_build(
    scudo_runs, tmp_path, monkeypatch,
):
    import memdiver.engine.scudo_chunk_consensus as engine

    def no_build(*_a, **_kw):
        raise AssertionError("the consensus was built for a reference it cannot use")

    monkeypatch.setattr(engine, "build_chunk_consensus", no_build)
    err = _refused(scudo_runs[:2], scudo_runs[2], tmp_path)
    assert err.code == REFERENCE_NOT_IN_DUMPS_CODE
    assert err.category is ErrorCategory.NOT_FOUND


def test_a_dump_named_twice_is_refused(scudo_runs, tmp_path):
    """Compared with itself, a run's own secret looks shared and is dropped."""
    err = _refused([*scudo_runs, scudo_runs[0]], scudo_runs[0], tmp_path)
    assert err.code == DUPLICATE_DUMPS_CODE
    link = tmp_path / "alias.msl"
    link.symlink_to(scudo_runs[1])
    assert _refused([*scudo_runs, str(link)], scudo_runs[0],
                    tmp_path).code == DUPLICATE_DUMPS_CODE


def test_a_missing_or_non_msl_dump_is_refused(scudo_runs, tmp_path):
    err = _refused([*scudo_runs[:2], str(tmp_path / "gone.msl")], scudo_runs[0], tmp_path)
    assert err.code == DUMP_NOT_FOUND_CODE and err.category is ErrorCategory.NOT_FOUND

    raw = tmp_path / "flat.bin"
    raw.write_bytes(b"\x00" * 4096)
    err = _refused([*scudo_runs[:2], str(raw)], scudo_runs[0], tmp_path)
    assert err.code == NOT_MSL_CODE and err.category is ErrorCategory.UNSUPPORTED


@pytest.mark.parametrize("sizes", [(), (0,), (-8,), ("x",)])
def test_invalid_key_sizes_are_refused(scudo_runs, tmp_path, sizes):
    assert _refused(scudo_runs, scudo_runs[0], tmp_path,
                    key_sizes=sizes).code == INVALID_KEY_SIZES_CODE


def test_a_locked_dump_is_refused_not_misread(tmp_path, aes_key):
    paths = [str(write_neighbour_run(tmp_path / f"run{run}.msl", run, vas=True,
                                     key=aes_key if run == 2 else None))
             for run in range(N_RUNS)]
    with pytest.raises(EncryptedDumpLockedError):
        search_reduce_android(dump_paths=paths, reference_path=paths[0],
                               output_dir=str(tmp_path / "locked"), allocator="scudo")


def test_a_truncated_reference_is_refused(neighbour_runs, tmp_path, monkeypatch):
    """Behind a short run read_all() and va_to_vas_offset part ways: refuse."""
    import memdiver.engine.scudo_chunk_consensus as engine
    from memdiver.msl.reader import MslReader

    real_build = engine.build_chunk_consensus

    def build_then_truncate(*args, **kwargs):
        scc = real_build(*args, **kwargs)
        # From here on every captured run reads one byte short -- what a
        # container cut mid-payload looks like through read_all().
        monkeypatch.setattr(MslReader, "run_span", lambda self, run: run.length - 1)
        return scc

    monkeypatch.setattr(engine, "build_chunk_consensus", build_then_truncate)
    err = _refused(neighbour_runs, neighbour_runs[0], tmp_path)
    assert err.code == REFERENCE_TRUNCATED_CODE
    assert err.category is ErrorCategory.PRECONDITION


def test_mixed_cohorts_are_refused_unless_mixed_ok(tmp_path):
    paths = []
    for run, cohort in enumerate(("a", "a", "b")):
        run_dir = tmp_path / f"run{run}"
        run_dir.mkdir()
        paths.append(str(write_neighbour_run(run_dir / "dump.msl", run, vas=True)))
        (run_dir / "meta.json").write_text(json.dumps({"cohort": cohort}))
    assert _refused(paths, paths[0], tmp_path).code == "cohort.mixed"
    result, cand = _reduce(paths, tmp_path, mixed_ok=True)
    assert result["cohort"] is None
    assert int(cand["regions"][0]["va"], 16) == neighbour_secret_user_va(0)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse(argv):
    from memdiver.cli.main import _build_parser
    return _build_parser().parse_args(argv)


def _run_cli(monkeypatch, argv):
    """Through ``main()``: the dispatch table AND the CapabilityError backstop.

    ``setup_logging`` (called by ``main()``) attaches its stderr handler only
    once, bound to the stderr of whichever test ran first; a fresh handler list
    per call (restored by monkeypatch) keeps a stale, closed capture stream out
    of this test's output.
    """
    import logging

    from memdiver.cli import main

    monkeypatch.setattr(logging.getLogger("memdiver"), "handlers", [])
    monkeypatch.setattr(sys, "argv", ["memdiver", *argv])
    with pytest.raises(SystemExit) as exc_info:
        main()
    return exc_info.value.code


def _begin_and_collect(monkeypatch, tmp_path, paths, allocator="scudo",
                       name="s.json"):
    """Run ``consensus-begin`` + ``consensus-add`` xN through ``main()``.

    The Scudo pipeline's front half: begin a collect session (--allocator
    scudo/auto, no --size) then record each dump's path. Returns the session
    state path for ``search-reduce --state`` to consume.
    """
    state = tmp_path / name
    assert _run_cli(monkeypatch, ["consensus-begin", "--state", str(state),
                                  "--allocator", allocator]) == 0
    for p in paths:
        assert _run_cli(monkeypatch,
                        ["consensus-add", "--state", str(state), p]) == 0
    return state


def test_cli_dispatch_registers_search_reduce():
    import importlib
    import inspect

    # There is no separate Android subcommand and no positional dumps: the Scudo
    # path is a mode of search-reduce selected by the --state session's kind,
    # dispatched to the one _cmd_search_reduce handler.
    _main = importlib.import_module("memdiver.cli.main")
    assert '"search-reduce": _cmd_search_reduce' in inspect.getsource(_main.main)
    assert "search-reduce-android" not in inspect.getsource(_main.main)
    sr = _parse(["search-reduce", "--state", "s.json", "--reference-dump",
                 "a.msl", "-o", "c.json"])
    assert sr.command == "search-reduce"
    assert sr.state == "s.json"
    assert sr.reference_dump == "a.msl"
    assert not hasattr(sr, "dumps")   # the CLI surface stays --state only
    # --key-sizes is a string flag (parsed in the handler), default "32".
    assert sr.key_sizes == "32"
    assert _parse(["search-reduce", "--state", "s.json", "--reference-dump",
                   "a.msl", "-o", "c.json", "--key-sizes", "32,48"]
                  ).key_sizes == "32,48"
    # consensus-begin chooses the pipeline: --size (Welford) vs --allocator
    # scudo/auto (Scudo); --size is now optional.
    cb_scudo = _parse(["consensus-begin", "--state", "s.json",
                       "--allocator", "scudo"])
    assert cb_scudo.allocator == "scudo" and cb_scudo.size is None
    cb_welford = _parse(["consensus-begin", "--state", "w.json", "--size", "4096"])
    assert cb_welford.size == 4096 and cb_welford.allocator is None


@pytest.mark.parametrize("flags, recorded", [
    ([], "auto"),   # the flag omitted next to --size means auto
    (["--allocator", "auto"], "auto"),
    (["--allocator", "ptmalloc2"], "ptmalloc2"),
    (["--allocator", "off"], None),
])
def test_consensus_begin_with_size_stays_a_welford_heap_session(
    tmp_path, flags, recorded,
):
    from memdiver.cli.consensus import (
        STATE_MODE_WELFORD,
        _cmd_consensus_begin,
        _load_consensus_state,
    )

    state = tmp_path / "w.json"
    assert _cmd_consensus_begin(_parse([
        "consensus-begin", "--state", str(state), "--size", "16", *flags])) == 0
    mode, payload = _load_consensus_state(state)
    assert mode == STATE_MODE_WELFORD
    assert payload.get("heap", {}).get("allocator") == recorded


@pytest.mark.parametrize("argv, code", [
    (["--size", "16", "--allocator", "scudo"], "consensus.size_allocator_xor"),
    ([], "consensus.mode_required"),
    (["--allocator", "ptmalloc2"], "consensus.bad_scudo_allocator"),
])
def test_consensus_begin_refuses_a_call_that_names_no_single_pipeline(
    tmp_path, argv, code,
):
    from memdiver.cli.consensus import _cmd_consensus_begin
    from memdiver.core.service_errors import CapabilityError

    state = tmp_path / "s.json"
    with pytest.raises(CapabilityError) as exc_info:
        _cmd_consensus_begin(_parse(["consensus-begin", "--state", str(state), *argv]))
    assert exc_info.value.code == code
    assert not state.exists()


def test_cli_pipeline_writes_candidates_and_prints_the_funnel(
    scudo_runs, tmp_path, capsys,
):
    from memdiver.cli.consensus import _cmd_consensus_add, _cmd_consensus_begin
    from memdiver.cli.pipeline import _cmd_search_reduce

    state = tmp_path / "s.json"
    assert _cmd_consensus_begin(_parse([
        "consensus-begin", "--state", str(state), "--allocator", "scudo"])) == 0
    for p in scudo_runs:
        assert _cmd_consensus_add(
            _parse(["consensus-add", "--state", str(state), p])) == 0
    capsys.readouterr()   # drop the begin/add chatter; assert only on search-reduce

    out = tmp_path / "candidates.json"
    assert _cmd_search_reduce(_parse([
        "search-reduce", "--state", str(state), "--reference-dump", scudo_runs[1],
        "--key-sizes", str(SECRET_SIZE), "-o", str(out)])) == 0
    cand = json.loads(out.read_text())
    (region,) = cand["regions"]
    assert int(region["va"], 16) == secret_user_va(1)
    captured = capsys.readouterr()
    assert captured.out == ""
    err = captured.err
    assert f"search-reduce[scudo] {SCUDO_CANDIDATES_VERSION} over 3 dump(s)" in err
    funnel = {}
    for line in err.splitlines():
        if line.startswith("memdiver:   "):
            parts = line.split()
            # "kept" / "dropped" are one word, "not judged" two.
            funnel[parts[3] if parts[1] == "not" else parts[2]] = line
    assert "kept" in funnel[VERDICT_SIGNATURE_UNIQUE] and " 1 chunk(s)" in \
        funnel[VERDICT_SIGNATURE_UNIQUE]
    assert "not judged" in funnel[VERDICT_MISSING]
    assert "dropped" in funnel[VERDICT_CONTENT_SHARED]
    assert f"-> 1 region(s), 0.0 KiB, 1 window(s) (key sizes {SECRET_SIZE}" in err
    assert "memdiver: WARNING —" in err      # the all-RW fallback scope
    assert "memdiver: note —" in err         # the unjudged class-1 chunk


@pytest.mark.parametrize("ref", range(N_RUNS))
def test_cli_pipeline_finds_each_runs_own_secret(
    scudo_runs, tmp_path, monkeypatch, ref,
):
    """The flagship chain through the pipeline: for EVERY reference, the
    candidates name that run's own secret at the offset brute-force reads."""
    from memdiver.cli.pipeline import _cmd_search_reduce

    state = _begin_and_collect(monkeypatch, tmp_path, scudo_runs)
    out = tmp_path / "candidates.json"
    assert _cmd_search_reduce(_parse([
        "search-reduce", "--state", str(state), "--reference-dump", scudo_runs[ref],
        "--key-sizes", str(SECRET_SIZE), "-o", str(out)])) == 0
    (region,) = json.loads(out.read_text())["regions"]
    assert int(region["va"], 16) == secret_user_va(ref)


def test_cli_pipeline_chain_into_brute_force_cli(scudo_runs, tmp_path, monkeypatch):
    """The terminal chain itself, all through main(): begin/add/search-reduce/brute-force."""
    state = _begin_and_collect(monkeypatch, tmp_path, scudo_runs)
    cand = tmp_path / "candidates.json"
    hits = tmp_path / "hits.json"
    assert _run_cli(monkeypatch, ["search-reduce", "--state", str(state),
                                  "--reference-dump", scudo_runs[2],
                                  "-o", str(cand)]) == 0
    assert _run_cli(monkeypatch, [
        "brute-force", "--candidates", str(cand), "--dump", scudo_runs[2],
        "--oracle", _oracle(tmp_path, secret_value(2)),
        "--key-sizes", str(SECRET_SIZE), "-o", str(hits)]) == 0
    (hit,) = json.loads(hits.read_text())["hits"]
    assert hit["offset"] == json.loads(cand.read_text())["regions"][0]["offset"]


def _refusal_one_dump(runs, tmp_path, out, mp):
    return _begin_and_collect(mp, tmp_path, runs[:1]), \
        ["--reference-dump", runs[0], "-o", out]


def _refusal_reference_outside(runs, tmp_path, out, mp):
    return _begin_and_collect(mp, tmp_path, runs[:2]), \
        ["--reference-dump", runs[2], "-o", out]


def _refusal_duplicate(runs, tmp_path, out, mp):
    return _begin_and_collect(mp, tmp_path, [*runs, runs[0]]), \
        ["--reference-dump", runs[0], "-o", out]


def _refusal_bad_key_sizes(runs, tmp_path, out, mp):
    return _begin_and_collect(mp, tmp_path, runs), \
        ["--reference-dump", runs[0], "-o", out, "--key-sizes", "0"]


def _refusal_no_reference(runs, tmp_path, out, mp):
    return _begin_and_collect(mp, tmp_path, runs), ["-o", out]


@pytest.mark.parametrize("setup, code, message", [
    pytest.param(_refusal_one_dump, 2, "Need at least 2 dumps", id="one-dump"),
    pytest.param(_refusal_reference_outside, 3, "not one of the named dumps",
                 id="reference-outside"),
    pytest.param(_refusal_duplicate, 2, "named twice", id="duplicate"),
    pytest.param(_refusal_bad_key_sizes, 2, "positive integers", id="bad-key-sizes"),
    pytest.param(_refusal_no_reference, 2, "--reference-dump", id="no-reference"),
])
def test_cli_pipeline_refusals_exit_with_category_codes_and_no_traceback(
    scudo_runs, tmp_path, monkeypatch, capsys, setup, code, message,
):
    out = tmp_path / "candidates.json"
    state, tail = setup(scudo_runs, tmp_path, str(out), monkeypatch)
    capsys.readouterr()   # drop the begin/add chatter
    assert _run_cli(monkeypatch,
                    ["search-reduce", "--state", str(state), *tail]) == code
    captured = capsys.readouterr()
    assert message in captured.err
    assert "Traceback" not in captured.err
    assert not out.exists()


def test_cli_pipeline_key_file_decrypts_every_dump(
    tmp_path, aes_key, capsys, monkeypatch,
):
    paths = _paths(write_neighbour_runs(tmp_path / "enc", N_RUNS, key=aes_key,
                                        vas=True))
    key_file = tmp_path / "content.key"
    key_file.write_bytes(aes_key)
    # consensus-add records paths only (no heap read), so no key is needed until
    # search-reduce opens the reference.
    state = _begin_and_collect(monkeypatch, tmp_path, paths)
    capsys.readouterr()
    out = tmp_path / "candidates.json"
    assert _run_cli(monkeypatch, [
        "search-reduce", "--state", str(state), "--reference-dump", paths[0],
        "--key-file", str(key_file), "-o", str(out)]) == 0
    (region,) = json.loads(out.read_text())["regions"]
    assert int(region["va"], 16) == neighbour_secret_user_va(0)
    assert "AEAD verified" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Allocator selection: the Scudo-mode gate and the --state XOR
# ---------------------------------------------------------------------------
#
# The synthetic fixtures are minimal, so the built-in detector calls them
# GENERIC (see the probe in the port). These tests therefore monkeypatch
# ``detect_allocator`` to exercise the auto path deterministically; the forced
# (``--allocator scudo``) path needs no detector and is what every test above
# already runs on.


def _fake_detection(best):
    """A ``detect_allocator`` replacement reporting ``best`` without scanning."""
    from memdiver.heap.detect import DetectionResult

    def _detect(*_args, **_kwargs):
        return DetectionResult(candidates=[], best=best, confidence=1.0)
    return _detect


def _detect_forbidden(*_args, **_kwargs):
    raise AssertionError("allocator detection ran when it should have been skipped")


def test_scudo_forces_the_path_without_detecting(scudo_runs, tmp_path, monkeypatch):
    """``--allocator scudo`` reduces without ever probing the allocator."""
    import memdiver.heap.detect as detect

    monkeypatch.setattr(detect, "detect_allocator", _detect_forbidden)
    _result, cand = _reduce(scudo_runs, tmp_path, allocator="scudo")
    assert len(cand["regions"]) == 1


def test_auto_accepts_a_scudo_reference(scudo_runs, tmp_path, monkeypatch):
    """``--allocator auto`` proceeds when detection calls the reference Scudo."""
    import memdiver.heap.detect as detect
    from memdiver.heap.model import AllocatorKind

    monkeypatch.setattr(detect, "detect_allocator",
                        _fake_detection(AllocatorKind.SCUDO))
    _result, cand = _reduce(scudo_runs, tmp_path, allocator="auto")
    assert int(cand["regions"][0]["va"], 16) == secret_user_va(0)


def test_auto_refuses_a_non_scudo_reference(scudo_runs, tmp_path, monkeypatch):
    """``--allocator auto`` refuses when the reference is not a Scudo heap."""
    import memdiver.heap.detect as detect
    from memdiver.heap.model import AllocatorKind

    monkeypatch.setattr(detect, "detect_allocator",
                        _fake_detection(AllocatorKind.PTMALLOC2))
    err = _refused(scudo_runs, scudo_runs[0], tmp_path, allocator="auto")
    assert err.code == WRONG_ALLOCATOR_CODE
    assert err.category is ErrorCategory.PRECONDITION
    assert "ptmalloc2" in str(err)


@pytest.mark.parametrize("allocator", ["ptmalloc2", "jemalloc", "generic", "off"])
def test_an_explicit_non_scudo_allocator_is_refused(
    scudo_runs, tmp_path, allocator, monkeypatch,
):
    """A named non-Scudo allocator (or ``off``) is refused outright, no scan."""
    import memdiver.heap.detect as detect

    monkeypatch.setattr(detect, "detect_allocator", _detect_forbidden)
    err = _refused(scudo_runs, scudo_runs[0], tmp_path, allocator=allocator)
    assert err.code == WRONG_ALLOCATOR_CODE


# ---------------------------------------------------------------------------
# The pipeline uses memdiver's OWN allocator awareness
# ---------------------------------------------------------------------------
#
# A Scudo session begun with --allocator auto defers the allocator decision to
# search-reduce, where the producer calls heap.detect.detect_allocator on the
# (decrypted) reference and proceeds only for Scudo. These tests prove the
# whole pipeline -- begin/add/search-reduce through main() -- routes through
# that existing detection rather than assuming Scudo. The synthetic fixtures
# detect as GENERIC, so the detector is monkeypatched to make its verdict (and
# thus the pipeline's decision) observable.


def test_cli_pipeline_auto_consults_memdiver_allocator_detection(
    scudo_runs, tmp_path, monkeypatch, capsys,
):
    """``begin --allocator auto`` -> ``add`` -> ``search-reduce`` calls
    memdiver's own ``detect_allocator`` and proceeds only because it reports the
    reference Scudo. The spy proves the detector was actually consulted."""
    import memdiver.heap.detect as detect
    from memdiver.heap.model import AllocatorKind

    calls = []
    detected = _fake_detection(AllocatorKind.SCUDO)

    def _spy(*args, **kwargs):
        calls.append(True)
        return detected(*args, **kwargs)

    monkeypatch.setattr(detect, "detect_allocator", _spy)
    state = _begin_and_collect(monkeypatch, tmp_path, scudo_runs, allocator="auto")
    capsys.readouterr()
    out = tmp_path / "candidates.json"
    assert _run_cli(monkeypatch, [
        "search-reduce", "--state", str(state), "--reference-dump", scudo_runs[0],
        "--key-sizes", str(SECRET_SIZE), "-o", str(out)]) == 0
    assert calls, "the Scudo pipeline never consulted memdiver's allocator detection"
    (region,) = json.loads(out.read_text())["regions"]
    assert int(region["va"], 16) == secret_user_va(0)


def test_cli_pipeline_auto_refuses_a_non_scudo_reference(
    scudo_runs, tmp_path, monkeypatch, capsys,
):
    """When memdiver's detector calls the reference non-Scudo, the auto pipeline
    refuses (scudo.wrong_allocator): the gate is the detector's verdict, not a
    hard-coded assumption, and nothing is written."""
    import memdiver.heap.detect as detect
    from memdiver.heap.model import AllocatorKind

    monkeypatch.setattr(detect, "detect_allocator",
                        _fake_detection(AllocatorKind.PTMALLOC2))
    state = _begin_and_collect(monkeypatch, tmp_path, scudo_runs, allocator="auto")
    capsys.readouterr()
    out = tmp_path / "candidates.json"
    code = _run_cli(monkeypatch, [
        "search-reduce", "--state", str(state), "--reference-dump", scudo_runs[0],
        "-o", str(out)])
    assert code != 0
    err = capsys.readouterr().err
    assert "ptmalloc2" in err and "Scudo" in err
    assert "Traceback" not in err
    assert not out.exists()


def test_cli_pipeline_scudo_state_is_dispatched_not_the_welford_path(
    scudo_runs, tmp_path, monkeypatch,
):
    """A Scudo collect state routes search-reduce to the Scudo producer, never
    the Welford reducer (which would need the mean/M2 arrays this state has
    not). The state-kind discriminant is the one place that decides."""
    from memdiver.cli.consensus import _consensus_state_mode, _load_consensus_state

    state = _begin_and_collect(monkeypatch, tmp_path, scudo_runs)
    mode, payload = _load_consensus_state(state)
    assert mode == "scudo"
    assert payload["allocator"] == "scudo"
    assert payload["dump_paths"] == list(scudo_runs)
    assert "mean_path" not in payload
    assert _consensus_state_mode(
        {"mean_path": "x", "m2_path": "y", "size": 8, "num_dumps": 0}) == "welford"


def test_cli_pipeline_finalize_reports_the_collected_session(
    scudo_runs, tmp_path, monkeypatch,
):
    """consensus-finalize on a Scudo session reports what has been collected
    (the candidate reduction itself is search-reduce's job)."""
    from memdiver.cli.consensus import _cmd_consensus_finalize

    state = _begin_and_collect(monkeypatch, tmp_path, scudo_runs)
    out = tmp_path / "finalize.json"
    assert _cmd_consensus_finalize(_parse([
        "consensus-finalize", "--state", str(state), "-o", str(out)])) == 0
    report = json.loads(out.read_text())
    assert report["mode"] == "scudo"
    assert report["allocator"] == "scudo"
    assert report["num_dumps"] == N_RUNS
    assert report["dump_paths"] == list(scudo_runs)


# ---------------------------------------------------------------------------
# What a user of the CLI chain runs into
# ---------------------------------------------------------------------------


def test_a_session_survives_a_change_of_directory(scudo_runs, tmp_path, monkeypatch):
    from memdiver.cli.consensus import _cmd_consensus_add, _cmd_consensus_begin
    from memdiver.cli.pipeline import _cmd_search_reduce

    state = tmp_path / "s.json"
    monkeypatch.chdir(Path(scudo_runs[0]).parent)
    assert _cmd_consensus_begin(_parse([
        "consensus-begin", "--state", str(state), "--allocator", "scudo"])) == 0
    for path in scudo_runs:
        assert _cmd_consensus_add(
            _parse(["consensus-add", "--state", str(state), Path(path).name])) == 0

    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    out = tmp_path / "candidates.json"
    assert _cmd_search_reduce(_parse([
        "search-reduce", "--state", str(state), "--reference-dump", scudo_runs[1],
        "--key-sizes", str(SECRET_SIZE), "-o", str(out)])) == 0
    (region,) = json.loads(out.read_text())["regions"]
    assert int(region["va"], 16) == secret_user_va(1)


def test_a_non_msl_refusal_names_no_command_that_does_not_exist(scudo_runs, tmp_path):
    raw = tmp_path / "raw.bin"
    raw.write_bytes(b"\x00" * 64)
    message = _refused([*scudo_runs, str(raw)], scudo_runs[0], tmp_path).message
    assert "search-reduce-android" not in message
    assert ".msl" in message


@pytest.mark.parametrize("allocator", ["auto", "ptmalloc2", "off"])
def test_a_wrong_heap_refusal_points_at_consensus_begin(
    scudo_runs, tmp_path, monkeypatch, allocator,
):
    import memdiver.heap.detect as detect
    from memdiver.heap.model import AllocatorKind

    monkeypatch.setattr(detect, "detect_allocator", _fake_detection(AllocatorKind.PTMALLOC2))
    refusal = _refused(scudo_runs, scudo_runs[0], tmp_path, allocator=allocator)

    assert refusal.code == WRONG_ALLOCATOR_CODE
    assert "consensus-begin --size" in refusal.message
    assert "consensus-begin --allocator scudo" in refusal.message
    assert "raw-dumps" not in refusal.message


def _brute_force_argv(candidates, dump, oracle, out, *extra):
    return ["brute-force", "--candidates", candidates, "--dump", dump, "--oracle", oracle,
            "--key-sizes", str(SECRET_SIZE), "--stride", "1", "--jobs", "1",
            "-o", str(out), *extra]


def test_brute_force_refuses_a_scudo_session_as_its_state(scudo_runs, tmp_path, monkeypatch):
    """Following the old plugin error led to the same error, after the whole search."""
    from memdiver.cli.pipeline import _cmd_brute_force

    state = _begin_and_collect(monkeypatch, tmp_path, scudo_runs)
    result, _cand = _reduce(scudo_runs, tmp_path)
    out = tmp_path / "hits.json"

    with pytest.raises(CapabilityError) as refused:
        _cmd_brute_force(_parse(_brute_force_argv(
            result["candidates_path"], scudo_runs[0],
            _oracle(tmp_path, secret_value(0)), out, "--state", str(state))))

    assert refused.value.code == PLUGIN_UNSUPPORTED_CODE
    assert "not supported yet" in refused.value.message
    assert "without --state" in refused.value.message
    assert not out.exists()


def test_brute_force_still_runs_without_a_state(scudo_runs, tmp_path):
    from memdiver.cli.pipeline import _cmd_brute_force

    result, _cand = _reduce(scudo_runs, tmp_path)
    out = tmp_path / "hits.json"

    assert _cmd_brute_force(_parse(_brute_force_argv(
        result["candidates_path"], scudo_runs[0],
        _oracle(tmp_path, secret_value(0)), out))) == 0
    assert len(json.loads(out.read_text())["hits"]) == 1


def test_an_unreadable_state_keeps_its_old_treatment(scudo_runs, tmp_path):
    from memdiver.cli.pipeline import _cmd_brute_force

    result, _cand = _reduce(scudo_runs, tmp_path)
    out = tmp_path / "hits.json"

    assert _cmd_brute_force(_parse(_brute_force_argv(
        result["candidates_path"], scudo_runs[0], _oracle(tmp_path, secret_value(0)),
        out, "--state", str(tmp_path / "missing.json")))) == 0
    assert len(json.loads(out.read_text())["hits"]) == 1


def test_emit_plugin_says_why_a_scudo_hit_cannot_become_one(tmp_path):
    from memdiver.engine.vol3_emit import emit_plugin_for_hit

    hit = {"offset": 16, "neighborhood_start": 16, "neighborhood_variance": []}
    with pytest.raises(ValueError, match="not supported yet with that method"):
        emit_plugin_for_hit(hit, bytes(64), "p", tmp_path / "p.py")


def _search_reduce_argv(state, reference, out, *extra):
    return ["search-reduce", "--state", str(state), "--reference-dump", reference,
            "--key-sizes", str(SECRET_SIZE), "-o", str(out), *extra]


def test_positional_flags_on_a_scudo_session_are_reported(
    scudo_runs, tmp_path, monkeypatch, capsys,
):
    from memdiver.cli.pipeline import _cmd_search_reduce

    state = _begin_and_collect(monkeypatch, tmp_path, scudo_runs)
    capsys.readouterr()

    assert _cmd_search_reduce(_parse(_search_reduce_argv(
        state, scudo_runs[0], tmp_path / "c.json",
        "--min-variance", "999999", "--heap-policy", "mask"))) == 0

    err = capsys.readouterr().err
    assert "--min-variance, --heap-policy only apply to the generic" in err


def test_search_reduce_allocator_on_a_scudo_session_is_reported(
    scudo_runs, tmp_path, monkeypatch, capsys,
):
    from memdiver.cli.pipeline import _cmd_search_reduce

    state = _begin_and_collect(monkeypatch, tmp_path, scudo_runs)
    capsys.readouterr()

    assert _cmd_search_reduce(_parse(_search_reduce_argv(
        state, scudo_runs[0], tmp_path / "c.json", "--allocator", "ptmalloc2"))) == 0

    assert "--allocator only apply to the generic" in capsys.readouterr().err


def test_an_untouched_command_warns_about_nothing(scudo_runs, tmp_path, monkeypatch, capsys):
    from memdiver.cli.pipeline import _cmd_search_reduce

    state = _begin_and_collect(monkeypatch, tmp_path, scudo_runs)
    capsys.readouterr()

    assert _cmd_search_reduce(_parse(_search_reduce_argv(
        state, scudo_runs[0], tmp_path / "c.json"))) == 0

    assert "only apply to the generic" not in capsys.readouterr().err


# ---------------------------------------------------------------------------
# The surface hooks the web pipeline drives
# ---------------------------------------------------------------------------


class _Events:
    def __init__(self):
        self.seen = []

    def __call__(self, event, **fields):
        self.seen.append((event, fields))

    def named(self, event):
        return [fields for name, fields in self.seen if name == event]


def _candidates_text(result) -> str:
    return Path(result["candidates_path"]).read_text()


def test_the_hooks_do_not_change_the_artifact_or_the_result(scudo_runs, tmp_path):
    plain, _ = _reduce(scudo_runs, tmp_path, name="plain")
    hooked, _ = _reduce(scudo_runs, tmp_path, name="plain", on_progress=_Events(),
                        is_cancelled=lambda: False)
    first = _candidates_text(plain)
    assert first == _candidates_text(hooked)
    assert {k: v for k, v in plain.items() if k != "candidates_path"} == \
        {k: v for k, v in hooked.items() if k != "candidates_path"}


def test_the_stage_stream_is_bracketed_and_reports_each_dump(scudo_runs, tmp_path):
    events = _Events()
    _reduce(scudo_runs, tmp_path, on_progress=events)

    assert events.seen[0][0] == "stage_start"
    assert events.seen[-1][0] == "stage_end"
    assert {fields["stage"] for name, fields in events.seen
            if name != "progress"} == {"search_reduce"}
    stages = [fields["stage"] for fields in events.named("progress")]
    assert stages == [*["search_reduce:chunk_consensus"] * N_RUNS,
                      "search_reduce:classify", "search_reduce:regions"]
    percentages = [fields["pct"] for fields in events.named("progress")]
    assert percentages == sorted(percentages)


def test_the_stage_end_is_compact_and_holds_no_memory_content(scudo_runs, tmp_path):
    """Signature lists stay in the artifact, and bytes never leave the dump."""
    events = _Events()
    result, _ = _reduce(scudo_runs, tmp_path, on_progress=events)
    (end,) = events.named("stage_end")
    extra = end["extra"]

    assert result["not_judged"]["signatures"]
    assert extra["not_judged"] == {"chunks": result["not_judged"]["chunks"],
                                   "bytes": result["not_judged"]["bytes"]}
    assert result["diagnostics"] and all("details" not in d for d in extra["diagnostics"])
    assert [d["code"] for d in extra["diagnostics"]] == \
        [d["code"] for d in result["diagnostics"]]
    assert extra["source"] == "search-reduce:scudo"
    assert extra["funnel"] == result["funnel"]
    assert extra["num_regions"] == result["num_regions"]
    serialized = json.dumps(extra)
    for run in range(N_RUNS):
        assert secret_value(run).hex() not in serialized


@pytest.mark.parametrize("after_calls", [1, 2, N_RUNS + 2], ids=["start", "scan", "regions"])
def test_a_cancel_stops_the_producer_without_an_artifact(scudo_runs, tmp_path, after_calls):
    calls = []

    def _is_cancelled():
        calls.append(1)
        return len(calls) >= after_calls

    events = _Events()
    with pytest.raises(CapabilityError) as refused:
        _reduce(scudo_runs, tmp_path, on_progress=events, is_cancelled=_is_cancelled)

    assert refused.value.code == "cancelled"
    assert events.named("error") == [{"error": "cancelled"}]
    assert not (tmp_path / "out" / "candidates.json").exists()


def _huge_estimate(*_args, **_kwargs):
    from memdiver.core.memory_budget import MemoryEstimate

    return MemoryEstimate(1 << 60, "test")


def test_no_budget_gate_without_force_memory(scudo_runs, tmp_path, monkeypatch):
    """The CLI passes nothing, so its behaviour does not change."""
    import memdiver.engine.scudo_chunk_consensus as scc

    def _forbidden(*_args, **_kwargs):
        raise AssertionError("the budget was checked although force_memory is None")

    monkeypatch.setattr(scc, "chunk_consensus_estimate", _forbidden)
    result, _ = _reduce(scudo_runs, tmp_path)
    assert result["num_regions"] == 1


def test_an_over_budget_build_is_refused_when_the_gate_is_on(scudo_runs, tmp_path, monkeypatch):
    import memdiver.engine.scudo_chunk_consensus as scc

    monkeypatch.setattr(scc, "chunk_consensus_estimate", _huge_estimate)
    with pytest.raises(CapabilityError) as refused:
        _reduce(scudo_runs, tmp_path, force_memory=False)
    assert refused.value.code == "memory_budget_exceeded"


def test_force_memory_proceeds_over_budget(scudo_runs, tmp_path, monkeypatch):
    import memdiver.engine.scudo_chunk_consensus as scc

    monkeypatch.setattr(scc, "chunk_consensus_estimate", _huge_estimate)
    result, _ = _reduce(scudo_runs, tmp_path, force_memory=True)
    assert result["num_regions"] == 1


def test_the_gate_decides_on_the_first_dump_before_reading_the_others(
    scudo_runs, tmp_path, monkeypatch,
):
    import memdiver.engine.scudo_chunk_consensus as scc

    scanned = []
    real_extract = scc.extract_chunks

    def _counting_extract(reader):
        scanned.append(reader)
        return real_extract(reader)

    estimated = []

    def _estimate(chunks, num_dumps):
        estimated.append((len(chunks), num_dumps))
        return _huge_estimate()

    monkeypatch.setattr(scc, "extract_chunks", _counting_extract)
    monkeypatch.setattr(scc, "chunk_consensus_estimate", _estimate)

    with pytest.raises(CapabilityError) as refused:
        _reduce(scudo_runs, tmp_path, force_memory=False)

    assert refused.value.code == "memory_budget_exceeded"
    assert len(scanned) == 1
    (count, num_dumps), = estimated
    assert count > 0 and num_dumps == N_RUNS


def test_the_refusal_only_suggests_what_a_scudo_run_accepts(scudo_runs, tmp_path, monkeypatch):
    import memdiver.engine.scudo_chunk_consensus as scc

    monkeypatch.setattr(scc, "chunk_consensus_estimate", _huge_estimate)
    with pytest.raises(CapabilityError) as refused:
        _reduce(scudo_runs, tmp_path, force_memory=False)

    assert "region filter" not in refused.value.message
    assert "fewer dumps" in refused.value.message
