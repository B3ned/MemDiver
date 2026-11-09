import { afterEach, describe, it, expect, vi } from "vitest";

import { artifactDownloadUrl, runPipeline } from "@/api/pipeline";
import { useRegionSelectionStore } from "@/stores/region-selection-store";
import type {
  LocateFieldPairsResult,
  PcapField,
  PcapFieldIndexEntry,
  PcapFieldSource,
  PcapFieldType,
  PcapPair,
  PcapPairRow,
  PcapPairStatus,
  PcapPairing,
  PcapSkipReason,
  PcapValidateResult,
  PipelineRunRequest,
} from "@/api/pipeline";

describe("artifactDownloadUrl", () => {
  it("builds the runs/artifacts path", () => {
    expect(artifactDownloadUrl("abc123", "keys.json")).toBe(
      "/api/pipeline/runs/abc123/artifacts/keys.json",
    );
  });

  it("percent-encodes both the task id and the artifact name", () => {
    expect(artifactDownloadUrl("a b/c", "my file.bin")).toBe(
      "/api/pipeline/runs/a%20b%2Fc/artifacts/my%20file.bin",
    );
  });
});

/**
 * The pcap arm step reports what the parse DROPPED, not only what it kept, so
 * the operator can tell "nothing to find" from "we never looked at 40 % of the
 * capture". These fixtures are the real payload shape of
 * ``POST /api/pcaps/validate`` (see tests/test_api_pcaps.py); typing them as
 * the declared interfaces makes this a compile-time contract check as much as
 * a runtime one.
 */
describe("PcapValidateResult accounting fields", () => {
  const result: PcapValidateResult = {
    pcap_path: "/tmp/traffic.pcap",
    session_count: 1,
    sessions: [
      {
        client_random: "aa".repeat(32),
        server_random: "bb".repeat(32),
        version: "13",
        cipher_suite: 4865,
        cipher_name: "TLS_AES_128_GCM_SHA256",
        client_app_records: 20,
        server_app_records: 4,
        has_app_records: true,
        app_records_seen: 24,
        records_returned: 20,
        // The 20 covered records over a TLS 1.3 sequence window, counted per
        // DIRECTION (the window index restarts on each side). Client: 16
        // records, indices 0..15, contributing min(index, 8) + 1 challenges =
        // (1+..+9) + 7*9 = 108. Server: 4 records = 1+2+3+4 = 10. Total 118 --
        // ~5.9 per covered record, which is why the challenge numbers are
        // reported separately from the record ones rather than derived.
        challenges_available: 118,
        challenges_returned: 118,
      },
    ],
    skipped_sessions: [
      {
        reason: "unsupported_cipher_suite",
        flow: "10.0.0.1:443 -> 10.0.0.2:51000",
        cipher_suite: 4866,
      },
    ],
    flow_count: 4,
    caps: { max_records_per_direction: 16, max_challenges: null },
    records_truncated: true,
  };

  it("surfaces a dropped session with a machine-readable reason", () => {
    expect(result.skipped_sessions?.[0].reason).toBe("unsupported_cipher_suite");
    expect(result.skipped_sessions?.[0].cipher_suite).toBe(4866);
  });

  it("distinguishes flows seen from sessions kept", () => {
    expect(result.flow_count).toBe(4);
    expect(result.session_count).toBe(1);
  });

  it("reports the record cap that clipped a session", () => {
    const session = result.sessions[0];
    expect(result.caps?.max_records_per_direction).toBe(16);
    expect(result.records_truncated).toBe(true);
    expect(session.records_returned).toBeLessThan(session.app_records_seen ?? 0);
  });

  it("tolerates a response without the accounting fields", () => {
    const bare: PcapValidateResult = {
      pcap_path: "/tmp/empty.pcap",
      session_count: 0,
      sessions: [],
    };
    expect(bare.records_truncated).toBeUndefined();
  });

  it("reports an uncapped challenge budget as a present null, not a gap", () => {
    // ``max_challenges`` is optional on the type but the backend always emits
    // the KEY (``null`` when uncapped), so "uncapped" is distinguishable from
    // "this response predates the field".
    expect(result.caps?.max_challenges).toBeNull();
    expect(result.caps && "max_challenges" in result.caps).toBe(true);
  });
});

/**
 * The skip reasons are a CLOSED union, so a literal that does not exist on the
 * backend is a compile error rather than a row the UI silently cannot label.
 * These are the exact strings ``TlsPcapResource._note_skipped`` is called with
 * (engine/resources/tls_pcap.py) -- pinned here because a wrong literal in a
 * closed union is worse than no union at all: it type-checks and then never
 * matches a real response.
 */
describe("PcapSkipReason", () => {
  const reasons: PcapSkipReason[] = [
    "no_client_hello",
    "no_server_hello",
    "no_cipher_suite",
    "short_random",
    "unsupported_cipher_suite",
    "no_change_cipher_spec",
    "client_random_mismatch",
  ];

  it("covers every reason the parser can emit", () => {
    expect(reasons).toHaveLength(7);
    expect(new Set(reasons).size).toBe(reasons.length);
  });

  it("carries per-direction context for a missing ChangeCipherSpec", () => {
    // A TLS 1.2 direction with no ChangeCipherSpec is undecryptable, so the
    // session is KEPT while its records are uncoverable: ``records_returned: 0``
    // against a non-zero ``app_records_seen``, explained by this entry. The
    // entry's ``app_records_seen`` is that DIRECTION's count, so it can be
    // smaller than the session-level (both-directions) number.
    const result: PcapValidateResult = {
      pcap_path: "/tmp/no-ccs.pcap",
      session_count: 1,
      sessions: [
        {
          client_random: "00".repeat(32),
          server_random: "11".repeat(32),
          version: "12",
          cipher_suite: 49199,
          cipher_name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
          client_app_records: 3,
          server_app_records: 0,
          has_app_records: true,
          app_records_seen: 3,
          records_returned: 0,
          challenges_available: 0,
          challenges_returned: 0,
        },
      ],
      skipped_sessions: [
        {
          reason: "no_change_cipher_spec",
          flow: "10.0.0.1:12345 -> 10.0.0.2:443",
          direction: "client",
          app_records_seen: 3,
        },
      ],
      flow_count: 2,
      caps: { max_records_per_direction: 16, max_challenges: null },
      records_truncated: true,
      challenges_available: 0,
      challenges_returned: 0,
      challenges_truncated: false,
    };

    const session = result.sessions[0];
    const skip = result.skipped_sessions?.[0];
    expect(session.records_returned).toBe(0);
    expect(session.app_records_seen).toBe(3);
    expect(result.records_truncated).toBe(true);
    expect(skip?.reason).toBe("no_change_cipher_spec");
    expect(skip?.direction).toBe("client");
    expect(skip?.app_records_seen).toBe(3);
    // Zero challenges available is NOT a truncation -- there was nothing to
    // truncate. The truncation flag must not fire on an empty stream.
    expect(result.challenges_truncated).toBe(false);
  });

  it("names the session a client_random filter passed over", () => {
    const skip: PcapValidateResult["skipped_sessions"] = [
      {
        reason: "client_random_mismatch",
        flow: "10.0.0.1:12345 -> 10.0.0.2:443",
        client_random: "cc".repeat(32),
      },
    ];
    expect(skip[0].client_random).toHaveLength(64);
  });
});

describe("capture-level challenge accounting", () => {
  it("flags a challenge budget that clipped the stream", () => {
    // ``max_challenges`` is spent ACROSS sessions in parse order, so the
    // capture-level numbers -- not the per-session ones -- are what say whether
    // the oracle saw the whole capture.
    const capped: PcapValidateResult = {
      pcap_path: "/tmp/traffic.pcap",
      session_count: 2,
      sessions: [],
      caps: { max_records_per_direction: 16, max_challenges: 50 },
      challenges_available: 195,
      challenges_returned: 50,
      challenges_truncated: true,
      records_truncated: true,
    };
    expect(capped.challenges_returned).toBeLessThan(
      capped.challenges_available ?? 0,
    );
    expect(capped.challenges_truncated).toBe(true);
    // ~3.9 challenges per record on the corpus, so a cap of 50 buys ~13
    // records: the reason ``challenges_available`` has to be reported at all.
    expect(Math.floor((capped.caps?.max_challenges ?? 0) / 3.9)).toBe(12);
  });
});

describe("PipelineRunRequest pcap work caps", () => {
  it("accepts both caps, and null to keep the backend defaults", () => {
    const capped: PipelineRunRequest = {
      source_paths: ["/tmp/a.dump"],
      pcap_path: "/tmp/traffic.pcap",
      pcap_max_records: 64,
      pcap_max_challenges: 128,
    };
    const defaulted: PipelineRunRequest = {
      source_paths: ["/tmp/a.dump"],
      pcap_path: "/tmp/traffic.pcap",
      pcap_max_records: null,
      pcap_max_challenges: null,
    };
    expect(capped.pcap_max_records).toBe(64);
    expect(defaulted.pcap_max_challenges).toBeNull();
  });
});

/**
 * The C2 field vocabulary. Both unions are CLOSED, mirroring the ``SOURCE_*``
 * and ``TYPE_*`` constants in ``engine/resources/protocol_fields.py``, and are
 * pinned here for the same reason ``PcapSkipReason`` above is: a wrong literal
 * in a closed union type-checks and then never matches a real response, so the
 * UI silently cannot label a row that arrives every time.
 */
describe("PcapFieldSource / PcapFieldType", () => {
  const sources: PcapFieldSource[] = [
    "client_hello",
    "server_hello",
    "certificate",
    "record_layer",
  ];
  const types: PcapFieldType[] = ["bytes", "uint", "string", "uint[]", "bytes[]"];

  it("covers every source the extractor emits", () => {
    expect(sources).toHaveLength(4);
    expect(new Set(sources).size).toBe(sources.length);
  });

  it("covers the whole type vocabulary, reserved members included", () => {
    // ``bytes[]`` is emitted by nothing today (certificates come out one per
    // field so each keeps its own provenance) but is part of the agreed
    // vocabulary, so a consumer must tolerate it rather than narrow it away.
    expect(types).toHaveLength(5);
    expect(types).toContain("bytes[]");
  });
});

describe("PcapField", () => {
  it("carries wire provenance a dump hit can be cross-checked against", () => {
    // ``stream_offset - record_offset - 5 == the record header's offset``: the
    // 5-byte TLS record header relates the pair, so the shape is self-checking.
    const field: PcapField = {
      field_id: "client_random",
      label: "ClientHello.random",
      type: "bytes",
      value_hex: "aa".repeat(32),
      value: null,
      length: 32,
      source: "client_hello",
      provenance: {
        direction: "client",
        record_index: 0,
        stream_offset: 16,
        record_offset: 11,
      },
      searchable: true,
    };
    expect(field.provenance!.stream_offset - field.provenance!.record_offset - 5).toBe(0);
    expect(field.searchable).toBe(true);
  });

  it("allows a null provenance for a field with no wire position", () => {
    // The record-sequence lists: TLS never transmits the sequence number, each
    // side counts it, so there is no offset to point at and inventing
    // ``record_index: -1`` would be worse than admitting it.
    const seq: PcapField = {
      field_id: "client_record_seq",
      label: "client record sequence numbers",
      type: "uint[]",
      value_hex: "",
      value: [0, 1, 2],
      length: 3,
      source: "record_layer",
      provenance: null,
      searchable: false,
    };
    expect(seq.provenance).toBeNull();
    expect(seq.searchable).toBe(false);
  });

  it("rides on the session as an OPTIONAL key, like app_records_seen", () => {
    // A response that did not ask for fields (the arm request) must still
    // type-check, which is why ``fields`` is optional rather than defaulted.
    const armed: PcapValidateResult = {
      pcap_path: "/tmp/traffic.pcap",
      session_count: 1,
      sessions: [
        {
          client_random: "aa".repeat(32),
          server_random: "bb".repeat(32),
          version: "13",
          cipher_suite: 0x1301,
          cipher_name: "TLS_AES_128_GCM_SHA256",
          client_app_records: 2,
          server_app_records: 3,
          has_app_records: true,
        },
      ],
    };
    expect(armed.sessions[0].fields).toBeUndefined();
    expect(armed.field_index).toBeUndefined();
  });
});

describe("field_index", () => {
  it("is a catalogue of ids, never a map of values", () => {
    // Two sessions both have a ``client_random`` with DIFFERENT bytes, so an
    // id-keyed map of values could only be right for one of them. What the
    // index carries instead is where to look each id up.
    const index: Record<string, PcapFieldIndexEntry> = {
      client_random: {
        label: "ClientHello.random",
        type: "bytes",
        source: "client_hello",
        searchable: true,
        sessions: [0, 1],
      },
    };
    expect(index.client_random.sessions).toEqual([0, 1]);
    expect(Object.keys(index.client_random)).not.toContain("value_hex");
  });
});

/**
 * The C3 pairing vocabulary. Two more CLOSED unions, mirroring the
 * ``PAIRINGS`` and ``PAIR_STATUSES`` tuples in ``app/tools_pipeline.py``, and
 * pinned for the same reason as every union above.
 *
 * The load-bearing part is the ``status``/``location`` biconditional: the
 * backend enforces it (``_pair_row`` raises a ValueError otherwise), and these
 * cases pin that a consumer can rely on it -- because a row that was never
 * searched, rendered as a zero-hit row, is an absence claim over bytes nobody
 * read.
 */
describe("PcapPairing / PcapPairStatus", () => {
  const pairings: PcapPairing[] = ["explicit", "discovered", "unpaired"];
  const statuses: PcapPairStatus[] = [
    "searched",
    "unpaired",
    "field_unresolved",
  ];

  it("covers every way a capture can be arrived at", () => {
    expect(pairings).toHaveLength(3);
    expect(new Set(pairings).size).toBe(pairings.length);
  });

  it("covers all three pair outcomes, so an unsearched pair has a name", () => {
    expect(statuses).toHaveLength(3);
    expect(statuses).toContain("unpaired");
    expect(statuses).toContain("field_unresolved");
  });
});

describe("PcapPairRow", () => {
  it("carries a location for a searched pair", () => {
    const row: PcapPairRow = {
      dump_path: "/dumps/a.dump",
      dump_name: "a.dump",
      pcap_path: "/caps/a.pcap",
      pairing: "discovered",
      capture_status: "present",
      field_id: "client_random",
      needle_hex: "aa".repeat(32),
      status: "searched",
      detail: "",
      location: { verdict: "found", first_offset: 583560 },
    };
    expect(row.location).not.toBeNull();
    expect(row.needle_hex).toHaveLength(64);
  });

  it("carries a NULL location and an empty needle for an unpaired dump", () => {
    // The distinction the whole type exists for: "" is not the empty needle
    // and a null location is not a zero-hit census.
    const row: PcapPairRow = {
      dump_path: "/dumps/orphan.dump",
      dump_name: "orphan.dump",
      pcap_path: "",
      pairing: "unpaired",
      capture_status: "absent",
      field_id: "client_random",
      needle_hex: "",
      status: "unpaired",
      detail: "no capture for this dump's run (capture_status=absent)",
      location: null,
    };
    expect(row.location).toBeNull();
    expect(row.needle_hex).toBe("");
    expect(row.detail).not.toBe("");
  });
});

describe("LocateFieldPairsResult", () => {
  it("keeps every ratio's denominator on counts, not on pairs.length", () => {
    // Two pairs, one of them never searched. ``pairs.length`` would make the
    // survival ratio 1/2; the honest one is 1/1 over a stated denominator,
    // with the second dump's content UNKNOWN.
    const pair: PcapPair = {
      dump_path: "/dumps/a.dump",
      pcap_path: "/caps/a.pcap",
    };
    const result: LocateFieldPairsResult = {
      verdict: "found",
      mode: "explicit",
      field_id: "client_random",
      view: null,
      caps: { pcap_max_records: null, pcap_max_challenges: null },
      counts: {
        pairs_total: 2,
        pairs_searched: 1,
        pairs_unpaired: 1,
        pairs_field_unresolved: 0,
        pairs_present: 1,
        pairs_absent: 0,
        dumps_searched: 1,
        dumps_unreadable: 0,
        dumps_too_small: 0,
        captures_distinct: 1,
        needles_distinct: 1,
      },
      offsets_agree: true,
      common_offset: 583560,
      pairs: [],
      elapsed_s: 0.2,
      diagnostics: [],
    };
    expect(pair.client_random).toBeUndefined();
    expect(result.counts.pairs_searched).toBeLessThan(result.counts.pairs_total);
    expect(
      result.counts.pairs_present + result.counts.pairs_absent,
    ).toBe(result.counts.pairs_searched);
  });
});

describe("PipelineRunRequest scudo", () => {
  it("names the method without a reduce block", () => {
    const body: PipelineRunRequest = {
      source_paths: ["/d/a.msl", "/d/b.msl"],
      scudo: { allocator: "auto" },
      brute_force: { key_sizes: [48] },
    };
    expect(JSON.parse(JSON.stringify(body))).toEqual({
      source_paths: ["/d/a.msl", "/d/b.msl"],
      scudo: { allocator: "auto" },
      brute_force: { key_sizes: [48] },
    });
  });
});

describe("runPipeline and the session region filter", () => {
  afterEach(() => {
    useRegionSelectionStore.getState().reset();
    vi.unstubAllGlobals();
  });

  async function postedBody(body: PipelineRunRequest): Promise<Record<string, unknown>> {
    useRegionSelectionStore.getState().setRegionFilter("heap,stack");
    const fetchMock = vi.fn(
      async () => new Response(JSON.stringify({ task_id: "t", status: "pending" }), { status: 200 }),
    );
    vi.stubGlobal("fetch", fetchMock);
    await runPipeline(body);
    const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    return JSON.parse(init.body as string) as Record<string, unknown>;
  }

  it("attaches the wizard's filter to a positional run", async () => {
    const body = await postedBody({ source_paths: ["/d/a.msl"] });
    expect(body.region_filter).toBe("heap,stack");
  });

  it("leaves it off a Scudo run, which the server would refuse", async () => {
    const body = await postedBody({
      source_paths: ["/d/a.msl", "/d/b.msl"],
      scudo: { allocator: "auto" },
    });
    expect(body).not.toHaveProperty("region_filter");
  });
});
