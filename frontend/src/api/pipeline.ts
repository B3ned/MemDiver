/**
 * Typed client for the Phase 25 pipeline endpoints.
 *
 * Mirrors the Pydantic models in api/routers/pipeline.py and the
 * TaskRecord shape from api/services/task_manager.py. Consumers
 * should prefer these helpers over hand-rolled fetch calls so
 * request/response changes stay in one place.
 */

import { request, uploadFile } from "./client";
import { withSessionRegionFilter } from "@/stores/region-selection-store";
// ``StageDiagnostic`` is the ONE diagnostic shape every producer emits, so
// the paired-field result below reuses it rather than declaring a second.
import type { StageDiagnostic } from "./progress-events";
import type { HeapPolicy } from "./types";

// ---- request models (must match api/routers/pipeline.py) ----

export interface ReduceParams {
  /**
   * What `search_reduce` does with the consensus heap roles. Optional and only
   * sent once chosen; the backend defaults to `"annotate"`.
   */
  heap_policy?: HeapPolicy;
  alignment?: number;
  block_size?: number;
  density_threshold?: number;
  min_variance?: number;
  entropy_window?: number;
  entropy_threshold?: number;
  min_region?: number;
}

export interface BruteForceParams {
  key_sizes?: number[];
  stride?: number;
  jobs?: number;
  exhaustive?: boolean;
  top_k?: number;
}

export interface NSweepParams {
  n_values: number[];
  reduce_kwargs?: ReduceParams | null;
  key_sizes?: number[];
  stride?: number;
  exhaustive?: boolean;
}

export interface EmitParams {
  name?: string;
  description?: string | null;
  hit_index?: number;
  min_static_ratio?: number;
  variance_threshold?: number | null;
}

export interface ScudoParams {
  allocator: "scudo" | "auto";
}

export interface PipelineRunRequest {
  source_paths: string[];
  // Supply exactly one oracle source: an armed BYO oracle (oracle_id) or a
  // pcap/pcapng of the same TLS session (pcap_path), which routes the
  // brute-force stage through the first-party trusted pcap oracle.
  oracle_id?: string | null;
  pcap_path?: string | null;
  tls_client_random?: string | null;
  // Pcap-oracle work caps, both validated server-side as >= 1 (api/routers/
  // pipeline.py). Omit or send null to keep the backend defaults: 16 records
  // per direction, no total challenge cap. Both are silent truncations of
  // verification coverage, so send them only deliberately -- and read the arm
  // step's `caps` / `records_truncated` to see what a capture actually loses.
  pcap_max_records?: number | null;
  pcap_max_challenges?: number | null;
  reduce?: ReduceParams;
  brute_force?: BruteForceParams;
  nsweep?: NSweepParams | null;
  emit?: EmitParams | null;
  // The server refuses this together with `reduce` thresholds, `nsweep` or
  // `emit`, which all need a positional consensus.
  scudo?: ScudoParams;
  /** Re-send past the server memory guard (see `@/api/memory-budget`). */
  force_memory?: boolean;
  /** Allow dumps from different experiment cohorts (else refused: `cohort.mixed`). */
  mixed_ok?: boolean;
}

export interface PipelineRunResponse {
  task_id: string;
  status: string;
  // null for a pcap-oracle run (no BYO oracle file to hash).
  oracle_sha256?: string | null;
}

// ---- pcap oracle upload + validation (api/routers/pcaps.py) ----

/** Result of uploading a pcap/pcapng to the server-managed pcap dir. */
export interface PcapUploadResult {
  pcap_path: string;
  filename: string;
  size: number;
}

/**
 * One TLS session dpkt could parse out of the capture. ``version`` is the
 * negotiated TLS version ("12" = 1.2, "13" = 1.3); the app-record counts hint
 * whether there is ciphertext worth decrypting on each side.
 */
export interface PcapSession {
  client_random: string;
  server_random: string;
  version: "12" | "13";
  cipher_suite: number;
  cipher_name: string;
  client_app_records: number;
  server_app_records: number;
  // True when the session carries at least one application_data record the
  // oracle can decrypt. Always emitted by the backend, so ``sessionHasAppRecords``
  // reads it directly.
  has_app_records: boolean;
  // Record accounting added by ``TlsPcapResource.describe_capture``: how many
  // application-data records the parser saw across both directions, and how
  // many of those the challenge stream actually COVERS -- after the per-
  // direction record cap, the TLS 1.2 ChangeCipherSpec gate, and whatever is
  // left of the total challenge budget. ``records_returned < app_records_seen``
  // means this session is only partially verified; ``records_returned: 0`` on a
  // session with records means it is not verified at all (look in
  // ``skipped_sessions`` for the reason). Optional so a caller holding a
  // ``describe_sessions`` dict (which carries neither) still type-checks.
  app_records_seen?: number;
  records_returned?: number;
  // Challenge accounting. A challenge is NOT a record: a TLS 1.3 record is
  // probed over a sequence-number window (up to 9 candidates), so one record
  // can contribute several challenges and this can far exceed
  // ``records_returned``. ``challenges_available`` is what the session would
  // contribute uncapped, ``challenges_returned`` what survives
  // ``caps.max_challenges`` -- which is spent ACROSS sessions in parse order,
  // so a later session can legitimately report 0 here.
  challenges_available?: number;
  challenges_returned?: number;
  // The C2 byte-addressed view: which bytes of this handshake could be hunted
  // for in a memory dump, and where on the wire each came from. Present ONLY
  // when the request asked for it (``validatePcap(path, {includeFields: true})``
  // -> ``include_fields`` on the body); the arm request does not, so these are
  // optional exactly as ``app_records_seen`` above is -- a response that
  // predates the flag, or one that simply did not ask, still type-checks.
  fields?: PcapField[];
  field_notes?: PcapFieldNote[];
}

/**
 * Which handshake message a field's bytes were read out of. A CLOSED union
 * mirroring the ``SOURCE_*`` constants in
 * ``engine/resources/protocol_fields.py`` -- named there rather than inlined so
 * a consumer can switch on them instead of matching free text.
 */
export type PcapFieldSource =
  | "client_hello"
  | "server_hello"
  | "certificate"
  | "record_layer";

/**
 * A field's value shape, mirroring the ``TYPE_*`` vocabulary in
 * ``protocol_fields.py``. ``bytes`` and ``string`` are the byte-needle cases;
 * ``uint``/``uint[]`` are wire-encoding artifacts no TLS library stores in wire
 * form, so no dump search over them is meaningful. ``bytes[]`` is reserved --
 * nothing emits it today (certificates come out individually so each keeps its
 * own provenance) but it is part of the agreed vocabulary, so a consumer must
 * tolerate it.
 */
export type PcapFieldType = "bytes" | "uint" | "string" | "uint[]" | "bytes[]";

/**
 * Where on the wire a field's bytes sat. Carried so a hit at some dump offset
 * can be cross-checked against WHICH record of WHICH direction produced the
 * bytes it matched. ``null`` for a field with no wire position at all -- the
 * record-sequence lists, which TLS never transmits.
 */
export interface PcapFieldProvenance {
  direction: "client" | "server";
  /** Index into that direction's record list. */
  record_index: number;
  /** Byte offset in the reassembled direction stream. */
  stream_offset: number;
  /** Byte offset inside the record fragment. */
  record_offset: number;
}

/**
 * One extracted protocol field: what it is, its bytes, and where from.
 *
 * ``searchable`` is DERIVED on the backend (a ``bytes``/``string`` run of at
 * least 8 bytes), never hand-set. Treat it as a permission: a field with
 * ``searchable: false`` matches everywhere in any real multi-megabyte dump, so
 * offering it as a needle could only produce a guaranteed false-positive sweep
 * -- and ``locate_key``'s ``pcap_field`` form refuses it.
 *
 * ``field_id`` is unique WITHIN a session. Extension ids carry a
 * ``client_ext.``/``server_ext.`` prefix for exactly that reason: extension
 * 0x000b appears in both hellos of a real handshake, so a bare ``ext.0x000b``
 * would collide and any id-keyed lookup would silently resolve to whichever
 * came last.
 */
export interface PcapField {
  field_id: string;
  label: string;
  type: PcapFieldType;
  /** The field's raw wire bytes as hex; empty for a field with no byte form. */
  value_hex: string;
  /** The decoded form when there is a more useful one than hex (the hostname
   * for ``sni``, the int for ``cipher_suite``, the list for ``cipher_suites``);
   * ``null`` when hex is all there is. */
  value: string | number | number[] | null;
  /** Bytes for a byte field, element count for a ``uint[]``. */
  length: number;
  source: PcapFieldSource;
  provenance: PcapFieldProvenance | null;
  searchable: boolean;
}

/**
 * Why a field a caller might reasonably expect is legitimately absent.
 *
 * Machine-readable ``code`` first, human ``detail`` second -- the same
 * discipline as ``PcapSkippedSession``, and for the same reason: an
 * unexplained absence is indistinguishable from a bug to the person least able
 * to tell the difference. The load-bearing one is
 * ``tls13_certificates_encrypted``: RFC 8446 moves the Certificate message
 * inside the protected epoch, so no TLS 1.3 capture can carry one.
 *
 * NOT a closed union: the backend adds codes as new fields gain explanations,
 * and a UI that cannot label one still shows its ``detail``.
 */
export interface PcapFieldNote {
  code: string;
  detail: string;
}

/**
 * One entry of the top-level ``field_index``: the ids a capture offers, and
 * which sessions carry each. A CATALOGUE, deliberately without values -- a
 * capture's two sessions both have a ``client_random`` field with different
 * bytes, so an id-keyed map of values could only be wrong.
 *
 * ``searchable`` here means "in at least one of the listed sessions", because
 * the flag is derived from a length and two sessions can legitimately disagree.
 * The authoritative per-session flag is ``PcapField.searchable``.
 */
export interface PcapFieldIndexEntry {
  label: string;
  type: PcapFieldType;
  source: PcapFieldSource;
  searchable: boolean;
  /** Positions in ``PcapValidateResult.sessions`` that carry this id. */
  sessions: number[];
}

/**
 * Why the parser had to drop work, machine-readable. Mirrors the ``reason``
 * values ``TlsPcapResource._note_skipped`` emits; the list is closed on the
 * backend today, so a new reason is a deliberate contract change on both sides.
 *
 * Not every reason drops a whole session. ``no_change_cipher_spec`` KEEPS the
 * session and reports that one direction's application data is unreachable,
 * and ``client_random_mismatch`` reports a session that parsed fine but is not
 * the one the resource is pinned to -- so a row can appear in both ``sessions``
 * and ``skipped_sessions``, which is the point: it explains a
 * ``records_returned: 0`` that would otherwise read as an unexplained zero.
 * ``client_random_mismatch`` requires a pinned resource, which the arm producer
 * does not do, so expect it from a run rather than from this response.
 *
 * ``no_cipher_suite`` and ``short_random`` are defensive guards the bundled
 * dpkt cannot actually produce (it always yields a 32-byte random and an int
 * suite code, and a short random surfaces as ``no_server_hello``). They stay
 * in the union so a different dpkt build cannot break the narrowing, but a UI
 * must not present them as expected outcomes.
 */
export type PcapSkipReason =
  | "no_client_hello"
  | "no_server_hello"
  | "no_cipher_suite"
  | "short_random"
  | "unsupported_cipher_suite"
  | "no_change_cipher_spec"
  | "client_random_mismatch";

/**
 * One piece of work the parser saw but could not use. ``flow`` is the
 * human-readable directional flow label ("ip:port -> ip:port"); the remaining
 * fields are reason-specific context (``cipher_suite`` for an out-of-table
 * suite, the two random lengths for a truncated handshake, ``direction`` plus
 * that direction's ``app_records_seen`` for a missing ChangeCipherSpec, and
 * the hex ``client_random`` of a session this run is not pinned to).
 */
export interface PcapSkippedSession {
  reason: PcapSkipReason;
  flow: string;
  cipher_suite?: number;
  client_random_len?: number;
  server_random_len?: number;
  /** ``no_change_cipher_spec`` only: which half of the session is unreachable. */
  direction?: "client" | "server";
  /** ``no_change_cipher_spec`` only: application-data records lost on that
   * direction. Per-direction, so it does NOT match the session-level
   * ``PcapSession.app_records_seen``, which sums both directions. */
  app_records_seen?: number;
  /** ``client_random_mismatch`` only: hex ``client_random`` of the session the
   * stream skipped, so the UI can say WHICH session was passed over. */
  client_random?: string;
}

/**
 * The caps in force for a capture (``describe_capture().caps``).
 *
 * Both are silent losses of verification coverage, which is why both are
 * reported rather than only the record one. ``max_challenges`` is ``null`` when
 * uncapped -- the KEY is always present, so "uncapped" can never be mistaken
 * for "unreported".
 */
export interface PcapCaps {
  /** Application-data records each DIRECTION of each session contributes. */
  max_records_per_direction: number;
  /** Total challenges the oracle keeps, spent across sessions in parse order;
   * ``null`` = uncapped. A value below 1 is rejected server-side. */
  max_challenges?: number | null;
}

/**
 * Server-side validation of an uploaded pcap: the sessions it contains.
 *
 * The accounting fields below say what the parse *dropped*, and exist so a
 * zero-confirmation run is never mistaken for full coverage: a session with a
 * cipher suite outside the parser's table used to vanish with only a log line.
 * They are optional purely for backward compatibility with a cached or older
 * response.
 *
 * ``POST /api/pcaps/validate`` returns the ``app.tools_pipeline.inspect_pcap``
 * dict verbatim, and that producer emits every key below. They stay optional so
 * a cached or older response still type-checks -- read them defensively, do not
 * treat an absent one as an error.
 */
export interface PcapValidateResult {
  pcap_path: string;
  session_count: number;
  sessions: PcapSession[];
  /** Work the parser dropped, each entry with a machine-readable reason. Not
   * all of it is a whole session -- see ``PcapSkipReason``. */
  skipped_sessions?: PcapSkippedSession[];
  /** Directional TCP flows the capture yielded -- the denominator for
   * ``session_count``: "1 session out of 40 flows" is not "1 out of 2". */
  flow_count?: number;
  caps?: PcapCaps;
  /** True when any session returns fewer records than it saw, WHATEVER the
   * cause: ``caps.max_records_per_direction``, a missing TLS 1.2
   * ChangeCipherSpec (which makes a direction undecryptable outright), or an
   * exhausted ``caps.max_challenges`` budget. It is not a statement about the
   * record cap alone. */
  records_truncated?: boolean;
  /** Challenges the whole capture would contribute uncapped. Reported because
   * it is not derivable from the record counts: a TLS 1.3 record is probed over
   * a sequence-number window, so the corpus average is ~3.9 challenges per
   * record -- a ``max_challenges`` of 50 therefore covers only ~13 records. */
  challenges_available?: number;
  /** Challenges that survive ``caps.max_challenges``. */
  challenges_returned?: number;
  /** ``challenges_returned < challenges_available`` -- some record got only
   * part of its sequence window, so a no-hit run is a statement about the
   * challenges tried, not about the capture. */
  challenges_truncated?: boolean;
  /** The C2 catalogue of field ids this capture offers, keyed by ``field_id``.
   * Present only when the request asked for fields. */
  field_index?: Record<string, PcapFieldIndexEntry>;
}

// ---- paired field search (POST /api/pcaps/locate-field) ----

/**
 * ONE explicit ``(dump, capture)`` pairing.
 *
 * Mirrors the backend's ``PCAP_PAIR_KEYS``: ``client_random`` is the only
 * optional key and picks a session when the capture holds several (there is no
 * default server-side -- the wrong session's field is a valid-looking needle
 * from another handshake).
 *
 * Explicit pairings are the alternative to letting each dump discover the
 * capture of the run it lives in; supply one form or the other, never both.
 */
export interface PcapPair {
  dump_path: string;
  pcap_path: string;
  client_random?: string;
}

/**
 * How a pair's capture was arrived at. A CLOSED union mirroring the
 * ``PAIRING_*`` constants in ``app/tools_pipeline.py`` -- ``"unpaired"`` is a
 * VALUE, not an absence: a dump with no capture is still a row, because
 * dropping it would shrink the denominator every ratio is computed over.
 */
export type PcapPairing = "explicit" | "discovered" | "unpaired";

/**
 * What HAPPENED to a pair. Three-valued for the same reason the per-dump
 * ``status`` in a ``locate-key`` census is, and it must be read BEFORE any
 * number on the row:
 *
 * * ``"searched"`` -- ``location`` is non-null and carries the census.
 * * ``"unpaired"`` -- no capture, so nothing was searched. NOT an absence.
 * * ``"field_unresolved"`` -- a capture was found but yields no usable field;
 *   ``detail`` says why. Also NOT an absence.
 */
export type PcapPairStatus = "searched" | "unpaired" | "field_unresolved";

/** One pair row. ``location`` is non-null iff ``status === "searched"``. */
export interface PcapPairRow {
  dump_path: string;
  dump_name: string;
  /** ``""`` when no capture was resolved for this dump. */
  pcap_path: string;
  pairing: PcapPairing;
  /** ``"supplied"`` for an explicit pair; otherwise the run walker's own
   * three-state verdict (``"present"`` / ``"absent"`` / ``"unreadable"``). */
  capture_status: string;
  field_id: string;
  /** The bytes actually searched for, hex. ``""`` means none was resolved --
   * never "the empty needle". Echoed (unlike a key census) because a handshake
   * field is public wire material and it is what makes the row reproducible. */
  needle_hex: string;
  status: PcapPairStatus;
  /** Why, whenever ``status`` is not ``"searched"``. */
  detail: string;
  /** The ``locate-key``-shaped census over this ONE dump, or ``null``. Typed
   * loosely because it is the key-location payload verbatim and no screen
   * consumes its interior yet; narrow it where one does. */
  location: Record<string, unknown> | null;
}

/** Per-status pair census. Every ratio must be read over these, not over
 * ``pairs.length``: unpaired and field-unresolved pairs were never searched. */
export interface PcapPairCounts {
  pairs_total: number;
  pairs_searched: number;
  pairs_unpaired: number;
  pairs_field_unresolved: number;
  pairs_present: number;
  pairs_absent: number;
  dumps_searched: number;
  dumps_unreadable: number;
  dumps_too_small: number;
  /** How many distinct captures were consulted, and how many distinct needles
   * they yielded -- together, whether this was a real pairing or one needle
   * wearing N hats. */
  captures_distinct: number;
  needles_distinct: number;
}

/**
 * Result of the paired field search. ``verdict`` uses the SAME three-valued
 * vocabulary a ``locate-key`` result does, so ``"not_searched"`` claims
 * nothing at all and must never render as an absence.
 */
export interface LocateFieldPairsResult {
  verdict: "found" | "absent" | "not_searched";
  mode: "explicit" | "discovery";
  field_id: string;
  view: string | null;
  caps: {
    pcap_max_records: number | null;
    pcap_max_challenges: number | null;
  };
  counts: PcapPairCounts;
  /** Whether every pair that found the field agrees on its first offset, and
   * that offset when they do. */
  offsets_agree: boolean;
  common_offset: number | null;
  pairs: PcapPairRow[];
  elapsed_s: number;
  diagnostics: StageDiagnostic[];
}

/** Request body for the paired field search: exactly one of the two forms. */
export interface LocateFieldPairsRequest {
  pairs?: PcapPair[] | null;
  dump_paths?: string[] | null;
  field_id?: string;
  view?: string | null;
  max_offsets?: number;
  pcap_max_records?: number | null;
  pcap_max_challenges?: number | null;
}

// ---- response models ----

/**
 * A single inferred structure field over a hit's neighborhood window.
 *
 * Produced server-side by ``PatternGenerator.infer_fields()`` (exposed via
 * ``POST /api/pipeline/infer-fields`` and the ``/refine`` response) so the
 * frontend consumes it instead of recomputing the segmentation client-side.
 * Shape matches the ``InferredField`` Pydantic contract byte-for-byte.
 */
export interface InferredField {
  offset: number;
  length: number;
  type: "static" | "key_material" | "dynamic";
  label: string;
  mean_variance: number;
}

export type TaskStatus =
  | "pending"
  | "running"
  | "succeeded"
  | "failed"
  | "cancelled";

export interface StageRecord {
  name: string;
  status: TaskStatus;
  pct: number;
  msg: string;
  started_at: number | null;
  ended_at: number | null;
}

export interface ArtifactSpec {
  name: string;
  relpath: string;
  media_type: string;
  size: number;
  sha256: string | null;
  registered_at: number;
}

export interface TaskRecord {
  task_id: string;
  kind: string;
  status: TaskStatus;
  params: Record<string, unknown>;
  stages: StageRecord[];
  artifacts: ArtifactSpec[];
  created_at: number;
  started_at: number | null;
  ended_at: number | null;
  error: string | null;
  /** Structured failure, e.g. `{code: "memory_budget_exceeded", estimate_bytes, budget_bytes, details}`. */
  error_info?: Record<string, unknown> | null;
  schema_version: number;
}

// ---- endpoints ----

export const runPipeline = (body: PipelineRunRequest) =>
  request<PipelineRunResponse>("/api/pipeline/run", {
    method: "POST",
    // Session region filter (wizard Regions step), unless the body sets one.
    // Never on a Scudo run: its offsets are in the dump's unfiltered view, so
    // the server refuses a filter rather than report offsets that do not match.
    body: JSON.stringify(body.scudo ? body : withSessionRegionFilter(body)),
  });

/**
 * Upload a pcap/pcapng. Multipart, so it delegates to the shared
 * ``uploadFile`` helper, which posts under the ``file`` form field and unwraps
 * FastAPI's ``{"detail": ...}`` error body into an ``ApiError`` so callers can
 * surface the capability-error message verbatim.
 */
export const uploadPcap = (file: File): Promise<PcapUploadResult> =>
  uploadFile<PcapUploadResult>("/api/pcaps/upload", file);

/**
 * Ask the server to parse the TLS sessions out of an uploaded pcap. On a
 * dpkt-missing / bad-capture condition the backend returns HTTP 400 via the
 * capability-error funnel, which ``request`` re-raises as an ``ApiError``.
 */
export interface ValidatePcapOptions {
  /**
   * Also ask for each session's byte-addressable protocol fields
   * (``PcapField``) plus the top-level ``field_index``. Costs a second
   * server-side read of the capture, so the arm request leaves it off and only
   * the field browser opts in. Omitted from the body entirely when false, so
   * the arm request stays byte-identical to what it has always sent.
   */
  includeFields?: boolean;
}

export const validatePcap = (pcapPath: string, options?: ValidatePcapOptions) =>
  request<PcapValidateResult>("/api/pcaps/validate", {
    method: "POST",
    body: JSON.stringify(
      options?.includeFields
        ? { pcap_path: pcapPath, include_fields: true }
        : { pcap_path: pcapPath },
    ),
  });

/**
 * Search N dumps for a handshake field, each dump taking the field from the
 * capture that belongs to IT.
 *
 * ``validatePcap`` above arms one capture; this is the multi-dump search built
 * on top. Supply exactly one of ``pairs`` (explicit) or ``dump_paths``
 * (discovery) -- the backend refuses both, with no precedence, and that
 * refusal arrives as an ``ApiError`` via the capability-error funnel.
 */
export const locateFieldPairs = (body: LocateFieldPairsRequest) =>
  request<LocateFieldPairsResult>("/api/pcaps/locate-field", {
    method: "POST",
    body: JSON.stringify(body),
  });

export const getPipelineRun = (taskId: string) =>
  request<TaskRecord>(
    `/api/pipeline/runs/${encodeURIComponent(taskId)}`,
  );

export const cancelPipelineRun = (taskId: string) =>
  request<{ task_id: string; cancelled: boolean; status?: string }>(
    `/api/pipeline/runs/${encodeURIComponent(taskId)}`,
    { method: "DELETE" },
  );

/**
 * Return an absolute URL for downloading a registered artifact. The
 * server enforces traversal + symlink guards via ArtifactStore so the
 * caller does not need to sanitize ``name``; it must still be one of
 * the ``name`` fields from a TaskRecord.artifacts entry.
 */
export const artifactDownloadUrl = (taskId: string, name: string): string =>
  `/api/pipeline/runs/${encodeURIComponent(taskId)}/artifacts/${encodeURIComponent(name)}`;

// --- Phase C: Refine workflow ---

export interface RefineResponse {
  num_dumps: number;
  static_count: number;
  dynamic_count: number;
  /** Variance threshold (PLUGIN_STATIC_THRESHOLD) used to classify bytes. */
  variance_threshold: number;
  hit_neighborhoods: Array<{
    offset: number;
    neighborhood_start: number;
    neighborhood_variance: number[];
    static_count: number;
    dynamic_count: number;
    /** Server-inferred field structure for this neighborhood window. */
    fields: InferredField[];
  }>;
}

/** Request body for ``POST /api/pipeline/infer-fields``. */
export interface InferFieldsRequest {
  neighborhood_variance: number[];
  neighborhood_start: number;
  offset: number;
  length: number;
  variance_threshold?: number | null;
}

/**
 * Segment a neighborhood variance array into contiguous static /
 * key_material / dynamic fields, server-side. Returns the inferred fields
 * plus the ``variance_threshold`` actually applied (so callers never hardcode
 * it). Replaces the former client-side ``inferNeighborhoodFields`` port.
 */
export async function inferFields(
  body: InferFieldsRequest,
): Promise<{ fields: InferredField[]; variance_threshold: number }> {
  return request<{ fields: InferredField[]; variance_threshold: number }>(
    "/api/pipeline/infer-fields",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    },
  );
}

export async function refinePipeline(
  taskId: string,
  additionalPaths: string[],
): Promise<RefineResponse> {
  return request<RefineResponse>(
    `/api/pipeline/runs/${encodeURIComponent(taskId)}/refine`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ additional_paths: additionalPaths }),
    },
  );
}

export async function getNeighborhood(
  taskId: string,
  offset: number,
  length: number = 32,
): Promise<{ offset: number; neighborhood_start: number; num_dumps: number; variance: number[] }> {
  return request(
    `/api/pipeline/runs/${encodeURIComponent(taskId)}/neighborhood?offset=${offset}&length=${length}`,
  );
}
