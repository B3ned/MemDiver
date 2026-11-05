import type {
  ScanRequest,
  AnalyzeRequest,
  AnalyzeFileRequest,
  ProtocolDescriptor,
  PhaseInfo,
  AnalysisRunResponse,
  HexData,
  EntropyData,
  SessionInfo,
  SessionSnapshot,
  TaskRecord,
  PathInfo,
  BrowseResult,
  DiscoverDumpsResult,
  StructureMatchResult,
  StructureApplyResult,
  StringsResponse,
  ConvergenceSweepResult,
  VerifyKeyResult,
  AutoExportResult,
  ExportKeylogRequest,
  ExportKeylogResult,
  FormatSuggestion,
  TagStatus,
  PageStatesResponse,
  SessionInfoResponse,
  VasRegionsResponse,
  ImportProvenanceResponse,
  DatasetRunsResponse,
  KeyMaterial,
  ImportPreview,
} from "./types";
import { keyMaterialWire } from "./key-material-wire";
import i18n from "@/i18n";

const BASE = ""; // relative -- Vite proxy handles /api/* during dev

/** Append the non-empty key-material fields to a query string, if present. */
export function appendKey(qs: URLSearchParams, key?: KeyMaterial) {
  if (key?.passphrase) qs.set("passphrase", key.passphrase);
  if (key?.key_hex) qs.set("key_hex", key.key_hex);
  if (key?.kem_key_hex) qs.set("kem_key_hex", key.kem_key_hex);
}

export class ApiError extends Error {
  status: number;
  /**
   * The raw response body. Equal to `message` for errors thrown by `request`;
   * kept separately so a caller that prefixes its own message (e.g. the
   * consensus store's "Consensus failed: ...") still exposes the structured
   * envelope to `isMemoryBudgetError`.
   */
  body: string;
  constructor(status: number, message: string, body: string = message) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

/**
 * A sentence a human can read, out of whatever a `request` call rejected with.
 *
 * `request` throws `ApiError` carrying the RAW response body, so an error
 * surfaced verbatim reads
 * `{"error":"anchor offset does not name an addressable byte","category":...}`.
 * Unwrapping the envelope's own message is the difference between a note the
 * analyst can act on and a JSON blob in the middle of the UI.
 *
 * Lives beside `ApiError` because that is the shape it decodes; every store
 * that surfaces a failed request should import THIS one rather than keep a
 * private copy that silently reverts to the raw body.
 */
export function readableFailure(err: unknown): string {
  const raw = (err instanceof Error ? err.message : String(err)).trim();
  if (!raw.startsWith("{")) return raw;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (parsed && typeof parsed === "object") {
      const envelope = parsed as { error?: unknown; detail?: unknown; message?: unknown };
      for (const field of [envelope.error, envelope.detail, envelope.message]) {
        if (typeof field === "string" && field.trim() !== "") return field.trim();
      }
      // FastAPI `detail` may itself be a `{code, message}` object (e.g. the agent models listing).
      const nested = (envelope.detail as { message?: unknown } | null)?.message;
      if (typeof nested === "string" && nested.trim() !== "") return nested.trim();
    }
  } catch {
    // Not JSON after all -- the raw text is the best we have.
  }
  return raw;
}

/** Decodes a non-empty response body (default `JSON.parse`). */
export type BodyParser = (text: string) => unknown;

/** Optional decoding inputs of {@link request}. */
export interface RequestOptions {
  /**
   * Decoder for a non-empty body. Default `JSON.parse`; the lossless decoder
   * (`parseJsonLossless`) keeps integers past 2^53 exact. A throw from it is
   * reported as the same "Malformed JSON response" `ApiError` either way.
   */
  parse?: BodyParser;
  /**
   * The endpoint always answers with a result, so an empty body is a server
   * fault: reject it as an `ApiError` instead of resolving `undefined` (which
   * a caller's shape guard would then be handed).
   */
  requireBody?: boolean;
}

export async function request<T>(
  url: string,
  init?: RequestInit,
  { parse = JSON.parse, requireBody = false }: RequestOptions = {},
): Promise<T> {
  const { headers: callerHeaders, ...restInit } = init ?? {};
  const res = await fetch(`${BASE}${url}`, {
    ...restInit,
    headers: { "Content-Type": "application/json", ...callerHeaders },
  });
  if (!res.ok) {
    const body = await res.text();
    throw new ApiError(res.status, body);
  }
  // Read as text first so an empty (e.g. 204 No Content) or malformed body
  // surfaces as an ApiError instead of a bare SyntaxError from res.json(),
  // keeping `instanceof ApiError` handling consistent for all callers.
  const text = await res.text();
  if (text === "") {
    if (requireBody) throw new ApiError(res.status, i18n.t("common:emptyResponse"));
    return undefined as T;
  }
  try {
    return parse(text) as T;
  } catch {
    throw new ApiError(res.status, `Malformed JSON response: ${text.slice(0, 200)}`);
  }
}

/** POST `body` as JSON through {@link request}. */
export const postJson = <T>(url: string, body: unknown, options?: RequestOptions) =>
  request<T>(url, { method: "POST", body: JSON.stringify(body) }, options);

/** Drop undefined / empty-string optionals so the backend sees `null`, not `""`. */
export function compact<T extends object>(body: T): Partial<T> {
  return Object.fromEntries(
    Object.entries(body).filter(([, v]) => v !== undefined && v !== ""),
  ) as Partial<T>;
}

// Dataset
export const scanDataset = (body: ScanRequest) =>
  request<Record<string, unknown>>("/api/dataset/scan", {
    method: "POST",
    body: JSON.stringify(body),
  });

export const listProtocols = () =>
  request<{ protocols: ProtocolDescriptor[] }>("/api/dataset/protocols");

/** Enumerate run directories (with their dumps) under a dataset/library dir. */
export const listDatasetRuns = (
  root: string,
  limit?: number,
  offset?: number,
) => {
  let query = `/api/dataset/runs?root=${encodeURIComponent(root)}`;
  if (limit !== undefined) query += `&limit=${limit}`;
  if (offset !== undefined) query += `&offset=${offset}`;
  return request<DatasetRunsResponse>(query);
};

export const listPhases = (libraryDir: string) =>
  request<PhaseInfo>(
    `/api/dataset/phases?library_dir=${encodeURIComponent(libraryDir)}`,
  );

// Analysis
//
// Both endpoints now dispatch the GIL-bound algorithm work onto the
// TaskManager's ProcessPool and return a ``task_id`` immediately (the
// same async pattern as the pipeline + batch endpoints). Callers
// subscribe to ``/ws/tasks/{task_id}`` for progress and fetch the full
// ``AnalysisResult`` from the ``analysis_result`` artifact on
// completion — see ``@/api/analysis`` for the higher-level helpers.
export const runAnalysis = (body: AnalyzeRequest) =>
  request<AnalysisRunResponse>("/api/analysis/run", {
    method: "POST",
    body: JSON.stringify(body),
  });

export const runFileAnalysis = (body: AnalyzeFileRequest & KeyMaterial) =>
  request<AnalysisRunResponse>("/api/analysis/run-file", {
    method: "POST",
    body: JSON.stringify(body),
  });

// Inspect
/** The byte views a dump can be read through (backend `ViewMode`). */
export type DumpViewMode = "raw" | "vas" | "va";

/** Optional addressing inputs of {@link readHex}. */
export interface ReadHexOptions {
  /**
   * The view `offset` addresses. Omitted = the backend default ("raw"), the
   * historical behaviour. Callers describing a hex-viewer cursor MUST pass the
   * viewer's current view, or a VAS/VA offset is read as a container offset.
   */
  view?: DumpViewMode;
}

export const readHex = (
  dumpPath: string,
  offset = 0,
  length = 256,
  key?: KeyMaterial,
  options: ReadHexOptions = {},
) => {
  const qs = new URLSearchParams({
    dump_path: dumpPath,
    offset: String(offset),
    length: String(length),
  });
  if (options.view) qs.set("view", options.view);
  appendKey(qs, key);
  return request<HexData>(`/api/inspect/hex?${qs.toString()}`);
};

/**
 * How many sliding-window positions the entropy profile may be computed at.
 *
 * `length = 0` means "the whole file", and on the 220 MB corpus dump that is
 * ~13.75 million window positions computed in order to plot 200 of them — which
 * the entropy tab used to ask for on mount, with no user action, stalling the
 * single-process backend for the duration. The server enforces its own ceiling;
 * sending one anyway keeps the cost of this call stated where the call is made,
 * so it cannot quietly become unbounded again if that default ever moves.
 */
export const ENTROPY_MAX_PROFILE_POSITIONS = 1 << 18;

/**
 * How many envelope buckets the entropy tab asks for: about one per pixel
 * column of a wide chart, so a single-window spike survives as a peak of the
 * bucket's max. The server clamps to [1, 4096].
 */
export const ENTROPY_ENVELOPE_BUCKETS = 1500;

export interface EntropyOptions {
  /** Same as the positional `maxPositions` (wins over it when both are given). */
  maxPositions?: number;
  /**
   * The byte view `offset`/`length` address and the profile is computed in.
   * Omitted = the dump's flat view (the historical behaviour). The response's
   * `view` names the view actually used.
   */
  view?: DumpViewMode;
  /** Envelope bucket count (server clamps to [1, 4096]; omitted = 1500). */
  buckets?: number;
  /**
   * "auto" (server default) = full resolution for small inputs, sampled with
   * `full_resolution_available` otherwise; "full" = every window position.
   */
  resolution?: "auto" | "sampled" | "full";
  /** High-entropy threshold; omitted = the server's window-aware default. */
  threshold?: number;
  /** Aborts the request (e.g. a superseded full-resolution refinement). */
  signal?: AbortSignal;
}

/**
 * `getEntropy(path, offset, length, key, maxPositions?, options?)`; the fifth
 * argument may also be the options object itself
 * (`getEntropy(path, offset, length, key, { view })`).
 */
export const getEntropy = (
  dumpPath: string,
  offset = 0,
  length = 0,
  key?: KeyMaterial,
  maxPositionsOrOptions: number | EntropyOptions = ENTROPY_MAX_PROFILE_POSITIONS,
  options: EntropyOptions = {},
) => {
  const opts: EntropyOptions =
    typeof maxPositionsOrOptions === "number"
      ? { ...options, maxPositions: options.maxPositions ?? maxPositionsOrOptions }
      : { ...maxPositionsOrOptions, ...options };
  const qs = new URLSearchParams({
    dump_path: dumpPath,
    offset: String(offset),
    length: String(length),
    max_positions: String(opts.maxPositions ?? ENTROPY_MAX_PROFILE_POSITIONS),
  });
  if (opts.view) qs.set("view", opts.view);
  if (opts.buckets !== undefined) qs.set("buckets", String(opts.buckets));
  if (opts.resolution) qs.set("resolution", opts.resolution);
  if (opts.threshold !== undefined) qs.set("threshold", String(opts.threshold));
  appendKey(qs, key);
  const url = `/api/inspect/entropy?${qs.toString()}`;
  return opts.signal
    ? request<EntropyData>(url, { signal: opts.signal })
    : request<EntropyData>(url);
};

export interface StringsOpts {
  minLength?: number;
  encoding?: string;
  maxResults?: number;
  cursor?: number;
  chunkSize?: number;
  key?: KeyMaterial;
}

export const extractStrings = (
  dumpPath: string,
  opts: StringsOpts = {},
): Promise<StringsResponse> => {
  const qs = new URLSearchParams({ dump_path: dumpPath });
  const { minLength, encoding, maxResults, cursor, chunkSize, key } = opts;
  if (minLength !== undefined) qs.set("min_length", String(minLength));
  if (encoding !== undefined) qs.set("encoding", encoding);
  if (maxResults !== undefined) qs.set("max_results", String(maxResults));
  if (cursor !== undefined) qs.set("cursor", String(cursor));
  if (chunkSize !== undefined) qs.set("chunk_size", String(chunkSize));
  appendKey(qs, key);
  return request<StringsResponse>(`/api/inspect/strings?${qs.toString()}`);
};

// Sessions
export const listSessions = () =>
  request<{ sessions: SessionInfo[] }>("/api/sessions/");

export const saveSession = (payload: Partial<SessionSnapshot>) =>
  request<{ path: string; name: string; status: string }>("/api/sessions/", {
    method: "POST",
    body: JSON.stringify(payload),
  });

export const loadSession = (name: string) =>
  request<SessionSnapshot>(`/api/sessions/${encodeURIComponent(name)}`);

export const deleteSession = (name: string) =>
  request<{ deleted: string; status: string }>(
    `/api/sessions/${encodeURIComponent(name)}`,
    { method: "DELETE" },
  );

// Tasks
// NOTE: currently unused (zero callers). GET /api/tasks/{id} returns the full
// TaskRecord (record.to_dict() from api/services/task_manager.py), not a bare
// status enum. Kept for parity with the tasks endpoint.
export const getTask = (taskId: string) =>
  request<TaskRecord>(`/api/tasks/${taskId}`);

// Path info
export const getPathInfo = (path: string) =>
  request<PathInfo>(
    `/api/path/info?path=${encodeURIComponent(path)}`,
  );

// File browser
/**
 * List one directory.
 *
 * `allFiles` lifts the endpoint's default extension filter (`.dump` / `.msl`).
 * It stays off by default because the dump pickers WANT that filter; the oracle
 * config editor does not — a gocryptfs ciphertext sample has no extension at
 * all, so with the filter on the file the user must pick is invisible.
 */
export const browsePath = (path?: string, allFiles = false) => {
  const qs = new URLSearchParams();
  if (path) qs.set("path", path);
  if (allFiles) qs.set("all_files", "true");
  const query = qs.toString();
  return request<BrowseResult>(
    query ? `/api/path/browse?${query}` : "/api/path/browse",
  );
};

/**
 * Every dump under `path`, recursively, grouped by kind.
 *
 * `kinds` is sent as one repeated parameter per kind (the endpoint also
 * accepts the comma-separated form; repetition is what `URLSearchParams`
 * produces naturally). Omitting it lets the server apply its `msl` default.
 * The returned `dumps` are already sorted by path and MUST stay in that
 * order -- the N-dump consensus alignment downstream pairs dumps positionally.
 */
export const discoverDumps = (
  path: string,
  kinds?: string[],
  recursive = true,
  limit?: number,
) => {
  const qs = new URLSearchParams({ path, recursive: String(recursive) });
  for (const kind of kinds ?? []) qs.append("kinds", kind);
  if (limit !== undefined) qs.set("limit", String(limit));
  return request<DiscoverDumpsResult>(`/api/path/discover-dumps?${qs.toString()}`);
};

// MSL inspection
export const listBlocks = (mslPath: string) =>
  request<Array<{ category: string; blocks: Array<{ label: string; block_type: number; offset: number; size: number; detail: string }> }>>(
    `/api/inspect/blocks?msl_path=${encodeURIComponent(mslPath)}`,
  );

export const listModules = (mslPath: string) =>
  request<Array<{ path: string; base_addr: number; size: number; version: string }>>(
    `/api/inspect/modules?msl_path=${encodeURIComponent(mslPath)}`,
  );

// The keyed /api/inspect/* endpoints differ only by path segment + response
// type, so they share one helper (msl_path + optional key material as query).
const getKeyedInspect = <T>(endpoint: string, mslPath: string, key?: KeyMaterial) => {
  const qs = new URLSearchParams({ msl_path: mslPath });
  appendKey(qs, key);
  return request<T>(`/api/inspect/${endpoint}?${qs.toString()}`);
};

export const getPageStates = (mslPath: string, key?: KeyMaterial) =>
  getKeyedInspect<PageStatesResponse>("page-states", mslPath, key);

export const getSessionInfo = (mslPath: string, key?: KeyMaterial) =>
  getKeyedInspect<SessionInfoResponse>("session-info", mslPath, key);

export const getVasRegions = (mslPath: string, key?: KeyMaterial) =>
  getKeyedInspect<VasRegionsResponse>("vas", mslPath, key);

export const getImportProvenance = (mslPath: string, key?: KeyMaterial) =>
  getKeyedInspect<ImportProvenanceResponse>("import-provenance", mslPath, key);

export const getTagStatus = (mslPath: string) =>
  request<{ tag_status: TagStatus }>(
    `/api/inspect/tag-status?msl_path=${encodeURIComponent(mslPath)}`,
  );

export const probeTagStatusWithKey = (
  mslPath: string,
  secret: { passphrase?: string; key_hex?: string; kem_key_hex?: string },
) =>
  request<{ tag_status: TagStatus }>("/api/inspect/tag-status", {
    method: "POST",
    body: JSON.stringify({ msl_path: mslPath, ...secret }),
  });

// Structure inspection
export const autoDetectStructure = (
  dumpPath: string,
  offset: number,
  protocol?: string,
  view?: DumpViewMode,
) =>
  request<StructureMatchResult>(
    `/api/inspect/structure?dump_path=${encodeURIComponent(dumpPath)}&offset=${offset}${protocol ? `&protocol=${encodeURIComponent(protocol)}` : ""}${view ? `&view=${view}` : ""}`,
  );

// Analysis patterns
export const listPatterns = () =>
  request<{ patterns: import("./types").PatternInfo[] }>("/api/analysis/patterns");

export const applyStructure = (
  dumpPath: string,
  offset: number,
  structureName: string,
  key?: KeyMaterial,
  view?: DumpViewMode,
) => {
  const qs = new URLSearchParams({
    dump_path: dumpPath,
    offset: String(offset),
    structure_name: structureName,
  });
  // The view `offset` addresses; omitted = the dump's default byte source.
  if (view) qs.set("view", view);
  appendKey(qs, key);
  return request<StructureApplyResult>(`/api/inspect/structure-apply?${qs.toString()}`);
};

// Format detection
export interface FormatResult {
  format: string | null;
  detected_format?: string | null;
  forced?: boolean;
  suggested_formats?: FormatSuggestion[];
  available_formats?: string[];
  nav_tree: Record<string, unknown> | null;
  overlays: { structure_name: string; base_offset: number; fields: Array<{ field_name: string; offset: number; length: number; display: string; description: string; path: string; valid: boolean }> } | null;
}

export const detectFormat = (
  dumpPath: string,
  offset = 0,
  forceFormat?: string,
  key?: KeyMaterial,
) => {
  const qs = new URLSearchParams({
    dump_path: dumpPath,
    offset: String(offset),
  });
  if (forceFormat) qs.set("force_format", forceFormat);
  appendKey(qs, key);
  return request<FormatResult>(`/api/inspect/format?${qs.toString()}`);
};

// Architect
export interface CheckStaticResult { static_mask: boolean[]; reference_hex: string; static_ratio: number; anchors: Array<{ start: number; length: number }> }
export interface PatternGenResult { name: string; length: number; hex_pattern: string; wildcard_pattern: string; static_ratio: number; static_count: number; volatile_count: number }
export interface ExportResult { format: string; content: string }

export const checkStatic = (body: { dump_paths: string[]; offset: number; length: number } & KeyMaterial) =>
  request<CheckStaticResult>("/api/architect/check-static", { method: "POST", body: JSON.stringify(body) });

export const generatePattern = (body: { reference_hex: string; static_mask: boolean[]; name?: string }) =>
  request<PatternGenResult>("/api/architect/generate-pattern", { method: "POST", body: JSON.stringify(body) });

export const exportPattern = (body: { pattern: Record<string, unknown>; format: string }) =>
  request<ExportResult>("/api/architect/export", { method: "POST", body: JSON.stringify(body) });

// File uploads (multipart — bypass JSON Content-Type)
export async function uploadFile<T>(url: string, file: File): Promise<T> {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch(`${BASE}${url}`, { method: "POST", body: form });
  if (!res.ok) {
    // FastAPI serializes errors as {"detail": "..."}; surface that human
    // message rather than the raw JSON envelope. A non-JSON body (e.g. a proxy
    // error page) is kept verbatim.
    const body = await res.text();
    let msg = body;
    try {
      msg = (JSON.parse(body) as { detail?: string }).detail ?? body;
    } catch {
      // Non-JSON body — keep it verbatim.
    }
    throw new ApiError(res.status, msg);
  }
  return res.json() as Promise<T>;
}

export const importKsy = (file: File) =>
  uploadFile<{ name: string; filename: string; message: string }>("/api/structures/import-ksy", file);

/**
 * Metadata-only preview of what importing a SERVER-SIDE dump would emit:
 * per-region categories, per-category totals, and the included/excluded
 * summary for the optional `regions` / `excludeRegions` specs. Writes nothing.
 * A bad category name answers 422 with the valid names in the message.
 */
export const previewImport = (
  path: string,
  regions?: string,
  excludeRegions?: string,
  keyMaterial?: KeyMaterial,
  options?: PreviewImportOptions,
) =>
  request<ImportPreview>("/api/dumps/preview", {
    method: "POST",
    // Key material rides in the POST body only — never in the URL.
    body: JSON.stringify({
      path,
      ...(regions ? { regions } : {}),
      ...(excludeRegions ? { exclude_regions: excludeRegions } : {}),
      ...keyMaterialWire(keyMaterial),
      ...(options?.mapsPath ? { maps_path: options.mapsPath } : {}),
    }),
  });

/** Extra, optional inputs of {@link previewImport}. */
export interface PreviewImportOptions {
  /**
   * `/proc/<pid>/maps`-style memory map splitting a raw dump into regions.
   * Omitted = the server auto-detects a `.maps` sidecar next to the dump.
   */
  mapsPath?: string;
}


// Notebook
export const getNotebookStatus = () =>
  request<{ available: boolean; error: string | null }>("/api/notebook/status");

// Convergence
export const runConvergence = (body: {
  dump_paths: string[];
  n_values?: number[];
  normalize?: boolean;
  max_fp?: number;
} & KeyMaterial) =>
  request<ConvergenceSweepResult>("/api/analysis/convergence", {
    method: "POST",
    body: JSON.stringify(body),
  });

// Key verification
export const verifyKey = (body: {
  dump_path: string;
  offset: number;
  length?: number;
  ciphertext_hex: string;
  iv_hex?: string;
  nonce_hex?: string;
  aad_hex?: string;
  tag_hex?: string;
  cipher?: string;
  /** View `offset` addresses; omitted = the dump's default view. */
  view?: DumpViewMode;
} & KeyMaterial) =>
  request<VerifyKeyResult>("/api/analysis/verify-key", {
    method: "POST",
    body: JSON.stringify(body),
  });

// Auto export
export const autoExport = (body: {
  dump_paths: string[];
  format?: string;
  name?: string;
  align?: boolean;
  context?: number;
} & KeyMaterial) =>
  request<AutoExportResult>("/api/analysis/auto-export", {
    method: "POST",
    body: JSON.stringify(body),
  });

// Keylog export -- render recovered TLS secrets as a Wireshark NSS key log
export const exportKeylog = (body: ExportKeylogRequest) =>
  request<ExportKeylogResult>("/api/analysis/export-keylog", {
    method: "POST",
    body: JSON.stringify(body),
  });
