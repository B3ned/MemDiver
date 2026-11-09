# api/

FastAPI backend. Serves the built React bundle at `/` and the Marimo notebook at `/notebook` (when installed). All routers mounted under `/api/*`, plus a WebSocket at `/ws/tasks/{task_id}`.

## Routers

| Prefix | Responsibility |
|---|---|
| `/api/dataset` | Scan, list protocols, list phases. |
| `/api/analysis` | Run, consensus, verify-key, auto-export. |
| `/api/inspect` | Hex, entropy, strings, structure overlay, VAS, module / process / connection / handle tables. |
| `/api/heap` | Heap allocator analysis: allocator detection (`/detect`), whole-heap overview (`/summary`), paged/filtered chunk table (`/chunks`), chunk containing a VA or offset (`/chunk-at`), walked free lists (`/free-lists`), byte-role runs of a view window (`/roles`). Errors use the global `{error, code, category}` contract. |
| `/api/sessions` | `.memdiver` session CRUD. |
| `/api/tasks` | Background-task status + cancellation. |
| `/api/dumps` | Multipart upload → MSL convert. |
| `/api/pcaps` | Packet-capture upload (`upload_dir/pcaps/`, 512 MiB cap), `validate` (arm) and `locate-field`. See [](../oracle/pcap_oracle.md). |
| `/api/path` | File-browser — detects single-file / run-dir / dataset mode. |
| `/api/structures` | Structure library + Kaitai import/export. |
| `/api/architect` | Static check, pattern generate, export (YARA / JSON / Vol3). |
| `/api/consensus` | Incremental Welford consensus sessions. |
| `/api/algorithms` | `GET /availability` — which algorithms can run, and why not. |
| `/api/oracles` | BYO-oracle registry: bundled examples (`GET /examples`, `POST /examples/{filename}/load`, `POST /examples/{filename}/suggest-config`), upload / arm / delete, `dry-run` and `smoke-test`, and the oracle-directory switch (`GET /status`, `POST /enable`, `DELETE /orphans`). Upload, example-load and `DELETE /orphans` answer 503 until an oracle directory is enabled — from the UI or pinned by `MEMDIVER_ORACLE_DIR`; see [Directories chosen in the UI](../user_guide/configuration.md#directories-chosen-in-the-ui). |
| `/api/pipeline` | Phase-25 pipeline orchestration. `POST /run` with `scudo: {"allocator": "auto" \| "scudo"}` runs the Android Scudo method instead of the positional consensus: the first source is the reference and the run ends at brute-force. Combined with `emit` it answers 400 `scudo.plugin_unsupported`; combined with `nsweep`, `escalate`, a region filter or `reduce` thresholds, 400 `scudo.unsupported_option`. |
| `/api/experiment` | SPA experiment runner — spawn target, dump, analyze per tool, verify, emit Volatility3 plugins. |
| `/api/scan` | Run an emitted YARA rule over dumps (`/yara`), score its firings against known key intervals (`/score`), and run an emitted Volatility3 plugin (`/verify-plugin`). |
| `/api/settings` | User-chosen server settings persisted in `<memdiver home>/config.json`: `upload-dir` (GET/POST), file-browser `favourites` (GET/POST/DELETE) and `last-dir` (GET/PUT). |
| `/api/docs` | Serves the repo's `docs/*.md` to the SPA's in-app help links. |
| `/ws/tasks/{id}` | WebSocket progress stream (ring buffer + HTTP fallback). |
| `/api/tasks/{id}/events` | HTTP backfill endpoint registered by the same WS router; returns buffered events when the WebSocket ring has rolled past a client's last-seen sequence. |
| `/api/notebook/status` | Top-level status probe reporting whether the Marimo notebook mount at `/notebook` is available. |

## Progress bus

Background tasks run in a shared `ProcessPoolExecutor` with an `asyncio.Semaphore(1)` gating outer runs. Progress events (`stage_start`, `progress`, `stage_end`, `funnel`, `nsweep_point`, `oracle_tick`, `oracle_hit`, `artifact`, `done`, `error`) flow through a `ProgressBus` with per-task 512-event ring buffers.

## Memory-budget guard

Consensus-building routes estimate their peak memory and refuse when it exceeds the budget (`MEMDIVER_MEMORY_BUDGET_MB`, see [](../user_guide/configuration.md)). The refusal is a `CapabilityError` with `code: "memory_budget_exceeded"`, which the global handler in `api/main.py` maps to **HTTP 507** with a flat body (`api/memory_budget_errors.py`):

```json
{"error": "...", "code": "memory_budget_exceeded", "category": "PRECONDITION",
 "message": "...", "estimate_bytes": 123, "budget_bytes": 45, "details": {"operation": "...", "breakdown": {}, "source": "..."}}
```

Routes that translate other `CapabilityError`s to `{"detail"}` locally re-raise this one so it always stays a 507. To run anyway, re-send the same request with `force_memory: true` (the `MemoryOverrideFields` mixin). It is accepted by `/api/analysis/consensus`, `/consensus/aligned-window`, `/consensus/regions`, `/candidates`, `/auto-export`, `/run`, `/api/pipeline/run`, `/api/experiment/run` and `/api/consensus/begin`, where `force` remains an alias. Background tasks get `force_memory` in their params. A task that fails on the guard records `error` (the message) plus `error_info: {code, estimate_bytes, budget_bytes, details}` on its task record, and its terminal `error` event carries the same dict as `extra`.

## Persistence

Task records are atomically persisted to `<task_root>/<id>/record.json`; orphan `PENDING` / `RUNNING` records are reset to `FAILED` on app restart.

Uploaded oracles are persisted as `<oracle_dir>/<uuid>.py` plus a `<uuid>.json` metadata sidecar, and are restored on restart (re-hashed against the stored sha256, and always restored **unarmed**). `.py` files without a sidecar are reported as `orphans` by `GET /api/oracles/status` and removed only on request (`DELETE /api/oracles/orphans`).

## Shutdown

`memdiver web` bounds uvicorn's graceful shutdown with `MEMDIVER_WEB_GRACEFUL_TIMEOUT_S` (default 10 s); the lifespan then closes the task manager, the oracle registry and the cached dump readers. The task manager's process-pool workers and `multiprocessing` manager child run a parent-death watchdog (`core/process_guard.py`), so they exit even if the server is killed with `SIGKILL`. Details: [Shutdown and child processes](../user_guide/configuration.md#shutdown-and-child-processes).

## Middleware

- **CORS** — `CORSMiddleware` with `allow_origins=settings.cors_origins` (default `["http://localhost:5173"]`; a literal `"*"` is dropped), credentials allowed, methods `GET`/`POST`/`PUT`/`DELETE`/`OPTIONS` (`PUT` is used by `PUT /api/settings/last-dir`; `PATCH` is not allowed), headers `Content-Type`/`Authorization`/`X-API-Key`.
- **GZip** — `GZipMiddleware` with `minimum_size=1000`.
- **Host allow-list** — `HostAllowListMiddleware` (pure ASGI, HTTP + WebSocket, always on) refuses any `Host` that is not `127.0.0.1`/`localhost`/`::1` (any port), `MEMDIVER_ALLOWED_HOSTS`, or a guarded non-loopback bind host, with `421` (DNS-rebinding defence).
- **Cross-site guard** — `CrossSiteRequestGuard` (pure ASGI, always on) refuses non-safe requests and WebSocket handshakes with `Sec-Fetch-Site: cross-site` or an `Origin` that is not same-origin with `Host`, not in `cors_origins` and not the Vite dev origin (`localhost`/`127.0.0.1` on `MEMDIVER_FRONTEND_PORT` / `FRONTEND_PORT` / `5173`) — loopback origins on other ports are refused (`403`), and non-empty bodies typed `text/plain`/form-urlencoded/missing (`415`). Both run outermost. See [Security model](../user_guide/configuration.md#security-model).
- **Read-path sandbox** — opt-in (`MEMDIVER_ALLOWED_ROOTS`); a router-level dependency (`api/path_policy.enforce_request_read_paths`) on every router taking read paths.
- **Token auth** — `ApiTokenAuthMiddleware` is a no-op unless `MEMDIVER_API_TOKEN` is set; then every `/api`, `/ws` and `/notebook` route requires the token (`Authorization: Bearer …` or `X-API-Key: …`; WebSockets may pass `?token=…`). `/health`, `/docs`, `/redoc`, `/openapi.json` and the static bundle stay open. `memdiver web` refuses a non-loopback `MEMDIVER_HOST` without a token unless `MEMDIVER_ALLOW_INSECURE` is set (`api/security.py`).

## Configuration

All settings come from `api/config.py` (`MEMDIVER_*` environment variables or `.env`). The full list, with defaults and effects, is in [](../user_guide/configuration.md).

## OpenAPI

`/docs` (Swagger), `/redoc` (ReDoc), `/openapi.json`.
