# Configuration and environment variables

MemDiver needs no configuration to run locally: every setting below has a safe
default, and the two directories that do not (`upload_dir` and `oracle_dir`) are
chosen from the web UI the first time they are needed. This page lists every
`MEMDIVER_*` environment variable the code reads, where it is read, and what it
changes.

## How the web backend reads settings

The FastAPI backend's settings live in one Pydantic `Settings` class
(`api/config.py`) with `env_prefix="MEMDIVER_"` and `env_file=".env"`. So every
field `foo` can be set as the environment variable `MEMDIVER_FOO`, or as a
`MEMDIVER_FOO=…` line in a `.env` file in the directory the server is started
from. A real environment variable beats the `.env` file. List-typed fields
(`cors_origins`) take a JSON array, e.g.
`MEMDIVER_CORS_ORIGINS='["http://localhost:5173"]'`.

Settings are read once, when the server starts (`get_settings()` is cached), so
changing a variable needs a restart. The exceptions are `upload_dir` and
`oracle_dir`, which the UI can also set while the server is running (see
[Directories chosen in the UI](#directories-chosen-in-the-ui)).

## Web backend (`memdiver web`)

| Variable | Default | Effect | Source |
|---|---|---|---|
| `MEMDIVER_HOST` | `127.0.0.1` | Interface `memdiver web` binds. A non-loopback host is refused unless `MEMDIVER_API_TOKEN` or `MEMDIVER_ALLOW_INSECURE` is set (see [Middleware](../architecture/api.md#middleware)). There is no `--host` flag. | `api/config.py`, `cli/dataset.py`, `api/security.py` |
| `MEMDIVER_PORT` | `8080` | Port `memdiver web` (and bare `memdiver`) binds when `--port` is not given. Precedence: `--port N` > `MEMDIVER_PORT` / `.env` > `8080`. The startup log line reports the port actually bound. | `api/config.py`, `cli/dataset.py`, `api/main.py` |
| `MEMDIVER_API_TOKEN` | unset | Opt-in token auth. When set, every `/api`, `/ws` and `/notebook` route needs `Authorization: Bearer <token>` or `X-API-Key: <token>` (WebSockets may also use `?token=<token>`). `/health`, `/docs`, `/redoc`, `/openapi.json` and the static frontend stay open. | `api/config.py`, `api/security.py` |
| `MEMDIVER_ALLOW_INSECURE` | `false` | Lets `memdiver web` bind a non-loopback host **without** a token; logs a loud warning. | `api/config.py`, `api/security.py` |
| `MEMDIVER_CORS_ORIGINS` | `["http://localhost:5173"]` | Allowed CORS origins (JSON array). A literal `"*"` is dropped; if nothing is left the default is used. The allowed methods are fixed at `GET`, `POST`, `PUT`, `DELETE` and `OPTIONS` (`PATCH` is refused). | `api/config.py`, `api/main.py` |
| `MEMDIVER_FRONTEND_PORT` | unset (`FRONTEND_PORT`, else `5173`) | Port of the Vite dev server whose origins (`http://localhost:<port>`, `http://127.0.0.1:<port>`) the cross-site guard trusts in addition to `MEMDIVER_CORS_ORIGINS`. Not needed when going through the Vite proxy (that is same-origin). See [Security model](#security-model). | `api/security.py` |
| `MEMDIVER_ALLOWED_HOSTS` | unset | Extra `Host` header names (comma-separated, no port) the API answers to, besides `127.0.0.1`, `localhost` and `::1`. Any other `Host` gets `421` — this defeats DNS rebinding. A non-loopback `MEMDIVER_HOST` that passed the bind guardrail is added automatically; set this when you reach the server by a different name (e.g. bound to `0.0.0.0`). `*` disables the check (not recommended). See [Security model](#security-model). | `api/config.py`, `api/security.py` |
| `MEMDIVER_ALLOWED_ROOTS` | unset (unrestricted) | **Opt-in read-path sandbox.** `os.pathsep`-separated directories (`:` on macOS/Linux, `;` on Windows). When set, every client-supplied read path must resolve (symlinks followed) inside one of them, the upload dir, the dataset root, `<memdiver home>`, a file-browser favourite, the server's startup working directory, or the system temp dir (`$TMPDIR`); anything else gets `403`. MCP tool arguments, MCP resources and saved sessions are checked too, and MCP output paths are then confined to `<memdiver home>` + the upload dir. The file browser's "up" stops at the boundary. See [Read sandbox](sandbox.md). | `api/config.py`, `api/path_policy.py`, `core/path_sandbox.py` |
| `MEMDIVER_WEB_GRACEFUL_TIMEOUT_S` | `10` | Seconds uvicorn may spend draining open connections on shutdown (`timeout_graceful_shutdown`). Without a bound, a parked progress WebSocket would make Ctrl-C hang. | `api/config.py`, `cli/dataset.py` |
| `MEMDIVER_DATASET_ROOT` | `""` | Dataset loaded into the tool session at startup. When unset, `dataset_root` is read from the file named by `MEMDIVER_CONFIG_PATH`. An unusable root is logged and ignored. | `api/config.py`, `api/main.py` |
| `MEMDIVER_CONFIG_PATH` | `config.json` (relative to the server's working directory) | The repo-level `config.json` that `dataset_root` falls back to. Not the user-local prefs file. | `api/config.py` |
| `MEMDIVER_SESSION_DIR` | `<memdiver home>/sessions` | Where `.memdiver` session snapshots are listed, saved, loaded and deleted. | `api/config.py`, `api/routers/sessions.py` |
| `MEMDIVER_UPLOAD_DIR` | unset (chosen in the UI) | Root for uploaded captures (`pcaps/`) and imported dumps (`imports/`), and the containment root for server-side writes. Pins the value and makes the UI control read-only. | `api/config.py`, `api/routers/settings.py` |
| `MEMDIVER_ORACLE_DIR` | unset (oracles disabled) | Directory BYO oracles are stored in and executed from. Pins the value; the UI can no longer change it. | `api/config.py`, `api/routers/oracles.py` |
| `MEMDIVER_TASK_ROOT` | `~/.memdiver/tasks` | Where pipeline task records (`<id>/record.json`) and artifacts are written. Note: built from `Path.home()`, so it does not follow `XDG_DATA_HOME`. | `api/config.py`, `api/main.py` |
| `MEMDIVER_TASK_QUOTA_BYTES` | `5368709120` (5 GiB) | Aggregate size cap for the task artifact store. | `api/config.py`, `api/main.py` |
| `MEMDIVER_PIPELINE_MAX_WORKERS` | `2` | Worker processes in the pipeline task manager's process pool. | `api/config.py`, `api/main.py` |
| `MEMDIVER_PCAP_QUOTA_BYTES` | `5368709120` (5 GiB) | Aggregate cap for `upload_dir/pcaps`; oldest captures are pruned first. `<= 0` disables pruning. | `api/config.py`, `api/routers/pcaps.py` |
| `MEMDIVER_DUMP_QUOTA_BYTES` | `5368709120` (5 GiB) | Aggregate cap for imported dumps (`upload_dir/imports`, or `<memdiver home>/imports` when no upload dir is chosen). `<= 0` disables pruning. | `api/config.py`, `api/routers/dumps.py` |
| `MEMDIVER_FRONTEND_DIST` | `<package>/frontend/dist` | Directory the prebuilt React bundle is served from, for packaged or relocated installs. Read directly from the environment (not via `.env`). | `api/frontend_build.py` |

`Settings` also declares `max_workers` (default `min(4, cpu_count - 1)`, at least
1) and `db_path` (`<memdiver home>/project.duckdb`), so `MEMDIVER_MAX_WORKERS` and
`MEMDIVER_DB_PATH` are accepted, but no code currently reads those two fields.
Setting them has no effect.

### Analysis memory budget

`max_rss_mb` (`MEMDIVER_MAX_RSS_MB`, default `0` = no cap) is an **upper cap** on the
analysis memory budget computed by `core/memory_budget.py`. The budget is

    budget = min(available_memory × 0.7, max_rss_mb, MEMDIVER_MEMORY_BUDGET_MB)

where the smallest configured cap wins and an unset or non-positive cap is
ignored. Available memory is measured with `psutil` when it is installed
(optional, not a dependency), otherwise `/proc/meminfo` `MemAvailable` on Linux
(lowered to the cgroup v2 `memory.max` headroom inside containers),
`vm_stat` free + inactive + speculative + purgeable pages on macOS, and as a last
resort total physical RAM (reported as source `total`, which overestimates what
is free). Operations whose estimated peak exceeds the budget are refused with a
message giving the estimate, the budget and how it was measured (error code
`memory_budget_exceeded`). Every interface has an explicit override that proceeds
anyway (a warning is logged):

| Interface | Override | Refusal surfaces as |
|---|---|---|
| CLI | `--force-memory` on `consensus`, `consensus-window`, `consensus-regions`, `analyze-candidates`, `analyze`, `batch`, `experiment`, `export --auto` | message + "Re-run with --force-memory", non-zero exit |
| MCP | `force_memory=true` on every tool that builds a consensus | tool error with code `memory_budget_exceeded`, `estimate_bytes`, `budget_bytes` |
| REST | `"force_memory": true` in the request body (consensus, aligned-window, regions, candidates, analysis/pipeline runs); `/api/consensus/begin` keeps `force` | HTTP 507 `{code, message, estimate_bytes, budget_bytes, ...}` |
| Web UI | "Run anyway" in the memory-budget dialog (re-sends with `force_memory: true`) | dialog with estimate vs budget |
| Python | `force=True` on the app/engine builders | `CapabilityError` (PRECONDITION) |

Prefer narrowing the work first (a region filter such as `heap,stack`, fewer dumps)
over forcing it.

| Variable | Default | Effect | Source |
|---|---|---|---|
| `MEMDIVER_MAX_RSS_MB` | `0` (no cap) | Upper cap (MiB) on the analysis memory budget, read through `Settings` and passed in by the caller. | `api/config.py`, `core/memory_budget.py` |
| `MEMDIVER_MEMORY_BUDGET_MB` | unset | Upper cap (MiB) on the analysis memory budget, read directly from the environment (applies to the CLI and library too, not via `.env`). Combined with `max_rss_mb` by taking the smaller. | `core/memory_budget.py` |

## Security model

`memdiver web` is a local single-user workbench. Its defences are layered:

1. **Network.** Binds `127.0.0.1` by default. A non-loopback `MEMDIVER_HOST`
   is refused unless `MEMDIVER_API_TOKEN` (or the loud
   `MEMDIVER_ALLOW_INSECURE`) is set.
2. **Browser — always on.** A loopback bind does not stop *web pages* you visit
   from sending requests to `127.0.0.1`. So:
   - **Host allow-list** (`HostAllowListMiddleware`): any `Host` header other
     than loopback / `MEMDIVER_ALLOWED_HOSTS` is refused with `421`, for HTTP
     and WebSocket alike. This blocks DNS-rebinding attacks.
   - **Cross-site guard** (`CrossSiteRequestGuard`): every state-changing
     request (`POST`/`PUT`/`PATCH`/`DELETE`) and every WebSocket handshake is
     refused with `403` when `Sec-Fetch-Site: cross-site` is sent, or when its
     `Origin` is neither the server's own origin nor listed in
     `MEMDIVER_CORS_ORIGINS` (`Origin: null` is always refused). Requests
     without an `Origin` (curl, scripts, the CLI) are not browser-originated
     and pass.
   - **JSON bodies only**: a state-changing request whose body has no
     `Content-Type`, or `text/plain` / `application/x-www-form-urlencoded`
     (the types a cross-site form can send without a CORS preflight), is
     refused with `415`. `multipart/form-data` uploads are allowed and rely on
     the `Origin` / `Sec-Fetch-Site` checks. The Marimo mount (`/notebook`)
     is exempt from this one rule, not from the origin checks.
   - **Trusted origins** are exactly: the request's own origin (`Origin`
     scheme-less `host:port` equal to the `Host` header), the
     `MEMDIVER_CORS_ORIGINS` list, and the Vite dev server as both
     `http://localhost:<port>` and `http://127.0.0.1:<port>`, where `<port>`
     is `MEMDIVER_FRONTEND_PORT`, else `FRONTEND_PORT`, else `5173`. A
     loopback `Origin` on any **other** port is refused like a foreign site,
     so another local web service (a notebook, a second dev server rendering
     untrusted content) cannot drive MemDiver. The Vite dev proxy
     (`frontend/vite.config.ts`) runs with `changeOrigin: false`, so `Host`
     stays the dev server's and proxied requests are plain same-origin, on
     whatever `--port` Vite got. If you serve the frontend from some other
     origin that talks to the API directly, add it to `MEMDIVER_CORS_ORIGINS`.
3. **Auth — opt-in.** `MEMDIVER_API_TOKEN`.
4. **Writes — always contained.** A client-supplied write location
   (`output_dir` on `/api/dumps/import-path` and `/api/analysis/key-pattern`,
   `output_path` on `/api/analysis/export-keylog`) must resolve inside the
   upload directory, and client-supplied file names (pattern `name`, `.ksy`
   `meta.id`, session names) must be bare names. The CLI and MCP tools are
   not restricted this way — they write wherever your shell can.
5. **Reads — opt-in.** Read paths (dump paths, the file browser, dataset roots)
   are unrestricted by default because pointing MemDiver at any local dump is
   its core job. Set `MEMDIVER_ALLOWED_ROOTS` to sandbox them. The policy is
   enforced once per router (`api/path_policy.enforce_request_read_paths`) on
   the well-known path fields of the query string and JSON body.

Changing the upload directory or favourites (`/api/settings/*`) widens what is
writable/readable, so those endpoints are covered by the cross-site guard like
every other mutation.

## Engine and other entry points

These are read directly with `os.environ` (not through `Settings`), so a `.env`
file does not apply to them.

| Variable | Default | Effect | Source |
|---|---|---|---|
| `MEMDIVER_ORACLE_SANDBOX_TIMEOUT` | `10.0` s | Wall-clock limit for the subprocess that replays an oracle's `import` + `build_oracle(config)` before it is loaded in-process. | `engine/oracle.py` |
| `MEMDIVER_ORACLE_SANDBOX_CPU` | `10` s | `RLIMIT_CPU` for that probe subprocess (Unix, best effort). | `engine/oracle.py` |
| `MEMDIVER_ORACLE_SANDBOX_MEM` | `2147483648` (2 GiB) | `RLIMIT_AS` for that probe subprocess (Unix, best effort). | `engine/oracle.py` |
| `MEMDIVER_VOL3_BIN` | unset | Explicit `vol` / `vol.py` launcher used to run emitted Volatility 3 plugins. Checked before `vol` and `vol.py` on `PATH`. A `vol_bin` parameter on a request beats it. | `engine/vol3_subproc.py` |
| `MEMDIVER_VOL3_PYTHON` | unset | Interpreter that runs a `vol.py` script (the checkout's own venv). Unset means MemDiver's own interpreter, with a warning. A `vol_python` parameter beats it. | `engine/vol3_subproc.py` |
| `MEMDIVER_MCP_RESULT_BUDGET` | unset (off) | Opt-in cap in bytes (min 1024) on each MCP tool result; larger results are truncated with a `_result_budget` marker. See [](mcp_reference.md). | `mcp_server/result_budget.py` |
| `MEMDIVER_AGENT_BACKEND` | `sdk` | Backend of the in-UI agent chat: `sdk` (real model of the selected provider, needs `memdiver[agent]` and server-side credentials), `scripted` (no model, demo/test, through the Claude runtime) or `scripted-compat` (no model, demo/test, through the OpenAI-compatible loop; needs neither the SDK nor `openai`). See [](agent_chat.md). | `api/services/agent_chat.py` |
| `MEMDIVER_AGENT_SCRIPT` | unset | Script JSON (`{"turns": [[step, ...], ...]}`) played by the `scripted` and `scripted-compat` agent backends; required for them. | `api/services/agent_chat.py` |
| `OPENAI_API_KEY` | unset | API key of the agent chat's `openai` provider; the provider is unavailable without it. Never sent to the browser or the MCP child. | `app/agent_chat/providers.py` |
| `DEEPSEEK_API_KEY` | unset | API key of the agent chat's `deepseek` provider; the provider is unavailable without it. Never sent to the browser or the MCP child. | `app/agent_chat/providers.py` |
| `VLLM_API_KEY` | unset | Optional API key for the agent chat's `vllm` provider (`http://127.0.0.1:8000/v1`), when the vLLM server was started with `--api-key`. | `app/agent_chat/providers.py` |
| `MEMDIVER_AGENT_OPENAI_BASE_URL` | unset | Base URL of the agent chat's `custom` OpenAI-compatible provider (e.g. `http://gpu-box:8000/v1`); the provider is only offered when this is set. Server-side only: the browser can never set a URL, because the server attaches the API key to it. | `app/agent_chat/providers.py` |
| `MEMDIVER_AGENT_OPENAI_API_KEY` | unset | Optional API key sent to `MEMDIVER_AGENT_OPENAI_BASE_URL`. | `app/agent_chat/providers.py` |
| `MEMDIVER_DATASET_ROOT` | unset | Also read by the Marimo notebook app (`run.py`) to preselect a dataset. | `run.py` |
| `MEMDIVER_LANG` | `en` | Locale of the Marimo UI strings (`ui/locales/<lang>.json`); anything after a `.` is dropped (`de.UTF-8` → `de`). Unknown locales fall back to `en`. Does not affect the React web UI. | `ui/locales.py` |

Other variables that matter:

- **`XDG_DATA_HOME`** — when set, the MemDiver home directory is
  `$XDG_DATA_HOME/memdiver` instead of `~/.memdiver` (`core/constants.py:memdiver_home`).
  This is where the user-local prefs file, sessions, the project DB and the
  default oracle directory live.
- **`OLLAMA_CONTEXT_LENGTH`** — not read by MemDiver, but set it on the **Ollama
  server** (e.g. `32768`) when the agent chat uses the `ollama` provider: the
  OpenAI-compatible API cannot raise the context window per request, and a too-small
  window makes MemDiver refuse the request with `agent.context_truncated`
  before sending it. vLLM likewise needs
  `--enable-auto-tool-choice --tool-call-parser <parser>`. See [](agent_chat.md).
- **`MEMDIVER_FIXTURE_ROOT`** — read only by developer scripts under `scripts/`
  (`ground-truth-run0001.py`, `precompute_pipeline_fixtures.py`) to find a local
  dataset. The app never reads it.

`MEMDIVER_PID=`, `MEMDIVER_KEY=`, `MEMDIVER_IV=` and `MEMDIVER_READY=` are not
environment variables: they are lines a target process prints on stdout for the
experiment dump driver (`core/dump_driver.py`), see
[](../quickstart/experiment.md).

## Directories chosen in the UI

`upload_dir` and `oracle_dir` have no silent default. Both resolve by the same
precedence (`api/config.py`):

1. `MEMDIVER_UPLOAD_DIR` / `MEMDIVER_ORACLE_DIR` from the environment or `.env`;
2. otherwise the value saved in the user-local prefs file
   `<memdiver home>/config.json` (`api/user_prefs.py`) — never the git-tracked
   repo `config.json`;
3. otherwise unconfigured (`None`).

An **empty** value (`MEMDIVER_ORACLE_DIR=""`) would otherwise parse as the
server's working directory; it is treated as unset and logged as a warning.

When the variable is set in the environment or in `.env`, the setting is
**pinned**: the save endpoints refuse with **409** (`… is pinned by
MEMDIVER_…; unset it to configure the directory from the UI`), because a value
saved to the prefs file would be shadowed by the variable forever. The status
endpoints report this as `env_pinned: true`.

| | Upload directory | Oracle directory |
|---|---|---|
| Status | `GET /api/settings/upload-dir` | `GET /api/oracles/status` |
| Save | `POST /api/settings/upload-dir` | `POST /api/oracles/enable` (body `{"path": …}` optional) |
| If unset | uploads answer **409** `upload_dir_unconfigured` | oracle upload, example-load and `DELETE /api/oracles/orphans` answer **503** |
| Default offered | none — the user picks | `<memdiver home>/oracles` |

`GET /api/oracles/status` always answers 200 with `enabled`, `path`, `source`
(`"env"`, `"user_config"` or `null`), `env_pinned`, `default_path` and
`orphans` (oracle files with no metadata; `DELETE /api/oracles/orphans` removes
them). Enabling the oracle directory validates the path, creates it with mode
`0o700`, writes the prefs file and points the running registry at it — no
restart needed. See [](../oracle/interface.md#running-oracles-from-the-web-ui).

## Shutdown and child processes

`memdiver web` runs uvicorn with `timeout_graceful_shutdown =
MEMDIVER_WEB_GRACEFUL_TIMEOUT_S`. On a normal shutdown the app's lifespan closes
the task manager (an in-flight run still publishes its terminal event), resets
the oracle registry and closes cached dump readers. A second Ctrl-C makes uvicorn
skip the lifespan shutdown; `memdiver web` then tears the task manager down
itself so its process pool and `multiprocessing` manager child do not outlive the
server (`cli/dataset.py:_teardown_task_manager`).

If the server is killed outright (`SIGKILL`), those children notice that their
parent is gone and exit on their own: `core/process_guard.py` installs a
watchdog thread in the pool workers and the manager child that polls the parent
PID every 5 seconds. On the next start, task records left in `PENDING` or
`RUNNING` are marked `FAILED` (`api/services/task_manager.py`).
