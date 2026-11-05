# Agent chat panel

The agent chat panel is a chat column in the web workspace where you ask Claude (or another model, see [Using other models](#using-other-models-openai-deepseek-ollama-vllm)) questions about the open case and dumps. The model works through MemDiver's own MCP tools (the same ones an external agent gets, see [](mcp_reference.md)); the panel is a **client of the MCP server**, not a new analysis surface. It uses the Claude Agent SDK, but removes every built-in tool: the model has **no shell, no file and no web tools**, only `mcp__memdiver__*` tools.

The panel is an optional extra and is off until the SDK is installed and credentials are configured on the server.

## Install

```bash
pip install "memdiver[agent]"
```

The extra installs `claude-agent-sdk`, which bundles the Claude Code runtime it drives, and the `openai` package used for [other models](#using-other-models-openai-deepseek-ollama-vllm). No Node.js is needed. If the SDK is missing the panel shows an install hint; if the bundled runtime is missing, reinstall with `pip install --force-reinstall "memdiver[agent]"`.

## Credentials

Credentials are read from the **server environment only**, never from the browser and never stored by MemDiver. Set one of these before starting `memdiver web`, then restart:

- `ANTHROPIC_API_KEY` (or `ANTHROPIC_AUTH_TOKEN`)
- `CLAUDE_CODE_USE_BEDROCK=1`, `CLAUDE_CODE_USE_VERTEX=1` or `CLAUDE_CODE_USE_FOUNDRY=1`, plus that platform's own environment

Signing in with a claude.ai account is not supported: third-party applications may not offer it. `GET /api/agent/status` reports `{available, backend, credentials}` and never any secret value.

## Security model

- **Read tools run automatically; write tools need your approval.** The READ/WRITE split is derived from each tool's parameters (`mcp_server/tool_policy.py`): a tool with a write-path parameter, a case parameter (outside the read-only case tools) or a parameter that executes, compiles or loads caller-supplied code or rules, or picks an executable (`CODE_EXEC_KEYS`: `source`, `plugin_path`, `plugin_source`, `oracle_path`, `source_name`, `vol_bin`, `vol_python`, `rule_source`, `rule_paths`, `rules`) is WRITE. A few tools without such a parameter are listed explicitly with a reason (`image_profile` runs pakunoda and writes the ISF cache; `analyze_candidates` writes the project database). `set_region_filter` stays READ: it only changes in-memory session state. A tool the policy does not know is treated as WRITE. Currently 65 tools are READ and 55 are WRITE (including `capture_dump`, which is never offered).
- **Approval scopes.** An approval card shows the full tool input and offers **Allow once**, **Allow for this chat** (that tool, until the chat ends) and **Deny**, with an optional note to the model. "Allow for this chat" is keyed by tool name only, so it is offered **only for WRITE tools that do not run caller-supplied code**. Tools with a `CODE_EXEC_KEYS` parameter (`verify_vol3_plugin`, `vol3_run`, `brute_force`, `scan_yara_rule`, ...) are once-only: the card has no chat button, the server sends `scopes: ["once"]`, and a chat-scoped answer is treated as once, so every call with new code or a new binary prompts again. Unanswered approvals are denied when the chat closes.
- With the optional result budget (`MEMDIVER_MCP_RESULT_BUDGET`), an oversized structured error keeps its `error` and `code` but has its long strings truncated and carries `_result_budget`; small errors are unchanged.
- **`capture_dump` is never available** to the chat, even with approval. Start captures from the Capture UI.
- The model runs with `permission_mode="default"`, no project or user Claude settings, and its own config directory under the MemDiver home.
- The MCP child is started **sandboxed**. Its read roots are `MEMDIVER_ALLOWED_ROOTS` if you set it, otherwise the MemDiver home, the upload directory, the chat's case directory and the parent directory of each dump passed to the chat. Writes stay confined to the MemDiver home and the upload directory (see [](sandbox.md)).
- **Credentials are not passed to the MCP child**: `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `MEMDIVER_API_TOKEN` and the provider keys (`OPENAI_API_KEY`, `DEEPSEEK_API_KEY`, `VLLM_API_KEY`, `MEMDIVER_AGENT_OPENAI_API_KEY`) are removed from its environment.
- The chat **refuses to run on a non-loopback bind without `MEMDIVER_API_TOKEN`**. `MEMDIVER_ALLOW_INSECURE=1` does not lift this rule. With a token set, the WebSocket needs `?token=` as `/ws/tasks` does.
- **Prompt injection:** tool results and dump contents are attacker-controllable data (strings in memory, process names, ISF text). The system prompt tells the model to treat them as data, never instructions, and write tools always need your click. Read every approval card before allowing.

## Settings

Stored server-side per user (`GET`/`PUT /api/agent/settings`). Defaults are deliberately low; raise them in the panel's Settings form. Out-of-range values are rejected (422).

| Setting | Default | Allowed |
|---|---|---|
| Provider | `anthropic` | `anthropic`, `openai`, `deepseek`, `ollama`, `vllm`, `custom` (see below) |
| Model | `claude-opus-5-5` | Anthropic: `claude-opus-5-5`, `claude-sonnet-5-5`, `claude-haiku-5-5`; other providers: any model name (letters, digits, `._:/@-`, up to 128 characters) |
| Effort | `low` | `low`, `medium`, `high` |
| Max turns | 8 | 1 to 200 |
| Max budget (USD) | 0.50 | 0.05 to 50 |
| Result budget (bytes) | 20000 | 2000 to 500000 |

Max budget is an **SDK-side estimate** and can overshoot; the meter labels cost as estimated. The result budget is passed to the MCP child as `MEMDIVER_MCP_RESULT_BUDGET`: a tool result above it is shrunk (lists keep their first items with `<key>__truncated: {kept, total}`, the largest values become `{"omitted_bytes": n}`, text is cut with a marker line) and always carries a top-level `_result_budget` object. The tool-call card shows a `truncated` badge, and the model is told to narrow the call (`limit`/`offset`, `detail="summary"`, `case_query`) instead of repeating it. See [](mcp_reference.md).

## Evidence labels

The system prompt requires every factual claim to be tagged `[seen]` (cite the tool and the offset, row or run id), `[inferred]` (state the reasoning) or `[unknown]`. "Not found" means unknown, never absent, and uncaptured bytes are absent, not zero. The panel highlights the tags. The point is to keep model claims separable from tool evidence in a forensic context.

The prompt's output and budget rules are adapted from ideas in [leanrea](https://github.com/aicodeking/leanrea): capped outputs with expansion handles, evidence labels, a call budget, and cheap recon first (`case_manifest`, `case_schema`, then `case_query`) before expensive tools.

## Using the panel

- **Start chat** opens a chat bound to the open case and dumps; **End chat** closes it. Enter sends, Shift+Enter adds a line, **Interrupt** stops the running turn.
- **Start from playbook** lists the MCP playbooks, fills in their arguments and puts the rendered text in the composer. The chosen playbook text travels in the first user message, not the system prompt.
- Tool calls appear as collapsible cards labelled read or write. Results that name a dump plus a `va` or `offset` get an **Open in hex** link (up to 10 per result); it works only for dumps open in the workspace.

## Using other models (OpenAI, DeepSeek, Ollama, vLLM)

Besides Claude, the panel can drive any model that speaks the OpenAI-compatible **Chat Completions** API with tool calling. The panel, the approval cards, the sandbox and the evidence rules are the same; only the model changes. MemDiver runs the tool loop itself for these providers.

### Install and credentials

`pip install "memdiver[agent]"` already includes the `openai` package. Keys, like the Anthropic one, come from the **server environment only**; set them before starting `memdiver web`:

| Provider | Endpoint | Server variable | Default model |
|---|---|---|---|
| `openai` | `https://api.openai.com/v1` | `OPENAI_API_KEY` (required) | `gpt-5-mini` |
| `deepseek` | `https://api.deepseek.com` | `DEEPSEEK_API_KEY` (required) | `deepseek-flash` |
| `ollama` | `http://127.0.0.1:11434/v1` | none | `llama3.3` |
| `vllm` | `http://127.0.0.1:8000/v1` | `VLLM_API_KEY` (only if your server uses `--api-key`) | none: enter the served model name |
| `custom` | `MEMDIVER_AGENT_OPENAI_BASE_URL` | `MEMDIVER_AGENT_OPENAI_API_KEY` (optional) | none |

The endpoints are fixed. You cannot type a URL in the browser: the server sends your API key to that URL, so it may only come from the server's own configuration. To use any other OpenAI-compatible server (another port, a LiteLLM proxy, a remote vLLM), set `MEMDIVER_AGENT_OPENAI_BASE_URL` (for example `http://gpu-box:8000/v1`) and pick **custom**. The custom provider is only offered when that variable is set.

```bash
export DEEPSEEK_API_KEY=sk-...
memdiver web
```

### Picking the provider

In the panel's **Settings**, choose the **Provider**. Providers that are not configured are greyed out and show why (for example "set OPENAI_API_KEY on the server to enable openai"). Changing the provider resets the model to that provider's default and clears the tool set and price fields. Then:

- **Model**: type a model name, or press **Load models** to ask the provider which models it serves (the request runs on the server; neither the key nor the URL reaches the browser) and pick one from the suggestions.
- **Effort** is only used by OpenAI; for other providers it is disabled.
- **Tool set** (see below) and **input/output price** (USD per 1M tokens; empty uses the provider default) appear for these providers.

Save, then start a new chat: a running chat keeps the settings it was started with.

### Tool sets

MemDiver has about 120 MCP tools, and their descriptions are sent with **every** request. That fits large hosted models, but it can fill a small local model's context window on its own:

| Tool set | What the model gets | Approximate size |
|---|---|---|
| `full` | every tool, full descriptions | ~34K tokens |
| `compact` | every tool, one-sentence descriptions | ~16K tokens |
| `minimal` | 16 read-only recon tools (`case_manifest`, `case_schema`, `case_query`, `read_hex`, `search_bytes`, `vas_regions`, ...) | ~1.6K tokens |

Ollama and vLLM default to `minimal`; OpenAI, DeepSeek and custom default to `full`. With `minimal` the model cannot call write tools at all. For a local model, start with `minimal` and move to `compact` only if the model has a large context window and handles many tools well.

Tool calls are only executed when the model returns them as structured tool calls. A model that writes a tool call as plain text in its answer gets nothing executed: MemDiver does not parse tool calls out of text, because text is where injected content from a dump would end up. Use models with native tool calling.

### Ollama

Ollama's default context window is small, and Ollama **cuts the prompt silently** when it is exceeded. The OpenAI-compatible API cannot raise it per request, so set it on the Ollama server:

```bash
OLLAMA_CONTEXT_LENGTH=32768 ollama serve
```

or create a model variant with `PARAMETER num_ctx 32768` in its Modelfile. Before each request MemDiver reads the loaded model's context window from Ollama (`GET /api/ps`) and, if the estimated request (plus room for the reply) does not fit, stops with `agent.context_truncated` instead of letting Ollama silently cut the conversation. If the model is not loaded yet or the server does not answer, the request goes out unchecked. Pick a model with tool support (`ollama pull <model>`, then **Load models**).

### vLLM

Start vLLM with tool calling enabled and the parser that matches your model, for example:

```bash
vllm serve <model> --enable-auto-tool-choice --tool-call-parser <parser>
```

(`hermes`, `llama3_json`, `mistral`, ... see the vLLM docs). Without these flags the model's tool calls arrive as text and are not executed. Enter the served model name in **Model** (or use **Load models**).

### DeepSeek

DeepSeek's thinking mode is on by default. Its reasoning is kept and sent back to DeepSeek with every later request, as its API requires when tools are used; you do not need to configure anything. The reasoning is not shown in the panel.

### Cost and limits

Max turns and Max budget apply **per message you send**, as with Claude; each model call counts as one turn. The cost is estimated from the token counts the provider reports and the configured prices. It ignores cached-input discounts, so it overestimates. For Ollama and vLLM (and providers with no price set) the meter shows **cost n/a (local model)** and the budget limit does not apply; use Max turns to bound a run.

### Current limits

- **Interrupt** stops the conversation, but a tool that is already running keeps running in the MCP server until it finishes; its result is discarded. Ending the chat stops it.
- A conversation that outgrows the model's context window is not compacted: it fails with `agent.context_overflow`. Start a new chat or use a smaller tool set.
- Only the Chat Completions API is supported. Newer OpenAI flagship models (GPT-6.x) need the Responses API for tools and are not supported yet; they fail with `agent.model_not_found`.

### Troubleshooting other models

Errors appear in the chat as `Error <code>: <message>`; API keys are removed from every message.

| Code | Cause and fix |
|---|---|
| `agent.openai_missing` | The `openai` package is missing: `pip install "memdiver[agent]"`. |
| `agent.unavailable` (503 on Start chat), `agent.provider_unavailable` | The selected provider's key (or `MEMDIVER_AGENT_OPENAI_BASE_URL` for custom) is not set on the server. Set it and restart. |
| `agent.provider_unreachable` | No answer or a timeout. Is Ollama/vLLM running on the default port? Is the custom URL right? |
| `agent.auth_failed` | The provider rejected the key, or the key may not use this model. |
| `agent.model_not_found` | The model name is wrong or not pulled/served (check with **Load models**). For OpenAI's newest models: they need the Responses API, which is not supported. |
| `agent.context_overflow` | The request is larger than the model's context window. Start a new chat, use tool set `minimal`, or pick a model with a larger window. |
| `agent.context_truncated` | Ollama: the request (~N tokens) does not fit the loaded model's context window, checked before sending. Other providers: the provider read far fewer tokens than were sent. Use tool set `minimal`, start a new chat, or raise `OLLAMA_CONTEXT_LENGTH` (or `num_ctx`). |
| `agent.rate_limited` | Rate limit hit, or the account is out of credit. Wait or top up. |
| `agent.provider_rejected` | Any other request error from the provider; the message carries its reason (often an unsupported parameter or tool schema). |
| `agent.tools_unavailable` | The MemDiver MCP server did not start (within 120 s). Check the server log. |

**Load models** reports its own errors: the provider did not answer (`provider_unreachable`), refused the key or answered with an HTTP error (`provider_error`).

## Demo and test backend (no model)

`MEMDIVER_AGENT_BACKEND=scripted` replaces the model with a scripted stand-in for the Claude Code runtime. **There is no model, no API key and no network**; tools still run for real on the sandboxed MCP server, and approvals go through the real gate. The panel shows a "Demo/test backend" badge.

```bash
MEMDIVER_AGENT_BACKEND=scripted MEMDIVER_AGENT_SCRIPT=demo.json memdiver web
```

```json
{"turns": [
  [{"text": "Checking the case."},
   {"tool": "case_manifest", "input": {"case_dir": "/path/to/case"}},
   {"text": "Done. [seen] manifest above."}],
  [{"text": "Second message reply."}]
]}
```

Each inner list is the reply to one user message; each step (`text` or `tool`) counts as one turn against Max turns. Tool names may omit the `mcp__memdiver__` prefix. Further messages get `(script exhausted)`. `MEMDIVER_AGENT_BACKEND` accepts `sdk` (default), `scripted` or `scripted-compat`. `scripted-compat` plays the same script through the OpenAI-compatible loop instead of the Claude runtime (no SDK and no `openai` package needed); a run of text steps and the tool step after it count as one turn there. Both scripted backends are unavailable without `MEMDIVER_AGENT_SCRIPT`. See [](configuration.md).

## Limits

- One WebSocket per chat (a second attach is rejected with `already_attached`); the browser does not reconnect automatically, so a dropped connection ends the chat.
- At most 4 open chats.
- A chat that no WebSocket attaches to within 120 s is closed.
- One turn at a time; a message sent while busy gets a `busy` error.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| 503 on creating a chat, or the panel banner | Runtime unavailable: SDK not installed (`pip install "memdiver[agent]"`), unknown `MEMDIVER_AGENT_BACKEND`, or scripted backend without `MEMDIVER_AGENT_SCRIPT`. |
| Banner says no credentials | Set `ANTHROPIC_API_KEY` or a Bedrock/Vertex/Foundry flag in the server environment and restart. For other providers, set that provider's key (see [Using other models](#using-other-models-openai-deepseek-ollama-vllm)). |
| `Error agent.<code>` in the chat with another provider | See [Troubleshooting other models](#troubleshooting-other-models). |
| 403 | Non-loopback bind without `MEMDIVER_API_TOKEN`. Set a token or bind loopback. |
| 429 | 4 chats are already open; end one. |
| 422 | A path (case or dump) does not exist, or a setting is out of bounds. |
