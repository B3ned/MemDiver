# Adding a pipeline stage

The end-to-end pipeline in `app/pipeline/pipeline_runner.py` is composed from an
ordered **stage registry** rather than a hardcoded sequence. You can add or
insert a stage without editing `run_pipeline`'s body.

## The `Stage` contract

A `Stage` is a small dataclass:

```python
from memdiver.app.pipeline.pipeline_runner import Stage, PipelineState

def _my_stage(state: PipelineState) -> None:
    # read upstream results, do work, write artifacts + summary back onto state
    ...

stage = Stage(
    name="my_stage",              # unique, used for ordering + progress emits
    run=_my_stage,                # run(state) -> None, mutates state in place
    enabled=lambda state: True,   # optional gate; default: always enabled
    check_cancel_before=True,     # raise if ctx cancelled before this stage
)
```

- **`run(state)`** receives the shared `PipelineState` and mutates it in place.
  Read what you need (`state.consensus`, `state.candidates_path`,
  `state.hits_path`, parsed params like `state.oracle_path`) and write your
  outputs back (`state.summary[...]`, plus any field later stages consume).
  `state.consensus` is `None` on an Android Scudo run (`state.scudo_params` is
  set), which builds no positional consensus and has no `variance.npy`.
- **`enabled(state)`** decides whether the stage runs at all. This is where
  optional stages gate themselves (e.g. the built-in `nsweep` stage is enabled
  only when `state.nsweep_params is not None`).
- **`check_cancel_before`** — when `True`, `ctx.is_cancelled()` is checked
  immediately before the stage runs and `_CancelledByContext` is raised if set.
  The `consensus` stage sets this to `False` because it checks cancellation
  inside its own fold loop.

## Writing artifacts + emits

Create your subdirectory under `state.artifact_dir`, write files, then
register each with
`register_artifact(state.artifacts, state.artifact_dir, name=..., relpath=...)`
(from `memdiver.core.artifact_util`) so it computes size + sha256 and appends
the spec. Wrap the work in `state.ctx.emit("stage_start", ...)` /
`state.ctx.emit("stage_end", ...)` and pass
`progress_callback=_bridge(state.ctx, "my_stage")` to any engine function so
fine-grained progress reaches the UI. (The default stages delegate their
compute and stage bracketing to the `app.tools_pipeline` producers via
`_run_producer` / `_producer_sink`; `_bridge` is kept as the reference adapter
for out-of-tree stages.)

The default stages, in order, are `consensus`, `search_reduce`, `brute_force`,
`escalate`, `nsweep` and `emit_plugin`.

## Registering

```python
from memdiver.app.pipeline.pipeline_runner import register_stage

register_stage(stage)                       # append to the end
register_stage(stage, before="brute_force") # insert before a named stage
register_stage(stage, after="brute_force")  # insert after a named stage
register_stage(stage, index=0)              # insert at an explicit position
```

Pass at most one of `index` / `before` / `after`. Inspect the current order
with `get_pipeline_stages()`.

### Register at import time, not in the API process

**Where you call `register_stage()` decides whether the stage ever runs.** Real
pipeline runs execute in a `mp_context="spawn"` process pool
(`api/services/task_manager.py`), and each freshly-spawned worker re-imports
`app/pipeline/pipeline_runner.py` clean and rebuilds its stage registry from scratch.
A `register_stage()` call made only in the parent/API process is invisible to
those workers — the stage silently no-ops in every actual run even though it
shows up in `get_pipeline_stages()` in the parent.

For a stage to execute, its `register_stage()` call must run at **import time**
of a module that `app/pipeline/pipeline_runner` itself imports (so every spawned
worker re-runs it) — or the stage must otherwise be re-registered inside each
worker. The simplest pattern is to register at module scope:

```python
# app/pipeline/my_stage.py — imported by app/pipeline/pipeline_runner
from memdiver.app.pipeline.pipeline_runner import Stage, register_stage

def _my_stage(state):
    ...

register_stage(Stage(name="my_stage", run=_my_stage), after="brute_force")
```

and ensure `app/pipeline/pipeline_runner` imports that module so registration happens
on every re-import.

### (Optional) out-of-tree via entry point

An installed third-party package can add a stage without living in this repo by
advertising it under the `memdiver.pipeline_stages` entry-point group. MemDiver
loads the group **at import time** of `app/pipeline/pipeline_runner.py` — which is
exactly the import-time requirement above: because each spawned worker
re-imports the module, it re-runs entry-point discovery too, so an out-of-tree
stage is spawn-visible and actually executes (this is the recommended way to
close the spawn-visibility gap for out-of-tree stages).

The entry point may resolve to either a **module** (imported for its
module-level `register_stage(...)` side effect) or a **callable** (invoked with
no arguments to self-register):

```toml
# pyproject.toml of your out-of-tree package
[project.entry-points."memdiver.pipeline_stages"]
# a module whose import calls register_stage(...)
my_stage = "my_pkg.memdiver_stage"
# ...or a callable that self-registers when invoked
# my_stage = "my_pkg.memdiver_stage:register"
```

Discovery is additive, import-safe and failure-isolated — a silent no-op when
your package is not installed, and a broken entry point is logged and skipped
without aborting import.

## Pickle / spawn safety

The worker runs under `mp_context="spawn"`, so keep stage `run` callables as
**top-level module functions that capture no state** — the module is
re-imported (and the registry rebuilt) in each worker, and only `run_pipeline`
plus the JSON-friendly `params`/`ctx` cross the process boundary. Do not move
closures to module scope that capture mutable state, and communicate between
stages only through `PipelineState` and on-disk artifacts.
