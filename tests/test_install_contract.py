"""The packaging contract, enforced against the code that depends on it.

MemDiver reports an absent dependency through a soft *import probe*::

    try:
        import yara
        HAS_YARA = True
    except ImportError:
        HAS_YARA = False

That idiom is load-bearing and also silent: the probe degrades so cleanly
that a module can depend on a distribution nobody ever declared, and every
test still passes -- as long as the developer's environment happens to have
the package installed for some *other* project. ``yara-python`` was exactly
that case before it was added to ``[project.dependencies]``.

This test closes the gap structurally. It walks the shipped package for
module-level probes, maps each probed import name onto its distribution name,
and requires that distribution to appear in ``pyproject.toml`` -- either in
the base ``[project.dependencies]`` or in some
``[project.optional-dependencies]`` group. Adding a probe for an undeclared
module therefore fails here instead of passing by accident.

Scope, stated honestly:

* Only **module-level** ``try: import X / except ImportError`` blocks are
  scanned -- the top-level ``HAS_*`` capability-flag idiom the docstring
  above shows. Lazily-guarded imports *inside a function* are out of scope;
  a few of those exist (``scipy`` in ``engine/auto_floor.py``, ``PyYAML`` in
  ``api/routers/structures.py``) and each has a real in-code fallback, so
  widening the scan would be a packaging-policy change, not a test fix.
* Only the directories ``[tool.setuptools] packages`` actually ships are
  scanned. ``scripts/`` and ``tools/`` are dev material that is not
  installed, so a probe there does not create an install-contract debt.
"""

from __future__ import annotations

import ast
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

#: Directories that are never part of the shipped package.
_SKIP_DIRS = frozenset({
    "tests", "env", "node_modules", "build", "__pycache__",
    ".git", ".venv", "dist", "docs", "scripts", "tools", "frontend",
})

#: Import name -> distribution name on PyPI, for every third-party module the
#: package probes. Deliberately EXPLICIT rather than derived: the mapping is
#: not mechanical (``ahocorasick`` ships in ``pyahocorasick``, ``oqs`` in
#: ``liboqs-python``, ``ibis`` in ``ibis-framework``), and writing it out is
#: what makes an undeclared new probe visible instead of silently allowed.
_IMPORT_TO_DISTRIBUTION = {
    "ahocorasick": "pyahocorasick",
    "argon2": "argon2-cffi",
    "blake3": "blake3",
    "claude_agent_sdk": "claude-agent-sdk",
    "cryptography": "cryptography",
    "dpkt": "dpkt",
    "duckdb": "duckdb",
    "fastapi": "fastapi",
    "frida": "frida-tools",
    "ibis": "ibis-framework",
    "kaitaistruct": "kaitaistruct",
    "lz4": "lz4",
    "marimo": "marimo",
    "mcp": "mcp",
    "memslicer": "memslicer",
    "nacl": "PyNaCl",
    "numpy": "numpy",
    "openai": "openai",
    "oqs": "liboqs-python",
    "plotly": "plotly",
    "polars": "polars",
    "pydantic_settings": "pydantic-settings",
    "scipy": "scipy",
    "uvicorn": "uvicorn",
    # Probed by engine/vol3_verify.py, which loads and RUNS an emitted
    # Volatility3 plugin. Declared as the opt-in `vol` extra in pyproject.toml
    # (and reached through `all`, so CI installs it).
    "volatility3": "volatility3",
    "yara": "yara-python",
    "yaml": "PyYAML",
    "zstandard": "zstandard",
}

#: Probed names that need no declaration, with the reason each is exempt.
#: Kept small on purpose -- an entry here is a claim that pip could not
#: install the module even if we asked it to.
_STDLIB_OR_VENDORED = frozenset({
    "memdiver",    # first-party: the package probing itself for optional submodules
    "importlib",   # stdlib
    "io",          # stdlib
    "resource",    # stdlib (Unix-only, hence the probe)
    "fcntl",       # stdlib (POSIX-only, hence the probe; yara_rule_store write lock)
    "tomllib",     # stdlib on 3.11+
    "typing",      # stdlib
    "asyncio",     # stdlib
})


def _normalize(distribution: str) -> str:
    """PEP 503 name normalization, so ``ibis_framework`` == ``ibis-framework``."""
    return re.sub(r"[-_.]+", "-", distribution).lower()


def _requirement_name(requirement: str) -> str:
    """Strip extras, version specifiers and markers off a requirement string."""
    return _normalize(re.split(r"[\[<>=!~;\s(]", requirement, maxsplit=1)[0])


def _declared_distributions() -> set[str]:
    """Every distribution ``pyproject.toml`` declares, base or optional."""
    data = tomllib.loads((ROOT / "pyproject.toml").read_text())
    project = data["project"]
    declared = {_requirement_name(r) for r in project.get("dependencies", [])}
    for group in project.get("optional-dependencies", {}).values():
        declared |= {_requirement_name(r) for r in group}
    return declared


def _package_python_files():
    for path in ROOT.rglob("*.py"):
        if any(part in _SKIP_DIRS for part in path.relative_to(ROOT).parts):
            continue
        yield path


def _catches_import_error(handler: ast.ExceptHandler) -> bool:
    exc = handler.type
    if isinstance(exc, ast.Name):
        names = [exc.id]
    elif isinstance(exc, ast.Tuple):
        names = [e.id for e in exc.elts if isinstance(e, ast.Name)]
    else:  # bare `except:` -- catches ImportError too
        return exc is None
    return any(n in ("ImportError", "ModuleNotFoundError", "Exception") for n in names)


def _probed_modules() -> dict[str, set[str]]:
    """Map probed top-level import name -> the files that probe it."""
    probes: dict[str, set[str]] = {}
    for path in _package_python_files():
        try:
            tree = ast.parse(path.read_text())
        except SyntaxError:
            continue
        for node in tree.body:  # module level only
            if not isinstance(node, ast.Try):
                continue
            if not any(_catches_import_error(h) for h in node.handlers):
                continue
            for stmt in node.body:
                if isinstance(stmt, ast.Import):
                    for alias in stmt.names:
                        probes.setdefault(
                            alias.name.split(".")[0], set(),
                        ).add(str(path.relative_to(ROOT)))
                elif isinstance(stmt, ast.ImportFrom) and stmt.level == 0 and stmt.module:
                    probes.setdefault(
                        stmt.module.split(".")[0], set(),
                    ).add(str(path.relative_to(ROOT)))
    return probes


def test_module_level_import_probes_are_declared_dependencies():
    """Every soft-probed third-party module is a declared dependency.

    Fails in two distinguishable ways, both actionable:

    * an unknown import name -> add it to ``_IMPORT_TO_DISTRIBUTION`` (or to
      ``_STDLIB_OR_VENDORED`` if pip cannot supply it);
    * a known name whose distribution is absent from ``pyproject.toml`` ->
      declare the dependency.
    """
    probes = _probed_modules()
    assert probes, "probe scan found nothing; the scanner is broken, not the contract"

    declared = _declared_distributions()
    unmapped: list[str] = []
    undeclared: list[str] = []

    for module, sites in sorted(probes.items()):
        if module in _STDLIB_OR_VENDORED:
            continue
        distribution = _IMPORT_TO_DISTRIBUTION.get(module)
        if distribution is None:
            unmapped.append(f"{module} (probed in {', '.join(sorted(sites))})")
        elif _normalize(distribution) not in declared:
            undeclared.append(
                f"{distribution} (import {module!r} probed in "
                f"{', '.join(sorted(sites))})"
            )

    assert not unmapped, (
        "import probe for a module with no known distribution:\n  "
        + "\n  ".join(unmapped)
        + "\nAdd it to _IMPORT_TO_DISTRIBUTION, or to _STDLIB_OR_VENDORED."
    )
    assert not undeclared, (
        "import probe for an UNDECLARED distribution:\n  "
        + "\n  ".join(undeclared)
        + "\nAdd it to [project.dependencies] or an optional-dependencies group "
          "in pyproject.toml. A probe that only works because some other "
          "project installed the package is not a dependency."
    )
