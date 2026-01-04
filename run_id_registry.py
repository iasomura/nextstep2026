
"""
run_id_registry.py
-------------------
Centralized RUN_ID management for this project.

- Single source of truth file: artifacts/_current/run_id.txt
- JSON mirror          : artifacts/_current/run.json
- Resolution order (bootstrap):
    1) env RUN_ID
    2) file artifacts/_current/run_id.txt
    3) latest Part3 handoff (cfg.run_id or folder name)
    4) latest artifacts/<RUN_ID>/
    5) new timestamp RUN_ID
- Safe to import in all notebooks. Use like:

    import run_id_registry as runreg, importlib, paths, os
    rid = runreg.bootstrap()         # resolves & writes to file/env
    importlib.reload(paths)          # ensure paths.py sees the env
    print("RUN_ID =", rid, "paths.RUN_ID =", paths.RUN_ID)

- To start a brand new run explicitly:

    rid = runreg.new_run()           # timestamp RUN_ID + writes + sets env
    importlib.reload(paths)

"""
from __future__ import annotations
from pathlib import Path
import os, glob, json, datetime

try:
    import joblib  # for reading Part3 handoff when available
except Exception:
    joblib = None

_BASE = Path.cwd()
_ART = _BASE / "artifacts"
(_ART / "_current").mkdir(parents=True, exist_ok=True)
_TXT  = _ART / "_current" / "run_id.txt"
_JSON = _ART / "_current" / "run.json"

def _write_atomic(path: Path, data: str) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(data, encoding="utf-8")
    tmp.replace(path)

def set_current_run_id(run_id: str) -> str:
    """Write RUN_ID to file (txt/json) and set env var."""
    _ART.mkdir(parents=True, exist_ok=True)
    (_ART / "_current").mkdir(parents=True, exist_ok=True)
    _write_atomic(_TXT, run_id.strip())
    _write_atomic(_JSON, json.dumps({"run_id": run_id}, ensure_ascii=False, indent=2))
    os.environ["RUN_ID"] = run_id
    return run_id

def read_current_run_id() -> str | None:
    if _TXT.exists():
        rid = _TXT.read_text(encoding="utf-8").strip()
        return rid or None
    return None

def _latest_artifacts_dir() -> str | None:
    if not _ART.exists():
        return None
    dirs = [p for p in _ART.iterdir() if p.is_dir() and p.name != "_current"]
    if not dirs:
        return None
    return sorted(dirs)[-1].name

def _latest_part3_run_id() -> str | None:
    """Find latest Part3 handoff and extract run_id."""
    cands = sorted(_ART.glob("*/handoff/03_ai_agent_analysis_part3*.pkl"))
    if not cands:
        return None
    p = cands[-1]
    if joblib is not None:
        try:
            d = joblib.load(p)
            rid = (d.get("cfg", {}) or {}).get("run_id")
            if rid:
                return rid
        except Exception:
            pass
    # Fallback: folder name artifacts/<RID>/handoff/...
    try:
        return p.parents[2].name
    except Exception:
        return None

def resolve(precedence=("env","file","part3","latest","new")) -> str:
    """Resolve RUN_ID without writing. Return a string."""
    for src in precedence:
        if src == "env":
            rid = os.environ.get("RUN_ID")
            if rid:
                return rid
        elif src == "file":
            rid = read_current_run_id()
            if rid:
                return rid
        elif src == "part3":
            rid = _latest_part3_run_id()
            if rid:
                return rid
        elif src == "latest":
            rid = _latest_artifacts_dir()
            if rid:
                return rid
        elif src == "new":
            return datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")
    # default fallback
    return datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")

def bootstrap(precedence=("env","file","part3","latest","new")) -> str:
    """Resolve RUN_ID and persist to file + env. Returns RUN_ID."""
    rid = resolve(precedence=precedence)
    return set_current_run_id(rid)

def new_run() -> str:
    """Create a brand new RUN_ID (timestamp) and persist to file + env."""
    rid = datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")
    return set_current_run_id(rid)
