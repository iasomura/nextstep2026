"""
Drop-in shim for legacy imports:
    from _compat.paths import resolve, ensure_roots, load_config, compat_base_dirs

It unifies IO under: artifacts/{RUN_ID}/...
- RUN_ID: env RUN_ID, or auto YYYY-mm-dd_HHMMSS
- compat_base_dirs: mirrors legacy keys ('raw','data','models','results','handoff','logs','traces')
"""
from __future__ import annotations

import os
import sys
import json
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, Optional

# --- optional YAML support ---
try:
    import yaml  # type: ignore
    _YAML_OK = True
except Exception:
    _YAML_OK = False

# ---- Run ID ----
RUN_ID = os.environ.get("RUN_ID") or datetime.now().strftime("%Y-%m-%d_%H%M%S")

# ---- Unified root ----
ARTIFACTS = Path("artifacts") / RUN_ID
RAW       = ARTIFACTS / "raw"
PROCESSED = ARTIFACTS / "processed"
MODELS    = ARTIFACTS / "models"
RESULTS   = ARTIFACTS / "results"
HANDOFF   = ARTIFACTS / "handoff"
LOGS      = ARTIFACTS / "logs"
TRACES    = ARTIFACTS / "traces"

def _mkdirs() -> None:
    for p in (RAW, PROCESSED, MODELS, RESULTS, HANDOFF, LOGS, TRACES):
        p.mkdir(parents=True, exist_ok=True)

# Public API (legacy-compatible)
compat_base_dirs: Dict[str, str] = {
    "raw": str(RAW),
    "data": str(PROCESSED),
    "models": str(MODELS),
    "results": str(RESULTS),
    "handoff": str(HANDOFF),
    "logs": str(LOGS),
    "traces": str(TRACES),
}

def resolve(p: str) -> str:
    """Ensure directory exists and return its string path (legacy behavior)."""
    pp = Path(p)
    pp.mkdir(parents=True, exist_ok=True)
    return str(pp)

def ensure_roots() -> None:
    """Create unified directory tree (legacy hook)."""
    _mkdirs()

# ----------------------------
# Config loader (JSON/YAML)
# ----------------------------
def _guess_config_path(explicit: Optional[str]) -> Path:
    """
    Search order:
      1) explicit path arg
      2) $CONFIG_PATH
      3) ./config.json
      4) ./config.yml
      5) ./config.yaml
    """
    if explicit:
        return Path(explicit)
    env_p = os.getenv("CONFIG_PATH")
    if env_p:
        return Path(env_p)
    for name in ("config.json", "config.yml", "config.yaml"):
        cand = Path(name)
        if cand.exists():
            return cand
    # fallback (not existing yet) -> default json name
    return Path("config.json")

def _read_config_file(p: Path) -> Dict[str, Any]:
    if not p.exists():
        raise RuntimeError(f"config が見つかりません: {p}")
    suffix = p.suffix.lower()
    if suffix in (".yml", ".yaml") and _YAML_OK:
        return yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    # default: JSON
    return json.loads(p.read_text(encoding="utf-8"))

def load_config(path: Optional[str] = None, *, strict: bool = True) -> Dict[str, Any]:
    """
    Return config dict (JSON/YAML). Also attaches:
      - cfg['paths']['root'] = artifacts/{RUN_ID}
      - cfg['run_id']        = RUN_ID

    strict=True: raise if config file not found; False: return minimal dict.
    """
    _mkdirs()
    cfg_path = _guess_config_path(path)
    if not cfg_path.exists():
        if strict:
            raise RuntimeError(f"config が見つかりません: {cfg_path}")
        # minimal fallback (legacy behavior)
        return {"paths": {"root": str(ARTIFACTS)}, "run_id": RUN_ID}

    cfg = _read_config_file(cfg_path)
    # attach paths/run_id for legacy compatibility
    paths = cfg.setdefault("paths", {})
    paths.setdefault("root", str(ARTIFACTS))
    cfg["run_id"] = RUN_ID
    return cfg

# --------------------------------------
# Provide import alias: _compat.paths.*
# --------------------------------------
# This allows: from _compat.paths import resolve, ensure_roots, load_config, compat_base_dirs
import types as _types
if "_compat" not in sys.modules:
    _compat_pkg = _types.ModuleType("_compat")
    # mark as pkg-like
    setattr(_compat_pkg, "__path__", [])
    sys.modules["_compat"] = _compat_pkg

# current module object
_this = sys.modules[__name__]
# register alias
sys.modules["_compat.paths"] = _this
# expose as attribute for "package.attr" access
setattr(sys.modules["_compat"], "paths", _this)


def load_config(path: Optional[str] = None, *, strict: bool = True) -> Dict[str, Any]:
    """
    Return config dict (JSON/YAML). Also attaches:
      - cfg['paths']['root'] = artifacts/{RUN_ID}
      - cfg['run_id']        = RUN_ID

    strict=True: raise if config file not found; False: return minimal dict.
    """
    _mkdirs()
    cfg_path = _guess_config_path(path)
    if not cfg_path.exists():
        if strict:
            raise RuntimeError(f"config が見つかりません: {cfg_path}")
        # minimal fallback (legacy behavior)
        return {"paths": {"root": str(ARTIFACTS)}, "run_id": RUN_ID}

    cfg = _read_config_file(cfg_path)
    # attach paths/run_id for legacy compatibility
    paths = cfg.setdefault("paths", {})
    paths.setdefault("root", str(ARTIFACTS))
    cfg["run_id"] = RUN_ID
    return cfg

# --------------------------------------
# Provide import alias: _compat.paths.*
# --------------------------------------
# This allows: from _compat.paths import resolve, ensure_roots, load_config, compat_base_dirs
import types as _types
if "_compat" not in sys.modules:
    _compat_pkg = _types.ModuleType("_compat")
    # mark as pkg-like
    setattr(_compat_pkg, "__path__", [])
    sys.modules["_compat"] = _compat_pkg

# current module object
_this = sys.modules[__name__]
# register alias
sys.modules["_compat.paths"] = _this
# expose as attribute for "package.attr" access
setattr(sys.modules["_compat"], "paths", _this)
