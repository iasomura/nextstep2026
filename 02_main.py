#!/usr/bin/env python3
"""
02_main.py - Stage1/Stage2 Pipeline (02_original.ipynb互換)

Usage:
    # パイプライン実行
    python 02_main.py --run

    # 特定RUN_ID指定
    python 02_main.py --run --run-id 2026-01-10_140940

Requirements:
    - PostgreSQL (phishtank_entries, jpcert_phishing_urls)
    - vLLM (Qwen3-14B-FP8)
    - .env with DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD, VLLM_BASE_URL
"""

import sys
import os
from pathlib import Path
from datetime import datetime
import json
import pickle
import argparse
import warnings
warnings.filterwarnings('ignore')

import numpy as np
import pandas as pd
import joblib

# ML
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, classification_report, roc_auc_score
import xgboost as xgb

# Add module path
sys.path.insert(0, str(Path(__file__).parent / "02_stage1_stage2"))

# Import feature extraction module
from src.features import FEATURE_ORDER, extract_features


# ============================================================
# Configuration
# ============================================================

def load_compat_config():
    """Load configuration from _compat/config.json (same as 02_original.ipynb Cell 4)."""
    config_path = Path("_compat/config.json")
    if config_path.exists():
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}


def get_default_config():
    """Get default configuration matching 02_original.ipynb."""
    # Load from _compat/config.json first (same as notebook)
    compat_cfg = load_compat_config()

    # Extract nested configs
    db_cfg = compat_cfg.get('db', compat_cfg.get('DB_CONFIG', {}))
    llm_cfg = compat_cfg.get('llm', {})
    brand_cfg = compat_cfg.get('brand_keywords', {})
    model_cfg = compat_cfg.get('model', {})

    return {
        # XGBoost (from config.json model section or defaults)
        'xgb_val_size': 0.10,
        'xgb_n_estimators': model_cfg.get('n_estimators', 500),
        'xgb_max_depth': model_cfg.get('max_depth', 6),
        'xgb_learning_rate': model_cfg.get('learning_rate', 0.1),
        'xgb_early_stopping_rounds': model_cfg.get('early_stopping_rounds', 50),

        # Route1 thresholds
        'xgb_t_mode': 'auto_from_val',
        'xgb_risk_max_auto_benign': 0.001,
        'xgb_risk_max_auto_phish': 0.0002,
        'xgb_min_auto_samples': 200,
        'xgb_risk_use_upper': True,
        'xgb_risk_alpha': 0.05,

        # Stage2 (defaults match 02_original.ipynb Cell 37)
        'stage2_select_mode': 'threshold_cap',  # default in notebook
        'stage2_max_budget': 0,  # 0 = disabled (variable-size handoff)
        'stage2_tau': 0.60,  # default in notebook
        'stage2_override_tau': 0.30,
        'stage2_phi_phish': 0.99,
        'stage2_phi_benign': 0.01,
        'stage2_seg_only_benign': False,
        'stage2_seg_optional': True,
        'stage2_seg_include_idn': True,
        'stage2_seg_include_brand': True,
        'stage2_seg_min_p1': 0.00,
        'stage2_oof_folds': 5,

        # Dangerous TLDs
        'dangerous_tlds': [
            'icu', 'top', 'xyz', 'buzz', 'cfd', 'cyou', 'rest',
            'tk', 'ml', 'ga', 'cf', 'gq', 'sbs', 'click', 'link',
            'online', 'site', 'website'
        ],

        # LLM (from config.json llm section)
        'llm_enabled': llm_cfg.get('enabled', True),
        'llm_base_url': llm_cfg.get('base_url') or llm_cfg.get('vllm_base_url') or os.getenv('VLLM_BASE_URL', 'http://192.168.100.71:30000/v1'),
        'llm_model': llm_cfg.get('model') or llm_cfg.get('vllm_model') or os.getenv('BRAND_LLM_MODEL', 'Qwen/Qwen3-14B-FP8'),
        'llm_api_key': llm_cfg.get('api_key') or os.getenv('VLLM_API_KEY', 'EMPTY'),

        # Brand keywords (from config.json brand_keywords section)
        'brand_min_count': brand_cfg.get('min_count', 2),
        'brand_max_brands': brand_cfg.get('max_brands', 0),  # 0 = unlimited
        'brand_dynamic': brand_cfg.get('dynamic_extraction', True),
        'brand_default_list': brand_cfg.get('default_list', []),  # Manual additions

        # Database (from config.json db/DB_CONFIG section)
        'db_host': db_cfg.get('host', os.getenv('DB_HOST', 'localhost')),
        'db_port': int(db_cfg.get('port', os.getenv('DB_PORT', '5432'))),
        'db_name': db_cfg.get('dbname', os.getenv('DB_NAME', 'rapids_data')),
        'db_user': db_cfg.get('user', os.getenv('DB_USER', 'postgres')),
        'db_password': db_cfg.get('password', os.getenv('DB_PASSWORD', '')),
    }


def get_run_id(specified_run_id=None):
    """
    Resolve RUN_ID (same logic as notebook).
    Priority: specified → env var → _current → latest artifacts → new
    """
    # 0. Specified
    if specified_run_id:
        print(f"   Using specified RUN_ID: {specified_run_id}")
        return specified_run_id

    # 1. Environment variable
    env_run_id = os.environ.get("RUN_ID")
    if env_run_id:
        print(f"   Using RUN_ID from environment: {env_run_id}")
        return env_run_id

    # 2. _current/run_id.txt
    current_file = Path("artifacts/_current/run_id.txt")
    if current_file.exists():
        run_id = current_file.read_text().strip()
        if run_id:
            print(f"   Using RUN_ID from _current: {run_id}")
            return run_id

    # 3. Latest artifacts
    artifacts_dir = Path("artifacts")
    if artifacts_dir.exists():
        runs = [d.name for d in artifacts_dir.iterdir()
                if d.is_dir() and d.name != '_current' and not d.name.startswith('.')]
        if runs:
            run_id = sorted(runs)[-1]
            print(f"   Using latest RUN_ID: {run_id}")
            return run_id

    # 4. Generate new
    run_id = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    print(f"   Generated new RUN_ID: {run_id}")
    return run_id


# ============================================================
# LLM Brand Extraction (Cell 15)
# ============================================================
# CHANGELOG (2026-01-10):
# - Rewritten to match 02_original.ipynb Cell 15 exactly
# - Uses Structured Output with JSON schema (extra_body)
# - Batch processing with _validate_batch_brands()
# - Proper JSON parsing with fallback (_safe_parse_json_or_python)
# - Guards against placeholder words like 'canonicalname'
# ============================================================

import re
import time
import ast as _ast

# Structured Output schemas (vLLM OpenAI-Compatible Server)
BRAND_VALIDATION_SCHEMA = {
    "title": "brand_validation",
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "valid": {"type": "boolean", "description": "True if token is a brand/company/organization name."},
        "canon": {
            "type": "string",
            "description": "Canonical token in lowercase ASCII, no spaces, only [a-z0-9&-].",
        },
    },
    "required": ["valid", "canon"],
}

BATCH_VALIDATION_SCHEMA = {
    "title": "brand_validation_batch",
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "results": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "index": {"type": "integer"},
                    "input": {"type": "string"},
                    "valid": {"type": "boolean"},
                    "canon": {"type": "string"},
                },
                "required": ["index", "input", "valid", "canon"],
            },
        }
    },
    "required": ["results"],
}

_CANON_PLACEHOLDER = {"canonicalname", "canonical_name", "canon", "brand", "company", "organization"}


def _safe_parse_json_or_python(content: str):
    """Parse JSON (preferred) or Python-literal dict/list as a fallback."""
    if not content:
        return {}
    s = content.strip()

    # 1) Strict JSON
    try:
        return json.loads(s)
    except Exception:
        pass

    # 2) Extract first JSON-looking object/array and try JSON again
    try:
        m = re.search(r"(\{.*\}|\[.*\])", s, flags=re.DOTALL)
        if m:
            return json.loads(m.group(1))
    except Exception:
        pass

    # 3) Python literal (e.g., {'valid': True, 'canon': 'microsoft'})
    try:
        return _ast.literal_eval(s)
    except Exception:
        pass

    # 4) Extract then python literal
    try:
        m = re.search(r"(\{.*\}|\[.*\])", s, flags=re.DOTALL)
        if m:
            return _ast.literal_eval(m.group(1))
    except Exception:
        pass

    return {}


def normalize_brand_name(name: str):
    """Normalize brand name to lowercase ASCII."""
    if not name:
        return None
    s = name.lower().replace("&amp;", "&")
    s = re.sub(r"[^a-z0-9\-&]", "", s)
    return s or None


def extract_brands_via_llm(cfg):
    """
    Extract brand keywords from database via LLM.
    Replicates Cell 15 of 02_original.ipynb exactly.
    """
    import psycopg2
    from openai import OpenAI

    print("\n" + "=" * 80)
    print("LLM Brand Keyword Extraction (Cell 15)")
    print("=" * 80)

    # Database connection
    db_config = {
        'host': cfg['db_host'],
        'port': cfg['db_port'],
        'dbname': cfg['db_name'],
        'user': cfg['db_user'],
        'password': cfg['db_password'],
    }

    print("\n[1/4] Connecting to database...")
    conn = psycopg2.connect(**db_config)
    cur = conn.cursor()
    print("   Database connected")

    # Query phishtank_entries
    print("\n[2/4] Querying phishtank_entries...")
    cur.execute("""
        SELECT target, COUNT(*) as count
        FROM public.phishtank_entries
        WHERE target IS NOT NULL AND target <> 'Other'
        GROUP BY target
        HAVING COUNT(*) >= 1
        ORDER BY count DESC
        LIMIT 200
    """)
    phishtank_targets = cur.fetchall()
    print(f"   Found {len(phishtank_targets)} targets")

    # Query jpcert_phishing_urls (description column)
    print("\n[3/4] Querying jpcert_phishing_urls...")
    cur.execute("""
        SELECT DISTINCT description
        FROM public.jpcert_phishing_urls
        WHERE description IS NOT NULL
          AND description <> ''
          AND description <> '-'
        LIMIT 200
    """)
    jpcert_descriptions = [r[0] for r in cur.fetchall()]
    print(f"   Found {len(jpcert_descriptions)} descriptions")

    cur.close()
    conn.close()

    # Build pt_counts (normalized + frequency)
    pt_counts = {}
    for tgt, cnt in phishtank_targets:
        nt = normalize_brand_name(tgt)
        if nt:
            pt_counts[nt] = pt_counts.get(nt, 0) + int(cnt)

    # Create LLM client
    print("\n[4/4] Extracting brand keywords via LLM...")
    client = OpenAI(
        base_url=cfg['llm_base_url'],
        api_key=cfg['llm_api_key'] or "EMPTY"
    )
    model = cfg['llm_model']

    # Test connection
    try:
        client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": "ping"}],
            max_tokens=1,
            temperature=0.0,
        )
        print(f"   LLM connected: {model}")
    except Exception as e:
        raise ConnectionError(f"LLM connection failed: {e}")

    # Context helper
    def _ctx_for(cand: str, max_lines: int = 2) -> str:
        cand_lc = (cand or "").lower()
        hits = [d for d in jpcert_descriptions if cand_lc in (d or "").lower()][:max_lines]
        return "\n- ".join(hits) if hits else ""

    # Single brand validation (fallback)
    def _validate_one_brand(cand: str) -> tuple:
        system = "You are a cybersecurity analyst. Output JSON only."
        ctx = _ctx_for(cand)
        user = (
            "Decide if the following token is a brand/company/organization name (not a generic word).\n"
            "If it is a brand, set valid=true and provide a canonical token in `canon`.\n"
            "- `canon` MUST be lowercase ASCII with no spaces, only [a-z0-9&-].\n"
            "- Do NOT return placeholder words like 'canonicalname'.\n"
            f'Token: "{cand}"'
        )
        if ctx:
            user += "\nContext:\n- " + ctx

        for _ in range(2):
            try:
                r = client.chat.completions.create(
                    model=model,
                    messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
                    temperature=0.0,
                    max_tokens=64,
                    extra_body={"structured_outputs": {"json": BRAND_VALIDATION_SCHEMA}},
                )
                content = (r.choices[0].message.content or "").strip()
                data = _safe_parse_json_or_python(content) or {}
                valid = bool(data.get("valid", False))
                canon_raw = str(data.get("canon", "") or "")
                canon = normalize_brand_name(canon_raw)

                if canon in _CANON_PLACEHOLDER:
                    canon = None
                if canon is None:
                    canon = normalize_brand_name(cand)

                return (valid and bool(canon)), (canon or cand)
            except Exception:
                time.sleep(0.5)
        return False, cand

    # Batch validation
    def _validate_batch_brands(cands: list) -> list:
        system = "You are a cybersecurity analyst. Output JSON only."
        items = []
        for idx, cand in enumerate(cands):
            items.append({
                "index": idx,
                "token": cand,
                "context": _ctx_for(cand)
            })

        user = (
            "For each item, decide whether it is a brand/company/organization name (not a generic word). "
            "Treat items independently.\n"
            "Output MUST be a single JSON object and NOTHING else (no markdown, no code fences).\n"
            "The JSON must match exactly this shape:\n"
            '{"results":[{"index":0,"input":"...","valid":true,"canon":"..."}, ...]}\n'
            "Requirements:\n"
            "- results length MUST equal the number of items.\n"
            "- Keep the same order as items. index MUST be 0..n-1.\n"
            "- input MUST be exactly the original item string.\n"
            "- valid MUST be JSON boolean: true or false (lowercase).\n"
            "- If valid is false, set canon to an empty string \"\".\n"
            "- If valid is true, canon MUST be a normalized form of the input: lowercase ASCII, no spaces, only [a-z0-9&-].\n"
            "- Do NOT output placeholder words like 'canonicalname', '<canonical_name>', 'canon', 'brand'.\n\n"
            "items:\n" + json.dumps(items, ensure_ascii=False)
        )

        max_tokens = 160 * len(cands) + 120
        for _ in range(2):
            try:
                r = client.chat.completions.create(
                    model=model,
                    messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
                    temperature=0.0,
                    max_tokens=max_tokens,
                    extra_body={"structured_outputs": {"json": BATCH_VALIDATION_SCHEMA}},
                )
                content = (r.choices[0].message.content or "").strip()
                data = _safe_parse_json_or_python(content) or {}
                results = data.get("results", [])
                if not isinstance(results, list):
                    raise ValueError("Invalid results type")

                tmp = [None] * len(cands)
                for entry in results:
                    if not isinstance(entry, dict):
                        continue
                    idx = entry.get("index", None)
                    if not isinstance(idx, int) or not (0 <= idx < len(cands)):
                        continue

                    valid = bool(entry.get("valid", False))
                    canon_raw = str(entry.get("canon", "") or entry.get("input", "") or cands[idx])
                    canon = normalize_brand_name(canon_raw)

                    if canon in _CANON_PLACEHOLDER:
                        canon = None
                    if canon is None:
                        canon = normalize_brand_name(cands[idx])

                    tmp[idx] = (valid and bool(canon), (canon or cands[idx]))

                # Fill missing indices with per-item fallback
                for i in range(len(tmp)):
                    if tmp[i] is None:
                        tmp[i] = _validate_one_brand(cands[i])

                return tmp

            except Exception:
                time.sleep(0.5)

        # Fallback per-item
        return [_validate_one_brand(c) for c in cands]

    # Process candidates
    # CHANGELOG (2026-01-10): max_brands=0 means unlimited
    MAX_BRANDS = cfg['brand_max_brands']
    if MAX_BRANDS <= 0:
        MAX_BRANDS = float('inf')  # Unlimited
    BATCH_SIZE = 5  # Same as notebook default

    candidates_sorted = [cand for cand, cnt in sorted(pt_counts.items(), key=lambda x: (-x[1], x[0]))]

    BRAND_KEYWORDS = []
    _seen = set()
    total_candidates = len(candidates_sorted)
    processed = 0
    found = 0
    start_ts = time.time()

    max_brands_display = "unlimited" if MAX_BRANDS == float('inf') else MAX_BRANDS
    print(f"   MAX_BRANDS: {max_brands_display}, BATCH_SIZE: {BATCH_SIZE}")
    print(f"   Total candidates: {total_candidates}")

    def _chunks(seq, n):
        for i in range(0, len(seq), n):
            yield seq[i:i+n]

    for chunk in _chunks(candidates_sorted, BATCH_SIZE):
        if len(BRAND_KEYWORDS) >= MAX_BRANDS:
            break

        results = _validate_batch_brands(chunk)

        added_this_batch = []
        for ok, canon in results:
            if len(BRAND_KEYWORDS) >= MAX_BRANDS:
                break
            if ok and canon not in _seen:
                BRAND_KEYWORDS.append(canon)
                _seen.add(canon)
                added_this_batch.append(canon)

        processed += len(chunk)
        found = len(BRAND_KEYWORDS)

        if added_this_batch:
            sample = ", ".join(added_this_batch[:3])
            if len(added_this_batch) > 3:
                sample += ", ..."
            print(f"   [{processed}/{total_candidates}] found={found} (added: {sample})")
        else:
            print(f"   [{processed}/{total_candidates}] found={found}")

    elapsed = time.time() - start_ts
    print(f"\n   Done. processed={processed}/{total_candidates}, found={found}, elapsed={elapsed:.1f}s")

    # CHANGELOG (2026-01-10): Add default_list (manual additions) from config
    default_list = cfg.get('brand_default_list', [])
    if default_list:
        added_defaults = []
        for brand in default_list:
            norm = normalize_brand_name(brand)
            if norm and norm not in _seen:
                BRAND_KEYWORDS.append(norm)
                _seen.add(norm)
                added_defaults.append(norm)
        if added_defaults:
            print(f"   Added from default_list: {added_defaults}")

    print(f"   Final BRAND_KEYWORDS: {len(BRAND_KEYWORDS)} items")
    print(f"   Top 20: {BRAND_KEYWORDS[:20]}")

    return BRAND_KEYWORDS


# ============================================================
# Wilson Score for Route1 Threshold Selection
# ============================================================

def wilson_upper_bound(n_total, n_error, alpha=0.05):
    """Wilson score one-sided upper confidence bound."""
    from scipy import stats

    if n_total == 0:
        return 1.0

    p = n_error / n_total
    z = stats.norm.ppf(1 - alpha)

    denominator = 1 + z**2 / n_total
    center = (p + z**2 / (2 * n_total)) / denominator
    margin = (z / denominator) * np.sqrt(p * (1 - p) / n_total + z**2 / (4 * n_total**2))

    return center + margin


def select_route1_thresholds(y_val, p_val, cfg):
    """
    Select Route1 thresholds using Wilson score (same as notebook).
    Returns (t_low, t_high, meta_dict)
    """
    risk_max_benign = cfg['xgb_risk_max_auto_benign']
    risk_max_phish = cfg['xgb_risk_max_auto_phish']
    min_samples = cfg['xgb_min_auto_samples']
    alpha = cfg['xgb_risk_alpha']

    # Sort by probability
    sorted_idx = np.argsort(p_val)
    p_sorted = p_val[sorted_idx]
    y_sorted = y_val[sorted_idx]

    n = len(p_val)

    # Find t_low (auto_benign threshold)
    t_low = 0.001
    best_low_n = 0
    for i in range(min_samples, n):
        t = p_sorted[i]
        n_below = i
        n_phish_below = y_sorted[:i].sum()
        risk_est = wilson_upper_bound(n_below, n_phish_below, alpha)

        if risk_est <= risk_max_benign and n_below >= min_samples:
            if n_below > best_low_n:
                t_low = t
                best_low_n = n_below

    # Find t_high (auto_phish threshold)
    t_high = 0.999
    best_high_n = 0
    for i in range(n - min_samples, 0, -1):
        t = p_sorted[i]
        n_above = n - i
        n_benign_above = (1 - y_sorted[i:]).sum()
        risk_est = wilson_upper_bound(n_above, n_benign_above, alpha)

        if risk_est <= risk_max_phish and n_above >= min_samples:
            if n_above > best_high_n:
                t_high = t
                best_high_n = n_above

    # Build meta
    low_mask = p_val <= t_low
    high_mask = p_val >= t_high

    meta = {
        't_low': float(t_low),
        't_high': float(t_high),
        'low_n': int(low_mask.sum()),
        'low_k': int(y_val[low_mask].sum()) if low_mask.any() else 0,
        'low_risk_point': float(y_val[low_mask].mean()) if low_mask.any() else 0.0,
        'low_risk_est': float(wilson_upper_bound(low_mask.sum(), y_val[low_mask].sum(), alpha)) if low_mask.any() else 0.0,
        'n': int(len(p_val)),
        'coverage': float((low_mask | high_mask).mean()),
        'high_n': int(high_mask.sum()),
        'high_k': int((1 - y_val[high_mask]).sum()) if high_mask.any() else 0,
        'high_risk_point': float((1 - y_val[high_mask]).mean()) if high_mask.any() else 0.0,
        'high_risk_est': float(wilson_upper_bound(high_mask.sum(), (1 - y_val[high_mask]).sum(), alpha)) if high_mask.any() else 0.0,
    }

    return t_low, t_high, meta


# ============================================================
# Stage2 Gate (OOF LR + segment_priority)
# ============================================================

def train_stage2_lr_oof(X_train, y_train, err_train, cfg):
    """
    Train Stage2 Logistic Regression with Out-of-Fold predictions.
    Predicts probability of Stage1 making an error.
    """
    n_folds = cfg['stage2_oof_folds']
    random_state = 42

    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_train)

    # OOF predictions
    oof_preds = np.zeros(len(X_train))
    skf = StratifiedKFold(n_splits=n_folds, shuffle=True, random_state=random_state)

    for fold, (train_idx, val_idx) in enumerate(skf.split(X_scaled, err_train)):
        X_tr, X_val = X_scaled[train_idx], X_scaled[val_idx]
        y_tr, y_val = err_train[train_idx], err_train[val_idx]

        model = LogisticRegression(
            max_iter=1000,
            random_state=random_state,
            class_weight='balanced'
        )
        model.fit(X_tr, y_tr)
        oof_preds[val_idx] = model.predict_proba(X_val)[:, 1]

    # Train final model on all data
    final_model = LogisticRegression(
        max_iter=1000,
        random_state=random_state,
        class_weight='balanced'
    )
    final_model.fit(X_scaled, err_train)

    return final_model, scaler, oof_preds


def run_stage2_gate(df_defer, X_defer, p1_defer, y_defer, domains_defer, tlds_defer,
                    sources_defer, brand_keywords, cfg, lr_model=None, lr_scaler=None):
    """
    Run Stage2 gate (threshold_cap or segment_priority mode).
    Returns: (selected_mask, gate_trace_df, stage2_select_stats)
    """
    n_defer = len(df_defer)
    select_mode = cfg['stage2_select_mode'].lower()

    # Stage1 predictions (0.5 threshold)
    stage1_pred = (p1_defer >= 0.5).astype(int)

    # Defer score (p_error from LR or simple uncertainty)
    if lr_model is not None and lr_scaler is not None:
        X_scaled = lr_scaler.transform(X_defer)
        p_error = lr_model.predict_proba(X_scaled)[:, 1]
    else:
        p_error = 1.0 - np.abs(p1_defer - 0.5) * 2.0

    defer_score = p_error

    # Common features for gate trace
    tld_lower = np.array([str(t).lower() for t in tlds_defer])
    is_dangerous = np.isin(tld_lower, cfg['dangerous_tlds'])
    dom_str = np.array([str(d) for d in domains_defer])
    is_idn = np.char.find(dom_str, 'xn--') >= 0

    brand_hit = np.zeros(n_defer, dtype=bool)
    if brand_keywords:
        dom_lower = np.char.lower(dom_str.astype(str))
        for brand in brand_keywords:
            brand_hit |= np.char.find(dom_lower, brand.lower()) >= 0

    # ================================================================
    # threshold_cap mode (default in 02_original.ipynb)
    # ================================================================
    if select_mode in ('threshold_cap', 'threshold-cap', 'threshold+cap'):
        max_budget = int(cfg['stage2_max_budget'])
        tau = float(cfg['stage2_tau'])
        override_tau = float(cfg['stage2_override_tau'])
        phi_phish = float(cfg['stage2_phi_phish'])
        phi_benign = float(cfg['stage2_phi_benign'])

        # Clear: very confident predictions (don't handoff unless override)
        clear = (p1_defer >= phi_phish) | (p1_defer <= phi_benign)

        # Override: rescue confident mistakes (high error probability)
        override = (p_error >= override_tau)

        # Gray: uncertain or high defer_score
        gray = (~clear) & (defer_score >= tau)

        picked = override | gray
        selected_idx = np.where(picked)[0]

        tau_final = tau
        override_tau_final = override_tau

        # Apply cap if max_budget > 0
        if max_budget > 0 and len(selected_idx) > max_budget:
            # Raise tau until within budget
            tau_step = 0.001
            _tau = tau
            for _ in range(2000):
                _tau = min(0.999999, _tau + tau_step)
                gray = (~clear) & (~override) & (defer_score >= _tau)
                selected_idx = np.where(override | gray)[0]
                if len(selected_idx) <= max_budget or _tau >= 0.999999:
                    tau_final = _tau
                    break

        selected_mask = np.zeros(n_defer, dtype=bool)
        selected_mask[selected_idx] = True

        stage2_select_stats = {
            'mode': 'threshold_cap',
            'max_budget': max_budget,
            'tau': tau,
            'tau_final': tau_final,
            'override_tau': override_tau,
            'override_tau_final': override_tau_final,
            'phi_phish': phi_phish,
            'phi_benign': phi_benign,
            'selected_final': int(selected_mask.sum()),
        }

    # ================================================================
    # segment_priority mode
    # ================================================================
    elif select_mode in ('segment_priority', 'segment-priority'):
        budget = cfg['stage2_max_budget']
        tau = cfg['stage2_tau']

        priority_pool = is_dangerous | is_idn | brand_hit
        legitimate_tlds = {'com', 'org', 'net', 'edu', 'gov', 'co', 'io', 'jp', 'uk', 'de', 'fr'}
        is_legitimate = np.isin(tld_lower, list(legitimate_tlds))
        optional_pool = ~is_dangerous & ~is_legitimate if cfg['stage2_seg_optional'] else np.zeros(n_defer, dtype=bool)

        # Select from priority pool first
        priority_idx = np.where(priority_pool)[0]
        priority_sorted = priority_idx[np.argsort(-defer_score[priority_idx])]
        priority_gray = priority_sorted[defer_score[priority_sorted] > tau]
        selected_priority = priority_gray[:min(len(priority_gray), budget)] if budget > 0 else priority_gray

        remaining_budget = (budget - len(selected_priority)) if budget > 0 else n_defer

        # Select from optional pool
        selected_optional = np.array([], dtype=int)
        if remaining_budget > 0 and cfg['stage2_seg_optional']:
            optional_idx = np.where(optional_pool & ~np.isin(np.arange(n_defer), selected_priority))[0]
            if len(optional_idx) > 0:
                optional_sorted = optional_idx[np.argsort(-defer_score[optional_idx])]
                optional_gray = optional_sorted[defer_score[optional_sorted] > tau]
                selected_optional = optional_gray[:min(len(optional_gray), remaining_budget)]

        selected_idx = np.concatenate([selected_priority, selected_optional]).astype(int)
        selected_mask = np.zeros(n_defer, dtype=bool)
        selected_mask[selected_idx] = True

        stage2_select_stats = {
            'mode': 'segment_priority',
            'max_budget': int(budget),
            'tau': tau,
            'priority_pool': int(priority_pool.sum()),
            'optional_pool': int(optional_pool.sum()),
            'selected_priority': int(len(selected_priority)),
            'selected_optional': int(len(selected_optional)),
            'selected_final': int(selected_mask.sum()),
        }
    else:
        raise ValueError(f"Unknown stage2_select_mode: {select_mode}")

    # Build gate trace DataFrame with all expected columns
    pool_priority = is_dangerous | is_idn | brand_hit
    legitimate_tlds = {'com', 'org', 'net', 'edu', 'gov', 'co', 'io', 'jp', 'uk', 'de', 'fr'}
    is_legitimate_tld = np.isin(tld_lower, list(legitimate_tlds))
    pool_optional = ~is_dangerous & ~is_legitimate_tld

    gate_trace = pd.DataFrame({
        'idx': np.arange(n_defer),
        'domain': domains_defer,
        'tld': tlds_defer,
        'ml_probability': p1_defer,
        'stage1_pred': stage1_pred,
        'y_true': y_defer,
        'p_error': p_error,
        'uncertainty': 1.0 - np.abs(p1_defer - 0.5) * 2.0,
        'defer_score': defer_score,
        'is_dangerous_tld': is_dangerous.astype(int),
        'is_idn': is_idn.astype(int),
        'brand_hit': brand_hit.astype(int),
        'pool_priority': pool_priority.astype(int),
        'pool_optional': pool_optional.astype(int),
        'selected': selected_mask.astype(int),
        'selected_priority': (pool_priority & selected_mask).astype(int),
        'selected_optional': (pool_optional & selected_mask & ~pool_priority).astype(int),
    })

    return selected_mask, gate_trace, stage2_select_stats


# ============================================================
# Main Pipeline
# ============================================================

def run_pipeline(run_id, cfg):
    """
    Run the full Stage1/Stage2 pipeline.
    Outputs all files compatible with 02_original.ipynb.
    """
    print("\n" + "=" * 80)
    print("02 Stage1/Stage2 Pipeline")
    print(f"RUN_ID: {run_id}")
    print("=" * 80)

    # Setup directories
    artifacts_dir = Path("artifacts") / run_id
    raw_dir = artifacts_dir / "raw"
    processed_dir = artifacts_dir / "processed"
    models_dir = artifacts_dir / "models"
    results_dir = artifacts_dir / "results"
    handoff_dir = artifacts_dir / "handoff"

    for d in [raw_dir, processed_dir, models_dir, results_dir, handoff_dir]:
        d.mkdir(parents=True, exist_ok=True)

    # Also create compat results dir
    compat_results = Path("results") / run_id
    compat_results.mkdir(parents=True, exist_ok=True)

    # ================================================================
    # Step 1: Brand Keywords (LLM)
    # ================================================================
    print("\n" + "-" * 40)
    print("[1/9] Brand keyword extraction via LLM...")

    brand_keywords = extract_brands_via_llm(cfg)

    # Save brand keywords
    brand_path = models_dir / "brand_keywords.json"
    with open(brand_path, 'w') as f:
        json.dump(brand_keywords, f, indent=2)
    print(f"   Saved: {brand_path.name}")

    # ================================================================
    # Step 2: Load Data
    # ================================================================
    print("\n" + "-" * 40)
    print("[2/9] Loading data...")

    data_path = raw_dir / "prepared_data.pkl"
    if not data_path.exists():
        raise FileNotFoundError(f"Data not found: {data_path}\nRun 01_data_preparation first.")

    with open(data_path, 'rb') as f:
        prepared_data = pickle.load(f)

    phishing_df = prepared_data['phishing_data']
    trusted_df = prepared_data['trusted_data']
    metadata = prepared_data['metadata']

    print(f"   Phishing: {len(phishing_df):,} samples")
    print(f"   Trusted:  {len(trusted_df):,} samples")

    # ================================================================
    # Step 3: Feature Extraction (Cell 19 of 02_original.ipynb)
    # ================================================================
    # CHANGELOG (2026-01-10):
    # - Rewritten to match 02_original.ipynb Cell 19 exactly
    # - Extract features using new brand_keywords (contains_brand feature)
    # - Generate train_data.pkl and test_data.pkl from scratch
    # ================================================================
    print("\n" + "-" * 40)
    print("[3/9] Extracting features (Cell 19)...")

    train_pkl = processed_dir / "train_data.pkl"
    test_pkl = processed_dir / "test_data.pkl"

    # Combine phishing and trusted data
    all_data = pd.concat([
        phishing_df[['domain', 'cert_data', 'label', 'source']],
        trusted_df[['domain', 'cert_data', 'label', 'source']]
    ], ignore_index=True)

    print(f"   Total samples: {len(all_data):,}")
    print(f"   Phishing: {len(all_data[all_data['label'] == 1]):,}")
    print(f"   Trusted:  {len(all_data[all_data['label'] == 0]):,}")

    # Feature extraction with progress display
    print("\n   Extracting features...")
    start_time = time.time()

    features_list = []
    domains_list = []
    labels_list = []
    sources_list = []
    tlds_list = []

    # Batch processing
    batch_size = 10000
    total_batches = (len(all_data) + batch_size - 1) // batch_size

    for batch_idx in range(total_batches):
        start_idx = batch_idx * batch_size
        end_idx = min((batch_idx + 1) * batch_size, len(all_data))
        batch_data = all_data.iloc[start_idx:end_idx]

        for _, row in batch_data.iterrows():
            try:
                features = extract_features(row['domain'], row['cert_data'], brand_keywords)
                features_list.append(features)
                domains_list.append(row['domain'])
                labels_list.append(row['label'])
                sources_list.append(row['source'])
                # Extract TLD
                parts = str(row['domain']).split('.')
                tld = parts[-1] if len(parts) > 1 else ''
                tlds_list.append(tld)
            except Exception as e:
                # Skip data with errors
                continue

        # Progress display
        processed = end_idx
        progress = processed / len(all_data) * 100
        elapsed = time.time() - start_time
        eta = elapsed / processed * len(all_data) - elapsed if processed > 0 else 0
        print(f"\r   Progress: {processed:,}/{len(all_data):,} ({progress:.1f}%) - "
              f"Elapsed: {elapsed:.1f}s - ETA: {eta:.1f}s", end='', flush=True)

    print("\n   Feature extraction complete")

    # Convert to NumPy arrays
    X = np.array(features_list)
    y = np.array(labels_list)
    domains = np.array(domains_list)
    sources = np.array(sources_list)
    tlds = np.array(tlds_list)

    print(f"   Generated: {len(X):,} samples, {X.shape[1]} features")
    print(f"   Processing time: {time.time() - start_time:.1f}s")

    # Train/test split (80:20)
    print("\n   Splitting data...")
    X_train, X_test, y_train, y_test, domain_train, domain_test, source_train, source_test, tld_train, tld_test = train_test_split(
        X, y, domains, sources, tlds,
        test_size=0.2,
        random_state=42,
        stratify=y
    )

    print(f"   Train: {len(X_train):,} samples")
    print(f"   Test:  {len(X_test):,} samples")

    # Save train_data.pkl and test_data.pkl
    print("\n   Saving processed data...")
    train_data = {
        'X': X_train,
        'y': y_train,
        'domains': domain_train,
        'sources': source_train,
        'tlds': tld_train,
        'feature_names': FEATURE_ORDER
    }

    test_data = {
        'X': X_test,
        'y': y_test,
        'domains': domain_test,
        'sources': source_test,
        'tlds': tld_test,
        'eval_imbalance': {"enabled": False},
        'feature_names': FEATURE_ORDER
    }

    joblib.dump(train_data, train_pkl)
    joblib.dump(test_data, test_pkl)
    print(f"   Saved: {train_pkl.name}")
    print(f"   Saved: {test_pkl.name}")

    feature_names = FEATURE_ORDER

    print(f"\n   Train: {X_train.shape[0]:,} samples, {X_train.shape[1]} features")
    print(f"   Test:  {X_test.shape[0]:,} samples")

    # ================================================================
    # Step 4: Train XGBoost (Stage1) - Always train with new features
    # ================================================================
    # CHANGELOG (2026-01-10):
    # - Always train new model to ensure consistency with new brand_keywords
    # - Matches 02_original.ipynb behavior exactly
    # ================================================================
    print("\n" + "-" * 40)
    print("[4/9] Training XGBoost (Stage1)...")

    model_path = models_dir / "xgboost_model.pkl"
    scaler_path = models_dir / "scaler.pkl"

    # Always train new model (matches notebook behavior)
    print("   Training new model with fresh features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)

    X_tr, X_val, y_tr, y_val = train_test_split(
        X_train_scaled, y_train,
        test_size=cfg['xgb_val_size'],
        random_state=42,
        stratify=y_train
    )

    model = xgb.XGBClassifier(
        n_estimators=cfg['xgb_n_estimators'],
        max_depth=cfg['xgb_max_depth'],
        learning_rate=cfg['xgb_learning_rate'],
        random_state=42,
        eval_metric='logloss',
        early_stopping_rounds=cfg['xgb_early_stopping_rounds'],
    )
    model.fit(X_tr, y_tr, eval_set=[(X_val, y_val)], verbose=False)

    # Save model
    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)
    print(f"   Model saved: {model_path.name}")
    print(f"   Scaler saved: {scaler_path.name}")

    # Scale test data
    X_test_scaled = scaler.transform(X_test)
    X_train_scaled = scaler.transform(X_train)

    # ================================================================
    # Step 5: Select Route1 Thresholds
    # ================================================================
    print("\n" + "-" * 40)
    print("[5/9] Selecting Route1 thresholds...")

    # Predict on validation subset for threshold selection
    val_size = int(len(X_test_scaled) * 0.4)
    p_val = model.predict_proba(X_test_scaled[:val_size])[:, 1]
    y_val = y_test[:val_size]

    t_low, t_high, route1_meta = select_route1_thresholds(y_val, p_val, cfg)
    print(f"   t_low:  {t_low:.6f}")
    print(f"   t_high: {t_high:.6f}")

    # Save thresholds
    thresholds_path = results_dir / "route1_thresholds.json"
    with open(thresholds_path, 'w') as f:
        json.dump(route1_meta, f, indent=2)
    print(f"   Saved: {thresholds_path.name}")

    # ================================================================
    # Step 6: Stage1 Decisions
    # ================================================================
    print("\n" + "-" * 40)
    print("[6/9] Generating Stage1 decisions...")

    p_test = model.predict_proba(X_test_scaled)[:, 1]
    n_test = len(p_test)

    stage1_decision = np.where(
        p_test <= t_low, "auto_benign",
        np.where(p_test >= t_high, "auto_phishing", "handoff_to_agent")
    )

    df_stage1 = pd.DataFrame({
        'domain': domain_test,
        'source': source_test,
        'ml_probability': p_test,
        'stage1_decision': stage1_decision,
        'y_true': y_test.astype(int),
    })

    # Save stage1_decisions_latest.csv
    stage1_csv = results_dir / "stage1_decisions_latest.csv"
    df_stage1.to_csv(stage1_csv, index=False)
    print(f"   Saved: {stage1_csv.name}")

    # Stats
    mask_auto_benign = stage1_decision == "auto_benign"
    mask_auto_phish = stage1_decision == "auto_phishing"
    mask_handoff = stage1_decision == "handoff_to_agent"

    n_auto_benign = mask_auto_benign.sum()
    n_auto_phish = mask_auto_phish.sum()
    n_handoff = mask_handoff.sum()

    print(f"   auto_benign:   {n_auto_benign:,} ({100*n_auto_benign/n_test:.1f}%)")
    print(f"   auto_phishing: {n_auto_phish:,} ({100*n_auto_phish/n_test:.1f}%)")
    print(f"   handoff:       {n_handoff:,} ({100*n_handoff/n_test:.1f}%)")

    # ================================================================
    # Step 7: Stage2 LR Training + Gate
    # ================================================================
    print("\n" + "-" * 40)
    print("[7/9] Running Stage2 gate...")

    # Get handoff candidates
    handoff_idx = np.where(mask_handoff)[0]
    df_defer = df_stage1.iloc[handoff_idx].copy()
    X_defer = X_test_scaled[handoff_idx]
    p1_defer = p_test[handoff_idx]
    y_defer = y_test[handoff_idx]
    domains_defer = np.array(domain_test)[handoff_idx]
    tlds_defer = np.array(tld_test)[handoff_idx]
    sources_defer = np.array(source_test)[handoff_idx]

    # Train Stage2 LR (OOF on training data)
    y_hat_train = (model.predict_proba(X_train_scaled)[:, 1] >= 0.5).astype(int)
    err_train = (y_hat_train != y_train).astype(int)

    print("   Training Stage2 LR (OOF)...")
    lr_model, lr_scaler, _ = train_stage2_lr_oof(X_train_scaled, y_train, err_train, cfg)

    # Save LR model
    joblib.dump(lr_model, models_dir / "lr_defer_model.pkl")
    joblib.dump(lr_scaler, models_dir / "lr_defer_scaler.pkl")

    # Run gate
    selected_mask, gate_trace, stage2_stats = run_stage2_gate(
        df_defer, X_defer, p1_defer, y_defer, domains_defer, tlds_defer,
        sources_defer, brand_keywords, cfg, lr_model, lr_scaler
    )

    print(f"   Mode:          {stage2_stats['mode']}")
    if 'priority_pool' in stage2_stats:
        print(f"   Priority pool: {stage2_stats['priority_pool']:,}")
    print(f"   Selected:      {stage2_stats['selected_final']:,}")

    # Save gate trace
    gate_trace['idx'] = handoff_idx
    gate_trace_path = results_dir / "stage2_decisions_candidates_latest.csv"
    gate_trace.to_csv(gate_trace_path, index=False)
    print(f"   Saved: {gate_trace_path.name}")

    # ================================================================
    # Step 8: Stage2 Decisions (full dataset)
    # ================================================================
    print("\n" + "-" * 40)
    print("[8/9] Building Stage2 decisions...")

    stage2_candidate = mask_handoff.astype(int)
    stage2_selected = np.zeros(n_test, dtype=int)
    stage2_selected[handoff_idx[selected_mask]] = 1

    stage2_decision = np.where(
        ~mask_handoff, "not_candidate",
        np.where(stage2_selected == 1, "handoff_to_agent", "drop_to_auto")
    )

    stage1_pred = (p_test >= 0.5).astype(int)

    df_stage2 = pd.DataFrame({
        'idx': np.arange(n_test),
        'domain': domain_test,
        'source': source_test,
        'ml_probability': p_test,
        'stage1_decision': stage1_decision,
        'y_true': y_test.astype(int),
        'stage2_candidate': stage2_candidate,
        'stage2_selected': stage2_selected,
        'stage2_decision': stage2_decision,
        'stage1_pred': stage1_pred,
    })

    stage2_csv = results_dir / "stage2_decisions_latest.csv"
    df_stage2.to_csv(stage2_csv, index=False)
    print(f"   Saved: {stage2_csv.name}")

    # ================================================================
    # Step 9: Handoff Candidates + Evaluation
    # ================================================================
    print("\n" + "-" * 40)
    print("[9/9] Saving outputs...")

    # Get selected samples
    selected_idx = handoff_idx[selected_mask]
    df_handoff = df_stage1.iloc[selected_idx].copy()

    # Rename ml_probability to prediction_proba for 03 system compatibility
    df_handoff = df_handoff.rename(columns={'ml_probability': 'prediction_proba'})

    # Build payload
    payload = {
        "analysis_df": df_handoff,
        "meta": {
            "t_low": float(t_low),
            "t_high": float(t_high),
            "created_at": datetime.now().isoformat(),
            "note": f"Stage-2 selection (mode={cfg['stage2_select_mode']}, max_budget={cfg['stage2_max_budget']}).",
            "stage2": {
                "method": "segment_priority",
                "select_mode": str(cfg['stage2_select_mode']),
                "max_budget": int(cfg['stage2_max_budget']),
                "handoff_budget": int(len(selected_idx)),
                "oof_folds": int(cfg['stage2_oof_folds']),
                "features": ["domain_features", "p1"],
                "select_stats": stage2_stats,
            },
        },
    }

    # Save handoff candidates
    handoff_pkl = handoff_dir / "handoff_candidates_latest.pkl"
    handoff_csv = handoff_dir / "handoff_candidates_latest.csv"
    joblib.dump(payload, handoff_pkl)
    df_handoff.to_csv(handoff_csv, index=False)
    print(f"   Saved: {handoff_pkl.name}")
    print(f"   Saved: {handoff_csv.name}")

    # Save with threshold suffix
    suffix = f"tl{t_low:g}_th{t_high:g}".replace(".", "p")
    joblib.dump(payload, handoff_dir / f"handoff_candidates_{suffix}.pkl")
    df_handoff.to_csv(handoff_dir / f"handoff_candidates_{suffix}.csv", index=False)

    # Save false_negatives_reconstructed.pkl (compat for 03 system)
    compat_pkl_primary = results_dir / "false_negatives_reconstructed.pkl"
    compat_pkl = compat_results / "false_negatives_reconstructed.pkl"
    joblib.dump(payload, compat_pkl_primary)
    joblib.dump(payload, compat_pkl)
    print(f"   Saved: {compat_pkl_primary}")
    print(f"   Saved: {compat_pkl}")

    # Evaluation metrics
    y_hat_test = (p_test >= 0.5).astype(int)
    err_test = (y_hat_test != y_test).astype(int)

    final_handoff_mask = stage2_selected == 1
    final_auto_mask = ~final_handoff_mask

    final_auto_err = int(err_test[final_auto_mask].sum())
    final_auto_err_rate = float(err_test[final_auto_mask].mean()) if final_auto_mask.any() else 0.0

    cm_gate = confusion_matrix(err_test, final_handoff_mask.astype(int), labels=[0, 1])
    tn_g, fp_g, fn_g, tp_g = cm_gate.ravel()
    prec_g = tp_g / (tp_g + fp_g) if (tp_g + fp_g) > 0 else 0.0
    rec_g = tp_g / (tp_g + fn_g) if (tp_g + fn_g) > 0 else 0.0
    f1_g = (2 * prec_g * rec_g / (prec_g + rec_g)) if (prec_g + rec_g) > 0 else 0.0

    eval_json = {
        "N_all": int(n_test),
        "N_stage1_handoff_region": int(n_handoff),
        "N_stage2_handoff": int(final_handoff_mask.sum()),
        "N_auto": int(final_auto_mask.sum()),
        "auto_errors": int(final_auto_err),
        "auto_error_rate": float(final_auto_err_rate),
        "stage2_select": stage2_stats,
        "gate_all": {
            "tn": int(tn_g), "fp": int(fp_g), "fn": int(fn_g), "tp": int(tp_g),
            "precision": float(prec_g), "recall": float(rec_g), "f1": float(f1_g)
        },
    }

    eval_path = results_dir / "stage2_budget_eval.json"
    with open(eval_path, 'w') as f:
        json.dump(eval_json, f, indent=2)
    print(f"   Saved: {eval_path.name}")

    # PENDING analysis
    pending_mask = (df_stage2['stage2_candidate'] == 1) & (df_stage2['stage2_selected'] == 0)
    pending_phish = ((pending_mask) & (df_stage2['y_true'] == 1)).sum()
    pending_total = pending_mask.sum()

    df_pending = df_stage2[pending_mask].copy()
    pending_csv = results_dir / "stage2_pending_latest.csv"
    df_pending.to_csv(pending_csv, index=False)
    print(f"   Saved: {pending_csv.name}")

    # ================================================================
    # Summary
    # ================================================================
    print("\n" + "=" * 80)
    print("Pipeline Complete!")
    print("=" * 80)
    print(f"\nRUN_ID: {run_id}")
    print(f"Artifacts: {artifacts_dir}")
    print("\nSummary:")
    print(f"  - Total samples:     {n_test:,}")
    print(f"  - AUTO (benign):     {n_auto_benign:,}")
    print(f"  - AUTO (phishing):   {n_auto_phish:,}")
    print(f"  - DEFER (Stage1):    {n_handoff:,}")
    print(f"  - Handoff (Stage2):  {stage2_stats['selected_final']:,}")
    print(f"  - PENDING:           {pending_total:,}")
    print(f"  - PENDING Phish:     {pending_phish:,}")
    print("=" * 80)

    return 0


# ============================================================
# Entry Point
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="02 Stage1/Stage2 Pipeline (compatible with 02_original.ipynb)"
    )

    parser.add_argument('--run', action='store_true',
                       help='Run the full pipeline')
    parser.add_argument('--run-id', type=str,
                       help='RUN_ID to use (default: auto-resolve)')
    parser.add_argument('--config', type=str,
                       help='Config file path (YAML)')

    args = parser.parse_args()

    if not args.run:
        parser.print_help()
        return 0

    # Load .env
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    # Get RUN_ID
    print("\nResolving RUN_ID...")
    run_id = get_run_id(args.run_id)

    # Get config
    cfg = get_default_config()

    # Load YAML config if specified
    if args.config:
        import yaml
        with open(args.config) as f:
            yaml_cfg = yaml.safe_load(f)
        cfg.update(yaml_cfg)

    # Run pipeline
    return run_pipeline(run_id, cfg)


if __name__ == '__main__':
    sys.exit(main())
