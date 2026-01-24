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

# Import vLLM manager for automatic server lifecycle
from scripts.vllm_manager import VLLMManager


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
        # XGBoost (optimized via Optuna - Trial 25)
        'xgb_val_size': 0.10,
        'xgb_n_estimators': model_cfg.get('n_estimators', 500),
        'xgb_max_depth': model_cfg.get('max_depth', 10),
        'xgb_learning_rate': model_cfg.get('learning_rate', 0.206),
        'xgb_min_child_weight': model_cfg.get('min_child_weight', 6),
        'xgb_subsample': model_cfg.get('subsample', 0.77),
        'xgb_colsample_bytree': model_cfg.get('colsample_bytree', 0.70),
        'xgb_gamma': model_cfg.get('gamma', 2.38),
        'xgb_reg_alpha': model_cfg.get('reg_alpha', 0.11),
        'xgb_reg_lambda': model_cfg.get('reg_lambda', 2.37),
        'xgb_early_stopping_rounds': model_cfg.get('early_stopping_rounds', 50),

        # Route1 thresholds
        'xgb_t_mode': 'auto_from_val',
        'xgb_risk_max_auto_benign': 0.001,
        'xgb_risk_max_auto_phish': 0.0002,
        'xgb_min_auto_samples': 200,
        'xgb_risk_use_upper': True,
        'xgb_risk_alpha': 0.05,

        # Data Quality Filter (証明書データ品質フィルター)
        # 証明書データが欠損しているサンプルをStage1から除外
        'stage1_require_cert_data': True,

        # Stage2 (defaults match 02_original.ipynb Cell 37)
        'stage2_select_mode': 'threshold_cap',  # default in notebook
        'stage2_max_budget': 0,  # 0 = disabled (variable-size handoff)
        'stage2_tau': 0.40,  # optimized via feature search (was 0.60)
        'stage2_override_tau': 0.30,
        'stage2_phi_phish': 0.99,
        'stage2_phi_benign': 0.01,
        'stage2_seg_only_benign': False,
        'stage2_seg_optional': True,
        'stage2_seg_include_idn': True,
        'stage2_seg_include_brand': True,
        'stage2_seg_min_p1': 0.00,
        'stage2_oof_folds': 5,

        # Scenario 5: Auto-BENIGN filter (reduce Stage3 handoff)
        # Cases with p1 < safe_benign_p1_max AND defer_score < safe_benign_defer_max
        # are considered safe to auto-classify as BENIGN (skip Stage3)
        'stage2_safe_benign_enabled': True,
        'stage2_safe_benign_p1_max': 0.15,
        'stage2_safe_benign_defer_max': 0.40,

        # Scenario 8: High ML Phishing (高ML フィッシング救済)
        # ML >= threshold のサンプルは、defer_score/uncertainty に関わらずStage3へ送る
        # これは「自信を持ってフィッシング」と予測されたサンプルがドロップされる問題を修正
        'stage2_high_ml_phish_enabled': True,
        'stage2_high_ml_phish_threshold': 0.50,  # ML >= 0.50 なら Stage3 へ

        # Scenario 6: Certificate-based early termination rules
        # These rules use certificate features to make early decisions
        'stage2_cert_rules_enabled': True,
        # Safe BENIGN rules (skip Stage3, mark as BENIGN)
        'stage2_cert_benign_crl_enabled': True,       # CRL保有 → 正規寄り
        'stage2_cert_benign_crl_p1_max': 0.30,        # CRLルールのp1閾値
        'stage2_cert_benign_ov_ev_enabled': True,     # OV/EV証明書 → 確実に正規
        'stage2_cert_benign_wildcard_enabled': True,  # ワイルドカード → 正規寄り
        'stage2_cert_benign_long_validity_enabled': True,  # 長期有効期間 → 正規寄り
        'stage2_cert_benign_long_validity_days': 180,
        'stage2_cert_benign_long_validity_p1_max': 0.25,
        # Safe PHISHING rules (skip Stage3, mark as PHISHING)
        'stage2_cert_phish_tier1_tld_enabled': True,  # Tier1危険TLD + LE → フィッシング
        'stage2_cert_phish_tier1_tlds': ['gq', 'ga', 'ci', 'cfd', 'tk'],
        'stage2_cert_phish_dynamic_dns_enabled': True,  # 動的DNS + 大量SAN
        'stage2_cert_phish_dynamic_dns_san_min': 20,

        # Scenario 7: TLD-based filtering (証明書ルールのFN削減)
        # TLDの信頼性に基づいて証明書ルールの適用を制限
        'stage2_tld_filtering_enabled': True,
        # 安全なTLD: 政府・教育機関、先進国ccTLD（フィッシング率 < 2%）
        'stage2_tld_safe': [
            'gov', 'edu', 'fi', 'ie', 'tv', 'at', 'nl', 'se', 'be',
            'uk', 'de', 'fr', 'au', 'jp', 'nz', 'ca', 'ch', 'it', 'es'
        ],
        # 危険なTLD: フィッシング率が高い（>15%）または無料/格安で悪用されやすい
        'stage2_tld_dangerous': [
            # 超危険（>90%）
            'mw', 'ci', 'cfd', 'icu', 'cn', 'buzz', 'dev', 'pw',
            'cyou', 'tokyo', 'xyz', 'club', 'top', 'shop', 'sbs',
            'vip', 'asia', 'cc', 'one', 'rest', 'link', 'click',
            # 高危険（>50%）
            'lat', 'gq', 'ga', 'tk', 'ml', 'cf',
            # 中危険（>15%）- FN分析から追加
            'online', 'site', 'website', 'me', 'pe', 'ar', 'cl',
        ],
        # 中立TLD: 証明書ルール適用には低MLが必要
        'stage2_tld_neutral': ['com', 'net', 'org', 'info', 'biz'],
        'stage2_tld_neutral_p1_max': 0.03,  # 中立TLDでの証明書ルール適用閾値

        # Dangerous TLDs
        'dangerous_tlds': [
            'icu', 'top', 'xyz', 'buzz', 'cfd', 'cyou', 'rest',
            'tk', 'ml', 'ga', 'cf', 'gq', 'sbs', 'click', 'link',
            'online', 'site', 'website'
        ],

        # LLM (from config.json llm section)
        'llm_enabled': llm_cfg.get('enabled', True),
        'llm_base_url': llm_cfg.get('base_url') or llm_cfg.get('vllm_base_url') or os.getenv('VLLM_BASE_URL', 'http://127.0.0.1:8000/v1'),
        'llm_model': llm_cfg.get('model') or llm_cfg.get('vllm_model') or os.getenv('BRAND_LLM_MODEL', 'Qwen/Qwen3-4B'),
        'llm_api_key': llm_cfg.get('api_key') or os.getenv('VLLM_API_KEY', 'EMPTY'),
        # vLLM auto management (自動起動・停止)
        'vllm_auto_manage': llm_cfg.get('auto_manage', True),
        'vllm_startup_timeout': llm_cfg.get('startup_timeout', 120),
        'vllm_gpu_memory_utilization': llm_cfg.get('gpu_memory_utilization', 0.85),

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
# CHANGELOG (2026-01-16):
# - Added JPCERT description as brand candidate source
# - Added Japanese brand name mapping table
# - Merged PhishTank and JPCERT candidates
# ============================================================

# Japanese brand name to English keyword mapping
# These are common Japanese phishing targets that need explicit mapping
JAPANESE_BRAND_MAPPING = {
    # Banks
    '三井住友カード': 'smbc',
    '三井住友銀行': 'smbc',
    '三菱UFJニコス': 'mufg',
    '三菱UFJ銀行': 'mufg',
    'みずほ銀行': 'mizuho',
    'りそな銀行': 'resona',
    'イオン銀行': 'aeonbank',
    'PayPay銀行': 'paypaybank',
    'GMOあおぞらネット銀行': 'gmoaozora',
    # Cards
    'イオンカード': 'aeoncard',
    'エポスカード': 'eposcard',
    '楽天カード': 'rakutencard',
    'クレディセゾン': 'saison',
    'JCB': 'jcb',
    'ビューカード': 'viewcard',
    'Viewcard': 'viewcard',
    'TS CUBIC CARD': 'tscubiccard',
    'MICARD': 'micard',
    'JACCS': 'jaccs',
    'Orico': 'orico',
    # Telecoms
    'NTT docomo': 'docomo',
    'ドコモ': 'docomo',
    'softbank': 'softbank',
    'ソフトバンク': 'softbank',
    'au': 'au',
    'KDDI': 'kddi',
    # EC/Services
    'メルカリ': 'mercari',
    '楽天': 'rakuten',
    'ヤマト運輸': 'yamato',
    '佐川急便': 'sagawa',
    '日本郵便': 'japanpost',
    'えきねっと': 'ekinet',
    'ETC利用照会サービス': 'etc',
    'ヨドバシカメラ': 'yodobashi',
    # Government
    '国税庁': 'nta',
    '総務省': 'soumu',
    # Utilities
    'TEPCO': 'tepco',
    '東京電力': 'tepco',
    # Others
    'BIGLOBE': 'biglobe',
    'NHK': 'nhk',
    'NHKプラス': 'nhk',
    'LINE': 'line',
    'PayPay': 'paypay',
    'FamilyMart': 'familymart',
    # International
    'Amazon': 'amazon',
    'Apple ID': 'apple',
    'Apple': 'apple',
    'Microsoft': 'microsoft',
    'Netflix': 'netflix',
    'PayPal': 'paypal',
    'American Express': 'amex',
    'DHL': 'dhl',
    'USPS': 'usps',
    'FedEx': 'fedex',
    'UPS': 'ups',
    'PostNord': 'postnord',
}

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

    # Query jpcert_phishing_urls (description column) - now with frequency
    print("\n[3/4] Querying jpcert_phishing_urls...")
    cur.execute("""
        SELECT description, COUNT(*) as count
        FROM public.jpcert_phishing_urls
        WHERE description IS NOT NULL
          AND description <> ''
          AND description <> '-'
        GROUP BY description
        ORDER BY count DESC
        LIMIT 200
    """)
    jpcert_targets = cur.fetchall()
    jpcert_descriptions = [r[0] for r in jpcert_targets]
    print(f"   Found {len(jpcert_targets)} unique descriptions")

    cur.close()
    conn.close()

    # Build pt_counts (normalized + frequency) from PhishTank
    pt_counts = {}
    for tgt, cnt in phishtank_targets:
        nt = normalize_brand_name(tgt)
        if nt:
            pt_counts[nt] = pt_counts.get(nt, 0) + int(cnt)

    # Build jpcert_counts from JPCERT descriptions
    # Use Japanese brand mapping for known brands, otherwise normalize
    jpcert_counts = {}
    jpcert_mapped = []
    for desc, cnt in jpcert_targets:
        # Check if description matches a known Japanese brand
        if desc in JAPANESE_BRAND_MAPPING:
            keyword = JAPANESE_BRAND_MAPPING[desc]
            jpcert_counts[keyword] = jpcert_counts.get(keyword, 0) + int(cnt)
            jpcert_mapped.append((desc, keyword, cnt))
        else:
            # Try to normalize (works for English brands)
            nt = normalize_brand_name(desc)
            if nt and len(nt) >= 3:
                jpcert_counts[nt] = jpcert_counts.get(nt, 0) + int(cnt)

    print(f"   Japanese brand mappings applied: {len(jpcert_mapped)}")
    for desc, keyword, cnt in jpcert_mapped[:10]:
        print(f"      {desc} -> {keyword} (count: {cnt})")

    # Merge PhishTank and JPCERT candidates
    all_counts = {}
    for k, v in pt_counts.items():
        all_counts[k] = all_counts.get(k, 0) + v
    for k, v in jpcert_counts.items():
        all_counts[k] = all_counts.get(k, 0) + v

    print(f"   PhishTank candidates: {len(pt_counts)}")
    print(f"   JPCERT candidates: {len(jpcert_counts)}")
    print(f"   Merged candidates: {len(all_counts)}")

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
    # CHANGELOG (2026-01-16): Use merged all_counts instead of pt_counts only
    MAX_BRANDS = cfg['brand_max_brands']
    if MAX_BRANDS <= 0:
        MAX_BRANDS = float('inf')  # Unlimited
    BATCH_SIZE = 5  # Same as notebook default

    # Use merged candidates (PhishTank + JPCERT)
    candidates_sorted = [cand for cand, cnt in sorted(all_counts.items(), key=lambda x: (-x[1], x[0]))]

    # Add mapped Japanese brands directly (skip LLM validation)
    # These are known brands from the mapping table
    pre_validated_brands = set(JAPANESE_BRAND_MAPPING.values())

    BRAND_KEYWORDS = []
    _seen = set()

    # First, add pre-validated brands from mapping table (no LLM needed)
    for brand in sorted(pre_validated_brands):
        if brand not in _seen:
            BRAND_KEYWORDS.append(brand)
            _seen.add(brand)

    print(f"   Pre-validated brands (from mapping): {len(BRAND_KEYWORDS)}")

    total_candidates = len(candidates_sorted)
    processed = 0
    found = len(BRAND_KEYWORDS)
    start_ts = time.time()

    max_brands_display = "unlimited" if MAX_BRANDS == float('inf') else MAX_BRANDS
    print(f"   MAX_BRANDS: {max_brands_display}, BATCH_SIZE: {BATCH_SIZE}")
    print(f"   Total candidates to validate: {total_candidates}")

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

def compute_lr_extra_features(p1_proba: np.ndarray) -> np.ndarray:
    """
    Compute extra features for Stage2 LR from Stage1 predictions.
    Selected features: entropy + uncertainty (based on feature search).
    """
    eps = 1e-7
    p_clipped = np.clip(p1_proba, eps, 1 - eps)

    # Entropy (maximum at 0.5)
    entropy = -(p_clipped * np.log(p_clipped) +
                (1 - p_clipped) * np.log(1 - p_clipped))
    entropy = np.nan_to_num(entropy, nan=0.0)

    # Uncertainty (1.0 at p=0.5, 0.0 at p=0 or p=1)
    uncertainty = 1.0 - np.abs(p1_proba - 0.5) * 2.0

    return np.column_stack([entropy, uncertainty])


def train_stage2_lr_oof(X_train, y_train, err_train, p1_proba, cfg):
    """
    Train Stage2 Logistic Regression with Out-of-Fold predictions.
    Predicts probability of Stage1 making an error.

    Uses base features (35) + extra features (entropy, uncertainty from p1_proba).
    """
    n_folds = cfg['stage2_oof_folds']
    random_state = 42

    # Add extra features derived from Stage1 predictions
    extra_features = compute_lr_extra_features(p1_proba)
    X_combined = np.hstack([X_train, extra_features])

    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_combined)

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
        # Add extra features (entropy, uncertainty) for LR
        extra_features = compute_lr_extra_features(p1_defer)
        X_combined = np.hstack([X_defer, extra_features])
        X_scaled = lr_scaler.transform(X_combined)
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

        # ============================================================
        # Scenario 7: TLD-based filtering (証明書ルールのFN削減)
        # TLDの信頼性に基づいて証明書ルールの適用を制限
        # NOTE: TLD classification must be done FIRST so it can be used
        #       in both Scenario 5 and Scenario 6
        # ============================================================
        tld_filtering_enabled = cfg.get('stage2_tld_filtering_enabled', False)
        safe_tlds = set(cfg.get('stage2_tld_safe', []))
        dangerous_tlds_s7 = set(cfg.get('stage2_tld_dangerous', []))
        neutral_tlds = set(cfg.get('stage2_tld_neutral', []))
        neutral_p1_max = float(cfg.get('stage2_tld_neutral_p1_max', 0.03))

        # Classify TLDs
        tld_lower_arr = np.array([str(t).lower() for t in tlds_defer])
        is_safe_tld = np.isin(tld_lower_arr, list(safe_tlds))
        is_dangerous_tld_s7 = np.isin(tld_lower_arr, list(dangerous_tlds_s7))
        is_neutral_tld = np.isin(tld_lower_arr, list(neutral_tlds))
        is_other_tld = ~(is_safe_tld | is_dangerous_tld_s7 | is_neutral_tld)

        # TLD filtering stats
        tld_filter_stats = {
            'enabled': tld_filtering_enabled,
            'safe_tld_count': int(is_safe_tld.sum()),
            'dangerous_tld_count': int(is_dangerous_tld_s7.sum()),
            'neutral_tld_count': int(is_neutral_tld.sum()),
            'other_tld_count': int(is_other_tld.sum()),
            'neutral_p1_max': neutral_p1_max,
            'cert_rule_blocked_dangerous': 0,
            'cert_rule_blocked_neutral': 0,
            's5_blocked_dangerous': 0,
            's5_blocked_neutral': 0,
        }

        # ============================================================
        # Scenario 5: Safe BENIGN filter
        # Cases with low p1 AND low defer_score are auto-BENIGN
        # ============================================================
        safe_benign_enabled = cfg.get('stage2_safe_benign_enabled', False)
        safe_benign_p1_max = float(cfg.get('stage2_safe_benign_p1_max', 0.15))
        safe_benign_defer_max = float(cfg.get('stage2_safe_benign_defer_max', 0.40))

        if safe_benign_enabled:
            safe_benign_base = (p1_defer < safe_benign_p1_max) & (defer_score < safe_benign_defer_max)

            # Apply TLD filtering to Scenario 5
            if tld_filtering_enabled:
                # Safe TLDs: Apply S5 normally
                # Dangerous TLDs: Block S5 (send to Stage3)
                # Neutral TLDs: Apply S5 only if ML < neutral_p1_max
                # Other TLDs: Apply S5 only if ML < neutral_p1_max (treat as neutral)
                tld_allowed_s5 = is_safe_tld | ((is_neutral_tld | is_other_tld) & (p1_defer < neutral_p1_max))
                blocked_dangerous_s5 = safe_benign_base & is_dangerous_tld_s7
                blocked_neutral_s5 = safe_benign_base & (is_neutral_tld | is_other_tld) & (p1_defer >= neutral_p1_max)
                tld_filter_stats['s5_blocked_dangerous'] = int(blocked_dangerous_s5.sum())
                tld_filter_stats['s5_blocked_neutral'] = int(blocked_neutral_s5.sum())
                safe_benign = safe_benign_base & tld_allowed_s5
            else:
                safe_benign = safe_benign_base

            n_safe_benign = int(safe_benign.sum())
        else:
            safe_benign = np.zeros(n_defer, dtype=bool)
            n_safe_benign = 0

        # ============================================================
        # Scenario 6: Certificate-based early termination rules
        # Uses certificate features to make confident early decisions
        # ============================================================
        cert_rules_enabled = cfg.get('stage2_cert_rules_enabled', False)

        # Feature indices (from FEATURE_ORDER in features.py)
        IDX_VALIDITY = 15    # cert_validity_days
        IDX_WILDCARD = 16    # cert_is_wildcard
        IDX_SAN_COUNT = 17   # cert_san_count
        IDX_HAS_ORG = 21     # cert_subject_has_org (OV/EV indicator)
        IDX_HAS_CRL = 29     # cert_has_crl_dp
        IDX_IS_LE = 34       # cert_is_lets_encrypt

        # Initialize certificate-based masks
        safe_benign_cert = np.zeros(n_defer, dtype=bool)
        safe_phishing_cert = np.zeros(n_defer, dtype=bool)
        cert_rule_stats = {
            'enabled': cert_rules_enabled,
            'benign_crl_hits': 0,
            'benign_ov_ev_hits': 0,
            'benign_wildcard_hits': 0,
            'benign_long_validity_hits': 0,
            'phishing_tier1_tld_hits': 0,
            'phishing_dynamic_dns_hits': 0,
        }

        if cert_rules_enabled:
            # ---- Safe BENIGN rules ----
            # Rule 1: CRL Distribution Points (正規サイトの81.7%が保有)
            if cfg.get('stage2_cert_benign_crl_enabled', False):
                crl_p1_max = float(cfg.get('stage2_cert_benign_crl_p1_max', 0.30))
                # Binary feature: scaled value > 0.5 means original was 1
                has_crl = X_defer[:, IDX_HAS_CRL] > 0.5
                crl_mask = has_crl & (p1_defer < crl_p1_max)

                # Scenario 7: TLD-based filtering
                if tld_filtering_enabled:
                    # Safe TLDs: Apply normally
                    # Dangerous TLDs: Block cert rule (send to Stage3)
                    # Neutral TLDs: Apply only if ML < neutral_p1_max
                    # Other TLDs: Apply only if ML < neutral_p1_max (treat as neutral)
                    tld_allowed = is_safe_tld | ((is_neutral_tld | is_other_tld) & (p1_defer < neutral_p1_max))
                    blocked_dangerous = crl_mask & is_dangerous_tld_s7
                    blocked_neutral = crl_mask & (is_neutral_tld | is_other_tld) & (p1_defer >= neutral_p1_max)
                    tld_filter_stats['cert_rule_blocked_dangerous'] += int(blocked_dangerous.sum())
                    tld_filter_stats['cert_rule_blocked_neutral'] += int(blocked_neutral.sum())
                    crl_mask = crl_mask & tld_allowed

                safe_benign_cert |= crl_mask
                cert_rule_stats['benign_crl_hits'] = int(crl_mask.sum())

            # Rule 2: OV/EV Certificate (Subject Organizationあり)
            if cfg.get('stage2_cert_benign_ov_ev_enabled', False):
                has_org = X_defer[:, IDX_HAS_ORG] > 0.5
                ov_ev_mask = has_org.copy()

                # Scenario 7: TLD-based filtering (OV/EVは信頼性が高いのでdangerousのみブロック)
                if tld_filtering_enabled:
                    blocked_dangerous = ov_ev_mask & is_dangerous_tld_s7
                    tld_filter_stats['cert_rule_blocked_dangerous'] += int(blocked_dangerous.sum())
                    ov_ev_mask = ov_ev_mask & (~is_dangerous_tld_s7)

                safe_benign_cert |= ov_ev_mask
                cert_rule_stats['benign_ov_ev_hits'] = int(ov_ev_mask.sum())

            # Rule 3: Wildcard Certificate (正規サイトの55.1%が使用)
            if cfg.get('stage2_cert_benign_wildcard_enabled', False):
                is_wildcard = X_defer[:, IDX_WILDCARD] > 0.5
                # Exclude dangerous TLDs (既存ロジック)
                dangerous_tlds = set(cfg.get('dangerous_tlds', []))
                is_dangerous = np.array([str(t).lower() in dangerous_tlds for t in tlds_defer])
                wildcard_mask = is_wildcard & (~is_dangerous)

                # Scenario 7: TLD-based filtering
                if tld_filtering_enabled:
                    tld_allowed = is_safe_tld | ((is_neutral_tld | is_other_tld) & (p1_defer < neutral_p1_max))
                    blocked_dangerous = wildcard_mask & is_dangerous_tld_s7
                    blocked_neutral = wildcard_mask & (is_neutral_tld | is_other_tld) & (p1_defer >= neutral_p1_max)
                    tld_filter_stats['cert_rule_blocked_dangerous'] += int(blocked_dangerous.sum())
                    tld_filter_stats['cert_rule_blocked_neutral'] += int(blocked_neutral.sum())
                    wildcard_mask = wildcard_mask & tld_allowed

                safe_benign_cert |= wildcard_mask
                cert_rule_stats['benign_wildcard_hits'] = int(wildcard_mask.sum())

            # Rule 4: Long Validity Period (180日超 = 正規寄り)
            # Note: cert_validity_days is scaled, need to use df_defer for raw value
            if cfg.get('stage2_cert_benign_long_validity_enabled', False):
                validity_days_min = int(cfg.get('stage2_cert_benign_long_validity_days', 180))
                validity_p1_max = float(cfg.get('stage2_cert_benign_long_validity_p1_max', 0.25))
                # Get raw validity from df_defer if available
                if 'cert_validity_days' in df_defer.columns:
                    raw_validity = df_defer['cert_validity_days'].values
                    long_validity = (raw_validity > validity_days_min) & (p1_defer < validity_p1_max)

                    # Scenario 7: TLD-based filtering
                    if tld_filtering_enabled:
                        tld_allowed = is_safe_tld | ((is_neutral_tld | is_other_tld) & (p1_defer < neutral_p1_max))
                        blocked_dangerous = long_validity & is_dangerous_tld_s7
                        blocked_neutral = long_validity & (is_neutral_tld | is_other_tld) & (p1_defer >= neutral_p1_max)
                        tld_filter_stats['cert_rule_blocked_dangerous'] += int(blocked_dangerous.sum())
                        tld_filter_stats['cert_rule_blocked_neutral'] += int(blocked_neutral.sum())
                        long_validity = long_validity & tld_allowed

                    safe_benign_cert |= long_validity
                    cert_rule_stats['benign_long_validity_hits'] = int(long_validity.sum())

            # ---- Safe PHISHING rules ----
            # Rule 5: Tier1 Dangerous TLD + Let's Encrypt
            if cfg.get('stage2_cert_phish_tier1_tld_enabled', False):
                tier1_tlds = set(cfg.get('stage2_cert_phish_tier1_tlds', ['gq', 'ga', 'ci', 'cfd', 'tk']))
                is_tier1 = np.array([str(t).lower() in tier1_tlds for t in tlds_defer])
                is_le = X_defer[:, IDX_IS_LE] > 0.5
                tier1_mask = is_tier1 & is_le
                safe_phishing_cert |= tier1_mask
                cert_rule_stats['phishing_tier1_tld_hits'] = int(tier1_mask.sum())

            # Rule 6: Dynamic DNS + Large SAN count
            if cfg.get('stage2_cert_phish_dynamic_dns_enabled', False):
                dyn_suffixes = ['duckdns.org', 'no-ip.com', 'ddns.net', 'dynu.com',
                               'hopto.org', 'zapto.org', 'sytes.net']
                san_min = int(cfg.get('stage2_cert_phish_dynamic_dns_san_min', 20))
                is_dynamic = np.array([
                    any(str(d).lower().endswith(s) for s in dyn_suffixes)
                    for d in domains_defer
                ])
                # Get raw SAN count from df_defer
                if 'cert_san_count' in df_defer.columns:
                    raw_san_count = df_defer['cert_san_count'].values
                    dyn_dns_mask = is_dynamic & (raw_san_count >= san_min)
                    safe_phishing_cert |= dyn_dns_mask
                    cert_rule_stats['phishing_dynamic_dns_hits'] = int(dyn_dns_mask.sum())

        # Combine with Scenario 5 safe_benign
        safe_benign_combined = safe_benign | safe_benign_cert
        n_safe_benign_combined = int(safe_benign_combined.sum())
        n_safe_benign_cert = int(safe_benign_cert.sum())
        n_safe_phishing_cert = int(safe_phishing_cert.sum())

        # ============================================================
        # Scenario 8: High ML Phishing (高ML フィッシング救済)
        # ML >= threshold のサンプルは defer_score に関わらず Stage3 へ送る
        # ただし safe_benign_cert（証明書で正規と判定）は除外
        # ============================================================
        high_ml_phish_enabled = cfg.get('stage2_high_ml_phish_enabled', False)
        high_ml_phish_threshold = float(cfg.get('stage2_high_ml_phish_threshold', 0.50))

        if high_ml_phish_enabled:
            # High ML samples (potential phishing) - exclude those marked benign by cert rules
            high_ml_phish = (p1_defer >= high_ml_phish_threshold) & (~safe_benign_cert)
            n_high_ml_phish = int(high_ml_phish.sum())
        else:
            high_ml_phish = np.zeros(n_defer, dtype=bool)
            n_high_ml_phish = 0

        high_ml_stats = {
            'enabled': high_ml_phish_enabled,
            'threshold': high_ml_phish_threshold,
            'selected': n_high_ml_phish,
        }

        # Exclude safe_benign AND safe_phishing_cert from selection
        # - safe_benign_combined: auto-classified as BENIGN (skip Stage3)
        # - safe_phishing_cert: auto-classified as PHISHING (skip Stage3)
        auto_decided = safe_benign_combined | safe_phishing_cert
        # Include high_ml_phish in selection (Scenario 8)
        picked = (override | gray | high_ml_phish) & (~auto_decided)
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
                # Keep auto_decided exclusion during budget adjustment
                # Include high_ml_phish (Scenario 8) - always selected regardless of budget
                selected_idx = np.where((override | gray | high_ml_phish) & (~auto_decided))[0]
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
            # Scenario 5 stats
            'safe_benign_enabled': safe_benign_enabled,
            'safe_benign_p1_max': safe_benign_p1_max,
            'safe_benign_defer_max': safe_benign_defer_max,
            'safe_benign_filtered': n_safe_benign,
            # Scenario 6 stats (certificate-based rules)
            'cert_rules': cert_rule_stats,
            'safe_benign_cert_filtered': n_safe_benign_cert,
            'safe_phishing_cert_filtered': n_safe_phishing_cert,
            'safe_benign_combined_filtered': n_safe_benign_combined,
            # Scenario 7 stats (TLD-based filtering)
            'tld_filtering': tld_filter_stats,
            # Scenario 8 stats (High ML Phishing)
            'high_ml_phish': high_ml_stats,
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

    # safe_benign and cert-related vars are only defined in threshold_cap mode
    if 'safe_benign' not in dir():
        safe_benign = np.zeros(n_defer, dtype=bool)
    if 'safe_benign_combined' not in dir():
        safe_benign_combined = safe_benign.copy()
    if 'safe_benign_cert' not in dir():
        safe_benign_cert = np.zeros(n_defer, dtype=bool)
    if 'safe_phishing_cert' not in dir():
        safe_phishing_cert = np.zeros(n_defer, dtype=bool)
    # TLD category vars (Scenario 7) - only defined in threshold_cap mode
    if 'is_safe_tld' not in dir():
        is_safe_tld = np.zeros(n_defer, dtype=bool)
    if 'is_dangerous_tld_s7' not in dir():
        is_dangerous_tld_s7 = np.zeros(n_defer, dtype=bool)
    if 'is_neutral_tld' not in dir():
        is_neutral_tld = np.zeros(n_defer, dtype=bool)
    if 'is_other_tld' not in dir():
        is_other_tld = np.zeros(n_defer, dtype=bool)
    # High ML Phishing (Scenario 8) - only defined in threshold_cap mode
    if 'high_ml_phish' not in dir():
        high_ml_phish = np.zeros(n_defer, dtype=bool)

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
        'safe_benign': safe_benign.astype(int),  # Scenario 5: auto-BENIGN filter
        'safe_benign_cert': safe_benign_cert.astype(int),  # Scenario 6: cert-based auto-BENIGN
        'safe_phishing_cert': safe_phishing_cert.astype(int),  # Scenario 6: cert-based auto-PHISHING
        'safe_benign_combined': safe_benign_combined.astype(int),  # Combined (Scenario 5 + 6)
        # Scenario 7: TLD categories
        'tld_safe': is_safe_tld.astype(int),
        'tld_dangerous': is_dangerous_tld_s7.astype(int),
        'tld_neutral': is_neutral_tld.astype(int),
        'tld_other': is_other_tld.astype(int),
        # Scenario 8: High ML Phishing
        'high_ml_phish': high_ml_phish.astype(int),
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
    # Step 1: Brand Keywords (LLM or cached)
    # ================================================================
    print("\n" + "-" * 40)
    print("[1/9] Brand keyword extraction...")

    brand_path = models_dir / "brand_keywords.json"
    if brand_path.exists():
        print(f"   Using existing: {brand_path.name}")
        with open(brand_path, 'r') as f:
            brand_keywords = json.load(f)
        print(f"   Loaded {len(brand_keywords)} brand keywords")
    else:
        print("   Extracting via LLM...")
        # Auto-manage vLLM server if configured
        if cfg.get('vllm_auto_manage', True):
            with VLLMManager(
                cfg,
                startup_timeout=cfg.get('vllm_startup_timeout', 120),
                gpu_memory_utilization=cfg.get('vllm_gpu_memory_utilization', 0.85),
            ):
                brand_keywords = extract_brands_via_llm(cfg)
        else:
            brand_keywords = extract_brands_via_llm(cfg)
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

    # ================================================================
    # Generate cert_full_info_map from prepared_data (for Stage3)
    # ================================================================
    print("\n   Building cert_full_info_map from prepared_data...")
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
    from datetime import datetime as _dt, timezone as _tz

    def _parse_cert_to_info(cert_data, domain=None):
        """Parse certificate data and extract info for cert_full_info_map."""
        info = {
            # 既存フィールド
            'issuer_org': None,
            'cert_age_days': 0,
            'is_free_ca': False,
            'san_count': 1,
            'is_wildcard': False,
            'is_self_signed': False,
            'has_organization': False,
            'not_before': None,
            'not_after': None,
            'validity_days': 0,
            'valid_days': 0,            # validity_days のエイリアス（互換性用）
            'has_certificate': False,
            'has_crl_dp': False,        # CRL Distribution Point 有無（互換性用）
            # 追加フィールド（LLM/人間可読用）
            'key_type': None,           # "RSA", "EC", "DSA", or None
            'key_size': None,           # 2048, 4096, 256, etc.
            'issuer_country': None,     # "US", "GB", etc.
            'issuer_type': None,        # "Let's Encrypt", "Google", "Cloudflare", "Commercial", or None
            'signature_algorithm': None, # "sha256WithRSAEncryption", etc.
            'common_name': None,        # CN field value
            'subject_org': None,        # Subject organization name (string, not just bool)
        }
        if cert_data is None:
            return info

        _cert_bytes = None
        if isinstance(cert_data, (bytes, bytearray)):
            _cert_bytes = bytes(cert_data)
        elif isinstance(cert_data, dict):
            for _k in ("der", "cert_der", "bytes", "data", "raw"):
                if _k in cert_data and cert_data[_k]:
                    _cert_bytes = bytes(cert_data[_k])
                    break

        if not _cert_bytes:
            return info

        try:
            cert = x509.load_der_x509_certificate(_cert_bytes, default_backend())
        except Exception:
            try:
                cert = x509.load_pem_x509_certificate(_cert_bytes, default_backend())
            except Exception:
                return info

        info['has_certificate'] = True

        # Issuer organization
        try:
            issuer_org_attrs = cert.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
            if issuer_org_attrs:
                info['issuer_org'] = issuer_org_attrs[0].value
        except Exception:
            pass

        # Validity
        try:
            not_before = cert.not_valid_before_utc.replace(tzinfo=None)
            not_after = cert.not_valid_after_utc.replace(tzinfo=None)
            info['not_before'] = not_before
            info['not_after'] = not_after
            info['cert_age_days'] = (_dt.now(_tz.utc).replace(tzinfo=None) - not_before).days
            _validity = (not_after - not_before).days
            info['validity_days'] = _validity
            info['valid_days'] = _validity  # エイリアス（互換性用）
        except Exception:
            pass

        # CRL Distribution Points
        try:
            crl_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.CRL_DISTRIBUTION_POINTS)
            info['has_crl_dp'] = crl_ext is not None
        except x509.ExtensionNotFound:
            info['has_crl_dp'] = False
        except Exception:
            pass

        # Free CA detection
        free_ca_list = ["let's encrypt", "zerosll", "cloudflare", "cpanel", "sectigo"]
        if info['issuer_org']:
            issuer_lower = info['issuer_org'].lower()
            info['is_free_ca'] = any(ca in issuer_lower for ca in free_ca_list)

        # SAN count
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            info['san_count'] = len(san_ext.value)
        except Exception:
            pass

        # Wildcard, self-signed, has_organization
        try:
            cn_attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            if cn_attrs:
                cn = cn_attrs[0].value
                info['is_wildcard'] = cn.startswith('*.')
        except Exception:
            pass

        info['is_self_signed'] = (cert.issuer == cert.subject)

        try:
            org_attrs = cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
            info['has_organization'] = bool(org_attrs)
            if org_attrs:
                info['subject_org'] = org_attrs[0].value
        except Exception:
            pass

        # === 追加フィールドの抽出 ===

        # Common Name (CN)
        try:
            cn_attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            if cn_attrs:
                info['common_name'] = cn_attrs[0].value
        except Exception:
            pass

        # Key type and size
        try:
            pk = cert.public_key()
            if isinstance(pk, rsa.RSAPublicKey):
                info['key_type'] = 'RSA'
                info['key_size'] = pk.key_size
            elif isinstance(pk, ec.EllipticCurvePublicKey):
                info['key_type'] = 'EC'
                info['key_size'] = pk.key_size
            elif isinstance(pk, dsa.DSAPublicKey):
                info['key_type'] = 'DSA'
                info['key_size'] = pk.key_size
        except Exception:
            pass

        # Issuer country
        try:
            country_attrs = cert.issuer.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)
            if country_attrs:
                info['issuer_country'] = country_attrs[0].value
        except Exception:
            pass

        # Issuer type (human-readable)
        try:
            issuer_l = (info['issuer_org'] or '').lower()
            if "let's encrypt" in issuer_l or "letsencrypt" in issuer_l:
                info['issuer_type'] = "Let's Encrypt"
            elif 'google' in issuer_l:
                info['issuer_type'] = 'Google'
            elif 'cloudflare' in issuer_l:
                info['issuer_type'] = 'Cloudflare'
            elif 'amazon' in issuer_l or 'aws' in issuer_l:
                info['issuer_type'] = 'Amazon'
            elif 'microsoft' in issuer_l or 'azure' in issuer_l:
                info['issuer_type'] = 'Microsoft'
            elif any(ca in issuer_l for ca in ['digicert', 'comodo', 'sectigo', 'geotrust', 'thawte', 'entrust', 'globalsign', 'godaddy']):
                info['issuer_type'] = 'Commercial CA'
            elif 'zerossl' in issuer_l or 'cpanel' in issuer_l:
                info['issuer_type'] = 'Free CA'
        except Exception:
            pass

        # Signature algorithm
        try:
            sig_algo = cert.signature_algorithm_oid
            # OIDから名前を取得
            info['signature_algorithm'] = sig_algo._name if hasattr(sig_algo, '_name') else str(sig_algo.dotted_string)
        except Exception:
            pass

        return info

    # Build cert_full_info_map
    cert_full_info_map = {}
    parse_errors = 0
    for _, row in all_data.iterrows():
        domain = row['domain']
        if domain not in cert_full_info_map:
            info = _parse_cert_to_info(row['cert_data'], domain)
            if info['has_certificate']:
                cert_full_info_map[domain] = info
            else:
                parse_errors += 1

    print(f"   cert_full_info_map: {len(cert_full_info_map):,} domains")
    if parse_errors > 0:
        print(f"   Parse errors: {parse_errors:,} (excluded from map)")

    # Filter: Remove samples without valid certificate data (using cert_full_info_map)
    if cfg['stage1_require_cert_data'] and parse_errors > 0:
        print("\n   Filtering samples without valid certificate data...")
        before_filter = len(all_data)
        valid_cert_mask = all_data['domain'].isin(cert_full_info_map.keys())
        filtered_domains = all_data[~valid_cert_mask]['domain'].tolist()
        all_data = all_data[valid_cert_mask].reset_index(drop=True)
        filtered_count = before_filter - len(all_data)

        print(f"   Certificate data filter: {filtered_count:,} samples removed (unparseable cert)")
        print(f"   After filter: {len(all_data):,} samples")
        print(f"     Phishing: {len(all_data[all_data['label'] == 1]):,}")
        print(f"     Trusted:  {len(all_data[all_data['label'] == 0]):,}")
        # Log filtered domains for debugging
        if filtered_count <= 50:
            print(f"   Filtered domains: {filtered_domains}")

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
        min_child_weight=cfg['xgb_min_child_weight'],
        subsample=cfg['xgb_subsample'],
        colsample_bytree=cfg['xgb_colsample_bytree'],
        gamma=cfg['xgb_gamma'],
        reg_alpha=cfg['xgb_reg_alpha'],
        reg_lambda=cfg['xgb_reg_lambda'],
        random_state=42,
        eval_metric='logloss',
        early_stopping_rounds=cfg['xgb_early_stopping_rounds'],
        tree_method='hist',
        device='cuda',  # GPU acceleration
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

    # === df_stage1 の構築（仕様書 SPEC-DATA-001 準拠） ===

    # 基本情報カラム（8列）
    df_stage1 = pd.DataFrame({
        'domain': domain_test,
        'source': source_test,
        'tld': tld_test,
        'ml_probability': p_test,
        'stage1_decision': stage1_decision,
        'stage1_pred': (p_test >= 0.5).astype(int),
        'y_true': y_test.astype(int),
        'label': y_test.astype(int),  # y_true のエイリアス（互換性用）
    })

    # ML特徴量カラム（42列、ml_ プレフィックス）
    for i, feat_name in enumerate(FEATURE_ORDER):
        df_stage1[f'ml_{feat_name}'] = X_test[:, i]

    # 証明書情報カラム（20列、cert_ プレフィックス）
    cert_info_fields = [
        'issuer_org', 'cert_age_days', 'is_free_ca', 'san_count',
        'is_wildcard', 'is_self_signed', 'has_organization',
        'not_before', 'not_after', 'validity_days', 'valid_days',
        'has_certificate', 'has_crl_dp',
        'key_type', 'key_size', 'issuer_country', 'issuer_type',
        'signature_algorithm', 'common_name', 'subject_org',
    ]
    for field in cert_info_fields:
        df_stage1[f'cert_{field}'] = [
            cert_full_info_map.get(d, {}).get(field)
            for d in domain_test
        ]

    print(f"   df_stage1 columns: {len(df_stage1.columns)}")

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
    p1_train = model.predict_proba(X_train_scaled)[:, 1]
    y_hat_train = (p1_train >= 0.5).astype(int)
    err_train = (y_hat_train != y_train).astype(int)

    print("   Training Stage2 LR (OOF) with entropy+uncertainty features...")
    lr_model, lr_scaler, _ = train_stage2_lr_oof(X_train_scaled, y_train, err_train, p1_train, cfg)

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
    if stage2_stats.get('safe_benign_enabled', False):
        print(f"   Safe BENIGN:   {stage2_stats['safe_benign_filtered']:,} (p1<{stage2_stats['safe_benign_p1_max']}, defer<{stage2_stats['safe_benign_defer_max']})")
    # Scenario 6: Certificate-based rules
    if stage2_stats.get('cert_rules', {}).get('enabled', False):
        cert_stats = stage2_stats['cert_rules']
        print(f"   Cert BENIGN:   {stage2_stats['safe_benign_cert_filtered']:,} (CRL:{cert_stats['benign_crl_hits']}, OV/EV:{cert_stats['benign_ov_ev_hits']}, Wildcard:{cert_stats['benign_wildcard_hits']}, Long:{cert_stats['benign_long_validity_hits']})")
    # Scenario 7: TLD-based filtering
    if stage2_stats.get('tld_filtering', {}).get('enabled', False):
        tld_stats = stage2_stats['tld_filtering']
        blocked_s5 = tld_stats.get('s5_blocked_dangerous', 0) + tld_stats.get('s5_blocked_neutral', 0)
        blocked_s6 = tld_stats['cert_rule_blocked_dangerous'] + tld_stats['cert_rule_blocked_neutral']
        blocked_total = blocked_s5 + blocked_s6
        print(f"   TLD Filtering: blocked {blocked_total:,} (S5:{blocked_s5}, S6:{blocked_s6})")
        print(f"     S5: dangerous={tld_stats.get('s5_blocked_dangerous', 0)}, neutral(p1>={tld_stats['neutral_p1_max']})={tld_stats.get('s5_blocked_neutral', 0)}")
        print(f"     S6: dangerous={tld_stats['cert_rule_blocked_dangerous']}, neutral={tld_stats['cert_rule_blocked_neutral']}")
    # Scenario 8: High ML Phishing
    if stage2_stats.get('high_ml_phish', {}).get('enabled', False):
        hml_stats = stage2_stats['high_ml_phish']
        print(f"   High ML Phish: {hml_stats['selected']:,} (ML>={hml_stats['threshold']}) → Stage3へ救済")
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

    # Add prediction_proba column for 03 system compatibility (keep ml_probability for 98 notebook)
    df_handoff['prediction_proba'] = df_handoff['ml_probability']

    # Build payload
    payload = {
        "analysis_df": df_handoff,
        "cert_full_info_map": cert_full_info_map,  # Stage3用の証明書情報マップ
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

    # Save cert_full_info_map separately for Stage3
    cert_map_pkl = processed_dir / "cert_full_info_map.pkl"
    joblib.dump(cert_full_info_map, cert_map_pkl)
    print(f"   Saved: {cert_map_pkl.name} ({len(cert_full_info_map):,} domains)")

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
