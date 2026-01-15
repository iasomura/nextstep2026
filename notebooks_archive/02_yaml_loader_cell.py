# ============================================================
# Cell -1 (NEW): Load configuration from YAML
# ============================================================
# CHANGELOG (2026-01-10): Phase 1 - Configuration externalization
#   - Load all settings from 02_config.yaml
#   - Set environment variables for backward compatibility
#   - Enable brand feature (seg_include_brand: true)
# ============================================================

import yaml
import os

print("📋 Loading configuration from 02_config.yaml...")

with open("02_config.yaml", "r") as f:
    config_data = yaml.safe_load(f)

# --- Apply Route1 settings ---
r1 = config_data.get("route1", {})
os.environ["XGB_T_MODE"] = r1.get("t_mode", "auto_from_val")
os.environ["XGB_RISK_MAX_AUTO_BENIGN"] = str(r1.get("risk_max_auto_benign", 0.001))
os.environ["XGB_RISK_MAX_AUTO_PHISH"] = str(r1.get("risk_max_auto_phish", 0.0002))
os.environ["XGB_MIN_AUTO_SAMPLES"] = str(r1.get("min_auto_samples", 200))
os.environ["XGB_RISK_USE_UPPER"] = "1" if r1.get("risk_use_upper", True) else "0"
os.environ["XGB_RISK_ALPHA"] = str(r1.get("risk_alpha", 0.05))

# --- Apply XGBoost settings ---
xgb_cfg = config_data.get("xgboost", {})
os.environ["XGB_VAL_SIZE"] = str(xgb_cfg.get("val_size", 0.10))

# --- Apply Stage2 Gate v2 settings ---
s2 = config_data.get("stage2", {})
GATEV2 = {
    'STAGE2_SELECT_MODE': s2.get("select_mode", "segment_priority"),
    'STAGE2_SEG_ONLY_BENIGN': '1' if s2.get("seg_only_benign", False) else '0',
    'STAGE2_SEG_OPTIONAL': '1' if s2.get("seg_optional", True) else '0',
    'STAGE2_SEG_MIN_P1': str(s2.get("seg_min_p1", 0.00)),
    'STAGE2_TAU': str(s2.get("tau", 0.40)),
    'STAGE2_MAX_BUDGET': str(s2.get("max_budget", 5000)),
    'STAGE2_SEG_INCLUDE_IDN': '1' if s2.get("seg_include_idn", True) else '0',
    'STAGE2_SEG_INCLUDE_BRAND': '1' if s2.get("seg_include_brand", True) else '0',  # ⚠️ Now TRUE
}

for k, v in GATEV2.items():
    os.environ[k] = str(v)

# --- Apply experiment settings ---
exp = config_data.get("experiment", {})
os.environ["VIZ_MAX_K"] = str(exp.get("viz_max_k", 40000))
os.environ["VIZ_K_STEP"] = str(exp.get("viz_k_step", 500))
os.environ["VIZ_FN_COST"] = str(exp.get("viz_fn_cost", 3.0))
os.environ["EVAL_IMBALANCE"] = "1" if exp.get("eval_imbalance", False) else "0"
os.environ["EVAL_POS_RATE"] = str(exp.get("eval_pos_rate", 0.001))
os.environ["EVAL_MIN_POS"] = str(exp.get("eval_min_pos", 200))
os.environ["EVAL_SEED"] = str(exp.get("eval_seed", 42))

# --- Store config for later use ---
cfg = config_data  # Make available to subsequent cells

print("✅ Configuration loaded successfully")
print(f"   Brand feature enabled: {GATEV2['STAGE2_SEG_INCLUDE_BRAND']}")
print(f"   Stage2 budget: {GATEV2['STAGE2_MAX_BUDGET']}")
print(f"   Route1 mode: {os.environ['XGB_T_MODE']}")
