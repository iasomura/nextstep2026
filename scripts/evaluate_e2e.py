#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
evaluate_e2e.py — End-to-End評価スクリプト

Stage-1 → Stage-2 (handoff gate) → Agent → 最終判定 のパイプライン全体を評価します。

基となるノートブック: 98-stage2-handoff-validation_v3_orthodox.ipynb

使用方法:
    python scripts/evaluate_e2e.py [オプション]

オプション:
    --n-sample N         評価サンプル数 (default: 100, "ALL"で全件)
    --n-benign N         追加benignサンプル数 (default: 0)
    --n-benign-hard N    追加hard benignサンプル数 (default: 0)
    --random-state N     乱数シード (default: 42)
    --fn-cost F          FNコスト係数 (default: 3.0)
    --fp-cost F          FPコスト係数 (default: 1.0)
    --handoff-cost F     Handoffコスト係数 (default: 0.0)
    --enable-db-tld      DBからTLDリストを動的生成 (default: False)
    --verbose            詳細ログ出力 (default: False)

出力:
    artifacts/{RUN_ID}/results/stage2_validation/
        - eval_df__n{N}__ts_{ts}.csv
        - all_test_merged__ts_{ts}.csv
        - summary__ts_{ts}.json

作成日: 2026-01-12
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import io
import json
import os
import pickle
import sys
import time
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd


# =============================================================================
# 1. 引数パーサー
# =============================================================================
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="End-to-End評価スクリプト (Stage-1 → Stage-2 → Agent)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--n-sample", type=str, default="100",
                        help="評価サンプル数 (数値 or 'ALL')")
    parser.add_argument("--n-benign", type=str, default="0",
                        help="追加benignサンプル数")
    parser.add_argument("--n-benign-hard", type=str, default="0",
                        help="追加hard benignサンプル数")
    parser.add_argument("--random-state", type=int, default=42,
                        help="乱数シード")
    parser.add_argument("--fn-cost", type=float, default=3.0,
                        help="FNコスト係数")
    parser.add_argument("--fp-cost", type=float, default=1.0,
                        help="FPコスト係数")
    parser.add_argument("--handoff-cost", type=float, default=0.0,
                        help="Handoffコスト係数")
    parser.add_argument("--enable-db-tld", action="store_true",
                        help="DBからTLDリストを動的生成")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="詳細ログ出力")
    return parser.parse_args()


def parse_n(s: str) -> int:
    """サンプル数をパース ('ALL' or 数値)"""
    s = str(s).strip().upper()
    if s == "ALL":
        return -1
    try:
        n = int(float(s))
        return -1 if n <= 0 else n
    except ValueError:
        return -1


# =============================================================================
# 2. 環境セットアップ
# =============================================================================
def setup_environment() -> Dict[str, Any]:
    """RUN_ID, paths, ディレクトリを初期化"""
    # プロジェクトルート
    base_dir = Path(os.environ.get("NEXTSTEP_BASE_DIR", ".")).resolve()
    if str(base_dir) not in sys.path:
        sys.path.insert(0, str(base_dir))

    # RUN_ID決定
    import run_id_registry as runreg
    rid = runreg.bootstrap()
    os.environ["RUN_ID"] = rid

    # paths
    try:
        import _compat.paths as paths
    except ImportError:
        import paths as paths
    importlib.reload(paths)

    print(f"[INFO] RUN_ID = {rid}")

    # ディレクトリ
    artifacts_dir = Path(paths.ARTIFACTS) if hasattr(paths, "ARTIFACTS") else (base_dir / "artifacts" / rid)
    dirs = {
        "base": base_dir,
        "artifacts": artifacts_dir,
        "raw": Path(paths.compat_base_dirs["raw"]),
        "processed": Path(paths.compat_base_dirs["data"]),
        "models": Path(paths.compat_base_dirs["models"]),
        "results": Path(paths.compat_base_dirs["results"]),
        "handoff": Path(paths.compat_base_dirs["handoff"]),
        "logs": Path(paths.compat_base_dirs["logs"]),
        "traces": Path(paths.compat_base_dirs["traces"]),
    }

    return {"run_id": rid, "dirs": dirs}


# =============================================================================
# 3. 指標計算ヘルパー
# =============================================================================
@dataclass
class ConfusionResult:
    TP: int
    FP: int
    TN: int
    FN: int
    precision: float
    recall: float
    f1: float
    fbeta: float
    fpr: float


def safe_int_series(x: pd.Series) -> pd.Series:
    """True/False, 0/1, "true"/"false" 等に耐性を持たせる"""
    if x.dtype == bool:
        return x.astype(int)
    y = pd.to_numeric(x, errors="coerce")
    if y.isna().any():
        x2 = x.astype(str).str.strip().str.lower()
        y2 = x2.map({"true": 1, "false": 0})
        y = y.fillna(y2)
    return y.fillna(0).astype(int)


def confusion_from_arrays(y_true, y_pred, *, beta: float = 2.0) -> ConfusionResult:
    y_true = np.asarray(y_true).astype(int)
    y_pred = np.asarray(y_pred).astype(int)

    tp = int(((y_true == 1) & (y_pred == 1)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    tn = int(((y_true == 0) & (y_pred == 0)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum())

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    b2 = beta * beta
    fbeta = ((1 + b2) * precision * recall / (b2 * precision + recall)) if (b2 * precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    return ConfusionResult(tp, fp, tn, fn, precision, recall, f1, fbeta, fpr)


def compute_cls_metrics(df: pd.DataFrame, *, label_col="label", pred_col="pred", beta: float = 2.0) -> ConfusionResult:
    y_true = safe_int_series(df[label_col])
    y_pred = safe_int_series(df[pred_col])
    return confusion_from_arrays(y_true, y_pred, beta=beta)


def compute_gate_metrics(err: pd.Series, handoff: pd.Series) -> dict:
    """Gate指標: error_capture_recall, handoff_precision"""
    e = safe_int_series(err)
    h = safe_int_series(handoff)
    tp = int(((e == 1) & (h == 1)).sum())
    fn = int(((e == 1) & (h == 0)).sum())
    fp = int(((e == 0) & (h == 1)).sum())
    tn = int(((e == 0) & (h == 0)).sum())

    recall = tp / (tp + fn) if (tp + fn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {
        "TP_captured_errors": tp,
        "FP_unneeded_handoff": fp,
        "FN_missed_errors": fn,
        "TN_correct_auto": tn,
        "error_capture_recall": recall,
        "handoff_precision": precision,
        "f1": f1,
    }


def cost_from_confusion(res: ConfusionResult, *, fn_cost: float, fp_cost: float,
                        handoff_cost: float, handoff_count: int) -> float:
    return fn_cost * res.FN + fp_cost * res.FP + handoff_cost * int(handoff_count)


# =============================================================================
# 4. データ読み込み
# =============================================================================
def load_data(dirs: Dict[str, Path]) -> Dict[str, pd.DataFrame]:
    """Stage-1/Stage-2データを読み込み"""
    stage1_csv = dirs["results"] / "stage1_decisions_latest.csv"
    handoff_csv = dirs["handoff"] / "handoff_candidates_latest.csv"

    if not stage1_csv.exists():
        raise FileNotFoundError(f"Not found: {stage1_csv}")
    if not handoff_csv.exists():
        raise FileNotFoundError(f"Not found: {handoff_csv}")

    full_df = pd.read_csv(stage1_csv)
    handoff_all = pd.read_csv(handoff_csv)

    # 正規化
    if "y_true" in full_df.columns:
        full_df["label"] = full_df["y_true"].astype(int)
    elif "label" not in full_df.columns:
        raise RuntimeError("stage1_decisions_latest.csv must have y_true or label")

    full_df["stage1_pred"] = (full_df["ml_probability"] >= 0.5).astype(int)

    if "y_true" in handoff_all.columns:
        handoff_all["label"] = handoff_all["y_true"].astype(int)
    elif "label" not in handoff_all.columns:
        raise RuntimeError("handoff_candidates_latest.csv must have y_true or label")

    return {"full_df": full_df, "handoff_all": handoff_all}


def load_external_data(dirs: Dict[str, Path]) -> Dict[str, Any]:
    """external_dataをロード"""
    external_data = {}
    handoff_path = dirs["handoff"] / "04-3_llm_tools_setup_with_tools.pkl"

    if handoff_path.exists():
        with open(handoff_path, "rb") as f:
            obj = pickle.load(f)
        if isinstance(obj, dict) and "external_data" in obj:
            external_data = obj["external_data"]
            print(f"[OK] loaded external_data from {handoff_path.name}")
        elif isinstance(obj, dict):
            external_data = obj
            print(f"[WARN] using whole dict as external_data")
    else:
        print(f"[WARN] not found: {handoff_path}")

    # Load brand_keywords from models directory if not already loaded
    if not external_data.get("brand_keywords"):
        brand_keywords_path = dirs["models"] / "brand_keywords.json"
        if brand_keywords_path.exists():
            try:
                with open(brand_keywords_path, "r", encoding="utf-8") as f:
                    brand_keywords = json.load(f)
                external_data["brand_keywords"] = brand_keywords
                print(f"[OK] loaded {len(brand_keywords)} brand_keywords from {brand_keywords_path.name}")
            except Exception as e:
                print(f"[WARN] failed to load brand_keywords: {e}")
                external_data.setdefault("brand_keywords", [])
        else:
            external_data.setdefault("brand_keywords", [])

    return external_data


# =============================================================================
# 5. Target DataFrame作成
# =============================================================================
def create_target_df(full_df: pd.DataFrame, handoff_all: pd.DataFrame,
                     n_sample: int, n_benign: int, n_benign_hard: int,
                     random_state: int) -> pd.DataFrame:
    """評価対象のDataFrameを作成"""
    handoff_domains = set(handoff_all["domain"].astype(str))

    def _sample(df: pd.DataFrame, n: int) -> pd.DataFrame:
        if n <= 0 or n >= len(df):
            return df.copy()
        return df.sample(n=n, random_state=random_state).copy()

    parts = []

    # 1) Stage-2 handoff
    s2 = _sample(handoff_all, n_sample)
    s2["eval_group"] = "stage2_handoff"
    parts.append(s2)

    # 2) benign random
    if n_benign > 0:
        pool = full_df[(full_df["label"] == 0) & (~full_df["domain"].astype(str).isin(handoff_domains))].copy()
        b = _sample(pool, n_benign)
        if "y_true" not in b.columns:
            b = b.rename(columns={"label": "y_true"})
        b["y_true"] = 0
        b["eval_group"] = "benign_random"
        keep_cols = [c for c in ["domain", "ml_probability", "y_true", "source"] if c in b.columns]
        parts.append(b[keep_cols])

    # 3) benign hard
    if n_benign_hard > 0:
        pool = full_df[(full_df["label"] == 0) & (~full_df["domain"].astype(str).isin(handoff_domains))].copy()
        pool = pool.sort_values("ml_probability", ascending=False)
        b = pool.head(n_benign_hard).copy()
        if "y_true" not in b.columns:
            b = b.rename(columns={"label": "y_true"})
        b["y_true"] = 0
        b["eval_group"] = "benign_hard"
        keep_cols = [c for c in ["domain", "ml_probability", "y_true", "source"] if c in b.columns]
        parts.append(b[keep_cols])

    target_df = pd.concat(parts, ignore_index=True)
    target_df["domain"] = target_df["domain"].astype(str)
    target_df = target_df.drop_duplicates(subset=["domain"], keep="first").reset_index(drop=True)

    return target_df


# =============================================================================
# 6. Agent初期化
# =============================================================================
def initialize_agent(base_dir: Path, external_data: Dict[str, Any]):
    """LangGraphPhishingAgentを初期化"""
    cfg_path = Path(os.environ.get("CONFIG_JSON", str(base_dir / "config.json"))).resolve()
    if not cfg_path.exists():
        alt = base_dir / "_compat" / "config.json"
        if alt.exists():
            cfg_path = alt.resolve()

    os.environ["CONFIG_JSON"] = str(cfg_path)
    print(f"[INFO] CONFIG_JSON = {cfg_path}")

    # Phase6 wiring
    from phishing_agent.phase6_wiring import wire_phase6
    wire_phase6(prefer_compat=True, fake_llm=False)
    print("[OK] Phase6 wired")

    # Agent
    from phishing_agent.langgraph_module import LangGraphPhishingAgent
    agent = LangGraphPhishingAgent(
        strict_mode=True,
        use_llm_selection=True,
        use_llm_decision=True,
        config_path=str(cfg_path),
        external_data=external_data,
    )
    print(f"[OK] Agent initialized: {type(agent)}")

    return agent


# =============================================================================
# 7. Code Fingerprint
# =============================================================================
def make_code_fingerprint() -> dict:
    """再現性のためのコードフィンガープリントを生成"""
    def _sha256_of_file(path: str) -> str:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception as e:
            return f"ERROR:{type(e).__name__}"

    def _module_info(modname: str):
        try:
            mod = importlib.import_module(modname)
            f = getattr(mod, "__file__", None)
            if f:
                f = str(Path(f).resolve())
                sha = _sha256_of_file(f)
            else:
                sha = None
            return f, sha, mod
        except Exception as e:
            return None, f"IMPORT_ERROR:{type(e).__name__}", None

    fp = {"eval_id": datetime.now().strftime("%Y-%m-%d_%H%M%S")}

    p6_file, p6_sha, _ = _module_info("phishing_agent.phase6_wiring")
    ld_file, ld_sha, ld_mod = _module_info("phishing_agent.llm_final_decision")
    lg_file, lg_sha, _ = _module_info("phishing_agent.langgraph_module")

    fp["phase6_wiring_sha256"] = p6_sha
    fp["llm_final_decision_sha256"] = ld_sha
    fp["langgraph_module_sha256"] = lg_sha
    fp["phase6_policy_version_code"] = getattr(ld_mod, "PHASE6_POLICY_VERSION", None) if ld_mod else None
    fp["python"] = sys.version.split()[0]

    return fp


# =============================================================================
# 8. Agent評価
# =============================================================================
def evaluate_domains(agent, target_df: pd.DataFrame, code_fp: dict,
                     output_dir: Path, verbose: bool = False) -> pd.DataFrame:
    """対象ドメインをAgentで評価"""
    results = []
    start_time = time.time()

    total_n = len(target_df)
    progress_every = 10 if total_n <= 100 else (25 if total_n <= 1000 else 50)

    print(f"[INFO] Starting evaluation of {total_n} domains...")
    print("=" * 80)

    for idx, row in target_df.iterrows():
        domain = row["domain"]
        ml_prob = row["ml_probability"]

        try:
            eval_start = time.time()
            result = agent.evaluate(domain, ml_prob)
            elapsed = time.time() - eval_start

            is_phishing = result.get("ai_is_phishing", False)
            confidence = result.get("ai_confidence", 0.0)
            risk_level = result.get("ai_risk_level", "unknown")

            graph_state = result.get("graph_state", {}) or {}
            tool_res = graph_state.get("tool_results", {}) or result.get("tool_results", {}) or {}

            results.append({
                "eval_id": code_fp.get("eval_id"),
                "domain": domain,
                "ml_probability": ml_prob,
                "ai_is_phishing": is_phishing,
                "ai_confidence": confidence,
                "ai_risk_level": risk_level,
                "processing_time": elapsed,
                "phase6_policy_version": graph_state.get("phase6_policy_version"),
                "error": None,
            })

            if verbose:
                mark = "PHISH" if is_phishing else "BENIGN"
                print(f"[{idx+1:4}/{total_n}] {mark:6} {domain} (ML={ml_prob:.3f}, conf={confidence:.2f}, t={elapsed:.2f}s)")

        except Exception as e:
            elapsed = time.time() - eval_start
            results.append({
                "eval_id": code_fp.get("eval_id"),
                "domain": domain,
                "ml_probability": ml_prob,
                "ai_is_phishing": False,
                "ai_confidence": 0.0,
                "ai_risk_level": "error",
                "processing_time": elapsed,
                "phase6_policy_version": None,
                "error": str(e),
            })
            print(f"[{idx+1:4}/{total_n}] ERROR  {domain} - {e}")

        # 進捗表示
        if not verbose and ((idx + 1) % progress_every == 0 or idx == total_n - 1):
            elapsed_total = time.time() - start_time
            n_phish = sum(1 for r in results if r.get("ai_is_phishing") and not r.get("error"))
            n_benign = sum(1 for r in results if not r.get("ai_is_phishing") and not r.get("error"))
            n_error = sum(1 for r in results if r.get("error"))
            print(f"[PROGRESS] {idx+1}/{total_n}  phish={n_phish} benign={n_benign} error={n_error}  elapsed={elapsed_total:.1f}s")

    print("=" * 80)
    print(f"[INFO] Evaluation complete. Total time: {time.time() - start_time:.2f}s")

    return pd.DataFrame(results)


# =============================================================================
# 9. End-to-End評価
# =============================================================================
def evaluate_e2e(full_df: pd.DataFrame, handoff_all: pd.DataFrame, eval_df: pd.DataFrame,
                 results_df: pd.DataFrame, fn_cost: float, fp_cost: float,
                 handoff_cost: float) -> Dict[str, Any]:
    """End-to-End評価を実行"""
    # Handoff domains
    handoff_domains = set(handoff_all["domain"].astype(str))
    full_df["stage2_handoff"] = full_df["domain"].astype(str).isin(handoff_domains).astype(int)
    full_df["stage1_err"] = (full_df["stage1_pred"] != full_df["label"]).astype(int)

    # Gate評価
    gate_metrics = compute_gate_metrics(full_df["stage1_err"], full_df["stage2_handoff"])

    # Agent予測をマージ
    eval_df["label"] = eval_df["y_true"].astype(int)
    eval_df["stage1_pred"] = (eval_df["ml_probability"] >= 0.5).astype(int)
    eval_df["agent_pred"] = pd.to_numeric(results_df["ai_is_phishing"], errors="coerce")
    eval_df["agent_covered"] = eval_df["agent_pred"].notna().astype(int)
    eval_df["final_pred"] = eval_df["agent_pred"].fillna(eval_df["stage1_pred"]).astype(int)

    # ALL testにマージ
    agent_for_merge = eval_df[["domain", "agent_pred"]].drop_duplicates(subset=["domain"], keep="first")
    merged = full_df.merge(agent_for_merge, on="domain", how="left")
    merged["final_pred"] = pd.to_numeric(merged["agent_pred"], errors="coerce").fillna(merged["stage1_pred"]).astype(int)

    # 指標計算
    m_stage1_all = compute_cls_metrics(merged.assign(pred=merged["stage1_pred"]), label_col="label", pred_col="pred")
    m_final_all = compute_cls_metrics(merged.assign(pred=merged["final_pred"]), label_col="label", pred_col="pred")

    auto_mask = merged["stage2_handoff"] == 0
    handoff_mask = merged["stage2_handoff"] == 1

    m_stage1_auto = compute_cls_metrics(merged.loc[auto_mask].assign(pred=merged.loc[auto_mask, "stage1_pred"]), label_col="label", pred_col="pred")
    m_final_auto = compute_cls_metrics(merged.loc[auto_mask].assign(pred=merged.loc[auto_mask, "final_pred"]), label_col="label", pred_col="pred")

    m_stage1_handoff = compute_cls_metrics(merged.loc[handoff_mask].assign(pred=merged.loc[handoff_mask, "stage1_pred"]), label_col="label", pred_col="pred")
    m_final_handoff = compute_cls_metrics(merged.loc[handoff_mask].assign(pred=merged.loc[handoff_mask, "final_pred"]), label_col="label", pred_col="pred")

    # コスト
    total_handoff = int(handoff_mask.sum())
    cost_stage1 = cost_from_confusion(m_stage1_all, fn_cost=fn_cost, fp_cost=fp_cost, handoff_cost=handoff_cost, handoff_count=0)
    cost_final = cost_from_confusion(m_final_all, fn_cost=fn_cost, fp_cost=fp_cost, handoff_cost=handoff_cost, handoff_count=total_handoff)

    return {
        "gate_metrics": gate_metrics,
        "metrics_stage1_all": m_stage1_all,
        "metrics_final_all": m_final_all,
        "metrics_stage1_auto": m_stage1_auto,
        "metrics_final_auto": m_final_auto,
        "metrics_stage1_handoff": m_stage1_handoff,
        "metrics_final_handoff": m_final_handoff,
        "cost_stage1": cost_stage1,
        "cost_final": cost_final,
        "total_handoff": total_handoff,
        "agent_covered": int(eval_df["agent_covered"].sum()),
        "merged": merged,
        "eval_df": eval_df,
    }


# =============================================================================
# 10. 結果保存
# =============================================================================
def save_results(results: Dict[str, Any], dirs: Dict[str, Path], run_id: str,
                 args: argparse.Namespace) -> None:
    """結果を保存"""
    out_dir = dirs["results"] / "stage2_validation"
    out_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")

    # eval_df
    eval_path = out_dir / f"eval_df__n{len(results['eval_df'])}__ts_{ts}.csv"
    results["eval_df"].to_csv(eval_path, index=False)

    # merged
    merged_path = out_dir / f"all_test_merged__ts_{ts}.csv"
    results["merged"].to_csv(merged_path, index=False)

    # summary
    summary = {
        "run_id": run_id,
        "timestamp": ts,
        "n_all_test": len(results["merged"]),
        "n_stage2_handoff": results["total_handoff"],
        "agent_covered": results["agent_covered"],
        "metrics_stage1_all": asdict(results["metrics_stage1_all"]),
        "metrics_final_all": asdict(results["metrics_final_all"]),
        "metrics_stage1_auto": asdict(results["metrics_stage1_auto"]),
        "metrics_final_auto": asdict(results["metrics_final_auto"]),
        "metrics_stage1_handoff": asdict(results["metrics_stage1_handoff"]),
        "metrics_final_handoff": asdict(results["metrics_final_handoff"]),
        "gate_metrics": results["gate_metrics"],
        "cost": {
            "fn_cost": args.fn_cost,
            "fp_cost": args.fp_cost,
            "handoff_cost": args.handoff_cost,
            "stage1_only": results["cost_stage1"],
            "final": results["cost_final"],
        },
        "params": {
            "n_sample": args.n_sample,
            "n_benign": args.n_benign,
            "n_benign_hard": args.n_benign_hard,
            "random_state": args.random_state,
        },
    }

    sum_path = out_dir / f"summary__ts_{ts}.json"
    sum_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"[SAVED] {eval_path}")
    print(f"[SAVED] {merged_path}")
    print(f"[SAVED] {sum_path}")


# =============================================================================
# 11. 結果表示
# =============================================================================
def print_results(results: Dict[str, Any], args: argparse.Namespace) -> None:
    """結果を表示"""
    print("\n" + "=" * 80)
    print("EVALUATION RESULTS")
    print("=" * 80)

    print("\n[Gate Metrics: Stage-2 Handoff vs Stage-1 Errors]")
    for k, v in results["gate_metrics"].items():
        if isinstance(v, float):
            print(f"  {k}: {v:.4f}")
        else:
            print(f"  {k}: {v}")

    print("\n[ALL Test] Stage-1 vs Final")
    print(f"  Stage-1: P={results['metrics_stage1_all'].precision:.4f} R={results['metrics_stage1_all'].recall:.4f} F1={results['metrics_stage1_all'].f1:.4f}")
    print(f"  Final  : P={results['metrics_final_all'].precision:.4f} R={results['metrics_final_all'].recall:.4f} F1={results['metrics_final_all'].f1:.4f}")

    print("\n[AUTO Subset] (not handed off)")
    print(f"  Stage-1: P={results['metrics_stage1_auto'].precision:.4f} R={results['metrics_stage1_auto'].recall:.4f} F1={results['metrics_stage1_auto'].f1:.4f}")
    print(f"  Final  : P={results['metrics_final_auto'].precision:.4f} R={results['metrics_final_auto'].recall:.4f} F1={results['metrics_final_auto'].f1:.4f}")

    print("\n[HANDOFF Subset]")
    print(f"  Stage-1: P={results['metrics_stage1_handoff'].precision:.4f} R={results['metrics_stage1_handoff'].recall:.4f} F1={results['metrics_stage1_handoff'].f1:.4f}")
    print(f"  Final  : P={results['metrics_final_handoff'].precision:.4f} R={results['metrics_final_handoff'].recall:.4f} F1={results['metrics_final_handoff'].f1:.4f}")

    print(f"\n[COST] cost = FN_COST*FN + FP_COST*FP + HANDOFF_COST*N")
    print(f"  Stage-1 only: {results['cost_stage1']:.2f}")
    print(f"  Final (with handoff): {results['cost_final']:.2f}")

    print("\n" + "=" * 80)


# =============================================================================
# Main
# =============================================================================
def main():
    args = parse_args()

    print("=" * 80)
    print("End-to-End Evaluation Script")
    print("=" * 80)

    # パラメータ表示
    n_sample = parse_n(args.n_sample)
    n_benign = parse_n(args.n_benign)
    n_benign_hard = parse_n(args.n_benign_hard)

    print(f"[PARAMS] n_sample={n_sample}, n_benign={n_benign}, n_benign_hard={n_benign_hard}")
    print(f"[PARAMS] random_state={args.random_state}")
    print(f"[PARAMS] costs: FN={args.fn_cost}, FP={args.fp_cost}, Handoff={args.handoff_cost}")

    # 環境セットアップ
    env = setup_environment()
    run_id = env["run_id"]
    dirs = env["dirs"]

    # データ読み込み
    print("\n[STEP 1] Loading data...")
    data = load_data(dirs)
    full_df = data["full_df"]
    handoff_all = data["handoff_all"]
    print(f"  ALL test: {len(full_df)}")
    print(f"  Stage-2 handoff: {len(handoff_all)}")

    # external_data
    print("\n[STEP 2] Loading external data...")
    external_data = load_external_data(dirs)

    # Target DataFrame作成
    print("\n[STEP 3] Creating target DataFrame...")
    target_df = create_target_df(full_df, handoff_all, n_sample, n_benign, n_benign_hard, args.random_state)
    print(f"  target_df rows: {len(target_df)}")
    print(f"  groups: {target_df['eval_group'].value_counts().to_dict()}")

    # Agent初期化
    print("\n[STEP 4] Initializing agent...")
    agent = initialize_agent(dirs["base"], external_data)

    # Code fingerprint
    code_fp = make_code_fingerprint()
    print(f"[INFO] eval_id: {code_fp['eval_id']}")

    # Agent評価
    print("\n[STEP 5] Running agent evaluation...")
    results_df = evaluate_domains(agent, target_df, code_fp, dirs["logs"], args.verbose)

    # End-to-End評価
    print("\n[STEP 6] Computing E2E metrics...")
    e2e_results = evaluate_e2e(full_df, handoff_all, target_df, results_df,
                                args.fn_cost, args.fp_cost, args.handoff_cost)

    # 結果表示
    print_results(e2e_results, args)

    # 結果保存
    print("\n[STEP 7] Saving results...")
    save_results(e2e_results, dirs, run_id, args)

    print("\n[DONE]")


if __name__ == "__main__":
    main()
