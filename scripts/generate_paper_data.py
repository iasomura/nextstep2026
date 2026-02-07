#!/usr/bin/env python3
"""
論文用データ生成スクリプト

paper_outline.md の図表計画に基づき、docs/paper/data/ に表・図データ・統計JSONを生成する。

Phase 1 (即時生成): 表1-5, 図2/4データ, 統計JSON 5件
Phase 2 (追加解析): 表6(アブレーション), 図3(閾値スイープ), 図5(誤りカテゴリ)

Usage:
    python scripts/generate_paper_data.py              # 全Phase実行
    python scripts/generate_paper_data.py --phase 1    # Phase 1のみ
    python scripts/generate_paper_data.py --phase 2    # Phase 2のみ
    python scripts/generate_paper_data.py --verify      # 検証のみ

変更履歴:
  - 2026-02-07: SO failure再評価後のVERIFIED数値更新
  - 2026-02-07: 初版作成（Phase 1 + Phase 2 統合スクリプト）
"""

import sys
import os
import json
import argparse
from pathlib import Path

import numpy as np
import pandas as pd

# Project root
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# ── Input paths ──────────────────────────────────────────────────────
ARTIFACTS_DIR = PROJECT_ROOT / "artifacts" / "2026-02-02_224105"
RESULTS_DIR = ARTIFACTS_DIR / "results"
STAGE1_CSV = RESULTS_DIR / "stage1_decisions_latest.csv"
STAGE2_CSV = RESULTS_DIR / "stage2_decisions_latest.csv"
STAGE2_CANDIDATES_CSV = RESULTS_DIR / "stage2_decisions_candidates_latest.csv"
STAGE2_BUDGET_JSON = RESULTS_DIR / "stage2_budget_eval.json"
EVAL_CSV = (
    RESULTS_DIR
    / "stage2_validation"
    / "eval_20260205_230157"
    / "eval_df__nALL__ts_20260205_230158.csv"
)

# ── Output paths ─────────────────────────────────────────────────────
OUTPUT_DIR = PROJECT_ROOT / "docs" / "paper" / "data"
TABLES_DIR = OUTPUT_DIR / "tables"
FIGURES_DIR = OUTPUT_DIR / "figures"
STATS_DIR = OUTPUT_DIR / "statistics"

# ── Verified reference numbers (from paper_outline.md §検証済み数値リファレンス) ──
# Used for verification after generation
# 変更履歴:
#   - 2026-02-07: SO failure 16件中15件を再評価してVERIFIED更新
#     Stage3: TP 1686→1685, FP 532→529, TN 8975→8978, FN 759→760, F1 72.31→72.33
#     System: TP 62454→62453, FP 535→532, TN 63076→63079, FN 1157→1158, F1 98.66→98.67
VERIFIED = {
    "dataset_total": 636110,
    "dataset_train": 508888,
    "dataset_test": 127222,
    "stage1_auto_phishing": 60767,
    "stage1_auto_benign": 8464,
    "stage1_handoff": 57991,
    "stage2_not_candidate": 69231,
    "stage2_drop_to_auto": 46039,
    "stage2_handoff_to_agent": 11952,
    "stage3_tp": 1685,
    "stage3_fp": 529,
    "stage3_tn": 8978,
    "stage3_fn": 760,
    "stage3_f1": 72.33,
    "system_tp": 62453,
    "system_fp": 532,
    "system_tn": 63079,
    "system_fn": 1158,
    "system_precision": 99.16,
    "system_recall": 98.18,
    "system_f1": 98.67,
}


def ensure_dirs():
    """出力ディレクトリを作成"""
    for d in [TABLES_DIR, FIGURES_DIR, STATS_DIR]:
        d.mkdir(parents=True, exist_ok=True)


def load_data():
    """全入力データを読み込み"""
    print("Loading data...")

    data = {}
    data["stage1"] = pd.read_csv(STAGE1_CSV)
    print(f"  stage1: {len(data['stage1']):,} rows")

    data["stage2"] = pd.read_csv(STAGE2_CSV)
    print(f"  stage2: {len(data['stage2']):,} rows")

    data["stage2_candidates"] = pd.read_csv(STAGE2_CANDIDATES_CSV)
    print(f"  stage2_candidates: {len(data['stage2_candidates']):,} rows")

    with open(STAGE2_BUDGET_JSON) as f:
        data["budget"] = json.load(f)
    print(f"  budget: loaded")

    # eval CSV: 11,983行あるが重複除去して11,952行にする
    eval_df = pd.read_csv(EVAL_CSV)
    print(f"  eval (raw): {len(eval_df):,} rows")
    eval_df = eval_df.drop_duplicates(subset=["domain"], keep="last")
    print(f"  eval (dedup): {len(eval_df):,} rows")
    data["eval"] = eval_df

    return data


# ═══════════════════════════════════════════════════════════════════════
#  Phase 1: 即時生成
# ═══════════════════════════════════════════════════════════════════════


def generate_table1():
    """表1: データセット構築内訳

    検証済み数値（paper_outline.md）から直接CSVを生成。
    DBからの再計算ではなく、確定値をそのまま使用する。
    """
    print("\n[Table 1] Dataset construction summary")

    rows = [
        # ソース別件数 (重複排除前)
        ("Source: certificates (JPCERT domains)", 532117, "Phishing certs from JPCERT domains"),
        ("Source: jpcert_phishing_urls", 222984, "JPCERT phishing URL feed"),
        ("Source: phishtank_entries", 94295, "PhishTank verified phishing"),
        ("Source: trusted_certificates", 554801, "Tranco-ranked legitimate sites"),
        # パイプライン
        ("Phishing (cert-holding, pre-dedup)", 319383, "Phishing domains with certificates"),
        ("Benign (balanced sampling)", 319383, "Balanced benign sample"),
        ("Total (pre-pipeline)", 638766, "Before inter-source dedup"),
        # パイプライン通過後
        ("Phishing (post-pipeline)", 318055, "After dedup + overlap removal"),
        ("Benign (post-pipeline)", 318055, "After balance adjustment"),
        ("Total (post-pipeline)", 636110, "Final dataset"),
        # Train/Test
        ("Train", 508888, "80% split (254,444/class)"),
        ("Test", 127222, "20% split (63,611/class)"),
    ]

    df = pd.DataFrame(rows, columns=["item", "count", "note"])
    path = TABLES_DIR / "table1_dataset.csv"
    df.to_csv(path, index=False)
    print(f"  -> {path}")
    return df


def generate_table2():
    """表2: 証明書可用性・ステータス分布

    dataset_overview.md のDB実測値をCSV化。
    """
    print("\n[Table 2] Certificate availability and status distribution")

    # Part A: テーブル別証明書保有率
    avail_rows = [
        ("certificates", 532117, 196083, 36.9),
        ("jpcert_phishing_urls", 222984, 119439, 53.6),
        ("phishtank_entries", 94295, 52808, 56.0),
        ("trusted_certificates", 554801, 450545, 81.2),
    ]
    df_avail = pd.DataFrame(
        avail_rows,
        columns=["table_name", "total_records", "cert_data_count", "availability_pct"],
    )
    path_a = TABLES_DIR / "table2_cert_availability.csv"
    df_avail.to_csv(path_a, index=False)
    print(f"  -> {path_a}")

    # Part B: 主要テーブルのステータス分布
    status_rows = [
        # certificates テーブル
        ("certificates", "NOT_FOUND", 261905, 49.2),
        ("certificates", "SUCCESS", 196083, 36.9),
        ("certificates", "UNKNOWN_ERROR", 42204, 7.9),
        ("certificates", "SEARCH_ERROR", 27242, 5.1),
        ("certificates", "DOWNLOAD_ERROR", 4683, 0.9),
        # jpcert テーブル
        ("jpcert_phishing_urls", "SUCCESS", 115620, 51.9),
        ("jpcert_phishing_urls", "NOT_HTTPS", 41633, 18.7),
        ("jpcert_phishing_urls", "DUPLICATE", 36033, 16.2),
        ("jpcert_phishing_urls", "NOT_FOUND", 26997, 12.1),
        ("jpcert_phishing_urls", "SEARCH_ERROR", 1558, 0.7),
        ("jpcert_phishing_urls", "UNKNOWN_ERROR", 851, 0.4),
        ("jpcert_phishing_urls", "DOWNLOAD_ERROR", 292, 0.1),
        # phishtank テーブル
        ("phishtank_entries", "SUCCESS", 52805, 56.0),
        ("phishtank_entries", "NOT_FOUND", 40653, 43.1),
        ("phishtank_entries", "UNKNOWN_ERROR", 441, 0.5),
        ("phishtank_entries", "SEARCH_ERROR", 327, 0.3),
        ("phishtank_entries", "DOWNLOAD_ERROR", 47, 0.0),
        ("phishtank_entries", "CONVERSION_ERROR", 12, 0.0),
        ("phishtank_entries", "INVALID_URL", 10, 0.0),
        # trusted テーブル
        ("trusted_certificates", "SUCCESS", 450545, 81.2),
        ("trusted_certificates", "DOWNLOAD_ERROR", 50206, 9.1),
        ("trusted_certificates", "NOT_FOUND", 38424, 6.9),
        ("trusted_certificates", "UNKNOWN_ERROR", 15626, 2.8),
    ]
    df_status = pd.DataFrame(
        status_rows,
        columns=["table_name", "status", "count", "percentage"],
    )
    path_b = TABLES_DIR / "table2_cert_status.csv"
    df_status.to_csv(path_b, index=False)
    print(f"  -> {path_b}")

    return df_avail, df_status


def generate_table3(data):
    """表3: システム全体性能（Stage1+2のみ vs Stage1+2+3）

    Stage1+2のみ: 自動判定(69,231) + Stage2 drop(46,039) で計算
    Stage1+2+3: 全Stage合算で計算
    """
    print("\n[Table 3] System performance comparison")

    s1 = data["stage1"]
    s2 = data["stage2"]
    ev = data["eval"]

    # ── Stage1+2のみ (Stage3なし = Stage2 handoffをML予測で代替) ──
    # Stage1自動判定: auto_phishing → pred=1, auto_benign → pred=0
    s1_auto_phishing = s1[s1["stage1_decision"] == "auto_phishing"]
    s1_auto_benign = s1[s1["stage1_decision"] == "auto_benign"]

    tp_s1 = int((s1_auto_phishing["y_true"] == 1).sum())  # 60,765
    fp_s1 = int((s1_auto_phishing["y_true"] == 0).sum())  # 2
    tn_s1 = int((s1_auto_benign["y_true"] == 0).sum())    # 8,461
    fn_s1 = int((s1_auto_benign["y_true"] == 1).sum())    # 3

    # Stage2 drop: ML予測(stage1_pred)をそのまま適用
    s2_drop = s2[s2["stage2_decision"] == "drop_to_auto"]
    tp_s2drop = int(((s2_drop["stage1_pred"] == 1) & (s2_drop["y_true"] == 1)).sum())
    fp_s2drop = int(((s2_drop["stage1_pred"] == 1) & (s2_drop["y_true"] == 0)).sum())
    tn_s2drop = int(((s2_drop["stage1_pred"] == 0) & (s2_drop["y_true"] == 0)).sum())
    fn_s2drop = int(((s2_drop["stage1_pred"] == 0) & (s2_drop["y_true"] == 1)).sum())

    # Stage2 handoff: Stage3がない場合はML予測で代替
    s2_handoff = s2[s2["stage2_decision"] == "handoff_to_agent"]
    tp_s2ho = int(((s2_handoff["stage1_pred"] == 1) & (s2_handoff["y_true"] == 1)).sum())
    fp_s2ho = int(((s2_handoff["stage1_pred"] == 1) & (s2_handoff["y_true"] == 0)).sum())
    tn_s2ho = int(((s2_handoff["stage1_pred"] == 0) & (s2_handoff["y_true"] == 0)).sum())
    fn_s2ho = int(((s2_handoff["stage1_pred"] == 0) & (s2_handoff["y_true"] == 1)).sum())

    # Stage1+2のみ（全データにML予測を適用）
    tp_no3 = tp_s1 + tp_s2drop + tp_s2ho
    fp_no3 = fp_s1 + fp_s2drop + fp_s2ho
    tn_no3 = tn_s1 + tn_s2drop + tn_s2ho
    fn_no3 = fn_s1 + fn_s2drop + fn_s2ho

    # ── Stage1+2+3 (全体) ──
    # 自動判定部分 (Stage1 auto + Stage2 drop)
    tp_auto = tp_s1 + tp_s2drop
    fp_auto = fp_s1 + fp_s2drop
    tn_auto = tn_s1 + tn_s2drop
    fn_auto = fn_s1 + fn_s2drop

    # Stage3判定
    tp_s3 = int(((ev["ai_is_phishing"] == True) & (ev["y_true"] == 1)).sum())
    fp_s3 = int(((ev["ai_is_phishing"] == True) & (ev["y_true"] == 0)).sum())
    tn_s3 = int(((ev["ai_is_phishing"] == False) & (ev["y_true"] == 0)).sum())
    fn_s3 = int(((ev["ai_is_phishing"] == False) & (ev["y_true"] == 1)).sum())

    tp_full = tp_auto + tp_s3
    fp_full = fp_auto + fp_s3
    tn_full = tn_auto + tn_s3
    fn_full = fn_auto + fn_s3

    def calc_metrics(tp, fp, tn, fn):
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
        accuracy = (tp + tn) / (tp + fp + tn + fn)
        return {
            "TP": tp, "FP": fp, "TN": tn, "FN": fn,
            "Precision": round(precision * 100, 2),
            "Recall": round(recall * 100, 2),
            "F1": round(f1 * 100, 2),
            "FPR": round(fpr * 100, 2),
            "FNR": round(fnr * 100, 2),
            "Accuracy": round(accuracy * 100, 2),
        }

    row_no3 = {"configuration": "Stage1+2 only (ML prediction)", **calc_metrics(tp_no3, fp_no3, tn_no3, fn_no3)}
    row_full = {"configuration": "Stage1+2+3 (Full cascade)", **calc_metrics(tp_full, fp_full, tn_full, fn_full)}

    df = pd.DataFrame([row_no3, row_full])
    path = TABLES_DIR / "table3_system_performance.csv"
    df.to_csv(path, index=False)
    print(f"  -> {path}")

    # 検証
    assert tp_full == VERIFIED["system_tp"], f"System TP mismatch: {tp_full} != {VERIFIED['system_tp']}"
    assert fp_full == VERIFIED["system_fp"], f"System FP mismatch: {fp_full} != {VERIFIED['system_fp']}"
    assert tn_full == VERIFIED["system_tn"], f"System TN mismatch: {tn_full} != {VERIFIED['system_tn']}"
    assert fn_full == VERIFIED["system_fn"], f"System FN mismatch: {fn_full} != {VERIFIED['system_fn']}"
    print(f"  ✓ System metrics verified: F1={row_full['F1']}%")

    return df


def generate_table4(data):
    """表4: Stage2効果（投入率、誤り、ゲート内訳）"""
    print("\n[Table 4] Stage2 effect")

    s2 = data["stage2"]
    budget = data["budget"]

    # Stage2 判定別集計
    decisions = s2["stage2_decision"].value_counts()
    n_total = len(s2)

    rows = []
    for dec in ["not_candidate", "drop_to_auto", "handoff_to_agent"]:
        subset = s2[s2["stage2_decision"] == dec]
        n = len(subset)
        y1 = int((subset["y_true"] == 1).sum())
        y0 = int((subset["y_true"] == 0).sum())
        rows.append({
            "decision": dec,
            "count": n,
            "percentage": round(n / n_total * 100, 1),
            "y_true_1": y1,
            "y_true_0": y0,
        })

    df_decisions = pd.DataFrame(rows)

    # ゲート内訳
    sel = budget["stage2_select"]
    gate_rows = [
        ("safe_benign (base)", sel["safe_benign_filtered"]),
        ("safe_benign_cert (cert-enhanced)", sel["safe_benign_cert_filtered"]),
        ("safe_phishing_cert", sel["safe_phishing_cert_filtered"]),
        ("safe_benign_combined", sel["safe_benign_combined_filtered"]),
        ("high_ml_phish override", sel["high_ml_phish"]["selected"]),
    ]
    df_gates = pd.DataFrame(gate_rows, columns=["gate", "filtered_count"])

    # 自動判定の誤り
    auto_errors = budget["auto_errors"]
    auto_total = budget["N_auto"]
    auto_error_rate = budget["auto_error_rate"]

    df_auto = pd.DataFrame([{
        "auto_decided_total": auto_total,
        "auto_errors": auto_errors,
        "auto_error_rate": round(auto_error_rate * 100, 3),
        "stage3_input": budget["N_stage2_handoff"],
        "stage3_input_rate": round(budget["N_stage2_handoff"] / n_total * 100, 1),
    }])

    # 全部まとめてCSV
    path = TABLES_DIR / "table4_stage2_effect.csv"
    with open(path, "w") as f:
        f.write("# Stage2 Decision Distribution\n")
        df_decisions.to_csv(f, index=False)
        f.write("\n# Gate Filtering Details\n")
        df_gates.to_csv(f, index=False)
        f.write("\n# Auto-decision Summary\n")
        df_auto.to_csv(f, index=False)

    print(f"  -> {path}")

    # 検証
    assert int(df_decisions[df_decisions["decision"] == "drop_to_auto"]["count"].iloc[0]) == VERIFIED["stage2_drop_to_auto"]
    assert int(df_decisions[df_decisions["decision"] == "handoff_to_agent"]["count"].iloc[0]) == VERIFIED["stage2_handoff_to_agent"]
    print(f"  ✓ Stage2 handoff: {VERIFIED['stage2_handoff_to_agent']:,} ({VERIFIED['stage2_handoff_to_agent']/n_total*100:.1f}%)")

    return df_decisions, df_gates, df_auto


def generate_table5(data):
    """表5: Stage3性能 + ルール発火率"""
    print("\n[Table 5] Stage3 performance and rule firing")

    ev = data["eval"]

    # 混同行列
    tp = int(((ev["ai_is_phishing"] == True) & (ev["y_true"] == 1)).sum())
    fp = int(((ev["ai_is_phishing"] == True) & (ev["y_true"] == 0)).sum())
    tn = int(((ev["ai_is_phishing"] == False) & (ev["y_true"] == 0)).sum())
    fn = int(((ev["ai_is_phishing"] == False) & (ev["y_true"] == 1)).sum())

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

    metrics = {
        "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "Precision": round(precision * 100, 2),
        "Recall": round(recall * 100, 2),
        "F1": round(f1 * 100, 2),
        "FPR": round(fpr * 100, 2),
        "total_evaluated": len(ev),
        "error_count": int((ev["error"].notna() & (ev["error"] != "")).sum()),
    }

    # 処理時間統計
    pt = ev["processing_time"].dropna()
    metrics["processing_time_mean"] = round(pt.mean(), 2)
    metrics["processing_time_p50"] = round(pt.quantile(0.5), 2)
    metrics["processing_time_p90"] = round(pt.quantile(0.9), 2)
    metrics["processing_time_p99"] = round(pt.quantile(0.99), 2)

    # ルール発火
    rules_col = ev["trace_phase6_rules_fired"]
    rule_fired_mask = rules_col.notna() & (rules_col != "[]") & (rules_col != "")
    n_rule_fired = int(rule_fired_mask.sum())
    metrics["rule_fired_count"] = n_rule_fired
    metrics["rule_fired_rate"] = round(n_rule_fired / len(ev) * 100, 1)

    # ルール別集計
    rule_counts = {}
    for val in rules_col[rule_fired_mask]:
        try:
            rules = json.loads(val) if isinstance(val, str) else val
            if isinstance(rules, list):
                for r in rules:
                    rule_counts[r] = rule_counts.get(r, 0) + 1
        except (json.JSONDecodeError, TypeError):
            pass

    df_metrics = pd.DataFrame([metrics])
    df_rules = pd.DataFrame(
        sorted(rule_counts.items(), key=lambda x: -x[1]),
        columns=["rule_name", "fire_count"],
    )
    df_rules["fire_rate_pct"] = (df_rules["fire_count"] / len(ev) * 100).round(2)

    path = TABLES_DIR / "table5_stage3_performance.csv"
    with open(path, "w") as f:
        f.write("# Stage3 Performance Metrics\n")
        df_metrics.to_csv(f, index=False)
        f.write("\n# Rule Firing Summary\n")
        df_rules.to_csv(f, index=False)

    print(f"  -> {path}")

    # 検証
    assert tp == VERIFIED["stage3_tp"], f"Stage3 TP mismatch: {tp} != {VERIFIED['stage3_tp']}"
    assert fp == VERIFIED["stage3_fp"], f"Stage3 FP mismatch: {fp} != {VERIFIED['stage3_fp']}"
    assert tn == VERIFIED["stage3_tn"], f"Stage3 TN mismatch: {tn} != {VERIFIED['stage3_tn']}"
    assert fn == VERIFIED["stage3_fn"], f"Stage3 FN mismatch: {fn} != {VERIFIED['stage3_fn']}"
    assert round(f1 * 100, 2) == VERIFIED["stage3_f1"], f"Stage3 F1 mismatch: {round(f1*100,2)} != {VERIFIED['stage3_f1']}"
    print(f"  ✓ Stage3 metrics verified: F1={round(f1*100,2)}%")

    return df_metrics, df_rules


def generate_fig2_data(data):
    """図2データ: Stage遷移の件数推移"""
    print("\n[Fig 2] Stage transition flow data")

    s1 = data["stage1"]
    s2 = data["stage2"]

    n_total = len(s1)

    # Stage1 routing
    s1_auto_phishing = int((s1["stage1_decision"] == "auto_phishing").sum())
    s1_auto_benign = int((s1["stage1_decision"] == "auto_benign").sum())
    s1_handoff = int((s1["stage1_decision"] == "handoff_to_agent").sum())

    # Stage2 routing
    s2_drop = int((s2["stage2_decision"] == "drop_to_auto").sum())
    s2_handoff = int((s2["stage2_decision"] == "handoff_to_agent").sum())

    rows = [
        ("Input", "Total test domains", n_total),
        ("Stage1", "auto_phishing", s1_auto_phishing),
        ("Stage1", "auto_benign", s1_auto_benign),
        ("Stage1", "handoff_to_stage2", s1_handoff),
        ("Stage2", "drop_to_auto", s2_drop),
        ("Stage2", "handoff_to_agent (Stage3)", s2_handoff),
        ("Summary", "Auto-decided (Stage1+Stage2)", s1_auto_phishing + s1_auto_benign + s2_drop),
        ("Summary", "Stage3 processed", s2_handoff),
    ]

    df = pd.DataFrame(rows, columns=["stage", "category", "count"])
    df["percentage"] = (df["count"] / n_total * 100).round(1)

    path = TABLES_DIR / "fig2_stage_transitions.csv"
    df.to_csv(path, index=False)
    print(f"  -> {path}")

    # 検証
    assert s1_auto_phishing == VERIFIED["stage1_auto_phishing"]
    assert s1_auto_benign == VERIFIED["stage1_auto_benign"]
    assert s1_handoff == VERIFIED["stage1_handoff"]
    assert s2_handoff == VERIFIED["stage2_handoff_to_agent"]
    print(f"  ✓ Stage transitions verified")

    return df


def generate_fig4_data(data):
    """図4データ: Stage3処理時間分布"""
    print("\n[Fig 4] Stage3 processing time distribution")

    ev = data["eval"]
    pt = ev["processing_time"].dropna()

    # ヒストグラム用ビン
    bins = np.arange(0, pt.max() + 2, 1)  # 1秒刻み
    hist, bin_edges = np.histogram(pt, bins=bins)

    df_hist = pd.DataFrame({
        "bin_start": bin_edges[:-1],
        "bin_end": bin_edges[1:],
        "count": hist,
    })

    # パーセンタイル統計
    percentiles = [10, 25, 50, 75, 90, 95, 99]
    df_pct = pd.DataFrame({
        "percentile": percentiles,
        "value_seconds": [round(pt.quantile(p / 100), 2) for p in percentiles],
    })

    # ワーカー別統計
    worker_stats = []
    for wid in sorted(ev["worker_id"].dropna().unique()):
        wpt = ev[ev["worker_id"] == wid]["processing_time"].dropna()
        worker_stats.append({
            "worker_id": int(wid),
            "count": len(wpt),
            "mean": round(wpt.mean(), 2),
            "median": round(wpt.median(), 2),
            "p90": round(wpt.quantile(0.9), 2),
        })
    df_workers = pd.DataFrame(worker_stats)

    path = TABLES_DIR / "fig4_processing_time.csv"
    with open(path, "w") as f:
        f.write("# Histogram (1-second bins)\n")
        df_hist.to_csv(f, index=False)
        f.write("\n# Percentiles\n")
        df_pct.to_csv(f, index=False)
        f.write("\n# Per-worker Statistics\n")
        df_workers.to_csv(f, index=False)

    print(f"  -> {path}")
    print(f"  mean={pt.mean():.2f}s, p50={pt.median():.2f}s, p90={pt.quantile(0.9):.2f}s, p99={pt.quantile(0.99):.2f}s")

    return df_hist, df_pct, df_workers


def generate_statistics(data):
    """統計JSON 5件を生成"""
    print("\n[Statistics] Generating JSON files")

    s1 = data["stage1"]
    s2 = data["stage2"]
    ev = data["eval"]
    budget = data["budget"]
    n_total = len(s1)

    # ── system_overall_metrics.json ──
    s1_auto_phishing = s1[s1["stage1_decision"] == "auto_phishing"]
    s1_auto_benign = s1[s1["stage1_decision"] == "auto_benign"]
    s2_drop = s2[s2["stage2_decision"] == "drop_to_auto"]

    tp_auto = int((s1_auto_phishing["y_true"] == 1).sum())
    fp_auto = int((s1_auto_phishing["y_true"] == 0).sum())
    tn_auto = int((s1_auto_benign["y_true"] == 0).sum())
    fn_auto = int((s1_auto_benign["y_true"] == 1).sum())

    tp_s2drop = int(((s2_drop["stage1_pred"] == 1) & (s2_drop["y_true"] == 1)).sum())
    fp_s2drop = int(((s2_drop["stage1_pred"] == 1) & (s2_drop["y_true"] == 0)).sum())
    tn_s2drop = int(((s2_drop["stage1_pred"] == 0) & (s2_drop["y_true"] == 0)).sum())
    fn_s2drop = int(((s2_drop["stage1_pred"] == 0) & (s2_drop["y_true"] == 1)).sum())

    tp_s3 = int(((ev["ai_is_phishing"] == True) & (ev["y_true"] == 1)).sum())
    fp_s3 = int(((ev["ai_is_phishing"] == True) & (ev["y_true"] == 0)).sum())
    tn_s3 = int(((ev["ai_is_phishing"] == False) & (ev["y_true"] == 0)).sum())
    fn_s3 = int(((ev["ai_is_phishing"] == False) & (ev["y_true"] == 1)).sum())

    tp_all = tp_auto + tp_s2drop + tp_s3
    fp_all = fp_auto + fp_s2drop + fp_s3
    tn_all = tn_auto + tn_s2drop + tn_s3
    fn_all = fn_auto + fn_s2drop + fn_s3

    prec_all = tp_all / (tp_all + fp_all)
    rec_all = tp_all / (tp_all + fn_all)
    f1_all = 2 * prec_all * rec_all / (prec_all + rec_all)

    system_overall = {
        "total_domains": n_total,
        "confusion_matrix": {"TP": tp_all, "FP": fp_all, "TN": tn_all, "FN": fn_all},
        "precision": round(prec_all * 100, 2),
        "recall": round(rec_all * 100, 2),
        "f1": round(f1_all * 100, 2),
        "fpr": round(fp_all / (fp_all + tn_all) * 100, 2),
        "fnr": round(fn_all / (fn_all + tp_all) * 100, 2),
        "auto_decision_rate": round((n_total - len(ev)) / n_total * 100, 1),
        "stage3_rate": round(len(ev) / n_total * 100, 1),
    }
    _write_json(STATS_DIR / "system_overall_metrics.json", system_overall)

    # ── stage1_metrics.json ──
    stage1_metrics = {
        "total_domains": n_total,
        "routing": {
            "auto_phishing": {
                "count": int((s1["stage1_decision"] == "auto_phishing").sum()),
                "TP": int((s1_auto_phishing["y_true"] == 1).sum()),
                "FP": int((s1_auto_phishing["y_true"] == 0).sum()),
            },
            "auto_benign": {
                "count": int((s1["stage1_decision"] == "auto_benign").sum()),
                "TN": int((s1_auto_benign["y_true"] == 0).sum()),
                "FN": int((s1_auto_benign["y_true"] == 1).sum()),
            },
            "handoff": {
                "count": int((s1["stage1_decision"] == "handoff_to_agent").sum()),
            },
        },
        "auto_decided_total": int((s1["stage1_decision"] != "handoff_to_agent").sum()),
        "auto_decided_rate": round(
            int((s1["stage1_decision"] != "handoff_to_agent").sum()) / n_total * 100, 1
        ),
        "thresholds": {
            "t_high": 0.95713,
            "t_low": 0.00120,
        },
    }
    _write_json(STATS_DIR / "stage1_metrics.json", stage1_metrics)

    # ── stage2_metrics.json ──
    stage2_metrics = {
        "total_domains": n_total,
        "handoff_region": budget["N_stage1_handoff_region"],
        "routing": {
            "not_candidate": int((s2["stage2_decision"] == "not_candidate").sum()),
            "drop_to_auto": int((s2["stage2_decision"] == "drop_to_auto").sum()),
            "handoff_to_agent": int((s2["stage2_decision"] == "handoff_to_agent").sum()),
        },
        "drop_to_auto_detail": {
            "y_true_0": int((s2_drop["y_true"] == 0).sum()),
            "y_true_1": int((s2_drop["y_true"] == 1).sum()),
        },
        "gates": {
            "safe_benign_base": budget["stage2_select"]["safe_benign_filtered"],
            "safe_benign_cert": budget["stage2_select"]["safe_benign_cert_filtered"],
            "safe_phishing_cert": budget["stage2_select"]["safe_phishing_cert_filtered"],
            "safe_benign_combined": budget["stage2_select"]["safe_benign_combined_filtered"],
            "high_ml_phish_selected": budget["stage2_select"]["high_ml_phish"]["selected"],
        },
        "cert_rules": budget["stage2_select"]["cert_rules"],
        "auto_errors": budget["auto_errors"],
        "auto_error_rate": round(budget["auto_error_rate"] * 100, 3),
        "parameters": {
            "tau": budget["stage2_select"]["tau"],
            "override_tau": budget["stage2_select"]["override_tau"],
            "phi_phish": budget["stage2_select"]["phi_phish"],
            "phi_benign": budget["stage2_select"]["phi_benign"],
        },
    }
    _write_json(STATS_DIR / "stage2_metrics.json", stage2_metrics)

    # ── stage3_metrics.json ──
    pt = ev["processing_time"].dropna()
    stage3_metrics = {
        "total_evaluated": len(ev),
        "confusion_matrix": {"TP": tp_s3, "FP": fp_s3, "TN": tn_s3, "FN": fn_s3},
        "precision": round(tp_s3 / (tp_s3 + fp_s3) * 100, 2),
        "recall": round(tp_s3 / (tp_s3 + fn_s3) * 100, 2),
        "f1": round(
            2 * (tp_s3 / (tp_s3 + fp_s3)) * (tp_s3 / (tp_s3 + fn_s3))
            / ((tp_s3 / (tp_s3 + fp_s3)) + (tp_s3 / (tp_s3 + fn_s3)))
            * 100,
            2,
        ),
        "fpr": round(fp_s3 / (fp_s3 + tn_s3) * 100, 2),
        "processing_time": {
            "mean": round(pt.mean(), 2),
            "median": round(pt.median(), 2),
            "p10": round(pt.quantile(0.1), 2),
            "p25": round(pt.quantile(0.25), 2),
            "p50": round(pt.quantile(0.5), 2),
            "p75": round(pt.quantile(0.75), 2),
            "p90": round(pt.quantile(0.9), 2),
            "p95": round(pt.quantile(0.95), 2),
            "p99": round(pt.quantile(0.99), 2),
            "min": round(pt.min(), 2),
            "max": round(pt.max(), 2),
        },
        "error_count": int((ev["error"].notna() & (ev["error"] != "")).sum()),
        "workers": {
            str(int(wid)): int((ev["worker_id"] == wid).sum())
            for wid in sorted(ev["worker_id"].dropna().unique())
        },
    }
    _write_json(STATS_DIR / "stage3_metrics.json", stage3_metrics)

    # ── rule_firing_summary.json ──
    rules_col = ev["trace_phase6_rules_fired"]
    rule_fired_mask = rules_col.notna() & (rules_col != "[]") & (rules_col != "")
    n_rule_fired = int(rule_fired_mask.sum())

    rule_counts = {}
    rule_tp = {}
    rule_fp = {}
    for _, row in ev[rule_fired_mask].iterrows():
        try:
            rules = json.loads(row["trace_phase6_rules_fired"])
            if isinstance(rules, list):
                is_phishing = row["ai_is_phishing"]
                y_true = row["y_true"]
                for r in rules:
                    rule_counts[r] = rule_counts.get(r, 0) + 1
                    if is_phishing and y_true == 1:
                        rule_tp[r] = rule_tp.get(r, 0) + 1
                    elif is_phishing and y_true == 0:
                        rule_fp[r] = rule_fp.get(r, 0) + 1
        except (json.JSONDecodeError, TypeError):
            pass

    rule_summary = {
        "total_evaluated": len(ev),
        "domains_with_rules_fired": n_rule_fired,
        "rule_firing_rate": round(n_rule_fired / len(ev) * 100, 1),
        "rules": {
            name: {
                "fire_count": count,
                "fire_rate_pct": round(count / len(ev) * 100, 2),
                "tp_contribution": rule_tp.get(name, 0),
                "fp_contribution": rule_fp.get(name, 0),
            }
            for name, count in sorted(rule_counts.items(), key=lambda x: -x[1])
        },
    }
    _write_json(STATS_DIR / "rule_firing_summary.json", rule_summary)

    # 検証
    assert tp_all == VERIFIED["system_tp"], f"Overall TP: {tp_all} != {VERIFIED['system_tp']}"
    assert fn_all == VERIFIED["system_fn"], f"Overall FN: {fn_all} != {VERIFIED['system_fn']}"
    print(f"  ✓ All statistics verified")


def _write_json(path, data):
    """JSON書き出し"""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"  -> {path}")


# ═══════════════════════════════════════════════════════════════════════
#  Phase 2: 追加解析
# ═══════════════════════════════════════════════════════════════════════


def generate_table6(data):
    """表6: Stage3アブレーション（LLM単体 vs LLM+Rules）

    eval CSV の graph_state_slim_json → decision_trace[0].policy_trace から
    "step": "llm_raw_output" の assessment.is_phishing を抽出（ルール適用前のLLM判定）し、
    ルール適用後の最終判定 (ai_is_phishing) と比較する。
    """
    print("\n[Table 6] Stage3 ablation (LLM only vs LLM+Rules)")

    ev = data["eval"]

    # graph_state_slim_json からLLM生判定を抽出
    llm_only_decisions = []
    parse_ok = 0
    parse_fail = 0

    for _, row in ev.iterrows():
        slim_json = row.get("graph_state_slim_json", "")
        llm_decision = None

        if pd.notna(slim_json) and slim_json:
            try:
                state = json.loads(slim_json)
                # decision_trace[0].policy_trace 内の "step": "llm_raw_output" を探す
                trace = state.get("decision_trace", [])
                if trace and isinstance(trace, list):
                    policy_trace = trace[0].get("policy_trace", [])
                    for step in policy_trace:
                        if isinstance(step, dict) and step.get("step") == "llm_raw_output":
                            assessment = step.get("assessment", {})
                            if isinstance(assessment, dict):
                                llm_decision = assessment.get("is_phishing")
                            break

                if llm_decision is not None:
                    parse_ok += 1
                else:
                    parse_fail += 1
            except (json.JSONDecodeError, TypeError):
                parse_fail += 1
        else:
            parse_fail += 1

        llm_only_decisions.append(llm_decision)

    ev_abl = ev.copy()
    ev_abl["llm_only_decision"] = llm_only_decisions

    # LLM判定が取得できた行のみ
    has_llm = ev_abl["llm_only_decision"].notna()
    n_has_llm = int(has_llm.sum())
    print(f"  LLM decisions extracted: {n_has_llm}/{len(ev)} (parse_fail={parse_fail})")

    ev_valid = ev_abl[has_llm]

    # LLM Only metrics
    tp_llm = int(((ev_valid["llm_only_decision"] == True) & (ev_valid["y_true"] == 1)).sum())
    fp_llm = int(((ev_valid["llm_only_decision"] == True) & (ev_valid["y_true"] == 0)).sum())
    tn_llm = int(((ev_valid["llm_only_decision"] == False) & (ev_valid["y_true"] == 0)).sum())
    fn_llm = int(((ev_valid["llm_only_decision"] == False) & (ev_valid["y_true"] == 1)).sum())

    # LLM + Rules (final) metrics (same subset for fair comparison)
    tp_final = int(((ev_valid["ai_is_phishing"] == True) & (ev_valid["y_true"] == 1)).sum())
    fp_final = int(((ev_valid["ai_is_phishing"] == True) & (ev_valid["y_true"] == 0)).sum())
    tn_final = int(((ev_valid["ai_is_phishing"] == False) & (ev_valid["y_true"] == 0)).sum())
    fn_final = int(((ev_valid["ai_is_phishing"] == False) & (ev_valid["y_true"] == 1)).sum())

    def _metrics(tp, fp, tn, fn, label):
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0
        return {
            "configuration": label,
            "TP": tp, "FP": fp, "TN": tn, "FN": fn,
            "Precision": round(prec * 100, 2),
            "Recall": round(rec * 100, 2),
            "F1": round(f1 * 100, 2),
            "FPR": round(fp / (fp + tn) * 100, 2) if (fp + tn) > 0 else 0,
            "n_evaluated": len(ev_valid),
        }

    rows = [
        _metrics(tp_llm, fp_llm, tn_llm, fn_llm, "LLM only"),
        _metrics(tp_final, fp_final, tn_final, fn_final, "LLM + Rules"),
    ]

    # ルール効果分析: LLM判定がルールで変更された件数
    flipped = ev_valid["llm_only_decision"] != ev_valid["ai_is_phishing"]
    n_flipped = int(flipped.sum())

    flip_to_phishing = int(
        ((ev_valid["llm_only_decision"] == False) & (ev_valid["ai_is_phishing"] == True)).sum()
    )
    flip_to_benign = int(
        ((ev_valid["llm_only_decision"] == True) & (ev_valid["ai_is_phishing"] == False)).sum()
    )

    # Flip correctness analysis
    flipped_rows = ev_valid[flipped]
    flip_correct = int(
        (flipped_rows["ai_is_phishing"] == flipped_rows["y_true"].astype(bool)).sum()
    )
    flip_incorrect = n_flipped - flip_correct

    rule_effect = {
        "total_flipped": n_flipped,
        "flip_to_phishing": flip_to_phishing,
        "flip_to_benign": flip_to_benign,
        "flip_rate_pct": round(n_flipped / len(ev_valid) * 100, 2),
        "flip_correct": flip_correct,
        "flip_incorrect": flip_incorrect,
        "flip_accuracy_pct": round(flip_correct / n_flipped * 100, 2) if n_flipped > 0 else 0,
    }

    df = pd.DataFrame(rows)
    df_effect = pd.DataFrame([rule_effect])

    path = TABLES_DIR / "table6_stage3_ablation.csv"
    with open(path, "w") as f:
        f.write("# Stage3 Ablation: LLM only vs LLM + Rules\n")
        df.to_csv(f, index=False)
        f.write("\n# Rule Effect on Decision Flips\n")
        df_effect.to_csv(f, index=False)

    print(f"  -> {path}")
    print(f"  LLM Only:  P={rows[0]['Precision']}% R={rows[0]['Recall']}% F1={rows[0]['F1']}%")
    print(f"  LLM+Rules: P={rows[1]['Precision']}% R={rows[1]['Recall']}% F1={rows[1]['F1']}%")
    print(f"  Flips: {n_flipped} ({rule_effect['flip_rate_pct']}%) "
          f"[→phish:{flip_to_phishing}, →benign:{flip_to_benign}] "
          f"accuracy:{rule_effect['flip_accuracy_pct']}%")

    return df, rule_effect


def generate_fig3_data(data):
    """図3データ: 投入率 vs 性能トレードオフ（閾値スイープ）

    stage2_candidates CSV の p_error 閾値を変化させ、
    各閾値でのStage3投入率と自動判定エラー率をシミュレーション。

    注意: 実際のStage2選択ロジックはpriority/optionalプール等の複雑な処理を含むため、
    p_error閾値のみの単純スイープは近似値。tau=0.4の実測値は `selected` 列から取得。
    """
    print("\n[Fig 3] Threshold sweep: budget vs performance tradeoff")

    cand = data["stage2_candidates"]
    s1 = data["stage1"]

    # Stage1自動判定の固定部分
    s1_auto = s1[s1["stage1_decision"] != "handoff_to_agent"]
    n_s1_auto = len(s1_auto)
    n_total = len(s1)
    n_candidates = len(cand)

    # Stage1自動判定の誤り（固定）
    s1_auto_phishing = s1[s1["stage1_decision"] == "auto_phishing"]
    s1_auto_benign = s1[s1["stage1_decision"] == "auto_benign"]
    s1_fp = int((s1_auto_phishing["y_true"] == 0).sum())  # 2
    s1_fn = int((s1_auto_benign["y_true"] == 1).sum())     # 3
    s1_errors = s1_fp + s1_fn  # 5

    # p_error閾値スイープ
    thresholds = np.arange(0.0, 1.01, 0.02)
    results = []

    for tau in thresholds:
        tau_r = round(tau, 2)

        # tau=0.4 は実際のselected列を使用（実測値）
        if tau_r == 0.40:
            selected = cand["selected"] == 1
        else:
            # safe_benign_combinedでdropされた行
            safe_dropped = cand["safe_benign_combined"] == 1
            # p_error >= tau かつ safe_benignでない → Stage3送り
            selected = (~safe_dropped) & (cand["p_error"] >= tau)
            # high_ml_phish override は常に含める
            selected = selected | (cand["high_ml_phish"] == 1)

        n_selected = int(selected.sum())
        n_dropped = n_candidates - n_selected

        # dropされた行の誤り（MLの予測が間違っている件数）
        dropped = cand[~selected]
        drop_fn = int(((dropped["stage1_pred"] == 0) & (dropped["y_true"] == 1)).sum())
        drop_fp = int(((dropped["stage1_pred"] == 1) & (dropped["y_true"] == 0)).sum())
        drop_errors = drop_fn + drop_fp

        # 全自動判定の誤り
        total_auto_errors = s1_errors + drop_errors
        total_auto = n_s1_auto + n_dropped

        results.append({
            "tau": tau_r,
            "stage3_count": n_selected,
            "stage3_rate_pct": round(n_selected / n_total * 100, 2),
            "auto_decided": total_auto,
            "auto_errors": total_auto_errors,
            "auto_error_rate_pct": round(total_auto_errors / total_auto * 100, 4) if total_auto > 0 else 0,
            "auto_fn": s1_fn + drop_fn,
            "auto_fp": s1_fp + drop_fp,
        })

    df = pd.DataFrame(results)
    path = TABLES_DIR / "fig3_threshold_sweep.csv"
    df.to_csv(path, index=False)
    print(f"  -> {path}")

    # 現在設定(tau=0.4)の行を確認
    current = df[df["tau"] == 0.40]
    if len(current) > 0:
        row = current.iloc[0]
        print(f"  Current setting (tau=0.4): Stage3={int(row['stage3_count']):,} "
              f"({row['stage3_rate_pct']}%), auto_errors={int(row['auto_errors'])}")
        assert int(row["stage3_count"]) == VERIFIED["stage2_handoff_to_agent"], \
            f"tau=0.4 count mismatch: {int(row['stage3_count'])} != {VERIFIED['stage2_handoff_to_agent']}"
        print(f"  ✓ tau=0.4 verified: {VERIFIED['stage2_handoff_to_agent']:,} domains")

    return df


def generate_fig5_data(data):
    """図5データ: 誤り分析（FN/FPカテゴリ別）

    FN 1,157件をStage別に分類し、さらにパターン分析を行う。
    """
    print("\n[Fig 5] Error category analysis")

    s1 = data["stage1"]
    s2 = data["stage2"]
    ev = data["eval"]

    # ── FN分析 ──
    # Stage1 FN: auto_benign で y_true=1
    s1_fn = s1[(s1["stage1_decision"] == "auto_benign") & (s1["y_true"] == 1)]
    n_s1_fn = len(s1_fn)  # 3

    # Stage2 FN: drop_to_auto で y_true=1 かつ stage1_pred=0 (benignと予測)
    s2_drop = s2[s2["stage2_decision"] == "drop_to_auto"]
    s2_fn = s2_drop[(s2_drop["stage1_pred"] == 0) & (s2_drop["y_true"] == 1)]
    n_s2_fn = len(s2_fn)  # 398

    # Stage3 FN: ai_is_phishing=False で y_true=1
    s3_fn = ev[(ev["ai_is_phishing"] == False) & (ev["y_true"] == 1)]
    n_s3_fn = len(s3_fn)  # 759

    total_fn = n_s1_fn + n_s2_fn + n_s3_fn

    # ── FP分析 ──
    # Stage1 FP: auto_phishing で y_true=0
    s1_fp = s1[(s1["stage1_decision"] == "auto_phishing") & (s1["y_true"] == 0)]
    n_s1_fp = len(s1_fp)  # 2

    # Stage2 FP: drop_to_auto で y_true=0 かつ stage1_pred=1 (phishingと予測)
    s2_fp = s2_drop[(s2_drop["stage1_pred"] == 1) & (s2_drop["y_true"] == 0)]
    n_s2_fp = len(s2_fp)  # 少数

    # Stage3 FP: ai_is_phishing=True で y_true=0
    s3_fp = ev[(ev["ai_is_phishing"] == True) & (ev["y_true"] == 0)]
    n_s3_fp = len(s3_fp)  # 532

    total_fp = n_s1_fp + n_s2_fp + n_s3_fp

    # FN/FPサマリ
    fn_rows = [
        ("Stage1 (auto_benign)", n_s1_fn, round(n_s1_fn / total_fn * 100, 1) if total_fn > 0 else 0),
        ("Stage2 (drop_to_auto)", n_s2_fn, round(n_s2_fn / total_fn * 100, 1) if total_fn > 0 else 0),
        ("Stage3 (LLM+Rules)", n_s3_fn, round(n_s3_fn / total_fn * 100, 1) if total_fn > 0 else 0),
        ("Total", total_fn, 100.0),
    ]

    fp_rows = [
        ("Stage1 (auto_phishing)", n_s1_fp, round(n_s1_fp / total_fp * 100, 1) if total_fp > 0 else 0),
        ("Stage2 (drop_to_auto)", n_s2_fp, round(n_s2_fp / total_fp * 100, 1) if total_fp > 0 else 0),
        ("Stage3 (LLM+Rules)", n_s3_fp, round(n_s3_fp / total_fp * 100, 1) if total_fp > 0 else 0),
        ("Total", total_fp, 100.0),
    ]

    df_fn = pd.DataFrame(fn_rows, columns=["stage", "count", "percentage"])
    df_fp = pd.DataFrame(fp_rows, columns=["stage", "count", "percentage"])

    # Stage3 FN のML確率分布
    if len(s3_fn) > 0:
        s3_fn_ml = s3_fn["ml_probability"]
        fn_ml_stats = {
            "mean": round(s3_fn_ml.mean(), 4),
            "median": round(s3_fn_ml.median(), 4),
            "p25": round(s3_fn_ml.quantile(0.25), 4),
            "p75": round(s3_fn_ml.quantile(0.75), 4),
        }
    else:
        fn_ml_stats = {}

    # Stage3 FP のML確率分布
    if len(s3_fp) > 0:
        s3_fp_ml = s3_fp["ml_probability"]
        fp_ml_stats = {
            "mean": round(s3_fp_ml.mean(), 4),
            "median": round(s3_fp_ml.median(), 4),
            "p25": round(s3_fp_ml.quantile(0.25), 4),
            "p75": round(s3_fp_ml.quantile(0.75), 4),
        }
    else:
        fp_ml_stats = {}

    # Stage3 FNのソース別分布
    if len(s3_fn) > 0 and "source" in s3_fn.columns:
        fn_by_source = s3_fn["source"].value_counts().to_dict()
    else:
        fn_by_source = {}

    # Stage3 FPのソース別分布
    if len(s3_fp) > 0 and "source" in s3_fp.columns:
        fp_by_source = s3_fp["source"].value_counts().to_dict()
    else:
        fp_by_source = {}

    # Stage3 FNのTLD分布 (上位10)
    if len(s3_fn) > 0 and "tld" in s3_fn.columns:
        fn_by_tld = s3_fn["tld"].value_counts().head(10).to_dict()
    else:
        fn_by_tld = {}

    path = TABLES_DIR / "fig5_error_categories.csv"
    with open(path, "w") as f:
        f.write("# False Negatives by Stage\n")
        df_fn.to_csv(f, index=False)
        f.write("\n# False Positives by Stage\n")
        df_fp.to_csv(f, index=False)
        f.write(f"\n# Stage3 FN ML probability stats: {json.dumps(fn_ml_stats)}\n")
        f.write(f"# Stage3 FP ML probability stats: {json.dumps(fp_ml_stats)}\n")
        f.write(f"# Stage3 FN by source: {json.dumps(fn_by_source)}\n")
        f.write(f"# Stage3 FP by source: {json.dumps(fp_by_source)}\n")
        f.write(f"# Stage3 FN top TLDs: {json.dumps(fn_by_tld)}\n")

    print(f"  -> {path}")
    print(f"  FN: Stage1={n_s1_fn}, Stage2={n_s2_fn}, Stage3={n_s3_fn}, Total={total_fn}")
    print(f"  FP: Stage1={n_s1_fp}, Stage2={n_s2_fp}, Stage3={n_s3_fp}, Total={total_fp}")

    # 検証
    assert total_fn == VERIFIED["system_fn"], f"Total FN: {total_fn} != {VERIFIED['system_fn']}"
    assert total_fp == VERIFIED["system_fp"], f"Total FP: {total_fp} != {VERIFIED['system_fp']}"
    print(f"  ✓ Error totals verified: FN={total_fn}, FP={total_fp}")

    return df_fn, df_fp


# ═══════════════════════════════════════════════════════════════════════
#  Verification
# ═══════════════════════════════════════════════════════════════════════


def verify_all():
    """生成済みデータの検証"""
    print("\n" + "=" * 60)
    print("VERIFICATION")
    print("=" * 60)

    errors = []

    # system_overall_metrics.json
    path = STATS_DIR / "system_overall_metrics.json"
    if path.exists():
        with open(path) as f:
            m = json.load(f)
        cm = m["confusion_matrix"]
        checks = [
            ("System TP", cm["TP"], VERIFIED["system_tp"]),
            ("System FP", cm["FP"], VERIFIED["system_fp"]),
            ("System TN", cm["TN"], VERIFIED["system_tn"]),
            ("System FN", cm["FN"], VERIFIED["system_fn"]),
            ("System F1", m["f1"], VERIFIED["system_f1"]),
            ("System Precision", m["precision"], VERIFIED["system_precision"]),
            ("System Recall", m["recall"], VERIFIED["system_recall"]),
        ]
        for name, actual, expected in checks:
            if actual != expected:
                errors.append(f"  ✗ {name}: {actual} != {expected}")
            else:
                print(f"  ✓ {name}: {actual}")
    else:
        errors.append(f"  ✗ {path} not found")

    # stage3_metrics.json
    path = STATS_DIR / "stage3_metrics.json"
    if path.exists():
        with open(path) as f:
            m = json.load(f)
        cm = m["confusion_matrix"]
        checks = [
            ("Stage3 TP", cm["TP"], VERIFIED["stage3_tp"]),
            ("Stage3 FP", cm["FP"], VERIFIED["stage3_fp"]),
            ("Stage3 TN", cm["TN"], VERIFIED["stage3_tn"]),
            ("Stage3 FN", cm["FN"], VERIFIED["stage3_fn"]),
            ("Stage3 F1", m["f1"], VERIFIED["stage3_f1"]),
        ]
        for name, actual, expected in checks:
            if actual != expected:
                errors.append(f"  ✗ {name}: {actual} != {expected}")
            else:
                print(f"  ✓ {name}: {actual}")
    else:
        errors.append(f"  ✗ {path} not found")

    # stage2_metrics.json - 投入率チェック
    path = STATS_DIR / "stage2_metrics.json"
    if path.exists():
        with open(path) as f:
            m = json.load(f)
        n_handoff = m["routing"]["handoff_to_agent"]
        if n_handoff != VERIFIED["stage2_handoff_to_agent"]:
            errors.append(f"  ✗ Stage2 handoff: {n_handoff} != {VERIFIED['stage2_handoff_to_agent']}")
        else:
            print(f"  ✓ Stage2 handoff: {n_handoff} (rate: {n_handoff/VERIFIED['dataset_test']*100:.1f}%)")

    if errors:
        print("\nERRORS:")
        for e in errors:
            print(e)
        return False
    else:
        print("\n✓ All verifications passed!")
        return True


# ═══════════════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════════════


def main():
    parser = argparse.ArgumentParser(description="Generate paper data files")
    parser.add_argument("--phase", type=int, choices=[1, 2], help="Run specific phase only")
    parser.add_argument("--verify", action="store_true", help="Run verification only")
    args = parser.parse_args()

    ensure_dirs()

    if args.verify:
        verify_all()
        return

    # Load data
    data = load_data()

    if args.phase is None or args.phase == 1:
        print("\n" + "=" * 60)
        print("PHASE 1: Immediate generation")
        print("=" * 60)

        generate_table1()
        generate_table2()
        generate_table3(data)
        generate_table4(data)
        generate_table5(data)
        generate_fig2_data(data)
        generate_fig4_data(data)
        generate_statistics(data)

    if args.phase is None or args.phase == 2:
        print("\n" + "=" * 60)
        print("PHASE 2: Additional analysis")
        print("=" * 60)

        generate_table6(data)
        generate_fig3_data(data)
        generate_fig5_data(data)

    # Final verification
    verify_all()


if __name__ == "__main__":
    main()
