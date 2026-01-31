#!/usr/bin/env python3
"""
FP/FN トレース分析スクリプト

評価結果のトレースフィールドを分析し、FP/FNの原因を特定する。

使用方法:
    python scripts/analyze_trace.py                    # 最新の結果を分析
    python scripts/analyze_trace.py --fp               # FPのみ分析
    python scripts/analyze_trace.py --fn               # FNのみ分析
    python scripts/analyze_trace.py --domain example.com  # 特定ドメインの詳細
    python scripts/analyze_trace.py --export fp_analysis.json  # JSON出力

変更履歴:
    - 2026-01-28: 初版作成
"""

import argparse
import json
import glob
import pandas as pd
from pathlib import Path
from typing import Dict, List, Any, Optional
from collections import Counter


def load_results(result_dir: Optional[str] = None) -> pd.DataFrame:
    """評価結果を読み込む"""
    if result_dir is None:
        # 最新のartifactsディレクトリを探す
        artifacts = sorted(glob.glob("artifacts/*/results/stage2_validation"))
        if not artifacts:
            raise FileNotFoundError("No evaluation results found")
        result_dir = artifacts[-1]

    csv_files = glob.glob(f"{result_dir}/worker_*_results.csv")
    if not csv_files:
        raise FileNotFoundError(f"No worker results in {result_dir}")

    dfs = []
    for f in csv_files:
        try:
            df = pd.read_csv(f)
            if len(df) > 0:
                dfs.append(df)
        except Exception as e:
            print(f"Warning: Failed to load {f}: {e}")

    if not dfs:
        raise ValueError("No valid results found")

    return pd.concat(dfs, ignore_index=True)


def safe_json_loads(s: Any) -> Any:
    """安全にJSONをパース"""
    if pd.isna(s) or s is None:
        return None
    if isinstance(s, (dict, list)):
        return s
    try:
        return json.loads(str(s))
    except:
        return str(s)


def get_fp_cases(df: pd.DataFrame) -> pd.DataFrame:
    """FPケースを抽出"""
    return df[(df['ai_is_phishing'] == True) & (df['y_true'] == 0)].copy()


def get_fn_cases(df: pd.DataFrame) -> pd.DataFrame:
    """FNケースを抽出"""
    return df[(df['ai_is_phishing'] == False) & (df['y_true'] == 1)].copy()


def analyze_domain(row: pd.Series) -> Dict[str, Any]:
    """単一ドメインの詳細分析"""
    result = {
        "domain": row['domain'],
        "ground_truth": "phishing" if row['y_true'] == 1 else "legitimate",
        "prediction": "phishing" if row['ai_is_phishing'] else "legitimate",
        "ml_probability": row['ml_probability'],
        "ai_confidence": row['ai_confidence'],
        "ai_risk_level": row['ai_risk_level'],
        "ai_reasoning": row.get('ai_reasoning'),
        "classification": None,
    }

    # 分類
    if row['ai_is_phishing'] and row['y_true'] == 0:
        result["classification"] = "FP"
    elif not row['ai_is_phishing'] and row['y_true'] == 1:
        result["classification"] = "FN"
    elif row['ai_is_phishing'] and row['y_true'] == 1:
        result["classification"] = "TP"
    else:
        result["classification"] = "TN"

    # graph_state_slim から追加情報取得
    graph_state = safe_json_loads(row.get('graph_state_slim_json')) or {}
    precheck_hints = graph_state.get('precheck_hints', {})
    precheck_stats = precheck_hints.get('stats', {})

    # トレース情報
    result["trace"] = {
        "precheck": {
            "ml_category": precheck_hints.get('ml_category') or row.get('trace_precheck_ml_category'),
            "tld_category": precheck_hints.get('tld_category') or row.get('trace_precheck_tld_category'),
            "brand_detected": precheck_hints.get('brand_detected') or row.get('trace_precheck_brand_detected'),
            "potential_brands": precheck_hints.get('potential_brands', []),
            "high_risk_hits": precheck_stats.get('high_risk_hits') or row.get('trace_precheck_high_risk_hits'),
            "phishing_tld_weight": precheck_stats.get('phishing_tld_weight', 0),
            "quick_risk": precheck_hints.get('quick_risk') or row.get('trace_precheck_quick_risk'),
        },
        "tools": {
            "selected": safe_json_loads(row.get('trace_selected_tools')) or graph_state.get('selected_tools'),
            "execution_flags": graph_state.get('tool_execution_flags'),
            "brand_risk_score": row.get('trace_brand_risk_score'),
            "cert_risk_score": row.get('trace_cert_risk_score'),
            "domain_risk_score": row.get('trace_domain_risk_score'),
            "ctx_risk_score": row.get('trace_ctx_risk_score'),
            "timings_ms": graph_state.get('tool_timings_ms'),
        },
        "ctx_issues": safe_json_loads(row.get('trace_ctx_issues')),
        "phase6_rules_fired": safe_json_loads(row.get('trace_phase6_rules_fired')) or graph_state.get('phase6_rules_fired'),
        "decision_trace": graph_state.get('decision_trace'),
        "fallback_info": graph_state.get('fallback_info'),
        "debug_llm_final": graph_state.get('debug_llm_final'),
    }

    # ツール出力詳細
    result["tool_outputs"] = {
        "brand": safe_json_loads(row.get('tool_brand_output')),
        "cert": safe_json_loads(row.get('tool_cert_output')),
        "domain": safe_json_loads(row.get('tool_domain_output')),
        "ctx": safe_json_loads(row.get('tool_ctx_output')),
    }

    # リスク要因
    result["risk_factors"] = safe_json_loads(row.get('ai_risk_factors'))
    result["detected_brands"] = safe_json_loads(row.get('ai_detected_brands'))

    # Final Assessment (生データ)
    result["final_assessment_raw"] = graph_state.get('final_assessment')

    return result


def summarize_fp(df: pd.DataFrame) -> Dict[str, Any]:
    """FPの統計サマリー"""
    fp = get_fp_cases(df)

    if len(fp) == 0:
        return {"count": 0, "message": "No FP cases"}

    # TLD分布
    tld_counts = fp['tld'].value_counts().head(10).to_dict()

    # ML確率分布
    ml_bins = {
        "ml < 0.1": len(fp[fp['ml_probability'] < 0.1]),
        "ml 0.1-0.3": len(fp[(fp['ml_probability'] >= 0.1) & (fp['ml_probability'] < 0.3)]),
        "ml 0.3-0.5": len(fp[(fp['ml_probability'] >= 0.3) & (fp['ml_probability'] < 0.5)]),
        "ml >= 0.5": len(fp[fp['ml_probability'] >= 0.5]),
    }

    # リスクレベル分布
    risk_level_counts = fp['ai_risk_level'].value_counts().to_dict()

    # コンテキストスコア分布
    ctx_scores = fp['trace_ctx_risk_score'].dropna()
    ctx_bins = {
        "ctx < 0.2": len(ctx_scores[ctx_scores < 0.2]),
        "ctx 0.2-0.5": len(ctx_scores[(ctx_scores >= 0.2) & (ctx_scores < 0.5)]),
        "ctx >= 0.5": len(ctx_scores[ctx_scores >= 0.5]),
    }

    # リスク要因集計
    risk_factors_counter = Counter()
    for rf in fp['ai_risk_factors'].dropna():
        factors = safe_json_loads(rf)
        if isinstance(factors, list):
            risk_factors_counter.update(factors)

    # Phase6ルール集計
    rules_counter = Counter()
    for rules in fp['trace_phase6_rules_fired'].dropna():
        rule_list = safe_json_loads(rules)
        if isinstance(rule_list, list):
            rules_counter.update(rule_list)

    return {
        "count": len(fp),
        "tld_distribution": tld_counts,
        "ml_distribution": ml_bins,
        "risk_level_distribution": risk_level_counts,
        "ctx_score_distribution": ctx_bins,
        "top_risk_factors": dict(risk_factors_counter.most_common(15)),
        "top_phase6_rules": dict(rules_counter.most_common(10)),
    }


def summarize_fn(df: pd.DataFrame) -> Dict[str, Any]:
    """FNの統計サマリー"""
    fn = get_fn_cases(df)

    if len(fn) == 0:
        return {"count": 0, "message": "No FN cases"}

    # TLD分布
    tld_counts = fn['tld'].value_counts().head(10).to_dict()

    # ML確率分布
    ml_bins = {
        "ml < 0.3": len(fn[fn['ml_probability'] < 0.3]),
        "ml 0.3-0.5": len(fn[(fn['ml_probability'] >= 0.3) & (fn['ml_probability'] < 0.5)]),
        "ml 0.5-0.7": len(fn[(fn['ml_probability'] >= 0.5) & (fn['ml_probability'] < 0.7)]),
        "ml >= 0.7": len(fn[fn['ml_probability'] >= 0.7]),
    }

    # リスクレベル分布
    risk_level_counts = fn['ai_risk_level'].value_counts().to_dict()

    # コンテキストスコア分布
    ctx_scores = fn['trace_ctx_risk_score'].dropna()
    ctx_bins = {
        "ctx < 0.2": len(ctx_scores[ctx_scores < 0.2]),
        "ctx 0.2-0.5": len(ctx_scores[(ctx_scores >= 0.2) & (ctx_scores < 0.5)]),
        "ctx >= 0.5": len(ctx_scores[ctx_scores >= 0.5]),
    }

    # ツールスコアの統計
    tool_scores = {
        "brand_score_mean": fn['trace_brand_risk_score'].dropna().mean(),
        "cert_score_mean": fn['trace_cert_risk_score'].dropna().mean(),
        "domain_score_mean": fn['trace_domain_risk_score'].dropna().mean(),
        "ctx_score_mean": fn['trace_ctx_risk_score'].dropna().mean(),
    }

    return {
        "count": len(fn),
        "tld_distribution": tld_counts,
        "ml_distribution": ml_bins,
        "risk_level_distribution": risk_level_counts,
        "ctx_score_distribution": ctx_bins,
        "tool_scores": tool_scores,
    }


def print_domain_detail(analysis: Dict[str, Any]):
    """ドメイン詳細を表示"""
    print(f"\n{'='*60}")
    print(f"Domain: {analysis['domain']}")
    print(f"{'='*60}")
    print(f"Classification: {analysis['classification']}")
    print(f"Ground Truth: {analysis['ground_truth']}")
    print(f"Prediction: {analysis['prediction']}")
    print(f"ML Probability: {analysis['ml_probability']:.4f}")
    print(f"AI Confidence: {analysis['ai_confidence']:.2f}")
    print(f"AI Risk Level: {analysis['ai_risk_level']}")

    print(f"\n--- Reasoning ---")
    print(analysis['ai_reasoning'] or "(none)")

    print(f"\n--- Risk Factors ---")
    print(analysis['risk_factors'] or "(none)")

    print(f"\n--- Detected Brands ---")
    print(analysis['detected_brands'] or "(none)")

    trace = analysis['trace']
    print(f"\n--- Precheck ---")
    for k, v in trace['precheck'].items():
        print(f"  {k}: {v}")

    print(f"\n--- Tool Scores & Selection ---")
    tools = trace['tools']
    print(f"  selected: {tools.get('selected')}")
    print(f"  execution_flags: {tools.get('execution_flags')}")
    print(f"  brand_risk_score: {tools.get('brand_risk_score')}")
    print(f"  cert_risk_score: {tools.get('cert_risk_score')}")
    print(f"  domain_risk_score: {tools.get('domain_risk_score')}")
    print(f"  ctx_risk_score: {tools.get('ctx_risk_score')}")
    if tools.get('timings_ms'):
        print(f"  timings_ms: {tools.get('timings_ms')}")

    print(f"\n--- Ctx Issues ---")
    print(trace['ctx_issues'] or "(none)")

    print(f"\n--- Phase6 Rules Fired ---")
    print(trace['phase6_rules_fired'] or "(none)")

    # LLM Debug Info
    debug_llm = trace.get('debug_llm_final')
    if debug_llm:
        print(f"\n--- LLM Debug ---")
        print(f"  success: {debug_llm.get('success')}")
        print(f"  so_failure: {debug_llm.get('so_failure')}")
        print(f"  use_llm_decision: {debug_llm.get('use_llm_decision')}")
        print(f"  path: {debug_llm.get('path')}")

    # Decision Trace
    if trace.get('decision_trace'):
        print(f"\n--- Decision Trace ---")
        print(json.dumps(trace['decision_trace'], indent=2, ensure_ascii=False)[:500])

    # Fallback Info
    if trace.get('fallback_info'):
        print(f"\n--- Fallback Info ---")
        print(trace['fallback_info'])

    print(f"\n--- Tool Outputs ---")
    for tool_name, output in analysis['tool_outputs'].items():
        if output:
            print(f"\n[{tool_name}]")
            if isinstance(output, dict):
                for k, v in output.items():
                    if k not in ['graph_state_slim_json']:  # Skip large fields
                        v_str = str(v)
                        if len(v_str) > 200:
                            v_str = v_str[:200] + "..."
                        print(f"  {k}: {v_str}")
            else:
                print(f"  {output}")


def print_summary(summary: Dict[str, Any], title: str):
    """サマリーを表示"""
    print(f"\n{'='*60}")
    print(f"{title}")
    print(f"{'='*60}")

    print(f"\nTotal: {summary['count']} cases")

    if summary['count'] == 0:
        return

    print(f"\n--- TLD Distribution ---")
    for tld, count in summary.get('tld_distribution', {}).items():
        print(f"  .{tld}: {count}")

    print(f"\n--- ML Distribution ---")
    for bin_name, count in summary.get('ml_distribution', {}).items():
        print(f"  {bin_name}: {count}")

    print(f"\n--- Risk Level Distribution ---")
    for level, count in summary.get('risk_level_distribution', {}).items():
        print(f"  {level}: {count}")

    print(f"\n--- Context Score Distribution ---")
    for bin_name, count in summary.get('ctx_score_distribution', {}).items():
        print(f"  {bin_name}: {count}")

    if 'top_risk_factors' in summary:
        print(f"\n--- Top Risk Factors ---")
        for factor, count in summary['top_risk_factors'].items():
            print(f"  {factor}: {count}")

    if 'top_phase6_rules' in summary:
        print(f"\n--- Top Phase6 Rules ---")
        for rule, count in summary['top_phase6_rules'].items():
            print(f"  {rule}: {count}")

    if 'tool_scores' in summary:
        print(f"\n--- Tool Score Means ---")
        for tool, score in summary['tool_scores'].items():
            if pd.notna(score):
                print(f"  {tool}: {score:.4f}")


def main():
    parser = argparse.ArgumentParser(description="FP/FN Trace Analysis")
    parser.add_argument("--result-dir", type=str, default=None,
                        help="Path to results directory")
    parser.add_argument("--fp", action="store_true",
                        help="Analyze FP cases only")
    parser.add_argument("--fn", action="store_true",
                        help="Analyze FN cases only")
    parser.add_argument("--domain", type=str, default=None,
                        help="Analyze specific domain")
    parser.add_argument("--list-fp", type=int, default=0,
                        help="List N FP domains with details")
    parser.add_argument("--list-fn", type=int, default=0,
                        help="List N FN domains with details")
    parser.add_argument("--export", type=str, default=None,
                        help="Export analysis to JSON file")
    args = parser.parse_args()

    # 結果読み込み
    print("Loading results...")
    df = load_results(args.result_dir)
    print(f"Loaded {len(df)} results")

    # 基本統計
    tp = ((df['ai_is_phishing'] == True) & (df['y_true'] == 1)).sum()
    tn = ((df['ai_is_phishing'] == False) & (df['y_true'] == 0)).sum()
    fp = ((df['ai_is_phishing'] == True) & (df['y_true'] == 0)).sum()
    fn = ((df['ai_is_phishing'] == False) & (df['y_true'] == 1)).sum()

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    print(f"\n=== Overall Metrics ===")
    print(f"TP={tp} FN={fn} FP={fp} TN={tn}")
    print(f"Precision={precision:.3f} Recall={recall:.3f} F1={f1:.3f}")

    # 特定ドメイン分析
    if args.domain:
        domain_rows = df[df['domain'] == args.domain]
        if len(domain_rows) == 0:
            print(f"Domain not found: {args.domain}")
            return
        analysis = analyze_domain(domain_rows.iloc[0])
        print_domain_detail(analysis)

        if args.export:
            with open(args.export, 'w') as f:
                json.dump(analysis, f, indent=2, ensure_ascii=False, default=str)
            print(f"\nExported to {args.export}")
        return

    # FP/FNサマリー
    export_data = {}

    if args.fp or (not args.fn):
        fp_summary = summarize_fp(df)
        print_summary(fp_summary, "FP Analysis Summary")
        export_data['fp_summary'] = fp_summary

    if args.fn or (not args.fp):
        fn_summary = summarize_fn(df)
        print_summary(fn_summary, "FN Analysis Summary")
        export_data['fn_summary'] = fn_summary

    # FPリスト
    if args.list_fp > 0:
        fp_df = get_fp_cases(df)
        print(f"\n{'='*60}")
        print(f"FP Cases (showing {min(args.list_fp, len(fp_df))} of {len(fp_df)})")
        print(f"{'='*60}")

        fp_list = []
        for _, row in fp_df.head(args.list_fp).iterrows():
            analysis = analyze_domain(row)
            print_domain_detail(analysis)
            fp_list.append(analysis)
        export_data['fp_cases'] = fp_list

    # FNリスト
    if args.list_fn > 0:
        fn_df = get_fn_cases(df)
        print(f"\n{'='*60}")
        print(f"FN Cases (showing {min(args.list_fn, len(fn_df))} of {len(fn_df)})")
        print(f"{'='*60}")

        fn_list = []
        for _, row in fn_df.head(args.list_fn).iterrows():
            analysis = analyze_domain(row)
            print_domain_detail(analysis)
            fn_list.append(analysis)
        export_data['fn_cases'] = fn_list

    # エクスポート
    if args.export:
        with open(args.export, 'w') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False, default=str)
        print(f"\nExported to {args.export}")


if __name__ == "__main__":
    main()
