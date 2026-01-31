"""
トレース分析ユーティリティ

Jupyter NotebookやREPLでの対話的分析用ヘルパー関数。

使用例:
    from scripts.trace_utils import *

    # データ読み込み
    df = load_latest_results()

    # FP/FN抽出
    fp = get_fp(df)
    fn = get_fn(df)

    # ドメイン詳細
    show_domain(df, "example.com")

    # FPサマリー
    fp_summary(df)

変更履歴:
    - 2026-01-28: 初版作成
"""

import json
import glob
import pandas as pd
from typing import Dict, Any, Optional, List
from collections import Counter
from IPython.display import display, HTML


def load_latest_results() -> pd.DataFrame:
    """最新の評価結果を読み込む"""
    artifacts = sorted(glob.glob("artifacts/*/results/stage2_validation"))
    if not artifacts:
        raise FileNotFoundError("No evaluation results found")
    result_dir = artifacts[-1]

    csv_files = glob.glob(f"{result_dir}/worker_*_results.csv")
    dfs = [pd.read_csv(f) for f in csv_files if pd.read_csv(f).shape[0] > 0]
    df = pd.concat(dfs, ignore_index=True)
    print(f"Loaded {len(df)} results from {result_dir}")
    return df


def parse_json(s: Any) -> Any:
    """JSON文字列をパース"""
    if pd.isna(s) or s is None:
        return None
    if isinstance(s, (dict, list)):
        return s
    try:
        return json.loads(str(s))
    except:
        return str(s)


def get_fp(df: pd.DataFrame) -> pd.DataFrame:
    """FPケースを抽出"""
    return df[(df['ai_is_phishing'] == True) & (df['y_true'] == 0)].copy()


def get_fn(df: pd.DataFrame) -> pd.DataFrame:
    """FNケースを抽出"""
    return df[(df['ai_is_phishing'] == False) & (df['y_true'] == 1)].copy()


def get_tp(df: pd.DataFrame) -> pd.DataFrame:
    """TPケースを抽出"""
    return df[(df['ai_is_phishing'] == True) & (df['y_true'] == 1)].copy()


def get_tn(df: pd.DataFrame) -> pd.DataFrame:
    """TNケースを抽出"""
    return df[(df['ai_is_phishing'] == False) & (df['y_true'] == 0)].copy()


def metrics(df: pd.DataFrame) -> Dict[str, float]:
    """評価指標を計算"""
    tp = len(get_tp(df))
    tn = len(get_tn(df))
    fp = len(get_fp(df))
    fn = len(get_fn(df))

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    return {
        "TP": tp, "TN": tn, "FP": fp, "FN": fn,
        "Precision": precision, "Recall": recall, "F1": f1,
        "Accuracy": (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
    }


def get_graph_state(row: pd.Series) -> Dict[str, Any]:
    """graph_state_slim_jsonをパースして返す"""
    slim = row.get('graph_state_slim_json')
    if pd.isna(slim):
        return {}
    return parse_json(slim) or {}


def show_domain(df: pd.DataFrame, domain: str, full_output: bool = False):
    """ドメインの詳細を表示"""
    rows = df[df['domain'] == domain]
    if len(rows) == 0:
        print(f"Domain not found: {domain}")
        return

    row = rows.iloc[0]
    graph_state = get_graph_state(row)

    # 分類
    if row['ai_is_phishing'] and row['y_true'] == 0:
        classification = "FP"
    elif not row['ai_is_phishing'] and row['y_true'] == 1:
        classification = "FN"
    elif row['ai_is_phishing'] and row['y_true'] == 1:
        classification = "TP"
    else:
        classification = "TN"

    print(f"{'='*60}")
    print(f"Domain: {domain}")
    print(f"{'='*60}")
    print(f"Classification: {classification}")
    print(f"Ground Truth: {'phishing' if row['y_true'] == 1 else 'legitimate'}")
    print(f"Prediction: {'phishing' if row['ai_is_phishing'] else 'legitimate'}")
    print(f"ML Probability: {row['ml_probability']:.4f}")
    print(f"AI Confidence: {row['ai_confidence']:.2f}")
    print(f"AI Risk Level: {row['ai_risk_level']}")

    print(f"\n--- Reasoning ---")
    print(row.get('ai_reasoning') or "(none)")

    print(f"\n--- Risk Factors ---")
    print(parse_json(row.get('ai_risk_factors')) or "(none)")

    # Precheck (graph_stateから詳細取得)
    precheck = graph_state.get('precheck_hints', {})
    stats = precheck.get('stats', {})
    print(f"\n--- Precheck ---")
    print(f"  ml_category: {precheck.get('ml_category') or row.get('trace_precheck_ml_category')}")
    print(f"  tld_category: {precheck.get('tld_category') or row.get('trace_precheck_tld_category')}")
    print(f"  brand_detected: {precheck.get('brand_detected') or row.get('trace_precheck_brand_detected')}")
    print(f"  potential_brands: {precheck.get('potential_brands', [])}")
    print(f"  high_risk_hits: {stats.get('high_risk_hits') or row.get('trace_precheck_high_risk_hits')}")
    print(f"  phishing_tld_weight: {stats.get('phishing_tld_weight', 0)}")
    print(f"  quick_risk: {precheck.get('quick_risk') or row.get('trace_precheck_quick_risk')}")

    print(f"\n--- Tool Scores ---")
    print(f"  brand: {row.get('trace_brand_risk_score')}")
    print(f"  cert: {row.get('trace_cert_risk_score')}")
    print(f"  domain: {row.get('trace_domain_risk_score')}")
    print(f"  ctx: {row.get('trace_ctx_risk_score')}")

    print(f"\n--- Ctx Issues ---")
    print(parse_json(row.get('trace_ctx_issues')) or "(none)")

    print(f"\n--- Phase6 Rules ---")
    print(parse_json(row.get('trace_phase6_rules_fired')) or "(none)")

    # LLM Debug Info (graph_stateから取得)
    debug_llm = graph_state.get('debug_llm_final', {})
    if debug_llm:
        print(f"\n--- LLM Debug ---")
        print(f"  success: {debug_llm.get('success')}")
        print(f"  so_failure: {debug_llm.get('so_failure')}")
        print(f"  use_llm_decision: {debug_llm.get('use_llm_decision')}")
        print(f"  path: {debug_llm.get('path')}")
        if debug_llm.get('error'):
            print(f"  error: {str(debug_llm.get('error'))[:200]}")

    # Decision Trace (graph_stateから取得)
    decision_trace = graph_state.get('decision_trace')
    if decision_trace:
        print(f"\n--- Decision Trace ---")
        print(json.dumps(decision_trace, indent=2, ensure_ascii=False)[:500])

    # Fallback Info
    fallback = graph_state.get('fallback_info')
    if fallback:
        print(f"\n--- Fallback Info ---")
        print(fallback)

    # Tool Timings
    timings = graph_state.get('tool_timings_ms')
    if timings:
        print(f"\n--- Tool Timings (ms) ---")
        for tool, ms in timings.items():
            print(f"  {tool}: {ms}ms")

    if full_output:
        print(f"\n--- Tool Outputs ---")
        for tool in ['brand', 'cert', 'domain', 'ctx']:
            output = parse_json(row.get(f'tool_{tool}_output'))
            if output:
                print(f"\n[{tool}]")
                print(json.dumps(output, indent=2, ensure_ascii=False)[:2000])

        # Final Assessment from graph_state
        final_assessment = graph_state.get('final_assessment')
        if final_assessment:
            print(f"\n--- Final Assessment (raw) ---")
            print(json.dumps(final_assessment, indent=2, ensure_ascii=False)[:1000])


def fp_summary(df: pd.DataFrame) -> pd.DataFrame:
    """FPサマリーを表示"""
    fp = get_fp(df)
    print(f"Total FP: {len(fp)}")

    print(f"\n--- TLD Distribution ---")
    print(fp['tld'].value_counts().head(10))

    print(f"\n--- ML Distribution ---")
    bins = [0, 0.1, 0.3, 0.5, 1.0]
    labels = ['<0.1', '0.1-0.3', '0.3-0.5', '>=0.5']
    fp['ml_bin'] = pd.cut(fp['ml_probability'], bins=bins, labels=labels)
    print(fp['ml_bin'].value_counts().sort_index())

    print(f"\n--- Risk Level ---")
    print(fp['ai_risk_level'].value_counts())

    print(f"\n--- Top Risk Factors ---")
    counter = Counter()
    for rf in fp['ai_risk_factors'].dropna():
        factors = parse_json(rf)
        if isinstance(factors, list):
            counter.update(factors)
    for factor, count in counter.most_common(15):
        print(f"  {factor}: {count}")

    return fp


def fn_summary(df: pd.DataFrame) -> pd.DataFrame:
    """FNサマリーを表示"""
    fn = get_fn(df)
    print(f"Total FN: {len(fn)}")

    print(f"\n--- TLD Distribution ---")
    print(fn['tld'].value_counts().head(10))

    print(f"\n--- ML Distribution ---")
    bins = [0, 0.3, 0.5, 0.7, 1.0]
    labels = ['<0.3', '0.3-0.5', '0.5-0.7', '>=0.7']
    fn['ml_bin'] = pd.cut(fn['ml_probability'], bins=bins, labels=labels)
    print(fn['ml_bin'].value_counts().sort_index())

    print(f"\n--- Risk Level ---")
    print(fn['ai_risk_level'].value_counts())

    print(f"\n--- Ctx Score Distribution ---")
    bins = [0, 0.2, 0.5, 1.0]
    labels = ['<0.2', '0.2-0.5', '>=0.5']
    fn['ctx_bin'] = pd.cut(fn['trace_ctx_risk_score'], bins=bins, labels=labels)
    print(fn['ctx_bin'].value_counts().sort_index())

    print(f"\n--- Tool Score Means ---")
    print(f"  brand: {fn['trace_brand_risk_score'].mean():.4f}")
    print(f"  cert: {fn['trace_cert_risk_score'].mean():.4f}")
    print(f"  domain: {fn['trace_domain_risk_score'].mean():.4f}")
    print(f"  ctx: {fn['trace_ctx_risk_score'].mean():.4f}")

    return fn


def find_by_pattern(df: pd.DataFrame, pattern: str) -> pd.DataFrame:
    """ドメイン名のパターンで検索"""
    return df[df['domain'].str.contains(pattern, case=False, na=False)]


def filter_by_tld(df: pd.DataFrame, tld: str) -> pd.DataFrame:
    """TLDでフィルタ"""
    return df[df['tld'] == tld.lstrip('.')]


def filter_by_risk_factor(df: pd.DataFrame, factor: str) -> pd.DataFrame:
    """リスク要因でフィルタ"""
    def has_factor(rf):
        if pd.isna(rf):
            return False
        factors = parse_json(rf)
        if isinstance(factors, list):
            return factor in factors
        return False

    return df[df['ai_risk_factors'].apply(has_factor)]


def export_cases(df: pd.DataFrame, output_file: str, n: int = None):
    """ケースをJSONにエクスポート"""
    if n:
        df = df.head(n)

    cases = []
    for _, row in df.iterrows():
        case = {
            "domain": row['domain'],
            "ground_truth": "phishing" if row['y_true'] == 1 else "legitimate",
            "prediction": "phishing" if row['ai_is_phishing'] else "legitimate",
            "ml_probability": row['ml_probability'],
            "ai_confidence": row['ai_confidence'],
            "ai_risk_level": row['ai_risk_level'],
            "ai_reasoning": row.get('ai_reasoning'),
            "risk_factors": parse_json(row.get('ai_risk_factors')),
            "ctx_risk_score": row.get('trace_ctx_risk_score'),
            "tool_brand": parse_json(row.get('tool_brand_output')),
            "tool_cert": parse_json(row.get('tool_cert_output')),
            "tool_domain": parse_json(row.get('tool_domain_output')),
            "tool_ctx": parse_json(row.get('tool_ctx_output')),
        }
        cases.append(case)

    with open(output_file, 'w') as f:
        json.dump(cases, f, indent=2, ensure_ascii=False, default=str)

    print(f"Exported {len(cases)} cases to {output_file}")


def analyze_typical_phishing_cert(df: pd.DataFrame) -> Dict[str, Any]:
    """typical_phishing_cert_pattern の効果を分析

    Returns:
        Dict containing:
        - total: 検出された件数
        - tp: TP件数 (正しくphishing判定)
        - fn: FN件数 (見逃し)
        - contribution: TP率 (検出がどれだけ貢献しているか)
    """
    def has_pattern(ctx_issues):
        if pd.isna(ctx_issues):
            return False
        issues = parse_json(ctx_issues)
        if isinstance(issues, list):
            return "typical_phishing_cert_pattern" in issues
        return False

    df_with_pattern = df[df['trace_ctx_issues'].apply(has_pattern)]

    total = len(df_with_pattern)
    tp = len(df_with_pattern[(df_with_pattern['ai_is_phishing'] == True) & (df_with_pattern['y_true'] == 1)])
    fn = len(df_with_pattern[(df_with_pattern['ai_is_phishing'] == False) & (df_with_pattern['y_true'] == 1)])
    fp = len(df_with_pattern[(df_with_pattern['ai_is_phishing'] == True) & (df_with_pattern['y_true'] == 0)])
    tn = len(df_with_pattern[(df_with_pattern['ai_is_phishing'] == False) & (df_with_pattern['y_true'] == 0)])

    contribution = tp / total if total > 0 else 0

    print(f"=== typical_phishing_cert_pattern 分析 ===")
    print(f"検出件数: {total}")
    print(f"  TP (正しくphishing判定): {tp} ({100*tp/total:.1f}%)" if total > 0 else "  TP: 0")
    print(f"  FN (見逃し): {fn} ({100*fn/total:.1f}%)" if total > 0 else "  FN: 0")
    print(f"  FP (誤検出): {fp} ({100*fp/total:.1f}%)" if total > 0 else "  FP: 0")
    print(f"  TN (正しくbenign判定): {tn} ({100*tn/total:.1f}%)" if total > 0 else "  TN: 0")
    print(f"\nこのパターンの精度: {100*contribution:.1f}% (phishing検出への貢献率)")

    return {
        "total": total,
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "tn": tn,
        "contribution": contribution,
        "dataframe": df_with_pattern,
    }


def filter_by_ctx_issue(df: pd.DataFrame, issue: str) -> pd.DataFrame:
    """特定の ctx_issue を含むレコードをフィルタ"""
    def has_issue(ctx_issues):
        if pd.isna(ctx_issues):
            return False
        issues = parse_json(ctx_issues)
        if isinstance(issues, list):
            return issue in issues
        return False

    return df[df['trace_ctx_issues'].apply(has_issue)]


# クイックリファレンス
def help():
    """使い方を表示"""
    print("""
=== Trace Analysis Utils ===

データ読み込み:
    df = load_latest_results()

分類抽出:
    fp = get_fp(df)
    fn = get_fn(df)
    tp = get_tp(df)
    tn = get_tn(df)

評価指標:
    metrics(df)

ドメイン詳細:
    show_domain(df, "example.com")
    show_domain(df, "example.com", full_output=True)

サマリー:
    fp_summary(df)
    fn_summary(df)

フィルタ:
    find_by_pattern(df, "paypal")
    filter_by_tld(df, "top")
    filter_by_risk_factor(df, "dangerous_tld_combo")
    filter_by_ctx_issue(df, "typical_phishing_cert_pattern")

機能分析:
    analyze_typical_phishing_cert(df)  # 証明書パターン検出の効果分析

エクスポート:
    export_cases(get_fp(df), "fp_cases.json", n=50)
""")
