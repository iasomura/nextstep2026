#!/usr/bin/env python3
"""
SO (Structured Output) 失敗ドメインの再評価スクリプト

eval CSVから policy_trace が空の行（SO parse failure）を特定し、
単一vLLMインスタンス（port 8000）で再評価する。

Usage:
    python scripts/retry_so_failures.py                    # 再評価実行
    python scripts/retry_so_failures.py --dry-run          # 対象ドメイン確認のみ
    python scripts/retry_so_failures.py --merge-only FILE  # 結果マージのみ

前提条件:
    - vLLM が port 8000 で起動していること（--max-model-len 8192 推奨）
    - max_tokens=4096 (phase6_wiring.py で設定済み)

変更履歴:
  - 2026-02-07: 初版作成
"""

import json
import os
import sys
import time
import argparse
from pathlib import Path
from datetime import datetime

import pandas as pd

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

EVAL_CSV = (
    PROJECT_ROOT / "artifacts" / "2026-02-02_224105" / "results"
    / "stage2_validation" / "eval_20260205_230157"
    / "eval_df__nALL__ts_20260205_230158.csv"
)

RETRY_OUTPUT = PROJECT_ROOT / "artifacts" / "2026-02-02_224105" / "results" / "so_retry_results.csv"


def find_so_failures(eval_csv: Path) -> pd.DataFrame:
    """eval CSVからSO失敗行（policy_trace空）を特定"""
    df = pd.read_csv(eval_csv)
    df = df.drop_duplicates(subset=["domain"], keep="last")

    so_fail_indices = []
    for idx, row in df.iterrows():
        slim_json = row.get("graph_state_slim_json", "")
        if pd.notna(slim_json) and slim_json:
            try:
                state = json.loads(slim_json)
                trace = state.get("decision_trace", [])
                if trace and isinstance(trace, list):
                    policy_trace = trace[0].get("policy_trace", [])
                    if not policy_trace:
                        so_fail_indices.append(idx)
                else:
                    so_fail_indices.append(idx)
            except (json.JSONDecodeError, TypeError):
                so_fail_indices.append(idx)
        else:
            so_fail_indices.append(idx)

    return df.loc[so_fail_indices]


def evaluate_domains(domains_df: pd.DataFrame, vllm_port: int = 8000, timeout: int = 120) -> list:
    """ドメインリストを評価"""
    import threading

    # config.json を一時的に port 指定で作成
    config_path = PROJECT_ROOT / "config.json"
    with open(config_path) as f:
        config = json.load(f)

    config["llm"]["base_url"] = f"http://localhost:{vllm_port}/v1"
    config["llm"]["vllm_base_url"] = f"http://localhost:{vllm_port}/v1"

    import tempfile
    temp_config = Path(tempfile.gettempdir()) / "config_retry_so.json"
    with open(temp_config, "w") as f:
        json.dump(config, f, indent=2)

    os.environ["CONFIG_JSON"] = str(temp_config)

    # Phase6 wiring + Agent初期化
    from phishing_agent.phase6_wiring import wire_phase6
    wire_phase6(prefer_compat=True, fake_llm=False)

    from phishing_agent.langgraph_module import LangGraphPhishingAgent
    agent = LangGraphPhishingAgent(
        strict_mode=True,
        use_llm_selection=True,
        use_llm_decision=True,
        config_path=str(temp_config),
    )

    print(f"Agent initialized (port={vllm_port})")

    results = []
    for i, (_, row) in enumerate(domains_df.iterrows()):
        domain = row["domain"]
        ml_prob = row["ml_probability"]
        print(f"\n[{i+1}/{len(domains_df)}] Evaluating: {domain} (ml_prob={ml_prob:.4f})")

        start_time = time.time()
        eval_result = [None]
        eval_error = [None]

        def target():
            try:
                eval_result[0] = agent.evaluate(domain, ml_prob, external_data={})
            except Exception as e:
                eval_error[0] = e

        thread = threading.Thread(target=target)
        thread.start()
        thread.join(timeout=timeout)

        elapsed = time.time() - start_time

        if thread.is_alive():
            print(f"  TIMEOUT after {timeout}s")
            results.append(_make_error_row(domain, ml_prob, row, elapsed, "Timeout"))
            continue

        if eval_error[0]:
            print(f"  ERROR: {eval_error[0]}")
            results.append(_make_error_row(domain, ml_prob, row, elapsed, str(eval_error[0])))
            continue

        r = eval_result[0]
        graph_state_slim = r.get("graph_state_slim") or {}
        tool_results = graph_state_slim.get("tool_results") or {}

        def _json_str(obj):
            if obj is None:
                return None
            try:
                return json.dumps(obj, ensure_ascii=False)
            except:
                return str(obj)

        result_row = {
            "domain": domain,
            "ml_probability": ml_prob,
            "ai_is_phishing": r.get("ai_is_phishing", False),
            "ai_confidence": r.get("ai_confidence", 0.0),
            "ai_risk_level": r.get("ai_risk_level", "unknown"),
            "processing_time": elapsed,
            "worker_id": 0,
            "error": None,
            "ai_reasoning": r.get("reasoning"),
            "ai_risk_factors": _json_str(r.get("risk_factors")),
            "ai_detected_brands": _json_str(r.get("detected_brands")),
            "trace_precheck_ml_category": r.get("trace_precheck_ml_category"),
            "trace_precheck_tld_category": r.get("trace_precheck_tld_category"),
            "trace_precheck_brand_detected": r.get("trace_precheck_brand_detected"),
            "trace_precheck_high_risk_hits": r.get("trace_precheck_high_risk_hits"),
            "trace_precheck_quick_risk": r.get("trace_precheck_quick_risk"),
            "trace_selected_tools": r.get("trace_selected_tools_json"),
            "trace_brand_risk_score": r.get("trace_brand_risk_score"),
            "trace_cert_risk_score": r.get("trace_cert_risk_score"),
            "trace_domain_risk_score": r.get("trace_domain_risk_score"),
            "trace_ctx_risk_score": r.get("trace_ctx_risk_score"),
            "trace_ctx_issues": r.get("trace_ctx_issues_json"),
            "trace_phase6_rules_fired": r.get("trace_phase6_rules_fired_json"),
            "graph_state_slim_json": r.get("graph_state_slim_json"),
            "tool_brand_output": _json_str(tool_results.get("brand")),
            "tool_cert_output": _json_str(tool_results.get("cert")),
            "tool_domain_output": _json_str(tool_results.get("domain")),
            "tool_ctx_output": _json_str(tool_results.get("contextual_risk_assessment")),
            # 元データからの付加情報
            "source": row.get("source"),
            "y_true": row.get("y_true"),
            "stage1_pred": row.get("stage1_pred"),
            "tld": row.get("tld"),
        }
        results.append(result_row)

        # SO成功を確認
        so_ok = _check_policy_trace(r.get("graph_state_slim_json", ""))
        status = "OK (policy_trace present)" if so_ok else "WARN (policy_trace still empty)"
        print(f"  -> is_phishing={r.get('ai_is_phishing')}, conf={r.get('ai_confidence', 0):.2f}, "
              f"time={elapsed:.1f}s, {status}")

    # クリーンアップ
    if temp_config.exists():
        temp_config.unlink()

    return results


def _make_error_row(domain, ml_prob, orig_row, elapsed, error_msg):
    """エラー時の結果行を作成"""
    return {
        "domain": domain,
        "ml_probability": ml_prob,
        "ai_is_phishing": False,
        "ai_confidence": 0.0,
        "ai_risk_level": "error",
        "processing_time": elapsed,
        "worker_id": 0,
        "error": error_msg,
        "source": orig_row.get("source"),
        "y_true": orig_row.get("y_true"),
        "stage1_pred": orig_row.get("stage1_pred"),
        "tld": orig_row.get("tld"),
    }


def _check_policy_trace(slim_json_str):
    """policy_traceが空でないか確認"""
    if not slim_json_str:
        return False
    try:
        state = json.loads(slim_json_str)
        trace = state.get("decision_trace", [])
        if trace and isinstance(trace, list):
            pt = trace[0].get("policy_trace", [])
            return len(pt) > 0
    except:
        pass
    return False


def merge_results(retry_csv: Path, eval_csv: Path):
    """再評価結果をeval CSVにマージ（ドメインで上書き）"""
    df_eval = pd.read_csv(eval_csv)
    df_retry = pd.read_csv(retry_csv)

    retry_domains = set(df_retry["domain"])
    print(f"Merging {len(retry_domains)} retry results into eval CSV ({len(df_eval)} rows)")

    # 既存の行を削除
    df_eval = df_eval[~df_eval["domain"].isin(retry_domains)]

    # retry結果を追加
    df_merged = pd.concat([df_eval, df_retry], ignore_index=True)

    # バックアップ
    backup = eval_csv.with_suffix(".csv.bak_so_retry")
    if not backup.exists():
        import shutil
        shutil.copy2(eval_csv, backup)
        print(f"Backup: {backup}")

    df_merged.to_csv(eval_csv, index=False)
    print(f"Merged CSV: {eval_csv} ({len(df_merged)} rows)")

    # 検証: dedup後の件数
    df_check = df_merged.drop_duplicates(subset=["domain"], keep="last")
    print(f"After dedup: {len(df_check)} unique domains")

    return df_merged


def main():
    parser = argparse.ArgumentParser(description="Retry SO-failure domains")
    parser.add_argument("--dry-run", action="store_true", help="対象ドメイン確認のみ")
    parser.add_argument("--merge-only", type=str, help="結果CSVのマージのみ実行")
    parser.add_argument("--port", type=int, default=8000, help="vLLM port (default: 8000)")
    parser.add_argument("--timeout", type=int, default=120, help="Timeout per domain (default: 120s)")
    args = parser.parse_args()

    if args.merge_only:
        merge_results(Path(args.merge_only), EVAL_CSV)
        return

    # SO失敗行を特定
    print(f"Scanning eval CSV: {EVAL_CSV}")
    so_failures = find_so_failures(EVAL_CSV)
    print(f"\nFound {len(so_failures)} SO-failure domains:")
    for _, row in so_failures.iterrows():
        print(f"  {row['domain']}: y_true={row['y_true']}, ai_phish={row['ai_is_phishing']}, "
              f"source={row.get('source', '?')}")

    if args.dry_run:
        return

    if len(so_failures) == 0:
        print("No SO failures found. Nothing to retry.")
        return

    # vLLM接続確認
    import urllib.request
    try:
        resp = urllib.request.urlopen(f"http://localhost:{args.port}/v1/models", timeout=5)
        print(f"\nvLLM port {args.port}: OK")
    except Exception as e:
        print(f"\nERROR: vLLM not available on port {args.port}: {e}")
        print("Start vLLM first: vllm serve ... --max-model-len 8192 --port 8000")
        sys.exit(1)

    # 再評価
    print(f"\n{'='*60}")
    print(f"Re-evaluating {len(so_failures)} domains (port={args.port}, timeout={args.timeout}s)")
    print(f"{'='*60}")

    results = evaluate_domains(so_failures, vllm_port=args.port, timeout=args.timeout)

    # 結果保存
    df_results = pd.DataFrame(results)
    df_results.to_csv(RETRY_OUTPUT, index=False)
    print(f"\nRetry results saved: {RETRY_OUTPUT}")

    # SO成功率
    so_ok_count = 0
    for r in results:
        if r.get("error") is None and _check_policy_trace(r.get("graph_state_slim_json", "")):
            so_ok_count += 1
    print(f"SO success: {so_ok_count}/{len(results)}")

    # 自動マージ
    if so_ok_count > 0:
        print(f"\nMerging results...")
        merge_results(RETRY_OUTPUT, EVAL_CSV)
        print("\nDone! Run 'python scripts/generate_paper_data.py' to regenerate paper data.")
    else:
        print("\nNo successful retries. Eval CSV not modified.")


if __name__ == "__main__":
    main()
