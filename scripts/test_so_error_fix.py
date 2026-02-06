#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_so_error_fix.py - SOエラー修正効果の検証スクリプト

max_length: 1000 → 2500 の修正後、以前SOエラーが発生したドメインで
再評価を行い、エラー率の改善を確認する。

使用方法:
    python scripts/test_so_error_fix.py --n-sample 50 --port 8000

作成日: 2026-02-03

変更履歴:
  - 2026-02-04: SOエラー詳細トレース出力を追加
    - so_error_type: エラータイプ (deterministic_fallback, validation_exception, parse_exception等)
    - so_error_detail: phase6_final_decision_error の詳細
    - debug_llm_final: LLMデバッグ情報
    - reasoning_preview: reasoning冒頭200文字
    - SOエラータイプ別集計を追加
"""

import argparse
import json
import os
import pickle
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

import yaml

# プロジェクトルートをパスに追加
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def load_so_error_domains(file_path: str, n_sample: int) -> List[str]:
    """SOエラードメインをファイルから読み込む"""
    with open(file_path, "r") as f:
        domains = [line.strip() for line in f if line.strip()]

    if n_sample and n_sample < len(domains):
        import random
        random.seed(42)
        domains = random.sample(domains, n_sample)

    return domains


def load_ml_probabilities(domains: List[str]) -> Dict[str, float]:
    """ドメインのML確率を取得"""
    import pandas as pd

    # 前回の評価結果からML確率を取得
    csv_path = "artifacts/2026-02-02_224105/results/stage2_validation/eval_20260203_030552/eval_df__nALL__ts_20260203_030553.csv"
    df = pd.read_csv(csv_path, usecols=['domain', 'ml_probability'])
    return dict(zip(df['domain'], df['ml_probability']))


def main():
    parser = argparse.ArgumentParser(description="SOエラー修正効果の検証")
    parser.add_argument("--n-sample", type=int, default=50, help="テストサンプル数")
    parser.add_argument("--port", type=int, default=8000, help="vLLMポート")
    parser.add_argument("--input", type=str, default="test_data/so_error_domains.txt",
                        help="SOエラードメインリスト")
    parser.add_argument("--output", type=str, default=None, help="出力ファイル")
    args = parser.parse_args()

    # 出力ファイル設定
    if args.output is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        args.output = f"test_data/so_error_fix_test_{timestamp}.jsonl"

    print("=" * 60)
    print("SO Error Fix Verification Test")
    print("=" * 60)
    print(f"Input file: {args.input}")
    print(f"Sample size: {args.n_sample}")
    print(f"vLLM port: {args.port}")
    print(f"Output file: {args.output}")
    print()

    # ドメイン読み込み
    domains = load_so_error_domains(args.input, args.n_sample)
    print(f"Loaded {len(domains)} domains for testing")

    # ML確率読み込み
    print("Loading ML probabilities...")
    ml_probs = load_ml_probabilities(domains)

    # 証明書特徴量ファイル
    cert_features_pkl = "artifacts/2026-02-02_224105/processed/cert_full_info_map.pkl"
    print(f"Loading certificate features from {cert_features_pkl}...")
    with open(cert_features_pkl, "rb") as f:
        cert_features = pickle.load(f)
    print(f"  Loaded {len(cert_features)} domain features")

    # エージェント初期化
    print("\nInitializing agent...")
    os.environ["VLLM_PORT"] = str(args.port)

    from phishing_agent.phase6_wiring import wire_phase6
    wire_phase6()

    from phishing_agent.langgraph_module import LangGraphPhishingAgent

    # config.yamlを生成（vLLMポート指定用）
    config_data = {
        "llm": {
            "enabled": True,
            "base_url": f"http://localhost:{args.port}/v1",
            "model_name": "qwen",
            "timeout": 120,
        }
    }
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        yaml.dump(config_data, f)
        temp_config_path = f.name

    agent = LangGraphPhishingAgent(
        config_path=temp_config_path,
        strict_mode=False,
        external_data={"cert_full_info_map": cert_features}
    )
    print("  Agent initialized")

    # 結果記録
    results = []
    so_error_count = 0
    success_count = 0
    error_count = 0

    print()
    print("Starting evaluation...")
    print("-" * 60)

    for i, domain in enumerate(domains, 1):
        ml_prob = ml_probs.get(domain, 0.2)
        print(f"[{i}/{len(domains)}] {domain} (ML: {ml_prob:.3f})...", end=" ", flush=True)

        result = {
            "domain": domain,
            "ml_probability": ml_prob,
            "so_error": False,
            "reasoning_length": 0,
            "is_phishing": None,
            "confidence": None,
            "risk_level": None,
            "error": None,
            "processing_time": 0,
            # 追加: SOエラー詳細トレース用
            "so_error_type": None,        # so_fallback, validation_error, parse_error, etc.
            "so_error_detail": None,      # phase6_final_decision_error の内容
            "debug_llm_final": None,      # debug_llm_final の内容
            "reasoning_preview": None,    # reasoning の冒頭200文字
        }

        start_time = time.time()

        try:
            # 評価実行
            out = agent.evaluate(domain, ml_prob, external_data={"cert_full_info_map": cert_features})

            result["processing_time"] = time.time() - start_time
            result["is_phishing"] = out.get("is_phishing")
            result["confidence"] = out.get("confidence")
            result["risk_level"] = out.get("risk_level")
            reasoning = out.get("reasoning", "") or ""
            result["reasoning_length"] = len(reasoning)
            result["reasoning_preview"] = reasoning[:200]

            # SOエラー詳細トレース情報の収集
            slim_json = out.get("graph_state_slim_json", "")
            debug_llm = out.get("debug_llm_final", {})
            phase6_error = out.get("phase6_final_decision_error", {})

            result["debug_llm_final"] = debug_llm if debug_llm else None
            result["so_error_detail"] = phase6_error if phase6_error else None

            # SOエラー判定: 複数の指標をチェック
            is_so_error = False
            so_error_type = None

            # 1. deterministic fallback が使われたか
            if "deterministic" in str(slim_json).lower():
                is_so_error = True
                so_error_type = "deterministic_fallback"

            # 2. debug_llm_finalのso_failureフラグ
            if debug_llm and debug_llm.get("so_failure"):
                is_so_error = True
                so_error_type = debug_llm.get("path", "so_failure")

            # 3. reasoning内にfallbackの文字列が含まれるか
            if "so failed" in reasoning.lower() or "deterministic" in reasoning.lower():
                is_so_error = True
                so_error_type = so_error_type or "fallback_in_reasoning"

            # 4. phase6_final_decision_error が存在するか
            if phase6_error:
                is_so_error = True
                so_error_type = phase6_error.get("type", "phase6_error")

            result["so_error"] = is_so_error
            result["so_error_type"] = so_error_type

            if is_so_error:
                so_error_count += 1
                err_detail = so_error_type or "unknown"
                if phase6_error:
                    err_detail += f" ({phase6_error.get('message', '')[:50]})"
                print(f"SO_ERROR [{err_detail}] (reasoning: {result['reasoning_length']} chars)")
            else:
                success_count += 1
                print(f"OK (reasoning: {result['reasoning_length']} chars, phish={result['is_phishing']})")

        except Exception as e:
            result["error"] = str(e)
            result["processing_time"] = time.time() - start_time
            err_str = str(e).lower()

            # エラータイプの判定
            if "validationerror" in err_str or "validation" in err_str:
                result["so_error"] = True
                result["so_error_type"] = "validation_exception"
                so_error_count += 1
                # ValidationErrorの詳細を抽出
                if "max_length" in err_str or "string_too_long" in err_str:
                    result["so_error_detail"] = {"type": "ValidationError", "message": "max_length exceeded"}
                elif "min_length" in err_str or "string_too_short" in err_str:
                    result["so_error_detail"] = {"type": "ValidationError", "message": "min_length not met"}
                else:
                    result["so_error_detail"] = {"type": "ValidationError", "message": str(e)[:200]}
                print(f"SO_ERROR [validation_exception] {str(e)[:60]}")
            elif "could not parse" in err_str or "json" in err_str:
                result["so_error"] = True
                result["so_error_type"] = "parse_exception"
                result["so_error_detail"] = {"type": "ParseError", "message": str(e)[:200]}
                so_error_count += 1
                print(f"SO_ERROR [parse_exception] {str(e)[:60]}")
            else:
                error_count += 1
                print(f"ERROR: {str(e)[:60]}")

        results.append(result)

        # 中間保存
        with open(args.output, "a") as f:
            f.write(json.dumps(result, ensure_ascii=False) + "\n")

    # 最終サマリ
    total = len(results)
    print()
    print("=" * 60)
    print("TEST RESULTS")
    print("=" * 60)
    print(f"Total tested: {total}")
    print(f"SO errors: {so_error_count} ({100*so_error_count/total:.1f}%)")
    print(f"Success (no SO error): {success_count} ({100*success_count/total:.1f}%)")
    print(f"Other errors: {error_count} ({100*error_count/total:.1f}%)")
    print()

    # SOエラータイプ別集計
    so_error_types = {}
    for r in results:
        if r.get("so_error") and r.get("so_error_type"):
            et = r["so_error_type"]
            so_error_types[et] = so_error_types.get(et, 0) + 1

    if so_error_types:
        print("SO Error Types Breakdown:")
        for et, cnt in sorted(so_error_types.items(), key=lambda x: -x[1]):
            print(f"  {et}: {cnt} ({100*cnt/total:.1f}%)")
        print()

    # SOエラー詳細メッセージのサンプル
    so_error_samples = [r for r in results if r.get("so_error_detail")]
    if so_error_samples:
        print("SO Error Details (samples):")
        for r in so_error_samples[:5]:
            detail = r["so_error_detail"]
            print(f"  [{r['domain']}] type={detail.get('type')}: {detail.get('message', '')[:100]}")
        print()

    # 比較
    print("=" * 60)
    print("COMPARISON")
    print("=" * 60)
    print(f"Before fix (max_length=1000): 23.4% SO error rate")
    print(f"After fix (max_length=2500):  {100*so_error_count/total:.1f}% SO error rate")
    print()

    if so_error_count == 0:
        print("SUCCESS: No SO errors detected!")
        print("The max_length fix (1000 -> 2500) is working perfectly.")
    elif so_error_count < total * 0.05:
        print(f"GOOD: SO error rate reduced from 23.4% to {100*so_error_count/total:.1f}% (target: <5%)")
    else:
        print(f"WARNING: SO error rate still at {100*so_error_count/total:.1f}%")
        print("Consider increasing max_length further or investigating other causes.")

    # reasoning長の統計
    reasoning_lengths = [r["reasoning_length"] for r in results if r.get("reasoning_length")]
    if reasoning_lengths:
        print()
        print("Reasoning length statistics:")
        print(f"  Min: {min(reasoning_lengths)}")
        print(f"  Max: {max(reasoning_lengths)}")
        print(f"  Mean: {sum(reasoning_lengths)/len(reasoning_lengths):.0f}")
        print(f"  >1000 chars: {sum(1 for l in reasoning_lengths if l > 1000)}")
        print(f"  >2000 chars: {sum(1 for l in reasoning_lengths if l > 2000)}")

    print()
    print(f"Results saved to: {args.output}")


if __name__ == "__main__":
    main()
