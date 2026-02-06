#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_prompt_recall.py - プロンプト改善効果の検証スクリプト

プロンプト改善後、FNケースで再評価を行い、Recall改善を確認する。

使用方法:
    python scripts/test_prompt_recall.py --n-sample 50 --port 8000

作成日: 2026-02-04
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
from typing import Dict, List, Any

import pandas as pd
import yaml

# プロジェクトルートをパスに追加
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def load_fn_domains(csv_path: str, n_sample: int) -> pd.DataFrame:
    """FNドメインをCSVから読み込む"""
    df = pd.read_csv(csv_path)

    if n_sample and n_sample < len(df):
        import random
        random.seed(42)
        indices = random.sample(range(len(df)), n_sample)
        df = df.iloc[indices]

    return df


def main():
    parser = argparse.ArgumentParser(description="プロンプト改善効果の検証")
    parser.add_argument("--n-sample", type=int, default=50, help="テストサンプル数")
    parser.add_argument("--port", type=int, default=8000, help="vLLMポート")
    parser.add_argument("--input", type=str,
                        default="fnfp_analysis/fn_analysis_20260127_135612.csv",
                        help="FN分析CSVファイル")
    parser.add_argument("--filter-dangerous-tld", action="store_true",
                        help="危険TLD + 高MLのケースのみテスト")
    parser.add_argument("--ml-threshold", type=float, default=0.5,
                        help="MLフィルタ閾値")
    parser.add_argument("--output", type=str, default=None, help="出力ファイル")
    args = parser.parse_args()

    # 出力ファイル設定
    if args.output is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        args.output = f"test_data/prompt_recall_test_{timestamp}.jsonl"

    print("=" * 60)
    print("Prompt Recall Improvement Test")
    print("=" * 60)
    print(f"Input file: {args.input}")
    print(f"Sample size: {args.n_sample}")
    print(f"vLLM port: {args.port}")
    print(f"Output file: {args.output}")
    print()

    # FNデータ読み込み
    fn_df = load_fn_domains(args.input, None)  # まず全件読み込み

    # フィルタ適用
    if args.filter_dangerous_tld:
        fn_df = fn_df[(fn_df['is_dangerous_tld'] == True) & (fn_df['ml_probability'] >= args.ml_threshold)]
        print(f"Filtered to dangerous TLD + ML >= {args.ml_threshold}: {len(fn_df)} domains")

    # サンプリング
    if args.n_sample and args.n_sample < len(fn_df):
        import random
        random.seed(42)
        indices = random.sample(range(len(fn_df)), args.n_sample)
        fn_df = fn_df.iloc[indices]

    print(f"Testing {len(fn_df)} FN domains")

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

    # config.yamlを生成
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
    tp_count = 0  # True Positive (正しくphishing判定)
    fn_count = 0  # False Negative (依然benign判定)
    error_count = 0

    print()
    print("Starting evaluation...")
    print("-" * 60)

    for i, row in fn_df.iterrows():
        domain = row['domain']
        ml_prob = row['ml_probability']
        y_true = row['y_true']  # 1 = phishing

        print(f"[{len(results)+1}/{len(fn_df)}] {domain} (ML: {ml_prob:.3f})...", end=" ", flush=True)

        result = {
            "domain": domain,
            "ml_probability": ml_prob,
            "y_true": y_true,
            "old_prediction": False,  # 以前はFN（benign判定）
            "new_is_phishing": None,
            "new_confidence": None,
            "new_risk_level": None,
            "reasoning_preview": None,
            "error": None,
            "processing_time": 0,
        }

        start_time = time.time()

        try:
            out = agent.evaluate(domain, ml_prob, external_data={"cert_full_info_map": cert_features})

            result["processing_time"] = time.time() - start_time
            result["new_is_phishing"] = out.get("ai_is_phishing")
            result["new_confidence"] = out.get("ai_confidence")
            result["new_risk_level"] = out.get("ai_risk_level")
            reasoning = out.get("reasoning", "") or ""
            result["reasoning_preview"] = reasoning[:200]

            if result["new_is_phishing"]:
                tp_count += 1
                print(f"✓ TP (now phishing, conf={result['new_confidence']:.2f})")
            else:
                fn_count += 1
                print(f"✗ FN (still benign)")

        except Exception as e:
            result["error"] = str(e)
            result["processing_time"] = time.time() - start_time
            error_count += 1
            print(f"ERROR: {str(e)[:50]}")

        results.append(result)

        # 中間保存
        with open(args.output, "a") as f:
            f.write(json.dumps(result, ensure_ascii=False) + "\n")

    # 最終サマリ
    total = len(results)
    valid = total - error_count

    print()
    print("=" * 60)
    print("TEST RESULTS")
    print("=" * 60)
    print(f"Total tested: {total}")
    print(f"Errors: {error_count}")
    print(f"Valid results: {valid}")
    print()

    if valid > 0:
        recall = tp_count / valid
        print(f"True Positives (now phishing): {tp_count} ({100*tp_count/valid:.1f}%)")
        print(f"False Negatives (still benign): {fn_count} ({100*fn_count/valid:.1f}%)")
        print()
        print(f"Recall on FN cases: {recall:.1%}")
        print()

        # 比較
        print("=" * 60)
        print("COMPARISON")
        print("=" * 60)
        print(f"Before prompt fix: 18.8% Recall (on SO success cases)")
        print(f"After prompt fix:  {recall:.1%} Recall (on FN cases)")
        print()

        if recall > 0.30:
            print("GOOD: Significant recall improvement!")
        elif recall > 0.20:
            print("OK: Some improvement, but more work needed.")
        else:
            print("WARNING: Recall still low. Consider further prompt adjustments.")

    print()
    print(f"Results saved to: {args.output}")


if __name__ == "__main__":
    main()
