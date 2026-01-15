#!/usr/bin/env python3
"""
Phase 2.1で実装予定: 完全版 02_main.py

このファイルは Phase 2.1 で実装される予定の統合スクリプトのイメージです。
現時点では動作しません（参考用）。

Usage:
    # CSVファイルから読み込んで予測
    python 02_main.py --input domains.csv --output results.csv

    # 既存のartifactsで評価
    python 02_main.py --eval --run-id 2026-01-10_140940

    # 新しいモデルを訓練
    python 02_main.py --train --data train.csv
"""

import argparse
from pathlib import Path
import sys

sys.path.insert(0, "02_stage1_stage2")

from src.config import load_config
from src.features import FeatureEngineer
from src.train_xgb import Stage1Trainer
from src.route1 import Route1ThresholdSelector
from src.stage2_gate import Stage2Gate
import pandas as pd
import json


def main():
    parser = argparse.ArgumentParser(
        description="Phase 2.1 統合スクリプト（完全版）"
    )

    # モード選択
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument('--predict', action='store_true',
                           help='新しいデータで予測')
    mode_group.add_argument('--eval', action='store_true',
                           help='既存データで評価')
    mode_group.add_argument('--train', action='store_true',
                           help='新しいモデルを訓練')

    # 共通オプション
    parser.add_argument('--config', type=str,
                       default='02_stage1_stage2/configs/default.yaml',
                       help='設定ファイルのパス')
    parser.add_argument('--run-id', type=str,
                       help='使用するartifactsのRUN_ID（デフォルト: 最新）')
    parser.add_argument('--output-dir', type=str,
                       default='results',
                       help='結果の出力先ディレクトリ')

    # 予測モード用
    parser.add_argument('--input', type=str,
                       help='入力CSVファイル（domain列が必要）')
    parser.add_argument('--output', type=str,
                       help='出力CSVファイル')

    # 訓練モード用
    parser.add_argument('--data', type=str,
                       help='訓練データCSV')
    parser.add_argument('--val-data', type=str,
                       help='検証データCSV（オプション）')

    # Stage2オプション
    parser.add_argument('--skip-stage2', action='store_true',
                       help='Stage2をスキップ')
    parser.add_argument('--stage2-budget', type=int,
                       help='Stage2の予算を上書き')

    args = parser.parse_args()

    # 設定読み込み
    cfg = load_config(args.config)
    print(f"✅ Config loaded from: {args.config}")

    # RUN_ID決定
    if args.run_id:
        run_id = args.run_id
    else:
        # 最新のRUN_IDを取得
        artifacts_dir = Path("artifacts")
        runs = [d.name for d in artifacts_dir.iterdir()
                if d.is_dir() and d.name != '_current']
        run_id = sorted(runs)[-1] if runs else None

    if not run_id and args.predict:
        print("❌ Error: --run-id が必要です（または artifacts/ にデータが必要）")
        return 1

    # モードに応じて実行
    if args.predict:
        return run_predict(args, cfg, run_id)
    elif args.eval:
        return run_eval(args, cfg, run_id)
    elif args.train:
        return run_train(args, cfg)

    return 0


def run_predict(args, cfg, run_id):
    """予測モード: 新しいデータで予測を実行"""
    print("\n" + "="*80)
    print("🔮 予測モード")
    print("="*80)

    if not args.input:
        print("❌ Error: --input が必要です")
        return 1

    # データ読み込み
    df = pd.read_csv(args.input)
    print(f"✅ データ読み込み: {len(df):,} domains from {args.input}")

    # Artifactsから必要なファイルを読み込み
    artifacts_dir = Path(f"artifacts/{run_id}")
    print(f"✅ Using artifacts: {run_id}")

    with open(artifacts_dir / "models/brand_keywords.json") as f:
        brand_keywords = json.load(f)

    # 特徴量抽出
    print("\n🔧 特徴量抽出中...")
    engineer = FeatureEngineer(brand_keywords)
    features = [engineer.extract_features(d, None) for d in df['domain']]
    df_features = pd.DataFrame(features, columns=engineer.get_feature_names())

    # 元のデータとマージ
    for col in df.columns:
        if col not in df_features.columns:
            df_features[col] = df[col].values

    print(f"✅ 特徴量抽出完了: {len(df_features):,} samples")

    # Stage1予測
    print("\n🤖 Stage1 予測中...")
    trainer = Stage1Trainer(cfg.xgboost)
    trainer.load_model(artifacts_dir / "models/xgboost_model_baseline.pkl")

    with open(artifacts_dir / "models/feature_order.json") as f:
        feature_order = json.load(f)

    predictions = trainer.predict_proba(df_features, feature_order)
    df_features['stage1_score'] = predictions
    print(f"✅ Stage1 予測完了")

    # Route1分類
    print("\n🚦 Route1 閾値適用中...")
    with open(artifacts_dir / "results/route1_thresholds.json") as f:
        thresholds = json.load(f)

    selector = Route1ThresholdSelector(cfg.route1)
    selector.t_low = thresholds['t_low']
    selector.t_high = thresholds['t_high']

    decisions = selector.apply_thresholds(predictions)
    decision_map = {0: 'AUTO_BENIGN', 1: 'DEFER', 2: 'AUTO_PHISH'}
    df_features['route1_decision'] = [decision_map[d] for d in decisions]

    print(f"✅ Route1 分類完了:")
    print(f"   AUTO_BENIGN: {(decisions == 0).sum():,}")
    print(f"   DEFER:       {(decisions == 1).sum():,}")
    print(f"   AUTO_PHISH:  {(decisions == 2).sum():,}")

    # Stage2（オプション）
    if not args.skip_stage2 and (decisions == 1).sum() > 0:
        print("\n🚪 Stage2 Gate適用中...")
        df_defer = df_features[decisions == 1].copy()

        if args.stage2_budget:
            from dataclasses import replace
            custom_config = replace(cfg.stage2, max_budget=args.stage2_budget)
            gate = Stage2Gate(custom_config, brand_keywords)
        else:
            gate = Stage2Gate(cfg.stage2, brand_keywords)

        p_defer = predictions[decisions == 1]
        df_defer = gate.select_segment_priority(df_defer, p_defer)

        # 結果をマージ
        df_features.loc[df_defer.index, 'stage2_decision'] = df_defer['stage2_decision']

        handoff_count = (df_defer['stage2_decision'] == 'handoff').sum()
        print(f"✅ Stage2 選択完了:")
        print(f"   Handoff: {handoff_count:,}")

    # 結果保存
    output_path = args.output or f"{args.output_dir}/predictions_{run_id}.csv"
    df_features.to_csv(output_path, index=False)
    print(f"\n💾 結果保存: {output_path}")

    # サマリー
    print("\n" + "="*80)
    print("✅ 予測完了")
    print("="*80)
    return 0


def run_eval(args, cfg, run_id):
    """評価モード: 既存データで性能評価"""
    print("\n" + "="*80)
    print("📊 評価モード")
    print("="*80)

    # TODO: Phase 2.1で実装
    # - test_data.pklを読み込み
    # - 予測を実行
    # - メトリクスを計算（AUC, Precision, Recall, etc.）
    # - Notebookの結果と比較

    print("⚠️  Phase 2.1で実装予定")
    return 0


def run_train(args, cfg):
    """訓練モード: 新しいモデルを訓練"""
    print("\n" + "="*80)
    print("🎓 訓練モード")
    print("="*80)

    # TODO: Phase 2.1で実装
    # - データ読み込み
    # - 特徴量抽出
    # - XGBoost訓練
    # - Route1閾値選択
    # - モデル保存
    # - 結果の出力

    print("⚠️  Phase 2.1で実装予定")
    return 0


if __name__ == '__main__':
    sys.exit(main())
