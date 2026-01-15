#!/usr/bin/env python3
"""
Stage2証明書ルールの独立評価スクリプト

目的: 証明書ルールの過学習を検証するため、train/test splitで独立評価を行う

使用方法:
    python evaluate_stage2_rules.py

出力:
    - train_cert_stats.json: Trainセットから算出した証明書統計
    - test_eval_results.json: Testセットでのルール評価結果
    - evaluation_report.md: 評価レポート

作成日: 2026-01-12
"""

import pandas as pd
import numpy as np
import pickle
import json
import sys
import os
from datetime import datetime
from tqdm import tqdm

# プロジェクトルートを追加
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..'))
sys.path.insert(0, os.path.join(PROJECT_ROOT, '02_stage1_stage2'))

from src.features import extract_features, FEATURE_ORDER

# 設定
SAMPLE_SIZE = 64000  # 各クラスのサンプル数
TRAIN_RATIO = 0.6    # Train/Test比率
RANDOM_SEED = 42

# 特徴量インデックス
IDX_VALIDITY_DAYS = FEATURE_ORDER.index('cert_validity_days')
IDX_IS_WILDCARD = FEATURE_ORDER.index('cert_is_wildcard')
IDX_SAN_COUNT = FEATURE_ORDER.index('cert_san_count')
IDX_HAS_ORG = FEATURE_ORDER.index('cert_subject_has_org')
IDX_HAS_CRL = FEATURE_ORDER.index('cert_has_crl_dp')
IDX_IS_LE = FEATURE_ORDER.index('cert_is_lets_encrypt')


def load_data(artifacts_dir):
    """データを読み込む"""
    data_path = os.path.join(artifacts_dir, 'raw/prepared_data.pkl')
    with open(data_path, 'rb') as f:
        data = pickle.load(f)

    brand_path = os.path.join(artifacts_dir, 'models/brand_keywords.json')
    with open(brand_path, 'r') as f:
        brand_keywords = json.load(f)

    return data['phishing_data'], data['trusted_data'], brand_keywords


def sample_and_split(phishing_df, trusted_df, sample_size, train_ratio, seed):
    """データをサンプリングしてtrain/testに分割"""
    np.random.seed(seed)

    # インデックスをシャッフル
    phishing_idx = np.random.permutation(len(phishing_df))
    trusted_idx = np.random.permutation(len(trusted_df))

    # 分割数を計算
    n_train = int(sample_size * train_ratio)
    n_test = sample_size - n_train

    # 分割
    ph_train_idx = phishing_idx[:n_train]
    ph_test_idx = phishing_idx[n_train:n_train + n_test]
    tr_train_idx = trusted_idx[:n_train]
    tr_test_idx = trusted_idx[n_train:n_train + n_test]

    # DataFrameを作成
    train_df = pd.concat([
        phishing_df.iloc[ph_train_idx].assign(y_true=1),
        trusted_df.iloc[tr_train_idx].assign(y_true=0)
    ]).reset_index(drop=True)

    test_df = pd.concat([
        phishing_df.iloc[ph_test_idx].assign(y_true=1),
        trusted_df.iloc[tr_test_idx].assign(y_true=0)
    ]).reset_index(drop=True)

    return train_df, test_df


def extract_features_batch(df, brand_keywords, desc=""):
    """バッチで特徴量を抽出"""
    features_list = []
    for i, row in tqdm(df.iterrows(), total=len(df), desc=desc):
        feat = extract_features(row['domain'], row['cert_data'], brand_keywords)
        features_list.append(feat)
    return np.array(features_list)


def compute_cert_stats(X, y):
    """証明書統計を計算"""
    phishing_mask = y == 1
    benign_mask = y == 0

    stats = {
        'sample_size': len(y),
        'phishing_count': int(phishing_mask.sum()),
        'benign_count': int(benign_mask.sum()),
        'features': {}
    }

    feature_names = ['CRL', 'OV_EV', 'Wildcard', 'Long_Validity', 'Lets_Encrypt']
    feature_indices = [IDX_HAS_CRL, IDX_HAS_ORG, IDX_IS_WILDCARD, IDX_VALIDITY_DAYS, IDX_IS_LE]
    thresholds = [0.5, 0.5, 0.5, 180, 0.5]

    for name, idx, thresh in zip(feature_names, feature_indices, thresholds):
        if name == 'Long_Validity':
            ph_rate = (X[phishing_mask, idx] > thresh).mean()
            bn_rate = (X[benign_mask, idx] > thresh).mean()
        else:
            ph_rate = (X[phishing_mask, idx] > thresh).mean()
            bn_rate = (X[benign_mask, idx] > thresh).mean()

        stats['features'][name] = {
            'phishing_rate': float(ph_rate),
            'benign_rate': float(bn_rate),
            'discrimination': float(abs(bn_rate - ph_rate))
        }

    return stats


def evaluate_rules(X, y):
    """ルールを評価"""
    # 各ルールのヒット判定
    rule_crl = X[:, IDX_HAS_CRL] > 0.5
    rule_org = X[:, IDX_HAS_ORG] > 0.5
    rule_wc = X[:, IDX_IS_WILDCARD] > 0.5
    rule_long = X[:, IDX_VALIDITY_DAYS] > 180
    any_rule = rule_crl | rule_org | rule_wc | rule_long

    results = {}
    rules = [
        ('CRL', rule_crl),
        ('OV_EV', rule_org),
        ('Wildcard', rule_wc),
        ('Long_Validity', rule_long),
        ('All_Rules_OR', any_rule)
    ]

    for name, rule_hit in rules:
        tn = int(((rule_hit) & (y == 0)).sum())
        fn = int(((rule_hit) & (y == 1)).sum())
        hit_count = int(rule_hit.sum())

        results[name] = {
            'hit_count': hit_count,
            'hit_rate': float(hit_count / len(y)),
            'true_negative': tn,
            'false_negative': fn,
            'precision': float(tn / hit_count) if hit_count > 0 else 0,
            'fn_rate': float(fn / (y == 1).sum())
        }

    return results


def generate_report(train_stats, test_results, output_dir):
    """評価レポートを生成"""
    report = f"""# Stage2証明書ルール独立評価レポート

生成日時: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## 実験設計

| 項目 | 値 |
|------|-----|
| サンプルサイズ (各クラス) | {SAMPLE_SIZE:,} |
| Train/Test比率 | {TRAIN_RATIO:.0%} / {1-TRAIN_RATIO:.0%} |
| 乱数シード | {RANDOM_SEED} |
| Trainセット | {train_stats['sample_size']:,} |
| Testセット | {test_results['sample_size']:,} |

## Trainセットから算出した証明書統計

| 特徴量 | Phishing | Benign | 識別力 |
|--------|----------|--------|--------|
"""
    for name, feat in train_stats['features'].items():
        report += f"| {name} | {feat['phishing_rate']*100:.1f}% | {feat['benign_rate']*100:.1f}% | {feat['discrimination']*100:.1f}% |\n"

    report += f"""
## Testセットでのルール評価結果

| ルール | ヒット数 | ヒット率 | 精度 | FN数 | FN率 |
|--------|----------|----------|------|------|------|
"""
    for name, res in test_results['rules'].items():
        report += f"| {name} | {res['hit_count']:,} | {res['hit_rate']*100:.1f}% | {res['precision']*100:.1f}% | {res['false_negative']:,} | {res['fn_rate']*100:.2f}% |\n"

    report += f"""
## 結論

- フィルタリング率: {test_results['rules']['All_Rules_OR']['hit_rate']*100:.1f}%
- 精度: {test_results['rules']['All_Rules_OR']['precision']*100:.1f}%
- 見逃し率 (FNR): {test_results['rules']['All_Rules_OR']['fn_rate']*100:.2f}%

## 使用したプログラム

- スクリプト: `docs/analysis/stage2_independent_eval/evaluate_stage2_rules.py`
- 特徴量抽出: `02_stage1_stage2/src/features.py`
- データ: `artifacts/2026-01-10_140940/raw/prepared_data.pkl`
"""

    report_path = os.path.join(output_dir, 'evaluation_report.md')
    with open(report_path, 'w') as f:
        f.write(report)

    return report_path


def main():
    print("=" * 60)
    print("Stage2証明書ルールの独立評価")
    print("=" * 60)

    # 出力ディレクトリ
    output_dir = os.path.dirname(os.path.abspath(__file__))
    artifacts_dir = os.path.join(PROJECT_ROOT, 'artifacts/2026-01-10_140940')

    # データ読み込み
    print("\n[1] データ読み込み中...")
    phishing_df, trusted_df, brand_keywords = load_data(artifacts_dir)
    print(f"  Phishing: {len(phishing_df):,}")
    print(f"  Trusted: {len(trusted_df):,}")

    # サンプリングと分割
    print("\n[2] サンプリングとtrain/test分割...")
    train_df, test_df = sample_and_split(
        phishing_df, trusted_df, SAMPLE_SIZE, TRAIN_RATIO, RANDOM_SEED
    )
    print(f"  Train: {len(train_df):,}")
    print(f"  Test: {len(test_df):,}")

    # 特徴量抽出
    print("\n[3] 特徴量抽出中...")
    X_train = extract_features_batch(train_df, brand_keywords, "Train")
    X_test = extract_features_batch(test_df, brand_keywords, "Test")
    y_train = train_df['y_true'].values
    y_test = test_df['y_true'].values

    # 統計算出
    print("\n[4] Train統計算出中...")
    train_stats = compute_cert_stats(X_train, y_train)

    # 評価
    print("\n[5] Testセット評価中...")
    test_results = {
        'sample_size': len(y_test),
        'rules': evaluate_rules(X_test, y_test)
    }

    # 結果保存
    print("\n[6] 結果保存中...")

    stats_path = os.path.join(output_dir, 'train_cert_stats.json')
    with open(stats_path, 'w') as f:
        json.dump(train_stats, f, indent=2)
    print(f"  {stats_path}")

    results_path = os.path.join(output_dir, 'test_eval_results.json')
    with open(results_path, 'w') as f:
        json.dump(test_results, f, indent=2)
    print(f"  {results_path}")

    report_path = generate_report(train_stats, test_results, output_dir)
    print(f"  {report_path}")

    print("\n完了!")


if __name__ == '__main__':
    main()
