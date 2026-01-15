#!/usr/bin/env python3
"""
AI Agent テスト（サンプル50件）

難しいケース（ML Paradox + .com + 高defer）に対してAI Agentを実行し、
検出性能を評価する。
"""

import pandas as pd
import sys
import time
from pathlib import Path
from tqdm import tqdm

# プロジェクトルートをパスに追加
sys.path.insert(0, str(Path(__file__).parent.parent))

from phishing_agent import make_phase4_agent_with_05

def test_ai_agent_sample():
    """サンプル50件でAI Agentをテスト"""

    # 設定
    run_id = "2026-01-10_140940"
    base_dir = "/data/hdd/asomura/nextstep"
    sample_path = f"{base_dir}/artifacts/{run_id}/stage3_test/difficult_sample_50.csv"

    # サンプル読み込み
    sample = pd.read_csv(sample_path)
    print(f"サンプル: {len(sample)}件")
    print(f"  Phishing: {len(sample[sample['y_true']==1])}件")
    print(f"  Benign: {len(sample[sample['y_true']==0])}件")
    print()

    # Phase4 エージェント作成
    print("AI Agent 初期化中...")
    agent = make_phase4_agent_with_05(
        run_id=run_id,
        base_dir=base_dir,
        strict_mode=False,
        config_path=f"{base_dir}/config.json"
    )
    print("AI Agent 初期化完了")
    print()

    # 結果格納
    results = []

    # 各ドメインを評価
    print("=" * 70)
    print("AI Agent 評価開始")
    print("=" * 70)

    start_time = time.time()

    for idx, row in tqdm(sample.iterrows(), total=len(sample), desc="Processing"):
        domain = row['domain']
        ml_prob = row['ml_probability']
        y_true = row['y_true']

        try:
            # AI Agent 実行
            result = agent.evaluate(domain, ml_prob)

            # 結果抽出（正しいキーを使用）
            if result and isinstance(result, dict):
                is_phishing = result.get('ai_is_phishing', False)
                confidence = result.get('ai_confidence', 0.0)
                risk_level = result.get('ai_risk_level', 'unknown')
                risk_factors = result.get('risk_factors', [])
                reasoning = result.get('reasoning', '')
            else:
                is_phishing = False
                confidence = 0.0
                risk_level = 'error'
                risk_factors = []
                reasoning = ''

            results.append({
                'domain': domain,
                'ml_probability': ml_prob,
                'y_true': y_true,
                'ai_pred': 1 if is_phishing else 0,
                'ai_confidence': confidence,
                'ai_risk_level': risk_level,
                'ai_risk_factors': str(risk_factors)[:200],
                'ai_reasoning': reasoning[:300] if reasoning else '',
                'correct': (1 if is_phishing else 0) == y_true,
            })

        except Exception as e:
            print(f"\nError for {domain}: {e}")
            results.append({
                'domain': domain,
                'ml_probability': ml_prob,
                'y_true': y_true,
                'ai_pred': -1,
                'ai_confidence': 0.0,
                'ai_risk_level': 'error',
                'ai_risk_factors': str(e)[:200],
                'ai_reasoning': '',
                'correct': False,
            })

    elapsed = time.time() - start_time

    # 結果をDataFrameに
    results_df = pd.DataFrame(results)

    # 結果保存
    output_path = f"{base_dir}/artifacts/{run_id}/stage3_test/ai_agent_sample_results.csv"
    results_df.to_csv(output_path, index=False)
    print(f"\n結果保存: {output_path}")

    # 評価
    print()
    print("=" * 70)
    print("評価結果")
    print("=" * 70)

    valid = results_df[results_df['ai_pred'] >= 0]

    # 混同行列
    tp = len(valid[(valid['y_true']==1) & (valid['ai_pred']==1)])
    tn = len(valid[(valid['y_true']==0) & (valid['ai_pred']==0)])
    fp = len(valid[(valid['y_true']==0) & (valid['ai_pred']==1)])
    fn = len(valid[(valid['y_true']==1) & (valid['ai_pred']==0)])

    print(f"\n混同行列:")
    print(f"  TP (正しくPhishing検出): {tp}")
    print(f"  TN (正しくBenign判定):   {tn}")
    print(f"  FP (誤ってPhishing判定): {fp}")
    print(f"  FN (見逃し):             {fn}")

    # メトリクス
    accuracy = (tp + tn) / len(valid) if len(valid) > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    print(f"\nメトリクス:")
    print(f"  Accuracy:  {accuracy:.3f}")
    print(f"  Precision: {precision:.3f}")
    print(f"  Recall:    {recall:.3f}")
    print(f"  F1 Score:  {f1:.3f}")

    print(f"\n処理時間: {elapsed:.1f}秒 ({elapsed/len(sample):.2f}秒/件)")

    # エラー分析
    errors = results_df[results_df['correct'] == False]
    if len(errors) > 0:
        print(f"\n誤判定ケース: {len(errors)}件")
        print("\n  FP (Benignを誤検出):")
        fp_cases = errors[(errors['y_true']==0) & (errors['ai_pred']==1)]
        for _, row in fp_cases.head(5).iterrows():
            print(f"    {row['domain'][:40]:<40} p1={row['ml_probability']:.3f} conf={row['ai_confidence']:.3f}")

        print("\n  FN (Phishingを見逃し):")
        fn_cases = errors[(errors['y_true']==1) & (errors['ai_pred']==0)]
        for _, row in fn_cases.head(5).iterrows():
            print(f"    {row['domain'][:40]:<40} p1={row['ml_probability']:.3f} conf={row['ai_confidence']:.3f}")

    return results_df


if __name__ == '__main__':
    test_ai_agent_sample()
