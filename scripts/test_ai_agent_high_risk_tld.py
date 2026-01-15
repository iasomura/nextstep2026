#!/usr/bin/env python3
"""
AI Agent テスト（高リスクTLD + ML Paradox）

森先生の提案に基づく検証:
- Stage1は「安全」と判定（p1 < 0.3）
- Stage2は「怪しい」と判定（defer >= 0.8）
- 危険TLD（cn, top, cc等）という追加シグナル
→ AI Agentがこれを正しくPhishingと検出できるか？
"""

import pandas as pd
import sys
import time
from pathlib import Path
from tqdm import tqdm

# プロジェクトルートをパスに追加
sys.path.insert(0, str(Path(__file__).parent.parent))

from phishing_agent import make_phase4_agent_with_05

def test_ai_agent_high_risk_tld():
    """高リスクTLD + ML ParadoxでAI Agentをテスト"""

    # 設定
    run_id = "2026-01-10_140940"
    base_dir = "/data/hdd/asomura/nextstep"
    data_path = f"{base_dir}/artifacts/{run_id}/stage3_test/high_risk_tld_ml_paradox.csv"

    # データ読み込み
    data = pd.read_csv(data_path)
    print(f"テストデータ: {len(data)}件")
    print(f"  Phishing: {len(data[data['y_true']==1])}件 ({100*len(data[data['y_true']==1])/len(data):.1f}%)")
    print(f"  Benign: {len(data[data['y_true']==0])}件")
    print()

    # TLD別内訳
    print("TLD別内訳:")
    for tld in data['tld'].unique():
        tld_data = data[data['tld'] == tld]
        phish = len(tld_data[tld_data['y_true']==1])
        print(f"  {tld:8}: {len(tld_data):3}件, Phishing {phish:2}件 ({100*phish/len(tld_data):.0f}%)")
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

    for idx, row in tqdm(data.iterrows(), total=len(data), desc="Processing"):
        domain = row['domain']
        ml_prob = row['ml_probability']
        y_true = row['y_true']
        tld = row['tld']

        try:
            # AI Agent 実行
            result = agent.evaluate(domain, ml_prob)

            # 結果抽出
            if result and isinstance(result, dict):
                is_phishing = result.get('ai_is_phishing', False)
                confidence = result.get('ai_confidence', 0.0)
                risk_level = result.get('ai_risk_level', 'unknown')
                risk_factors = result.get('risk_factors', [])
                reasoning = result.get('reasoning', '')

                # 追加情報
                ctx_risk = result.get('trace_ctx_risk_score', 0.0)
                is_ml_paradox = result.get('trace_ctx_is_ml_paradox', False)
            else:
                is_phishing = False
                confidence = 0.0
                risk_level = 'error'
                risk_factors = []
                reasoning = ''
                ctx_risk = 0.0
                is_ml_paradox = False

            results.append({
                'domain': domain,
                'tld': tld,
                'ml_probability': ml_prob,
                'y_true': y_true,
                'ai_pred': 1 if is_phishing else 0,
                'ai_confidence': confidence,
                'ai_risk_level': risk_level,
                'ctx_risk_score': ctx_risk,
                'is_ml_paradox': is_ml_paradox,
                'ai_risk_factors': str(risk_factors)[:200],
                'ai_reasoning': reasoning[:300] if reasoning else '',
                'correct': (1 if is_phishing else 0) == y_true,
            })

        except Exception as e:
            print(f"\nError for {domain}: {e}")
            results.append({
                'domain': domain,
                'tld': tld,
                'ml_probability': ml_prob,
                'y_true': y_true,
                'ai_pred': -1,
                'ai_confidence': 0.0,
                'ai_risk_level': 'error',
                'ctx_risk_score': 0.0,
                'is_ml_paradox': False,
                'ai_risk_factors': str(e)[:200],
                'ai_reasoning': '',
                'correct': False,
            })

    elapsed = time.time() - start_time

    # 結果をDataFrameに
    results_df = pd.DataFrame(results)

    # 結果保存
    output_path = f"{base_dir}/artifacts/{run_id}/stage3_test/ai_agent_high_risk_tld_results.csv"
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

    print(f"\n処理時間: {elapsed:.1f}秒 ({elapsed/len(data):.2f}秒/件)")

    # TLD別評価
    print("\n" + "=" * 70)
    print("TLD別評価")
    print("=" * 70)
    print(f"\n{'TLD':8} {'件数':>6} {'TP':>4} {'TN':>4} {'FP':>4} {'FN':>4} {'Recall':>8} {'Prec':>8}")
    print("-" * 60)

    for tld in sorted(valid['tld'].unique()):
        tld_data = valid[valid['tld'] == tld]
        tld_tp = len(tld_data[(tld_data['y_true']==1) & (tld_data['ai_pred']==1)])
        tld_tn = len(tld_data[(tld_data['y_true']==0) & (tld_data['ai_pred']==0)])
        tld_fp = len(tld_data[(tld_data['y_true']==0) & (tld_data['ai_pred']==1)])
        tld_fn = len(tld_data[(tld_data['y_true']==1) & (tld_data['ai_pred']==0)])
        tld_recall = tld_tp / (tld_tp + tld_fn) if (tld_tp + tld_fn) > 0 else 0
        tld_prec = tld_tp / (tld_tp + tld_fp) if (tld_tp + tld_fp) > 0 else 0
        print(f"{tld:8} {len(tld_data):>6} {tld_tp:>4} {tld_tn:>4} {tld_fp:>4} {tld_fn:>4} {tld_recall:>8.1%} {tld_prec:>8.1%}")

    # risk_level別分析
    print("\n" + "=" * 70)
    print("risk_level別分析")
    print("=" * 70)
    print(f"\n{'risk_level':12} {'件数':>6} {'Phishing':>10} {'Benign':>10}")
    print("-" * 45)
    for level in ['low', 'medium', 'high', 'very_high']:
        level_data = valid[valid['ai_risk_level'] == level]
        if len(level_data) > 0:
            phish = len(level_data[level_data['y_true']==1])
            benign = len(level_data[level_data['y_true']==0])
            print(f"{level:12} {len(level_data):>6} {phish:>10} {benign:>10}")

    return results_df


if __name__ == '__main__':
    test_ai_agent_high_risk_tld()
