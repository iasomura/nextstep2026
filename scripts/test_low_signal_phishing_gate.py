#!/usr/bin/env python3
"""
低シグナルフィッシング検出ゲート (P1-P3) のLLMテスト

低MLスコア + フィッシングの難しいケースで新しいゲートの効果を検証する。
"""

import pandas as pd
import sys
import time
from pathlib import Path

# プロジェクトルートをパスに追加
sys.path.insert(0, str(Path(__file__).parent.parent))

from phishing_agent import make_phase4_agent_with_05

def test_low_signal_phishing():
    """低シグナルフィッシングのケースでテスト"""

    # 設定
    run_id = "2026-01-10_140940"
    base_dir = "/data/hdd/asomura/nextstep"
    sample_path = f"{base_dir}/artifacts/{run_id}/stage3_test/difficult_sample_50.csv"

    # サンプル読み込み
    sample = pd.read_csv(sample_path)

    # 低シグナルフィッシングを抽出（y_true=1 かつ ml < 0.25）
    low_signal_phishing = sample[(sample['y_true'] == 1) & (sample['ml_probability'] < 0.25)]

    print("=" * 70)
    print("低シグナルフィッシング検出ゲート テスト")
    print("=" * 70)
    print(f"\n全サンプル: {len(sample)}件")
    print(f"低シグナルフィッシング（y_true=1, ml<0.25）: {len(low_signal_phishing)}件")

    # テスト対象を表示
    print("\nテスト対象ドメイン:")
    for _, row in low_signal_phishing.iterrows():
        print(f"  {row['domain']:<40} ml={row['ml_probability']:.3f}")
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
    print(f"Policy Version: {agent.policy_version if hasattr(agent, 'policy_version') else 'unknown'}")
    print()

    # 結果格納
    results = []

    # 各ドメインを評価
    print("=" * 70)
    print("AI Agent 評価開始")
    print("=" * 70)

    start_time = time.time()

    for idx, row in low_signal_phishing.iterrows():
        domain = row['domain']
        ml_prob = row['ml_probability']
        y_true = row['y_true']

        print(f"\n[{len(results)+1}/{len(low_signal_phishing)}] {domain}")
        print(f"  ML: {ml_prob:.3f}")

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

                # ゲート発火情報
                graph_state = result.get('graph_state', {})
                low_signal_gate = graph_state.get('low_signal_phishing_gate', None)
                benign_cert_gate = graph_state.get('benign_cert_gate', None)

                # 証明書情報 - tool_results から取得（tool_summary は空の場合がある）
                tool_results = graph_state.get('tool_results', {})
                cert_data = tool_results.get('cert', {})
                cert_details = cert_data.get('details', {})
                valid_days = cert_details.get('valid_days', 0)
                san_count = cert_details.get('san_count', 0)
                benign_indicators = cert_details.get('benign_indicators', [])

                # ブランド情報 - tool_results から取得
                brand_data = tool_results.get('brand', {})
                brand_detected = 'brand_detected' in (brand_data.get('detected_issues') or brand_data.get('issues') or [])
                brand_suspected = 'brand_suspected' in (brand_data.get('detected_issues') or brand_data.get('issues') or [])
            else:
                is_phishing = False
                confidence = 0.0
                risk_level = 'error'
                risk_factors = []
                reasoning = ''
                low_signal_gate = None
                benign_cert_gate = None
                valid_days = 0
                san_count = 0
                benign_indicators = []
                brand_detected = False
                brand_suspected = False

            # 判定結果
            pred_label = "PHISHING" if is_phishing else "BENIGN"
            correct = is_phishing == True  # y_true=1 なので is_phishing=True が正解
            status = "✓" if correct else "✗"

            print(f"  判定: {pred_label} (conf={confidence:.2f}, risk={risk_level}) {status}")
            print(f"  証明書: valid_days={valid_days}, san_count={san_count}")
            print(f"  benign_indicators: {benign_indicators}")
            print(f"  brand_detected={brand_detected}, brand_suspected={brand_suspected}")

            if low_signal_gate:
                print(f"  >>> LOW_SIGNAL_GATE 発火: {low_signal_gate.get('rule')}")
            if benign_cert_gate:
                print(f"  >>> BENIGN_CERT_GATE 発火: {benign_cert_gate.get('rule')}")

            results.append({
                'domain': domain,
                'ml_probability': ml_prob,
                'y_true': y_true,
                'ai_pred': 1 if is_phishing else 0,
                'ai_confidence': confidence,
                'ai_risk_level': risk_level,
                'valid_days': valid_days,
                'san_count': san_count,
                'benign_indicators': str(benign_indicators),
                'brand_detected': brand_detected,
                'brand_suspected': brand_suspected,
                'low_signal_gate': str(low_signal_gate) if low_signal_gate else '',
                'benign_cert_gate': str(benign_cert_gate) if benign_cert_gate else '',
                'correct': correct,
            })

        except Exception as e:
            print(f"  ERROR: {e}")
            results.append({
                'domain': domain,
                'ml_probability': ml_prob,
                'y_true': y_true,
                'ai_pred': -1,
                'ai_confidence': 0.0,
                'ai_risk_level': 'error',
                'valid_days': 0,
                'san_count': 0,
                'benign_indicators': '',
                'brand_detected': False,
                'brand_suspected': False,
                'low_signal_gate': '',
                'benign_cert_gate': '',
                'correct': False,
            })

    elapsed = time.time() - start_time

    # 結果をDataFrameに
    results_df = pd.DataFrame(results)

    # 結果保存
    output_path = f"{base_dir}/artifacts/{run_id}/stage3_test/low_signal_phishing_gate_test.csv"
    results_df.to_csv(output_path, index=False)
    print(f"\n結果保存: {output_path}")

    # 評価
    print()
    print("=" * 70)
    print("評価結果")
    print("=" * 70)

    valid = results_df[results_df['ai_pred'] >= 0]

    # 検出率
    detected = len(valid[valid['ai_pred'] == 1])
    total = len(valid)
    detection_rate = detected / total if total > 0 else 0

    print(f"\n低シグナルフィッシング検出率: {detected}/{total} = {detection_rate:.1%}")

    # ゲート発火統計
    low_signal_fired = len(results_df[results_df['low_signal_gate'] != ''])
    print(f"LOW_SIGNAL_GATE 発火: {low_signal_fired}件")

    print(f"\n処理時間: {elapsed:.1f}秒 ({elapsed/len(low_signal_phishing):.2f}秒/件)")

    # 見逃しケース
    missed = results_df[results_df['correct'] == False]
    if len(missed) > 0:
        print(f"\n見逃しケース: {len(missed)}件")
        for _, row in missed.iterrows():
            print(f"  {row['domain']:<40}")
            print(f"    ml={row['ml_probability']:.3f}, valid_days={row['valid_days']}, san={row['san_count']}")
            print(f"    benign_indicators={row['benign_indicators']}")

    return results_df


if __name__ == '__main__':
    test_low_signal_phishing()
