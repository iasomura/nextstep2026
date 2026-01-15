# パイプライン実行順序

## 概要

フィッシング検知システムの全体パイプラインを実行する際の順序を定義します。

## 実行順序

| 順番 | プログラム | 実行方法 | 処理内容 | 推定時間 |
|------|-----------|---------|---------|---------|
| 1 | `01_data_preparation_fixed_patched_nocert_full_artifacts_unified.ipynb` | papermill | データ準備・前処理 | ~4分 |
| 2 | `02_main.py --run` | python | Stage1 XGBoost + Stage2 LR + Gate | ~3分 |
| 3 | `03_ai_agent_analysis_part1.ipynb` | papermill | AI Agent設定確認 | ~5秒 |
| 4 | `03_ai_agent_analysis_part2_full_HardFail_patched.ipynb` | papermill | AI Agentサンプル検証 | ~20秒 |
| 5 | `03_ai_agent_analysis_part3_config_api.ipynb` | papermill | Config API確認 | ~10秒 |
| 6 | `04-1_config_and_data_preparation.ipynb` | papermill | 統計分析準備 | ~2秒 |
| 7 | `04-2_statistical_analysis_COMPAT_PATCHED_v2_skip_smoke_and_fix_known_domains.ipynb` | papermill | 統計分析 | ~3秒 |
| 8 | `04-3_llm_tools_setup.ipynb` | papermill | LLMツール設定 | ~8秒 |
| 9 | `scripts/evaluate_e2e.py --n-sample ALL` | python | AI Agent全件実行 | **~39時間** |

## 自動実行スクリプト

```bash
# 全体実行
./scripts/run_full_pipeline.sh

# evaluate_e2e.py以外を実行（開発・テスト用）
./scripts/run_full_pipeline.sh --no-e2e
```

## 出力ファイル

### artifacts/{RUN_ID}/ 構造

```
artifacts/{RUN_ID}/
├── raw/                    # 生データ
├── processed/              # 前処理済みデータ
│   ├── train_data.pkl
│   └── test_data.pkl
├── models/                 # 学習済みモデル
│   ├── xgboost_model.pkl
│   ├── scaler.pkl
│   ├── lr_defer_model.pkl
│   ├── lr_defer_scaler.pkl
│   ├── feature_order.json
│   └── brand_keywords.json
├── results/                # 結果ファイル
│   ├── stage1_decisions_latest.csv
│   ├── stage2_decisions_latest.csv
│   ├── stage2_decisions_candidates_latest.csv
│   ├── stage2_budget_eval.json
│   └── stage2_validation/  # evaluate_e2e.py出力
│       ├── eval_df__n{N}__ts_{ts}.csv
│       ├── all_test_merged__ts_{ts}.csv
│       └── summary__ts_{ts}.json
└── handoff/                # Stage3用データ
    ├── handoff_candidates_latest.pkl
    └── handoff_candidates_latest.csv
```

## 依存関係

```
01_data_preparation
        ↓
   02_main.py ──→ feature_order.json生成（02実行後に必要）
        ↓
03_part1 → 03_part2 → 03_part3
        ↓
04-1 → 04-2 → 04-3
        ↓
  evaluate_e2e.py
```

## 注意事項

1. **artifacts/フォルダ**: 実行前にクリアすることを推奨
2. **feature_order.json**: 02_main.py実行後、03ノートブック実行前に生成が必要
3. **evaluate_e2e.py**: 約39時間かかるため、バックグラウンド実行を推奨
4. **可視化**: evaluate_e2e.pyは画像を出力しないが、出力CSVから後で可視化可能

## 作成日

2026-01-13
