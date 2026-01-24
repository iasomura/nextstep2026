# パイプライン実行順序

**更新日**: 2026-01-24

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
| 9 | `scripts/evaluate_e2e_parallel.py` | python | AI Agent全件評価 (並列) | **~17時間 (2GPU)** |

## 自動実行スクリプト

```bash
# 全体実行 (ステップ1-8)
./scripts/run_full_pipeline.sh

# evaluate_e2e.py以外を実行（開発・テスト用）
./scripts/run_full_pipeline.sh --no-e2e

# vLLMなしで実行
./scripts/run_full_pipeline.sh --no-vllm
```

## vLLM管理

GPUサーバは共用のため、vLLMの起動・停止を適切に管理すること。

### 手動管理

```bash
# 起動
bash scripts/vllm.sh start

# 停止
bash scripts/vllm.sh stop

# 状態確認
bash scripts/vllm.sh status

# API疎通確認
curl -s http://localhost:8000/v1/models
```

### 自動管理 (並列評価)

`evaluate_e2e_parallel.py` はvLLMの自動起動・停止に対応:
- `local` タイプ: 評価開始時に起動、完了後に自動停止
- `external` タイプ (start_cmd/stop_cmd あり): SSH経由で起動・停止
- `external` タイプ (cmd なし): 外部管理 (no-op)

### 管理ルール

| タイミング | アクション |
|-----------|-----------|
| LLM必要スクリプト実行直前 | `bash scripts/vllm.sh start` |
| スクリプト完了後 | `bash scripts/vllm.sh stop` |
| エラーで中断した場合 | 問題解決に時間がかかるなら停止 |
| アイドル10分以上 | 停止 |

## Stage3 評価 (並列版)

### 基本使用法

```bash
# GPU 0のみ (デフォルト)
python scripts/evaluate_e2e_parallel.py -y

# GPU 0 + 1 で並列 (推奨)
python scripts/evaluate_e2e_parallel.py --add-gpu 1 -y

# 3GPU並列
python scripts/evaluate_e2e_parallel.py --add-gpu 1,2 -y

# テスト (100件)
python scripts/evaluate_e2e_parallel.py --add-gpu 1 --n-sample 100 -y

# 中断後の再開
python scripts/evaluate_e2e_parallel.py --add-gpu 1 --resume -y

# GPU確認
python scripts/evaluate_e2e_parallel.py --check-gpus
```

### バックグラウンド実行

```bash
# バッファリング防止 + バックグラウンド
PYTHONUNBUFFERED=1 nohup python scripts/evaluate_e2e_parallel.py \
  --add-gpu 1 -y > artifacts/{RUN_ID}/logs/parallel_all.log 2>&1 &

# 進捗確認
tail -f artifacts/{RUN_ID}/logs/parallel_all.log
```

### 処理時間目安

| GPU数 | 17,434ドメイン | スループット |
|-------|---------------|-------------|
| 1 GPU | ~33時間 | ~8.5 domains/min |
| 2 GPU | ~17時間 | ~17 domains/min |
| 3 GPU | ~11時間 | ~25 domains/min |

## 出力ファイル

### artifacts/{RUN_ID}/ 構造

```
artifacts/{RUN_ID}/
├── raw/                    # 生データ
│   └── prepared_data.pkl
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
│   └── stage2_validation/  # evaluate_e2e出力
│       ├── eval_df__nALL__ts_{ts}.csv         # 最終結果
│       ├── worker_N_results.csv               # Worker個別結果
│       ├── worker_N_checkpoint.json           # チェックポイント
│       ├── parallel_state.json                # 全体状態
│       └── summary__ts_{ts}.json
├── handoff/                # Stage3用データ
│   ├── handoff_candidates_latest.csv
│   ├── handoff_candidates_latest.pkl
│   └── 04-3_llm_tools_setup_with_tools.pkl
└── logs/                   # ログ
    └── parallel_all_*.log
```

## 依存関係

```
01_data_preparation
        ↓
   02_main.py ──→ feature_order.json / handoff_candidates 生成
        ↓
03_part1 → 03_part2 → 03_part3
        ↓
04-1 → 04-2 → 04-3 ──→ llm_tools_setup_with_tools.pkl 生成
        ↓
  evaluate_e2e_parallel.py ──→ vLLM起動 → 評価 → vLLM停止
        ↓
  (optional) vt_batch_investigation.py ──→ ラベルエラー調査
        ↓
  (optional) data_cleaning_*.sql ──→ DB修正 → パイプライン再実行
```

## 注意事項

1. **vLLM**: GPUサーバ共用のため、使用後は必ず停止すること
2. **PYTHONUNBUFFERED=1**: バックグラウンド実行時はログバッファリング防止のため必須
3. **artifacts/フォルダ**: パイプライン再実行時はクリアを推奨
4. **feature_order.json**: 02_main.py実行後、03ノートブック実行前に生成が必要
5. **チェックポイント**: 中断時はresume可能。ただしWorker数変更は非対応
6. **共有サーバ**: `--check-gpus` でGPU状態を確認してから実行すること
