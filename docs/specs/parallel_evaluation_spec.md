# 並列評価システム仕様書

**バージョン**: v1.4
**更新日**: 2026-01-31
**対象モジュール**: `scripts/evaluate_e2e_parallel.py`, `scripts/parallel/`

---

## 1. 概要

Stage3 (AI Agent) の評価を複数GPU/vLLMインスタンスで並列実行するシステム。共有GPUサーバ環境を想定し、動的なGPU追加・チェックポイントリカバリ・ヘルスモニタリングを備える。

## 2. アーキテクチャ

```
evaluate_e2e_parallel.py (エントリポイント)
       │
       ▼
┌─────────────────────────────────────────┐
│  ParallelOrchestrator                    │
│  ┌──────────────┐  ┌─────────────────┐  │
│  │ VLLMCluster  │  │ HealthMonitor   │  │
│  │ (N instances)│  │ (Background)    │  │
│  └──────────────┘  └─────────────────┘  │
│  ┌──────────────┐  ┌─────────────────┐  │
│  │ Checkpoint   │  │ RecoveryManager │  │
│  │ Manager      │  │                 │  │
│  └──────────────┘  └─────────────────┘  │
└───────────────┬─────────────────────────┘
                │ multiprocessing.Process
       ┌────────┼────────┐
       ▼        ▼        ▼
   Worker 0  Worker 1  Worker 2
   (GPU 0)   (Port 8001)(Port 8002)
   Port 8000  External   SSH start/stop
```

## 3. Workerタイプ

### 3.1 local

ローカルGPUでvLLMを管理する。

| 項目 | 説明 |
|------|------|
| 起動 | vLLMプロセスを直接起動 (CUDA_VISIBLE_DEVICES指定) |
| 停止 | PID追跡 + pgrep による確実な停止 |
| ヘルスチェック | `GET /v1/models` |
| 設定例 | `type: local, gpu: 0, port: 8000` |

### 3.2 external

ポートフォワード済みの外部vLLMに接続する。`start_cmd`/`stop_cmd` でSSH経由の起動停止も可能。

| 項目 | 説明 |
|------|------|
| 起動 | ヘルスチェックのみ (or start_cmd実行) |
| 停止 | no-op (or stop_cmd実行) |
| ヘルスチェック | `GET localhost:{port}/v1/models` |
| 設定例 (受動) | `type: external, port: 8001` |
| 設定例 (SSH) | `type: external, port: 8002, start_cmd: "ssh ...", stop_cmd: "ssh ..."` |

### 3.3 remote

SSH + tmux でリモートvLLMを完全管理する。

| 項目 | 説明 |
|------|------|
| 起動 | SSH接続 → tmuxセッション作成 → vLLM起動 |
| 停止 | tmuxセッション内でvLLM停止 → セッション削除 |
| ヘルスチェック | SSHトンネル経由で `/v1/models` |
| 設定例 | `type: remote, ssh: {host, user, remote_port, gpu}, tmux: {session_name}` |

## 4. CLI インタフェース

```bash
python scripts/evaluate_e2e_parallel.py [OPTIONS]
```

| オプション | 説明 | デフォルト |
|-----------|------|-----------|
| `--config PATH` | 設定ファイルパス | `scripts/parallel_config.yaml` |
| `--add-gpu N[,M,...]` | 追加使用するWorker ID | なし (Worker 0のみ) |
| `--n-sample N` | 評価サンプル数 | ALL (全件) |
| `--random-state N` | 乱数シード | 42 |
| `--shuffle` | ドメインリストをシャッフル | False |
| `--resume, -r` | チェックポイントから再開 | False |
| `--check-gpus` | GPU状態確認のみ | False |
| `--dry-run` | ドライラン | False |
| `-y, --yes` | 確認プロンプトスキップ | False |

### 使用例

```bash
# GPU 0のみ (デフォルト)
python scripts/evaluate_e2e_parallel.py -y

# GPU 0 + 1 で並列
python scripts/evaluate_e2e_parallel.py --add-gpu 1 -y

# 3 GPU 並列
python scripts/evaluate_e2e_parallel.py --add-gpu 1,2 -y

# 100件テスト
python scripts/evaluate_e2e_parallel.py --add-gpu 1 --n-sample 100 -y

# 中断後の再開
python scripts/evaluate_e2e_parallel.py --add-gpu 1 --resume -y

# GPU状態確認
python scripts/evaluate_e2e_parallel.py --check-gpus
```

## 5. 設定ファイル (parallel_config.yaml)

```yaml
num_workers: 3

workers:
  - id: 0
    port: 8000
    type: local
    gpu: 0
    speed_weight: 1.59      # 処理速度の重み（ドメイン配分に使用）

  - id: 1
    port: 8001
    type: external          # ポートフォワード済み
    stop_on_complete: false # 完了後にvLLMを停止しない
    speed_weight: 1.77

  - id: 2
    port: 8002
    type: external
    start_cmd: "ssh user@host 'bash -lc \"/path/to/vllm.sh start\"'"  # オプション
    stop_cmd: "ssh user@host 'bash -lc \"/path/to/vllm.sh stop\"'"    # オプション
    stop_on_complete: false
    speed_weight: 1.00

vllm:
  model: "JunHowie/Qwen3-4B-Thinking-2507-GPTQ-Int8"  # GPTQモデル
  max_model_len: 4096
  max_num_seqs: 8
  gpu_memory_utilization: 0.25
  dtype: auto

evaluation:
  checkpoint_interval: 100    # チェックポイント保存間隔
  timeout_per_domain: 60      # 1ドメインのタイムアウト(秒)
  retry_count: 2              # リトライ回数

health_check:
  interval: 5                 # ヘルスチェック間隔(秒)
  timeout: 10
  max_failures: 3

retry:
  request_retries: 3
  request_delay: 5
  domain_retries: 2           # ドメイン評価リトライ
  domain_delay: 10
  vllm_restarts: 3
  vllm_restart_delay: 30

failover:
  enabled: true
  redistribute_on_failure: true  # 障害時に他Workerへ再分配
  min_workers: 1

shared_server:
  enabled: true
  check_gpu_usage_before_start: true
  gpu_memory_threshold_mb: 1000
  warn_if_other_users: true
  require_confirmation: true

logging:
  level: INFO
  separate_worker_logs: true  # Worker毎に別ログ
  log_dir: null               # null=artifacts/{RUN_ID}/logs/
```

## 6. チェックポイントシステム

### 6.1 ファイル構成

```
artifacts/{RUN_ID}/results/stage2_validation/
├── parallel_state.json           # グローバル状態
├── worker_0_checkpoint.json      # Worker 0 進捗
├── worker_0_domains.json         # Worker 0 ドメインリスト
├── worker_0_input.json           # Worker 0 入力データ (全カラム)
├── worker_0_results.csv          # Worker 0 結果 (WAL追記)
├── worker_1_checkpoint.json
├── worker_1_domains.json
├── worker_1_input.json
├── worker_1_results.csv
└── eval_df__nALL__ts_{timestamp}.csv  # マージ済み最終結果
```

### 6.2 GlobalState (parallel_state.json)

```json
{
  "run_id": "2026-01-24_213326",
  "total_domains": 15670,
  "num_workers": 3,
  "active_workers": [0, 1, 2],
  "failed_workers": [],
  "started_at": "2026-01-28T19:32:40.916481",
  "updated_at": "2026-01-28T19:32:40.916522",
  "completed": false
}
```

### 6.3 WorkerProgress (worker_N_checkpoint.json)

```json
{
  "worker_id": 0,
  "status": "running",
  "total": 5715,
  "completed": 60,
  "failed": 0,
  "last_completed_domain": "example.com",
  "last_completed_index": 59,
  "current_processing": "next-domain.com",
  "current_index": 60,
  "started_at": "2026-01-28T19:32:41.322579",
  "updated_at": "2026-01-28T19:41:29.041702",
  "vllm_restarts": 0,
  "errors": []
}
```

### 6.4 Resume動作

1. `parallel_state.json` を読み込み
2. 各Worker の `last_completed_index + 1` から再開
3. 結果CSVは追記モード (重複なし)

## 7. ヘルスモニタリング

### 7.1 HealthMonitor

- バックグラウンドスレッドで定期チェック (5秒間隔)
- `GET /v1/models` の応答で生存確認
- 連続3回失敗でWorker障害と判定
- イベントコールバックで RecoveryManager に通知

### 7.2 RecoveryManager

- vLLM障害検出時に自動再起動 (最大3回)
- 再起動待ち時間: 30秒
- 全リトライ失敗時: Worker除外、他Workerへの再分配 (failover有効時)

## 8. データフロー

```
1. handoff_candidates_latest.csv 読込 (17,434件)
2. サンプリング (--n-sample指定時)
3. NaN→None変換
4. Worker数で均等分割
5. per-worker input.json 書き出し
6. Worker プロセス起動 (multiprocessing.Process)
7. 各Worker: config.json生成 (base_url変更) → evaluate_e2e相当の処理
8. 結果: worker_N_results.csv に1行ずつ追記 (fcntlロック)
9. 完了後: 全Worker結果をマージ → eval_df__nALL__ts_{ts}.csv
```

## 9. Worker内部処理 (worker.py)

### 9.1 初期化
- per-worker `config.json` を生成 (`llm.base_url` を該当portに変更)
- `phishing_agent` モジュールをインポート
- `LangGraphPhishingAgent` を初期化

### 9.2 評価ループ
```python
for i, domain_info in enumerate(domains[start_index:]):
    # チェックポイント: 処理中マーク
    checkpoint_manager.mark_worker_processing(worker_id, domain, i)

    # タイムアウト付き評価
    result = evaluate_single_domain(domain_info, timeout=60)

    # 結果書き込み (WAL)
    result_writer.append(result)

    # チェックポイント: 完了マーク
    checkpoint_manager.update_worker_progress(worker_id, domain, i, success)
```

### 9.3 エラーハンドリング
- ドメイン単位タイムアウト: 60秒
- vLLM接続エラー: `VLLMConnectionError` → RecoveryManager通知
- その他エラー: ログ記録、次ドメインへ進む

### 9.4 リトライ機能 ✅ (実装完了: 2026-01-31)

**実装概要**:
評価完了後に失敗ドメインをバッチリトライする方式を採用。

**使用方法**:
```bash
# 失敗ドメインのリトライ
python scripts/evaluate_e2e_parallel.py --retry-failed -y
```

**実装詳細**:
- `evaluate_e2e_parallel.py`: `--retry-failed` オプション追加
- `orchestrator.py`: `retry_failed_domains()` メソッド追加
- `worker.py`: `retry_failed()` メソッド追加
- `checkpoint.py`: `get_all_failed_domains()`, `clear_failed_domain()` メソッド追加

**動作**:
1. チェックポイントから全Workerの失敗ドメインを収集
2. タイムアウト2倍（60秒→120秒）で再評価
3. 成功時はチェックポイントのエラーリストから削除
4. 結果は `retry_results_{run_id}.csv` に保存

**検証結果** (2026-01-31):
- 3000件評価で5件がタイムアウト (0.17%)
- リトライにより5件全て成功

## 10. 結果マージ

- 各Worker の `worker_N_results.csv` を読み込み
- domain列で重複除去 (resume時の重複対策)
- タイムスタンプ付きCSVとして保存
- マージ結果に全カラム含む (下記セクション10.1参照)

### 10.1 出力カラム一覧 (v1.1: 2026-01-28更新)

| カテゴリ | カラム名 | 説明 |
|---------|---------|------|
| **基本** | domain | 対象ドメイン |
| | ml_probability | Stage1 ML確率 |
| | ai_is_phishing | AI Agent判定結果 |
| | ai_confidence | AI Agent信頼度 |
| | ai_risk_level | リスクレベル (low/medium/high/critical) |
| | processing_time | 処理時間(秒) |
| | worker_id | 処理Worker ID |
| | error | エラーメッセージ (あれば) |
| | source | データソース |
| | y_true | 正解ラベル (1=phishing, 0=legitimate) |
| | stage1_pred | Stage1予測 |
| | tld | TLD |
| **判定理由** | ai_reasoning | LLMの判定理由 (50文字以上) |
| | ai_risk_factors | 検出されたリスク要因 (JSON) |
| | ai_detected_brands | 検出されたブランド (JSON) |
| **Precheck** | trace_precheck_ml_category | ML確率カテゴリ |
| | trace_precheck_tld_category | TLDカテゴリ |
| | trace_precheck_brand_detected | ブランド検出フラグ |
| | trace_precheck_high_risk_hits | 高リスクキーワードヒット数 |
| | trace_precheck_quick_risk | クイックリスクスコア |
| **ツール選択** | trace_selected_tools | 選択されたツール (JSON) |
| **ツールスコア** | trace_brand_risk_score | ブランドチェックスコア |
| | trace_cert_risk_score | 証明書チェックスコア |
| | trace_domain_risk_score | ドメインチェックスコア |
| | trace_ctx_risk_score | コンテキストリスクスコア |
| | trace_ctx_issues | コンテキスト検出問題 (JSON) |
| **ポリシー** | trace_phase6_rules_fired | 発火したルール (JSON) |
| **デバッグ** | graph_state_slim_json | 完全なグラフ状態 (JSON) |
| **ツール出力詳細** | tool_brand_output | brand_impersonation_check出力 (JSON) |
| | tool_cert_output | certificate_analysis出力 (JSON) |
| | tool_domain_output | short_domain_analysis出力 (JSON) |
| | tool_ctx_output | contextual_risk_assessment出力 (JSON) |

### 10.2 FP/FN分析での活用

トレースフィールドを使用した原因分析:

```python
import pandas as pd
import json

df = pd.read_csv("worker_0_results.csv")

# FPケースの抽出
fp = df[(df['ai_is_phishing'] == True) & (df['y_true'] == 0)]

# 判定理由の確認
for _, row in fp.iterrows():
    print(f"Domain: {row['domain']}")
    print(f"  Reasoning: {row['ai_reasoning']}")
    print(f"  Risk factors: {row['ai_risk_factors']}")
    print(f"  Ctx score: {row['trace_ctx_risk_score']}")

    # ツール出力の詳細確認
    if pd.notna(row['tool_brand_output']):
        brand = json.loads(row['tool_brand_output'])
        print(f"  Brand issues: {brand.get('detected_issues')}")
```

## 11. vLLM自動停止

- 評価完了後、`LocalVLLMManager.stop()` でGPU0のvLLMを自動停止
- `pgrep -f "vllm serve.*--port {port}"` でメインプロセスPIDを特定
- SIGTERM送信後、PIDファイル削除
- `external` タイプ (start_cmd/stop_cmd あり): stop_cmd実行
- `external` タイプ (stop_cmdなし): no-op (外部管理)

## 12. 制限事項

- resume時のWorker数変更は未対応 (ドメイン再分配が整合しなくなるため)
- Worker間の動的負荷分散は未実装
- 同一ドメインの重複評価防止はresult CSVのdomain重複除去で対応

## 13. データ混在防止機能 ✅ (実装完了: 2026-01-31)

### 13.1 背景

複数回の評価実行（中断・再開の繰り返し）により、Worker CSVに重複データが蓄積し、分析データが混在する問題が発生していた。

### 13.2 解決策

1. **評価ごとに一意のディレクトリ**
   - 結果は `results/stage2_validation/eval_YYYYMMDD_HHMMSS/` に保存
   - 既存データとの混在を防止

2. **ロックファイルによる排他制御**
   - 評価開始時に `.eval_lock` を作成
   - 別の評価が開始されようとした場合は拒否
   - 評価終了時にロックを解放

### 13.3 ディレクトリ構成

```
results/stage2_validation/
├── .eval_lock                    # 排他制御用ロックファイル
├── eval_20260131_210056/         # 評価1
│   ├── worker_0_results.csv
│   ├── worker_1_results.csv
│   ├── worker_2_results.csv
│   ├── eval_df__nALL__ts_xxx.csv # マージ結果
│   └── *.json                    # チェックポイント
├── eval_20260131_220000/         # 評価2
│   └── ...
└── backup_YYYYMMDD_HHMMSS/       # バックアップ（手動）
```

### 13.4 ロックファイルの動作

```python
# 評価開始時
if lock_file.exists():
    print("❌ 別の評価が実行中です")
    return False
lock_file.write(f"eval_{eval_id}")

# 評価終了時（正常/異常問わず）
lock_file.unlink()
```

### 13.5 中断時の対処

評価が異常終了した場合、ロックファイルが残存する可能性がある。
その場合は手動で削除する:

```bash
rm artifacts/.../results/stage2_validation/.eval_lock
```

---

## 変更履歴

| バージョン | 日付 | 変更内容 |
|-----------|------|---------|
| v1.0 | 2026-01-24 | 初版作成 |
| v1.1 | 2026-01-28 | トレースフィールド追加 (AI Agent説明可能性向上) |
|      |            | - 判定理由 (ai_reasoning, ai_risk_factors, ai_detected_brands) |
|      |            | - Precheckトレース (ml_category, tld_category, brand_detected等) |
|      |            | - ツールスコア (brand/cert/domain/ctx_risk_score) |
|      |            | - ツール出力詳細 (tool_brand/cert/domain/ctx_output) |
|      |            | - FP/FN分析用サンプルコード追加 |
| v1.2 | 2026-01-28 | 実装との整合性修正 |
|      |            | - CLIオプション追加 (--config, --shuffle) |
|      |            | - Config: vllm.model をGPTQ版に更新 |
|      |            | - Config: speed_weight, stop_on_complete 追加 |
|      |            | - Config: evaluation, failover, logging セクション追加 |
|      |            | - Checkpoint: current_processing, current_index, started_at, updated_at 追加 |
|      |            | - GlobalState: updated_at 追加 |
| v1.3 | 2026-01-31 | データ混在防止機能追加 |
|      |            | - 評価ごとに一意のディレクトリ (`eval_YYYYMMDD_HHMMSS/`) |
|      |            | - ロックファイルによる排他制御 (`.eval_lock`) |
|      |            | - `run_eval_3gpu.sh` に自動リトライ (Step 5) 追加 |
| v1.4 | 2026-01-31 | 中断からの再開機能追加 (#11) |
|      |            | - `run_eval_3gpu.sh` に `--resume` オプション追加 |
|      |            | - チェックポイント検出時の自動プロンプト |
|      |            | - `orchestrator.setup(resume)` で既存ディレクトリ再利用 |
|      |            | - `_find_latest_checkpoint_dir()` メソッド追加 |
