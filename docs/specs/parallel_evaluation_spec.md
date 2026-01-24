# 並列評価システム仕様書

**バージョン**: v1.0
**更新日**: 2026-01-24
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
| `--add-gpu N[,M,...]` | 追加使用するWorker ID | なし (Worker 0のみ) |
| `--n-sample N` | 評価サンプル数 | ALL (全件) |
| `--random-state N` | 乱数シード | 42 |
| `--resume` | チェックポイントから再開 | False |
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

  - id: 1
    port: 8001
    type: external      # ポートフォワード済み

  - id: 2
    port: 8002
    type: external
    start_cmd: "ssh user@host 'bash -lc \"/path/to/vllm.sh start\"'"
    stop_cmd: "ssh user@host 'bash -lc \"/path/to/vllm.sh stop\"'"

vllm:
  model: "Qwen/Qwen3-4B"
  max_model_len: 8192
  max_num_seqs: 8
  gpu_memory_utilization: 0.85

health_check:
  interval: 5        # 秒
  timeout: 10
  max_failures: 3

retry:
  request_retries: 3
  request_delay: 5
  vllm_restarts: 3
  vllm_restart_delay: 30

shared_server:
  enabled: true
  check_gpu_usage_before_start: true
  gpu_memory_threshold_mb: 1000
  require_confirmation: true
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
  "run_id": "2026-01-21_152158",
  "total_domains": 17434,
  "num_workers": 2,
  "active_workers": [0, 1],
  "failed_workers": [],
  "started_at": "2026-01-23T15:39:00",
  "completed": false
}
```

### 6.3 WorkerProgress (worker_N_checkpoint.json)

```json
{
  "worker_id": 0,
  "status": "running",
  "total": 8717,
  "completed": 5000,
  "failed": 0,
  "last_completed_domain": "example.com",
  "last_completed_index": 4999,
  "current_processing": null,
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

## 10. 結果マージ

- 各Worker の `worker_N_results.csv` を読み込み
- domain列で重複除去 (resume時の重複対策)
- タイムスタンプ付きCSVとして保存
- マージ結果に全カラム含む (domain, ml_probability, ai_is_phishing, ai_confidence, ai_risk_level, processing_time, worker_id, error, source, y_true, stage1_pred, tld)

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
