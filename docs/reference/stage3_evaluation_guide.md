# Stage3 AI Agent 評価手順ガイド

## 概要

Stage3 は Qwen3-4B を使った AI Agent で、Stage1 (ML) の判定結果を再評価する。
本ドキュメントは、Stage3 の評価テストを実行する手順をまとめる。

---

## 前提条件

- PostgreSQL (`rapids_data` DB) が稼働中
- vLLM 用の GPU サーバにアクセス可能
- Python 仮想環境 (`phish-core`) がセットアップ済み

---

## 1. vLLM 起動

### ローカル GPU (port 8000)

```bash
# 起動
bash scripts/vllm.sh start

# 状態確認
bash scripts/vllm.sh status

# API疎通確認
curl -s http://localhost:8000/v1/models | python3 -c "import json,sys; print(json.load(sys.stdin)['data'][0]['id'])"
```

### Worker 1: リモート GPU (port 8001) - mana-vllm

```bash
# SSH トンネル経由で接続 (mana-vllm)
ssh -fNT -L 8001:127.0.0.1:8000 mana-vllm

# 疎通確認
curl -s http://localhost:8001/v1/models
```

### Worker 2: リモート GPU (port 8002) - 192.168.100.70

```bash
# SSH トンネル設定
ssh -fNT -L 8002:127.0.0.1:8000 asomura@192.168.100.70

# 疎通確認
curl -s http://localhost:8002/v1/models

# vLLM起動 (自動起動される場合は不要)
ssh asomura@192.168.100.70 'bash -lc "/home/asomura/src/vllm.sh start"'

# vLLM停止
ssh asomura@192.168.100.70 'bash -lc "/home/asomura/src/vllm.sh stop"'
```

**注意**: Worker 2 は `parallel_config.yaml` で `start_cmd`/`stop_cmd` が設定されているため、
`evaluate_e2e_parallel.py` が自動で起動・停止を行う。

### 注意事項

- GPU サーバは共用。使用後は必ず停止: `bash scripts/vllm.sh stop`
- モデル: `JunHowie/Qwen3-4B-Thinking-2507-GPTQ-Int8`
- port 8000: `max_model_len=4096` (ローカル)
- port 8001: `max_model_len=4096` (mana-vllm)
- port 8002: `max_model_len=4096` (192.168.100.70)

---

## 2. 評価実行

### 2a. 並列評価 (推奨)

```bash
# 2ワーカー並列 (port 8000 + 8001)
python3 scripts/evaluate_e2e_parallel.py --n-sample 3000 --add-gpu 1 --yes

# 3ワーカー並列 (port 8000 + 8001 + 8002)
python3 scripts/evaluate_e2e_parallel.py --add-gpu 1,2 --yes

# 全件評価 (17,434件)
# - 2ワーカー: 約18時間
# - 3ワーカー: 約6-8時間
python3 scripts/evaluate_e2e_parallel.py --add-gpu 1,2 --yes

# ドライラン (データ分割確認のみ)
python3 scripts/evaluate_e2e_parallel.py --n-sample 3000 --add-gpu 1,2 --yes --dry-run

# 前回の途中から再開
python3 scripts/evaluate_e2e_parallel.py --add-gpu 1,2 --yes --resume
```

### 2b. 単一ワーカー評価

```bash
# 1ワーカーのみ (port 8000)
python3 scripts/evaluate_e2e_parallel.py --n-sample 3000 --yes
```

### オプション

| オプション | 説明 | デフォルト |
|-----------|------|-----------|
| `--n-sample N` | 評価サンプル数 | ALL (17,434) |
| `--add-gpu N` | 追加ワーカー ID (1, 2, or 1,2) | なし (Worker 0のみ) |
| `--yes` | 確認プロンプトスキップ | 対話確認あり |
| `--resume` | チェックポイントから再開 | 最初から |
| `--random-state N` | 乱数シード | 42 |

### 所要時間の目安

| サンプル数 | 1ワーカー | 2ワーカー | 3ワーカー |
|-----------|-----------|-----------|-----------|
| 3,000 | ~6時間 | ~3時間 | ~2時間 |
| 17,434 (全件) | ~36時間 | ~18時間 | ~6-8時間 |

### Worker速度 (実測値)

| Worker | GPU | 速度 | speed_weight |
|--------|-----|------|--------------|
| 0 | RTX 5000 Ada | 9.0 dom/min | 1.59 |
| 1 | RTX 3080 | 10.0 dom/min | 1.77 |
| 2 | RTX 4000 Ada | 5.6 dom/min | 1.00 |

`speed_weight` に基づいてドメインが比例配分されるため、全Workerがほぼ同時に完了する。

---

## 3. 進捗確認

```bash
# チェックポイント確認
cat artifacts/2026-01-21_152158/results/stage2_validation/worker_0_checkpoint.json
cat artifacts/2026-01-21_152158/results/stage2_validation/worker_1_checkpoint.json

# 結果ファイルの行数
wc -l artifacts/2026-01-21_152158/results/stage2_validation/worker_*_results.csv

# プロセス確認
ps aux | grep evaluate_e2e | grep -v grep
```

---

## 3b. モニタリングスクリプト (推奨)

評価中にリアルタイムでFN/FP分析を行うモニタリングスクリプト。
**別ターミナル**で実行する。

### 使用方法

```bash
# 1000件ごとにFN/FP分析 + リアルタイム監視
python3 scripts/monitor_evaluation.py --interval 1000 --watch

# 単発で現在の状態を確認
python3 scripts/monitor_evaluation.py

# 500件ごとに分析
python3 scripts/monitor_evaluation.py --interval 500 --watch

# 特定のRUN_IDを指定
python3 scripts/monitor_evaluation.py --run-id 2026-01-25_123456 --watch
```

### オプション

| オプション | 説明 | デフォルト |
|-----------|------|-----------|
| `--interval N` | 分析間隔（件数） | 1000 |
| `--watch` | リアルタイム監視モード | Off |
| `--watch-interval N` | 監視間隔（秒） | 30 |
| `--run-id ID` | RUN_ID指定 | 最新 |

### 出力例

```
======================================================================
Stage3 AI Agent 評価レポート (2026-01-25 12:34:56)
======================================================================

【処理件数】
  完了: 3,000 件 (phishing: 540, benign: 2,460)

【AI Agent 性能】
  TP: 380  FP: 45  TN: 2,415  FN: 160
  Precision: 0.8941  Recall: 0.7037  F1: 0.7876

【ML Baseline (>0.5) 性能】
  TP: 350  FP: 70  FN: 190
  Precision: 0.8333  Recall: 0.6481  F1: 0.7292

【AI Agent vs ML Baseline】
  FP差分: -25 (改善)
  FN差分: -30 (改善)
  F1差分: +0.0584 (改善)

【FN内訳】
  危険TLD: 45
  短ドメイン(≤6文字): 38
======================================================================
```

---

## 4. 結果の確認

評価完了後、結果 CSV が生成される:

```
artifacts/2026-01-21_152158/results/stage2_validation/
  eval_df__nNNN__ts_TIMESTAMP.csv     # マージ済み結果
  worker_0_results.csv                 # Worker 0 の生データ
  worker_1_results.csv                 # Worker 1 の生データ
```

### メトリクス計算

```python
import csv
from collections import Counter

path = "artifacts/2026-01-21_152158/results/stage2_validation/eval_df__nNNN__ts_TIMESTAMP.csv"
with open(path) as f:
    rows = list(csv.DictReader(f))

# Stage3 結果
tp = fp = tn = fn = 0
for r in rows:
    y_true = int(r['y_true'])
    pred = 1 if r.get('ai_is_phishing', '').lower() in ('true', '1', 'yes') else 0
    if y_true == 1 and pred == 1: tp += 1
    elif y_true == 0 and pred == 1: fp += 1
    elif y_true == 0 and pred == 0: tn += 1
    elif y_true == 1 and pred == 0: fn += 1

precision = tp / (tp + fp)
recall = tp / (tp + fn)
f1 = 2 * precision * recall / (precision + recall)
print(f"TP={tp}, FP={fp}, TN={tn}, FN={fn}")
print(f"Precision={precision:.4f}, Recall={recall:.4f}, F1={f1:.4f}")
```

---

## 5. 設定ファイル

### scripts/parallel_config.yaml

```yaml
# ワーカー定義
workers:
  - id: 0
    port: 8000
    type: local
    gpu: 0
    speed_weight: 1.59      # RTX 5000 Ada

  - id: 1
    port: 8001
    type: external          # ポートフォワード済み (mana-vllm)
    stop_on_complete: false # 自分専用GPUのため停止不要
    speed_weight: 1.77      # RTX 3080

  - id: 2
    port: 8002
    type: external          # ポートフォワード + SSH起動/停止
    start_cmd: "ssh asomura@192.168.100.70 'bash -lc \"/home/asomura/src/vllm.sh start\"'"
    stop_cmd: "ssh asomura@192.168.100.70 'bash -lc \"/home/asomura/src/vllm.sh stop\"'"
    speed_weight: 1.00      # RTX 4000 Ada

# 評価設定
evaluation:
  checkpoint_interval: 100
  timeout_per_domain: 60
  retry_count: 2
```

---

## 6. トラブルシューティング

### vLLM が応答しない

```bash
# プロセス確認
ps aux | grep vllm | grep -v grep

# 再起動
bash scripts/vllm.sh stop
bash scripts/vllm.sh start
```

### Worker がクラッシュした

```bash
# --resume で途中から再開
python3 scripts/evaluate_e2e_parallel.py --add-gpu 1 --yes --resume
```

### チェックポイントをリセットしたい

```bash
rm artifacts/2026-01-21_152158/results/stage2_validation/worker_*_checkpoint.json
rm artifacts/2026-01-21_152158/results/stage2_validation/parallel_state.json
```

### port 8001 への接続が切れた (mana-vllm)

```bash
# SSH トンネル再接続
pkill -f "ssh.*mana-vllm"
ssh -fNT -L 8001:127.0.0.1:8000 mana-vllm
```

### port 8002 への接続が切れた (192.168.100.70)

```bash
# SSH トンネル再接続
pkill -f "ssh.*192.168.100.70"
ssh -fNT -L 8002:127.0.0.1:8000 asomura@192.168.100.70

# リモートvLLM再起動
ssh asomura@192.168.100.70 'bash -lc "/home/asomura/src/vllm.sh stop"'
ssh asomura@192.168.100.70 'bash -lc "/home/asomura/src/vllm.sh start"'

# 疎通確認
curl -s http://localhost:8002/v1/models
```

---

## 7. データクリーニング後の再評価

データクリーニング SQL を実行した後は、評価結果が変わる。
再評価のワークフロー:

1. `scripts/data_cleaning_stage3_v2.sql` を実行（ラベル誤り削除）
2. 評価を再実行
3. 結果比較: 以前の `eval_df` と新しい `eval_df` を比較

```bash
# データクリーニング実行 (Python経由)
python3 -c "
import psycopg2
conn = psycopg2.connect(host='localhost', port=5432, user='postgres', password='asomura', dbname='rapids_data')
with open('scripts/data_cleaning_stage3_v2.sql') as f:
    conn.cursor().execute(f.read())
conn.commit()
"

# 再評価 (3GPU並列)
python3 scripts/evaluate_e2e_parallel.py --add-gpu 1,2 --yes
```
