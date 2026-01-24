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

### リモート GPU (port 8001) - ポートフォワード

```bash
# SSH トンネル経由で接続 (mana-vllm)
ssh -fNT -L 8001:127.0.0.1:8000 mana-vllm

# 疎通確認
curl -s http://localhost:8001/v1/models
```

### 注意事項

- GPU サーバは共用。使用後は必ず停止: `bash scripts/vllm.sh stop`
- モデル: `JunHowie/Qwen3-4B-Thinking-2507-GPTQ-Int8`
- port 8000: `max_model_len=16384`
- port 8001: `max_model_len=4096` (リモート設定依存)

---

## 2. 評価実行

### 2a. 並列評価 (推奨)

```bash
# 2ワーカー並列 (port 8000 + 8001)
python3 scripts/evaluate_e2e_parallel.py --n-sample 3000 --add-gpu 1 --yes

# 全件評価 (17,434件, 約6-8時間)
python3 scripts/evaluate_e2e_parallel.py --add-gpu 1 --yes

# ドライラン (データ分割確認のみ)
python3 scripts/evaluate_e2e_parallel.py --n-sample 3000 --add-gpu 1 --yes --dry-run

# 前回の途中から再開
python3 scripts/evaluate_e2e_parallel.py --add-gpu 1 --yes --resume
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

| サンプル数 | 1ワーカー | 2ワーカー |
|-----------|-----------|-----------|
| 3,000 | ~6時間 | ~3時間 |
| 17,434 (全件) | ~36時間 | ~18時間 |

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
  - id: 1
    port: 8001
    type: external    # ポートフォワード済み

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

### port 8001 への接続が切れた

```bash
# SSH トンネル再接続
pkill -f "ssh.*mana-vllm"
ssh -fNT -L 8001:127.0.0.1:8000 mana-vllm
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

# 再評価
python3 scripts/evaluate_e2e_parallel.py --n-sample 3000 --add-gpu 1 --yes
```
