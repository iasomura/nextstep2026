# VirusTotal バッチ調査スクリプト仕様書

**更新日**: 2026-01-24
**対象**: `scripts/vt_batch_investigation.py`

---

## 1. 概要

評価結果のFP/FNドメインをVirusTotal APIで一括調査し、データセットのラベルエラーを検出するスクリプト。複数APIキーによる並列処理、チェックポイントリジューム、レートリミット制御に対応。

## 2. 目的

- Stage1/Stage2/Stage3のFP/FNドメインを調査
- VirusTotalの検出数 (malicious/suspicious) に基づきラベルエラーを特定
- 調査結果からデータクリーニングSQL を生成

## 3. CLI インタフェース

```bash
python scripts/vt_batch_investigation.py [OPTIONS]
```

| オプション | 説明 | デフォルト |
|-----------|------|-----------|
| `--input, -i` | 入力CSVファイル | (設定値) |
| `--output, -o` | 出力CSVファイル | (設定値) |
| `--checkpoint, -c` | チェックポイントファイル | (設定値) |
| `--keys, -k` | APIキー (カンマ区切り) | 環境変数/ファイル |
| `--resume, -r` | チェックポイントから再開 | True |
| `--no-resume` | 最初から実行 | False |
| `--daily-limit` | 1キーあたりの日次リミット | 500 |

### 使用例

```bash
# Stage3 FP/FN調査
python scripts/vt_batch_investigation.py \
  --input artifacts/.../stage3_fp_fn_all_domains.csv \
  --output artifacts/.../stage3_vt_investigation_all.csv \
  --no-resume

# 複数キーで並列処理
python scripts/vt_batch_investigation.py --keys key1,key2,key3,key4

# チェックポイントから再開
python scripts/vt_batch_investigation.py --resume
```

## 4. APIキー管理

優先度順:
1. コマンドライン引数 (`--keys`)
2. 環境変数 (`VIRUSTOTAL_API_KEYS`, カンマ区切り)
3. キーファイル (`docs/virustotal_api_key.txt`)
4. 環境変数 (`VIRUSTOTAL_API_KEY`, 単一)

## 5. 入力仕様

### 入力CSV

| カラム | 型 | 説明 |
|--------|-----|------|
| `domain` | str | 調査対象ドメイン |
| `source` | str | データソース (optional) |
| `y_true` | int | 正解ラベル (optional) |
| `error_type` | str | FP/FN分類 (optional) |

## 6. VirusTotal API

### 6.1 エンドポイント

```
GET https://www.virustotal.com/api/v3/domains/{domain}
```

### 6.2 レートリミット

| プラン | 制限 |
|--------|------|
| Free | 4 req/min, 500 req/day per key |
| Premium | 制限緩和 |

### 6.3 レスポンス解析

- `last_analysis_stats.malicious`: malicious検出数
- `last_analysis_stats.suspicious`: suspicious検出数
- `last_analysis_stats.harmless`: harmless判定数
- `last_analysis_stats.undetected`: 未検出数
- `reputation`: レピュテーションスコア

## 7. 並列処理

### 7.1 Worker構成

- 各APIキーに1 Workerスレッドを割当
- キューベースのドメイン配分
- Worker間で結果を逐次書込

### 7.2 レートリミット制御

```python
VT_RATE_LIMIT_DELAY = 15.5  # 秒 (4 req/min)
```

- 429応答受信時: 60秒待機
- Worker単位で独立したレートリミット管理

## 8. 出力仕様

### 出力CSV

| カラム | 型 | 説明 |
|--------|-----|------|
| `domain` | str | ドメイン名 |
| `malicious` | int | malicious検出数 |
| `suspicious` | int | suspicious検出数 |
| `harmless` | int | harmless判定数 |
| `undetected` | int | 未検出数 |
| `reputation` | int | レピュテーションスコア |
| `error_type` | str | FP/FN分類 |
| `label_error` | bool | ラベルエラー判定 |
| `error` | str | APIエラー情報 |

### ラベルエラー判定基準

| ケース | 条件 | 判定 |
|--------|------|------|
| FP → ラベルエラー | FP かつ malicious >= 3 | 実はphishing (ラベルが間違い) |
| FN → ラベルエラー | FN かつ malicious == 0 & suspicious == 0 | 実はbenign (ラベルが間違い) |

## 9. チェックポイント

### checkpoint.json

```json
{
  "checked_domains": ["domain1.com", "domain2.com", ...],
  "last_updated": "2026-01-24T11:05:00"
}
```

- 各ドメイン処理完了時にチェックポイント更新
- `--resume` で未処理ドメインのみ実行

## 10. 出力活用

### データクリーニングSQL生成

調査結果からラベルエラーと判定されたドメインを削除するSQLを手動作成:

```sql
-- FP ラベルエラー (trusted_certificatesから削除)
DELETE FROM trusted_certificates WHERE domain IN ('error1.com', ...);

-- FN ラベルエラー (phishtank/jpcertから削除)
DELETE FROM phishtank_entries WHERE url LIKE '%error2.com%';
DELETE FROM jpcert_phishing_urls WHERE url LIKE '%error3.com%';
```

### パイプライン再実行

1. ラベルエラー削除SQL実行
2. パイプライン再実行 (`scripts/run_full_pipeline.sh`)
3. 調整後の性能指標で評価

## 11. 実績

### Stage1 VT調査 (2026-01-21)

| 対象 | 件数 | ラベルエラー | 割合 |
|------|------|-------------|------|
| FP | 505 | 190 | 37.6% |
| FN | 1667 | 49 | 2.9% |
| **合計** | **2172** | **239** | **11.0%** |

### Stage3 VT調査 (2026-01-24)

| 対象 | 件数 | 調査結果 |
|------|------|---------|
| FP | 196 | 調査中 |
| FN | 1428 | 調査中 |
| **合計** | **1624** | — |
