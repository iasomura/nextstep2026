# CSV拡張による特徴量保持 - 修正方針

## 概要

特徴量がパイプラインを通過するごとに脱落する問題を、CSV出力の拡張により解決する。

---

## 1. 現状の問題

### データフロー

```
X_test (42特徴量)
     │
     ▼
df_stage1 (7列のみ)  ← ここで35特徴量が脱落
     │
     ▼
df_handoff (7列)
     │
     ▼
eval_df (7列 + agent結果)
```

### 現在の `stage1_decisions_latest.csv` (7列)

| 列名 | 内容 |
|------|------|
| domain | ドメイン名 |
| source | データソース |
| ml_probability | XGBoost予測確率 |
| stage1_decision | Stage1判定 |
| y_true | 正解ラベル |
| cert_validity_days | 証明書有効期間（日） |
| cert_san_count | SAN数 |

---

## 2. 修正後のデータフロー

```
X_test (42特徴量) + cert_full_info_map (11項目)
     │
     ▼
df_stage1 (60+列)  ← 全特徴量を保持
     │
     ▼
df_handoff (60+列)
     │
     ▼
eval_df (60+列 + agent結果)
```

---

## 3. 02_main.py の修正

### 3.1 修正箇所: `df_stage1` 作成部分 (lines 1756-1765)

**現在のコード:**
```python
df_stage1 = pd.DataFrame({
    'domain': domain_test,
    'source': source_test,
    'ml_probability': p_test,
    'stage1_decision': stage1_decision,
    'y_true': y_test.astype(int),
    'cert_validity_days': X_test[:, 15],
    'cert_san_count': X_test[:, 17],
})
```

**修正後のコード:**
```python
from 02_stage1_stage2.src.features import FEATURE_ORDER

# 基本情報
df_stage1 = pd.DataFrame({
    'domain': domain_test,
    'source': source_test,
    'tld': tld_test,  # 追加: TLD（分析用）
    'ml_probability': p_test,
    'stage1_decision': stage1_decision,
    'stage1_pred': (p_test >= 0.5).astype(int),  # 追加
    'y_true': y_test.astype(int),
})

# ML特徴量 (42列) を追加
for i, feat_name in enumerate(FEATURE_ORDER):
    df_stage1[feat_name] = X_test[:, i]

# cert_full_info_map の情報を追加 (11列)
cert_info_cols = [
    'issuer_org', 'cert_age_days', 'is_free_ca', 'san_count',
    'is_wildcard', 'is_self_signed', 'has_organization',
    'not_before', 'not_after', 'validity_days', 'has_certificate'
]
for col in cert_info_cols:
    df_stage1[f'cert_info_{col}'] = df_stage1['domain'].map(
        lambda d: cert_full_info_map.get(d, {}).get(col)
    )
```

### 3.2 カラム数の変化

| 区分 | 列数 | 内容 |
|------|------|------|
| 基本情報 | 7 | domain, source, tld, ml_probability, stage1_decision, stage1_pred, y_true |
| ML特徴量 | 42 | FEATURE_ORDER の全項目 |
| 証明書情報 | 11 | cert_full_info_map の全項目 |
| **合計** | **60** | |

### 3.3 追加の修正箇所

**handoff_candidates_latest.csv の出力 (line 1921):**
- 修正不要（`df_handoff` は `df_stage1` からコピーするため自動的に拡張される）

**stage2_decisions_latest.csv (line 1880):**
- 必要に応じて特徴量カラムを追加（現在はgate_traceベース）

---

## 4. evaluate_e2e.py の修正

### 4.1 修正箇所: 結果保存部分 (lines 560-566)

**現在のコード:**
```python
eval_path = out_dir / f"eval_df__n{len(results['eval_df'])}__ts_{ts}.csv"
results["eval_df"].to_csv(eval_path, index=False)
```

**修正方針:**
- 入力CSV（stage1_decisions, handoff_candidates）が拡張されるため、自動的に特徴量が引き継がれる
- `eval_df` と `merged` に特徴量が含まれるようになる
- **追加修正は最小限**（特徴量カラムの選択的出力が必要な場合のみ）

### 4.2 オプション: 出力サイズ削減

全60列を出力するとファイルサイズが大きくなる。必要に応じて：

```python
# 分析に必要な列のみ出力
essential_cols = [
    'domain', 'source', 'tld', 'ml_probability', 'stage1_decision',
    'stage1_pred', 'y_true', 'agent_pred', 'agent_confidence',
    # 主要な特徴量
    'domain_length', 'entropy', 'contains_brand',
    'cert_validity_days', 'cert_is_lets_encrypt',
    # 証明書情報
    'cert_info_issuer_org', 'cert_info_is_free_ca', 'cert_info_validity_days',
]
eval_df_slim = results["eval_df"][essential_cols]
eval_df_slim.to_csv(eval_path_slim, index=False)

# フル版も保存（分析用）
results["eval_df"].to_csv(eval_path_full, index=False)
```

---

## 5. 分析スクリプトの修正

### 5.1 analyze_evaluation_results.py

**現状:** 複数ファイルをマージして分析
**修正後:** 拡張されたCSVから直接分析可能

```python
# 現状
fn_df = pd.read_csv(fn_cases_path)
cert_df = pd.read_pickle(cert_full_info_map_path)
fn_enriched = fn_df.merge(cert_df, on='domain')  # マージが必要

# 修正後
fn_df = eval_df[eval_df['y_true'] == 1 & eval_df['final_pred'] == 0]
# マージ不要、全特徴量が既に含まれている
```

### 5.2 05_pipeline_analysis.ipynb

**修正方針:**
- `cert_full_info_map.pkl` の読み込みを削除（または互換性のため残す）
- 拡張CSVから直接分析

---

## 6. 互換性の考慮

### 6.1 後方互換性

既存のスクリプトが壊れないように：

```python
# 02_main.py で従来形式も出力（オプション）
df_stage1_legacy = df_stage1[['domain', 'source', 'ml_probability',
                               'stage1_decision', 'y_true',
                               'cert_validity_days', 'cert_san_count']]
df_stage1_legacy.to_csv(results_dir / "stage1_decisions_legacy.csv", index=False)
```

### 6.2 カラム名の衝突回避

`cert_full_info_map` のカラムには `cert_info_` プレフィックスを付与：
- `validity_days` → `cert_info_validity_days`（ML特徴量の `cert_validity_days` と区別）
- `san_count` → `cert_info_san_count`（ML特徴量の `cert_san_count` と区別）

---

## 7. ファイルサイズの見積もり

### 現状
- `stage1_decisions_latest.csv`: ~128,000行 × 7列 ≈ 5-10 MB

### 拡張後
- `stage1_decisions_latest.csv`: ~128,000行 × 60列 ≈ 50-80 MB

**許容範囲**: 分析効率の向上に比べれば問題なし

---

## 8. 実装手順

### Phase 1: 02_main.py の修正
1. `df_stage1` 作成部分を拡張
2. テスト実行して出力確認
3. 既存の分析スクリプトが動作することを確認

### Phase 2: evaluate_e2e.py の修正
1. 拡張CSVの読み込み確認
2. 出力に特徴量が含まれることを確認
3. オプションでスリム版出力を追加

### Phase 3: 分析スクリプトの更新
1. マージ処理を削除/簡略化
2. 拡張CSVを直接使用するように変更

### Phase 4: ドキュメント更新
1. 研究日誌に記録
2. カラム定義のドキュメント化

---

## 9. 確認チェックリスト

- [ ] `df_stage1` に42特徴量が含まれている
- [ ] `df_stage1` に11証明書情報が含まれている
- [ ] `df_handoff` に特徴量が引き継がれている
- [ ] `eval_df` に特徴量が含まれている
- [ ] FN/FP分析でマージなしに特徴量にアクセスできる
- [ ] 既存スクリプトが動作する（後方互換性）
