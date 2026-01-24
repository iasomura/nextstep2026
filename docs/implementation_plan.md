# プログラム変更計画

## 概要

特徴量保持問題を解決するため、CSV出力を拡張する。

---

## 変更対象ファイル一覧

| ファイル | 変更内容 | 優先度 | 状態 |
|----------|----------|--------|------|
| `02_main.py` | cert_full_info_map拡張 | 1 | **完了** |
| `02_main.py` | df_stage1にML特徴量追加 | 1 | 未着手 |
| `02_main.py` | df_stage1に証明書情報追加 | 1 | 未着手 |
| `evaluate_e2e.py` | 出力確認・必要に応じて修正 | 2 | 未着手 |
| `docs/csv_extension_plan.md` | カラム定義更新 | 3 | 未着手 |
| 分析スクリプト | マージ処理簡略化 | 3 | 未着手 |

---

## 1. 02_main.py の変更

### 1.1 cert_full_info_map の拡張 ✅ 完了

**変更箇所**: lines 1448-1609

**追加フィールド** (7項目):
- `key_type`: "RSA", "EC", "DSA"
- `key_size`: 2048, 4096, 256等
- `issuer_country`: "US", "GB"等
- `issuer_type`: "Let's Encrypt", "Google", "Commercial CA"等
- `signature_algorithm`: "sha256WithRSAEncryption"等
- `common_name`: CN値
- `subject_org`: Subject組織名

### 1.2 df_stage1 の拡張 ⬜ 未着手

**変更箇所**: lines 1756-1769

**現在のコード**:
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

**変更後のコード**:
```python
from 02_stage1_stage2.src.features import FEATURE_ORDER

# 基本情報 (8列)
df_stage1 = pd.DataFrame({
    'domain': domain_test,
    'source': source_test,
    'tld': tld_test,
    'ml_probability': p_test,
    'stage1_decision': stage1_decision,
    'stage1_pred': (p_test >= 0.5).astype(int),
    'y_true': y_test.astype(int),
    'label': y_test.astype(int),  # 互換性のため
})

# ML特徴量 (42列) を追加
for i, feat_name in enumerate(FEATURE_ORDER):
    df_stage1[f'ml_{feat_name}'] = X_test[:, i]

# cert_full_info_map の情報を追加 (18列)
cert_info_cols = [
    'issuer_org', 'cert_age_days', 'is_free_ca', 'san_count',
    'is_wildcard', 'is_self_signed', 'has_organization',
    'not_before', 'not_after', 'validity_days', 'has_certificate',
    # 追加フィールド
    'key_type', 'key_size', 'issuer_country', 'issuer_type',
    'signature_algorithm', 'common_name', 'subject_org',
]
for col in cert_info_cols:
    df_stage1[f'cert_{col}'] = df_stage1['domain'].map(
        lambda d: cert_full_info_map.get(d, {}).get(col)
    )
```

### 1.3 カラム命名規則

| プレフィックス | 内容 | 例 |
|----------------|------|-----|
| (なし) | 基本情報 | domain, source, tld, ml_probability |
| `ml_` | ML特徴量 (42列) | ml_domain_length, ml_cert_validity_days |
| `cert_` | 証明書情報 (18列) | cert_issuer_org, cert_key_type |

**理由**: ML特徴量の`cert_validity_days`と証明書情報の`validity_days`が重複するため、プレフィックスで区別

### 1.4 出力カラム数

| 区分 | 列数 |
|------|------|
| 基本情報 | 8 |
| ML特徴量 | 42 |
| 証明書情報 | 18 |
| **合計** | **68** |

---

## 2. evaluate_e2e.py の変更

### 2.1 確認事項

- 拡張されたCSVの読み込みが正常に動作するか
- 追加カラムがeval_df, mergedに引き継がれるか

### 2.2 想定される変更

**最小限の変更で済む見込み**:
- `full_df = pd.read_csv(stage1_csv)` は追加カラムも読み込む
- `handoff_all = pd.read_csv(handoff_csv)` も同様

**オプション: スリム版出力**:
```python
# 全カラム版
results["eval_df"].to_csv(eval_path_full, index=False)

# 分析用スリム版（主要カラムのみ）
slim_cols = ['domain', 'source', 'tld', 'ml_probability', 'stage1_decision',
             'y_true', 'agent_pred', 'agent_confidence', 'cert_issuer_type', ...]
results["eval_df"][slim_cols].to_csv(eval_path_slim, index=False)
```

---

## 3. 分析スクリプトの変更

### 3.1 analyze_evaluation_results.py

**現在**: 複数ファイルをマージして分析
```python
fn_df = pd.read_csv(fn_cases_path)
cert_info = pd.read_pickle(cert_full_info_map_path)
fn_enriched = fn_df.merge(cert_info, on='domain')
```

**変更後**: 拡張CSVから直接分析
```python
eval_df = pd.read_csv(eval_path)
fn_df = eval_df[(eval_df['y_true'] == 1) & (eval_df['final_pred'] == 0)]
# マージ不要、全カラムが既に含まれている
```

### 3.2 05_pipeline_analysis.ipynb

- `cert_full_info_map.pkl`の読み込みをオプション化
- 拡張CSVからの直接分析に対応

---

## 4. 実装順序

### Phase 1: 02_main.py の修正
1. ✅ cert_full_info_map の拡張（完了）
2. ⬜ df_stage1 の拡張（ML特徴量 + 証明書情報）
3. ⬜ テスト実行

### Phase 2: 動作確認
4. ⬜ 生成されたCSVのカラム確認
5. ⬜ evaluate_e2e.py の動作確認
6. ⬜ 分析スクリプトの動作確認

### Phase 3: ドキュメント更新
7. ⬜ カラム定義ドキュメント更新
8. ⬜ 研究日誌更新

---

## 5. テスト計画

### 5.1 単体テスト

```bash
# 02_main.py の実行（小規模データで）
python 02_main.py --test-mode

# 出力CSVの確認
head -1 artifacts/{RUN_ID}/results/stage1_decisions_latest.csv | tr ',' '\n' | wc -l
# 期待値: 68
```

### 5.2 統合テスト

```bash
# evaluate_e2e.py の実行
python scripts/evaluate_e2e.py --run-id {RUN_ID} --n-sample 100

# 出力確認
python -c "import pandas as pd; df = pd.read_csv('artifacts/{RUN_ID}/results/stage2_validation/eval_df__*.csv'); print(df.columns.tolist())"
```

### 5.3 回帰テスト

- 既存のメトリクス計算が正しく動作することを確認
- Stage1/Stage2/Stage3の判定結果に影響がないことを確認

---

## 6. ロールバック計画

問題が発生した場合:
1. Git で変更前の状態に戻す
2. 既存のpklファイル（cert_full_info_map.pkl）は変更されないため、分析は継続可能

---

## 7. 見積もり

| フェーズ | 作業内容 |
|----------|----------|
| Phase 1 | 02_main.py修正 + テスト |
| Phase 2 | 動作確認 |
| Phase 3 | ドキュメント |
