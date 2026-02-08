# データ仕様書 v1.0

**文書番号**: SPEC-DATA-001
**作成日**: 2026-01-20
**ステータス**: 完了

---

## 1. 概要

### 1.1 目的

本仕様書は、フィッシング検出パイプラインにおけるデータ構造、フィールド定義、およびデータフローを定義する。

### 1.2 スコープ

- `cert_full_info_map`: 証明書情報マップ
- `df_stage1`: Stage1出力DataFrame
- `df_handoff`: Stage2ハンドオフ候補DataFrame
- 関連するCSV/PKLファイル

### 1.3 用語

| 用語 | 定義 |
|------|------|
| ML特徴量 | XGBoostモデルで使用する数値特徴量（42項目） |
| 証明書情報 | cert_full_info_mapに格納される人間可読な証明書属性 |
| Stage1 | XGBoostによる初期分類 |
| Stage2 | ハンドオフ候補の選択 |
| Stage3 | AI Agentによる詳細判定 |

---

## 2. cert_full_info_map 仕様

### 2.1 概要

証明書から抽出した情報をドメインごとに格納する辞書型データ構造。

```python
cert_full_info_map: Dict[str, Dict[str, Any]]
# キー: ドメイン名（小文字）
# 値: 証明書情報辞書
```

### 2.2 フィールド定義

#### 2.2.1 基本フィールド（既存）

| フィールド名 | 型 | 必須 | デフォルト | 説明 |
|--------------|-----|------|------------|------|
| `has_certificate` | bool | ✓ | False | 証明書パース成功フラグ |
| `issuer_org` | str \| None | - | None | 発行者組織名 |
| `validity_days` | int | ✓ | 0 | 有効期間（日数） |
| `valid_days` | int | ✓ | 0 | 有効期間（日数）※validity_daysのエイリアス |
| `cert_age_days` | int | ✓ | 0 | 発行からの経過日数 |
| `not_before` | datetime \| None | - | None | 有効期間開始日時 |
| `not_after` | datetime \| None | - | None | 有効期間終了日時 |
| `san_count` | int | ✓ | 1 | Subject Alternative Name の数 |
| `is_free_ca` | bool | ✓ | False | 無料CA発行フラグ |
| `is_wildcard` | bool | ✓ | False | ワイルドカード証明書フラグ |
| `is_self_signed` | bool | ✓ | False | 自己署名証明書フラグ |
| `has_organization` | bool | ✓ | False | Subject に組織名があるか |

#### 2.2.2 追加フィールド（LLM/人間可読用）

| フィールド名 | 型 | 必須 | デフォルト | 説明 |
|--------------|-----|------|------------|------|
| `key_type` | str \| None | - | None | 鍵種別 ("RSA", "EC", "DSA") |
| `key_size` | int \| None | - | None | 鍵サイズ (2048, 4096, 256等) |
| `issuer_country` | str \| None | - | None | 発行者国コード ("US", "GB"等) |
| `issuer_type` | str \| None | - | None | 発行者種別（下記参照） |
| `signature_algorithm` | str \| None | - | None | 署名アルゴリズム |
| `common_name` | str \| None | - | None | CN (Common Name) |
| `subject_org` | str \| None | - | None | Subject組織名（文字列） |

#### 2.2.3 互換性フィールド（新規追加）

| フィールド名 | 型 | 必須 | デフォルト | 説明 |
|--------------|-----|------|------------|------|
| `has_crl_dp` | bool | ✓ | False | CRL Distribution Point 有無 |

### 2.3 issuer_type の値

| 値 | 説明 |
|----|------|
| `"Let's Encrypt"` | Let's Encrypt発行 |
| `"Google"` | Google Trust Services発行 |
| `"Cloudflare"` | Cloudflare発行 |
| `"Amazon"` | Amazon/AWS発行 |
| `"Microsoft"` | Microsoft/Azure発行 |
| `"Commercial CA"` | 商用CA (DigiCert, Comodo等) |
| `"Free CA"` | その他無料CA (ZeroSSL, cPanel等) |
| `None` | 不明/未分類 |

### 2.4 is_free_ca 判定ロジック

以下の文字列が `issuer_org` に含まれる場合に True:
- "let's encrypt"
- "zerossl"
- "cloudflare"
- "cpanel"
- "sectigo"

---

## 3. df_stage1 仕様

### 3.1 概要

Stage1の判定結果と全特徴量を格納するDataFrame。

### 3.2 カラム定義

#### 3.2.1 基本情報カラム（8列）

| カラム名 | 型 | 説明 |
|----------|-----|------|
| `domain` | str | ドメイン名 |
| `source` | str | データソース (phishtank, jpcert, certificates, tranco) |
| `tld` | str | TLD (.com, .jp等) |
| `ml_probability` | float | XGBoost予測確率 [0.0-1.0] |
| `stage1_decision` | str | Stage1判定 (auto_benign, auto_phishing, handoff_to_agent) |
| `stage1_pred` | int | Stage1予測 (0=benign, 1=phishing) ※ml_probability >= 0.5 |
| `y_true` | int | 正解ラベル (0=benign, 1=phishing) |
| `label` | int | y_trueのエイリアス（互換性用） |

#### 3.2.2 ML特徴量カラム（42列）

プレフィックス: `ml_`

| カラム名 | 型 | 説明 |
|----------|-----|------|
| `ml_domain_length` | int | ドメイン長 |
| `ml_dot_count` | int | ドット数 |
| `ml_hyphen_count` | int | ハイフン数 |
| `ml_digit_count` | int | 数字の数 |
| `ml_digit_ratio` | float | 数字の割合 |
| `ml_tld_length` | int | TLD長 |
| `ml_subdomain_count` | int | サブドメイン数 |
| `ml_longest_part_length` | int | 最長パート長 |
| `ml_entropy` | float | エントロピー |
| `ml_vowel_ratio` | float | 母音割合 |
| `ml_max_consonant_length` | int | 最長子音連続長 |
| `ml_has_special_chars` | int | 特殊文字有無 (0/1) |
| `ml_non_alphanumeric_count` | int | 非英数字数 |
| `ml_contains_brand` | int | ブランド含有 (0/1) |
| `ml_has_www` | int | www有無 (0/1) |
| `ml_cert_validity_days` | int | 証明書有効日数 |
| `ml_cert_is_wildcard` | int | ワイルドカード (0/1) |
| `ml_cert_san_count` | int | SAN数 |
| `ml_cert_issuer_length` | int | 発行者名長 |
| `ml_cert_is_self_signed` | int | 自己署名 (0/1) |
| `ml_cert_cn_length` | int | CN長 |
| `ml_cert_subject_has_org` | int | Subject組織有無 (0/1) |
| `ml_cert_subject_org_length` | int | Subject組織名長 |
| `ml_cert_san_dns_count` | int | DNS SAN数 |
| `ml_cert_san_ip_count` | int | IP SAN数 |
| `ml_cert_cn_matches_domain` | int | CNがドメインと一致 (0/1) |
| `ml_cert_san_matches_domain` | int | SANがドメインと一致 (0/1) |
| `ml_cert_san_matches_etld1` | int | SANがeTLD+1と一致 (0/1) |
| `ml_cert_has_ocsp` | int | OCSP有無 (0/1) |
| `ml_cert_has_crl_dp` | int | CRL DP有無 (0/1) |
| `ml_cert_has_sct` | int | SCT有無 (0/1) |
| `ml_cert_sig_algo_weak` | int | 弱い署名アルゴリズム (0/1) |
| `ml_cert_pubkey_size` | int | 公開鍵サイズ |
| `ml_cert_key_type_code` | int | 鍵種別コード (0-3) |
| `ml_cert_is_lets_encrypt` | int | Let's Encrypt (0/1) |
| `ml_cert_key_bits_normalized` | float | 正規化鍵サイズ [0-1] |
| `ml_cert_issuer_country_code` | int | 発行者国コード (0-2) |
| `ml_cert_serial_entropy` | float | シリアル番号エントロピー |
| `ml_cert_has_ext_key_usage` | int | EKU有無 (0/1) |
| `ml_cert_has_policies` | int | Policies有無 (0/1) |
| `ml_cert_issuer_type` | int | 発行者種別コード (0-4) |
| `ml_cert_is_le_r3` | int | LE R3/E1 (0/1) |

#### 3.2.3 証明書情報カラム（20列）

プレフィックス: `cert_`

| カラム名 | 型 | 説明 |
|----------|-----|------|
| `cert_issuer_org` | str \| None | 発行者組織名 |
| `cert_age_days` | int | 発行からの経過日数 |
| `cert_is_free_ca` | bool | 無料CAフラグ |
| `cert_san_count` | int | SAN数 |
| `cert_is_wildcard` | bool | ワイルドカードフラグ |
| `cert_is_self_signed` | bool | 自己署名フラグ |
| `cert_has_organization` | bool | 組織名有無 |
| `cert_not_before` | datetime \| str | 有効期間開始 |
| `cert_not_after` | datetime \| str | 有効期間終了 |
| `cert_validity_days` | int | 有効期間（日数） |
| `cert_has_certificate` | bool | 証明書有無 |
| `cert_key_type` | str \| None | 鍵種別 |
| `cert_key_size` | int \| None | 鍵サイズ |
| `cert_issuer_country` | str \| None | 発行者国 |
| `cert_issuer_type` | str \| None | 発行者種別 |
| `cert_signature_algorithm` | str \| None | 署名アルゴリズム |
| `cert_common_name` | str \| None | CN |
| `cert_subject_org` | str \| None | Subject組織名 |
| `cert_has_crl_dp` | bool | CRL DP有無 |
| `cert_valid_days` | int | 有効期間（エイリアス） |

### 3.3 合計カラム数

| 区分 | 列数 |
|------|------|
| 基本情報 | 8 |
| ML特徴量 | 42 |
| 証明書情報 | 20 |
| **合計** | **70** |

---

## 4. 出力ファイル仕様

### 4.1 stage1_decisions_latest.csv

| 項目 | 値 |
|------|-----|
| パス | `artifacts/{RUN_ID}/results/stage1_decisions_latest.csv` |
| 形式 | CSV (UTF-8, ヘッダあり) |
| カラム数 | 70 |
| 行数 | 全テストサンプル数（約128,000） |

### 4.2 handoff_candidates_latest.csv

| 項目 | 値 |
|------|-----|
| パス | `artifacts/{RUN_ID}/handoff/handoff_candidates_latest.csv` |
| 形式 | CSV (UTF-8, ヘッダあり) |
| カラム数 | 71 (基本70 + prediction_proba) |
| 行数 | Stage2選択サンプル数（最大budget） |

### 4.3 cert_full_info_map.pkl

| 項目 | 値 |
|------|-----|
| パス | `artifacts/{RUN_ID}/processed/cert_full_info_map.pkl` |
| 形式 | joblib pickle |
| 構造 | `Dict[str, Dict[str, Any]]` |
| フィールド数 | 20 |

---

## 5. 互換性要件

### 5.1 後方互換性

以下のコードが修正なしで動作すること:

```python
# evaluate_e2e.py
full_df = pd.read_csv(stage1_csv)
full_df["label"] = full_df["y_true"].astype(int)
full_df["stage1_pred"] = (full_df["ml_probability"] >= 0.5).astype(int)

# precheck_module.py
valid_days = int(meta.get("valid_days") or meta.get("validity_days") or 0)
has_crl_dp = bool(meta.get("has_crl_dp") or False)
```

### 5.2 フィールド名エイリアス

互換性のため、以下のエイリアスを維持:

| 正規名 | エイリアス | 理由 |
|--------|------------|------|
| `validity_days` | `valid_days` | precheck_module.py互換 |
| `y_true` | `label` | evaluate_e2e.py互換 |

---

## 6. 実装チェックリスト

### 6.1 02_main.py

- [x] cert_full_info_map に `valid_days` エイリアス追加 ✅ 2026-01-20
- [x] cert_full_info_map に `has_crl_dp` 追加 ✅ 2026-01-20
- [x] df_stage1 に `tld` カラム追加 ✅ 2026-01-20
- [x] df_stage1 に `stage1_pred` カラム追加 ✅ 2026-01-20
- [x] df_stage1 に `label` カラム追加 ✅ 2026-01-20
- [x] df_stage1 に ML特徴量 42列追加（`ml_` プレフィックス） ✅ 2026-01-20
- [x] df_stage1 に 証明書情報 20列追加（`cert_` プレフィックス） ✅ 2026-01-20

### 6.2 検証項目

- [x] stage1_decisions_latest.csv が70列であること ✅ 2026-01-20
- [x] cert_full_info_map.pkl が20フィールドであること ✅ 2026-01-20
- [x] evaluate_e2e.py が正常動作すること ✅ 2026-01-20
- [x] precheck_module.py が valid_days を正しく取得すること ✅ 2026-01-20

---

## 7. 変更履歴

| 版 | 日付 | 変更内容 |
|----|------|----------|
| 1.0 | 2026-01-20 | 初版作成 |
