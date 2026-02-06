# データセット概要

> **最終更新**: 2026-02-06（DBから直接クエリした実測値に基づく）

## 概要

本研究で使用するデータセットは、PostgreSQLデータベース `rapids_data` に格納されている。フィッシングサイトの証明書データと、正規サイトの証明書データを収集・整理したものである。

## データベース接続情報

- Host: localhost
- Port: 5432
- Database: rapids_data
- 設定ファイル: `_compat/config.json`

---

## テーブル一覧

| テーブル名 | レコード数 | 説明 |
|-----------|-----------|------|
| certificates | 532,117 | フィッシングサイト証明書（JPCERT由来ドメイン） |
| jpcert_phishing_urls | 222,984 | JPCERTフィッシングURLフィード |
| phishtank_entries | 94,295 | PhishTankフィッシングデータ |
| phishing_sites | 1,831,206 | 統合フィッシングサイト情報（外部DB由来、全カラムJSONB） |
| phishing_sites_new | 1,831,206 | phishing_sitesのコピー |
| trusted_certificates | 554,801 | 正規サイト証明書（Tranco由来） |
| phishtank_cert_stats | 7 | PhishTank証明書統計 |
| phishtank_cert_progress | 1 | PhishTank証明書収集進捗 |
| phishtank_stats | 1 | PhishTank基本統計 |
| phishtank_target_stats | 117 | PhishTankターゲット統計 |
| phishtank_rir_stats | 5 | PhishTank RIR統計 |

---

## 主要テーブル詳細

### 1. certificates テーブル

フィッシングドメインの証明書データを格納。JPCERT URLから抽出したドメインに対して証明書を収集。

**カラム構成:**
- `id`: integer（主キー）
- `domain`: text
- `cert_id`: numeric
- `cert_data`: bytea（DER形式のX.509証明書バイナリ）
- `download_date`: timestamp
- `status`: text
- `debug_info`: text
- `debug_info_jsonb`: jsonb

**ステータス分布:**

| ステータス | 件数 | 割合 |
|-----------|------|------|
| NOT_FOUND | 261,905 | 49.2% |
| SUCCESS | 196,083 | 36.9% |
| UNKNOWN_ERROR | 42,204 | 7.9% |
| SEARCH_ERROR | 27,242 | 5.1% |
| DOWNLOAD_ERROR | 4,683 | 0.9% |

**証明書取得成功率:** 36.9% (196,083 / 532,117)

**ユニークドメイン数:** 532,117

**ダウンロード期間:** 2025-03-09 〜 2025-08-24

**TLD分布（上位10）:**

| TLD | 件数 |
|-----|------|
| .org | 207,707 |
| .com | 127,567 |
| .top | 61,146 |
| .cn | 39,273 |
| .cc | 21,034 |
| .icu | 19,516 |
| .xyz | 9,840 |
| .shop | 7,830 |
| .ci | 5,993 |
| .co | 5,258 |

---

### 2. jpcert_phishing_urls テーブル

JPCERT/CCのフィッシングURLフィードから収集したデータ。

**カラム構成:**
- `id`: integer（主キー）
- `date`: timestamp（URL報告日時）
- `url`: text
- `description`: text
- `domain`: text
- `cert_id`: numeric
- `cert_data`: bytea（DER形式）
- `download_date`: timestamp
- `status`: text
- `debug_info`: text
- `debug_info_jsonb`: jsonb
- `is_duplicate`: boolean
- `duplicate_source`: text
- `created_at`, `updated_at`: timestamp

**ステータス分布:**

| ステータス | 件数 | 割合 |
|-----------|------|------|
| SUCCESS | 115,620 | 51.9% |
| NOT_HTTPS | 41,633 | 18.7% |
| DUPLICATE | 36,033 | 16.2% |
| NOT_FOUND | 26,997 | 12.1% |
| SEARCH_ERROR | 1,558 | 0.7% |
| UNKNOWN_ERROR | 851 | 0.4% |
| DOWNLOAD_ERROR | 292 | 0.1% |

**URL報告期間:** 2019-01-04 〜 2025-03-31（約6年分）

**証明書ダウンロード期間:** 2025-06-19 〜 2025-07-12

**ユニークドメイン数:** 206,610

**重複分析:**
- 非重複: 186,951件
- 重複: 36,033件

**TLD分布（上位10）:**

| TLD | 件数 |
|-----|------|
| .com | 61,830 |
| .cn | 56,001 |
| .org | 22,856 |
| .top | 12,786 |
| .xyz | 10,384 |
| .dev | 7,043 |
| .shop | 6,104 |
| .cfd | 4,467 |
| .icu | 4,336 |
| .net | 3,539 |

---

### 3. phishtank_entries テーブル

PhishTankのverified phishing URLデータ。

**カラム構成:**
- `id`: integer
- `generated_at`: timestamptz
- `batch_id`: uuid
- `url`: text
- `phish_id`: bigint（PhishTank ID）
- `phish_detail_url`: text
- `ip_address`: inet
- `cidr_block`: cidr
- `announcing_network`: bigint
- `rir`: text
- `detail_time`, `submission_time`: timestamptz
- `verified`: boolean
- `verification_time`: timestamptz
- `online`: boolean
- `target`: text
- `cert_data`: bytea（DER形式）
- `cert_status`: text
- `cert_debug_info`: jsonb
- `cert_download_date`: timestamp
- `cert_id`: numeric
- `cert_domain`: text

**基本統計:**
- 全件 verified: True (94,295件)
- 全件 online: True (94,295件)
- 検証期間: 2011-02-19 〜 2025-07-02

**ユニークドメイン数:** 54,360（URLから抽出）

**証明書ステータス分布:**

| ステータス | 件数 |
|-----------|------|
| SUCCESS | 52,805 |
| NOT_FOUND | 40,653 |
| UNKNOWN_ERROR | 441 |
| SEARCH_ERROR | 327 |
| DOWNLOAD_ERROR | 47 |
| CONVERSION_ERROR | 12 |
| INVALID_URL | 10 |

**証明書ダウンロード期間:** 2025-06-08 〜 2025-07-02

**ターゲット分布（上位15）:**

| ターゲット | 件数 |
|-----------|------|
| Other | 85,238 |
| Allegro | 1,574 |
| Internal Revenue Service | 1,198 |
| Facebook | 944 |
| Microsoft | 916 |
| AT&T | 740 |
| Adobe | 324 |
| Optus | 260 |
| AEON Card | 248 |
| Amazon.com | 242 |
| Apple | 228 |
| Yahoo | 191 |
| DocuSign | 169 |
| British Telecom | 163 |
| Coinbase | 141 |

---

### 4. trusted_certificates テーブル

正規サイトの証明書データ。Trancoランキング由来のドメインから収集。

**カラム構成:**
- `id`: integer（主キー）
- `domain`: text
- `cert_data`: bytea（DER形式）
- `issuer_name`: text
- `common_name`: text
- `not_before`, `not_after`: text（"Mar 31 08:54:37 2025 GMT" 形式）
- `serial_number`: text
- `san_domains`: ARRAY
- `status`: text
- `download_date`: timestamp
- `debug_info`: jsonb

**ステータス分布:**

| ステータス | 件数 | 割合 |
|-----------|------|------|
| SUCCESS | 450,545 | 81.2% |
| DOWNLOAD_ERROR | 50,206 | 9.1% |
| NOT_FOUND | 38,424 | 6.9% |
| UNKNOWN_ERROR | 15,626 | 2.8% |

**ユニークドメイン数:** 554,801

**証明書取得成功数:** 450,545

**ダウンロード期間:** 2025-04-19 〜 2025-07-21

**TLD分布（上位10）:**

| TLD | 件数 |
|-----|------|
| .com | 278,016 |
| .org | 45,304 |
| .ru | 20,186 |
| .net | 19,030 |
| .uk | 17,256 |
| .de | 13,149 |
| .cn | 11,455 |
| .jp | 10,606 |
| .nl | 8,041 |
| .fr | 6,472 |

**証明書発行者分布（上位10）:**

| 発行者 | 件数 |
|--------|------|
| Google Trust Services (WE1) | 160,777 |
| Let's Encrypt (R10) | 68,591 |
| Let's Encrypt (R11) | 68,273 |
| Let's Encrypt (E5) | 20,010 |
| Let's Encrypt (E6) | 19,989 |
| Sectigo RSA DV | 14,915 |
| GoDaddy G2 | 11,455 |
| Amazon RSA 2048 M03 | 9,448 |
| Amazon RSA 2048 M02 | 9,171 |
| DigiCert Global G2 | 6,077 |

---

### 5. phishing_sites テーブル

外部データベースからインポートした統合フィッシングサイト情報。**全57カラムがJSONB型**。

**カラム数:** 57

**ユニークドメイン数:** 883,276

**データソース (src) 分布:**

| ソース | 件数 |
|--------|------|
| (空) | 1,756,008 |
| VTpassive | 53,329 |
| Certstream | 14,539 |
| Twitter | 4,836 |
| PhishHunterSANs | 1,448 |
| DNPedia | 296 |
| Twitter VTpassive | 234 |
| DNPedia VTpassive | 164 |

**ターゲット分布（上位15）:**

| ターゲット | 件数 |
|-----------|------|
| auid (au) | 203,061 |
| mufg_card | 202,121 |
| unknown | 199,203 |
| aeon | 196,524 |
| mufg | 184,779 |
| amazon | 181,223 |
| softbank | 99,915 |
| apple | 94,649 |
| docomo | 47,570 |
| smbc_card | 41,726 |
| nta (国税庁) | 41,045 |
| aeon_card | 33,176 |
| etc | 25,939 |
| mercari | 25,669 |
| rakuten_ichiba | 24,733 |

**国別分布（上位10）:**

| 国 | 件数 |
|----|------|
| US | 900,485 |
| (空) | 195,374 |
| KR | 192,976 |
| CA | 178,983 |
| CH | 62,250 |
| (null) | 61,004 |
| JP | 56,364 |
| HK | 27,989 |
| BG | 23,438 |
| RU | 18,142 |

---

## 証明書データ可用性サマリー

| テーブル | 総レコード | cert_data保有 | 保有率 |
|----------|-----------|---------------|--------|
| certificates | 532,117 | 196,083 | 36.9% |
| jpcert_phishing_urls | 222,984 | 119,439 | 53.6% |
| phishtank_entries | 94,295 | 52,808 | 56.0% |
| trusted_certificates | 554,801 | 450,545 | 81.2% |

---

## モデル学習用データ

### データ構築プロセス

`01_data_preparation_fixed_patched_nocert_full_artifacts_unified.ipynb` で実行。

#### Step 1: 各ソースから証明書保有ドメインを抽出

| ソース | 初期件数 | 重複除去後 |
|--------|---------|-----------|
| phishtank | 17,200 | 17,200 |
| jpcert | 112,038 | 112,038 |
| certificates | 190,145 | 190,145 |
| **フィッシング小計** | **319,383** | **319,383** |
| trusted_certificates | 319,383 | 319,383 |

※ ソース間の優先順位: phishtank > jpcert > certificates

#### Step 2: バランシング

フィッシング(319,383件)に合わせてtrusted_certificatesからサンプリングし、50:50のバランスデータを構築。

#### Step 3: Train/Test 分割（80:20）

| セット | 件数 | Phishing | Benign |
|--------|------|----------|--------|
| Train | 511,012 | 255,506 | 255,506 |
| Test | 127,754 | 63,877 | 63,877 |
| **合計** | **638,766** | **319,383** | **319,383** |

#### ソース別内訳

| ソース | Train | Test |
|--------|-------|------|
| certificates | 152,101 | 38,044 |
| jpcert | 89,637 | 22,401 |
| phishtank | 13,768 | 3,432 |
| trusted | 255,506 | 63,877 |

### 特徴量（42個）

| # | 特徴量名 | カテゴリ |
|---|---------|---------|
| 1 | domain_length | ドメイン構造 |
| 2 | dot_count | ドメイン構造 |
| 3 | hyphen_count | ドメイン構造 |
| 4 | digit_count | ドメイン構造 |
| 5 | digit_ratio | ドメイン構造 |
| 6 | tld_length | ドメイン構造 |
| 7 | subdomain_count | ドメイン構造 |
| 8 | longest_part_length | ドメイン構造 |
| 9 | entropy | ドメイン構造 |
| 10 | vowel_ratio | ドメイン構造 |
| 11 | max_consonant_length | ドメイン構造 |
| 12 | has_special_chars | ドメイン構造 |
| 13 | non_alphanumeric_count | ドメイン構造 |
| 14 | contains_brand | ドメイン構造 |
| 15 | has_www | ドメイン構造 |
| 16 | cert_validity_days | 証明書 |
| 17 | cert_is_wildcard | 証明書 |
| 18 | cert_san_count | 証明書 |
| 19 | cert_issuer_length | 証明書 |
| 20 | cert_is_self_signed | 証明書 |
| 21 | cert_cn_length | 証明書 |
| 22 | cert_subject_has_org | 証明書 |
| 23 | cert_subject_org_length | 証明書 |
| 24 | cert_san_dns_count | 証明書 |
| 25 | cert_san_ip_count | 証明書 |
| 26 | cert_cn_matches_domain | 証明書 |
| 27 | cert_san_matches_domain | 証明書 |
| 28 | cert_san_matches_etld1 | 証明書 |
| 29 | cert_has_ocsp | 証明書 |
| 30 | cert_has_crl_dp | 証明書 |
| 31 | cert_has_sct | 証明書 |
| 32 | cert_sig_algo_weak | 証明書 |
| 33 | cert_pubkey_size | 証明書 |
| 34 | cert_key_type_code | 証明書 |
| 35 | cert_is_lets_encrypt | 証明書 |
| 36 | cert_key_bits_normalized | 証明書 |
| 37 | cert_issuer_country_code | 証明書 |
| 38 | cert_serial_entropy | 証明書 |
| 39 | cert_has_ext_key_usage | 証明書 |
| 40 | cert_has_policies | 証明書 |
| 41 | cert_issuer_type | 証明書 |
| 42 | cert_is_le_r3 | 証明書 |

---

## ドメイン重複分析

### フィッシングソース間の重複

| 比較 | 重複ドメイン数 |
|------|--------------|
| certificates ∩ jpcert | 5,457 |
| certificates ∩ trusted | 15 |
| jpcert ∩ trusted | 13 |

### 統合後のユニークドメイン数

| 組み合わせ | ユニークドメイン数 |
|-----------|------------------|
| certificates (SUCCESS) | 196,083 |
| jpcert (SUCCESS) | 111,530 |
| phishtank (cert_data有) | 16,785 |
| cert + jpcert 統合 | 302,156 |
| cert + jpcert + phishtank 統合 | 318,315 |
| trusted (SUCCESS) | 450,545 |

---

## 証明書有効期間分析（全件）

> 詳細な証明書特徴量分析は `docs/analysis/03_certificate_analysis.md` を参照。
> 以下はDBからの全件実査（2026-02-06実施）。

### フィッシングサイト証明書

#### certificates テーブル（N=196,083）

| 統計量 | 値 |
|--------|-----|
| 平均有効期間 | 92.0 日 |
| 中央値 | 89 日 |

| 有効期間 | 件数 | 割合 |
|----------|------|------|
| 0-60日 | 1 | 0.0% |
| 61-100日 | 193,958 | 98.9% |
| 101-180日 | 24 | 0.0% |
| 181-365日 | 1,904 | 1.0% |
| 366-730日 | 196 | 0.1% |

**発行者 (上位5):**

| 発行者 | 件数 |
|--------|------|
| R3 (Let's Encrypt) | 168,287 |
| R10 (Let's Encrypt) | 11,103 |
| R11 (Let's Encrypt) | 10,605 |
| WE1 (Google Trust Services) | 844 |
| Let's Encrypt Authority X3 | 743 |

**発行年分布:**

| 年 | 件数 |
|----|------|
| 2020 | 1,161 |
| 2021 | 33,289 |
| 2022 | 76,681 |
| 2023 | 42,635 |
| 2024 | 39,716 |
| 2025 | 2,500 |

#### jpcert_phishing_urls テーブル（N=115,617）

| 統計量 | 値 |
|--------|-----|
| 平均有効期間 | 100.2 日 |
| 中央値 | 89 日 |

| 有効期間 | 件数 | 割合 |
|----------|------|------|
| 0-60日 | 23 | 0.0% |
| 61-100日 | 110,976 | 96.0% |
| 101-180日 | 38 | 0.0% |
| 181-365日 | 3,873 | 3.3% |
| 366-730日 | 693 | 0.6% |
| 731日+ | 14 | 0.0% |

**発行者 (上位5):**

| 発行者 | 件数 |
|--------|------|
| R3 (Let's Encrypt) | 80,880 |
| R11 (Let's Encrypt) | 7,598 |
| R10 (Let's Encrypt) | 6,893 |
| Let's Encrypt Authority X3 | 4,057 |
| WE1 (Google Trust Services) | 2,937 |

#### phishtank_entries テーブル（N=52,806）

| 統計量 | 値 |
|--------|-----|
| 平均有効期間 | 154.3 日 |
| 中央値 | 89 日 |

| 有効期間 | 件数 | 割合 |
|----------|------|------|
| 0-60日 | 2,199 | 4.2% |
| 61-100日 | 37,952 | 71.9% |
| 101-180日 | 171 | 0.3% |
| 181-365日 | 3,984 | 7.5% |
| 366-730日 | 8,469 | 16.0% |
| 731日+ | 31 | 0.1% |

**発行者 (上位5):**

| 発行者 | 件数 |
|--------|------|
| WR2 (Google Trust Services) | 8,145 |
| Amazon RSA 2048 M03 | 6,657 |
| WE1 (Google Trust Services) | 6,065 |
| R11 (Let's Encrypt) | 5,851 |
| R10 (Let's Encrypt) | 4,331 |

> **注**: PhishTankの証明書は、他のソースと比較してLet's Encryptの比率が低く（30%程度）、Google Trust Services/Amazon等の割合が高い。PhishTankは国際的なフィッシングデータであり、ターゲットがより多様なため、証明書の特性も異なる。

---

### 正規サイト証明書

#### trusted_certificates テーブル（N=450,545）

| 統計量 | 値 |
|--------|-----|
| 平均有効期間 | 153.2 日 |
| 中央値 | 90 日 |

| 有効期間 | 件数 | 割合 |
|----------|------|------|
| 0-60日 | 472 | 0.1% |
| 61-100日 | 349,024 | 77.5% |
| 101-180日 | 2,223 | 0.5% |
| 181-365日 | 29,721 | 6.6% |
| 366-730日 | 69,105 | 15.3% |

**発行者 (上位5):**

| 発行者 | 件数 |
|--------|------|
| WE1 (Google Trust Services) | 160,777 |
| R10 (Let's Encrypt) | 68,591 |
| R11 (Let's Encrypt) | 68,273 |
| E5 (Let's Encrypt) | 20,010 |
| E6 (Let's Encrypt) | 19,989 |

**発行年分布:**

| 年 | 件数 |
|----|------|
| 2024 | 51,089 |
| 2025 | 399,456 |

---

### フィッシング vs 正規 比較サマリー

| 指標 | フィッシング (certificates) | フィッシング (jpcert) | フィッシング (phishtank) | 正規 |
|------|---------------------------|----------------------|------------------------|------|
| 平均有効期間 | 92.0日 | 100.2日 | 154.3日 | 153.2日 |
| 中央値 | 89日 | 89日 | 89日 | 90日 |
| 90日証明書率 | 98.9% | 96.0% | 71.9% | 77.5% |
| 1年以上の証明書率 | 0.1% | 0.6% | 16.0% | 15.3% |
| Let's Encrypt率 | 97.5% | 91.3% | 30.7%※ | 39.3% |

※ PhishTankではLet's Encryptの比率が低い（Google Trust Services, Amazonが上位）

> **重要な発見**: certificates/jpcertテーブルのフィッシング証明書は97-98%がLet's Encryptの90日証明書で、有効期間による識別が可能。一方、PhishTankデータは正規サイトに近い分布を示しており、単純な証明書有効期間のみでの識別には限界がある。**有効期間は識別に有効だが万能ではない**。

---

## データの特徴

### 時間的範囲

| データソース | 期間 |
|------------|------|
| JPCERTフィード (URL報告) | 2019-01-04 〜 2025-03-31（約6年分） |
| PhishTank (検証日) | 2011-02-19 〜 2025-07-02（約14年分） |
| 証明書収集 (certificates) | 2025-03-09 〜 2025-08-24 |
| 証明書収集 (jpcert) | 2025-06-19 〜 2025-07-12 |
| 証明書収集 (phishtank) | 2025-06-08 〜 2025-07-02 |
| 証明書収集 (trusted) | 2025-04-19 〜 2025-07-21 |

### 地理的特徴（phishing_sitesより）

- フィッシングサイト: 米国(900K), 韓国(193K), カナダ(179K)が上位
- 日本向けフィッシング: au ID, MUFG, AEON, SoftBank等が多数（日本特化のデータソース由来）

### TLD特徴

- フィッシング (certificates): .org, .com, .top, .cn, .cc, .icu が多い
- フィッシング (jpcert): .com, .cn, .org, .top, .xyz, .dev が多い
- 正規: .com, .org, .ru, .net, .uk が主流

---

## 注意事項

1. **証明書の時間差**: URLの報告日時と証明書のダウンロード日時に数ヶ月〜数年の差がある。フィッシングサイトのURL報告は2019年〜2025年だが、証明書収集は2025年6月〜8月に実施。そのため、報告時点とは異なる証明書（更新後・失効後の再発行等）を取得している可能性がある。

2. **NOT_HTTPS**: jpcert URLの約18.7%はHTTPS未使用のため証明書データなし。

3. **ラベルノイズ**: フィッシングとしてラベル付けされたデータの一部は、時間経過により無害化または削除されている可能性がある。

4. **phishing_sitesテーブルの特殊性**: 全57カラムがJSONB型であり、直接的な集計にはJSON演算子が必要。外部データベースからのインポートデータ。

5. **PhishTankの証明書分布**: PhishTankのフィッシング証明書は、他ソースと比較してLet's Encrypt比率が低く、有効期間が長い傾向がある。これは国際的なフィッシングの多様性を反映している。

---

## 関連ドキュメント

- `_compat/config.json`: データベース接続設定
- `docs/analysis/03_certificate_analysis.md`: SSL/TLS証明書特徴量の詳細分析報告書
- `docs/analysis/04_stage3_certificate_analysis.md`: Stage3グレーゾーンの証明書分析
- `01_data_preparation_fixed_patched_nocert_full_artifacts_unified.ipynb`: データ構築ノートブック
- `artifacts/00-firststep/`: 構築済みデータセット（pickle形式）

---

## 更新履歴

- 2026-02-06: DBから直接クエリした実測値に全面改訂。証明書分析を全件で実施。
- 2026-01-12: 初版作成
