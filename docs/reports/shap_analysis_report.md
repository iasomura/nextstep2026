# SHAP Analysis Report — Stage1 XGBoost

作成日: 2026-02-08
目的: MTG 2025-12-25 アクションアイテムA2「高確信度誤判定の抽出と特徴分析」への対応

---

## 1. 全体の特徴量重要度（Top-20）

| 順位 | 特徴量 | 種別 | Mean |SHAP| |
|------|--------|------|------------|
| 1 | dot_count | Domain | 2.6166 |
| 2 | domain_length | Domain | 1.7965 |
| 3 | tld_length | Domain | 1.5587 |
| 4 | cert_has_crl_dp | Cert | 1.4475 |
| 5 | cert_validity_days | Cert | 1.4274 |
| 6 | cert_issuer_length | Cert | 1.3764 |
| 7 | max_consonant_length | Domain | 0.9894 |
| 8 | cert_is_le_r3 | Cert | 0.8842 |
| 9 | cert_is_lets_encrypt | Cert | 0.7480 |
| 10 | entropy | Domain | 0.4041 |
| 11 | cert_cn_length | Cert | 0.3815 |
| 12 | cert_san_count | Cert | 0.2998 |
| 13 | subdomain_count | Domain | 0.2932 |
| 14 | longest_part_length | Domain | 0.2829 |
| 15 | cert_san_dns_count | Cert | 0.1915 |
| 16 | cert_san_matches_domain | Cert | 0.1815 |
| 17 | cert_issuer_type | Cert | 0.1699 |
| 18 | cert_has_sct | Cert | 0.1615 |
| 19 | cert_is_wildcard | Cert | 0.1145 |
| 20 | vowel_ratio | Domain | 0.1138 |

全42特徴量のうち、ドメイン特徴量 Top-20内: 8個、証明書特徴量 Top-20内: 12個

---

## 2. 高確信度誤判定の分析

### 2.1 Auto-phishing FP（p₁ ≥ 0.957 かつ y=0）: 4件

FPを引き起こした上位特徴量（SHAP平均値、正=フィッシング方向）:

| 特徴量 | Mean SHAP | 方向 |
|--------|-----------|------|
| dot_count | +2.9488 | →phishing |
| domain_length | +1.8468 | →phishing |
| cert_has_crl_dp | +1.4632 | →phishing |
| cert_validity_days | -1.4108 | →benign |
| cert_issuer_length | -1.3897 | →benign |
| tld_length | +1.3807 | →phishing |
| max_consonant_length | +1.0401 | →phishing |
| cert_is_le_r3 | -0.8431 | →benign |
| entropy | +0.4132 | →phishing |
| cert_cn_length | -0.3562 | →benign |

### 2.2 Auto-benign FN（p₁ ≤ 0.001 かつ y=1）: 2件

FNを引き起こした上位特徴量（SHAP平均値、負=正規方向）:

| 特徴量 | Mean SHAP | 方向 |
|--------|-----------|------|
| dot_count | +2.4280 | →phishing |
| domain_length | +1.8510 | →phishing |
| tld_length | +1.7752 | →phishing |
| cert_validity_days | -1.7571 | →benign |
| cert_is_lets_encrypt | -1.5721 | →benign |
| cert_issuer_length | -1.5691 | →benign |
| cert_has_crl_dp | +1.3834 | →phishing |
| max_consonant_length | +0.9954 | →phishing |
| cert_is_le_r3 | -0.9522 | →benign |
| cert_issuer_type | -0.6372 | →benign |
---

## 3. Gray zone（handoff領域）の特徴量分析

Gray zone 件数: 59281件（全127222件中 46.6%）

Gray zone で判定に最も寄与した特徴量:

| 順位 | 特徴量 | Mean |SHAP| (gray) | Mean |SHAP| (全体) | 比率 |
|------|--------|-------------------|------------------|------|
| 1 | dot_count | 2.3643 | 2.6166 | 0.90x |
| 2 | domain_length | 1.8134 | 1.7965 | 1.01x |
| 3 | tld_length | 1.7717 | 1.5587 | 1.14x |
| 4 | cert_validity_days | 1.4887 | 1.4274 | 1.04x |
| 5 | cert_has_crl_dp | 1.4519 | 1.4475 | 1.00x |
| 6 | cert_issuer_length | 1.3448 | 1.3764 | 0.98x |
| 7 | max_consonant_length | 0.9930 | 0.9894 | 1.00x |
| 8 | cert_is_lets_encrypt | 0.9896 | 0.7480 | 1.32x |
| 9 | cert_is_le_r3 | 0.9499 | 0.8842 | 1.07x |
| 10 | entropy | 0.4048 | 0.4041 | 1.00x |

---

## 4. まとめ

- 全体重要度は `docs/paper/images/shap_global_importance.png` を参照
- Beeswarm plot は `docs/paper/images/shap_beeswarm.png` を参照
- Auto-decision errors（高確信度誤判定）は合計 6 件
  - Auto-phishing FP: 4件
  - Auto-benign FN: 2件
- これらは Stage1 単体の高確信度誤判定であり、Stage2+3 で一部が救済される