# Stage2 証明書ベース早期終了ルール仕様書

**作成日**: 2026-01-12
**バージョン**: 1.1
**ステータス**: 実装完了

---

## 1. 現状分析

### 1.1 既存の特徴量

`features.py` の `FEATURE_ORDER` に以下の証明書特徴量が**既に実装済み**:

| # | 特徴量名 | 説明 | 提案との対応 |
|---|----------|------|-------------|
| 27 | `cert_has_crl_dp` | CRL Distribution Points有無 | = `has_crl` ✓ |
| 17 | `cert_is_wildcard` | ワイルドカード証明書（CNのみ） | ≒ `has_wildcard` (部分的) |
| 18 | `cert_san_count` | SAN数 | = `san_count` ✓ |
| 22 | `cert_subject_has_org` | Subject Organization有無 | = `is_ov_ev` ✓ |
| 16 | `cert_validity_days` | 有効期間（日数） | ✓ |
| 35 | `cert_is_lets_encrypt` | Let's Encrypt発行 | ✓ |

### 1.2 現在のStage2フロー

```
run_stage2_gate() in 02_main.py:715-900
├── Input
│   ├── df_defer: DataFrame（生データ）
│   ├── X_defer: np.ndarray（スケール済み41特徴量）
│   ├── p1_defer: Stage1確率
│   └── tlds_defer, domains_defer: ドメイン情報
│
├── LR Defer Model
│   └── defer_score = lr_model.predict_proba(X_combined)
│
├── Scenario 5: Safe BENIGN Filter (L774-783)
│   └── safe_benign = (p1 < 0.15) & (defer_score < 0.40)
│
└── Output
    ├── selected_mask: Stage3送信対象
    └── safe_benign: 自動BENIGN（Stage3スキップ）
```

### 1.3 特徴量インデックス

`FEATURE_ORDER` における証明書特徴量の位置:

```python
# Index: Feature Name
15: cert_validity_days
16: cert_is_wildcard
17: cert_san_count
18: cert_issuer_length
19: cert_is_self_signed
20: cert_cn_length
21: cert_subject_has_org      # = is_ov_ev
27: cert_has_crl_dp           # = has_crl
29: cert_is_lets_encrypt
```

---

## 2. 提案: 証明書ベースルール

### 2.1 Safe BENIGN 追加条件

現在の条件に加え、以下を追加:

```python
# 現在（Scenario 5）
safe_benign_base = (p1 < 0.15) & (defer_score < 0.40)

# 新規条件
safe_benign_crl = (cert_has_crl_dp == 1) & (p1 < 0.30)
safe_benign_wildcard = (cert_is_wildcard == 1) & (~is_dangerous_tld)
safe_benign_ov_ev = (cert_subject_has_org == 1)
safe_benign_long_validity = (cert_validity_days > 180) & (p1 < 0.25)

# 統合
safe_benign = safe_benign_base | safe_benign_crl | safe_benign_wildcard | safe_benign_ov_ev | safe_benign_long_validity
```

### 2.2 Safe PHISHING 追加条件

```python
# 動的DNSドメイン
DYNAMIC_DNS_SUFFIXES = [
    'duckdns.org', 'no-ip.com', 'ddns.net', 'dynu.com',
    'hopto.org', 'zapto.org', 'sytes.net'
]

# 条件
is_dynamic_dns = any(domain.endswith(suffix) for suffix in DYNAMIC_DNS_SUFFIXES)
safe_phish_dynamic_dns = is_dynamic_dns & (cert_san_count >= 20)

# Tier1 危険TLD（フィッシング率99%以上）
TIER1_TLDS = ['gq', 'ga', 'ci', 'cfd', 'tk']
is_tier1_tld = tld in TIER1_TLDS
safe_phish_tier1 = is_tier1_tld & (cert_is_lets_encrypt == 1)

# 統合
safe_phishing = safe_phish_dynamic_dns | safe_phish_tier1
```

---

## 3. 実装計画

### 3.1 変更箇所

| ファイル | 変更内容 |
|----------|----------|
| `02_main.py` L774-783 | `run_stage2_gate()` に新条件追加 |
| `_compat/config.json` | 新設定パラメータ追加 |

### 3.2 設定パラメータ追加

```json
{
  "stage2_cert_rules": {
    "enabled": true,
    "safe_benign": {
      "crl_enabled": true,
      "crl_p1_max": 0.30,
      "wildcard_enabled": true,
      "ov_ev_enabled": true,
      "long_validity_enabled": true,
      "long_validity_days": 180,
      "long_validity_p1_max": 0.25
    },
    "safe_phishing": {
      "dynamic_dns_enabled": true,
      "dynamic_dns_san_min": 20,
      "tier1_tld_enabled": true,
      "tier1_tlds": ["gq", "ga", "ci", "cfd", "tk"]
    }
  }
}
```

### 3.3 実装コード案

```python
def apply_cert_rules(X_defer, p1_defer, domains_defer, tlds_defer, cfg):
    """証明書ベースの早期終了ルールを適用"""

    n = len(p1_defer)
    cert_cfg = cfg.get('stage2_cert_rules', {})

    if not cert_cfg.get('enabled', False):
        return np.zeros(n, dtype=bool), np.zeros(n, dtype=bool)

    # 特徴量抽出（X_deferはスケール済みなので、元の値を使用するか閾値を調整）
    # FEATURE_ORDERのインデックス
    IDX_VALIDITY = 15
    IDX_WILDCARD = 16
    IDX_SAN_COUNT = 17
    IDX_HAS_ORG = 21
    IDX_HAS_CRL = 27
    IDX_IS_LE = 29

    # 注意: X_deferはスケール済み。元のDataFrameから取得するか、
    # 閾値をスケール後の値に変換する必要あり

    # --- Safe BENIGN ---
    safe_benign = np.zeros(n, dtype=bool)
    benign_cfg = cert_cfg.get('safe_benign', {})

    # CRLルール（cert_has_crl_dp == 1 は バイナリなのでスケール後も判別可能）
    if benign_cfg.get('crl_enabled', False):
        has_crl = X_defer[:, IDX_HAS_CRL] > 0.5  # スケール後でも1は正の値
        p1_threshold = benign_cfg.get('crl_p1_max', 0.30)
        safe_benign |= has_crl & (p1_defer < p1_threshold)

    # OV/EV ルール
    if benign_cfg.get('ov_ev_enabled', False):
        has_org = X_defer[:, IDX_HAS_ORG] > 0.5
        safe_benign |= has_org

    # --- Safe PHISHING ---
    safe_phishing = np.zeros(n, dtype=bool)
    phish_cfg = cert_cfg.get('safe_phishing', {})

    # 動的DNSルール
    if phish_cfg.get('dynamic_dns_enabled', False):
        dyn_suffixes = ['duckdns.org', 'no-ip.com', 'ddns.net', 'dynu.com',
                        'hopto.org', 'zapto.org', 'sytes.net']
        san_min = phish_cfg.get('dynamic_dns_san_min', 20)

        is_dynamic = np.array([
            any(str(d).lower().endswith(s) for s in dyn_suffixes)
            for d in domains_defer
        ])
        # SAN数はスケール後なので直接比較は難しい
        # → 元のDataFrameから取得するか、別途計算
        # ここでは簡略化のためスキップ

    # Tier1 TLDルール
    if phish_cfg.get('tier1_tld_enabled', False):
        tier1_tlds = phish_cfg.get('tier1_tlds', ['gq', 'ga', 'ci', 'cfd', 'tk'])
        tld_lower = np.array([str(t).lower() for t in tlds_defer])
        is_tier1 = np.isin(tld_lower, tier1_tlds)
        is_le = X_defer[:, IDX_IS_LE] > 0.5
        safe_phishing |= is_tier1 & is_le

    return safe_benign, safe_phishing
```

---

## 4. 課題と検討事項

### 4.1 スケール済み特徴量の扱い

`X_defer` はStandardScalerでスケール済みのため、バイナリ特徴量（0/1）の判定には注意が必要:

**選択肢:**
1. **閾値調整**: スケール後の値で判定（例: > 0.5）
2. **元データ参照**: `df_defer` から元の特徴量値を取得
3. **逆変換**: `scaler.inverse_transform()` で元の値に戻す

**推奨**: バイナリ特徴量は `> 0.5` で判定可能（0がスケール後に負、1が正になるため）

### 4.2 SAN数の扱い

`cert_san_count` は連続値のため、スケール後の比較が困難:

**対策:**
- `df_defer` にSAN数を保持しておく
- または、特徴量抽出時に `cert_san_count_raw` を別途保存

### 4.3 段階的導入

| Phase | 実装内容 | リスク |
|-------|----------|--------|
| 1 | `safe_benign_crl` のみ | 低 |
| 2 | `safe_benign_ov_ev` 追加 | 低 |
| 3 | `safe_phish_tier1` 追加 | 中（FP注意） |
| 4 | `safe_phish_dynamic_dns` 追加 | 中 |

---

## 5. テスト計画

### 5.1 効果測定指標

| 指標 | Scenario 5のみ | 目標 | Scenario 5+6実績 |
|------|----------------|------|------------------|
| Stage3 Handoff | 5,003件 | 削減 | **4,386件** |
| Safe BENIGN | 33,477件 | 増加 | **57,779件** |
| Auto Error Rate | 1.07% | 維持 | 1.10% |
| 新規safe_phishing | - | 追加 | 12件 |

### 5.2 A/Bテスト

1. 既存パイプラインと新パイプラインを並行実行
2. 判定差分を抽出
3. 差分サンプルをGSB等で外部検証

---

## 6. 実装結果（2026-01-12）

### 6.1 実装状況

| ルール | ステータス | 備考 |
|--------|-----------|------|
| CRL Distribution Points | **実装完了** | 最も効果的 |
| OV/EV証明書 | **実装完了** | |
| ワイルドカード | **実装完了** | dangerous_tld除外 |
| 長期有効期間 | **実装完了** | df_deferに生データ追加 |
| Tier1 TLD + LE | **実装完了** | |
| 動的DNS + 大量SAN | **実装完了** | ヒット0件（要調整） |

### 6.2 ルール別ヒット数

| ルール | ヒット数 | 効果 |
|--------|----------|------|
| CRL Distribution Points | **54,567** | 最大効果 |
| 長期有効期間 (180日超) | 8,507 | 高効果 |
| ワイルドカード | 4,841 | 中効果 |
| OV/EV証明書 | 1,355 | 中効果 |
| Tier1 TLD + LE | 12 | 限定的 |
| 動的DNS + 大量SAN | 0 | 要調整 |

### 6.3 効果測定結果

| 指標 | 目標 | 実績 | 達成 |
|------|------|------|------|
| Stage3 Handoff | 20,000件以下 | **4,386件** | **達成** |
| Auto Error Rate | 維持 | 1.07%→1.10% | ほぼ維持 |
| Safe BENIGN追加 | - | +24,302件 | - |
| Safe PHISHING追加 | - | +12件 | - |

### 6.4 変更ファイル

| ファイル | 行番号 | 変更内容 |
|----------|--------|----------|
| `02_main.py` | L113-128 | 設定オプション追加 |
| `02_main.py` | L802-892 | ルールロジック実装 |
| `02_main.py` | L900-947 | 選択ロジック・統計更新 |
| `02_main.py` | L1001-1009 | 変数初期化追加 |
| `02_main.py` | L1029-1032 | gate_traceカラム追加 |
| `02_main.py` | L1321-1323 | df_stage1に証明書特徴量追加 |

### 6.5 課題と今後の対応

| 課題 | 対応案 |
|------|--------|
| 動的DNSルールの不発 | san_count閾値を10に緩和 |
| Tier1 TLDの限定的効果 | Tier2 TLD追加検討 |
| Auto Error Rate微増 | 許容範囲内、監視継続 |

---

## 7. 関連ドキュメント

- 分析レポート: `docs/analysis/certificate_analysis_report.md`
- 特徴量候補メモ: `docs/analysis/feature_candidates_memo.md`
- Stage1/2特徴量仕様: `docs/specs/stage1_stage2_feature_spec.md`
- 研究日誌: `docs/research/20260112.md`

---

## 変更履歴

| 日付 | バージョン | 変更内容 |
|------|-----------|----------|
| 2026-01-12 | 1.0 | 初版作成 |
| 2026-01-12 | 1.1 | 実装結果追加 |
