# 新規特徴量候補メモ

**作成日**: 2026-01-12
**目的**: 証明書分析から発見した特徴量を各Stageに組み込むための備忘録

---

## Stage1 (XGBoost) 候補特徴量

証明書から抽出可能で、高速に計算できる特徴量。

| 特徴量名 | 計算方法 | 期待効果 | 優先度 |
|----------|----------|----------|--------|
| `has_crl` | CRL Distribution Points拡張の有無 | 正規81.7% vs フィッシング1.6% | **最高** |
| `has_wildcard` | SANに`*.`を含むか | 正規55.1% vs フィッシング1.5% | **最高** |
| `san_count_category` | SAN数を区分（1, 2-5, 6-20, 21-100, 100+） | 21-100がフィッシングで63.7% | **最高** |
| `subdomain_depth` | ドメインのドット数 - 1 | 深度1以上が正規9.5% vs フィッシング75% | **高** |
| `validity_over_180` | 有効期間が180日超か | 正規27% vs フィッシング1% | **高** |
| `is_ov_ev` | OV/EV証明書か（Subject Orgの有無） | 正規6.6% vs フィッシング0.1% | 中 |
| `issuer_is_le` | 発行者がLet's Encryptか | 正規39.8% vs フィッシング97.7% | 中 |
| `san_diversity` | ユニークSLD数 / SAN数 | 正規0.472 vs フィッシング0.288 | 中 |

---

## Stage2 (LR Defer) 候補特徴量

Stage1の出力と組み合わせて、Stage3送信判断に使用。

| 特徴量名 | 計算方法 | 用途 |
|----------|----------|------|
| `cert_anomaly_score` | Stage1特徴量の異常度合い | defer判定の補助 |
| `tld_risk_tier` | TLDの危険度（Tier1/2/3） | 高リスクTLDは詳細調査へ |
| `le_with_dangerous_tld` | LE証明書 + 危険TLD | 組み合わせでリスク上昇 |

---

## Stage3 (AI Agent) 候補特徴量・ルール

LLMによる詳細分析で使用。ポリシールール（R1-R6）への追加候補。

### 新規ルール候補

| ルール案 | 条件 | アクション |
|----------|------|-----------|
| **R7: 大量SAN + 動的DNS** | san_count >= 20 AND domain含む(duckdns, no-ip, etc) | → PHISHING |
| **R8: ワイルドカード正規パターン** | has_wildcard AND NOT dangerous_tld | → リスクスコア低下 |
| **R9: CRL保有正規パターン** | has_crl = True | → リスクスコア低下 |
| **R10: OV/EV正規パターン** | is_ov_ev = True | → BENIGN判定強化 |
| **R11: 週末発行 + 他リスク要因** | is_weekend_issued AND (dangerous_tld OR le_cert) | → リスクスコア上昇 |

### precheck_hints 追加候補

```python
precheck_hints = {
    # 既存
    'dangerous_tld': bool,
    'has_brand': bool,
    # 新規追加
    'has_crl': bool,           # CRL保有 → 正規寄り
    'has_wildcard': bool,      # ワイルドカード → 正規寄り
    'large_san': bool,         # SAN >= 20 → フィッシング寄り
    'is_ov_ev': bool,          # OV/EV証明書 → 正規寄り
    'is_dynamic_dns': bool,    # duckdns等 → フィッシング寄り
    'weekend_issued': bool,    # 週末発行 → やや怪しい
}
```

---

## 動的DNSサービスリスト

フィッシングで多用される動的DNSドメイン:

```python
DYNAMIC_DNS_DOMAINS = [
    'duckdns.org',
    'no-ip.com',
    'no-ip.org',
    'noip.com',
    'ddns.net',
    'dynu.com',
    'freedns.org',
    'afraid.org',
    'hopto.org',
    'zapto.org',
    'sytes.net',
]
```

---

## TLD危険度ティア

```python
TLD_RISK_TIERS = {
    # Tier 1: 99%以上 → 即座に危険フラグ
    'ultra_high': ['.gq', '.ga', '.ci', '.cfd', '.tk'],

    # Tier 2: 95-99% → 他要素と組み合わせで判定
    'very_high': ['.mw', '.icu', '.cn', '.bar', '.cyou', '.pw', '.xyz', '.ml'],

    # Tier 3: 90-95% → 注意が必要
    'high': ['.top', '.shop', '.club', '.buzz', '.sbs', '.work', '.bond'],
}
```

---

## 実装優先順位

### Phase 1（即座に効果大）
1. `has_crl` - 識別力80%、実装容易
2. `has_wildcard` - 識別力54%、実装容易
3. `san_count_category` - 識別力59%、実装容易

### Phase 2（中期）
4. `subdomain_depth` の強化
5. 動的DNSパターン検出
6. `is_ov_ev` 判定

### Phase 3（長期）
7. 時間的パターン（週末発行等）
8. SAN多様性指標
9. Issuer世代分析

---

## 関連ファイル

- 詳細分析レポート: `docs/analysis/certificate_analysis_report.md`
- データセット概要: `docs/research/dataset_overview.md`
- 研究日誌: `docs/research/20260111.md`, `20260110.md`

---

## 注意事項

1. **Stage1特徴量追加時**: `features.py` の特徴量リストに追加、再学習が必要
2. **Stage3ルール追加時**: `llm_final_decision.py` の `_apply_policy_adjustments()` に追加
3. **precheck追加時**: `short_domain_analysis.py` または `precheck` モジュールに追加

---

**次のステップ**: このメモを参照して仕様書を作成する
