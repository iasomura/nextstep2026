# Stage1/Stage2 新規特徴量追加仕様書

**作成日**: 2026-01-12
**バージョン**: 1.1
**ステータス**: Stage2実装完了（Stage1は既存実装活用）

---

## 1. 概要

### 1.1 目的

証明書分析から発見した高識別力特徴量をStage1（XGBoost）およびStage2（LR Defer）に追加し、フィッシング検出精度の向上とStage3 Handoff件数の削減を実現する。

### 1.2 期待効果

| 指標 | 現状 | 目標 |
|------|------|------|
| Stage1 AUC | 0.9973 | 0.998+ |
| Stage1 FN率 | 3.01% | 2.5%以下 |
| Stage3 Handoff | 28,684件 | 20,000件以下 |

---

## 2. Stage1 新規特徴量

### 2.1 追加特徴量一覧

| # | 特徴量名 | 型 | 説明 | 期待識別力 |
|---|----------|-----|------|-----------|
| 1 | `has_crl` | bool→int | CRL Distribution Points拡張の有無 | 80.1% |
| 2 | `has_wildcard` | bool→int | SANにワイルドカード(`*.`)を含むか | 53.6% |
| 3 | `san_count` | int | SAN（Subject Alternative Names）の数 | - |
| 4 | `san_count_category` | int | SAN数カテゴリ（0:1, 1:2-5, 2:6-20, 3:21-100, 4:100+） | 59.4% |
| 5 | `subdomain_depth` | int | サブドメイン深度（ドット数 - 1） | 65.9% |
| 6 | `validity_over_180` | bool→int | 有効期間が180日を超えるか | 26.6% |
| 7 | `is_ov_ev` | bool→int | OV/EV証明書か（Subject Organizationの有無） | 6.5% |
| 8 | `san_diversity` | float | SAN多様性（ユニークSLD数 / SAN数） | 18.4% |

### 2.2 特徴量抽出ロジック

```python
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def extract_new_features(cert_bytes: bytes, domain: str) -> dict:
    """証明書から新規特徴量を抽出"""

    cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())

    # 1. has_crl: CRL Distribution Points
    has_crl = 0
    try:
        cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.CRL_DISTRIBUTION_POINTS
        )
        has_crl = 1
    except x509.ExtensionNotFound:
        pass

    # 2-4. SAN関連
    san_count = 0
    has_wildcard = 0
    san_domains = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        for name in san_ext.value:
            if isinstance(name, x509.DNSName):
                san_domains.append(name.value.lower())
                san_count += 1
                if name.value.startswith('*.'):
                    has_wildcard = 1
    except x509.ExtensionNotFound:
        pass

    # san_count_category
    if san_count <= 1:
        san_count_category = 0
    elif san_count <= 5:
        san_count_category = 1
    elif san_count <= 20:
        san_count_category = 2
    elif san_count <= 100:
        san_count_category = 3
    else:
        san_count_category = 4

    # 5. subdomain_depth
    subdomain_depth = domain.count('.') - 1 if domain else 0
    subdomain_depth = max(0, subdomain_depth)

    # 6. validity_over_180
    validity_days = (cert.not_valid_after_utc - cert.not_valid_before_utc).days
    validity_over_180 = 1 if validity_days > 180 else 0

    # 7. is_ov_ev (Subject Organization有無)
    is_ov_ev = 0
    for attr in cert.subject:
        if attr.oid == x509.oid.NameOID.ORGANIZATION_NAME:
            is_ov_ev = 1
            break

    # 8. san_diversity
    if san_count <= 1:
        san_diversity = 1.0
    else:
        unique_slds = set()
        for d in san_domains:
            parts = d.lstrip('*.').split('.')
            if len(parts) >= 2:
                sld = '.'.join(parts[-2:])
                unique_slds.add(sld)
        san_diversity = len(unique_slds) / san_count

    return {
        'has_crl': has_crl,
        'has_wildcard': has_wildcard,
        'san_count': san_count,
        'san_count_category': san_count_category,
        'subdomain_depth': subdomain_depth,
        'validity_over_180': validity_over_180,
        'is_ov_ev': is_ov_ev,
        'san_diversity': san_diversity,
    }
```

### 2.3 実装箇所

| ファイル | 変更内容 |
|----------|----------|
| `src/features.py` | `extract_new_features()` 関数追加 |
| `src/features.py` | `FEATURE_COLUMNS` リストに8特徴量追加 |
| `src/train_xgb.py` | 特徴量抽出パイプラインに組み込み |

---

## 3. Stage2 早期終了条件

### 3.1 Auto-BENIGN条件（Stage3スキップ）

```python
def check_auto_benign(row: dict) -> bool:
    """Stage3をスキップしてBENIGN判定する条件"""

    p1 = row['ml_probability']
    defer_score = row['defer_score']

    # 既存条件
    if p1 < 0.15 and defer_score < 0.40:
        return True

    # 新規条件1: CRL保有 + 低リスク
    if row['has_crl'] == 1 and p1 < 0.30:
        return True

    # 新規条件2: ワイルドカード + 非危険TLD
    if row['has_wildcard'] == 1 and not row['is_dangerous_tld']:
        return True

    # 新規条件3: OV/EV証明書
    if row['is_ov_ev'] == 1:
        return True

    # 新規条件4: 長期有効期間 + 低リスク
    if row['validity_over_180'] == 1 and p1 < 0.25:
        return True

    return False
```

### 3.2 Auto-PHISHING条件（Stage3スキップ）

```python
# 動的DNSドメインリスト
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

# 超高リスクTLD（フィッシング率99%以上）
TIER1_DANGEROUS_TLDS = ['.gq', '.ga', '.ci', '.cfd', '.tk']

def check_auto_phishing(row: dict) -> bool:
    """Stage3をスキップしてPHISHING判定する条件"""

    domain = row['domain'].lower()

    # 新規条件1: 大量SAN + 動的DNS
    if row['san_count'] >= 20:
        for dyn_domain in DYNAMIC_DNS_DOMAINS:
            if domain.endswith(dyn_domain):
                return True

    # 新規条件2: Tier1危険TLD（99%以上がフィッシング）
    for tld in TIER1_DANGEROUS_TLDS:
        if domain.endswith(tld):
            # 追加条件: LE証明書 or 短期有効期間
            if row['issuer_is_le'] == 1 or row['validity_over_180'] == 0:
                return True

    # 新規条件3: 大量SAN + 低SAN多様性（同一ドメインの繰り返し）
    if row['san_count'] >= 20 and row['san_diversity'] < 0.1:
        return True

    return False
```

### 3.3 実装箇所

| ファイル | 変更内容 |
|----------|----------|
| `src/stage2_gate.py` | `check_auto_benign()` 関数追加 |
| `src/stage2_gate.py` | `check_auto_phishing()` 関数追加 |
| `src/stage2_gate.py` | defer判定ロジックに組み込み |
| `_compat/config.json` | 設定フラグ追加 |

---

## 4. 設定ファイル追加

```json
{
  "stage2_auto_rules": {
    "enabled": true,
    "auto_benign": {
      "crl_threshold": 0.30,
      "wildcard_enabled": true,
      "ov_ev_enabled": true,
      "long_validity_threshold": 0.25
    },
    "auto_phishing": {
      "dynamic_dns_enabled": true,
      "tier1_tld_enabled": true,
      "large_san_low_diversity_enabled": true,
      "san_threshold": 20,
      "diversity_threshold": 0.1
    }
  }
}
```

---

## 5. テスト計画

### 5.1 単体テスト

| テスト項目 | 内容 |
|-----------|------|
| 特徴量抽出 | 各特徴量が正しく抽出されるか |
| Auto-BENIGN | 条件に合致するケースが正しく判定されるか |
| Auto-PHISHING | 条件に合致するケースが正しく判定されるか |
| エッジケース | 証明書なし、SAN=0等の境界条件 |

### 5.2 統合テスト

| テスト項目 | 期待結果 |
|-----------|----------|
| Handoff削減率 | 20%以上削減 |
| FN率変化 | 悪化なし（3.01%以下維持） |
| FP率変化 | 大幅悪化なし |
| 処理時間 | 大幅増加なし |

### 5.3 A/Bテスト

既存パイプラインと新パイプラインを並行実行し、以下を比較:
- 判定一致率
- 性能指標（Precision, Recall, F1）
- Stage3送信件数

---

## 6. 実装スケジュール

| Phase | 内容 | 優先度 | ステータス |
|-------|------|--------|-----------|
| Phase 1 | Stage1特徴量追加（has_crl, has_wildcard, san_count） | 最高 | **既存実装済み** |
| Phase 2 | Stage2 Auto-BENIGN条件追加 | 高 | **2026-01-12 実装完了** |
| Phase 3 | Stage2 Auto-PHISHING条件追加 | 高 | **2026-01-12 実装完了** |
| Phase 4 | モデル再学習と評価 | 高 | 保留（現行で効果確認） |
| Phase 5 | 本番適用と監視 | 中 | 未着手 |

**備考**: Stage1特徴量（cert_has_crl_dp, cert_is_wildcard, cert_san_count等）は`features.py`に既に実装済みであったため、Stage2ルールの実装を優先した。

---

## 7. リスクと対策

| リスク | 影響 | 対策 |
|--------|------|------|
| FP増加 | 正規サイトの誤検知 | Auto-PHISHING条件を保守的に設定 |
| FN増加 | フィッシング見逃し | Auto-BENIGN条件に複合条件を使用 |
| 処理時間増加 | スループット低下 | 特徴量キャッシュ、遅延評価 |
| 設定ミス | 誤判定多発 | 設定値のバリデーション追加 |

---

## 8. 関連ドキュメント

- 分析レポート: `docs/analysis/certificate_analysis_report.md`
- 特徴量候補メモ: `docs/analysis/feature_candidates_memo.md`
- Stage2証明書ルール仕様: `docs/specs/stage2_certificate_rules_spec.md`
- 研究日誌: `docs/research/20260111.md`, `docs/research/20260112.md`

---

## 変更履歴

| 日付 | バージョン | 変更内容 |
|------|-----------|----------|
| 2026-01-12 | 1.0 | 初版作成 |
| 2026-01-12 | 1.1 | 実装ステータス更新 |
