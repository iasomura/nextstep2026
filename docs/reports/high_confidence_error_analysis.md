# 高確信度誤判定の詳細分析（6件）

作成日: 2026-02-08
目的: MTG 2025-12-25 アクションアイテムA2「高確信度誤判定の抽出と特徴分析」への対応
データ: `artifacts/2026-02-02_224105/results/stage1_decisions_latest.csv`（127,222件）

---

## 1. Auto-phishing FP（p₁ ≥ 0.957 かつ y=0）: 4件

正規サイトをフィッシングと高確信度で誤判定したケース。

### FP-1: `estyn.gov.wales`（p₁ = 0.9634, auto_phishing確定）

ウェールズ政府の教育監査機関（Estyn）の公式サイト。

| 特徴量 | 値 | 参考: 正規平均 | 参考: フィッシング平均 |
|--------|-----|-------------|-------------------|
| domain_length | 15 | 14.6 | 21.1 |
| dot_count | 2 | 1.1 | 2.1 |
| entropy | 3.507 | 3.276 | 3.616 |
| tld_length | **5** (.wales) | 2.7 | 2.9 |
| cert_validity_days | **89** | 153.3 | 95.5 |
| cert_is_lets_encrypt | **1** | 0.39 | 0.93 |
| cert_issuer_length | 27 | 41.7 | 29.0 |
| cert_has_crl_dp | 1 | 0.92 | 0.08 |
| cert_issuer_type | 1 (LE) | 1.6 | 1.1 |
| cert_san_count | 2 | 4.8 | 38.5 |

**誤判定の原因**: `.wales` TLDは訓練データに稀で、tld_length=5が異常値として作用。Let's Encrypt + 89日証明書 + dot_count=2の組み合わせがフィッシング方向に強く寄与。CRLありという正規シグナルでは補正しきれなかった。

**最終結果: auto_phishing として確定（後段で救済されず）**

---

### FP-2: `www.gov.scot`（p₁ = 0.9661, auto_phishing確定）

スコットランド政府の公式サイト。

| 特徴量 | 値 | 参考: 正規平均 | 参考: フィッシング平均 |
|--------|-----|-------------|-------------------|
| domain_length | 12 | 14.6 | 21.1 |
| dot_count | 2 | 1.1 | 2.1 |
| entropy | 2.855 | 3.276 | 3.616 |
| tld_length | **4** (.scot) | 2.7 | 2.9 |
| cert_validity_days | **394** | 153.3 | 95.5 |
| cert_is_lets_encrypt | 0 | 0.39 | 0.93 |
| cert_issuer_length | 36 | 41.7 | 29.0 |
| cert_has_crl_dp | 1 | 0.92 | 0.08 |
| cert_issuer_type | **0** (Amazon) | 1.6 | 1.1 |
| cert_san_count | 1 | 4.8 | 38.5 |
| cert_subject_has_org | **0** | - | - |

**誤判定の原因**: 最も不可解なケース。LEではなくAmazon CA、有効期間394日、CRLあり、SAN数1、低エントロピーと正規の特徴が多い。しかし `.scot` TLD（length=4、稀）+ dot_count=2 + cert_issuer_type=0（Amazon CAはフィッシングにも多い: 1,218件）+ cert_subject_has_org=0 の組み合わせでフィッシング判定に至った。

**最終結果: auto_phishing として確定（後段で救済されず）**

---

### FP-3: `lightsystemsoft.com.br`（p₁ = 0.95707, handoff→Stage3→FP確定）

ブラジルのソフトウェア企業。

| 特徴量 | 値 | 参考: 正規平均 | 参考: フィッシング平均 |
|--------|-----|-------------|-------------------|
| domain_length | 22 | 14.6 | 21.1 |
| dot_count | 2 | 1.1 | 2.1 |
| entropy | 3.754 | 3.276 | 3.616 |
| tld_length | 2 (br) | 2.7 | 2.9 |
| cert_validity_days | **89** | 153.3 | 95.5 |
| cert_is_lets_encrypt | **1** | 0.39 | 0.93 |
| cert_issuer_length | 27 | 41.7 | 29.0 |
| cert_has_crl_dp | **0** | 0.92 | 0.08 |
| cert_issuer_type | 1 (LE) | 1.6 | 1.1 |
| cert_san_count | **47** | 4.8 | 38.5 |
| max_consonant_length | 7 | 2.5 | 4.5 |

**誤判定の原因**: ほぼ全特徴量がフィッシング寄り。domain_length=22（フィッシング平均21.1に一致）、LE + 89日 + CRLなし + SAN数47（共有ホスティング証明書）。cert CNが `franquialightsystem.com.br` でドメインと不一致。正規の企業だが、証明書・ドメイン構造がフィッシングインフラと酷似。

**Stage3の処理**: p₁ = 0.95707 は t_high（0.95713）をわずかに下回り（差 6×10⁻⁵）、handoffとなった。Stage3のLLMは正しくbenign（safe_generic_content）と判定したが、very_high_ml_overrideルール（ML ≥ 0.85でLLMのbenign判定を上書き）が発動し、最終的にphishing判定。

**最終結果: FP確定（LLMの正しい判定がルールで上書き）**

---

### FP-4: `skatepro.com`（p₁ = 0.95710, handoff→Stage3→FP確定）

スポーツ用品のECサイト（デンマーク発）。

| 特徴量 | 値 | 参考: 正規平均 | 参考: フィッシング平均 |
|--------|-----|-------------|-------------------|
| domain_length | 12 | 14.6 | 21.1 |
| dot_count | 1 | 1.1 | 2.1 |
| entropy | 3.418 | 3.276 | 3.616 |
| tld_length | 3 (com) | 2.7 | 2.9 |
| cert_validity_days | **89** | 153.3 | 95.5 |
| cert_is_lets_encrypt | **1** | 0.39 | 0.93 |
| cert_issuer_length | 27 | 41.7 | 29.0 |
| cert_has_crl_dp | **0** | 0.92 | 0.08 |
| cert_issuer_type | 1 (LE) | 1.6 | 1.1 |
| cert_san_count | **31** | 4.8 | 38.5 |

**誤判定の原因**: cert CN が `skatepro.dk` でドメイン `skatepro.com` と不一致（多地域展開のEC）。LE + 89日 + CRLなし + SAN数31（複数地域ドメインをカバー）が強いフィッシングシグナル。ドメイン名自体は正常だが、証明書特徴が圧倒。

**Stage3の処理**: p₁ = 0.95710 は t_high（0.95713）をわずかに下回り（差 3×10⁻⁵）、handoffとなった。Stage3のLLMは正しくbenign（safe_generic_content）と判定したが、very_high_ml_overrideルール（ML ≥ 0.85でLLMのbenign判定を上書き）が発動し、最終的にphishing判定。

**最終結果: FP確定（LLMの正しい判定がルールで上書き）**

---

## 2. Auto-benign FN（p₁ ≤ 0.001 かつ y=1）: 2件

フィッシングサイトを正規と高確信度で誤判定したケース。

### FN-1: `mebelkomomsk.ru`（p₁ = 0.000577, auto_benign確定）

ロシアの家具店ドメインが乗っ取られたケース（PhishTank報告）。

| 特徴量 | 値 | 参考: 正規平均 | 参考: フィッシング平均 |
|--------|-----|-------------|-------------------|
| domain_length | 15 | 14.6 | 21.1 |
| dot_count | 1 | 1.1 | 2.1 |
| entropy | 3.190 | 3.276 | 3.616 |
| tld_length | 2 (ru) | 2.7 | 2.9 |
| cert_validity_days | **396** | 153.3 | 95.5 |
| cert_is_lets_encrypt | **0** | 0.39 | 0.93 |
| cert_issuer_length | **61** | 41.7 | 29.0 |
| cert_has_crl_dp | **1** | 0.92 | 0.08 |
| cert_issuer_type | **4** (Commercial CA) | 1.6 | 1.1 |
| cert_san_count | 2 | 4.8 | 38.5 |
| cert_issuer_org | GlobalSign nv-sa | - | - |
| cert_key_size | 4096 | - | - |

**誤判定の原因**: 正規サイトの乗っ取り（compromised site）。元の家具店が取得したGlobalSign商用証明書（396日有効, CRLあり, RSA 4096bit）がそのまま残存しているため、全証明書特徴量が強く正規方向を示す。ドメイン名も「mebel（家具）+ Omsk（都市名）」で自然。証明書・ドメイン特徴量だけでは検出不可能な攻撃パターン。

**最終結果: auto_benign として確定（Stage2/3に到達せず）**

---

### FN-2: `fb.st`（p₁ = 0.000463, auto_benign確定）

Facebook偽装のフィッシングドメイン（JPCERT報告）。

| 特徴量 | 値 | 参考: 正規平均 | 参考: フィッシング平均 |
|--------|-----|-------------|-------------------|
| domain_length | **5** | 14.6 | 21.1 |
| dot_count | 1 | 1.1 | 2.1 |
| entropy | **2.322** | 3.276 | 3.616 |
| tld_length | 2 (st) | 2.7 | 2.9 |
| cert_validity_days | **396** | 153.3 | 95.5 |
| cert_is_lets_encrypt | **0** | 0.39 | 0.93 |
| cert_issuer_length | **104** | 41.7 | 29.0 |
| cert_has_crl_dp | 0 | 0.92 | 0.08 |
| cert_issuer_type | **4** (Commercial CA) | 1.6 | 1.1 |
| cert_san_count | 4 | 4.8 | 38.5 |
| cert_issuer_org | Sectigo Limited | - | - |
| cert_common_name | 24sevensocial.com | - | - |

**誤判定の原因**: 正規SaaS基盤（24sevensocial.com = ソーシャルメディア管理サービス）の悪用。Sectigo商用証明書（396日有効）、issuer_length=104と長い正規発行者名。ドメイン長5文字・エントロピー2.32は「正規ドメインの平均よりも正規に見える」極端な値。`contains_brand=0`（"fb"が短すぎてブランド検出に引っかからない）。正規インフラ + 超短ドメインの組み合わせで、モデルにとって検出不可能。

**最終結果: auto_benign として確定（Stage2/3に到達せず）**

---

## 3. 根本原因の分類

| 根本原因 | 件数 | 方向 | 最終判定 |
|---------|------|------|---------|
| 稀な地理TLD（.wales, .scot）の訓練データ不足 | 2 | FP | auto_phishing確定 |
| LE + 共有ホスティング証明書が正規サイトにも使用 | 2 | FP | handoff→Stage3→FP確定（LLMは正解、ルールが上書き） |
| 正規サイト乗っ取り（商用CA証明書がそのまま残存） | 1 | FN | auto_benign確定 |
| 正規SaaS基盤の悪用 + 超短ブランド偽装ドメイン | 1 | FN | auto_benign確定 |

## 4. 考察

### 6件すべてがシステム全体でも誤判定のまま確定

6件すべてが最終的に誤判定として確定している。

- **FP-1, FP-2（政府サイト）**: auto_phishingとして確定。稀なTLDに対する訓練データの追加、またはTLD長に対する特別な処理で改善の余地あり
- **FP-3, FP-4（LE + 共有ホスティング）**: t_highをわずかに下回りhandoffとなったが、Stage3のvery_high_ml_overrideルール（ML ≥ 0.85）がLLMの正しいbenign判定を上書きしてFPとなった
- **FN-1, FN-2（正規インフラ悪用）**: auto_benignとして確定。証明書・ドメイン特徴量のみでは原理的に検出困難

### FP-3, FP-4 における LLM vs ルールの衝突

FP-3とFP-4では、Stage3のLLMが正しくbenign（safe_generic_content）と判定していたにもかかわらず、very_high_ml_overrideルールがML確信度を優先してphishingに上書きした。このルールは「ML確信度が高い場合にLLMのbenign判定を信用しない」という安全策だが、Stage1のMLスコア自体が誤っている場合には裏目に出る。

p₁の精密値（0.95707, 0.95710）はt_high（0.95713）をわずか3〜6×10⁻⁵だけ下回っており、閾値のごくわずかな変動でauto_phishing（Stage1確定）にもhandoff（Stage3処理）にもなりうる境界ケースである。

### 閾値設計の評価

127,222件中6件（0.005%）という高確信度誤判定率は、閾値（t_high=0.957, t_low=0.001）が十分に保守的に設定されていることを示す。ただし、6件すべてがシステム全体でも救済されない誤りであり、運用上のリスクとして認識が必要。
