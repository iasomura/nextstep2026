# Stage3 AI Agent 改善効果分析

## 目的

Qwen3-4B AI Agent の検出性能を向上させ、CSS2025論文のベンチマーク（FN 639件）に近づける。

## 目標

| 指標 | ベースライン | 目標 | CSS2025参考 |
|------|-------------|------|------------|
| F1 Score | 0.6426 | 0.78-0.81 | - |
| FN | 899 | ~540 (40%削減) | 639 |
| FP | 172 | 維持または微増 | - |

## 改善項目（計画書より）

| # | 改善内容 | 期待効果 | 実装状態 |
|---|---------|---------|---------|
| 1 | KNOWN_DOMAINS拡張 (Tranco Top 100K) | FP削減 | 完了 |
| 2 | CRITICAL_BRAND_KEYWORDS追加 | FN削減 | 完了 |
| 3 | 多言語ソーシャルエンジニアリング検出 | FN削減 | 完了 |
| 4 | ランダム文字列検出強化 | FN削減 | 完了 |
| 5 | 危険TLD重み強化 | FN削減 | 完了 |
| 6 | ブランド検出→phishing判定強化 | FN削減 | 完了 |

---

## 評価結果（2026-01-28）

### 中間結果（11.5%完了時点で停止）

| 指標 | ベースライン | 改善後 | 変化 |
|------|-------------|-------|------|
| F1 Score | 0.6426 | 0.6478 | +0.52pp |
| FN (予測) | 899 | ~896 | **-3 (0.3%減)** |
| FP (予測) | 172 | ~1,165 | **+993 (577%増)** |

**結論**: 改善は失敗。FN削減効果がほぼゼロで、FPが7倍に増加。

---

## 詳細分析

### 1. FP分析（137件）

#### 1.1 short_domain_analysisによる検出理由

| 検出理由 | 件数 | 割合 | 問題点 |
|---------|------|------|--------|
| short | 60 | 43.8% | 短い正規ドメイン（略語等） |
| random_pattern | 55 | 40.1% | 母音<0.2で略語を誤検出 |
| dangerous_tld | 35 | 25.5% | 正規サイトも危険TLDに存在 |
| **NO_ISSUES** | 31 | 22.6% | **ツール0点でもLLMがphishing判定** |
| rare_bigram_random | 16 | 11.7% | 略語が誤検出 |
| consonant_cluster_random | 11 | 8.0% | 複合語を誤検出 |

#### 1.2 FP原因の分類

| 原因カテゴリ | 件数 | 割合 |
|------------|------|------|
| ランダム検出のみ | 72 | 52.6% |
| LLM判断ミス（ツール0点） | 31 | 22.6% |
| 危険TLD + ランダム | 22 | 16.1% |
| 危険TLDのみ | 11 | 8.0% |

#### 1.3 FPサンプル

**random_pattern誤検出**:
- `frmtr.com` - 略語
- `fncdg.com` - 略語
- `wfqqmy.com` - 略語

**consonant_cluster誤検出**:
- `cheapflights.com` - 正規の旅行サイト
- `upgrade2sdnbhd.com` - マレーシア企業（Sdn Bhd）

**LLM判断ミス（ツール0点）**:
- `pixelfed.de` - 連合型SNS
- `doublefine.com` - ゲーム会社
- `twincities.com` - ニュースサイト

---

### 2. FN分析（106件）

#### 2.1 概要

| 指標 | 値 |
|-----|-----|
| FN数 | 106 |
| FN率 | 5.6% |
| 主要TLD | .com (64%), .br (7%), .cn (4%) |
| AI Confidence分布 | 0.7-0.9が86% |

**特徴**: LLMが高い確信度（0.7-0.9）で「benign」と判定しているが、実際はphishing。

#### 2.2 検出シグナル別内訳

| 検出シグナル | 件数 | 割合 |
|-------------|------|------|
| **NO_ISSUES（シグナルなし）** | 81 | **76.4%** |
| short | 16 | 15.1% |
| dangerous_tld | 9 | 8.5% |
| random_pattern | 4 | 3.8% |
| その他 | 5 | 4.7% |

**重要な発見**: FNの76%はshort_domain_analysisで**何もシグナルが検出されない**。
改善項目（ランダム検出、危険TLD等）はこれらに効かない。

#### 2.3 NO_ISSUES FN の特徴

| 特徴 | 値 |
|-----|-----|
| ブランド検出 | 0% |
| 母音比率 | 0.25-0.50（正常範囲） |
| ドメイン長 | 7-22文字（正常範囲） |
| 外見 | 企業名・サービス名に見える |

**サンプル（目視で「正規サイト」に見える）**:
- `therapyaoyama.com` - セラピー施設?
- `rsacouriers.com` - 宅配会社?
- `capitalprowealthonline.com` - 資産運用サービス?
- `gregphillipslaw.com` - 法律事務所?
- `tile-machine.com` - 機械メーカー?

#### 2.4 データソース別FN分布

| ソース | FN件数 | 割合 |
|--------|--------|------|
| jpcert | 52 | 49% |
| phishtank | 36 | 34% |
| certificates | 18 | 17% |

#### 2.5 ML + 証明書の組み合わせ分析

**ML Probability分布**:

| カテゴリ | ML Prob (mean) | ML Prob (median) | 意味 |
|---------|----------------|------------------|------|
| FP | 0.274 | 0.141 | MLは低リスク → AIが誤判定 |
| **FN** | **0.201** | **0.132** | **MLもAIも見逃し** |
| TP | 0.700 | 0.823 | MLもAIも検出 |
| TN | 0.082 | 0.048 | MLもAIも正解 |

**証明書特徴**:

| カテゴリ | 証明書年齢 | Free CA | SAN Count |
|---------|-----------|---------|-----------|
| FP | 283日 | 70% | 4.3 |
| FN | 378日 | 90% | 4.1 |
| TP | 511日 | 87% | 11.4 |
| TN | 263日 | 81% | 3.8 |

**FNサンプル（ML+証明書）**:
```
domain                              ML     age   SAN  free
contcomexcontabilidade.com.br       0.04   242d  2    No
therapyaoyama.com                   0.03   244d  2    Yes
rsacouriers.com                     0.04   231d  2    Yes
```

**結論**: FNは「MLスコアが低く、証明書も正常」なフィッシング。
ドメイン名・証明書の表面的な特徴からは検出困難。

---

### 3. 改善項目別の効果分析

各改善項目がFP/FN/TP/TNにどう影響したかを個別分析。

#### 3.1 改善項目別のFP/TP内訳

| # | 改善項目 | FP | TP | FP率 | TP率 | Precision | 判定 |
|---|---------|-----|-----|------|------|-----------|------|
| 3 | **低母音比率 (random_pattern)** | **55** | 35 | 40.1% | 15.0% | **39%** | **主犯** |
| 5 | 短ドメイン検出 | 60 | 78 | 43.8% | 33.3% | 57% | 微妙 |
| 4 | 危険TLD重み付け | 35 | 106 | 25.5% | 45.3% | 75% | 効果あり |
| 2 | レアバイグラム検出 | 16 | 19 | 11.7% | 8.1% | 54% | 微妙 |
| 1 | 子音クラスター検出 | 11 | 23 | 8.0% | 9.8% | 68% | 効果あり |
| 6 | 数字混在ランダム | 6 | 5 | 4.4% | 2.1% | 45% | 悪影響 |
| 7 | 母音なし+危険TLD | 4 | 3 | 2.9% | 1.3% | 43% | 悪影響 |

**Precision = TP / (TP + FP)**：シグナルが検出された時、実際にフィッシングである確率

#### 3.2 改善項目の評価

**【悪影響】ロールバック推奨**:
- **3. 低母音比率 (random_pattern)**: Precision 39%、FP 55件（最大の問題）
- 6. 数字混在ランダム: Precision 45%、効果薄い
- 7. 母音なし+危険TLD: Precision 43%、効果薄い

**【微妙】調整が必要**:
- 5. 短ドメイン検出: FP 60件と多いが、TP 78件もある
- 2. レアバイグラム検出: Precision 54%、改善の余地あり

**【効果あり】維持推奨**:
- 4. 危険TLD重み付け: Precision 75%、TP 106件で検出貢献大
- 1. 子音クラスター検出: Precision 68%、バランス良い

#### 3.3 FN側の分析

各シグナルがFNにどれだけ該当するか（検出できれば防げた可能性）:

| # | 改善項目 | FN該当 | FN率 | 評価 |
|---|---------|--------|------|------|
| 5 | 短ドメイン検出 | 16 | 15.1% | FN削減に貢献可能 |
| 4 | 危険TLD重み付け | 9 | 8.5% | FN削減に貢献可能 |
| 3 | 低母音比率 | 4 | 3.8% | FN削減効果小 |
| 1 | 子音クラスター検出 | 1 | 0.9% | FN削減効果なし |
| 2 | レアバイグラム検出 | 1 | 0.9% | FN削減効果なし |
| 6 | 数字混在ランダム | 0 | 0.0% | FN削減効果なし |
| 7 | 母音なし+危険TLD | 0 | 0.0% | FN削減効果なし |

**結論**: FNの76%はどのシグナルにも該当しない。
改善項目はFN削減にほとんど寄与していない。

---

### 4. 分析結論

#### 4.1 改善が効かなかった理由

```
【FPが増加した理由】
  改善項目 → 「ランダム文字列」「危険TLD」を検出
           → 正規サイト（略語、ccTLD）にも該当
           → FP大量発生

【FNが減らなかった理由】
  改善項目 → 「ランダム文字列」「危険TLD」を検出
           → フィッシングサイトの76%はこれらに該当しない
           → FN削減効果なし
```

#### 3.2 根本的な問題

| 改善項目 | FP影響 | FN影響 | 結論 |
|---------|--------|--------|------|
| ランダム検出 | 52%のFPに関与 | 4%のFNのみ | **逆効果** |
| 危険TLD | 24%のFPに関与 | 8.5%のFNのみ | **逆効果** |
| ブランド検出 | - | 0%（FNに効果なし） | **効果なし** |

**「ランダム文字列」「危険TLD」は、フィッシングと正規サイトを区別する識別能力が低い。**

---

## 現在地

```
目標: FN 899 → 540 (40%削減)、FP 172 維持
現在: FN 896 (0.3%減)、FP 1165 (7倍増) ← 評価停止

分析完了: FP分析 ✓、FN分析 ✓
結論: 改善アプローチが根本的に間違っていた
```

---

## 実施済み: 部分的ロールバック

### ロールバック内容 (2026-01-28)

#### 1. ツール側 (short_domain_analysis.py)

以下の検出ロジックを無効化:

| 項目 | Precision | FP | 対応 |
|-----|-----------|-----|------|
| **random_pattern（低母音比率）** | 39% | 55 | **無効化** |
| digit_mixed_random | 45% | 6 | **無効化** |
| no_vowel_dangerous_tld | 43% | 4 | **無効化** |

#### 2. ルールエンジン側 (settings.py)

| ルール | 対応 | 理由 |
|-------|------|------|
| random_pattern_minimum | **無効化** | random_pattern無効化に連動 |
| random_crl_override | 無効化済み | 以前のFP分析で無効化 |

### 維持した検出ロジック

| 項目 | Precision | TP | 理由 |
|-----|-----------|-----|------|
| dangerous_tld | 75% | 106 | 効果大 |
| consonant_cluster_random | 68% | 23 | バランス良 |
| rare_bigram_random | 54% | 19 | 維持（様子見）|
| high_entropy | - | - | 既存ロジック |

### 期待効果

- **FP削減**: random_pattern 55件 + digit_mixed 6件 + no_vowel 4件 = **65件減少予想**
- **FN影響**: random_pattern が検出したTP 35件が減少する可能性あり

---

## ロールバック後の再評価（2026-01-28 14:19〜）

### 中間結果（9%完了時点）

| 指標 | ベースライン | ロールバック前 | ロールバック後 |
|------|-------------|--------------|---------------|
| FP予測 | 172 | 1165 (7倍) | 850 (5倍) |
| FN予測 | 899 | 896 | 950 |

**評価**: ロールバックでFPは改善したが、まだベースラインより高い。

---

## 追加FP分析（ブランド検出）

### 5.1 FP by ML Probability

| ML範囲 | FP件数 | 割合 | 問題 |
|-------|--------|------|------|
| 0-0.2 | 53 | 48% | **低MLなのにPhishing判定** |
| 0.2-0.4 | 17 | 15% | |
| 0.4-0.6 | 12 | 11% | |
| 0.6-0.8 | 21 | 19% | |
| 0.8-1.0 | 8 | 7% | ML高 = ML誤判定? |

**54%のFPがML < 0.3** → AI Agentが低MLを過度にオーバーライド

### 5.2 FP by TLD Category

| TLDカテゴリ | FP件数 | 割合 |
|------------|--------|------|
| **Legitimate (.com等)** | 60 | 55% |
| Dangerous | 40 | 37% |
| Other | 9 | 8% |

**55%のFPが正規TLD** → ブランド検出が主原因の可能性

### 5.3 ブランド誤検出パターン

`brand_impersonation_check`によるFP:

| FPドメイン | 検出ブランド | マッチタイプ | 問題点 |
|-----------|-------------|-------------|--------|
| hermesonlineshop.com | `hermes` | compound | 高級ブランド |
| swifterm.com | `swift` | substring | SWIFTバンキング（正規ターミナルソフト） |
| metaflow.org | `meta` | substring | Meta/Facebook（Netflix製MLフレームワーク） |
| educationalappstore.com | `appstore` | compound | Apple |
| twincities.com | `citi` | substring | Citibank（米国ニュースサイト） |
| changing-cities.org | `citi` | substring | "cities"内の"citi" |

### 5.4 問題の根本原因

| ブランド | 問題 | 誤マッチ例 |
|---------|------|-----------|
| `citi` | 一般英単語`cities`にマッチ | twincities, changing-cities |
| `swift` | 正規ソフト名にマッチ | swifterm |
| `meta` | 正規フレームワーク名にマッチ | metaflow |
| `hermes` | compound検出が緩い | hermesonlineshop |
| `appstore` | compound検出が緩い | educationalappstore |

### 5.5 対策

**BOUNDARY_REQUIRED_BRANDS に追加**:
- `citi` → `cities`等の一般単語を除外
- `swift` → `swifterm`等を除外
- `meta` → `metaflow`等を除外

**BRAND_FP_EXCLUSION_WORDS に追加**:
- `cities`, `twincities`
- `swifterm`, `swiftui`, `swiftly`
- `metaflow`, `metadata`, `metamask`（ただしmetamaskは本当のブランドなので注意）

---

## 実施済み: ブランド検出FP対策（2026-01-28）

### 変更内容

`brand_impersonation_check.py` を更新:

**BOUNDARY_REQUIRED_BRANDS に追加**:
- `citi` - "cities"への誤マッチ防止
- `swift` - "swifterm"への誤マッチ防止
- `meta` - "metaflow"への誤マッチ防止
- `hermes` - "hermesonlineshop"への誤マッチ防止
- `appstore` - "educationalappstore"への誤マッチ防止

**BRAND_FP_EXCLUSION_WORDS に追加**:
- citi系: cities, twincities, changingcities, etc.
- swift系: swifterm, swiftly, swiftui, etc.
- meta系: metaflow, metadata, metalprotection, etc.
- hermes系: hermesonlineshop, hermesdelivery, etc.
- appstore系: educationalappstore, etc.

### テスト結果

| FPドメイン | 修正前 | 修正後 |
|-----------|--------|--------|
| swifterm.com | swift検出 | ✓ Fixed |
| metaflow.org | meta検出 | ✓ Fixed |
| twincities.com | citi検出 | ✓ Fixed |
| changing-cities.org | citi検出 | ✓ Fixed |
| asmetalwork.com.ua | meta検出 | ✓ Fixed |
| metalprotection.com.ua | meta検出 | ✓ Fixed |
| hermesonlineshop.com | hermes検出 | ✓ Fixed |
| educationalappstore.com | appstore検出 | ✓ Fixed |

**8/8 FPドメイン修正完了**

---

## 6. トレースフィールド追加（2026-01-28 19:30）

### 背景

FP/FN の原因調査に必要な情報が評価結果に保存されていなかった。AI Agentの説明可能性（Explainability）を確保するため、トレースフィールドを追加。

### 変更内容

**scripts/parallel/worker.py** を修正:

#### 追加されたフィールド（20項目）

| カテゴリ | フィールド | 用途 |
|---------|-----------|------|
| 判定理由 | ai_reasoning | LLMの判定理由（50文字以上） |
| | ai_risk_factors | 検出リスク要因（JSON） |
| | ai_detected_brands | 検出ブランド（JSON） |
| Precheck | trace_precheck_ml_category | ML確率カテゴリ |
| | trace_precheck_tld_category | TLDカテゴリ |
| | trace_precheck_brand_detected | ブランド検出フラグ |
| | trace_precheck_high_risk_hits | 高リスクキーワードヒット数 |
| | trace_precheck_quick_risk | クイックリスクスコア |
| ツール | trace_selected_tools | 選択ツール（JSON） |
| | trace_brand_risk_score | ブランドスコア |
| | trace_cert_risk_score | 証明書スコア |
| | trace_domain_risk_score | ドメインスコア |
| | trace_ctx_risk_score | コンテキストスコア |
| | trace_ctx_issues | コンテキスト問題（JSON） |
| ポリシー | trace_phase6_rules_fired | 発火ルール（JSON） |
| デバッグ | graph_state_slim_json | 完全グラフ状態 |
| ツール出力 | tool_brand_output | brand_impersonation_check全出力 |
| | tool_cert_output | certificate_analysis全出力 |
| | tool_domain_output | short_domain_analysis全出力 |
| | tool_ctx_output | contextual_risk_assessment全出力 |

### 活用方法

```python
# FP原因分析の例
import pandas as pd
import json

df = pd.read_csv("worker_0_results.csv")
fp = df[(df['ai_is_phishing'] == True) & (df['y_true'] == 0)]

for _, row in fp.iterrows():
    print(f"Domain: {row['domain']}")
    print(f"  Reasoning: {row['ai_reasoning']}")
    print(f"  Risk factors: {row['ai_risk_factors']}")
    print(f"  Ctx score: {row['trace_ctx_risk_score']}")
```

### 仕様書更新

`docs/specs/parallel_evaluation_spec.md` v1.1 に詳細を記載。

---

---

## 7. トレースデータによる詳細分析（2026-01-28 22:00）

新たに追加したトレースフィールドを使用して、FP/FNの根本原因を詳細分析。

### 7.1 ツール別リスクスコア分析

| ツール | TP平均 | TN平均 | FP平均 | FN平均 | 識別力 |
|--------|--------|--------|--------|--------|--------|
| **ctx** | 0.514 | 0.129 | 0.467 | 0.262 | **最高** |
| cert | 0.449 | 0.372 | 0.434 | 0.417 | 低い |
| brand | 0.047 | 0.000 | 0.086 | **0.000** | FNで機能せず |
| domain | 0.047 | 0.035 | 0.161 | 0.038 | 低い |

**重要発見**:
- `ctx` (contextual_risk_assessment) が最も判定に寄与
- **brand がFNで完全に機能していない** (平均0.0)

### 7.2 Policy発火パターン分析

#### TPで効いているPolicy（正しい検出）

| Policy | 発火率 | 役割 |
|--------|--------|------|
| ml_ge_0.50_no_mitigation | 74% | ML高スコアをそのまま判定 |
| brand_cert_high | 12% | ブランド+証明書の組み合わせ |
| ctx_ge_0.50_with_strong_evidence | 10% | ctx高+強証拠 |

#### FPを引き起こしているPolicy（誤検出）

| Policy | 発火率 | 問題点 |
|--------|--------|--------|
| **POST_LLM_FLIP_GATE_BYPASS** | **30%** | LLM判定を覆すゲートが機能せず |
| ctx_ge_0.50_with_strong_evidence | 25% | ctx高いが実は正規サイト |
| brand_cert_high | 21% | fuzzy matchの誤検出が原因 |

#### FNを引き起こしているPolicy（見逃し）

| Policy | 発火率 | 問題点 |
|--------|--------|--------|
| **LOW_ML_GUARD** | **55%** | ML低いと反転を過度に抑制 |
| POST_LLM_FLIP_GATE | 8% | 正当な反転もブロック |

### 7.3 ctx_issues パターン分析

| Issue | TP% | FP% | FN% | 解釈 |
|-------|-----|-----|-----|------|
| old_cert_phishing | 62% | 3% | 19% | TPで有効、FNでは検出されてない |
| **ml_paradox** | 8% | **45%** | 7% | **FPの主因** |
| dangerous_tld_combo | 13% | 19% | 3% | FPで過検出気味 |
| **critical_brand_minimum** | 6% | **18%** | 0% | **FPの要因** |

### 7.4 根本原因の定量分析

#### FP根本原因（125件）

| 原因 | 件数 | 割合 | 既存レポートとの関連 |
|------|------|------|---------------------|
| ML低いのにctx/policy発火 | 64 | 51% | **新発見**: ml_paradox が主因 |
| 危険TLD + ctx高い | 50 | 40% | 既知 |
| ML高いのでそのまま判定 | 42 | 34% | 既知 |
| brand fuzzy誤検出 | 26 | 21% | 既知（citi, swift等） |

#### FN根本原因（158件）

| 原因 | 件数 | 割合 | 既存レポートとの関連 |
|------|------|------|---------------------|
| **brand未検出 (risk=0)** | 154 | **98%** | **新発見**: 最大の問題 |
| .com TLD (安全扱い) | 106 | 67% | 既知だが定量化は新規 |
| ctx低い (<0.3) | 90 | 57% | 新発見 |
| LOW_ML_GUARD発動 | 87 | 55% | **新発見**: Policy原因を特定 |

### 7.5 具体的なブランドキーワード不足

FNドメインを分析した結果、以下のブランドがキーワード未登録:

| ドメイン | 含まれるブランド | 状態 |
|---------|-----------------|------|
| aupayfirmisco.shop | au PAY | **未登録** |
| vanillagift.remadet.com | Vanilla Gift Card | **未登録** |

**brand_keywords.json** (461キーワード) を確認:
- `aupay`: 未登録（`au` のみ登録）
- `vanillagift`, `vanilla`: 未登録

### 7.6 fuzzy match誤検出の詳細

| FPドメイン | 誤マッチ先 | 編集距離 | 問題 |
|-----------|-----------|---------|------|
| yourule.top | youtube | 2 | 短いブランド名で過敏 |
| costa-rica-guide.com | costco | 2 | 一般語と類似 |

**既存対策** (BOUNDARY_REQUIRED_BRANDS) では防げていないケース。

### 7.7 LLM判定パス分析

| パス | FP | FN | 解釈 |
|------|-----|-----|------|
| llm | 121 | 143 | 大半がLLM判定を通過 |
| so_fallback | 4 | 11 | SO解析失敗は少数 |

**結論**: LLM自体は正常動作。問題はPolicy/ctx_issuesの閾値設定。

### 7.8 新発見のまとめ

既存レポートにない重要な発見:

1. **brand検出がFNの最大原因 (98%)** - キーワード不足が根本原因
2. **LOW_ML_GUARDがFNの55%に関与** - 過度に保守的
3. **ml_paradoxがFPの45%に関与** - ML低いのに他シグナルで誤判定
4. **ctx がTPとTNで最も識別力が高い** - 0.514 vs 0.129
5. **.com TLDがFNの67%** - 安全扱いの罠

### 7.9 改善提案（優先度順）※旧版

> **注記**: この提案は中間分析時点のもの。最新の優先順位は「**14. やることリスト**」を参照。

| # | 改善内容 | 期待効果 | 対象エラー | 状態 |
|---|---------|---------|-----------|------|
| 1 | ブランドキーワード追加 | FN -10〜20件 | FN 98% | ✅ 実施済 |
| 2 | LOW_ML_GUARD 閾値調整 | FN -30〜50件 | FN 55% | 保留 |
| 3 | ml_paradox 条件厳格化 | **FP -122件, F1 +1.31pp** | FP 50% | **次に実施推奨** |
| 4 | fuzzy match 条件厳格化 | FP -10件 | FP 21% | ✅ 実施済 |

---

## 現在地

```
目標: F1 0.78-0.81、FN 540件 (40%削減)、FP 維持
ベースライン: F1 0.6426、FN 899件、FP 172件

★★★ 最新評価結果 (2,601件サンプル, 2026-01-29 19:30) ★★★
  F1:        0.689
  Precision: 0.696
  Recall:    0.682
  TP: 307, FP: 134, TN: 2017, FN: 143

  FP内訳 (134件):
    - ブランドなし + typical_phishing_cert_pattern: 58件 (最大要因)
    - ブランドなし + ml_paradox: 38件
    - fuzzy2マッチ誤検出: 20件
    - compound/substringマッチ: 15件
    - その他: 3件

  FN内訳 (143件):
    - ブランド検出なし + ML低確率: 103件 (72%)
    - MLモデル自体が検出失敗
    - 検出可能なtyposquatting: 数件のみ

前回評価結果 (3,000件サンプル, 2026-01-29 14:00):
  F1:        0.709 (+2.9pp)
  Precision: 0.732 (+3.2pp)
  Recall:    0.687 (+2.6pp)

分析状態:
  ✓ ベースライン分析完了
  ✓ 改善効果分析完了
  ✓ ロールバック実施済み
  ✓ ブランドFP対策実施済み
  ✓ トレースフィールド追加済み
  ✓ トレースデータによる詳細分析完了
  ✓ FP/FN原因の定量分析完了
  ✓ typical_phishing_cert_pattern 削除実施
  ✓ steam/roblox/eshop 除外パターン追加
  ✓ 2601件サンプルで詳細分析完了 ← NEW
```

---

## 8. 検討事項リスト（評価完了後に判断）

### 8.1 FP対策（要検証）

| # | 改善案 | 期待効果 | 副作用リスク | 判断基準 |
|---|--------|---------|-------------|---------|
| 1 | fuzzy match 特定パターン除外 | FP -9件 | 低 (TPへの影響なし) | Precision < 50%なら実施 |
| 2 | .com TLD で ml_paradox 軽減 | FP -24件 | 中 (FN増加リスク) | .comのFN/FP比率で判断 |
| 3 | ピンイン検出追加 (母音0%許容) | FP -28件 | 中 (実装複雑) | 中国語ドメインのFP率で判断 |
| 4 | 危険TLD + ML < 0.1 の保守的判定 | FP -10件 | 中 (FN増加リスク) | 危険TLDのTP/FP比率で判断 |

### 8.2 fuzzy match 分析結果

**現状** (Precision: 34.6%):
- TP: 9件 (telegram, whatsapp, rakuten等のタイポ検出)
- FP: 17件 (costco, hermes, sbinet等の誤マッチ)

**除外候補パターン** (`BRAND_FP_EXCLUSION_WORDS` に追加):

| 誤マッチ元 | 誤マッチ先 | 件数 | 除外ワード候補 |
|-----------|-----------|------|---------------|
| costa, custo | costco | 2 | costa, costarica, custo |
| hi-res, lozano-hemmer | hermes | 2 | hires, highres, lozanohemmer |
| rinet, biznet, seo | sbinet | 3 | rinet, biznet |
| lacoste | laposte | 1 | lacoste |
| yourule | youtube | 1 | yourule |

**判断**: 評価完了後、fuzzy matchのPrecisionが50%未満なら特定パターン除外を実施。

### 8.3 typical_phishing_cert_pattern 分析結果 (2026-01-29)

**現状**: Precision **39.4%** (非常に低い)

| 項目 | 値 | 評価 |
|-----|-----|------|
| 検出数 | 3,815件 (24.3%) | 多すぎる |
| TP | 1,504件 | フィッシング正検出 |
| FP | 2,311件 | **正規サイト誤検出** |
| Precision | 39.4% | **低すぎて使用不可** |

**問題点**:
- パターン条件（free_ca + no_org + valid_days <= 90）が広すぎる
- Let's Encrypt利用の正規サイトも多数該当
- `_strong_cert` に追加したが、強い証拠として使うには不適切

**対応**: ✅ **実施済み (2026-01-29 11:30)**
- `_strong_cert` から `typical_phishing_cert_pattern` を削除
- パターン検出自体は残すが、strong_evidenceとしては使わない

### 8.4 トレース詳細分析結果 (2026-01-29)

#### FP原因分析 (747件)

| 発見# | 原因 | 件数 | 割合 | 対策 | 状態 |
|-------|------|------|------|------|------|
| 1 | ml_paradox | 403件 | 53.9% | 条件厳格化 | 未実施 |
| 2 | typical_phishing_cert_pattern | 366件 | 49.0% | _strong_cert削除 | ✅実施済 |
| 3 | POST_LLM_FLIP_GATE_BYPASS | 301件 | 40.3% | 発見1,2の結果 | - |
| 4 | critical_brand_minimum | 214件 | 28.6% | fuzzy match除外 | 未実施 |

#### FN原因分析 (942件)

| 発見# | 原因 | 件数 | 割合 | 対策 | 状態 |
|-------|------|------|------|------|------|
| 6 | LOW_ML_GUARD | 564件 | 59.9% | 閾値調整(0.25→0.15) | 未実施 |
| 7 | brand_risk_score = 0 | 928件 | 98.5% | キーワード追加 | 未実施 |
| 8 | ctx_risk_score < 0.3 | 554件 | 58.8% | 発見6,7の結果 | - |

### 8.5 実装済み改善

| # | 改善内容 | 実装日 | 効果検証 |
|---|---------|--------|---------|
| 1 | typical_phishing_cert_pattern 検出追加 | 2026-01-28 | 問題あり→修正済 |
| 2 | _strong_cert から typical_phishing_cert_pattern 削除 | 2026-01-29 | ✅ **F1 +2.9pp** |

### 8.6 3000件サンプル評価結果 (2026-01-29 14:00)

| 指標 | 今回 | 前回 | 変化 |
|------|------|------|------|
| F1 | 0.709 | 0.680 | **+2.9pp** |
| Precision | 0.732 | 0.706 | **+3.2pp** |
| Recall | 0.687 | 0.661 | **+2.6pp** |
| FP (15,668換算) | 741 | 747 | -6 |
| FN (15,668換算) | 924 | 942 | -18 |

**修正効果**:
- R1ルール発火数: 0 (typical_phishing_cert_pattern削除により期待通り)
- FP/FN共に減少、F1スコアが全体的に改善

---

## 10. 詳細分析結果（2026-01-30 全件評価後）

### 10.1 評価結果サマリー

#### 3,000件サンプル評価（ml_paradox TLD修正前: 2026-01-29）

| 指標 | 値 |
|------|-----|
| 総ドメイン数 | 3,000件 |
| **Precision** | 0.7321 |
| **Recall** | 0.6867 |
| **F1 Score** | 0.7087 |
| **FPR** | 5.83% (142件) |
| **FNR** | 31.33% (177件) |

**混同行列**:
```
              Predicted
            Benign  Phishing
Actual  Benign   2293    142 (FP)
       Phishing  177(FN) 388 (TP)
```

#### 全件評価（ml_paradox TLD修正前: 2026-01-29 23:49 〜 2026-01-30 16:46 完了）

| 指標 | 値 |
|------|-----|
| 総ドメイン数 | 13,426件 |
| 有効ドメイン数 | 13,219件 |
| エラー数 | 207件 |
| **Precision** | 0.7090 |
| **Recall** | 0.6640 |
| **F1 Score** | 0.6858 |
| **FP** | 624件 |
| **FN** | 769件 |

**混同行列**:
```
              Predicted
            Benign  Phishing
Actual  Benign  10306    624 (FP)
       Phishing  769(FN) 1520 (TP)
```

**ソース別内訳**:

| ソース | 件数 | TP | FP | FN | TN | Recall |
|--------|------|----|----|----|----|--------|
| trusted | 10,930 | 0 | 624 | 0 | 10,306 | - |
| certificates | 637 | 510 | 0 | 127 | 0 | 80.1% |
| jpcert | 1,036 | 664 | 0 | 372 | 0 | 64.1% |
| phishtank | 616 | 346 | 0 | 270 | 0 | 56.2% |

**注**: この評価はml_paradox TLD修正**前**のコードで実行。修正後の評価は別途必要。

---

### 10.2 全件評価 FP詳細分析（624件）

#### TLD分布

| TLD | 件数 | 割合 |
|-----|------|------|
| .com | 264 | 42.3% |
| .org | 34 | 5.4% |
| .xyz | 33 | 5.3% |
| .online | 30 | 4.8% |
| .top | 29 | 4.6% |
| .cc | 22 | 3.5% |
| .cn | 21 | 3.4% |

#### ctx_issues分布（FP原因）

| Issue | 件数 | 割合 | 解釈 |
|-------|------|------|------|
| **ml_paradox** | 269 | 43.1% | **FP最大の原因** |
| critical_brand_minimum | 131 | 21.0% | ブランド関連誤検出 |
| (なし) | 136 | 21.8% | LLM判断ミス |
| dangerous_tld_combo | 65 | 10.4% | 危険TLDコンボで誤検出 |
| random_pattern_minimum | 54 | 8.7% | ランダムパターン誤検出 |

**ml_paradox TLD修正の期待効果**:
- FP 624件中、ml_paradox関与は269件 (43.1%)
- うち non-dangerous TLD (.com等) は約40%と推定 → **約100件のFP削減が期待**

---

### 10.3 全件評価 FN詳細分析（769件）

#### TLD分布

| TLD | 件数 | 割合 |
|-----|------|------|
| .com | 507 | 65.9% |
| .cn | 42 | 5.5% |
| .br | 30 | 3.9% |
| .net | 25 | 3.3% |
| .org | 11 | 1.4% |

#### ML確率分布

| ML確率帯 | 件数 | 割合 | 解釈 |
|---------|------|------|------|
| 0.0-0.1 | 370 | 48.1% | MLモデル自体が見逃し |
| 0.1-0.2 | 124 | 16.1% | MLモデル自体が見逃し |
| 0.2-0.3 | 92 | 12.0% | 閾値境界 |
| 0.3-0.4 | 74 | 9.6% | 閾値境界 |
| 0.4-0.5 | 57 | 7.4% | 閾値境界 |
| **0.5-1.0** | **52** | **6.8%** | **MLは検出したがCtxで打ち消し** |

**FNの主因**: 76%がML確率0.3未満 → MLモデル自体の限界

---

### 10.5 3000件サンプル評価 FP詳細分析（142件, 参考）

#### 分布

| カテゴリ | 分布 | 洞察 |
|---------|------|------|
| **TLD** | .com: 54 (38%), .xyz: 10, .top: 9 | .comが最多 |
| **ML Category** | very_low: 86 (61%) | 低MLスコアでも誤検出 |
| **Risk Level** | high: 126 (89%) | ほぼ全てhigh判定 |
| **Brand検出** | False: 142 (100%) | ブランド検出なし |
| **Ctx Score** | 0.4-0.6: 113 (80%) | 中程度スコアで誤検出 |

#### ctx_issues分布（FP原因）

| Issue | 件数 | 割合 | 解釈 |
|-------|------|------|------|
| **ml_paradox** | 87 | 61.3% | **FP最大の原因** |
| typical_phishing_cert_pattern | 71 | 50.0% | 証明書パターンで誤検出 |
| critical_brand_minimum | 29 | 20.4% | ブランド関連誤検出 |
| dangerous_tld_combo | 26 | 18.3% | 危険TLDコンボで誤検出 |

#### FPサンプル（ml_paradox）

| ドメイン | ML Prob | Ctx Score | Issues | 問題点 |
|---------|---------|-----------|--------|--------|
| stiiizypods.shop | 0.053 | 0.453 | ml_paradox | 低MLなのにdangerous TLDで誤検出 |
| surli.cc | 0.040 | 0.523 | ml_paradox, dangerous_tld_combo | 短ドメイン+危険TLD |
| aetherapparel.com | 0.077 | 0.500 | ml_paradox, critical_brand_minimum | 正常サイトを誤検出 |
| ltrbxd.com | 0.173 | 0.500 | ml_paradox, random_pattern_minimum | 略語ドメインを誤検出 |

### 10.3 FN詳細分析（177件）

#### 分布

| カテゴリ | 分布 | 洞察 |
|---------|------|------|
| **TLD** | .com: 122 (69%) | .comフィッシングの検出が困難 |
| **ML Category** | very_low: 115 (65%) | ML低予測が主因 |
| **Risk Level** | low: 140 (79%) | low判定で見逃し |
| **Brand検出** | False: 173 (98%) | ブランド検出できず |
| **Ctx Score** | 0.0-0.2: 91 (53%) | 低スコアで見逃し |

#### ML確率分布

| ML確率帯 | 件数 | 割合 | 解釈 |
|---------|------|------|------|
| ML < 0.1 | 84 | 47% | MLモデル自体が見逃し |
| ML 0.1-0.3 | 57 | 32% | MLモデル自体が見逃し |
| ML 0.3-0.5 | 26 | 15% | 閾値境界 |
| **ML >= 0.5** | **10** | **6%** | **MLは検出したがCtxで打ち消し** |

#### FNサンプル（高ML + 低Ctx）

| ドメイン | ML Prob | Ctx Score | Issues | 問題点 |
|---------|---------|-----------|--------|--------|
| myaupaykddifsout.shop | 0.690 | 0.357 | なし | **高MLなのにCtx低で見逃し** |
| moulinexoutlets.shop | 0.654 | 0.341 | なし | 高MLなのにCtx低で見逃し |
| ymxwasxbj.cn | 0.643 | 0.336 | なし | 高MLなのにCtx低で見逃し |
| checkout-aruba.zahnklinik-villingen.de | 0.584 | 0.310 | なし | サブドメイン型フィッシング |

---

## 11. 問題のメカニズム詳細分析

### 11.1 FP原因: ml_paradox（87件, FPの61%）

#### メカニズム

```
【現在のロジック】
ml_paradox ルール: ML < 0.2 かつ Ctx >= 0.4 → phishing疑いフラグ

【問題の発生経路】
1. 正常サイトのMLスコアが低い（0.05未満が多い）
2. しかし証明書がLet's Encrypt + 短期 → Ctx Scoreが0.4-0.5に上昇
3. ml_paradoxフラグが立つ
4. LLMが「MLは低いがml_paradoxがあるので警戒」と判断
5. FP発生
```

#### 定量データ

**ml_paradox FPのML確率分布**:
```
ML < 0.05:    38件 (44%)  ← 非常に低いMLなのにphishing判定
ML 0.05-0.10: 26件 (30%)
ML 0.10-0.20: 21件 (24%)
ML >= 0.20:    2件 (2%)
```

**ml_paradox FPのContext Score分布**:
```
Ctx 0.4-0.5:   26件 (30%)  ← 中程度スコアで誤判定
Ctx 0.5-0.55:  50件 (57%)  ← 0.5付近に集中
Ctx 0.55-0.6:   5件 (6%)
Ctx >= 0.6:     6件 (7%)
```

**TLD分布**: .com: 28件 (32%), dangerous TLD以外が多い

#### 根本原因

- MLスコアが非常に低い（0.05未満）サイトでも、Let's Encrypt + 短期証明書は一般的
- `typical_phishing_cert_pattern` が正常サイトの**17.8%**にも該当
- ml_paradoxルールがこれらを過度に疑っている

---

### 11.2 FP原因: typical_phishing_cert_pattern（71件, FPの50%）

#### メカニズム

```
【パターン条件】
free_ca (Let's Encrypt等) + no_org + valid_days <= 90

【問題の発生経路】
1. 正常サイトでもLet's Encryptは一般的（無料SSL）
2. 小規模サイトはOrganization情報なし
3. 90日更新は正常な運用
4. パターン該当 → Ctx Scoreに加算 → FP発生
```

#### 定量データ

| 項目 | Benign | Phishing | 識別力 |
|------|--------|----------|--------|
| パターン該当率 | 434件 (17.8%) | 320件 (56.6%) | **低い** |
| Precision | - | - | **42.4%** |

**結論**: このパターンだけでphishing判定すると、**57.6%が誤検出**。

---

### 11.3 FN原因: 高ML + 低Ctx（10件）

#### メカニズム

```
【現在のロジック】
最終判定 = f(ML, Ctx, Brand, Rules)
Ctx閾値 0.5-0.65 を超えないとphishing判定されにくい

【問題の発生経路】
1. MLモデルが高確率（0.5以上）でphishing判定
2. しかしCtx Scoreが低い（0.3-0.4）
3. Brandも検出されない
4. 最終判定でbenignに反転
5. FN発生
```

#### 定量データ

**高ML FNの内訳**:
| 条件 | 件数 | 解釈 |
|------|------|------|
| ML >= 0.5 かつ Ctx < 0.4 | 8件 | **MLの判断が正しいのにCtxで打ち消し** |
| ML >= 0.5 かつ Ctx 0.4-0.5 | 0件 | - |
| ML >= 0.5 かつ Ctx >= 0.5 | 0件 | - |

#### 根本原因

- フィッシングサイトが正常な証明書を使用（OV/EV証明書や、ブランドと無関係なドメイン）
- ドメイン名に怪しいパターンがない（企業名風）
- MLが正しく検出しているのに、Ctxツールが「問題なし」と判断して打ち消し

---

### 11.4 FN原因: ML低確率 + ブランド未検出（141件, FNの80%）

#### メカニズム

```
【問題の発生経路】
1. フィッシングだがドメイン名にブランド名が含まれない
2. ドメイン名が企業名風（therapyaoyama.com等）
3. 証明書も正常
4. MLスコアも低い（0.1-0.3）
5. 全てのシグナルが「benign」を示す
6. FN発生
```

#### 定量データ

**FNの検出シグナル状況**:
| シグナル | 検出率 | 解釈 |
|---------|--------|------|
| Brand検出 | 2% (4件) | **98%は検出不可** |
| ML >= 0.3 | 21% (36件) | 79%はML低確率 |
| Ctx >= 0.4 | 37% (62件) | 63%はCtx低 |

#### 根本原因

- **フィッシングの進化**: 明らかなタイポスクワッティングを避け、無関係なドメイン名を使用
- **MLモデルの限界**: ドメイン名だけでは検出できないケースが多い
- **証明書の正常化**: Let's Encryptが普及し、証明書だけでは区別不可能

---

## 12. 改善推奨事項（詳細根拠付き）

### ~~12.1 推奨事項1: ml_paradox + TLD条件追加~~ ⛔ 廃止

> **注記 (2026-01-31)**: この提案は #14 として実装・評価したが、効果限定的（FP -1件のみ）のためロールバック済み。
> 代わりに **#3 ml_paradox: _needs_extra 修正** を推奨（詳細は「やることリスト #3」を参照）。

<details>
<summary>旧提案（参考）</summary>

#### 改善案

```python
# 現在
if ml_prob < 0.2 and ctx_score >= 0.4:
    flag_ml_paradox()

# 改善案: non-dangerous TLDは除外
if ml_prob < 0.2 and ctx_score >= 0.4 and is_dangerous_tld:
    flag_ml_paradox()
```

#### 根拠データ

| 条件 | FP件数 | TP件数 | 影響 |
|------|--------|--------|------|
| ml_paradox + dangerous TLD | 47件 | 24件 | 維持 |
| ml_paradox + non-dangerous TLD | **40件** | 16件 | **削除候補** |

#### 期待効果とリスク

| 効果 | 値 |
|------|-----|
| FP削減 | -40件 |
| Recall影響 | -16件 (TP減少4.1%) |
| Net効果 | **FP -40, TP -16** |

**結論**: ~~FP削減効果がTP減少より大きいため、**実施推奨**。~~ → 実測では効果なし

</details>

---

### 12.2 推奨事項2: ctx閾値0.65の見直し ※優先度低下

#### 分析結果

**FNのContext Score分布**:
```
Ctx < 0.3:     105件 (61%)  ← 大半がここ
Ctx 0.3-0.4:     6件
Ctx 0.4-0.5:    41件
Ctx 0.5-0.55:   21件
Ctx 0.55-0.65:   0件  ← 該当なし
Ctx >= 0.65:     0件  ← 該当なし
```

**結論**: 閾値0.65→0.55の変更は**効果なし**。FNのCtx Scoreは0.55未満に集中しており、閾値変更では救済できない。

**真の問題**: FNはCtx Score自体が低く計算されている（証明書/ドメイン特徴が正常に見える）

---

### 12.3 推奨事項3: 高ML時のctx閾値緩和

#### 改善案

```python
# 高ML時はctx閾値を緩和
if ml_prob >= 0.5:
    ctx_threshold = 0.35  # 通常0.5→0.35に緩和
elif ml_prob >= 0.3:
    ctx_threshold = 0.45
else:
    ctx_threshold = 0.50
```

#### 根拠データ

| 条件 | FN救済 | FP増加リスク |
|------|--------|-------------|
| ML >= 0.5 でctx緩和 | +10件 | +24件 |

**Benign (ML>=0.5 + Ctx<0.5) の内訳**: 24件が新たにFPになるリスク

#### 期待効果とリスク

| 効果 | 値 |
|------|-----|
| FN救済 | +10件 |
| FP増加リスク | +24件 |
| Net効果 | **FN -10, FP +24** |

**結論**: トレードオフが悪い（FN救済10件に対しFP増加24件）。**慎重な検討が必要**。

---

### 12.4 推奨事項4: typical_phishing_cert_pattern の重み調整

#### 改善案

```python
# 現在: cert_patternだけでスコア加算
if has_typical_phishing_cert_pattern:
    ctx_score += 0.15

# 改善案: 他の要因との組み合わせで判定
if has_typical_phishing_cert_pattern:
    if is_dangerous_tld or has_random_pattern or has_brand_keyword:
        ctx_score += 0.15  # 他の要因ありなら加算
    else:
        ctx_score += 0.05  # 単独では弱い重み
```

#### 根拠データ

| パターン | Benign該当 | Phishing該当 | Precision |
|---------|-----------|-------------|-----------|
| cert_pattern単独 | 434件 (17.8%) | 320件 (56.6%) | 42.4% |
| cert_pattern + dangerous_tld | 少数 | 多数 | 高い |
| cert_pattern + brand検出 | 少数 | 多数 | 高い |

**結論**: 単独での使用は避け、**他要因との組み合わせで使用**すべき。

---

## 13. 改善優先順位まとめ（2026-01-31 更新）

| 優先度 | 項目 | 期待効果 | リスク | 推奨 |
|--------|------|----------|--------|------|
| ~~1~~ | ~~ml_paradox: _needs_extra 修正~~ | ~~FP -122件, F1 +1.31pp~~ | - | ✅ **実施済み (2026-01-31)** |
| **2** | ML >= 0.5 FN救済 | FN -60件 | FP増加リスク要調査 | ⚠️ 要検討 |
| **3** | critical_brand_minimum 調整 | FP -171件 | 要詳細分析 | ⚠️ 要検討 |
| ~~4~~ | ~~ml_paradox + TLD条件追加~~ | ~~FP -40件~~ | - | ❌ ロールバック済み |
| ~~5~~ | ~~cert_pattern 重み調整~~ | - | - | ❌ 既に無効化済み |
| ~~6~~ | ~~ctx閾値0.65→0.55~~ | ~~効果なし~~ | - | ❌ 実施不要 |

---

## 14. やることリスト（優先度順）

### 最新分析に基づくやることリスト（2026-01-31更新）

#### 現状の課題（全件評価 13,680件）

**FP主因 (638件)**:
| Issue | 件数 | 割合 |
|-------|------|------|
| ml_paradox | 320 | 50.2% |
| critical_brand_minimum | 171 | 26.8% |
| dangerous_tld_combo | 99 | 15.5% |
| (LLM判断ミス) | 141 | 22.1% |

**FN主因 (801件)**:
| 原因 | 件数 | 割合 |
|------|------|------|
| ML < 0.3 (モデル限界) | 605 | 75.5% |
| シグナル無し | 514 | 64.2% |
| ML >= 0.5 → Ctx打消 | 60 | 7.5% |
| ブランド未検出 | 801 | 100% |

#### 優先タスク

| # | 項目 | 期待効果 | 優先度 | 状態 |
|---|------|---------|--------|------|
| **18** | **fuzzy/fuzzy2 ブランドマッチ閾値調整** | **FP -107, F1 +0.55pp** | **高** | **新規 (2026-02-01)** |
| 16 | ML >= 0.5 FN救済 (Ctx閾値緩和) | FN -60件 (7.5%) | 中 | 新規 |
| 3 | ml_paradox 条件厳格化 | FP -320件 (50.2%) | 中 | 未実施 |
| 17 | critical_brand_minimum ML閾値 | FP -22件 | 低 | **✅ 完了** |

#### #18 詳細（2026-02-01 追加）

**背景**: 全件評価（15,630件）のTP/FP分析より、ブランドマッチタイプ別に精度差を発見。

| Type | TP | FP | TP/FP比 |
|------|-----|-----|---------|
| substring | 90 | 50 | 1.80 |
| compound | 68 | 60 | 1.13 |
| **fuzzy** | 72 | 107 | **0.67** |
| **fuzzy2** | 42 | 92 | **0.46** |

**推奨アクション**:
- fuzzy/fuzzy2 マッチの閾値を厳格化、または無効化
- 72件のTPのうち37件は他ルール（ml_no_mitigation_gate等）で救済可能
- 純TP損失: 35件、純FP削減: 107件

**期待効果**:
- Precision: 72.81% → 75.78% (+2.97pp)
- Recall: 65.33% → 64.05% (-1.28pp)
- **F1: 68.87% → 69.42% (+0.55pp)**

#### 廃止・保留

| # | 項目 | 理由 |
|---|------|------|
| 14 | ml_paradox TLD修正 | ⛔ ロールバック済み（効果限定的） |
| 15 | cert_pattern重み調整 | ⛔ 廃止（#9で既に無効化済み） |
| 12 | ブランドキーワード追加 | 保留（FN -3件のみで効果薄い） |
| 4 | LOW_ML_GUARD調整 | 保留（FP増加リスク高い）|

#### #14 実装詳細 (2026-01-30 実施 → 2026-01-31 ロールバック)

**変更ファイル**: `phishing_agent/tools/contextual_risk_assessment.py`

**試行した変更**:
- `has_dangerous_tld_for_paradox` 変数を追加
- 強/弱パラドックス条件に dangerous TLD ガードを追加
- non-dangerous TLD では ml_paradox を発火させない

**期待効果**:
- FP -40件（non-dangerous TLD での ml_paradox FP を抑制）
- F1 +0.74pp

**実際の結果 (2026-01-30 評価)**:

| 指標 | 期待 | 結果 |
|------|------|------|
| FP削減 | -40件 | -1件（共通554ドメイン） |
| F1改善 | +0.74pp | -0.23pp（共通ドメイン） |

**ロールバック理由**:
1. 効果が限定的（FP -1件のみ）
2. F1の改善が見られなかった
3. 評価サンプルの違い（共通率18%）により正確な測定が困難
4. 複雑性に見合う効果が得られなかった

**備考**:
- 評価時に `--shuffle` オプションの有無でサンプルが異なった
- 効果測定のためのログ出力がなく、正確な影響把握が困難だった

### 検証完了

| # | 項目 | 期待効果 | 結果 |
|---|------|---------|------|
| 1 | typical_phishing_cert_pattern 削除の効果検証 | FP -100〜150 | ✅ F1 +2.9pp, R1発火=0 |

### 実施済み（FP対策）

| # | 項目 | 期待効果 | 結果 |
|---|------|---------|------|
| 2 | fuzzy match 特定パターン除外 | FP -9 | ✅ 採用（FP/FN 1:1トレードオフ、FN優先で受容） |
| 6 | steam/roblox/eshop 除外パターン追加 | FP -3 | ✅ 実施済み |

### 実施済み（FN対策）

| # | 項目 | 期待効果 | 結果 |
|---|------|---------|------|
| 5 | ブランドキーワード追加 | FN -10〜20 | ✅ **FN -58** (トレードオフ込み) |

### 実施済み（FP対策）★最新分析に基づく★

| # | 項目 | 期待効果 | 結果 |
|---|------|---------|------|
| 9 | typical_phishing_cert_pattern 検出無効化 | FP -68 | ✅ 実施 (2026-01-29 19:45) |

### 実施済み（FP対策）★#10★

| # | 項目 | 期待効果 | 結果 |
|---|------|---------|------|
| 10 | fuzzy2 FP対策 (BOUNDARY_REQUIRED_BRANDS追加) | FP -20 | ✅ 実施 (2026-01-29 22:45) |

### 実施済み（FP対策）★#11★

| # | 項目 | 期待効果 | 結果 |
|---|------|---------|------|
| 11 | compound/substring FP対策 | FP -15 | ✅ 実施 (2026-01-29 23:00) |

### 実施済み（FP対策）★#3★

| # | 項目 | 期待効果 | 結果 |
|---|------|---------|------|
| 3 | ml_paradox: _needs_extra 修正 | FP -122件, F1 +1.31pp | ✅ **評価完了** (2026-01-31 07:17) |

**変更内容**: `contextual_risk_assessment.py` の `_needs_extra` から以下を除外:
- `brand_detected` (Precision 18.2%)
- `consonant_cluster_random` (Precision 10.5%)

**評価結果 (3000件サンプル)**:

| 指標 | 期待 | 実測 | 判定 |
|------|------|------|------|
| F1 | +1.31pp | **+2.37pp** | ✅ 期待超 |
| Precision | +3.93pp | +1.69pp | △ |
| Recall | -0.74pp | **+2.93pp** | ✅ 期待超 |

**効果測定ログ確認 (整合性 ✓)**:
- 除外でブロック: 79件
  - `consonant_cluster_random`: 53件
  - `brand_detected`: 26件
- 結果内訳: TN 53件 (FP回避), FP 20件, TP 6件, FN 0件
- **FP削減**: 53件（除外がなければFPになっていた）
- **FN増加**: 0件

### 未実施（優先度高）

| # | 項目 | 期待効果 | 優先度 | 根拠 |
|---|------|---------|--------|------|
| 16 | ML >= 0.5 FN救済 | FN -60件 | 高 | ML検出→Ctx打消の救済 |
| 17 | critical_brand_minimum 調整 | FP -171件 | 中 | FP 26.8%に関与 |

#### #16 ML >= 0.5 FN救済の詳細

**問題**: MLモデルが0.5以上で検出したのに、Ctx Scoreが低くbenign判定される

**対象**: 60件 (FN全体の7.5%)
- Ctx Score 平均: 0.333
- Ctx Score 範囲: 0.271 - 0.500

**改善案**:
```python
# ML >= 0.5 の場合、Ctx閾値を緩和
if ml_prob >= 0.5:
    # 現在: ctx >= 0.5 でphishing判定
    # 改善: ctx >= 0.35 でphishing判定（ML信頼）
    ctx_threshold = 0.35
```

**リスク**: Benign で ML >= 0.5 のケースがFP増加する可能性 → 要事前調査

#### #3 ml_paradox 条件厳格化の詳細（2026-01-31 分析更新）

**問題**: ml_paradox (強) が FP 320件 (50.2%) に関与

**発火パス分析**:

| パス | FP | TP | Precision |
|-----|---:|---:|----------:|
| 通常パス (risk_signal_count >= 2) | 43 | 17 | 28.3% |
| **free_ca + no_org + _needs_extra** | **277** | 106 | 27.7% |

**→ FPの86.6%が「free_ca + no_org + _needs_extra」パスで発生**

**_needs_extra 内のシグナル別精度**:

| シグナル | FP | TP | Precision | 判定 |
|---------|---:|---:|----------:|------|
| short_random_combo | 4 | 11 | 73.3% | ✓ 維持 |
| dangerous_tld | 153 | 95 | 38.3% | ✓ 維持 |
| rare_bigram_random | 59 | 26 | 30.6% | ✓ 維持 |
| **brand_detected** | **130** | **29** | **18.2%** | ⚠ 除外候補 |
| **consonant_cluster_random** | **17** | **2** | **10.5%** | ⚠ 除外候補 |

**改善案**: `_needs_extra` から低精度シグナルを除外

```python
# contextual_risk_assessment.py (lines 415-425)
# 現在
_needs_extra = {
    "dangerous_tld", "brand_detected", "random_pattern", ...
    "consonant_cluster_random", "rare_bigram_random",
}

# 改善案: brand_detected と consonant_cluster_random を除外
_needs_extra = {
    "dangerous_tld", "random_pattern", "high_entropy",
    "short_random_combo", "random_with_high_tld_stat",
    "idn_homograph", "rare_bigram_random",
}
```

**期待効果**:

| 指標 | 現状 | 改善後 | 変化 |
|------|------|--------|------|
| FP | 638 | 516 | **-122件** |
| TP | 1586 | 1568 | -18件 |
| Precision | 71.31% | 75.24% | **+3.93pp** |
| Recall | 65.03% | 64.29% | -0.74pp |
| **F1** | **68.02%** | **69.33%** | **+1.31pp** |

**リスク**: TP 18件の損失（Recall -0.74pp）→ Precision大幅改善で相殺

### 保留（効果薄い/リスク高い）

| # | 項目 | 理由 |
|---|------|------|
| 12 | ブランドキーワード追加 | FN -3件のみで効果薄い |
| 4 | LOW_ML_GUARD 閾値調整 | FP増加リスク高い |

### 将来検討

| # | 項目 | 期待効果 | 優先度 | 備考 |
|---|------|---------|--------|------|
| 7 | トレースログから判定理由を自動生成 | UX向上 | 低 | trace_utils.py拡張 |
| 8 | 評価スクリプトの重複排除改善 | 評価精度向上 | 中 | v2評価で729件重複発見 |

### 最新分析結果（2026-01-31 全件評価）

**FP原因の内訳 (638件)**:
1. `ml_paradox`: 320件 (50.2%) - **最大の原因** → **#3で対策予定（F1 +1.31pp見込み）**
2. `critical_brand_minimum`: 171件 (26.8%) - ブランド検出関連
3. `(LLM判断ミス)`: 141件 (22.1%) - issue無しでFP
4. `dangerous_tld_combo`: 99件 (15.5%) - 危険TLD関連
5. `random_pattern_minimum`: 95件 (14.9%) - ランダムパターン関連
6. その他: 3件 (2%)

**FN原因の内訳 (143件)**:
1. ブランド検出なし: 143件 (100%) - キーワード追加で改善困難
2. ML低確率 (<0.3): 103件 (72%) - MLモデル自体の限界
3. 検出可能なtyposquatting: 数件のみ - キーワード追加で対応可能

---

## 次のステップ（2026-01-31 更新）

### 実装方針: 1つずつ評価

複数機能を同時に実装すると効果の切り分けが困難になるため、**1機能ずつ実装・評価**する。

| 観点 | 複数同時 | 1つずつ |
|------|---------|---------|
| 評価時間 | 1回で済む | 複数回必要 |
| 因果関係 | ログで推測 | **明確** |
| 相互作用 | 発見しにくい | - |
| デバッグ | 複雑 | **単純** |

**今回1つずつが良い理由**:
- #16 (FN救済) と #17 (FP削減) は逆方向の効果 → 打ち消し合う可能性
- #17 は #3 で一部解消される可能性 → #3 評価後に再分析が必要
- #17 は2つの実装案があり、どちらが効果的か不明

### 推奨実装順序

```
Step 1: #3 の効果確認（実装済み、評価待ち）
   ↓
Step 2: #16 実装・評価（シミュレーション済み）
   ↓
Step 3: #17 再分析・実装（#3評価後に改めて分析）
```

---

### Step 1: #3 ml_paradox 修正 ✅ 完了

**変更内容**: `_needs_extra` から低精度シグナルを除外
- `brand_detected` (Precision 18.2%)
- `consonant_cluster_random` (Precision 10.5%)

**効果測定ログ追加済み**:
```python
"paradox": {
    "excluded_signals": [...],      # 除外されたシグナル
    "would_have_triggered": True,   # 除外がなければ発火していたか
}
```

**評価結果 (2026-01-31 07:17完了)**:

| 指標 | 期待 | 実測 | 状態 |
|------|------|------|------|
| F1 | +1.31pp | **+2.37pp** | ✅ |
| FP削減 | 122件 | 53件 (ログ確認) | ✅ |
| FN増加 | 18件 | 0件 | ✅ |

**次のアクション**: Step 2 (#16 ML >= 0.5 FN救済) の実装

---

### Step 2: #16 ML高スコアFN救済 ✅ 実装完了 (2026-01-31)

**問題**: ML確率が高いのに Ctx が中程度で見逃されるFN

**再分析結果** (3000件評価データ):
- FN (ML >= 0.35): 105件
- 最適閾値: ML >= 0.35, Ctx >= 0.40 (Precision 90.4%)

**閾値シミュレーション** (更新版):

| 設定 | FN救済 | FP増加 | Net | 救済Prec | F1変化 |
|------|--------|--------|-----|----------|--------|
| ML >= 0.35, Ctx >= 0.30 | +105 | +41 | +64 | 71.9% | +2.24pp |
| **ML >= 0.35, Ctx >= 0.40** | **+66** | **+7** | **+59** | **90.4%** | **+1.69pp** |
| ML >= 0.40, Ctx >= 0.40 | +45 | +4 | +41 | 91.8% | +1.17pp |

**採用**: `ML >= 0.35, Ctx >= 0.40` (B案) - 高精度でF1改善

**実装**:
- ファイル: `phishing_agent/rules/detectors/ml_guard.py`
- ルール: `HighMLCtxRescueRule`
- 除外条件: allowlist, 信頼TLD (.org, .edu, .gov等)

```python
class HighMLCtxRescueRule(DetectionRule):
    def __init__(self, ml_threshold=0.35, ctx_threshold=0.40, ctx_upper=0.50):
        ...

    def _evaluate(self, ctx: RuleContext) -> RuleResult:
        if ctx.llm_is_phishing:
            return RuleResult.not_triggered(self.name)
        if ctx.ml_probability < self._ml_threshold:
            return RuleResult.not_triggered(self.name)
        if ctx.ctx_score < self._ctx_threshold or ctx.ctx_score >= self._ctx_upper:
            return RuleResult.not_triggered(self.name)
        # 除外条件チェック後...
        return RuleResult(triggered=True, force_phishing=True, ...)
```

**次のアクション**: 3000件評価で効果確認

---

### Step 3: #17 critical_brand_minimum 調整 ✅ 完了 (2026-01-31)

**問題**: critical_brand_minimum の Precision が 38.0% と低い（ML < 0.15 で 84.6% が FP）

**実装内容**:
- ML < 0.15 の場合は `critical_brand_minimum` によるスコアブースト（→0.50）をスキップ
- 効果測定用に `critical_brand_minimum_blocked` タグを追加
- 実装場所: `contextual_risk_assessment.py`（例外的にルールモジュールではなくcontextual側に実装）

**設計判断**: contextual vs rules module

| アプローチ | 実装場所 | 動作 |
|-----------|---------|------|
| A (採用) | contextual | ブーストをスキップ、他要因による高ctxは維持 |
| B | rules module | 一律benign強制 |

**エッジケース分析** (3000件中3件):

| ドメイン | ctx | ML | 実際 | A | B |
|----------|-----|-----|------|---|---|
| vpn-android.com | 0.69 | 0.079 | benign | FP | 正 |
| xcloud.host | 0.72 | 0.032 | benign | FP | 正 |
| paypal-home.com | 0.60 | 0.106 | phishing | **正** | **FN** |

**結論**: Approach A を採用（paypal-home.com のTP維持を優先）

---

### 完了済み
- ~~#3 ml_paradox: _needs_extra 修正~~ ✅ (2026-01-31 11:00)
- ~~#9 typical_phishing_cert_pattern 完全無効化~~ ✅
- ~~#10 fuzzy2 FP対策~~ ✅
- ~~#11 compound/substring FP対策~~ ✅
- ~~#17 critical_brand_minimum ML閾値~~ ✅ (2026-01-31)

### ロールバック済み
- **#14 ml_paradox TLD修正** - 効果限定的（FP -1件のみ）のためロールバック

### 最新評価結果（2026-01-30 全件評価、#3修正前）
- **全件評価 (13,890件)**
  - F1: 68.02%, Precision: 71.31%, Recall: 65.03%
  - TP: 1,586, FP: 638, FN: 853, TN: 10,813
  - ml_paradox がFP **50.2%** に関与（320件）
  - ML >= 0.5 のFN: 90件 (10.6%)

### 評価完了後のタスク

#### #13 ログベース分析によるチューニング指針策定

**目的**: 評価結果のトレースログを体系的に分析し、論理的なチューニング方針を導出

**既存の分析スクリプト**:

| スクリプト | 用途 | 使用例 |
|-----------|------|--------|
| `analyze_trace.py` | FP/FNトレース分析 | `python scripts/analyze_trace.py --fp` |
| `analyze_rule_metrics.py` | ルール効果分析 | `python scripts/analyze_rule_metrics.py results.csv` |
| `export_fnfp_analysis.py` | FN/FP詳細エクスポート | `python scripts/export_fnfp_analysis.py` |
| `analyze_evaluation_results.py` | 汎用評価分析 | `python scripts/analyze_evaluation_results.py` |
| `analyze_brand_exclusion.py` | ブランド除外効果分析 | `python scripts/analyze_brand_exclusion.py` |

**分析手順**:

```bash
# 1. FP/FN概要分析
python scripts/analyze_trace.py

# 2. FPの詳細分析 (ctx_issues, rules_fired別)
python scripts/analyze_trace.py --fp --export fp_analysis.json

# 3. FNの詳細分析 (ML確率帯, ブランド検出有無別)
python scripts/analyze_trace.py --fn --export fn_analysis.json

# 4. ルール効果分析 (Precision/Recall)
python scripts/analyze_rule_metrics.py artifacts/.../worker_*_results.csv --export-json rule_metrics.json

# 5. ブランド除外パターン効果確認
python scripts/analyze_brand_exclusion.py
```

**利用可能なトレースフィールド**:

| カテゴリ | フィールド | 用途 |
|---------|-----------|------|
| 判定理由 | ai_reasoning, ai_risk_factors | FP/FN原因の詳細分析 |
| Precheck | trace_precheck_ml_category, trace_precheck_tld_category | ML/TLD分布分析 |
| ツールスコア | trace_brand/cert/domain/ctx_risk_score | ツール別効果測定 |
| ctx_issues | trace_ctx_issues | 問題パターン分類 |
| Policy | trace_phase6_rules_fired | ルール発火分析 |
| ツール出力 | tool_brand/cert/domain/ctx_output | 詳細デバッグ |

**分析項目**:
1. **FP原因分類**: ctx_issues / rules_fired / brand検出パターン別
2. **FN原因分類**: ML確率帯 / ブランド検出有無 / TLDカテゴリ別
3. **ツール効果測定**: 各ツールのTP/FP寄与度
4. **閾値最適化**: risk_scoreの最適閾値探索
5. **ルール効果分析**: 各ルールのPrecision/Recall

**成果物**:
- 分析レポート (FP/FN原因、チューニング推奨事項)
- 次回チューニング項目リスト

---

---

## 付録A: チューニング知見 (2026-01-27)

*tuning_insights_20260127.md より統合*

### A.1 初期評価結果 (n=260, 1.7% of total)

| Metric | Value |
|--------|-------|
| F1 | 0.6038 |
| Recall | 0.6275 |
| Precision | 0.5818 |
| FN | 19 (7.3%) |
| FP | 23 (8.8%) |

### A.2 FPパターン分析

| パターン | 件数 | 説明 |
|---------|------|------|
| Dangerous TLD単独 | 6 | 正規サイトが.icu, .online等を使用 |
| Random Pattern誤検出 | 8 | 略語(frmtr.com等)を誤検出 |
| Brand Substring誤マッチ | 2 | "meta"が"asmetalwork"にマッチ |
| High ML but No AI Signals | 2 | MLは正常動作 |

### A.3 FNパターン分析

| パターン | 説明 |
|---------|------|
| Low Signal Phishing | ブランド/ランダムパターンなし、正常に見えるドメイン |
| ML Paradox but Still Missed | 複数リスクシグナルがあるがSAN/CRLで打ち消し |
| Brand Detected but Not Flagged | ブランド検出したがスコア不足 |

### A.4 推奨アクション

**高優先度 (FP削減)**:
1. dangerous TLD単独トリガー緩和 → 2+シグナル必須に
2. Trancoホワイトリスト活用 → random_pattern抑制

**中優先度 (FN削減)**:
3. random + dangerous TLDコンボ強化
4. low_signal_phishing閾値見直し

---

## 付録B: 検出不能FN分析 (1,111件)

*undetectable_fn_1111_analysis.txt より統合*

### B.1 明示的な欠損 (29件, 2.61%)

**欠損フィールド**:
- cert_issuer_org
- cert_not_before
- cert_not_after

**ソース別内訳**:
- phishtank: 15件
- jpcert: 10件
- certificates: 4件

### B.2 欠損の特徴

1. 29件だけcert_issuer_org/cert_not_before/cert_not_afterが空欄
2. 同じ29件でcert_age_days = 0（既定値で埋めた可能性）
3. cert_is_free_ca = False（issuer空欄で判定不能）

### B.3 体系的に欠損に近い挙動

- `cert_has_organization`: 全1,111件でFalse
- `cert_san_count.1`: 欠損29件で常に0（重複列の疑い）

### B.4 次のアクション

- 29件の証明書取得処理をログで追跡（取得失敗/パース失敗/結合漏れの特定）
- cert_has_organizationの生成箇所を確認

---

## 15. 全件評価（15,630件）詳細分析（2026-02-01）

### 15.1 評価結果

| 指標 | 値 |
|------|-----|
| **F1 Score** | **68.87%** |
| Precision | 72.81% |
| Recall | 65.33% |
| TP | 1,781 |
| FP | 665 |
| FN | 945 |
| TN | 12,239 |

### 15.2 カテゴリ別特性

| Category | Count | ML Mean | CTX Mean | 特徴 |
|----------|-------|---------|----------|------|
| **TP** | 1,781 | 0.719 | 0.512 | 高ML + 高CTX |
| **FP** | 665 | 0.314 | 0.435 | 低ML + 中CTX |
| **TN** | 12,239 | 0.085 | 0.131 | 低ML + 低CTX |
| **FN** | 945 | 0.191 | 0.256 | 低ML + 低CTX |

### 15.3 ルール別 TP/FP 比

| Rule | TP | FP | TP/FP比 | 評価 |
|------|-----|-----|---------|------|
| very_high_ml_override | 804 | 37 | **21.7** | 優良 |
| ml_no_mitigation_gate | 1,384 | 199 | **7.0** | 優良 |
| soft_ctx_trigger | 292 | 106 | 2.8 | 良好 |
| brand_cert_high | 228 | 218 | **1.0** | 要注意 |
| policy_r4 | 304 | 432 | **0.7** | 問題 |

### 15.4 ブランドマッチタイプ別分析

| Type | TP | FP | TP/FP比 | 評価 |
|------|-----|-----|---------|------|
| substring | 90 | 50 | 1.80 | 許容 |
| compound | 68 | 60 | 1.13 | 許容 |
| **fuzzy** | 72 | 107 | **0.67** | 問題 |
| **fuzzy2** | 42 | 92 | **0.46** | 問題 |

**発見**: fuzzy/fuzzy2 は FP > TP であり、削減対象として適切

### 15.5 POST_LLM_FLIP_GATE の役割

| Category | GATE発火 | 割合 |
|----------|---------|------|
| TP | 0 | 0.0% |
| FP | 0 | 0.0% |
| **TN** | **1,003** | **8.2%** |
| FN | 111 | 11.7% |

**重要発見**: GATEはTN 1,003件を保護している。緩和すると大幅FP増加のリスク。

### 15.6 トレードオフシミュレーション

#### シナリオ1: fuzzy/fuzzy2 無効化（推奨）

| 指標 | 現状 | 変更後 | 差分 |
|------|------|--------|------|
| TP | 1,781 | 1,746 | -35 |
| FP | 665 | 558 | **-107** |
| Precision | 72.81% | 75.78% | **+2.97pp** |
| Recall | 65.33% | 64.05% | -1.28pp |
| F1 | 68.87% | 69.42% | **+0.55pp** |

#### シナリオ2: POST_LLM_FLIP_GATE 緩和（非推奨）

| リスク | 値 |
|--------|-----|
| FN救済 | +111 |
| FP増加 | **+1,003** |

### 15.7 結論

#### 許容すべき限界

| 領域 | 件数 | 理由 |
|------|------|------|
| 極低シグナルFN | 361 (38%) | 外部脅威インテリジェンスなしでは検出不可能 |
| GATE保護TN | 1,003 | 緩和するとFP急増 |

#### チューニング可能な領域

| 対策 | FP削減 | TP損失 | 純効果 |
|------|--------|--------|--------|
| fuzzy/fuzzy2 無効化 | -107 | -35 | **F1 +0.55pp** |

---

## 変更履歴

- 2026-02-01: **全件評価完了・FN/FP詳細分析** - 15,630件評価完了（F1 68.87%）、TP/TN/FP/FN全カテゴリの特性分析、ルール別TP/FP比分析、ブランドマッチタイプ別分析（fuzzy/fuzzy2問題発見）、POST_LLM_FLIP_GATE役割分析（TN 1,003件保護）、トレードオフシミュレーション（fuzzy/fuzzy2無効化でF1 +0.55pp）、Section 15追加
- 2026-01-31 07:17: **#3評価完了** - 3000件サンプル評価で効果確認。F1 +2.37pp（期待+1.31ppを上回る）、効果測定ログ整合性確認済み、タイムアウト5件（リトライ機能検討）
- 2026-01-31 11:00: **#3実装完了** - contextual_risk_assessment.py の `_needs_extra` から `brand_detected`, `consonant_cluster_random` を除外。テスト確認済み
- 2026-01-31 10:30: #3詳細分析完了 - ml_paradox発火パス分析（通常パス43件/free_ca+no_org+_needs_extra 277件）、_needs_extraから低精度シグナル(brand_detected:18.2%, consonant_cluster_random:10.5%)除外で**F1 +1.31pp**の見込み
- 2026-01-31 01:00: やることリスト更新 - 最新全件評価(13,680件)に基づき再分析、#16/#17追加、#15廃止、優先順位再設定
- 2026-01-31 00:30: #14ロールバック - ml_paradox TLD修正を元に戻し（効果限定的: FP -1件のみ、F1改善なし）
- 2026-01-30 19:00: #14評価完了 - 3000件評価（ml_paradox TLD修正後）、サンプル不一致で正確な比較困難
- 2026-01-30 17:30: 全件評価（13,426件）完了報告追加 - F1=0.6858, FP=624, FN=769（ml_paradox TLD修正前）
- 2026-01-30 16:30: docs/analysis/ フォルダ整理 - ファイル統合・二桁番号プレフィックス付与
- 2026-01-30 16:10: 付録A,B追加（tuning_insights, undetectable_fn統合）
- 2026-01-30 15:00: #14実施 - ml_paradox + non-dangerous TLD 抑制（contextual_risk_assessment.py修正）
- 2026-01-30 14:30: Section 10-13追加 - 全件評価後の詳細分析結果、問題メカニズム、改善推奨事項（根拠データ付き）
- 2026-01-30 00:30: #13追加 - 評価完了後のログベース分析タスク定義
- 2026-01-29 23:48: 全件評価開始 (15,670件, 3GPU並列)
- 2026-01-29 23:00: #11実施 - compound/substring FP対策（acom,wise,stripe,tmobile,promise,disney,mastercard追加）
- 2026-01-29 22:45: #10実施 - fuzzy2 FP対策（bestbuy,binance,usbank,signal,nordea,shopify追加）、分析スクリプト更新
- 2026-01-29 19:45: #9実施 - typical_phishing_cert_pattern 検出を完全無効化（FP 68件対策）
- 2026-01-29 19:30: 2601件詳細分析完了、FP原因分類（typical_cert:58, ml_paradox:38, fuzzy2:20, compound:15）、FN原因分類（ブランド未検出100%、ML低確率72%）、やることリスト大幅更新
- 2026-01-29 17:00: FP増加原因調査完了、トレードオフ分析（FP+58/FN-58の1:1、FN優先で受容）、やることリスト更新
- 2026-01-29 16:30: 3000件評価v2完了（F1=0.698, FN-58改善, FP+58）
- 2026-01-29 15:00: ブランドキーワード追加（aupay, vanillagift, steam, googleplay等 15キーワード）
- 2026-01-29 14:30: fuzzy match FP対策実施（costco/youtube/laposte/sbinet除外パターン追加）
- 2026-01-29 14:00: 3000件評価完了、効果確認（F1 +2.9pp, R1発火=0）、やることリスト更新（Section 8.6, 9更新）
- 2026-01-29 11:30: _strong_certからtypical_phishing_cert_pattern削除、やることリスト整理（Section 9追加）
- 2026-01-29 11:00: トレース詳細分析実施、FP/FN原因の定量分析完了（Section 8.4追加）
- 2026-01-29 00:30: 評価完了、typical_phishing_cert_pattern分析結果追加（Precision 39.4%で問題あり）
- 2026-01-28 23:30: 検討事項リスト追加（Section 8）、fuzzy match分析結果、typical_phishing_cert_pattern実装
- 2026-01-28 22:00: トレースデータによる詳細分析追加（Section 7）、Policy/ctx_issues/ツールスコア分析
- 2026-01-28 19:30: トレースフィールド追加（worker.py修正、20フィールド追加）
- 2026-01-28 19:30: 仕様書更新（parallel_evaluation_spec.md v1.1）
- 2026-01-28 16:00: ブランド検出FP対策実施（citi, swift, meta, hermes, appstore）
- 2026-01-28 15:30: FP追加分析（ブランド誤検出パターン特定）
- 2026-01-28 15:00: ルールエンジン設定更新（random_pattern_minimum 無効化）
- 2026-01-28 14:30: 部分的ロールバック実施（random_pattern, digit_mixed, no_vowel 無効化）
- 2026-01-28 13:00: FN分析完了、改善項目別分析完了
- 2026-01-28 12:30: FP分析完了、FN分析開始
