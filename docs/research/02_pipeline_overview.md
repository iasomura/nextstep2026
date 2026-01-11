# フィッシング検出パイプライン概要

**作成日**: 2026-01-11
**最終更新**: 2026-01-11
**対象**: 02_main.py および関連モジュール
**検証データ**: 128,067ドメイン（Phishing: 7,341件, Benign: 120,726件）

---

## 1. 解決したい課題

インターネット上には日々大量の新規ドメインが出現し、その中にはフィッシングサイトが含まれている。フィッシングサイトとは、正規のサービス（銀行、ECサイト、SNSなど）を模倣してユーザーの認証情報やクレジットカード情報を詐取する悪意あるWebサイトである。

本研究では、SSL証明書のCertificate Transparency (CT) ログから収集したドメイン情報を入力として、各ドメインがフィッシングサイトである可能性を判定するシステムを構築する。

### 課題の難しさ

1. **大量データ**: 1日あたり数十万件の新規ドメインが発行される
2. **コスト制約**: 全件を詳細分析することは計算コスト的に非現実的
3. **精度要件**: 見逃し（フィッシングを安全と誤判定）は深刻な被害につながる
4. **偽陽性の問題**: 正規サイトをフィッシングと誤判定すると、正当なサービスに影響
5. **クラス不均衡**: Phishing : Benign ≈ 1 : 16 という著しい不均衡

---

## 2. 提案するアプローチ

本システムは「段階的フィルタリング」の考え方を採用している。すべてのドメインを同じ深さで分析するのではなく、明らかに安全/危険なケースは高速に処理し、判断が難しいケースにのみ計算コストの高い詳細分析を適用する。

この考え方を実現するため、3段階のパイプライン構成を採用した：

```
全ドメイン（128,067件）
    ↓
[Stage1] XGBoost + Route1閾値判定
    ├── AUTO_BENIGN  → 60,101件 (46.9%) ─→ 最終判定: Benign
    ├── AUTO_PHISHING → 7,595件 (5.9%)  ─→ 最終判定: Phishing
    └── PENDING       → 60,371件 (47.2%) ─→ Stage2へ
                ↓
[Stage2] Logistic Regression Defer + 優先度選別
    ├── Stage1採用    → 31,687件 ─→ Stage1の判定を使用
    └── Handoff       → 28,684件 (22.4%) ─→ Stage3へ
                ↓
[Stage3] LLM AI Agent (Qwen3-14B)
    └── 詳細分析による最終判定
```

### 処理コスト比較

| Stage | 処理時間/件 | 全件処理時の総時間 | 実際の処理件数 | 実際の処理時間 |
|-------|-------------|-------------------|----------------|----------------|
| Stage1 | ~1ms | ~2分 | 128,067件 | ~2分 |
| Stage2 | ~5ms | ~10分 | 60,371件 | ~5分 |
| Stage3 | ~8秒 | ~285時間 | 28,684件 | **~64時間** |

Stage1/Stage2のフィルタリングにより、Stage3の処理時間を285時間から64時間に削減（**-77.5%**）。

---

## 3. Stage1: 機械学習による高速分類

### 3.1 特徴量設計

合計41種類の特徴量を使用。SSL証明書とドメイン名から抽出可能な情報のみを使用し、Webコンテンツへのアクセスは行わない（高速化のため）。

#### ドメイン特徴量（15種類）

| 特徴量名 | 説明 | 重要度* |
|----------|------|---------|
| `domain_length` | ドメイン名の文字数 | 中 |
| `domain_entropy` | シャノンエントロピー（ランダム性） | 高 |
| `digit_ratio` | 数字の含有率 | 中 |
| `hyphen_count` | ハイフンの数 | 低 |
| `subdomain_depth` | サブドメインの階層数 | 中 |
| `tld_is_dangerous` | 危険TLDフラグ | 高 |
| `tld_phishing_rate` | TLD別のフィッシング出現率 | 高 |
| `is_idn` | 国際化ドメイン名（IDN）フラグ | 中 |
| `consonant_ratio` | 子音の比率（ランダム文字列検出） | 中 |
| `has_brand_keyword` | ブランド名含有フラグ | 高 |
| ... | （他5種類） | |

*重要度はXGBoostのfeature_importanceに基づく

#### 証明書特徴量（26種類）

| 特徴量名 | 説明 | 重要度 |
|----------|------|--------|
| `cert_validity_days` | 証明書の有効期間（日数） | 高 |
| `cert_is_free_ca` | 無料CA（Let's Encrypt等）フラグ | 高 |
| `cert_has_org` | 組織情報（O=）の有無 | 高 |
| `cert_san_count` | SANエントリ数 | 中 |
| `cert_chain_depth` | 証明書チェーンの深さ | 低 |
| `cert_key_bits` | 公開鍵のビット長 | 低 |
| `cert_issuer_type` | 発行者タイプ（LE/Google/Cloudflare/Commercial） | 中 |
| `cert_serial_entropy` | シリアル番号のエントロピー | 低 |
| `cert_has_ext_key_usage` | Extended Key Usage拡張の有無 | 低 |
| `cert_issuer_country` | 発行者の国コード | 低 |
| ... | （他16種類） | |

### 3.2 XGBoostモデル

#### ハイパーパラメータ（Optuna最適化後）

```python
{
    "n_estimators": 500,
    "max_depth": 10,
    "learning_rate": 0.206,
    "min_child_weight": 6,
    "subsample": 0.77,
    "colsample_bytree": 0.70,
    "gamma": 2.38,
    "reg_alpha": 0.11,
    "reg_lambda": 2.37,
    "tree_method": "hist",
    "device": "cuda",
    "scale_pos_weight": 16.45  # クラス不均衡対応
}
```

#### 検証結果

| メトリクス | 初期モデル | Optuna最適化後 | 改善 |
|------------|------------|----------------|------|
| AUC | 0.9945 | **0.9973** | +0.28% |
| Validation Loss | 0.0312 | 0.0287 | -8.0% |

#### 特徴量追加の効果（2026-01-10実験）

6つの証明書特徴量を追加した結果：

| 追加特徴量 | AUC変化 |
|------------|---------|
| `cert_key_bits_normalized` | +0.05% |
| `cert_issuer_country_code` | +0.08% |
| `cert_serial_entropy` | +0.03% |
| `cert_has_ext_key_usage` | +0.04% |
| `cert_has_policies` | +0.02% |
| `cert_issuer_type` | +0.06% |
| **合計** | **+0.28%** |

### 3.3 Route1: 閾値による自動判定

#### Wilson信頼区間による閾値決定

単純に「確率 > 0.5ならPhishing」とするのではなく、統計的信頼区間を用いて「誤り率が許容範囲内に収まる」閾値を決定する。

Wilson信頼区間の上側境界は以下の式で計算される：

```
p̂_upper = (p̂ + z²/(2n) + z√(p̂(1-p̂)/n + z²/(4n²))) / (1 + z²/n)
```

ここで：
- p̂: 観測された誤り率
- n: サンプル数
- z: 信頼水準に対応するz値（95%信頼区間ではz=1.96）

#### 閾値決定の実例

```
t_low = 0.001 の決定根拠:
  - ml_probability ≤ 0.001 のサンプル数: 60,101件
  - そのうち実際のPhishing: 12件
  - 観測誤り率: 0.02%
  - Wilson上側95%信頼区間: 0.035%
  - 許容誤り率: 0.1%
  → 信頼区間が許容範囲内なので採用

t_high = 0.988 の決定根拠:
  - ml_probability ≥ 0.988 のサンプル数: 7,595件
  - そのうち実際のBenign: 0件
  - 観測誤り率: 0.0%
  - Wilson上側95%信頼区間: 0.05%
  - 許容誤り率: 0.02%
  → 信頼区間が許容範囲内なので採用
```

#### Route1の判定結果

| 判定 | 件数 | 割合 | 誤り件数 | 誤り率 |
|------|------|------|----------|--------|
| AUTO_BENIGN | 60,101 | 46.9% | 12 | 0.02% |
| AUTO_PHISHING | 7,595 | 5.9% | 0 | 0.00% |
| PENDING | 60,371 | 47.2% | - | - |

---

## 4. Stage2: 確信度による再評価

### 4.1 問題設定

Stage1で「PENDING」とされた60,371件をすべてStage3に送ると、処理時間が約134時間かかる。Stage2の目的は、この中から「本当に詳細調査が必要なケース」を選別し、Stage3の負荷を削減することである。

### 4.2 Defer（判断保留）モデル

#### アーキテクチャ

Out-of-Fold (OOF) 予測を用いたロジスティック回帰モデル：

```
入力特徴量（37次元）:
  - Stage1の35特徴量
  - p1_entropy: Stage1予測のエントロピー = -p*log(p) - (1-p)*log(1-p)
  - p1_uncertainty: Stage1予測の不確実性 = 4 * p * (1-p)

出力:
  - defer_score: [0, 1] の判断保留スコア
```

#### 追加特徴量の効果（2026-01-10実験）

| 特徴量構成 | Stage3 Handoff | 削減率 |
|------------|----------------|--------|
| 35特徴量のみ | 55,524件 | - |
| +entropy, +uncertainty | **34,848件** | **-37.2%** |

エントロピーと不確実性の追加により、Stage1の「迷い」を明示的にモデル化し、本当に判断が難しいケースを効率的に選別できるようになった。

### 4.3 優先度に基づく選別（segment_priority）

単純にdefer_score順ではなく、リスクの高いケースを優先的にStage3に送る方式を採用。

#### Priority Pool（最優先）

以下のいずれかに該当するケース：

1. **危険TLD**: `.icu`, `.top`, `.xyz`, `.buzz`, `.cc`, `.cn`, `.lat`, `.online`, `.shop` 等
2. **IDN（国際化ドメイン名）**: ホモグラフ攻撃の可能性
3. **ブランド名含有**: `paypal`, `amazon`, `apple` 等のキーワードを含む

#### Optional Pool（次優先）

- 未知のTLD
- defer_score >= tau（閾値）のケース

#### Scenario 5: Auto-BENIGNフィルター（2026-01-10追加）

Stage1のml_probabilityが非常に低く、かつdefer_scoreも低いケースは、Stage3をスキップして自動的にBENIGNと判定する：

```
条件: p1 < 0.15 AND defer_score < 0.4 → 自動BENIGN
```

| メトリクス | 適用前 | 適用後 | 変化 |
|------------|--------|--------|------|
| Stage3 Handoff | 36,489件 | **28,684件** | **-21.4%** |
| 追加FN | - | +87件 | +2.5% of Phishing |

87件の追加FNを分析した結果、43.7%は「短いドメイン + 正規TLD + ブランド名なし」という特徴で、Stage1/Stage2では本質的に検出困難なケースであった。

---

## 5. Stage3: LLMによる詳細分析

### 5.1 AI Agentアーキテクチャ

LangGraphを使用したマルチツールAI Agent：

```
┌─────────────────────────────────────────────────────────┐
│  AI Agent (Qwen3-14B-FP8 / vLLM)                        │
├─────────────────────────────────────────────────────────┤
│  ツール1: brand_impersonation_check                     │
│    - ブランド名との類似度計算                           │
│    - ロゴ・ファビコン検出                               │
│                                                         │
│  ツール2: certificate_analysis                          │
│    - DV/OV/EV証明書の判定                               │
│    - 発行者の信頼性評価                                 │
│                                                         │
│  ツール3: short_domain_analysis                         │
│    - TLDリスク評価                                      │
│    - ドメイン構造分析                                   │
│                                                         │
│  ツール4: contextual_risk_assessment                    │
│    - ツール結果の統合評価                               │
│    - ML Paradox検出                                     │
│    - 複合リスク判定                                     │
├─────────────────────────────────────────────────────────┤
│  Phase6 Policy Layer (llm_final_decision.py)            │
│    - R1〜R6ポリシールール適用                           │
│    - POST_LLM_FLIP_GATE（FP抑制）                       │
└─────────────────────────────────────────────────────────┘
```

### 5.2 ポリシールール詳細

LLMの判定に対して、明確なルールベースの調整を適用：

| ルール | 条件 | アクション |
|--------|------|------------|
| **R1** | ml < 0.20 AND free_ca AND no_org AND ctx >= 0.28 AND strong_evidence | → Phishing |
| **R2** | ml < 0.30 AND no_org AND (free_ca OR short) AND ctx >= 0.34 AND strong_evidence | → Phishing |
| **R3** | ml < 0.40 AND no_org AND short AND ctx >= 0.36 AND strong_evidence | → Phishing |
| **R4** | ml < 0.50 AND free_ca AND no_org AND ctx >= threshold AND strong_evidence | → Phishing |
| **R5** | ml < 0.50 AND dangerous_tld AND no_org AND ctx >= 0.33 | → Phishing |
| **R6** | ml < 0.30 AND dangerous_tld AND free_ca AND no_org AND ctx >= 0.35 | → Phishing |

**strong_evidence**の定義：
- brand_detected（ブランド検出）
- dangerous_tld（危険TLD）
- idn_homograph（IDNホモグラフ）
- random_pattern + (short OR dangerous_tld)
- self_signed（自己署名証明書）

### 5.3 ML Paradox検出

「ML Paradox」とは、Stage1が安全と判定（ml < 0.3）しているが、Stage2が要調査と判定（defer_score >= 0.8）している矛盾状態を指す。

#### 検出ロジック

```python
ml_paradox = (ml_probability < 0.3) and (defer_score >= 0.8)
ml_paradox_medium = (ml_probability < 0.3) and (0.5 <= defer_score < 0.8)
```

#### 検証結果（2026-01-11、210件テスト）

| TLD | テスト件数 | TP | FN | Recall |
|-----|-----------|----|----|--------|
| .cn | 61 | 40 | 5 | 88.9% |
| .top | 34 | 22 | 0 | 100.0% |
| .xyz | 29 | 6 | 1 | 85.7% |
| .icu | 12 | 10 | 0 | 100.0% |
| .cc | 22 | 10 | 2 | 83.3% |
| .lat | 9 | 8 | 1 | 88.9% |
| .online | 16 | 5 | 1 | 83.3% |
| .shop | 20 | 4 | 1 | 80.0% |
| **合計** | **210** | **108** | **11** | **90.8%** |

### 5.4 バグ修正とその効果（2026-01-11）

#### 問題1: Phase6ポリシーのバイパス

`langgraph_module.py`の`_final_decision_node`が、`llm_final_decision.py`のポリシー調整関数を経由せずにLLM出力を直接返していた。

```python
# 修正前（バグ）
asmt = self.so.final_assessment(domain, ml, tool_results)

# 修正後
asmt = phase6_final_decision(llm, domain, ml, tool_results, state)
```

#### 問題2: dangerous_tldリストの不整合

`short_domain_analysis.py`のデフォルトリストに`.cc`, `.lat`, `.online`, `.shop`, `.cn`等が含まれていなかった。

```python
# 修正後: always-dangerousリストをマージ
_always_dangerous = [
    "info","top","xyz","buzz","click","icu","download",
    "cc","lat","online","shop","cn","ws","pw","cfd","cyou","wang","bar","mw","live",
]
danger_def = list(set((dangerous_tlds or []) + _always_dangerous))
```

#### 修正効果

| メトリクス | 修正前 | 修正後 | 改善 |
|------------|--------|--------|------|
| Recall | 0% | **90.8%** | +90.8pt |
| Precision | N/A | 57.8% | - |
| F1 Score | 0 | **0.706** | +0.706 |

---

## 6. 総合性能評価

### 6.1 全体フロー別の判定結果

| 経路 | 件数 | Phishing | Benign | 誤り |
|------|------|----------|--------|------|
| Stage1 AUTO_BENIGN | 60,101 | 12 | 60,089 | 12 FN |
| Stage1 AUTO_PHISHING | 7,595 | 7,595 | 0 | 0 FP |
| Stage2 → Stage1採用 | 31,687 | 推定50 | 31,637 | 推定50 FN |
| Stage2 → Stage3 | 28,684 | 検証中 | 検証中 | - |

### 6.2 処理効率

| メトリクス | 値 |
|------------|------|
| Stage3処理件数 | 28,684件（全体の22.4%） |
| Stage3推定処理時間 | 約64時間 |
| 全件Stage3時の処理時間 | 約285時間 |
| **処理時間削減率** | **77.5%** |

### 6.3 研究期間中の改善履歴

| 日付 | 施策 | Stage3 Handoff | 累積削減率 |
|------|------|----------------|------------|
| 初期 | - | 55,524件 | - |
| 01/10 | Stage2 LR + entropy/uncertainty | 34,848件 | -37.2% |
| 01/10 | 証明書特徴量追加 | 36,489件* | -34.3% |
| 01/10 | Auto-BENIGNフィルター | **28,684件** | **-48.3%** |

*再学習により一時的に増加

---

## 7. 設計上の重要な判断

### 7.1 なぜ3段階なのか

2段階（ML + LLM）ではなく3段階とした理由：

1. **計算コストの最適化**: Stage1だけでは判断困難なケースが多く（47%）、すべてをLLMに送るとコストが膨大
2. **確信度の明示的モデル化**: Stage2で「確信度」を独立したモデルで評価することで、「MLが迷っているケース」を効率的に検出
3. **優先度の考慮**: 危険TLDやブランド偽装の可能性があるケースを優先的に詳細分析できる

### 7.2 なぜ閾値を2つ使うのか（t_low, t_high）

単一の閾値（例: 0.5）ではなく2つの閾値を使用する理由：

- **中間領域の明示化**: 0.001 < p < 0.988 の広い領域を「判断困難」として扱う
- **統計的保証**: 各閾値で誤り率の上限を保証できる
- **非対称なコスト**: FNとFPのコストが異なるため、別々の閾値で制御

### 7.3 Recallを重視する理由

Precision（適合率）よりもRecall（再現率）を重視している理由：

- **False Negative（見逃し）のコスト**: フィッシングサイトを安全と誤判定すると、ユーザーが被害に遭う
- **False Positive（誤検知）のコスト**: 正規サイトを危険と誤判定しても、追加確認で救済可能
- **運用上の対応**: FPは人間によるレビューで修正可能だが、FNは被害が発生してから発覚

---

## 8. 今後の課題

### 8.1 短期課題

- [ ] Stage3のスループット向上（並列化、バッチ処理）
- [ ] `.shop`, `.xyz` の Precision 改善（現状 21.1%, 25.0%）
- [ ] 統合テストの追加（ポリシーバイパス再発防止）

### 8.2 中期課題

- [ ] TLDリストの一元管理と自動更新
- [ ] フィードバックループの構築（誤判定の自動収集と再学習）
- [ ] 説明可能性の向上（判定理由の可視化）

### 8.3 長期課題

- [ ] リアルタイム処理への対応
- [ ] 多言語ブランド検出の強化
- [ ] 新種フィッシング手法への適応

---

## 9. 関連ドキュメント

- [02_spec.md](../02_spec.md): 技術仕様書（実装詳細、API仕様）
- [20260110.md](20260110.md): 研究日誌（用語定義、システム構成図、Stage2改善）
- [20260111.md](20260111.md): 研究日誌（ML Paradox、Phase6バグ修正）

---

## 付録A: 危険TLD一覧

本システムで「危険」として扱うTLD：

```
高リスク（フィッシング出現率 > 50%）:
  .icu, .top, .xyz, .buzz, .cfd, .cyou

中リスク（フィッシング出現率 10-50%）:
  .tk, .ml, .ga, .cf, .gq, .cc, .cn, .lat, .online, .shop

要注意（特定の攻撃パターンで使用）:
  .ws, .pw, .wang, .bar, .mw, .live, .click, .link, .site
```

## 付録B: ブランドキーワード抽出

LLM（Qwen3-14B）を使用して、PhishTank/JPCERTのフィッシングURLからブランド名を自動抽出：

```
抽出されたブランド例（上位20件）:
  paypal, amazon, apple, microsoft, google, facebook, netflix,
  instagram, whatsapp, linkedin, twitter, yahoo, ebay, wellsfargo,
  chase, bankofamerica, americanexpress, dhl, fedex, usps
```
