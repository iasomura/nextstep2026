# Stage3 判定合理性分析

作成日: 2026-02-04
評価データ: 11,936件（全件回帰テスト結果）

---

## 1. 概要

| 分類 | 件数 | 割合 |
|------|------|------|
| FP (誤検出) | 574 | 4.8% |
| FN (見逃し) | 750 | 6.3% |

---

## 2. FP分析（正規サイトをPhishingと誤判定）

### 2.1 主要な問題パターン

| 問題 | 件数 | 割合 | 説明 |
|------|------|------|------|
| **reasoningで「legitimate」と言及しながらPhishing判定** | 487 | 84.8% | LLMは正しく認識しているがルールが上書き |
| brand_risk_score=0 なのにPhishing判定 | 414 | 72.1% | ブランドなしなのに過剰検出 |
| ctx_risk_score < 0.4 なのにPhishing判定 | 225 | 39.2% | 低リスクなのに過剰検出 |

### 2.2 発火ルール分析

| ルール | 件数 | 割合 | 問題点 |
|--------|------|------|--------|
| policy_r4 | 290 | 50.5% | 最も多くFPを引き起こす |
| policy_r2 | 233 | 40.6% | 同上 |
| policy_r1 | 207 | 36.1% | 同上 |
| benign_cert_gate_skip | 157 | 27.4% | ブランド検出時のゲートスキップ |
| brand_cert_high | 157 | 27.4% | ブランド+証明書ルール |
| very_high_ml_override | 20 | 3.5% | ML>=0.85で無条件Phishing化 |

### 2.3 致命的な問題: LLM判断をルールが上書き

**例: elements.envato.com**

- LLM Reasoning: "a legitimate subdomain of envato.com", "well-known legitimate platform", "Tranco rank 2151"
- 発火ルール: `[very_high_ml_override]` ML=0.879 >= 0.85
- **結果**: Phishing判定（confidence: 0.95）
- **実際**: Benign（正規サイト）

**問題**: LLMが正しく「legitimate」と認識しているのに、`very_high_ml_override`ルールが**無条件で**Phishing判定に上書きしている。

### 2.4 FP TLD分布

| TLD | 件数 | 割合 | 備考 |
|-----|------|------|------|
| com | 205 | 35.7% | 正規サイトも多い |
| xyz | 33 | 5.7% | 危険TLDだが正規サイトも存在 |
| org | 31 | 5.4% | 非営利組織サイト |
| top | 28 | 4.9% | 危険TLD |
| online | 25 | 4.4% | 危険TLD |

---

## 3. FN分析（PhishingをBenignと誤判定）

### 3.1 主要な問題パターン

| 問題 | 件数 | 割合 | 説明 |
|------|------|------|------|
| **"below threshold"で見逃し** | 603 | 80.4% | リスクスコアが閾値未満 |
| **"no detected brands"で見逃し** | 491 | 65.5% | ブランド検出失敗 |
| **"benign_cert_mitigation"で見逃し** | 432 | 57.6% | CRL DPで過剰緩和 |
| **"legitimate TLD"で見逃し** | 430 | 57.3% | TLD分類の誤り |

### 3.2 ブランド検出失敗の詳細

| FNドメイン | 含まれるキーワード | brand_risk_score | 問題 |
|------------|------------------|------------------|------|
| myjcb-open.com | jcb | 0.0 | **JCBブランド未検出** |
| jcbrocl.com | jcb | 0.0 | JCBブランド未検出 |
| authenticationaua.shop | auth | 0.0 | 認証系キーワード未検出 |
| ulys-support.com | support | 0.0 | サポート系キーワード未検出 |
| kecbank.com | bank | 0.0 | 銀行キーワード未検出 |
| saccount-members.com | account | 0.0 | アカウント系キーワード未検出 |

### 3.3 致命的な問題: CRL DP過剰緩和

**例: myjcb-open.com**

- ドメイン: `myjcb-open.com` （明らかにJCBを騙る）
- ML: 0.647（高め）
- LLM Reasoning: "benign_cert_mitigation (CRL distribution point)"で緩和
- **結果**: Benign判定（confidence: 0.75）
- **実際**: Phishing

**問題**: CRL Distribution Pointがあるだけで「benign_cert_mitigation」として扱い、他のリスクシグナルを打ち消している。

### 3.4 致命的な問題: TLD誤分類

**例: authenticationaua.shop**

- ドメイン: `authenticationaua.shop`
- TLD: .shop（**危険TLD**）
- ML: 0.674（高め）
- LLM Reasoning: "The TLD 'shop' is legitimate"
- **結果**: Benign判定
- **実際**: Phishing

**問題**: `.shop`を「legitimate」と誤分類している。

### 3.5 FN TLD分布

| TLD | 件数 | 割合 | 備考 |
|-----|------|------|------|
| com | 539 | 71.9% | ほとんどが.comで見逃し |
| cn | 29 | 3.9% | 中国TLD |
| net | 21 | 2.8% | |
| br | 11 | 1.5% | ブラジルTLD |

---

## 4. 根本原因分析

### 4.1 FPの根本原因

1. **ルールがLLM判断を無視**
   - LLMが「legitimate」と正しく認識しても、`very_high_ml_override`等のルールが上書き
   - 84.8%のFPがこのパターン

2. **policy_r1/r2/r4の過剰発火**
   - これらのルールがFPの40-50%を引き起こしている
   - 条件が緩すぎる可能性

### 4.2 FNの根本原因

1. **ブランド検出の失敗**
   - JCB, bank, auth等の明らかなキーワードを検出できていない
   - 65.5%のFNで「no detected brands」

2. **CRL DP過剰緩和**
   - CRL Distribution Pointがあるだけで「benign」と判断
   - 57.6%のFNがこの緩和で見逃し

3. **TLD分類の誤り**
   - .shopを「legitimate」と分類
   - 57.3%のFNで「legitimate TLD」言及

4. **閾値が高すぎる**
   - 80.4%のFNが「below threshold」
   - ctx_risk_score 0.4-0.5のケースが見逃されている

---

## 5. 改善提案

### 5.1 FP削減

| 改善案 | 期待効果 | リスク |
|--------|---------|--------|
| very_high_ml_override にLLM判断チェック追加 | FP -19件 | 複雑化 |
| policy_r1/r2/r4 の条件厳格化 | FP大幅削減 | FN増加リスク |
| Tranco Top 100K ドメインの除外強化 | FP削減 | 低リスク |

### 5.2 FN削減

| 改善案 | 期待効果 | リスク |
|--------|---------|--------|
| ブランドキーワード追加（jcb, auth, bank等） | FN -24件以上 | FP増加リスク |
| CRL DP緩和の条件追加（他のリスクがある場合は緩和しない） | FN大幅削減 | 実装複雑 |
| .shopを危険TLDに追加 | FN削減 | 低リスク |
| ctx_risk_score閾値の引き下げ（0.4 → 0.35） | FN削減 | FP増加リスク |

---

## 6. 結論

### 6.1 判定の合理性評価

| 観点 | 評価 | 理由 |
|------|------|------|
| **LLMの判断能力** | ○ 良好 | 84.8%のFPでLLMは「legitimate」と正しく認識 |
| **ルールシステム** | × 問題あり | LLM判断を無視して上書きするケースが多い |
| **ブランド検出** | × 問題あり | 明らかなブランドキーワードを検出できていない |
| **証明書緩和ロジック** | × 問題あり | CRL DPで過剰に緩和している |

### 6.2 優先改善項目

1. **最優先**: ブランドキーワード追加（jcb, auth, bank, support, account）
2. **高優先**: CRL DP緩和条件の見直し
3. **中優先**: policy_r1/r2/r4の条件見直し
4. **低優先**: very_high_ml_override のLLM判断チェック追加

### 6.3 総合評価

**LLM自体の判断は合理的だが、ルールシステムがそれを上書きしてしまうことが多い。**

特に:
- FPの84.8%はLLMが正しく「legitimate」と認識しているのにルールが上書き
- FNの65.5%はブランド検出の失敗が原因

ルールとLLMの連携を改善することで、F1 +3-5ppの向上が期待できる。
