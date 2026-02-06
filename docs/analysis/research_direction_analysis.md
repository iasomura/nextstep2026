# フィッシング検出研究の方向性分析

**作成日**: 2026-02-03
**目的**: AI Agentの追加価値がF1 ±0.00ppという結果を受け、研究として成立させるための方向性を検討

---

## 1. 現状の問題

### 1.1 評価結果

| 指標 | ML単体 | システム全体 | 差分 |
|------|--------|-------------|------|
| Precision | 99.48% | 99.11% | -0.38pp |
| Recall | 97.74% | 98.10% | +0.36pp |
| **F1** | **98.60%** | **98.60%** | **±0.00pp** |

### 1.2 問題点

1. **ML（XGBoost）が既に非常に優秀**: F1 98.6%を達成
2. **AI Agentの追加価値がほぼゼロ**: 統計的に有意な改善なし
3. **コスト効率が悪い**: 11,920件のLLM処理で改善なし

### 1.3 このままでは研究として成立しない理由

> "We added an AI Agent to ML-based phishing detection, but it didn't improve anything."

これは**ネガティブリザルト**であり、そのままでは学術的貢献が限定的。

---

## 2. 世界の研究動向

### 2.1 主要な研究アプローチ

| アプローチ | 代表研究 | 精度 | 特徴 |
|-----------|---------|------|------|
| Multi-Agent Debate | [PhishDebate](https://arxiv.org/html/2506.15656v1) | F1 96.6% | 4専門エージェント + 討論 |
| ML + XAI + LLM | [EXPLICATE](https://arxiv.org/html/2503.20796v1) | 98.4% | SHAP/LIME + LLMで説明生成 |
| CNN-LSTM + XAI | [IoT Phishing](https://link.springer.com/article/10.1007/s43926-025-00202-9) | 98.64% | FP率41%削減（XAIにより） |
| Zero-Day Detection | [ZdAD-UML](https://www.sciencedirect.com/science/article/abs/pii/S0950705125008792) | 100% | 教師なし学習 |

### 2.2 AI Agentが優位性を持つ領域

研究から明らかになった**AI Agentの強み**:

1. **Explainability（説明可能性）**
   - MLの"ブラックボックス"問題を解決
   - SOCアナリストが判断理由を理解可能
   - 規制対応（GDPR等）で必須化の傾向

2. **Zero-Day/Novel Attack Detection**
   - 既知パターンに依存しない検出
   - LLMの言語理解による意図分析
   - 署名ベース手法の限界を克服

3. **Contextual Reasoning（文脈理解）**
   - ブランド模倣の微妙なニュアンス
   - 緊急性を煽る文言の検出
   - 多言語での攻撃意図分析

4. **Adaptability（適応性）**
   - 継続学習による進化
   - 新しい攻撃パターンへの対応
   - 強化学習による自己改善

5. **Multi-Lingual Support（多言語対応）**
   - 英語以外の言語でのML限界
   - 日本語フィッシングは研究が少ない

### 2.3 MLが優位な領域

1. **高速処理**: LLMより約138万倍高速
2. **大量処理**: 全メール/URLをスキャン
3. **コスト効率**: 推論コストが低い
4. **安定性**: ハルシネーションなし

---

## 3. 研究として成立させる方向性

### 3.1 方向性A: Explainability（説明可能性）に焦点

**コンセプト**: MLで検出し、AI Agentで「なぜ危険か」を説明

```
[User] → [ML Detection (98.6%)] → [Phishing?]
                                      ↓ Yes
                              [AI Agent: Why?]
                                      ↓
                              [Human-Readable Explanation]
```

**研究貢献**:
- MLの精度を維持しつつ、判断根拠を提供
- SOCアナリストの判断支援
- 「検出精度」ではなく「説明品質」を評価指標に

**参考**: EXPLICATE (SHAP + LIME + LLM)

**評価指標案**:
- 説明の正確性（専門家評価）
- 説明の理解しやすさ（Flesch-Kincaid等）
- SOCアナリストの判断時間短縮

### 3.2 方向性B: Zero-Day/Novel Attack Detection

**コンセプト**: 訓練データにない新種の攻撃をAI Agentで検出

**問題**: 現在の評価はMLの訓練/検証データを使用しており、「既知」の攻撃

**必要なアプローチ**:
1. 時系列分割: 古いデータで訓練 → 新しいデータで評価
2. LLM生成フィッシングへの耐性テスト
3. 未知ブランドへの対応力評価

**研究貢献**:
- MLが見たことのないパターンでの検出力
- 敵対的攻撃への耐性

### 3.3 方向性C: 日本語/多言語フィッシング検出

**コンセプト**: 英語中心の研究では見落とされている日本語フィッシング

**背景**:
- 多くの研究は英語データセットに依存
- 日本語フィッシング（ヤマト、佐川、楽天等）は独自の特徴
- Cross-lingual transfer learningの性能低下（Precision 66.7% → 14.8%）

**研究貢献**:
- 日本語ブランド検出の精度向上
- 英語→日本語の転移学習限界の明確化
- 日本語固有の言語特徴（敬語、漢字混じり等）の活用

**データセット**: 既存の日本語フィッシングサンプル + 新規収集

### 3.4 方向性D: Multi-Agent Debate Architecture

**コンセプト**: PhishDebate的な複数エージェント討論システム

**現システムとの違い**:
- 現在: 1エージェントが複数ツールを使用
- 提案: 専門エージェントが独立分析 → 討論 → 合意形成

```
[URL Agent] ────────┐
[HTML Agent] ───────┤
[Content Agent] ────┼→ [Moderator] → [Judge] → Final Decision
[Brand Agent] ──────┤
[Cert Agent] ───────┘
```

**研究貢献**:
- Single-Agent vs Multi-Agent の比較
- ハルシネーション削減効果
- 各エージェントの寄与度分析

**参考**: PhishDebate (Single Agent 74.7% → Multi-Agent 94.1%)

### 3.5 方向性E: Cost-Aware Hybrid System

**コンセプト**: いつMLを使い、いつAI Agentを使うかの最適化

**問題**: 全件AI Agent処理は非効率（138万倍遅い）

**研究貢献**:
- ML確信度に基づくルーティング戦略
- コスト vs 精度のトレードオフ分析
- 処理時間制約下での最適配分

**評価指標**:
- Cost-Adjusted F1: F1 / (処理コスト)
- Time-to-Detection: 検出までの時間
- Resource Efficiency: TP / (LLM API呼び出し数)

---

## 4. 推奨: 方向性の組み合わせ

### 4.1 最も実現可能性が高い組み合わせ

**A + C: 日本語フィッシングの説明可能な検出**

理由:
1. 既存システムの改修が少ない
2. 日本語フィッシング研究のギャップを埋める
3. 説明可能性は規制対応で需要あり
4. データ収集が比較的容易（日本のフィッシング報告サイト）

### 4.2 学術的インパクトが高い組み合わせ

**B + D: Zero-Day攻撃に対するMulti-Agent Defense**

理由:
1. LLM生成フィッシングへの対応は最先端
2. Multi-Agent系は2025-2026で注目
3. 敵対的環境での評価は新規性あり

---

## 5. 具体的な次のステップ

### Step 1: 研究テーマの選定（1週間）

以下から選択:
- [ ] A: Explainability Focus
- [ ] B: Zero-Day Detection
- [ ] C: Japanese/Multilingual
- [ ] D: Multi-Agent Debate
- [ ] E: Cost-Aware Hybrid

### Step 2: 関連研究の詳細調査（2週間）

選択したテーマの:
- 最新論文の精読
- ベースラインの特定
- 評価指標の決定

### Step 3: 実験計画の策定（1週間）

- データセット準備
- 評価プロトコル設計
- 比較対象の明確化

---

## 6. 参考文献

### Multi-Agent / LLM-Based Detection
- [PhishDebate](https://arxiv.org/html/2506.15656v1) - Multi-Agent LLM Framework (2025)
- [MultiPhishGuard](https://arxiv.org/html/2505.23803v1) - Multi-Agent Email Detection (2025)

### Explainable AI
- [EXPLICATE](https://arxiv.org/html/2503.20796v1) - XAI + LLM Interpretability (2025)
- [IoT Phishing XAI](https://link.springer.com/article/10.1007/s43926-025-00202-9) - CNN-LSTM + SHAP (2025)

### Zero-Day Detection
- [ZdAD-UML](https://www.sciencedirect.com/science/article/abs/pii/S0950705125008792) - Unsupervised Zero-Day (2025)
- [Explainable Zero-Day IoT](https://link.springer.com/article/10.1007/s43926-025-00184-8) - Attention Fusion (2025)

### Multilingual / Cross-lingual
- [X-Phishing-Writer](https://dl.acm.org/doi/10.1145/3670402) - Cross-lingual Generation (2024)
- [Multilingual OSINT](https://arxiv.org/html/2501.08723v1) - Multi-language ML (2025)

### Survey Papers
- [ML/NN Systematic Review 2017-2024](https://www.mdpi.com/2079-9292/14/18/3744) - MDPI Electronics (2025)
- [LLMs meet Cybersecurity](https://link.springer.com/article/10.1186/s42400-025-00361-w) - Springer Cybersecurity (2025)
- [AI Phishing Bibliometric Review](https://pmc.ncbi.nlm.nih.gov/articles/PMC12589022/) - Frontiers AI (2025)

---

## 変更履歴

- 2026-02-03: 初版作成
