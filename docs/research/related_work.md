# 関連研究調査

調査日: 2026-01-25
更新日: 2026-02-06（引用監査に基づくCritical/Major/Minor修正適用、§13追加）

## 概要

本研究（3段カスケード型フィッシング検出: XGBoost → Gate → AI Agent (Qwen3-4B)）に関連する過去研究を、査読付き論文を中心に調査した。

---

## 1. マルチステージ ML+LLM ハイブリッド

### 1.1 Evolution of Phishing Detection with AI (arXiv, July 2025)
- **URL**: https://arxiv.org/html/2507.07406v1
- **内容**: ML/DL と量子化LLMの比較評価
- **主要結論**: ハイブリッドアプローチ（ML+LLM）が最適
- **関連性**: DeepSeek R1 Distill Qwen 14B (Q8_0) が 17GB VRAM で80%以上。LLMは文脈説明と敵対的攻撃耐性で優位、MLは速度で優位 → 両者の組み合わせを推奨
- **本研究との差異**: 本研究はカスケード（MLで絞ってからLLM）だが、この論文は並列/独立評価

### 1.2 A Two-Stage Deep Learning Framework for AI-Driven Phishing Email Detection (MDPI Computers, Dec 2025)
- **URL**: https://www.mdpi.com/2073-431X/14/12/523
- **査読**: あり (MDPI)
- **内容**: 第1段階で説得原理分類 → 第2段階でフィッシング判定
- **関連性**: 2段階構造のカスケードエラー伝播問題を指摘
- **本研究との差異**: メール対象、DLのみ（LLMエージェントなし）

### 1.3 A comprehensive dual-layer architecture for phishing and spam (Computers & Security, 2023)
- **URL**: https://www.sciencedirect.com/science/article/abs/pii/S0167404823002882
- **査読**: あり (Elsevier)
- **内容**: Layer 1 で軽量分類 → Layer 2 で詳細分析
- **関連性**: 本研究のStage1→Stage2/3と同じ思想
- **本研究との差異**: ANN/RNN/CNNの2層であり、LLMエージェントは不使用

---

## 2. LLMマルチエージェント型フィッシング検出

### 2.1 PhishDebate (arXiv, June 2025) ★重要
- **URL**: https://arxiv.org/html/2506.15656v1
- **内容**: 4専門エージェント (URL構造, HTML構造, コンテンツ意味, ブランド偽装) + Moderator + Judge
- **アーキテクチャ**:
  - URL Analyst Agent: ドメイン名、サブドメイン、URLパターンを分析
  - HTML Structure Agent: フォーム、JavaScript、iframeのコードレベル指標を分析
  - Content Semantic Agent: 言語的操作と緊急性戦術を検出
  - Brand Impersonation Agent: 無許可のブランド使用を識別
  - Moderator: 各ラウンド後の合意を評価
  - Judge: 全証拠に基づき最終判定
- **性能比較**:

| 手法 | Precision | Recall | F1 |
|------|-----------|--------|-----|
| Single Agent Direct | 60.57% | 97.40% | 74.69% |
| Chain of Thought | 88.61% | 93.40% | 90.94% |
| **PhishDebate (Multi-Agent)** | **90.57%** | **98.00%** | **94.14%** |
| PhishDebate (GPT-4o) | 94.97% | 98.20% | 96.56% |

- **Multi-Agentの優位性**:
  1. ハルシネーション削減（相互検証による）
  2. 透明性の高い判断根拠（各エージェントの分析が追跡可能）
  3. モジュール性（エージェントの追加・削除が容易）
  4. 早期終了メカニズム（合意形成で効率化）
- **関連性**: 本研究の AI Agent (brand_check, certificate_analysis, contextual_risk 等) と構造が類似
- **本研究との差異**: GPT-4レベルの大型LLM前提、全件にLLM適用（トリアージなし）、ページ内容取得が必要
- **示唆**: Single-Agent → Multi-Agent で F1が74.69% → 94.14%に大幅改善。本研究のアーキテクチャ改善の参考になる

### 2.2 MultiPhishGuard (arXiv, May 2025)
- **URL**: https://arxiv.org/html/2505.23803v1
- **内容**: メタデータ・本文・URLを並列に専門エージェントが分析、verdict + confidence + rationale を出力
- **関連性**: 本研究の Judge ノード（統合判定）に相当する Explanation Simplifier Agent
- **本研究との差異**: メール対象、大型LLM前提

### 2.3 Debate-Driven Multi-Agent LLMs (ISDFS 2025, March 2025)
- **URL**: https://arxiv.org/html/2503.22038v1
- **査読**: あり (IEEE ISDFS)
- **内容**: 2つのLLMエージェントが賛否議論、Judge が最終判定
- **関連性**: 多角的分析による精度向上
- **本研究との差異**: Debate型（賛否議論）vs 本研究のツール呼び出し型（順次分析）

---

## 3. 小型LLMによるフィッシング検出

### 3.1 Small Language Models for Phishing Website Detection (arXiv, Nov 2025)
- **URL**: https://arxiv.org/html/2511.15434v1
- **内容**: クラウドAPIのプライバシー・コスト問題 → ≤70B のローカルLLMを評価
- **関連性**: 本研究と同じ動機（ローカル推論、プライバシー保護）
- **本研究との差異**: LLM単体評価（カスケードなし）、HTMLベース分析

### 3.2 Improving Phishing Email Detection of Small LLMs (arXiv, May 2025)
- **URL**: https://arxiv.org/pdf/2505.00034
- **内容**: Qwen-2.5-1.5B, Phi-4-mini (3.8B), LLaMA-3.2 (3B) を評価
- **主要結果**: Qwen-2.5-1.5B はファインチューニングで精度 0.388 → 0.860 (122%向上)
- **関連性**: 単一RTX 3090で推論・FT可能（本研究の環境に近い）
- **本研究との差異**: メール対象、FT前提（本研究はプロンプトエンジニアリング + ツール呼び出し）

### 3.3 Benchmarking 21 Open-Source LLMs for Phishing URL Detection (MDPI Information, Apr 2025)
- **URL**: https://www.mdpi.com/2078-2489/16/5/366
- **査読**: あり (MDPI)
- **内容**: Qwen, Llama3, Gemma, DeepSeek 等 21モデルを4種のプロンプト技法で比較
- **主要結果**: Few-shot で21モデル平均 F1=82.6%（最高 91.24%, Llama3.3-70B）。9B以上のモデルが上位を占める
- **関連性**: 本研究 (Qwen3-4B, F1=72.5%) の性能比較のベンチマーク
- **本研究との差異**: LLM単体（カスケードなし）、URL文字列のみ入力

### 3.4 How Can We Effectively Use LLMs for Phishing Detection? (arXiv, Nov 2025)
- **URL**: https://arxiv.org/abs/2511.09606
- **内容**: 入力モダリティ（スクリーンショット, ロゴ, HTML, URL）の影響を評価
- **主要結果**: 商用LLMが93-95%精度、Qwenは最大92%
- **関連性**: スクリーンショット入力が最高精度（本研究はURL+証明書のみ）

### 3.5 Benchmarking LLMs for Zero-shot and Few-shot Phishing URL Detection (NeurIPS 2025 Workshop)
- **URL**: https://openreview.net/pdf?id=COmhlLFVk9
- **査読**: あり (NeurIPS Workshop)
- **内容**: GPT-4o, Claude-3-7-sonnet, Grok-3-Beta をゼロショット・フューショットで評価

---

## 4. 説明可能AI (XAI) によるフィッシング検出【2026-02-03追加】

### 4.1 EXPLICATE (arXiv, March 2025) ★重要
- **URL**: https://arxiv.org/html/2503.20796v1
- **内容**: ML検出 + SHAP/LIME説明 + LLM自然言語変換の3層アーキテクチャ
- **アーキテクチャ**:
  1. **ML Detection Layer**: ロジスティック回帰 + TF-IDF + NLP特徴量でフィッシング検出
  2. **Dual Explainability Layer**: LIME（単語レベル寄与）+ SHAP（概念レベルグループ化）
  3. **LLM Enhancement Layer**: DeepSeek v3で技術的説明を人間が読める形式に変換
- **性能**:
  - 検出精度: 98.4% (accuracy, precision, recall, F1全て)
  - 説明品質: Feature Mapping 94.2%、LLM-Model一貫性 96.8%
  - 可読性スコア: Flesch-Kincaid 68.3（一般ユーザーが理解可能）
- **実装**: GUIアプリ + Chrome拡張として展開
- **関連性**: 本研究のStage3が生成する`ai_reasoning`の品質向上に応用可能
- **本研究との差異**: メール対象、LLMは説明生成のみ（検出には不使用）
- **示唆**: 「検出精度」ではなく「説明品質」を評価指標とすることで研究の差別化が可能

### 4.2 IoT Phishing XAI (Springer Discover IoT, 2025)
- **URL**: https://link.springer.com/article/10.1007/s43926-025-00202-9
- **内容**: CNN-LSTM + SHAP-based XAI + LLM分析の統合
- **性能**:
  - CNN-LSTM: Web URL 93.26%, DistilBERT: テキスト/メール 98.64%
  - XAIによりFP率41%削減（従来手法比）
- **関連性**: XAIによるFP削減は本研究の課題（FP 560件）に直接関連
- **示唆**: SHAP統合でFP削減の可能性

### 4.3 Explainable Phishing for Sustainable Cyber Infrastructure (Nature Scientific Reports, 2025)
- **URL**: https://www.nature.com/articles/s41598-025-27984-w
- **内容**: XGBoost + LIME/SHAPによる解釈可能なフィッシング検出
- **主要結果**: XGBoostが高精度を達成 [要確認: 原論文では99.65%または99.17%の報告あり]、LIMEで特徴量重要度を可視化
- **関連性**: 本研究のStage1 (XGBoost) に直接適用可能

### 4.4 XAIの研究動向まとめ

| 観点 | 従来のML | XAI統合 |
|------|---------|---------|
| 判断根拠 | ブラックボックス | 透明性あり |
| 規制対応 | 困難 | GDPR等に準拠可能 |
| ユーザー信頼 | 低い | 高い（理由が分かる） |
| FP対応 | 困難 | 原因特定が容易 |
| SOC運用 | 自動判定のみ | アナリスト支援可能 |

**重要な知見**:
> "Regulatory frameworks require more and more AI-driven decisions that need to be explainable. Thus, black-box phishing detectors are no longer done by compliance-driven organizations." [出典要特定: EXPLICATE (R18) またはIoT Phishing XAI (R19) の本文から引用と推定されるが、該当箇所未確認]

---

## 5. Zero-Day / 未知攻撃検出【2026-02-03追加】

### 5.1 ZdAD-UML: Intelligent Zero-day Attack Detection (ScienceDirect, 2025)
- **URL**: https://www.sciencedirect.com/science/article/abs/pii/S0950705125008792
- **内容**: 教師なし学習によるゼロデイネットワーク侵入攻撃検出
- **手法**: 重複特徴に依存しない、ラベルなしデータでの学習
- **性能**: Random Forest-AE で標準評価上 F1 100%（未知データでは99.99%） [注: ネットワーク侵入検知であり、フィッシング固有ではない]
- **関連性**: 本研究の評価は「訓練データ内」の検証であり、真のゼロデイ評価ではない

### 5.2 Automated AI-Driven Phishing Detection for Zero-Day Attacks (eHaCON 2025, Springer, published 2026)
- **URL**: https://link.springer.com/chapter/10.1007/978-981-96-8632-2_16
- **内容**: NLP + 画像認識 + 異常検出を統合したゼロデイフィッシング検出
- **手法**: 教師あり・教師なし学習のハイブリッド + リアルタイム対策
- **関連性**: 本研究のStage3が持つ「意図分析」能力のゼロデイ活用

### 5.3 LLMによるゼロデイ検出の優位性

従来のML/DLの限界:
- 既知の攻撃パターンへの依存
- 署名ベース手法の限界
- データセット偏り

LLMの優位性:
- **意味理解**: 新しい言い回しでも攻撃意図を認識
- **ゼロショット能力**: 訓練データにないパターンにも対応
- **コンテキスト分析**: 文脈から不審な点を発見

**重要な知見**:
> "LLMs currently underperform compared to ML and DL methods in terms of raw accuracy, but exhibit strong potential for identifying subtle, context-based phishing cues." [出典要特定: Evolution of Phishing Detection with AI (R01) の結論と推定されるが、該当箇所未確認]

### 5.4 本研究への示唆

現在の評価方法の問題:
- 訓練/検証分割は「既知」のデータ
- MLが学習したパターンでの評価

真のゼロデイ評価に必要なアプローチ:
1. **時系列分割**: 2025年データで訓練 → 2026年データで評価
2. **LLM生成フィッシング**: GPT/Claude生成の新種攻撃への耐性
3. **未知ブランド**: 訓練時に存在しないブランドへの対応力

---

## 6. 多言語/クロスリンガル フィッシング検出【2026-02-03追加】

### 6.1 X-Phishing-Writer (ACM TALLIP, 2024)
- **URL**: https://dl.acm.org/doi/10.1145/3670402
- **内容**: クロスリンガルフィッシングメール生成フレームワーク
- **手法**: Multilingual T5 (mT5) による多言語フィッシング生成
- **言語**: 中国語、日本語、ベトナム語等（コーパスが少ない言語）
- **関連性**: 日本語フィッシングデータセット構築の参考

### 6.2 Multilingual Email Phishing Detection using OSINT and ML (arXiv, Jan 2025)
- **URL**: https://arxiv.org/html/2501.08723v1
- **内容**: 英語・アラビア語の多言語フィッシング検出
- **性能**: Random Forest が両言語で97.37%
- **課題**: "Most ML models feed on phishing indicators in English, hence limiting detectability in other languages"
- **関連性**: 日本語フィッシングへの直接的な適用可能性

### 6.3 Cross-lingual Detection Performance Issue ★重要発見

**[要出典確認]** 以下の数値は出典論文・実験条件の特定が必要（§6.1 X-Phishing-Writer または §6.2 Multilingual Email のいずれか、あるいは別の論文か要確認）:

| 言語 | Precision |
|------|-----------|
| 英語（ソース） | 66.7% |
| 翻訳後（ターゲット） | **14.8%** |

**Precision が 66.7% → 14.8% に激減** [出典要確認]

一般的に報告されているクロスリンガル転移の限界:
- 英語で訓練されたモデルは非英語の特徴を捉えられない
- 翻訳でフィッシング指標が保持されても、モデルは認識できない
- 言語固有の特徴（敬語、文字種混在等）が未学習

### 6.4 日本語フィッシング研究の現状

**研究ギャップ**:
- 英語中心の研究が大半
- 日本語フィッシング（ヤマト、佐川、楽天、アマゾン等）の学術研究は少ない
- 日本特有のブランド模倣パターンの体系的分析がない

**日本語フィッシングの特徴**:
- 運送会社（ヤマト、佐川、日本郵便）の不在通知偽装
- 銀行（三井住友、三菱UFJ、楽天銀行）のセキュリティ警告偽装
- ECサイト（Amazon、楽天市場）のアカウント確認偽装
- 敬語・丁寧語による「もっともらしさ」の演出

**本研究の強み**:
- 既に500+の日本語ブランドキーワードを実装
- 日本のフィッシング報告サイトからデータ収集可能
- 日本語特化研究で差別化可能

---

## 7. 知識拡張型フィッシング検出

### 7.1 KnowPhish (USENIX Security 2024) ★最重要
- **URL**: https://www.usenix.org/conference/usenixsecurity24/presentation/li-yuexin
- **arXiv**: https://arxiv.org/abs/2403.02253
- **GitHub**: https://github.com/imethanlee/KnowPhish
- **査読**: あり (USENIX Security, Top-tier)
- **内容**:
  - 20,000ブランドの多モーダル知識ベースを自動構築
  - Trancoドメインリスト + WHOIS でドメインバリアント収集
  - LLMでウェブページからブランド情報抽出
  - 既存検出器 (Phishpedia等) に plug-and-play で統合
- **関連性**: 本研究の Tranco Top 100K + brand_keywords 500+ 拡張と動機・手法が非常に類似
- **本研究との差異**:
  - KnowPhish: ロゴ画像ベース、ページ内容取得必須、クラウドAPI前提
  - 本研究: 証明書のみ（ドメイン名はCN/SANから抽出）、ページ取得不要、ローカルGPU完結

### 7.2 PhishIntel (ACM WWW 2025 Demo)
- KnowPhish の実運用向け展開システム
- 参照: https://dl.acm.org/doi/10.1145/3701716.3715192
- DOI: 10.1145/3701716.3715192

### 7.3 PhishAgent (AAAI 2025 Oral)
- **DOI**: 10.1609/aaai.v39i27.35003
- KnowPhish をベースにしたエージェント型検出器

### 7.4 A Study of Effectiveness of Brand Domain Identification Features (Springer, 2025)
- **URL**: https://link.springer.com/chapter/10.1007/978-3-032-01823-6_6
- **内容**: ブランドドメイン識別特徴量の有効性を2025年のデータで検証

---

## 8. 証明書特徴量によるフィッシング検出

### 8.1 Unmasking phishers: ML for malicious certificate detection (Computers & Industrial Eng., 2024)
- **URL**: https://www.sciencedirect.com/science/article/pii/S0360835224007745
- **査読**: あり (Elsevier)
- **内容**: 証明書 + ドメイン名特徴量で ML 検出
- **データ**: PhishTank + Tranco、Censys で証明書取得（本研究と同じデータソース）
- **主要結果**: 証明書のみ F1=0.77 → ドメイン名ベクトル追加で F1=0.89
- **関連性**: 本研究の Stage1 特徴量設計と直接的に関連

### 8.2 ML models for phishing detection from TLS traffic (Cluster Computing, 2023)
- **URL**: https://link.springer.com/article/10.1007/s10586-023-04042-6
- **査読**: あり (Springer)
- **内容**: TLS 1.2/1.3 トラフィックから特徴抽出（復号不要）

### 8.3 An effective detection approach for phishing websites (Nature Scientific Reports, 2022)
- **URL**: https://www.nature.com/articles/s41598-022-10841-5.pdf
- **査読**: あり (Nature)
- **内容**: URL + HTML + 証明書のハイブリッド特徴量、XGBoost で F1=96.38%

---

## 9. XGBoost によるフィッシングURL検出

### 9.1 Enhancing Phishing Detection: Integrating XGBoost with Feature Selection (SSRN, Jan 2025, 査読なし)
- **URL**: https://papers.ssrn.com/sol3/Delivery.cfm/04aedd64-6697-4f16-a533-f6aaa3f043a8-MECA.pdf?abstractid=5087049
- **内容**: XGBoost + 複数特徴選択技法のVoting、精度99.80%、MCC=0.996
- **データ**: PhishTank + UCI ML Repository

### 9.2 Phishing URL Detection Using XGBoost and Custom Feature Engineering (IJRASET)
- **URL**: https://www.ijraset.com/research-paper/phishing-url-detection-using-xgboost-and-custom-feature-engineering
- **内容**: URL長、ディレクトリ構造、SSL可否、ASN、ドメイン登録情報等13+特徴量
- **主要結果**: 精度97.27%、AUC=0.9957

---

## 10. 本研究の位置づけ

### 10.1 新規性マトリクス

| 観点 | 先行研究の主流 | 本研究 |
|------|--------------|--------|
| アーキテクチャ | 単一ML or 単一LLM | **3段カスケード (XGBoost→Gate→AI Agent)** |
| LLM規模 | GPT-4 / 14B+ (クラウドAPI) | **Qwen3-4B 量子化** (ローカル推論) |
| 入力情報 | URL + HTML + スクリーンショット | **証明書のみ** (ドメイン名はCN/SANから抽出、ページ取得不要) |
| 知識拡張 | ロゴ画像ベース (KnowPhish) | **ドメイン名ベース**: Tranco 100K + 多言語キーワード |
| 証明書活用 | ML特徴量のみ | **ML特徴量 (Stage1) + LLM解釈 (Stage3)** の二重活用 |
| コスト | クラウドAPI課金 | **消費者GPU (8-24GB)** で完結 |
| エージェント設計 | Debate型 (賛否議論) | **ツール呼び出し型** (構造化出力で順次実行) |
| トリアージ | なし（全件LLM処理） | **XGBoostで52%を高速処理** → LLMは残り48%のみ |

### 10.2 主要な差別化ポイント

1. **コスト効率**: XGBoost で容易な52%を除外し、高コストなLLM推論を48%に集中。既存研究は全件にLLMを適用するため、本研究は推論コストを約半分に削減。

2. **ページ取得不要**: KnowPhish (USENIX'24), PhishDebate 等はウェブページの内容取得が前提。本研究は証明書のみで判定（ドメイン名はCN/SANフィールドから抽出）するため、ダウン済みサイトやブロック済みURLにも適用可能。

3. **小型LLM + ツール呼び出し**: 4Bパラメータの量子化モデルで構造化出力（JSON）を生成し、各分析ツールを順次呼び出す設計。Debate型（PhishDebate）のような複数LLM同時推論が不要。

4. **証明書の二重活用**: 同一の証明書データを Stage1 では42次元の数値特徴量として、Stage3 では発行者・有効期間・SAN等をLLMが解釈するテキストとして活用。我々の調査範囲では、同一の証明書データをML特徴量とLLMテキスト入力として二重に活用する手法は報告されていない。

5. **早期検知（Pre-emptive Detection）**: 証明書発行時点でのPhishing候補検出により、サイト稼働前の予防的対策が可能。従来研究は稼働中サイトの検知が主。

### 10.3 証明書ベース早期検知の独自性【2026-02-05追加】

#### 検知タイミングの根本的な違い

| 観点 | 従来研究 | 本研究 |
|------|----------|--------|
| **検知タイミング** | サイト稼働後（被害発生後） | **サイト稼働前/直後** |
| **入力データ** | URL、HTML、スクリーンショット、ユーザー報告 | **証明書（CT Log）** |
| **検知対象** | 既知のPhishingサイト | **Phishing候補（誕生前）** |
| **対応可能性** | 被害軽減 | **被害予防** |

#### 証明書ベース検知の優位性

1. **先制検知**: Phishingサイトのライフサイクル「証明書発行 → サイト構築 → 被害発生」において、最初の段階で検知可能

2. **網羅性**: Certificate Transparency (CT) Logは公開義務があり、HTTPSを使用するPhishingサイトは証明書取得時に必ず露出

3. **早期警戒システム**: 「怪しい証明書」を監視することで、サイトが稼働する前にセキュリティチームへアラート

4. **ページ取得不要の利点**:
   - ダウン済み/ブロック済みサイトにも適用可能
   - 攻撃者によるクローキング回避
   - ネットワーク負荷・遅延なし

#### 実用シナリオ

| ユースケース | 従来アプローチ | 本研究のアプローチ |
|-------------|--------------|------------------|
| **SOC運用** | ユーザー報告待ち | CT Log監視で先制アラート |
| **ブランド保護** | 侵害発見後の対応 | 自社ブランド証明書の早期発見 |
| **ISP/CDN** | ブラックリスト反映待ち | 事前ブロック候補の特定 |

#### 論文での主張

> 「本研究で用いた証明書特徴はCT Logから取得可能であり、CT Log監視パイプラインと組み合わせることで、サイト稼働前の早期検知への応用が期待される。ただし、本研究の現時点での評価は収集済みデータに対する事後分類であり、リアルタイム早期検知の実証は今後の課題である。」

**注意**: 先制検知（Pre-emptive Detection）は本システムのアーキテクチャが原理的に対応可能であることを意味するが、現時点のシステムはCT Logのリアルタイム監視を実装しておらず、事後評価による性能検証のみ実施している。

---

## 11. 関連研究との性能比較【2026-02-04更新】

### 11.1 比較方法の注意点

**重要**: 本研究のStage3は「ハンドオフ候補」（MLが判断困難なケース）のみを処理する設計。
関連研究の多くは「全データ」（簡単なケース＋難しいケース）で評価している。

したがって、**Stage3単体の性能と他研究の全体性能を直接比較することは不適切**である。

公平な比較方法:
1. **システム全体 vs システム全体** で比較する
2. または、同一データセットで評価する（追加実験が必要）

### 11.2 システム全体での性能比較（参考値）

**注記**: 各研究は異なるデータセット・入力情報・評価条件で評価されており、直接的な優劣比較は困難である。参考値として並記する。

| 研究 | F1 | Precision | Recall | 入力情報 | モデル |
|------|-----|-----------|--------|---------|--------|
| **本研究 (Stage1+2+3)** | **98.60%** | 99.11% | 98.10% | 証明書のみ | XGBoost + Qwen3-4B |
| PhishDebate (Multi-Agent) | 94.14% | 90.57% | 98.00% | URL+HTML+Content | GPT-4o |
| PhishDebate (CoT) | 90.94% | 88.61% | 93.40% | URL+HTML+Content | GPT-4o |
| PhishDebate (Single-Agent) | 74.69% | 60.57% | 97.40% | URL+HTML+Content | GPT-4o |
| 21 LLMs Benchmark (Few-shot) | 82.6% | - | - | URL only | 9B+ LLMs |
| Unmasking Phishers | 89.0% | - | - | Cert+Domain | ML only |

**注記**: 本研究のF1はPhishDebateの報告値より4.5pp高いが、データセット・入力条件が異なるため直接比較は困難である。

### 11.3 Stage3（AI Agent）の役割と貢献

Stage3は「難しいケース専門家」として機能:

| 指標 | 値 |
|------|-----|
| 処理対象 | ハンドオフ候補 11,952件（全体の約20%） |
| Phishing検出数 | **1,491件** |
| Recall | 69.4%（難しいケースで） |
| Precision | 74.7% |
| F1 | 71.9% |

**重要**: Stage3がなければ、この1,491件のPhishingは全て見逃される。
Stage3の価値は「全体F1の改善」ではなく「難しいケースの救済」にある。

### 11.4 補足: Stage3単体と他研究のLLM単体比較

現時点ではデータセットが異なるため直接比較は困難。

| 研究 | F1 | 評価データ | 備考 |
|------|-----|-----------|------|
| **本研究 Stage3** | **71.9%** | 難しいケースのみ | 公平な比較には全データ評価が必要 |
| PhishDebate Single-Agent | 74.69% | 全データ | 難しいケースに限定すれば低下する可能性 |
| Small LLMs (1.5B FT) | 86.0% | 全データ | ファインチューニング済み |

**今後の課題**: Stage3を全データ（または5,000〜10,000件のランダムサンプル）で評価し、
公平な比較データを取得する（タスク #25）。

---

## 12. 研究方向性の検討【2026-02-03追加】

### 12.1 本研究の強み（関連研究との比較より）

| 観点 | 本研究 | 関連研究 |
|------|--------|---------|
| **システム全体F1** | 98.60% | PhishDebate: 94.14% |
| **ページ取得** | 不要 | 多くが必要 |
| **LLMコスト** | 20%のみLLM処理 | 100%LLM処理 |
| **ローカル推論** | 可能（4B量子化） | 多くがクラウドAPI |

### 12.2 AI Agentが価値を発揮できる領域（研究調査より）

| 領域 | MLの限界 | AI Agentの優位性 |
|------|---------|-----------------|
| **Explainability** | ブラックボックス | 人間が読める説明を生成 |
| **Zero-Day** | 既知パターン依存 | 意図分析で未知攻撃を検出 |
| **Multilingual** | 英語データ偏重 | 言語理解で多言語対応 |
| **Context** | 特徴量ベース | 文脈・意図を理解 |

### 12.3 研究方向性の選択肢

| 方向性 | 概要 | 実現性 | インパクト | 評価指標 |
|--------|------|--------|-----------|---------|
| **A: Explainability** | MLで検出、AIで理由説明 | 高 | 中 | 説明品質、可読性 |
| **B: Zero-Day** | 未知攻撃への対応力評価 | 中 | 高 | 時系列分割での検出率 |
| **C: 日本語特化** | 日本語フィッシング検出 | 高 | 中 | 日本語ブランド検出率 |
| **D: Multi-Agent** | PhishDebate型討論システム | 中 | 高 | Single vs Multi比較 |
| **E: Cost-Aware** | ML/AI使い分け最適化 | 中 | 中 | Cost-Adjusted F1 |

### 12.4 推奨する組み合わせ

**実現可能性重視: A + C（日本語フィッシングの説明可能な検出）**

理由:
1. 既存システムの大幅改修不要
2. 日本語フィッシング研究のギャップを埋める
3. 説明可能性は規制対応で需要増
4. 「検出精度」ではなく「説明品質」で評価可能

**学術的インパクト重視: B + D（Zero-Day攻撃に対するMulti-Agent Defense）**

理由:
1. LLM生成フィッシングへの対応は最先端テーマ
2. Multi-Agent討論は2025-2026の注目分野
3. Single→Multi で F1 74.7%→94.1%の改善実績（PhishDebate）

### 12.5 次のステップ

1. **研究テーマの選定**: 上記A-Eから選択
2. **関連研究の深掘り**: 選択テーマの最新論文精読
3. **評価プロトコル設計**: 新しい評価指標の定義
4. **実験計画策定**: データセット、比較対象の明確化

詳細な分析は `docs/analysis/research_direction_analysis.md` を参照。

---

## 13. TLS証明書ベースのフィッシング検出【2026-02-06追加】

本研究は TLS 証明書の特徴量（発行者、有効期間、SAN、組織情報等）を主要な入力情報としてフィッシング検出を行う。
同様に証明書をテーマとした関連研究を以下に整理する。

### 13.1 Certificate Transparency (CT) Logベース検出

#### 13.1.1 Phicious: Content-Agnostic Detection of Phishing Domains using CT and Passive DNS (RAID 2022) ★重要

- **著者**: Mashael AlSabah, Mohamed Nabeel, Yazan Boshmaf, Euijin Choo
- **URL**: https://dl.acm.org/doi/10.1145/3545948.3545958
- **査読**: あり (RAID, Top-tier)
- **内容**: CT ログと Passive DNS から80以上の特徴量を抽出し、ページ取得なしでフィッシングドメインを先制検知
- **主要結果**: サイト稼働前の段階で検知可能であることを実証
- **本研究との関連**:
  - 共通点: 証明書特徴 + ドメイン名特徴を使用、ページ取得不要、先制検知
  - 差異: ML単体（LLMエージェントなし）、Passive DNS併用（本研究は証明書のみ）

#### 13.1.2 Finding Phish in a Haystack: Pipeline for Phishing Classification on CT Logs (ARES 2021)

- **著者**: Bohdan Rudis et al.
- **URL**: https://dl.acm.org/doi/10.1145/3465481.3470111 | https://arxiv.org/abs/2106.12343
- **査読**: あり (ARES)
- **内容**: CT ログからデータセット作成→分類器訓練→リアルタイム分類のモジュラーパイプライン
- **主要結果**: CT ログのリアルタイム監視フレームワークを提供
- **本研究との関連**: パイプライン設計の参考。本研究は分類器にLLMエージェントを統合した点が差異

#### 13.1.3 Phish-Hook: Detecting Phishing Certificates Using CT Logs (SecureComm 2019)

- **著者**: Edona Fasllija, Hasan Ferit Eniser, Bernd Prunster
- **URL**: https://link.springer.com/chapter/10.1007/978-3-030-37231-6_18
- **査読**: あり (SecureComm 2019, Springer LNCS)
- **内容**: CT ログを入力とし、証明書属性（発行者、CN、有効期間）に基づくML分類 + ヒューリスティックスコアリング
- **主要結果**: フィッシングサイトの90%以上を正しく識別
- **本研究との関連**: 証明書属性ベーススコアリングの基礎論文。本研究の Stage1 特徴量設計と動機が共通

#### 13.1.4 Anomaly Detection in Certificate Transparency Logs (arXiv 2024)

- **著者**: Richard Ostertag, Martin Stanek
- **URL**: https://arxiv.org/abs/2405.05206
- **内容**: CT ログの X.509 証明書に対して Isolation Forest による教師なし異常検出。Google Xenon 2024 ログから12万件を分析
- **主要結果**: クラウドサービスの自動化スクリプトや設定ミスの証明書を異常として検出
- **本研究との関連**: 教師なしアプローチとして、ラベルなしデータでの証明書特徴活用を示す

#### 13.1.5 Graph-Based Phishing Domain Detection via Certificate-DNS Heterogeneous Networks (Preprints.org 2025, 査読なし)

- **URL**: https://www.preprints.org/manuscript/202512.2708
- **内容**: R-GCN（Relational Graph Convolutional Network）による異種グラフ検出。ドメイン・IP・証明書・レジストラのグラフ構造を310万ドメイン（21万フィッシング）で学習
- **主要結果**: ブラックリスト登録の24時間前に73%を検知。ドメイン文字列ベースラインと比較し Precision を15.6pp改善
- **本研究との関連**: 証明書の「再利用パターン」や共有インフラをグラフ特徴として活用。個別属性を超えた関係性の分析

---

### 13.2 証明書特徴量によるML検出

#### 13.2.1 Unmasking Phishers: ML for Malicious Certificate Detection (C&IE 2024)

- **著者**: Haraldsdottir et al.
- **URL**: https://www.sciencedirect.com/science/article/pii/S0360835224007745
- **査読**: あり (Elsevier)
- **内容**: 証明書属性 + ドメイン名ベクトル表現によるフィッシング検出。NLP・時系列深層学習を活用
- **主要結果**: 証明書のみ F1=0.77 → ドメイン名埋め込み追加で F1=0.89
- **本研究との関連**:
  - 共通点: 証明書特徴 + ドメイン名特徴の組み合わせ
  - 示唆: 証明書のみの F1=0.77 は本研究の Stage1（F1=0.9560）より低い → 本研究の特徴量設計の有効性を裏付け
  - 差異: ML単体（LLMなし）、ドメイン名をNLP埋め込みで表現（本研究は手設計特徴量 + LLM解釈）

#### 13.2.2 Machine Learning-Based Malicious X.509 Certificates' Detection (Applied Sciences 2021)

- **著者**: Kasim Oztoprak et al.
- **URL**: https://www.mdpi.com/2076-3417/11/5/2164
- **査読**: あり (MDPI)
- **内容**: X.509 証明書の属性（version, validity, issuer, SAN, self-signed, signature algorithm, public key）のみでML分類
- **主要結果**: アンサンブル平均精度 95.9%、SVM 98.2%
- **本研究との関連**: 本研究の Stage1 と同じ証明書フィールド（issuer, validity, SAN, organization）を使用。X.509 属性のみで高精度分類が可能であることを実証

#### 13.2.3 Identifying Phishing Websites Using the Patterns of TLS Certificates (EuroSPW 2020 / JCSM 2021) ★重要

- **著者**: Yuji Sakurai, Takuya Watanabe, Tetsuya Okuda, Mitsuaki Akiyama, **Tatsuya Mori**
- **URL**: https://journals.riverpublishers.com/index.php/JCSANDM/article/view/6111
- **原著**: https://ieeexplore.ieee.org/document/9229674/ (EuroSPW 2020)
- **査読**: あり (IEEE EuroSPW / JCSM)
- **EuroSPW版タイトル**: "Discovering HTTPSified Phishing Websites Using the TLS Certificates Footprints"
- **内容**: CT ログからフィッシングサイトの TLS 証明書を収集し、Common Name (FQDN) のクラスタリング分析。CN テンプレートにより未知のフィッシングサイトを発見
- **主要結果**: CN クラスタリングによりフィッシングキャンペーンの共有インフラを発見
- **本研究との関連**:
  - **共著者の森達哉教授は本研究と同じグループ**
  - 共通点: TLS 証明書の CN/SAN パターンによるフィッシング検出
  - 差異: クラスタリング（教師なし）vs 本研究の分類（教師あり + LLM）
  - 示唆: 本研究は Sakurai et al. の証明書パターン分析をML+LLMで発展させた位置づけ

#### 13.2.4 Malcertificate: Malicious Certificate Detection Algorithm Based on GCN (Applied Sciences 2022)

- **URL**: https://www.mdpi.com/2076-3417/12/9/4440
- **査読**: あり (MDPI)
- **内容**: 証明書データセットをグラフ構造に変換し、GCN（Graph Convolutional Network）で悪性証明書を分類
- **主要結果**: GCN 精度 97.41%（従来MLおよびDNNを上回る）
- **本研究との関連**: 証明書属性間の関係性をグラフで表現する新しいアプローチ

#### 13.2.5 Brand Domain Identification Features for Phishing Detection (Springer 2025)

- **URL**: https://link.springer.com/chapter/10.1007/978-3-032-01823-6_6 | https://arxiv.org/abs/2503.06487
- **査読**: あり (Springer)
- **内容**: ブランドドメイン識別特徴量（証明書 CN 情報、ロゴドメイン、フォームアクションドメイン等）の有効性を体系的に評価
- **主要結果**: Random Forest 精度 99.7%。**証明書 CN 情報がトップ特徴量の一つ**。CN 情報を含む3特徴量のみで 99.8% 達成
- **本研究との関連**: 証明書 CN 情報がフィッシング検出において最も有効な特徴量の一つであることを実証。本研究の CN/SAN ベースのブランド検出設計を支持

---

### 13.3 証明書ベース早期検知・ライフサイクル分析

#### 13.3.1 DomainDynamics: Lifecycle-Aware Risk Timeline Construction (CCNC 2025 / C&S 2025) ★重要

- **著者**: Daiki Chiba, Hiroki Nakano, Takashi Koide
- **URL**: https://arxiv.org/abs/2410.02096 | https://www.sciencedirect.com/science/article/pii/S0167404825000550
- **査読**: あり (IEEE CCNC / Computers & Security)
- **内容**: ドメインのライフサイクル（証明書発行→DNS変更→稼働→ブラックリスト登録）を時系列で分析し、各段階のリスクを評価
- **主要結果**: 検出率 82.58%、FPR 0.41%（85,000以上の実悪性ドメイン）。先行研究および商用サービスを上回る
- **本研究との関連**:
  - **日本の研究者チーム**（NTTセキュリティ）
  - 証明書発行タイミングをリスク評価の重要イベントとして使用
  - 差異: 時系列分析（本研究は単一時点のスナップショット分析）

#### 13.3.2 Certifiably Vulnerable: Using CT Logs for Target Reconnaissance (EuroS&P 2023)

- **著者**: Stijn Pletinckx et al.
- **URL**: https://ieeexplore.ieee.org/document/10190522/
- **査読**: あり (IEEE EuroS&P)
- **内容**: CT ログが攻撃者の偵察にも利用される二面性を調査。200日間のハニーポット実験
- **主要結果**: CT ログへの証明書公開後、数秒以内にネットワークプローブが到達。IPv6では制御群との差が顕著（2,700パケット vs 0）
- **本研究との関連**: CT ログベース検出の限界と攻撃者への情報漏洩リスクを提示。検出システム設計時の考慮事項

#### 13.3.3 Uninvited Guests: Identity and Behavior of CT Bots (USENIX Security 2022)

- **著者**: Brian Kondracki, Johnny So, Nick Nikiforakis
- **URL**: https://www.usenix.org/conference/usenixsecurity22/presentation/kondracki
- **査読**: あり (USENIX Security, Top-tier、**NSA Best Scientific Cybersecurity Paper 第11回 2023年ノミネート/2024年授与**)
- **内容**: CTPOT（分散ハニーポット）を構築し、CT ログを監視するボットの実態を調査。10週間で4,657証明書を作成、150万リクエスト・31,898ユニークIPを観測
- **主要結果**: CT ログが事実上の「新規ウェブサイト登録簿」として機能していることを実証
- **本研究との関連**: CT ログの監視エコシステムの理解。先制検知システム設計の文脈情報

#### 13.3.4 Certificate Transparency Revisited: Public Inspections on Third-party Monitors (NDSS 2024)

- **著者**: Aozhuo Sun et al.
- **URL**: https://www.ndss-symposium.org/ndss-paper/certificate-transparency-revisited-the-public-inspections-on-third-party-monitors/
- **査読**: あり (NDSS, Top-tier)
- **内容**: CT モニターの信頼性を検査するための "CT Watcher" を提案。6つの主要 CT モニターの実装バグと設計上の限界を発見
- **主要結果**: 4,000ドメインの試験運用で主要モニター間の不整合を検出
- **本研究との関連**: CT ログデータ自体の信頼性に関する課題。証明書ベース検出の前提条件

---

### 13.4 LLM/NLP + 証明書

#### 13.4.1 Using LLM Embeddings with Similarity Search for Botnet TLS Certificate Detection [手法名: C-BERT] (AISec/CCS 2024) ★重要

- **著者**: Kumar Shashwat, Francis Hahn, Stuart Millar, Xinming Ou
- **URL**: https://dl.acm.org/doi/10.1145/3689932.3694766
- **査読**: あり (AISec Workshop, ACM CCS併設)
- **内容**: TLS 証明書のテキストフィールドを LLM 埋め込み（C-BERT）でベクトル表現し、類似度検索でボットネット証明書を検出
- **主要結果**: F1=0.994（テストデータ）、ゼロデイ評価で平均 F1=0.946。推論時間 0.064ms/証明書。15万件の実証明書で13件のボットネット候補を特定
- **本研究との関連**:
  - 共通点: LLM を証明書の分析に適用する新しい方向性
  - 差異: ボットネット対象（フィッシングではない）、埋め込みベース（本研究はツール呼び出し型エージェント）
  - 示唆: 証明書テキストの LLM 表現が高い分類性能を持つことを実証。本研究の Stage3 における証明書解析ツールの設計を支持

---

### 13.5 TLS トラフィック分析

#### 13.5.1 ML Models for Phishing Detection from TLS Traffic (Cluster Computing 2023)

- **著者**: Kumar, M. et al.
- **URL**: https://link.springer.com/article/10.1007/s10586-023-04042-6
- **査読**: あり (Springer)
- **内容**: TLS 1.2/1.3 暗号化トラフィックから復号なしでフィッシング検出。9つの証明書特徴（version, validity, SAN count, extensions, self-signed, signature algorithm, public key）を使用
- **本研究との関連**: 本研究と同じ証明書フィールドを使用。暗号化トラフィックからの検出という応用先を示す

#### 13.5.2 Enhanced Malicious Traffic Detection Using TLS Features (JNSM 2024)

- **URL**: https://link.springer.com/article/10.1007/s10922-024-09847-3
- **査読**: あり (Springer)
- **内容**: TLS 特徴 + アンサンブル（DL, ML, Self-Attention）による多クラス分類（フィッシング/正規/マルウェア）
- **主要結果**: RF+LGBM+XGB アンサンブル精度 94.85%、Self-Attention 付き 96.71%

#### 13.5.3 Ensemble Learning for Detecting Phishing URLs in Encrypted TLS Traffic (Telecom. Systems 2024)

- **URL**: https://link.springer.com/article/10.1007/s11235-024-01229-z
- **査読**: あり (Springer)
- **内容**: DNN + LSTM + Random Forest のアンサンブルによる TLS トラフィックからのフィッシング検出
- **主要結果**: 精度 99.61%、Precision 99.80%、MCC 99.22%

---

### 13.6 CT 検査の限界と回避手法

#### 13.6.1 Effectiveness of CT Check and Other Datapoints in Countering Phishing (INDIACom 2023, IEEE)

- **URL**: https://ieeexplore.ieee.org/document/10112566/
- **査読**: あり (IEEE)
- **内容**: CT チェックによるフィッシング対策の有効性を評価。ワイルドカード SSL 証明書による CT チェック回避手法を報告
- **本研究との関連**: 証明書ベース検出の限界の理解。本研究の Stage2 でワイルドカード証明書を「正規運用の指標」として扱う設計との対比

---

### 13.7 証明書ベース研究のまとめ

#### 本研究の位置づけ

| 観点 | 先行研究の主流 | 本研究 |
|------|--------------|--------|
| **検出手法** | ML単体 or ヒューリスティック | **ML + Gate/Rule + LLM Agent の3段カスケード** |
| **証明書の活用方法** | ML特徴量のみ | **ML特徴量 (Stage1) + ルール判定 (Stage2) + LLM解釈 (Stage3) の三重活用** |
| **LLM統合** | C-BERT（埋め込みベース） | **ツール呼び出し型エージェント + ルールエンジン** |
| **先制検知** | Phicious（CT+pDNS） | **CT ログベース + ドメイン知識ルール** |
| **説明可能性** | なし or SHAP/LIME | **リスク要因 + ルール発火トレース + 自然言語reasoning** |

#### 証明書特徴量の有効性（他研究との比較）

| 研究 | 証明書のみ F1 | 拡張後 F1 | 拡張方法 |
|------|-----------|---------|--------|
| Haraldsdottir et al. (2024) | 0.77 | 0.89 | ドメイン名NLP埋め込み追加 |
| Oztoprak et al. (2021) | 0.96 (Acc) | - | X.509属性のみ |
| **本研究 Stage1** | **0.9560** | - | **証明書 + ドメイン構造特徴量** |
| **本研究 全体** | - | **0.9866** | **+ Gate/Rule + LLM Agent** |

証明書特徴量のみで F1 0.77-0.96 が達成可能であり、本研究の Stage1（F1 0.9560）はこの範囲の上位に位置する。さらに Stage2/Stage3 の追加により F1 0.9866 を達成しており、証明書データの多段階活用の有効性が確認された。

#### 重要な知見

1. **証明書ベース検出は確立した研究分野**: RAID, USENIX Security, NDSS, EuroS&P 等のトップ会議で発表されている
2. **Let's Encrypt 等の無料 DV 証明書がフィッシングの主要指標**: 複数の論文が issuer を最重要特徴量の一つと報告
3. **先制検知が可能**: ブラックリスト登録の24時間以上前に73%を検知可能（Graph-Based, 2025）
4. **LLM + 証明書の組み合わせは未開拓**: 我々の調査範囲では、LLMエージェントを証明書ベースのフィッシング検出に適用した研究は確認されなかった。C-BERT [R41] はLLM埋め込みを証明書分析に適用した先行事例だが、対象はボットネット検出である
5. **日本の関連研究**: Sakurai et al. (2020/2021, 森達哉教授グループ)、DomainDynamics (千葉ら, 2025, NTT) が直接的な関連研究

---

## 14. 参考文献一覧

**注**: 番号1-27は既存、28以降は2026-02-06追加分

1. Li, Y. et al., "KnowPhish: Large Language Models Meet Multimodal Knowledge Graphs for Enhancing Reference-Based Phishing Detection," USENIX Security 2024.
2. PhishDebate, "An LLM-Based Multi-Agent Framework for Phishing Website Detection," arXiv:2506.15656, 2025.
3. MultiPhishGuard, "An LLM-based Multi-Agent System for Phishing Email Detection," arXiv:2505.23803, 2025.
4. "Debate-Driven Multi-Agent LLMs for Phishing Email Detection," IEEE ISDFS 2025.
5. "Small Language Models for Phishing Website Detection," arXiv:2511.15434, 2025.
6. "Improving Phishing Email Detection Performance of Small Large Language Models," arXiv:2505.00034, 2025.
7. "Benchmarking 21 Open-Source Large Language Models for Phishing Link Detection," MDPI Information 16(5), 2025.
8. Ji, F. and Kim, D., "How Can We Effectively Use LLMs for Phishing Detection?," arXiv:2511.09606, 2025.
9. "Evolution of Phishing Detection with AI: A Comparative Review," arXiv:2507.07406, 2025.
10. "Unmasking phishers: ML for malicious certificate detection," Computers & Industrial Engineering, 2024.
11. "Machine learning models for phishing detection from TLS traffic," Cluster Computing, 2023.
12. "An effective detection approach for phishing websites," Nature Scientific Reports, 2022.
13. "A Two-Stage Deep Learning Framework for AI-Driven Phishing Email Detection," MDPI Computers 14(12), 2025.
14. "A comprehensive dual-layer architecture for phishing and spam email detection," Computers & Security, 2023.
15. "Enhancing Phishing Detection: Integrating XGBoost with Feature Selection," SSRN, 2025.
16. "Benchmarking Large Language Models for Zero-shot and Few-shot Phishing URL Detection," NeurIPS 2025 Workshop.
17. "Lightweight malicious URL detection using deep learning and large language models," Nature Scientific Reports, 2025.

### 2026-02-03 追加分

18. EXPLICATE, "Enhancing Phishing Detection through Explainable AI and LLM-Powered Interpretability," arXiv:2503.20796, 2025.
19. "Phishing detection in IoT: an integrated CNN-LSTM framework with explainable AI and LLM-enhanced analysis," Discover Internet of Things (Springer), 2025.
20. "Explainable phishing website detection for secure and sustainable cyber infrastructure," Nature Scientific Reports, 2025.
21. ZdAD-UML, "An intelligent zero-day attack detection system using unsupervised machine learning," Knowledge-Based Systems (ScienceDirect), 2025.
22. "Automated AI-Driven Phishing Detection and Countermeasures for Zero-Day Phishing Attacks," eHaCON 2025, Springer LNNS (published Jan 2026).
23. X-Phishing-Writer, "A Framework for Cross-lingual Phishing E-mail Generation," ACM TALLIP, 2024.
24. "Multilingual Email Phishing Attacks Detection using OSINT and Machine Learning," arXiv:2501.08723, 2025.
25. "When LLMs meet cybersecurity: a systematic literature review," Cybersecurity (Springer), 2025.
26. "Machine Learning and Neural Networks for Phishing Detection: A Systematic Review (2017–2024)," MDPI Electronics, 2025.
27. "Staying ahead of phishers: a review of recent advances and emerging methodologies," Artificial Intelligence Review (Springer), 2024.

### 2026-02-06 追加分（証明書ベース研究）

28. AlSabah, M., Nabeel, M., Boshmaf, Y., Choo, E.: "Content-Agnostic Detection of Phishing Domains using Certificate Transparency and Passive DNS," Proc. RAID 2022, https://dl.acm.org/doi/10.1145/3545948.3545958
29. Rudis, B. et al.: "Finding Phish in a Haystack: A Pipeline for Phishing Classification on Certificate Transparency Logs," Proc. ARES 2021, https://dl.acm.org/doi/10.1145/3465481.3470111
30. Fasllija, E., Eniser, H.F., Prunster, B.: "Phish-Hook: Detecting Phishing Certificates Using Certificate Transparency Logs," SecureComm 2019, Springer LNCS vol. 305, https://link.springer.com/chapter/10.1007/978-3-030-37231-6_18
31. Ostertag, R., Stanek, M.: "Anomaly Detection in Certificate Transparency Logs," arXiv:2405.05206, 2024.
32. "Graph-Based Phishing Domain Detection via Certificate-DNS Heterogeneous Networks," Preprints.org, December 2025, https://www.preprints.org/manuscript/202512.2708
33. Oztoprak, K. et al.: "Machine Learning-Based Malicious X.509 Certificates' Detection," Applied Sciences (MDPI) 11(5):2164, 2021. https://www.mdpi.com/2076-3417/11/5/2164
34. Sakurai, Y., Watanabe, T., Okuda, T., Akiyama, M., Mori, T.: "Identifying the Phishing Websites Using the Patterns of TLS Certificates," Journal of Cyber Security and Mobility 10(2):451-486, 2021. (Extended from IEEE EuroSPW 2020)
35. "Malcertificate: Malicious Certificate Detection Algorithm Based on GCN," Applied Sciences (MDPI) 12(9):4440, 2022.
36. Chiba, D., Nakano, H., Koide, T.: "DomainDynamics: Lifecycle-Aware Risk Timeline Construction for Domain Names," IEEE CCNC 2025 / Computers & Security, 2025. https://arxiv.org/abs/2410.02096
37. Pletinckx, S. et al.: "Certifiably Vulnerable: Using Certificate Transparency Logs for Target Reconnaissance," IEEE EuroS&P 2023. https://ieeexplore.ieee.org/document/10190522/
38. Kondracki, B., So, J., Nikiforakis, N.: "Uninvited Guests: Analyzing the Identity and Behavior of Certificate Transparency Bots," USENIX Security 2022. (NSA Best Scientific Cybersecurity Paper 2023)
39. Sun, A. et al.: "Certificate Transparency Revisited: The Public Inspections on Third-party Monitors," NDSS 2024.
40. Shashwat, K., Hahn, F., Millar, S., Ou, X.: "Using LLM Embeddings with Similarity Search for Botnet TLS Certificate Detection," AISec 2024 (ACM CCS Workshop). https://dl.acm.org/doi/10.1145/3689932.3694766
41. "Enhanced Malicious Traffic Detection in Encrypted Communication Using TLS Features and a Multi-class Classifier Ensemble," Journal of Network and Systems Management (Springer), 2024.
42. "An Ensemble Learning Approach for Detecting Phishing URLs in Encrypted TLS Traffic," Telecommunication Systems (Springer) 87(4), 2024.
43. "Effectiveness of Certificate Transparency (CT) Check and Other Datapoints in Countering Phishing Attacks," INDIACom 2023 (IEEE). https://ieeexplore.ieee.org/document/10112566/
44. "Leveraging Machine Learning to Proactively Identify Phishing Campaigns Before They Strike," Journal of Big Data (Springer) 12:124, 2025.
