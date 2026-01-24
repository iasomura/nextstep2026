# 関連研究調査

調査日: 2026-01-25

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

### 2.1 PhishDebate (arXiv, June 2025)
- **URL**: https://arxiv.org/html/2506.15656v1
- **内容**: 4専門エージェント (URL構造, HTML構造, コンテンツ意味, ブランド偽装) + Moderator + Judge
- **関連性**: 本研究の AI Agent (brand_check, certificate_analysis, contextual_risk 等) と構造が類似
- **本研究との差異**: GPT-4レベルの大型LLM前提、全件にLLM適用（トリアージなし）、ページ内容取得が必要

### 2.2 MultiPhishGuard (arXiv, May 2025 / ACM CCS 2025投稿)
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
- **主要結果**: Few-shot で平均 F1=82.6%、9B以上が最高性能
- **関連性**: 本研究 (Qwen3-4B, F1=72.5%) の性能比較のベンチマーク
- **本研究との差異**: LLM単体（カスケードなし）、URL文字列のみ入力

### 3.4 How Can We Effectively Use LLMs for Phishing Detection? (arXiv, Nov 2025)
- **URL**: https://arxiv.org/abs/2511.09606
- **内容**: 入力モダリティ（スクリーンショット, ロゴ, HTML, URL）の影響を評価
- **主要結果**: 商用LLMが93-95%精度、Qwenは最大92%
- **関連性**: スクリーンショット入力が最高精度（本研究はURL+証明書のみ）

### 3.5 Benchmarking LLMs for Zero-shot Phishing URL Detection (NeurIPS 2025 Workshop)
- **URL**: https://openreview.net/pdf?id=COmhlLFVk9
- **査読**: あり (NeurIPS Workshop)
- **内容**: GPT-4o, Claude-3-7-sonnet, Grok-3-Beta をゼロショットで評価

---

## 4. 知識拡張型フィッシング検出

### 4.1 KnowPhish (USENIX Security 2024) ★最重要
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
  - 本研究: ドメイン名+証明書のみ、ページ取得不要、ローカルGPU完結

### 4.2 PhishIntel (ACM WWW 2025 Demo)
- KnowPhish の実運用向け展開システム
- 参照: https://dl.acm.org/doi/10.5555/3698900.3698945

### 4.3 PhishAgent (AAAI 2025 Oral)
- KnowPhish をベースにしたエージェント型検出器

### 4.4 A Study of Effectiveness of Brand Domain Identification Features (Springer, 2025)
- **URL**: https://link.springer.com/chapter/10.1007/978-3-032-01823-6_6
- **内容**: ブランドドメイン識別特徴量の有効性を2025年のデータで検証

---

## 5. 証明書特徴量によるフィッシング検出

### 5.1 Unmasking phishers: ML for malicious certificate detection (Computers & Industrial Eng., 2024)
- **URL**: https://www.sciencedirect.com/science/article/pii/S0360835224007745
- **査読**: あり (Elsevier)
- **内容**: 証明書 + ドメイン名特徴量で ML 検出
- **データ**: PhishTank + Tranco、Censys で証明書取得（本研究と同じデータソース）
- **主要結果**: 証明書のみ F1=0.77 → ドメイン名ベクトル追加で F1=0.89
- **関連性**: 本研究の Stage1 特徴量設計と直接的に関連

### 5.2 ML models for phishing detection from TLS traffic (Cluster Computing, 2023)
- **URL**: https://link.springer.com/article/10.1007/s10586-023-04042-6
- **査読**: あり (Springer)
- **内容**: TLS 1.2/1.3 トラフィックから特徴抽出（復号不要）

### 5.3 An effective detection approach for phishing websites (Nature Scientific Reports, 2022)
- **URL**: https://www.nature.com/articles/s41598-022-10841-5.pdf
- **査読**: あり (Nature)
- **内容**: URL + HTML + 証明書のハイブリッド特徴量、XGBoost で F1=96.38%

---

## 6. XGBoost によるフィッシングURL検出

### 6.1 Enhancing Phishing Detection: Integrating XGBoost with Feature Selection (SSRN, Jan 2025)
- **URL**: https://papers.ssrn.com/sol3/Delivery.cfm/04aedd64-6697-4f16-a533-f6aaa3f043a8-MECA.pdf?abstractid=5087049
- **内容**: XGBoost + 複数特徴選択技法のVoting、精度99.80%、MCC=0.996
- **データ**: PhishTank + UCI ML Repository

### 6.2 Phishing URL Detection Using XGBoost and Custom Feature Engineering (IJRASET)
- **URL**: https://www.ijraset.com/research-paper/phishing-url-detection-using-xgboost-and-custom-feature-engineering
- **内容**: URL長、ディレクトリ構造、SSL可否、ASN、ドメイン登録情報等13+特徴量
- **主要結果**: 精度97.27%、AUC=0.9957

---

## 7. 本研究の位置づけ

### 7.1 新規性マトリクス

| 観点 | 先行研究の主流 | 本研究 |
|------|--------------|--------|
| アーキテクチャ | 単一ML or 単一LLM | **3段カスケード (XGBoost→Gate→AI Agent)** |
| LLM規模 | GPT-4 / 14B+ (クラウドAPI) | **Qwen3-4B 量子化** (ローカル推論) |
| 入力情報 | URL + HTML + スクリーンショット | **ドメイン名 + 証明書のみ** (ページ取得不要) |
| 知識拡張 | ロゴ画像ベース (KnowPhish) | **ドメイン名ベース**: Tranco 100K + 多言語キーワード |
| 証明書活用 | ML特徴量のみ | **ML特徴量 (Stage1) + LLM解釈 (Stage3)** の二重活用 |
| コスト | クラウドAPI課金 | **消費者GPU (8-24GB)** で完結 |
| エージェント設計 | Debate型 (賛否議論) | **ツール呼び出し型** (構造化出力で順次実行) |
| トリアージ | なし（全件LLM処理） | **XGBoostで52%を高速処理** → LLMは残り48%のみ |

### 7.2 主要な差別化ポイント

1. **コスト効率**: XGBoost で容易な52%を除外し、高コストなLLM推論を48%に集中。既存研究は全件にLLMを適用するため、本研究は推論コストを約半分に削減。

2. **ページ取得不要**: KnowPhish (USENIX'24), PhishDebate 等はウェブページの内容取得が前提。本研究はドメイン名と証明書のみで判定するため、ダウン済みサイトやブロック済みURLにも適用可能。

3. **小型LLM + ツール呼び出し**: 4Bパラメータの量子化モデルで構造化出力（JSON）を生成し、各分析ツールを順次呼び出す設計。Debate型（PhishDebate）のような複数LLM同時推論が不要。

4. **証明書の二重活用**: 同一の証明書データを Stage1 では42次元の数値特徴量として、Stage3 では発行者・有効期間・SAN等をLLMが解釈するテキストとして活用。この二重利用は先行研究に見られない。

---

## 8. 参考文献一覧

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
16. "Benchmarking Large Language Models for Zero-shot Phishing URL Detection," NeurIPS 2025 Workshop.
17. "Lightweight malicious URL detection using deep learning and large language models," Nature Scientific Reports, 2025.
