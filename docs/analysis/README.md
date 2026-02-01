# 分析・検証ドキュメント

このディレクトリには、システムの各コンポーネントの検証結果とその実行に使用したプログラムを格納します。

更新日: 2026-02-01

## ディレクトリ構成

```
docs/analysis/
├── README.md                           # このファイル
├── 01_baseline_analysis.md             # ベースライン分析（統合版）
├── 02_improvement_analysis.md          # ★メイン: 改善効果分析・やることリスト
├── 03_certificate_analysis.md          # 証明書特徴量の分析レポート
├── 04_stage3_certificate_analysis.md   # Stage3証明書分析レポート
├── 05_feature_candidates.md            # 特徴量候補メモ
├── fnfp_analysis_20260201.md           # ★NEW: 全件評価FN/FP詳細分析
├── fn_gsb_verification/                # False Negative のGoogle Safe Browsing検証
├── stage2_independent_eval/            # Stage2証明書ルールの独立評価
└── stage3_experiments/                 # Stage3 AI Agent実験結果
```

---

## 主要ドキュメント

### 01_baseline_analysis.md

**目的**: ベースライン性能の定義と分析

**統合元**:
- baseline_comparison.md
- baseline_fnfp_analysis_20260128.md

**内容**:
- CSS2025 Paper ベンチマーク (F1: 0.9845)
- System Baseline 定義 (F1: 0.6426)
- データソース別分析
- シグナル分析 (FN/FPの特徴)
- 証明書特徴量分析
- チューニング履歴サマリ

**主な発見**:
- FNの80.2%はシグナル無し - 特徴量ベースでは検出困難
- FPの39.0%はシグナル無し - AIの過剰検出
- 証明書特徴量はFN/TN区別に有効でない

---

### 02_improvement_analysis.md (メイン)

**目的**: AI Agent改善の効果分析・チューニング記録

**統合元**:
- improvement_analysis_20260128.md (本体)
- Appendix A: tuning_insights_20260127.md
- Appendix B: undetectable_fn_1111_analysis.txt

**内容**:
- FP/FN詳細分析（問題のメカニズム）
- 改善項目の効果測定
- やることリスト（優先度付き）
- 変更履歴
- チューニング知見 (Appendix A)
- 検出不能FN分析 (Appendix B)

**最新の分析結果** (2026-02-01 全件評価):

| 指標 | 値 |
|------|-----|
| F1 Score | **68.87%** |
| Precision | 72.81% |
| Recall | 65.33% |
| TP | 1,781件 |
| FP | 665件 |
| FN | 945件 |
| TN | 12,239件 |

**主な発見**:
- fuzzy/fuzzy2 ブランドマッチの TP/FP比 が問題（0.46-0.67）
- POST_LLM_FLIP_GATE が TN 1,003件を保護
- FNの38%（361件）は外部情報なしでは検出不可能

---

### fnfp_analysis_20260201.md (NEW)

**目的**: 全件評価（15,630件）のFN/FP詳細分析とトレードオフ評価

**内容**:
- FN/FPのカテゴリ分類と特性分析
- ルール別 TP/FP 比（トレードオフ評価）
- ブランドマッチタイプ別分析
- POST_LLM_FLIP_GATE の役割分析
- トレードオフシミュレーション
- 推奨アクション

**主な発見**:
- fuzzy/fuzzy2 無効化で F1 +0.55pp 改善可能
- GATE緩和は FP 急増リスクのため非推奨
- FNの38%は原理的に検出困難

---

### 03_certificate_analysis.md

**目的**: SSL/TLS証明書特徴量の識別力を分析

**データソース**: PostgreSQLデータベース
- フィッシング: 320,409ドメイン
- 正規サイト: 450,656ドメイン

**内容**:
- 発行者別の分布
- 有効期限の分析
- SAN数の分析
- CRL/OCSP設定の分析

---

### 04_stage3_certificate_analysis.md

**目的**: Stage3における証明書特徴量の詳細分析

**内容**:
- OV/EV証明書を持つフィッシングドメインの分析
- 証明書タイプ別の検出率
- 信頼できる証明書を悪用するフィッシングの特徴
- 24件のOV/EV証明書フィッシングドメイン一覧

---

### 05_feature_candidates.md

**目的**: 将来の改善に向けた特徴量候補のメモ

**内容**:
- 検討中の特徴量
- 実装優先度
- 期待される効果

---

## サブディレクトリ

### fn_gsb_verification/

**目的**: Stage1 False NegativeのGoogle Safe Browsingでの検証

### stage2_independent_eval/

**目的**: Stage2証明書ルールの過学習検証

**プログラム**: `evaluate_stage2_rules.py`

**結果サマリー** (2026-01-12):

| 指標 | 元の評価 | 独立評価 |
|------|----------|----------|
| フィルタリング率 | 93.0% | 53.3% |
| 精度 | 96.6% | 90.7% |

### stage3_experiments/

**目的**: Stage3 AI Agentの各種実験結果

**主要ファイル**:
- `ai_agent_sample_results.csv`: ランダムサンプル評価結果
- `ai_agent_high_risk_tld_results.csv`: 高リスクTLD評価結果
- `low_signal_*.csv`: 低シグナルフィッシング分析
- `difficult_cases.csv`: 分類困難ケース

---

## 関連スクリプト

| スクリプト | 用途 |
|-----------|------|
| `scripts/analyze_trace.py` | FP/FNトレース分析 |
| `scripts/analyze_rule_metrics.py` | ルール効果分析 |
| `scripts/export_fnfp_analysis.py` | FN/FP詳細エクスポート |
| `scripts/analyze_evaluation_results.py` | 汎用評価分析 |
| `scripts/analyze_brand_exclusion.py` | ブランド除外効果分析 |

---

## 命名規則

- `NN_*.md`: 二桁番号プレフィックス付きドキュメント（読む順序を示す）
- `evaluate_*.py`: 評価スクリプト（独立実行可能）
- `analyze_*.py`: 分析スクリプト
- `*_results.json`: 機械可読な結果データ

---

## 変更履歴

- 2026-02-01: 全件評価FN/FP分析追加
  - fnfp_analysis_20260201.md 新規作成
  - 02_improvement_analysis.md に Section 15 追加
  - 最新評価結果（F1 68.87%）に更新
- 2026-01-30: ファイル統合・リネーム実施
  - baseline_comparison.md + baseline_fnfp_analysis_20260128.md → 01_baseline_analysis.md
  - improvement_analysis_20260128.md + tuning_insights + undetectable_fn → 02_improvement_analysis.md
  - 全ファイルに二桁番号プレフィックスを付与
