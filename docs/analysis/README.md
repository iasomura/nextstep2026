# 分析・検証ドキュメント

このディレクトリには、システムの各コンポーネントの検証結果とその実行に使用したプログラムを格納します。

## ディレクトリ構成

```
docs/analysis/
├── README.md                          # このファイル
├── baseline_fnfp_analysis_20260128.md # Stage3ベースラインFN/FP分析
├── certificate_analysis_report.md     # 証明書特徴量の分析レポート
├── feature_candidates_memo.md         # 特徴量候補メモ
├── fn_gsb_verification/               # False Negative のGoogle Safe Browsing検証
├── stage2_independent_eval/           # Stage2証明書ルールの独立評価
└── stage3_experiments/                # Stage3 AI Agent実験結果
```

## 各分析の詳細

### 1. baseline_fnfp_analysis_20260128.md

**目的**: Stage3 AI Agentベースライン評価のFN/FP詳細分析

**データソース**: `artifacts/00-baseline/2026-01-27_f1_0.6426/`
- 評価データ: 15,670件
- F1: 0.6426, FN: 899件, FP: 1,148件

**主な発見** (2026-01-28):
- **FNの80.2%（721件）はシグナル無し** - 特徴量ベースでは検出困難
- **FPの39.0%（448件）はシグナル無し** - AIの過剰検出
- **エラー全体の57.1%がシグナル無し** - 外部データ連携が必要
- phishtankのRecallが最低（56.2%）- 国際フィッシングの検出が課題
- 証明書特徴量はFN/TN区別に有効でない

**関連**: `docs/specs/rules_modularization_spec.md`

---

### 3. certificate_analysis_report.md

**目的**: SSL/TLS証明書特徴量の識別力を分析

**データソース**: PostgreSQLデータベース
- フィッシング: 320,409ドメイン
- 正規サイト: 450,656ドメイン

**注意**: この統計は後続の評価データと重複している可能性があり、独立評価が必要

---

### 4. stage2_independent_eval/

**目的**: Stage2証明書ルールの過学習検証

**プログラム**: `evaluate_stage2_rules.py`

**実行方法**:
```bash
cd /data/hdd/asomura/nextstep
python docs/analysis/stage2_independent_eval/evaluate_stage2_rules.py
```

**出力ファイル**:
- `train_cert_stats.json`: Trainセットから算出した証明書統計
- `test_eval_results.json`: Testセットでのルール評価結果
- `evaluation_report.md`: 評価レポート

**結果サマリー** (2026-01-12):

| 指標 | 元の評価 | 独立評価 |
|------|----------|----------|
| フィルタリング率 | 93.0% | **53.3%** |
| 精度 | 96.6% | 90.7% |

**結論**: Stage2の93%フィルタリングは過学習の結果。独立データでは53%程度。

---

### 5. fn_gsb_verification/

**目的**: Stage1 False NegativeのGoogle Safe Browsingでの検証

**内容**: 詳細は当該ディレクトリ内のファイルを参照

---

### 6. stage3_experiments/

**目的**: Stage3 AI Agentの各種実験結果

**主要ファイル**:
- `ai_agent_sample_results.csv`: ランダムサンプル評価結果
- `ai_agent_high_risk_tld_results.csv`: 高リスクTLD評価結果
- `low_signal_*.csv`: 低シグナルフィッシング分析（ML<0.25）
- `high_signal_alive_check.csv`: 高シグナル対照実験
- `difficult_cases.csv`: 分類困難ケース

**主な発見** (2026-01-12):
- 低シグナルフィッシング1,446件のうち純粋なフィッシングは限定的
- JPCERTソースの12.7%が現在正規サイト（一時侵害パターン）
- 109件を除外候補としてリスト化

**関連**: `docs/research/20260112.md`

---

## 検証プログラム命名規則

- `evaluate_*.py`: 評価スクリプト（独立実行可能）
- `analyze_*.py`: 分析スクリプト
- `*_report.md`: 分析レポート（人間が読む用）
- `*_results.json`: 機械可読な結果データ

## 再現性のための注意事項

1. **乱数シード**: 必ず固定する（デフォルト: 42）
2. **データパス**: プロジェクトルートからの相対パスを使用
3. **依存関係**: スクリプト冒頭に必要なモジュールを明記
4. **実行日時**: 結果ファイルに日時を記録
