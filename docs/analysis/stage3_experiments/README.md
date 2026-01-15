# Stage3 AI Agent 実験結果

作成日: 2026-01-12
移設元: `artifacts/2026-01-10_140940/stage3_test/`

## 概要

このディレクトリには、Stage3 AI Agentの各種実験結果を格納しています。

## ファイル一覧

### AI Agent評価結果

| ファイル | 説明 | 件数 |
|---------|------|------|
| ai_agent_sample_results.csv | ランダムサンプル評価結果 | - |
| ai_agent_high_risk_tld_results.csv | 高リスクTLDドメイン評価結果 | - |
| ai_agent_v148_test.log | Agent v1.48 テストログ | - |
| ai_agent_v148b_test.log | Agent v1.48b テストログ | - |

### 低シグナルフィッシング分析

**目的**: ML確率が低い（<0.25）フィッシングサイトの特性分析

| ファイル | 説明 |
|---------|------|
| low_signal_phishing_for_validation.csv | 検証用低シグナルフィッシング |
| low_signal_phishing_gate_test.csv | Gate機能テスト結果 |
| low_signal_alive_check.csv | 生存確認（サンプル） |
| low_signal_alive_check_full.csv | 生存確認（全件） |
| low_signal_exclusion_list.csv | 除外候補リスト（109件） |
| low_signal_wayback_sample.csv | Wayback Machine確認サンプル |

**主な発見** (docs/research/20260112.md より):
- 低シグナルフィッシング1,446件のうち、純粋なフィッシングは限定的
- JPCERTソースの12.7%が現在正規サイト（一時侵害パターン）
- 109件を除外候補としてリスト化

### 高シグナル対照実験

| ファイル | 説明 |
|---------|------|
| high_signal_alive_check.csv | 高シグナル（ML>0.75）ドメインの生存確認 |
| high_risk_tld_ml_paradox.csv | 高リスクTLD × 低ML確率のパラドックスケース |

### 難しいケース分析

| ファイル | 説明 |
|---------|------|
| difficult_cases.csv | 分類が難しいケース（全件） |
| difficult_sample_50.csv | 難しいケース（サンプル50件） |

## 関連ドキュメント

- 研究日誌: `docs/research/20260112.md` - 低シグナル/高シグナル分析の詳細
- 仕様書: `docs/specs/low_signal_phishing_detection_spec.md`

## 関連スクリプト

- `scripts/test_low_signal_phishing_gate.py` - 低シグナルGateテスト
- `scripts/test_ai_agent_sample.py` - Agentサンプルテスト
- `scripts/test_ai_agent_high_risk_tld.py` - 高リスクTLDテスト

## 再現方法

これらのデータは以下のパイプラインを実行することで再生成可能：

```bash
# 1. パイプライン実行（01〜04）
# 2. テストスクリプト実行
python scripts/test_ai_agent_sample.py
python scripts/test_ai_agent_high_risk_tld.py
python scripts/test_low_signal_phishing_gate.py
```
