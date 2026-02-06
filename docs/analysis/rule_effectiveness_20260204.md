# ルール効果分析

作成日: 2026-02-04
評価データ: 11,936件（全件回帰テスト結果）

---

## 1. 分析方法

各ルールについて以下を計算:
- **TP**: ルール発火 → Phishing判定 → 実際もPhishing（正解）
- **FP**: ルール発火 → Phishing判定 → 実際はBenign（誤検出）
- **TN**: ルール発火 → Benign判定 → 実際もBenign（正解）
- **FN**: ルール発火 → Benign判定 → 実際はPhishing（見逃し）

**主要指標**:
- **Precision** = TP / (TP + FP) - ルール発火時の正解率
- **Net Benefit** = TP - FP - 純粋な貢献度

---

## 2. 問題ルール（Net Benefit < 0）

| ルール | 発火 | TP | FP | Net | Precision | 評価 |
|--------|------|-----|-----|------|-----------|------|
| **policy_r4** | 1,271 | 142 | 290 | **-148** | 32.9% | 🔴 深刻 |
| **policy_r2** | 1,183 | 104 | 233 | **-129** | 30.9% | 🔴 深刻 |
| **policy_r1** | 628 | 80 | 207 | **-127** | 27.9% | 🔴 深刻 |
| **benign_cert_gate_skip** | 258 | 95 | 158 | **-63** | 37.5% | 🔴 深刻 |
| **brand_cert_high** | 251 | 94 | 157 | **-63** | 37.5% | 🔴 深刻 |
| **policy_r5** | 558 | 72 | 128 | **-56** | 36.0% | 🔴 深刻 |
| policy_r6 | 509 | 56 | 98 | -42 | 36.4% | 🟡 注意 |
| policy_r3 | 291 | 36 | 54 | -18 | 40.0% | 🟡 注意 |
| high_ml_override | 21 | 5 | 16 | -11 | 23.8% | 🟡 注意 |

### 2.1 最も問題なルール: policy_r4

**条件**:
```
ML < 0.50 + free_ca & no_org + ctx >= 0.34 + strong_evidence → PHISHING
```

**問題点**:
- 発火回数が最多（1,271回）
- FP 290件を引き起こす最大の問題ルール
- Precision 32.9%（3回に1回しか正解しない）
- Net Benefit -148（TP 142件に対しFP 290件）

**原因仮説**:
1. ctx閾値 0.34 が低すぎる
2. `_has_strong_evidence()` の定義が広すぎる
3. legitimate TLDでも発火している

### 2.2 policy_r1/r2/r3 の問題

| ルール | ML閾値 | ctx閾値 | 追加条件 | 問題点 |
|--------|--------|---------|----------|--------|
| policy_r1 | < 0.20 | >= 0.28 | DV + strong_evidence | ctx閾値が低い |
| policy_r2 | < 0.30 | >= 0.34 | no_org + (free_ca or short) | 条件が緩い |
| policy_r3 | < 0.40 | >= 0.36 | short + no_org | shortの誤検出 |

### 2.3 brand関連ルールの問題

- **benign_cert_gate_skip**: ブランド検出時にbenign cert gateをスキップ
- **brand_cert_high**: ブランド検出 + 低品質証明書 → Phishing

**問題**: ブランド検出自体の精度が低い（FPを引き起こす）

---

## 3. 効果的ルール（Net Benefit >= 0）

| ルール | 発火 | TP | FP | Net | Precision | 評価 |
|--------|------|-----|-----|------|-----------|------|
| **very_high_ml_override** | 138 | 118 | 20 | **+98** | 85.5% | 🟢 優秀 |
| **ml_no_mitigation_gate** | 322 | 197 | 125 | **+72** | 61.2% | 🟢 良好 |
| **high_ml_ctx_rescue** | 170 | 114 | 56 | **+58** | 67.1% | 🟢 良好 |
| **soft_ctx_trigger** | 365 | 95 | 72 | **+23** | 56.9% | 🟢 良好 |
| hard_ctx_trigger | 26 | 15 | 11 | +4 | 57.7% | 🟢 良好 |
| post_llm_flip_gate | 49 | 0 | 0 | 0 | - | 🟢 安全 |

### 3.1 最も効果的: very_high_ml_override

**条件**: ML >= 0.85 → 無条件 PHISHING

**結果**:
- Precision 85.5%（非常に高い）
- Net Benefit +98（TP 118件、FP 20件）
- **維持推奨**

---

## 4. _has_strong_evidence() の分析

多くの問題ルール（policy_r1-r6）は `_has_strong_evidence()` を条件に含む。

**現在の定義**:
```python
# 強証拠とみなすシグナル
- brand_detected  # ← ブランド検出FPの原因
- dangerous_tld   # ← 正規サイトも使用
- random_pattern + 他シグナル  # ← 略語を誤検出
- ランダム系シグナル (digit_mixed_random等)  # ← 誤検出多い
- high_risk_words  # ← 広すぎる
- dv_suspicious_combo  # ← 正規サイトも該当
```

**問題**: 「強証拠」の定義が広すぎて、正規サイトでも発火する

---

## 5. 改善提案

### 5.1 即効性のある対策（FP削減）

| 対策 | 期待効果 | リスク |
|------|---------|--------|
| policy_r4 の ctx閾値を 0.34 → 0.40 に引き上げ | FP大幅削減 | FN微増 |
| policy_r1/r2 の ctx閾値を引き上げ | FP削減 | FN微増 |
| high_ml_override 無効化 | FP -16件 | TP -5件 |
| _has_strong_evidence() から brand_detected を除外 | FP削減 | FN増加リスク |

### 5.2 段階的な対策

**Phase 1**: 閾値調整（低リスク）
- policy_r4: ctx_threshold 0.34 → 0.40
- policy_r1: ctx_threshold 0.28 → 0.32
- policy_r2: ctx_threshold 0.34 → 0.38

**Phase 2**: ルール無効化検討
- high_ml_override: Precision 23.8%で効果なし → 無効化
- low_signal_phishing_gate_p3: Net -6 → 無効化検討

**Phase 3**: _has_strong_evidence() の再設計
- brand_detected を条件から分離
- random系シグナルの除外条件追加

### 5.3 効果シミュレーション

policy_r4 の ctx閾値を 0.40 に引き上げた場合の推定:

| 指標 | 現状 | 変更後（推定） |
|------|------|----------------|
| policy_r4 発火 | 1,271 | ~800 |
| FP | 290 | ~180 |
| TP | 142 | ~120 |
| Net Benefit | -148 | ~-60 |

---

## 6. 結論

### 6.1 問題の本質

**policyルール群（r1-r6）がFPの主要因**
- 合計でFP 1,010件を引き起こしている
- 全FP 574件の大部分がこれらのルールに起因

### 6.2 優先対応

1. **policy_r4** の閾値調整（最優先）
2. **policy_r1/r2** の閾値調整
3. **high_ml_override** の無効化
4. **_has_strong_evidence()** の見直し

### 6.3 維持すべきルール

- very_high_ml_override（Precision 85.5%）
- ml_no_mitigation_gate（Precision 61.2%）
- high_ml_ctx_rescue（Precision 67.1%）
