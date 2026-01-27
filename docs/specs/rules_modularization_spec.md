# ルールモジュール化仕様書

## 概要

本体（`llm_final_decision.py`、`contextual_risk_assessment.py`、`brand_impersonation_check.py`）に実装されている個別のルールを、`phishing_agent/rules/` モジュールに分離・統合する。

### 目的

1. **可読性向上**: 複雑なルールロジックを個別ファイルに分離
2. **テスト容易性**: ルール単位でのユニットテスト実装
3. **効果測定**: `MetricsCollector` による各ルールの TP/FP/TN/FN 計測
4. **有効/無効制御**: コードまたは設定による動的なルール制御
5. **再利用性**: ルールの組み合わせや優先度の柔軟な変更

### 実装状況 (2026-01-28)

| カテゴリ | 状態 | ルール数 |
|---------|------|---------|
| RuleContext/RuleResult 拡張 | **完了** | - |
| ML Paradox | 完了 (既存) | 2 |
| TLD Combo | 完了 (既存) | 4 |
| Low Signal (old) | 完了 (既存) | 2 |
| ML Guard | **完了** | 4 |
| Cert Gate (B1-B4) | **完了** | 4 |
| Low Signal Gate (P1-P4) | **完了** | 4 |
| Policy (R1-R6) | **完了** | 6 |
| EngineResult Phase6拡張 | **完了** | - |
| RuleEngine 統合API | **完了** | - |
| MetricsCollector 統合 | **完了** | - |

**合計: 26ルール実装済み**

### Phase 1-2 統合 (2026-01-28)

**Phase 1: RuleEngine 統合**
- `EngineResult` に Phase6 フィールドを追加 (force_phishing, force_benign, highest_risk_bump, confidence_floor, confidence_ceiling)
- `create_all_rules()` 全ルール生成ファクトリ関数を追加
- `create_default_engine()` デフォルトエンジン生成関数を追加
- `rules/integration.py` 統合ヘルパーモジュールを作成

**Phase 2: MetricsCollector 統合**
- `scripts/analyze_rule_metrics.py` ルール効果分析スクリプトを作成
- 評価結果CSVからルールごとのTP/FP/TN/FNを集計可能

---

## モジュール構造

```
phishing_agent/rules/
├── __init__.py           # 公開API (RuleEngine, create_all_rules, create_default_engine等)
├── engine.py             # RuleEngine (ルール実行エンジン)
├── metrics.py            # MetricsCollector (効果測定)
├── integration.py        # 統合ヘルパー (build_rule_context, evaluate_rules等) [2026-01-28追加]
├── config/
│   ├── __init__.py
│   ├── settings.py       # RulesConfig, RuleSettings
│   └── thresholds.py     # 各種閾値設定 (dataclass)
├── data/
│   ├── __init__.py
│   ├── tlds.py           # TLDデータ (HIGH_DANGER_TLDS, MEDIUM_DANGER_TLDS, SAFE_TLDS等)
│   ├── patterns.py       # パターンデータ (HIGH_RISK_WORDS, RARE_BIGRAMS等)
│   └── brands.py         # ブランドデータ (CRITICAL_BRAND_KEYWORDS等)
└── detectors/
    ├── __init__.py       # 全ルールのエクスポート
    ├── base.py           # DetectionRule, RuleContext, RuleResult
    ├── ml_paradox.py     # MLParadoxStrongRule, MLParadoxWeakRule (2個)
    ├── tld_combo.py      # 危険TLD組み合わせルール (4個)
    ├── low_signal.py     # 低シグナルフィッシングルール - 旧版 (2個)
    ├── ml_guard.py       # MLガードルール (4個) [2026-01-27追加]
    ├── cert_gate.py      # 証明書ゲートルール B1-B4 (4個) [2026-01-27追加]
    ├── low_signal_gate.py # 低シグナルゲートルール P1-P4 (4個) [2026-01-27追加]
    └── policy.py         # ポリシールール R1-R6 (6個) [2026-01-27追加]
```

---

## 設計原則

### 1. DetectionRule 基底クラス

```python
class DetectionRule(ABC):
    def __init__(self, enabled: bool = True):
        self._enabled = enabled

    @property
    def enabled(self) -> bool: ...

    @enabled.setter
    def enabled(self, value: bool): ...

    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def _evaluate(self, ctx: RuleContext) -> RuleResult: ...

    def evaluate(self, ctx: RuleContext) -> RuleResult:
        if not self._enabled:
            return RuleResult.skipped_result(self.name, "Rule disabled")
        result = self._evaluate(ctx)
        result.rule_name = self.name
        return result
```

### 2. RuleContext データクラス

```python
@dataclass
class RuleContext:
    # 基本フィールド
    domain: str
    ml_probability: float = 0.0
    issue_set: Set[str] = field(default_factory=set)
    tool_risks: Dict[str, float] = field(default_factory=dict)
    cert_details: Dict[str, Any] = field(default_factory=dict)
    brand_details: Dict[str, Any] = field(default_factory=dict)
    domain_details: Dict[str, Any] = field(default_factory=dict)
    is_known_legitimate: bool = False
    tld: str = ""
    registered_domain: str = ""

    # Phase6 拡張フィールド (2026-01-27追加)
    ctx_score: float = 0.0                    # contextual risk score
    ctx_issues: Set[str] = field(default_factory=set)
    precheck: Dict[str, Any] = field(default_factory=dict)
    benign_indicators: Set[str] = field(default_factory=set)
    llm_is_phishing: Optional[bool] = None
    llm_confidence: float = 0.0
    llm_risk_level: str = "low"
```

### 3. RuleResult データクラス

```python
@dataclass
class RuleResult:
    triggered: bool
    rule_name: str = ""
    issue_tag: Optional[str] = None
    score_adjustment: float = 0.0
    min_score: Optional[float] = None
    reasoning: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    skipped: bool = False

    # Phase6 拡張フィールド (2026-01-27追加)
    force_phishing: Optional[bool] = None     # Trueならis_phishing強制
    force_benign: Optional[bool] = None       # Trueならis_phishing=False強制
    risk_level_bump: Optional[str] = None     # risk_levelの引き上げ先
    confidence_floor: Optional[float] = None  # 最低confidence
    confidence_ceiling: Optional[float] = None  # 最大confidence
```

---

## 実装済みルール一覧

### ML Paradox (2個) - `ml_paradox.py`

| ルール名 | 説明 |
|---------|------|
| `ml_paradox_strong` | ML <= 0.20 + 2つ以上の強シグナル → 高リスク |
| `ml_paradox_weak` | ML <= 0.30 + 1つ以上の強シグナル → 中リスク |

### TLD Combo (4個) - `tld_combo.py`

| ルール名 | 説明 |
|---------|------|
| `dangerous_tld_low_ml` | 危険TLD + 低ML → スコアブースト |
| `dangerous_tld_random` | 危険TLD + ランダムパターン → スコアブースト |
| `dangerous_tld_brand` | 危険TLD + ブランド検出 → スコアブースト |
| `high_danger_tld` | 高危険TLD → 最低スコア保証 |

### Low Signal - 旧版 (2個) - `low_signal.py`

| ルール名 | 説明 |
|---------|------|
| `low_signal_phishing` | 低シグナルフィッシング検出 |
| `dv_suspicious_combo` | DV証明書 + 疑わしい組み合わせ |

### ML Guard (4個) - `ml_guard.py` [2026-01-27追加]

| ルール名 | 説明 | 効果 |
|---------|------|------|
| `very_high_ml_override` | ML >= 0.85 → 無条件 phishing | force_phishing |
| `high_ml_override` | ML >= 0.40 + (random or dangerous_tld) → phishing | force_phishing |
| `ultra_low_ml_block` | ML < 0.05 + no brand + no dangerous TLD → benign | force_benign |
| `post_llm_flip_gate` | 低ML + LLM phishing判定 → ブロック (TLD別閾値) | force_benign |

### Cert Gate (4個) - `cert_gate.py` [2026-01-27追加]

| ルール名 | 説明 | 効果 |
|---------|------|------|
| `benign_cert_gate_b1` | OV/EV証明書 + ctx < 0.50 | force_benign |
| `benign_cert_gate_b2` | CRL保有 + ML < 0.30 + ctx < 0.45 | force_benign |
| `benign_cert_gate_b3` | ワイルドカード + 非危険TLD + ctx < 0.40 | force_benign |
| `benign_cert_gate_b4` | 高SAN数 + 非危険TLD + ctx < 0.45 | force_benign |

### Low Signal Gate (4個) - `low_signal_gate.py` [2026-01-27追加]

| ルール名 | 説明 | 効果 |
|---------|------|------|
| `low_signal_phishing_gate_p1` | ブランド + 短期証明書(≤90日) + ML < 0.30 | force_phishing |
| `low_signal_phishing_gate_p2` | ブランド疑い + 短期証明書 + 低SAN(≤5) + ML < 0.25 | force_phishing |
| `low_signal_phishing_gate_p3` | 危険TLD + 短期証明書 + 低SAN(≤3) + ML < 0.20 | risk_bump (medium) |
| `low_signal_phishing_gate_p4` | 中危険TLD + 短期証明書 + 低SAN(≤2) + ML < 0.05 | force_phishing |

### Policy (6個) - `policy.py` [2026-01-27追加]

| ルール名 | 説明 | 効果 |
|---------|------|------|
| `policy_r1` | ML < 0.20 + DV証明書 + ctx >= 0.28 + strong_evidence | force_phishing |
| `policy_r2` | ML < 0.30 + no_org + (free_ca or short) + ctx >= 0.34 + strong_evidence | force_phishing |
| `policy_r3` | ML < 0.40 + short + no_org + ctx >= 0.36 + strong_evidence | force_phishing |
| `policy_r4` | ML < 0.50 + DV証明書 + ctx >= 0.34 + strong_evidence | force_phishing |
| `policy_r5` | ML < 0.50 + dangerous_tld + no_org + ctx >= 0.33 | force_phishing |
| `policy_r6` | ML < 0.30 + dangerous_tld + DV証明書 + ctx >= 0.35 | force_phishing |

---

## 使用例

### 全ルールの作成

```python
from phishing_agent.rules.detectors import (
    create_ml_paradox_rules,
    create_tld_combo_rules,
    create_low_signal_rules,
    create_ml_guard_rules,
    create_cert_gate_rules,
    create_low_signal_gate_rules,
    create_policy_rules,
)

# 全ルールを作成
all_rules = (
    create_ml_paradox_rules() +
    create_tld_combo_rules() +
    create_low_signal_rules() +
    create_ml_guard_rules() +
    create_cert_gate_rules() +
    create_low_signal_gate_rules() +
    create_policy_rules()
)
print(f"Total rules: {len(all_rules)}")  # 26
```

### 個別ルールの使用

```python
from phishing_agent.rules.detectors import (
    VeryHighMLOverrideRule,
    RuleContext,
)

# ルールを作成
rule = VeryHighMLOverrideRule(enabled=True)

# コンテキストを作成
ctx = RuleContext(
    domain="suspicious.com",
    ml_probability=0.92,
    tld="com",
    llm_is_phishing=False,
    llm_risk_level="low",
)

# 評価
result = rule.evaluate(ctx)
print(f"Triggered: {result.triggered}")
print(f"Force phishing: {result.force_phishing}")
```

### RuleEngine での使用

```python
from phishing_agent.rules import RuleEngine
from phishing_agent.rules.detectors import create_ml_guard_rules

engine = RuleEngine()
for rule in create_ml_guard_rules():
    engine.register(rule)

# 評価
result = engine.evaluate(ctx)
```

---

## 今後の作業

### Phase 1: 本体統合 (未着手)

`llm_final_decision.py` の `_apply_policy_adjustments()` から `RuleEngine` を呼び出す。

```python
# 将来の統合イメージ
from phishing_agent.rules import RuleEngine
from phishing_agent.rules.detectors import create_all_phase6_rules

engine = RuleEngine()
engine.register_all(create_all_phase6_rules())

# _apply_policy_adjustments 内で
ctx = RuleContext(
    domain=domain,
    ml_probability=ml,
    ctx_score=ctx_score,
    # ...
)
results = engine.evaluate(ctx)
```

### Phase 2: 効果測定

`MetricsCollector` を使用して各ルールの TP/FP/TN/FN を計測し、ルールの有効性を評価する。

---

## 変更履歴

- 2026-01-27: 初版作成
- 2026-01-27: ログ出力仕様を追加
- 2026-01-27: 実装完了 - ML Guard, Cert Gate, Low Signal Gate, Policy ルール (18個追加)

---

# AI向け操作ガイド

## 概要

このセクションは、AI Agent がルールモジュールを操作する際のガイドです。
**ルールは頻繁に変更するものではありません。** 設定方法を理解し、必要な時のみ操作してください。

## ルールの有効/無効の設定方法

### 方法1: インスタンス作成時に指定

```python
from phishing_agent.rules.detectors import VeryHighMLOverrideRule

# 無効化して作成
rule = VeryHighMLOverrideRule(enabled=False)

# 有効化して作成 (デフォルト)
rule = VeryHighMLOverrideRule(enabled=True)
```

### 方法2: 作成後に変更

```python
rule = VeryHighMLOverrideRule()
rule.enabled = False  # 無効化
rule.enabled = True   # 有効化
```

### 方法3: ファクトリー関数で一括制御

```python
from phishing_agent.rules.detectors import create_ml_guard_rules

# 全ML Guardルールを無効化
rules = create_ml_guard_rules(enabled=False)

# 特定ルールのみ有効化
for rule in rules:
    if rule.name == "very_high_ml_override":
        rule.enabled = True
```

## ルールの確認方法

### 全ルールの一覧表示

```python
from phishing_agent.rules.detectors import (
    create_ml_paradox_rules,
    create_tld_combo_rules,
    create_low_signal_rules,
    create_ml_guard_rules,
    create_cert_gate_rules,
    create_low_signal_gate_rules,
    create_policy_rules,
)

all_rules = (
    create_ml_paradox_rules() +
    create_tld_combo_rules() +
    create_low_signal_rules() +
    create_ml_guard_rules() +
    create_cert_gate_rules() +
    create_low_signal_gate_rules() +
    create_policy_rules()
)

print(f"Total: {len(all_rules)} rules")
for rule in all_rules:
    status = "enabled" if rule.enabled else "disabled"
    print(f"  {rule.name}: {status}")
```

### 特定カテゴリのルール確認

```python
# ML Guard ルールのみ
from phishing_agent.rules.detectors import create_ml_guard_rules
for rule in create_ml_guard_rules():
    print(f"{rule.name}: {rule.description}")
```

## ルールのテスト方法

### 単体テスト

```python
from phishing_agent.rules.detectors import VeryHighMLOverrideRule, RuleContext

rule = VeryHighMLOverrideRule()
ctx = RuleContext(
    domain="test.com",
    ml_probability=0.90,
    tld="com",
    llm_is_phishing=False,
    llm_risk_level="low",
)
result = rule.evaluate(ctx)
print(f"Triggered: {result.triggered}")
print(f"Reasoning: {result.reasoning}")
```

## ファイル配置

| ファイル | 内容 |
|----------|------|
| `detectors/ml_guard.py` | ML閾値ベースのガード (4ルール) |
| `detectors/cert_gate.py` | 証明書品質によるBENIGN保護 (4ルール) |
| `detectors/low_signal_gate.py` | 低シグナルフィッシング検出 (4ルール) |
| `detectors/policy.py` | 複合条件ポリシー (6ルール) |
| `detectors/base.py` | 基底クラス (RuleContext, RuleResult, DetectionRule) |
| `data/tlds.py` | TLDデータ (HIGH_DANGER_TLDS, MEDIUM_DANGER_TLDS) |

## 注意事項

1. **ルールは頻繁に変更しない**: ルールのロジックは慎重に設計されています。変更が必要な場合は、まず影響範囲を確認してください。

2. **閾値の変更は慎重に**: 各ルールには閾値があります（ML threshold, ctx threshold等）。変更すると精度に大きく影響します。

3. **テストを実行**: ルールを変更した場合は、必ず評価テストを実行してください。
   ```bash
   # 100件の簡易テスト
   python scripts/evaluate_e2e.py --n-sample 100 --random-state 42
   ```

4. **本体との整合性**: 現在、ルールモジュールは本体 (`llm_final_decision.py`) とは独立しています。本体にも同様のロジックが実装されているため、モジュール側の変更は本体には影響しません。

## 関連ドキュメント

- `/data/hdd/asomura/nextstep/CLAUDE.local.md` - vLLM起動/停止の手順
- `/data/hdd/asomura/nextstep/docs/specs/rules_modularization_spec.md` - この仕様書
