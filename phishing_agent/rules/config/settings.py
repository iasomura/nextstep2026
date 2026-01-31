# -*- coding: utf-8 -*-
"""
phishing_agent.rules.config.settings
------------------------------------
Rule enable/disable settings and configuration management.
"""

from dataclasses import dataclass, field
from typing import Dict, Optional
from pathlib import Path
import yaml


@dataclass
class RuleSettings:
    """Individual rule settings.

    Attributes:
        enabled: Whether the rule is enabled
        description: Human-readable description
        disabled_reason: Reason for disabling (if disabled)
        version: Version when this rule was added/modified
    """
    enabled: bool = True
    description: str = ""
    disabled_reason: str = ""
    version: str = ""


@dataclass
class RulesConfig:
    """Configuration for all detection rules.

    This class manages the enable/disable state of all rules.
    Can be loaded from YAML or configured programmatically.
    """

    # ML Paradox detection
    ml_paradox: RuleSettings = field(default_factory=lambda: RuleSettings(
        enabled=True,
        description="低ML + 高シグナル時にスコア底上げ",
        version="1.0.0"
    ))

    # Dangerous TLD combination
    dangerous_tld_combo: RuleSettings = field(default_factory=lambda: RuleSettings(
        enabled=True,
        description="危険TLD + 他シグナルの組み合わせ検出",
        version="1.0.0"
    ))

    # Low signal phishing detection
    low_signal_phishing: RuleSettings = field(default_factory=lambda: RuleSettings(
        enabled=True,
        description="低シグナルフィッシングパターン検出 (ML 0.10-0.30)",
        version="1.0.0"
    ))

    # DV certificate suspicious combo
    dv_suspicious_combo: RuleSettings = field(default_factory=lambda: RuleSettings(
        enabled=True,
        description="DV証明書 + 疑わしいドメインの組み合わせ",
        version="1.0.0"
    ))

    # Random pattern minimum score
    # 2026-01-28: FP分析に基づき無効化
    # random_pattern (低母音比率) はPrecision 39%でFP 55件の主犯だったため、
    # short_domain_analysis.py の検出ロジック自体を無効化済み。
    # この最低スコアルールも連動して無効化。
    random_pattern_minimum: RuleSettings = field(default_factory=lambda: RuleSettings(
        enabled=False,
        description="ランダムパターン検出時の最低スコア保証",
        disabled_reason="2026-01-28: random_pattern検出が無効化されたため連動して無効化",
        version="1.0.0"
    ))

    # High risk words detection
    high_risk_words: RuleSettings = field(default_factory=lambda: RuleSettings(
        enabled=True,
        description="高リスクワード（verify, secure等）検出",
        version="1.0.0"
    ))

    # Multiple risk factors bonus
    multiple_risk_factors: RuleSettings = field(default_factory=lambda: RuleSettings(
        enabled=True,
        description="複数カテゴリのリスク要因検出",
        version="1.0.0"
    ))

    # Known domain mitigation
    known_domain_mitigation: RuleSettings = field(default_factory=lambda: RuleSettings(
        enabled=True,
        description="既知正規ドメインのスコア緩和",
        version="1.0.0"
    ))

    # Old certificate phishing detection
    old_cert_phishing: RuleSettings = field(default_factory=lambda: RuleSettings(
        enabled=True,
        description="古い証明書パターンによるフィッシング検出",
        version="1.0.0"
    ))

    # Critical brand minimum score
    critical_brand_minimum: RuleSettings = field(default_factory=lambda: RuleSettings(
        enabled=True,
        description="重要ブランド検出時の最低スコア保証",
        version="1.0.0"
    ))

    # Brand impersonation detection
    brand_impersonation: RuleSettings = field(default_factory=lambda: RuleSettings(
        enabled=True,
        description="ブランドなりすまし検出",
        version="1.0.0"
    ))

    # Random pattern detection
    # 2026-01-28: FP分析に基づく部分的無効化
    # 低母音比率による random_pattern は無効化したが、
    # consonant_cluster_random (Precision 68%) と rare_bigram_random (54%) は維持。
    # このルール設定は consonant_cluster/rare_bigram の最低スコアにも影響するため、
    # 有効のまま維持する。
    random_pattern: RuleSettings = field(default_factory=lambda: RuleSettings(
        enabled=True,
        description="ランダムパターン（エントロピー/子音クラスター等）検出",
        version="1.0.0"
    ))

    # IDN homograph detection
    idn_homograph: RuleSettings = field(default_factory=lambda: RuleSettings(
        enabled=True,
        description="IDNホモグラフ攻撃検出",
        version="1.0.0"
    ))

    # Short domain risky
    short_domain_risky: RuleSettings = field(default_factory=lambda: RuleSettings(
        enabled=True,
        description="短いドメイン + リスク要因の組み合わせ検出",
        version="1.0.0"
    ))

    # Legitimate domain override
    legitimate_domain_override: RuleSettings = field(default_factory=lambda: RuleSettings(
        enabled=True,
        description="正規ドメインリストによるスコア上書き",
        version="1.0.0"
    ))

    # --- Disabled rules ---

    # Random CRL override (disabled due to FP increase)
    random_crl_override: RuleSettings = field(default_factory=lambda: RuleSettings(
        enabled=False,
        description="ランダムパターン + CRL DP時のbenign効果打ち消し",
        disabled_reason="2026-01-27: 26%のFPに寄与していたため無効化",
        version="1.0.0"
    ))

    def get_enabled_rules(self) -> Dict[str, bool]:
        """Get dictionary of rule names and their enabled status."""
        result = {}
        for field_name in self.__dataclass_fields__:
            settings = getattr(self, field_name)
            if isinstance(settings, RuleSettings):
                result[field_name] = settings.enabled
        return result

    def set_rule_enabled(self, rule_name: str, enabled: bool, reason: str = ""):
        """Set a rule's enabled status."""
        if hasattr(self, rule_name):
            settings = getattr(self, rule_name)
            if isinstance(settings, RuleSettings):
                settings.enabled = enabled
                if not enabled and reason:
                    settings.disabled_reason = reason

    def is_enabled(self, rule_name: str) -> bool:
        """Check if a rule is enabled."""
        if hasattr(self, rule_name):
            settings = getattr(self, rule_name)
            if isinstance(settings, RuleSettings):
                return settings.enabled
        return False

    @classmethod
    def from_yaml(cls, path: Path) -> "RulesConfig":
        """Load configuration from YAML file."""
        config = cls()
        if path.exists():
            with open(path, 'r') as f:
                data = yaml.safe_load(f)
                if data and 'rules' in data:
                    for rule_name, rule_data in data['rules'].items():
                        if hasattr(config, rule_name):
                            settings = RuleSettings(
                                enabled=rule_data.get('enabled', True),
                                description=rule_data.get('description', ''),
                                disabled_reason=rule_data.get('disabled_reason', ''),
                                version=rule_data.get('version', ''),
                            )
                            setattr(config, rule_name, settings)
        return config

    def to_yaml(self, path: Path):
        """Save configuration to YAML file."""
        data = {'rules': {}}
        for field_name in self.__dataclass_fields__:
            settings = getattr(self, field_name)
            if isinstance(settings, RuleSettings):
                data['rules'][field_name] = {
                    'enabled': settings.enabled,
                    'description': settings.description,
                    'disabled_reason': settings.disabled_reason,
                    'version': settings.version,
                }
        with open(path, 'w') as f:
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True)

    def print_status(self):
        """Print all rules and their status."""
        print("Rule Status:")
        print("-" * 60)
        for field_name in self.__dataclass_fields__:
            settings = getattr(self, field_name)
            if isinstance(settings, RuleSettings):
                status = "✓ Enabled" if settings.enabled else "✗ Disabled"
                print(f"  {field_name:30s} {status}")
                if not settings.enabled and settings.disabled_reason:
                    print(f"    Reason: {settings.disabled_reason}")
