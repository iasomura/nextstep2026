# phishing_agent/tools/__init__.py
"""
Phishing Agent Tools Package
フィッシング検知のための各種分析ツールを提供
"""

from .brand_impersonation_check import brand_impersonation_check
from .certificate_analysis import certificate_analysis
from .short_domain_analysis import short_domain_analysis
from .contextual_risk_assessment import contextual_risk_assessment
from .legitimate_domains import is_legitimate_domain, LEGITIMATE_DOMAINS

__all__ = [
    # ブランド偽装検知
    "brand_impersonation_check",

    # 証明書分析
    "certificate_analysis",

    # ドメイン構造分析
    "short_domain_analysis",

    # 文脈的リスク評価
    "contextual_risk_assessment",

    # 正規ドメイン検証
    "is_legitimate_domain",
    "LEGITIMATE_DOMAINS",
]

__version__ = "1.1.0"
__author__ = "Phishing Agent Team"

TOOL_DESCRIPTIONS = {
    "brand_impersonation_check": "ドメイン名から有名ブランドの偽装を検出（ルールベース＋LLM）",
    "certificate_analysis": "SSL/TLS証明書の分析によるリスク評価（オフライン専用）",
    "short_domain_analysis": "ドメイン長・TLD・ランダム性からの構造的リスク評価",
    "contextual_risk_assessment": "MLスコアと複数ツール結果を統合した文脈的リスク評価（MLパラドックス対応）",
    "is_legitimate_domain": "ホワイトリストによる正規ドメインの判定",
}

def get_all_tools():
    """利用可能なすべてのツール関数を返す"""
    return {
        "brand_impersonation_check": brand_impersonation_check,
        "certificate_analysis": certificate_analysis,
        "short_domain_analysis": short_domain_analysis,
        "contextual_risk_assessment": contextual_risk_assessment,
        "is_legitimate_domain": is_legitimate_domain,
    }

def get_tool_info(tool_name: str = None):
    """ツールの情報を取得"""
    if tool_name:
        if tool_name in TOOL_DESCRIPTIONS:
            return {
                "name": tool_name,
                "description": TOOL_DESCRIPTIONS[tool_name],
                "function": globals().get(tool_name),
            }
        else:
            raise ValueError(f"Unknown tool: {tool_name}")
    else:
        return TOOL_DESCRIPTIONS
