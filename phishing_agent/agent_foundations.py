
"""
agent_foundations.py
--------------------
Phase 1「基礎設計と型定義」: 型・定数・例外・ヘルパー関数の実装と簡易テスト

- Pydantic v2 スキーマ:
    * ToolSelectionResult（ツール選択結果）
    * PhishingAssessment（最終判定結果）
    * AgentState（LangGraphの状態）— tool_results は Annotated[Dict[str, Any], merge_dicts]
- カスタム例外:
    * PhishingAgentError（基底クラス）
    * ToolExecutionError / ConfigurationError / DataValidationError / LLMConnectionError
    * StructuredOutputError / GraphExecutionError / TimeoutError（互換用）
- 定数定義:
    * ERROR_CATEGORIES, TOOL_NAMES(=AVAILABLE_TOOLS), RISK_LEVELS, STEP_NAMES, 他
- ヘルパー関数:
    * clip_confidence, normalize_list, get_risk_level, convert_to_phase2_format, merge_dicts

実行方法:
    $ python agent_foundations.py

仕様参照: Phase1_基礎設計と型定義_仕様書.md / マスター仕様書（Phase 1）
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Literal, Annotated, TypedDict
from operator import add
from pydantic import BaseModel, Field, field_validator

# ==============================
# 定数定義
# ==============================

#: エラーカテゴリ
ERROR_CATEGORIES: Dict[str, str] = {
    "timeout": "タイムアウト",
    "network": "ネットワークエラー",
    "llm": "LLM呼び出しエラー",
    "parse": "出力パースエラー",
    "schema": "スキーマバリデーションエラー",
    "tool_execution": "ツール実行エラー",
    "fallback_activated": "フォールバック発動",
    "graph_execution": "GraphStateエラー",
    "unknown": "その他・分類不能",
}

#: 使用可能なツール一覧
AVAILABLE_TOOLS: List[str] = [
    "brand_impersonation_check",
    "certificate_analysis",
    "short_domain_analysis",
    "contextual_risk_assessment",
]

#: 後方互換のための別名（仕様で TOOL_NAMES と呼ばれることがある）
TOOL_NAMES: List[str] = AVAILABLE_TOOLS

#: ツールの説明
TOOL_DESCRIPTIONS: Dict[str, str] = {
    "brand_impersonation_check": "ブランド偽装チェック - ドメイン名に有名ブランドが含まれているか検出",
    "certificate_analysis": "証明書分析 - SSL/TLS証明書の発行者、有効期限、SANを分析",
    "short_domain_analysis": "短いドメイン分析 - ドメイン長、TLD、文字種の分析",
    "contextual_risk_assessment": "文脈リスク評価 - 他ツール結果を統合し、ML Paradoxを検出",
}

#: リスクレベルの列挙（表示順）
RISK_LEVELS: List[str] = ["low", "medium", "medium-high", "high", "critical"]

#: リスクレベルの閾値定義
RISK_LEVEL_THRESHOLDS: Dict[str, float] = {
    "critical": 0.9,     # confidence >= 0.9
    "high": 0.7,         # confidence >= 0.7
    "medium-high": 0.5,  # confidence >= 0.5
    "medium": 0.3,       # confidence >= 0.3
    "low": 0.0,          # confidence >= 0.0
}

#: ステップ名（LangGraph内での可読表示）
STEP_NAMES: Dict[str, str] = {
    "initial": "初期状態",
    "precheck": "事前チェック",
    "tool_selection": "ツール選択",
    "tool_execution": "ツール実行",
    "final": "最終判定",
    "completed": "完了",
    "error": "エラー",
}

# ==============================
# ヘルパー関数
# ==============================

def clip_confidence(value: float) -> float:
    """
    信頼度を [0.0, 1.0] に丸め込む（外れ値でも例外にせず安全側に補正）.

    Args:
        value: 任意の数値

    Returns:
        0.0〜1.0 の範囲にクリップされた float

    Examples:
        >>> clip_confidence(1.5)
        1.0
        >>> clip_confidence(-0.5)
        0.0
        >>> clip_confidence(0.75)
        0.75
    """
    try:
        v = float(value)
    except Exception:
        # 数値化できない場合は 0.0 にフォールバック
        return 0.0
    return 0.0 if v < 0.0 else (1.0 if v > 1.0 else v)


def normalize_list(items: List[str]) -> List[str]:
    """
    文字列リストを正規化し、重複排除する.

    - 小文字化
    - 前後空白の除去
    - 空/空白のみの要素を除外
    - 入力順を保持したまま重複を削除

    Args:
        items: 入力の文字列リスト

    Returns:
        正規化済みのユニーク文字列リスト

    Examples:
        >>> normalize_list(["PayPal", "paypal", " PAYPAL ", "", "amazon"])
        ['paypal', 'amazon']
        >>> normalize_list(["", "  ", ""])
        []
    """
    normalized: List[str] = []
    seen: set[str] = set()
    for item in items or []:
        s = (item or "").strip().lower()
        if not s:
            continue
        if s not in seen:
            seen.add(s)
            normalized.append(s)
    return normalized


def get_risk_level(confidence: float, is_phishing: bool) -> str:
    """
    is_phishing と信頼度から 5段階のリスクレベルを返す.

    Args:
        confidence: 信頼度（0.0〜1.0）
        is_phishing: True のときのみ confidence に応じて段階化

    Returns:
        "low" | "medium" | "medium-high" | "high" | "critical"

    Examples:
        >>> get_risk_level(0.95, True)
        'critical'
        >>> get_risk_level(0.95, False)
        'low'
        >>> get_risk_level(0.55, True)
        'medium-high'
    """
    if not is_phishing:
        return "low"
    c = clip_confidence(confidence)
    if c >= RISK_LEVEL_THRESHOLDS["critical"]:
        return "critical"
    if c >= RISK_LEVEL_THRESHOLDS["high"]:
        return "high"
    if c >= RISK_LEVEL_THRESHOLDS["medium-high"]:
        return "medium-high"
    if c >= RISK_LEVEL_THRESHOLDS["medium"]:
        return "medium"
    return "low"


def merge_dicts(x: Optional[Dict[str, Any]], y: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    LangGraph のリデューサーとして使用する辞書マージ関数（後勝ち）.

    - None は空辞書として扱う
    - キー重複時は y の値を採用（後勝ち）

    Args:
        x: 既存の辞書（または None）
        y: 追加・上書きする辞書（または None）

    Returns:
        マージ済み辞書（浅いマージ）

    Examples:
        >>> merge_dicts({"a": 1, "b": 2}, {"b": 3, "c": 4})
        {'a': 1, 'b': 3, 'c': 4}
        >>> merge_dicts({}, {"x": 10})
        {'x': 10}
        >>> merge_dicts({"x": 10}, {})
        {'x': 10}
    """
    dx: Dict[str, Any] = dict(x or {})
    dy: Dict[str, Any] = dict(y or {})
    dx.update(dy)
    return dx


def convert_to_phase2_format(
    domain: str,
    ml_probability: float,
    assessment: "PhishingAssessment",
    tools_used: List[str],
    processing_time: float,
    success: bool = True,
    error: Optional[str] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """
    Phase 2 固定キーの成果物に変換するユーティリティ.

    Args:
        domain: 対象ドメイン
        ml_probability: 第一層 ML の確率
        assessment: LLM エージェントの最終判定
        tools_used: 使用したツール一覧
        processing_time: 処理時間（秒）
        success: 成功可否
        error: エラー文字列（あれば）
        **kwargs: 追加メタ情報（error_category など）

    Returns:
        Phase 2 形式の辞書

    Examples:
        >>> pa = PhishingAssessment(
        ...     is_phishing=True,
        ...     confidence=0.85,
        ...     risk_level="high",
        ...     detected_brands=["paypal"],
        ...     risk_factors=["brand_impersonation"],
        ...     reasoning="PayPalを偽装している。"
        ... )
        >>> result = convert_to_phase2_format(
        ...     domain="paypal-login.info",
        ...     ml_probability=0.15,
        ...     assessment=pa,
        ...     tools_used=["brand_impersonation_check"],
        ...     processing_time=2.5
        ... )
        >>> result["ai_is_phishing"]
        True
    """
    result: Dict[str, Any] = {
        "domain": domain,
        "ml_probability": float(ml_probability),
        "ai_is_phishing": bool(assessment.is_phishing),
        "ai_confidence": clip_confidence(assessment.confidence),
        "ai_risk_level": assessment.risk_level,
        "detected_brands": list(assessment.detected_brands),
        "reasoning": assessment.reasoning,
        "success": bool(success),
        "processing_time": float(processing_time),
        "tools_used": list(tools_used or []),
        "llm_driven": True,
    }
    if error:
        result["error"] = error
        result["error_category"] = kwargs.get("error_category", "unknown")
    result.update(kwargs)
    return result

# ==============================
# Pydantic v2 スキーマ
# ==============================

class ToolSelectionResult(BaseModel):
    """
    LLMによるツール選択の結果（Structured Output）

    LLMは「このドメインにはどのツールが必要か」を判断し、
    その結果をこのスキーマで返す。

    Attributes:
        selected_tools: 選択されたツール名のリスト（0〜4件）
        reasoning: ツール選択の理由（10〜500文字）
        confidence: 選択の信頼度（0.0〜1.0）

    Examples:
        >>> ToolSelectionResult(
        ...     selected_tools=["brand_impersonation_check", "certificate_analysis"],
        ...     reasoning="PayPalブランドを含むため偽装チェックが必要。証明書も分析する。",
        ...     confidence=0.85
        ... )
    """
    selected_tools: List[str] = Field(
        default_factory=list,
        description="選択されたツール名のリスト（0〜4件）",
        min_items=0,
        max_items=4,
    )
    reasoning: str = Field(
        description="ツール選択の理由（10〜500文字）",
        min_length=10,
        max_length=500,
    )
    confidence: float = Field(
        default=0.5,
        description="選択の信頼度（0.0〜1.0）",
        ge=0.0,
        le=1.0,
    )

    @field_validator("selected_tools")
    @classmethod
    def _validate_tools(cls, v: List[str]) -> List[str]:
        """
        ツール名の妥当性と重複排除.
        """
        invalid = [t for t in v if t not in AVAILABLE_TOOLS]
        if invalid:
            raise ValueError(f"無効なツール名: {invalid}")
        # 重複排除（順序保持）
        uniq = []
        seen = set()
        for t in v:
            if t not in seen:
                seen.add(t)
                uniq.append(t)
        return uniq

    @field_validator("confidence", mode="before")
    @classmethod
    def _clip_confidence(cls, v: float) -> float:
        """
        信頼度は事前クリップしてから数値制約へ.
        """
        return clip_confidence(v)


class PhishingAssessment(BaseModel):
    """
    LLM による最終判定結果.

    Attributes:
        is_phishing: フィッシングサイトかどうか
        confidence: 判定の信頼度（0.0〜1.0）
        risk_level: 5段階のリスクレベル
        detected_brands: 検出ブランド名のリスト
        risk_factors: リスク要因のリスト
        reasoning: 判定理由（20〜1000文字）

    Examples:
        >>> PhishingAssessment(
        ...     is_phishing=True,
        ...     confidence=0.85,
        ...     risk_level="high",
        ...     detected_brands=["paypal"],
        ...     risk_factors=["brand_impersonation", "free_ca"],
        ...     reasoning="PayPalを偽装している。証明書は無料CA。ML確率が低いが複数根拠あり。"
        ... )
    """
    is_phishing: bool = Field(description="フィッシングサイトかどうか")
    confidence: float = Field(description="判定の信頼度（0.0〜1.0）", ge=0.0, le=1.0)
    risk_level: Literal["low", "medium", "medium-high", "high", "critical"] = Field(
        description="5段階のリスクレベル"
    )
    detected_brands: List[str] = Field(default_factory=list, description="検出ブランド名のリスト")
    risk_factors: List[str] = Field(default_factory=list, description="リスク要因のリスト")
    reasoning: str = Field(description="判定理由（20〜1000文字）", min_length=20, max_length=1000)

    @field_validator("confidence", mode="before")
    @classmethod
    def _clip_confidence(cls, v: float) -> float:
        """
        信頼度を事前クリップしてから制約チェック.
        """
        return clip_confidence(v)

    @field_validator("detected_brands")
    @classmethod
    def _normalize_brands(cls, v: List[str]) -> List[str]:
        """
        ブランド名は小文字化＋重複排除.
        """
        return normalize_list(v)

    @field_validator("risk_factors")
    @classmethod
    def _dedup_risk_factors(cls, v: List[str]) -> List[str]:
        """
        リスク要因は重複のみ排除（大文字小文字は保持）.
        """
        uniq: List[str] = []
        seen: set[str] = set()
        for r in v or []:
            if r not in seen:
                seen.add(r)
                uniq.append(r)
        return uniq

# ==============================
# LangGraph 用 AgentState
# ==============================

class AgentState(TypedDict, total=False):
    """
    LangGraph の StateGraph で用いる状態.

    StateGraph の各ノードがこの状態を更新していく。
    Annotated を使って累積更新のルールを宣言する。

    重要: tool_results は merge_dicts カスタムリデューサを使用。
    これにより、dict + dict の未定義演算を回避し、
    キー重複時に「後勝ち」（新しい値 y を採用）を実現する。

    Attributes:
        domain: 対象ドメイン名
        ml_probability: XGBoost など第一層の予測確率
        current_step: 現在のステップ名
        precheck_hints: 事前チェックのヒント情報
        selected_tools: 選択されたツール名のリスト
        tool_results: 各ツールの実行結果（累積、merge_dicts でマージ）
        final_assessment: 最終判定結果
        error: エラーメッセージ
        retry_count: リトライ回数
        fallback_count: フォールバック発動回数（累積）
        fallback_locations: フォールバック発動箇所のリスト（累積、+で連結）
    """
    # 入力
    domain: str
    ml_probability: float

    # 中間状態
    current_step: str  # "initial" | "precheck" | "tool_selection" | "tool_execution" | "final" | "completed" | "error"
    precheck_hints: Dict[str, Any]
    selected_tools: List[str]

    # ツール結果（累積）
    tool_results: Annotated[Dict[str, Any], merge_dicts]

    # 最終結果
    final_assessment: Optional[PhishingAssessment]

    # エラー・デバッグ情報
    error: Optional[str]
    retry_count: int
    fallback_count: int
    fallback_locations: Annotated[List[str], add]

# ==============================
# カスタム例外
# ==============================

class PhishingAgentError(Exception):
    """
    AI エージェント基底例外.
    すべてのカスタム例外は本クラスを継承する。
    """
    def __init__(
        self,
        message: str,
        domain: Optional[str] = None,
        ml_probability: Optional[float] = None,
        step: Optional[str] = None,
        original_error: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        エージェント例外を初期化.

        Args:
            message: エラーメッセージ
            domain: ドメイン名
            ml_probability: ML 確率
            step: エラーが発生したステップ
            original_error: 元の例外のメッセージ
            context: 追加のコンテキスト情報
        """
        super().__init__(message)
        self.message = message
        self.domain = domain
        self.ml_probability = ml_probability
        self.step = step
        self.original_error = original_error
        self.context: Dict[str, Any] = dict(context or {})

    def to_dict(self) -> Dict[str, Any]:
        """
        例外内容を辞書化して返す（ログ・API応答用）.
        """
        return {
            "error_type": self.__class__.__name__,
            "message": self.message,
            "domain": self.domain,
            "ml_probability": self.ml_probability,
            "step": self.step,
            "original_error": self.original_error,
            "context": self.context,
        }


class ToolExecutionError(PhishingAgentError):
    """
    ツール実行時の例外.
    """
    def __init__(self, message: str, tool_name: Optional[str] = None, **kwargs: Any) -> None:
        super().__init__(message, **kwargs)
        self.tool_name = tool_name

    def to_dict(self) -> Dict[str, Any]:
        d = super().to_dict()
        d["tool_name"] = self.tool_name
        return d


class ConfigurationError(PhishingAgentError):
    """
    設定ファイルや環境変数の不備に起因する例外.
    """
    pass


class DataValidationError(PhishingAgentError):
    """
    入力データの妥当性違反に起因する例外.
    """
    pass


class LLMConnectionError(PhishingAgentError):
    """
    LLM 接続・応答異常に関連する例外.
    """
    def __init__(
        self,
        message: str,
        provider: Optional[str] = None,
        endpoint: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, **kwargs)
        self.provider = provider
        self.endpoint = endpoint

    def to_dict(self) -> Dict[str, Any]:
        d = super().to_dict()
        if self.provider:
            d["provider"] = self.provider
        if self.endpoint:
            d["endpoint"] = self.endpoint
        return d

# 互換用（仕様書の別版で指定されている例外クラス）
class StructuredOutputError(PhishingAgentError):
    """Structured Output のパース不整合."""
    pass

class GraphExecutionError(PhishingAgentError):
    """LangGraph 実行時の例外."""
    pass

# 注意: builtins.TimeoutError を隠蔽するが、モジュール内用途に限定
class TimeoutError(PhishingAgentError):
    """処理のタイムアウト."""
    pass

# ==============================
# テストコード
# ==============================

def _test_merge_dicts() -> None:
    """merge_dicts の基本動作テスト + nested dict."""
    assert merge_dicts({}, {}) == {}
    assert merge_dicts({"a": 1}, {"b": 2}) == {"a": 1, "b": 2}
    # 後勝ちの確認
    assert merge_dicts({"k": 1}, {"k": 2}) == {"k": 2}
    # None 入力の取り扱い
    assert merge_dicts(None, {"x": 1}) == {"x": 1}
    assert merge_dicts({"x": 1}, None) == {"x": 1}
    # ネスト辞書の共存（浅いマージ）
    out = merge_dicts({"tool1": {"status": "ok"}}, {"tool2": {"status": "ok"}})
    assert "tool1" in out and "tool2" in out


def _test_pydantic_schemas() -> None:
    """Pydantic スキーマのバリデーションテスト."""
    # ToolSelectionResult 正常
    ts = ToolSelectionResult(
        selected_tools=["brand_impersonation_check", "certificate_analysis", "certificate_analysis"],
        reasoning="PayPalブランドを含むため偽装チェックと証明書分析が必要です。",
        confidence=0.85,
    )
    assert ts.selected_tools == ["brand_impersonation_check", "certificate_analysis"]
    assert abs(ts.confidence - 0.85) < 1e-9

    # 不正ツール名の検出
    try:
        ToolSelectionResult(
            selected_tools=["invalid_tool"],
            reasoning="不正ツール名のテストです。十分な長さがあります。",
            confidence=0.5,
        )
        raise AssertionError("無効なツール名で例外が発生しなかった")
    except ValueError as e:
        assert "無効なツール名" in str(e)

    # 信頼度クリップ（上限）
    ts2 = ToolSelectionResult(
        selected_tools=[],
        reasoning="上限クリップのテストのための十分な長さの文字列です。",
        confidence=1.5,
    )
    assert abs(ts2.confidence - 1.0) < 1e-9

    # PhishingAssessment 正常 + 正規化
    pa = PhishingAssessment(
        is_phishing=True,
        confidence=0.92,
        risk_level="high",  # 任意入力だが get_risk_level とは独立に保持
        detected_brands=["PayPal", " paypal ", "PAYPAL"],
        risk_factors=["brand_impersonation", "free_ca", "free_ca"],
        reasoning="PayPal を偽装しており、証明書に組織情報が存在しないことなど複数の根拠があります。",
    )
    assert pa.detected_brands == ["paypal"]
    assert pa.risk_factors == ["brand_impersonation", "free_ca"]

    # 信頼度クリップ（下限）
    pa2 = PhishingAssessment(
        is_phishing=False,
        confidence=-0.3,
        risk_level="low",
        reasoning="正規サイトと判断しました。十分な長さの説明文です。",
    )
    assert abs(pa2.confidence - 0.0) < 1e-9


def _test_custom_exceptions() -> None:
    """カスタム例外の to_dict() テスト."""
    try:
        raise StructuredOutputError(
            "LLM出力のパースに失敗",
            domain="test.com",
            ml_probability=0.5,
            step="tool_selection",
            original_error="JSONDecodeError",
        )
    except StructuredOutputError as e:
        d = e.to_dict()
        assert d["error_type"] == "StructuredOutputError"
        assert d["domain"] == "test.com"
        assert "パース" in d["message"]

    try:
        raise ToolExecutionError(
            "ツール実行に失敗",
            tool_name="brand_impersonation_check",
            domain="example.com",
            ml_probability=0.3,
        )
    except ToolExecutionError as e:
        d = e.to_dict()
        assert d["error_type"] == "ToolExecutionError"
        assert d["tool_name"] == "brand_impersonation_check"

    try:
        raise LLMConnectionError(
            "エンドポイントに接続できません",
            provider="vllm",
            endpoint="http://localhost:8000/v1",
            domain="foo.bar",
        )
    except LLMConnectionError as e:
        d = e.to_dict()
        assert d["error_type"] == "LLMConnectionError"
        assert d["provider"] == "vllm"
        assert "endpoint" in d


def _test_helper_functions() -> None:
    """ヘルパー関数の境界値・基本動作テスト."""
    # clip_confidence
    assert clip_confidence(1.5) == 1.0
    assert clip_confidence(-0.5) == 0.0
    assert clip_confidence(0.0) == 0.0
    assert clip_confidence(1.0) == 1.0
    assert clip_confidence(0.55) == 0.55

    # normalize_list
    items = ["PayPal", "paypal", " PAYPAL ", "", "amazon", "Amazon  ", "   "]
    assert normalize_list(items) == ["paypal", "amazon"]
    assert normalize_list(["", "  ", ""]) == []

    # get_risk_level
    assert get_risk_level(0.95, True) == "critical"
    assert get_risk_level(0.75, True) == "high"
    assert get_risk_level(0.55, True) == "medium-high"
    assert get_risk_level(0.35, True) == "medium"
    assert get_risk_level(0.15, True) == "low"
    assert get_risk_level(0.95, False) == "low"

    # convert_to_phase2_format
    pa = PhishingAssessment(
        is_phishing=True,
        confidence=0.95,
        risk_level=get_risk_level(0.95, True),
        detected_brands=["PayPal"],
        risk_factors=["brand_impersonation"],
        reasoning="ブランド偽装の明確な証拠があるため、危険度は非常に高いと判断。",
    )
    result = convert_to_phase2_format(
        domain="paypal-secure-login.info",
        ml_probability=0.12,
        assessment=pa,
        tools_used=["brand_impersonation_check", "certificate_analysis"],
        processing_time=2.51,
        success=True,
    )
    assert result["ai_is_phishing"] is True
    assert result["ai_risk_level"] == "critical"
    assert "tools_used" in result and len(result["tools_used"]) == 2

    # 失敗ケースの拡張
    result_err = convert_to_phase2_format(
        domain="example.com",
        ml_probability=0.5,
        assessment=pa,
        tools_used=[],
        processing_time=0.01,
        success=False,
        error="Timeout",
        error_category="timeout",
        extra="ok",
    )
    assert result_err["success"] is False
    assert result_err["error_category"] == "timeout"
    assert result_err["extra"] == "ok"


def run_all_tests() -> None:
    """
    Phase 1 の全テストを順に実行し、結果を表示する。
    """
    print("=" * 80)
    print("Phase 1: 基礎設計と型定義 - テスト実行")
    print("=" * 80)

    _test_merge_dicts()
    print("✅ merge_dicts のテスト完了")

    _test_pydantic_schemas()
    print("✅ Pydantic スキーマのテスト完了")

    _test_custom_exceptions()
    print("✅ カスタム例外のテスト完了")

    _test_helper_functions()
    print("✅ ヘルパー関数のテスト完了")

    print("\n" + "=" * 80)
    print("✅ Phase 1 の全テスト完了")
    print("=" * 80)


if __name__ == "__main__":
    run_all_tests()
