# -*- coding: utf-8 -*-
"""
LLMスクリーニング用Pydanticスキーマ

Structured Output (with_structured_output) で使用するスキーマ定義。

変更履歴:
    - 2026-02-03: 初版作成
"""
from typing import Optional, List
from pydantic import BaseModel, Field


class TypoAnalysis(BaseModel):
    """Typosquatting分析結果"""
    is_typosquatting: bool = Field(
        default=False,
        description="ドメイン名が有名ブランドのtyposquattingかどうか"
    )
    target_brand: Optional[str] = Field(
        default=None,
        description="模倣対象のブランド名（検出された場合）"
    )
    similarity_score: float = Field(
        default=0.0,
        ge=0.0, le=1.0,
        description="ブランド名との類似度スコア (0.0-1.0)"
    )


class LegitimacyAnalysis(BaseModel):
    """正当性分析結果"""
    legitimacy_score: float = Field(
        default=0.5,
        ge=0.0, le=1.0,
        description="正規ドメインとしての自然さスコア (0.0-1.0)"
    )
    red_flags: List[str] = Field(
        default_factory=list,
        description="検出されたリスク要因のリスト"
    )


class DGAAnalysis(BaseModel):
    """DGA (Domain Generation Algorithm) 分析結果"""
    is_likely_dga: bool = Field(
        default=False,
        description="自動生成ドメイン（DGA）の可能性が高いかどうか"
    )
    dga_score: float = Field(
        default=0.0,
        ge=0.0, le=1.0,
        description="DGAの可能性スコア (0.0-1.0)"
    )


class DomainScreeningResult(BaseModel):
    """ドメインスクリーニング結果 (Structured Output用)"""
    domain: str = Field(description="分析対象のドメイン名")
    typo_analysis: TypoAnalysis = Field(
        default_factory=TypoAnalysis,
        description="Typosquatting分析"
    )
    legitimacy_analysis: LegitimacyAnalysis = Field(
        default_factory=LegitimacyAnalysis,
        description="正当性分析"
    )
    dga_analysis: DGAAnalysis = Field(
        default_factory=DGAAnalysis,
        description="DGA分析"
    )
    impersonation_target: Optional[str] = Field(
        default=None,
        description="模倣対象のサービス/企業名"
    )
    risk_score: float = Field(
        default=0.0,
        ge=0.0, le=1.0,
        description="総合リスクスコア (0.0-1.0)"
    )
