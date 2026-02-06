#!/usr/bin/env python3
"""
LLM-based Domain Feature Extraction

ドメイン名からLLMを使用して特徴量を抽出するスクリプト。
Structured Output (Pydantic) を使用して、一貫したJSON形式で特徴量を取得。

Usage:
    # 単一ドメイン
    python scripts/llm_domain_features.py example.com

    # バッチ処理
    python scripts/llm_domain_features.py --input domains.csv --output features.csv

    # vLLM使用（ローカル）
    python scripts/llm_domain_features.py --provider vllm --port 8000 example.com

References:
    - LangChain Structured Output: https://docs.langchain.com/oss/python/langchain/structured-output
    - Pydantic: https://docs.pydantic.dev/

変更履歴:
    - 2026-02-02: 初版作成 - LLM特徴量抽出スクリプト
"""

import os
import sys
import json
import argparse
import re
from typing import Optional, List
from pathlib import Path

# Pydantic for structured output
from pydantic import BaseModel, Field

# LangChain imports
try:
    from langchain_openai import ChatOpenAI
    from langchain_core.prompts import ChatPromptTemplate
    from langchain_core.output_parsers import PydanticOutputParser
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False
    print("Warning: LangChain not installed. Using fallback mode.")

# Direct API for fallback
import requests


# ============================================================================
# Pydantic Models for Structured Output
# ============================================================================

class TypoAnalysis(BaseModel):
    """Typosquatting分析結果"""
    is_typosquatting: bool = Field(
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
    typo_type: Optional[str] = Field(
        default=None,
        description="typoの種類: character_swap, missing_char, extra_char, homoglyph, none"
    )


class LegitimacyAnalysis(BaseModel):
    """正当性分析結果"""
    legitimacy_score: float = Field(
        ge=0.0, le=1.0,
        description="正規ドメインとしての自然さスコア (0.0-1.0)"
    )
    looks_legitimate: bool = Field(
        description="正規のビジネスドメインに見えるかどうか"
    )
    red_flags: List[str] = Field(
        default_factory=list,
        description="検出されたリスク要因のリスト"
    )


class DGAAnalysis(BaseModel):
    """DGA (Domain Generation Algorithm) 分析結果"""
    is_likely_dga: bool = Field(
        description="自動生成ドメイン（DGA）の可能性が高いかどうか"
    )
    dga_score: float = Field(
        default=0.0,
        ge=0.0, le=1.0,
        description="DGAの可能性スコア (0.0-1.0)"
    )


class DomainFeatures(BaseModel):
    """ドメイン特徴量の統合モデル"""
    domain: str = Field(description="分析対象のドメイン名")
    typo_analysis: TypoAnalysis = Field(description="Typosquatting分析")
    legitimacy_analysis: LegitimacyAnalysis = Field(description="正当性分析")
    dga_analysis: DGAAnalysis = Field(description="DGA分析")
    impersonation_target: Optional[str] = Field(
        default=None,
        description="模倣対象のサービス/企業名"
    )
    risk_score: float = Field(
        default=0.0,
        ge=0.0, le=1.0,
        description="総合リスクスコア (0.0-1.0)"
    )


# ============================================================================
# Japanese Brand Keywords for Better Detection
# ============================================================================

JAPANESE_BRANDS = """
日本のブランド/サービスリスト（typosquatting検出用）:
- kuronekoyamato, yamato: ヤマト運輸（クロネコヤマト）
- sagawa: 佐川急便
- japanpost, yubin: 日本郵便
- smbc: 三井住友銀行
- mufg, mitsubishi: 三菱UFJ銀行
- mizuho: みずほ銀行
- rakuten: 楽天
- amazon, アマゾン: Amazon
- mercari, メルカリ: メルカリ
- aeon, イオン: イオン
- docomo, ドコモ: NTTドコモ
- au, エーユー: KDDI/au
- softbank: ソフトバンク
- line, ライン: LINE
- yahoo, ヤフー: Yahoo! Japan
- biglobe: BIGLOBE
- nifty: @nifty
- jcb: JCB
- visa, mastercard: クレジットカード
- ekinet, えきねっと: JR東日本
- etc: ETC
"""


# ============================================================================
# Prompt Templates
# ============================================================================

ANALYSIS_PROMPT = """あなたはフィッシングドメイン分析の専門家です。
与えられたドメイン名を分析し、以下の観点で評価してください。

{brand_context}

分析対象ドメイン: {domain}

以下の点を分析してください:
1. Typosquatting分析: 有名ブランドの綴り違いかどうか
2. 正当性分析: 正規のビジネスドメインとして自然かどうか
3. DGA分析: 自動生成ドメインの可能性
4. 模倣対象: どのサービス/企業を模倣しているか

{format_instructions}
"""


# ============================================================================
# LLM Feature Extractor Classes
# ============================================================================

class LLMFeatureExtractor:
    """LLMを使用したドメイン特徴量抽出器（基底クラス）"""

    def __init__(self, model_name: str = "gpt-4o-mini", temperature: float = 0.0):
        self.model_name = model_name
        self.temperature = temperature

    def extract(self, domain: str) -> Optional[DomainFeatures]:
        """ドメインから特徴量を抽出"""
        raise NotImplementedError


class LangChainExtractor(LLMFeatureExtractor):
    """LangChain + Structured Output を使用した抽出器"""

    def __init__(self,
                 model_name: str = "gpt-4o-mini",
                 temperature: float = 0.0,
                 api_key: Optional[str] = None,
                 base_url: Optional[str] = None):
        super().__init__(model_name, temperature)

        if not LANGCHAIN_AVAILABLE:
            raise ImportError("LangChain is not installed")

        # Initialize ChatOpenAI (works with OpenAI-compatible APIs)
        self.llm = ChatOpenAI(
            model=model_name,
            temperature=temperature,
            api_key=api_key or os.getenv("OPENAI_API_KEY", "dummy"),
            base_url=base_url,
        )

        # Create parser for structured output
        self.parser = PydanticOutputParser(pydantic_object=DomainFeatures)

        # Create prompt template
        self.prompt = ChatPromptTemplate.from_template(ANALYSIS_PROMPT)

    def extract(self, domain: str) -> Optional[DomainFeatures]:
        """LangChainを使用して特徴量を抽出"""
        try:
            # Try with_structured_output first (if supported)
            try:
                structured_llm = self.llm.with_structured_output(DomainFeatures)
                chain = self.prompt | structured_llm
                result = chain.invoke({
                    "domain": domain,
                    "brand_context": JAPANESE_BRANDS,
                    "format_instructions": ""
                })
                return result
            except Exception:
                pass

            # Fallback to PydanticOutputParser
            chain = self.prompt | self.llm | self.parser
            result = chain.invoke({
                "domain": domain,
                "brand_context": JAPANESE_BRANDS,
                "format_instructions": self.parser.get_format_instructions()
            })
            return result

        except Exception as e:
            print(f"Error extracting features for {domain}: {e}")
            return None


class VLLMExtractor(LLMFeatureExtractor):
    """vLLM (OpenAI互換API) を直接使用した抽出器"""

    def __init__(self,
                 base_url: str = "http://localhost:8000/v1",
                 model_name: str = "JunHowie/Qwen3-4B-Thinking-2507-GPTQ-Int8",
                 temperature: float = 0.0):
        super().__init__(model_name, temperature)
        self.base_url = base_url
        self.parser = PydanticOutputParser(pydantic_object=DomainFeatures)

    def _call_api(self, prompt: str, max_tokens: int = 1500) -> Optional[str]:
        """vLLM APIを直接呼び出す"""
        try:
            response = requests.post(
                f"{self.base_url}/completions",
                json={
                    "model": self.model_name,
                    "prompt": prompt,
                    "max_tokens": max_tokens,
                    "temperature": self.temperature,
                },
                timeout=120
            )

            if response.status_code == 200:
                result = response.json()
                return result['choices'][0]['text'].strip()
        except Exception as e:
            print(f"API call error: {e}")
        return None

    def _extract_json(self, text: str) -> Optional[dict]:
        """テキストからJSON部分を抽出

        変更履歴:
            - 2026-02-02: 貪欲マッチによる余分なテキスト取り込み問題を修正
        """
        if not text:
            return None

        # Remove thinking tags if present
        if '</think>' in text:
            text = text.split('</think>')[-1].strip()

        # Method 1: Find balanced braces to extract complete JSON object
        def find_balanced_json(s: str) -> Optional[str]:
            start = s.find('{')
            if start == -1:
                return None

            depth = 0
            in_string = False
            escape = False

            for i, c in enumerate(s[start:], start):
                if escape:
                    escape = False
                    continue
                if c == '\\' and in_string:
                    escape = True
                    continue
                if c == '"' and not escape:
                    in_string = not in_string
                    continue
                if in_string:
                    continue
                if c == '{':
                    depth += 1
                elif c == '}':
                    depth -= 1
                    if depth == 0:
                        return s[start:i+1]
            return None

        json_str = find_balanced_json(text)
        if json_str:
            try:
                return json.loads(json_str)
            except json.JSONDecodeError:
                pass

        # Method 2: Fallback to simple regex (first complete object)
        match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', text)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass
        return None

    def extract(self, domain: str) -> Optional[DomainFeatures]:
        """vLLM APIを使用して特徴量を抽出"""

        # Simplified prompt for vLLM
        prompt = f"""Analyze this domain for phishing: {domain}

{JAPANESE_BRANDS}

Output ONLY valid JSON matching this schema:
{{
  "domain": "{domain}",
  "typo_analysis": {{
    "is_typosquatting": true/false,
    "target_brand": "brand name or null",
    "similarity_score": 0.0-1.0,
    "typo_type": "character_swap|missing_char|extra_char|homoglyph|null"
  }},
  "legitimacy_analysis": {{
    "legitimacy_score": 0.0-1.0,
    "looks_legitimate": true/false,
    "red_flags": ["flag1", "flag2"]
  }},
  "dga_analysis": {{
    "is_likely_dga": true/false,
    "dga_score": 0.0-1.0
  }},
  "impersonation_target": "service name or null",
  "risk_score": 0.0-1.0
}}

JSON:"""

        response_text = self._call_api(prompt)
        json_data = self._extract_json(response_text)

        if json_data:
            try:
                return DomainFeatures(**json_data)
            except Exception as e:
                print(f"Validation error for {domain}: {e}")

        return None


# ============================================================================
# Batch Processing
# ============================================================================

def process_batch(extractor: LLMFeatureExtractor,
                  domains: List[str],
                  output_file: Optional[str] = None) -> List[dict]:
    """バッチ処理で複数ドメインの特徴量を抽出"""
    import time

    results = []
    total = len(domains)

    for i, domain in enumerate(domains):
        print(f"[{i+1}/{total}] Processing: {domain}")

        features = extractor.extract(domain)

        if features:
            result = features.model_dump()
            results.append(result)
            print(f"  -> Risk: {result['risk_score']:.2f}, "
                  f"Typo: {result['typo_analysis']['is_typosquatting']}, "
                  f"Target: {result['impersonation_target']}")
        else:
            results.append({
                "domain": domain,
                "error": "extraction_failed"
            })
            print(f"  -> Failed")

        # Rate limiting
        time.sleep(0.5)

    # Save results
    if output_file:
        import pandas as pd

        # Flatten nested structure for CSV
        flat_results = []
        for r in results:
            if "error" in r:
                flat_results.append({"domain": r["domain"], "error": r["error"]})
            else:
                flat = {
                    "domain": r["domain"],
                    "is_typosquatting": r["typo_analysis"]["is_typosquatting"],
                    "target_brand": r["typo_analysis"]["target_brand"],
                    "typo_score": r["typo_analysis"]["similarity_score"],
                    "legitimacy_score": r["legitimacy_analysis"]["legitimacy_score"],
                    "looks_legitimate": r["legitimacy_analysis"]["looks_legitimate"],
                    "red_flags": "|".join(r["legitimacy_analysis"]["red_flags"]),
                    "is_dga": r["dga_analysis"]["is_likely_dga"],
                    "dga_score": r["dga_analysis"]["dga_score"],
                    "impersonation_target": r["impersonation_target"],
                    "risk_score": r["risk_score"],
                }
                flat_results.append(flat)

        df = pd.DataFrame(flat_results)
        df.to_csv(output_file, index=False)
        print(f"\nResults saved to: {output_file}")

    return results


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="LLM-based Domain Feature Extraction"
    )
    parser.add_argument(
        "domain",
        nargs="?",
        help="Domain to analyze"
    )
    parser.add_argument(
        "--input", "-i",
        help="Input CSV file with domains"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output CSV file for results"
    )
    parser.add_argument(
        "--provider",
        choices=["openai", "vllm"],
        default="vllm",
        help="LLM provider (default: vllm)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="vLLM port (default: 8000)"
    )
    parser.add_argument(
        "--model",
        default="JunHowie/Qwen3-4B-Thinking-2507-GPTQ-Int8",
        help="Model name"
    )

    args = parser.parse_args()

    # Initialize extractor
    if args.provider == "vllm":
        extractor = VLLMExtractor(
            base_url=f"http://localhost:{args.port}/v1",
            model_name=args.model
        )
    else:
        extractor = LangChainExtractor(model_name=args.model)

    # Process
    if args.input:
        import pandas as pd
        df = pd.read_csv(args.input)
        domains = df['domain'].tolist()
        process_batch(extractor, domains, args.output)
    elif args.domain:
        features = extractor.extract(args.domain)
        if features:
            print(json.dumps(features.model_dump(), indent=2, ensure_ascii=False))
        else:
            print("Failed to extract features")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
