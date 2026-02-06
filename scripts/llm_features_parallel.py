#!/usr/bin/env python3
"""
LLM特徴量抽出 - 並列処理スクリプト

3GPU並列でLLM特徴量を抽出する。

Usage:
    python scripts/llm_features_parallel.py \
        --input artifacts/2026-02-02_224105/fn_candidates_for_llm.csv \
        --output artifacts/2026-02-02_224105/llm_features.csv \
        --ports 8000,8001,8002

変更履歴:
    - 2026-02-02: 初版作成
"""

import os
import sys
import json
import argparse
import time
import re
from pathlib import Path
from typing import Optional, List, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

import pandas as pd
import requests
from pydantic import BaseModel, Field


# ============================================================================
# Pydantic Models (from llm_domain_features.py)
# ============================================================================

class TypoAnalysis(BaseModel):
    is_typosquatting: bool = Field(default=False)
    target_brand: Optional[str] = Field(default=None)
    similarity_score: float = Field(default=0.0, ge=0.0, le=1.0)
    typo_type: Optional[str] = Field(default=None)

class LegitimacyAnalysis(BaseModel):
    legitimacy_score: float = Field(default=0.5, ge=0.0, le=1.0)
    looks_legitimate: bool = Field(default=True)
    red_flags: List[str] = Field(default_factory=list)

class DGAAnalysis(BaseModel):
    is_likely_dga: bool = Field(default=False)
    dga_score: float = Field(default=0.0, ge=0.0, le=1.0)

class DomainFeatures(BaseModel):
    domain: str
    typo_analysis: TypoAnalysis = Field(default_factory=TypoAnalysis)
    legitimacy_analysis: LegitimacyAnalysis = Field(default_factory=LegitimacyAnalysis)
    dga_analysis: DGAAnalysis = Field(default_factory=DGAAnalysis)
    impersonation_target: Optional[str] = Field(default=None)
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)


# ============================================================================
# Japanese Brand Context
# ============================================================================

JAPANESE_BRANDS = """
Japanese brands/services for typosquatting detection:
- kuronekoyamato, yamato, kuronek: ヤマト運輸
- sagawa: 佐川急便
- japanpost, yubin: 日本郵便
- smbc: 三井住友銀行
- mufg, mitsubishi: 三菱UFJ銀行
- mizuho: みずほ銀行
- rakuten: 楽天
- amazon: Amazon
- mercari: メルカリ
- aeon: イオン
- docomo: NTTドコモ
- au: KDDI/au
- softbank: ソフトバンク
- line: LINE
- yahoo: Yahoo! Japan
- ekinet: JR東日本
- jcb, visa, mastercard: クレジットカード
"""


# ============================================================================
# LLM Feature Extractor
# ============================================================================

class ParallelExtractor:
    """並列LLM特徴量抽出器"""

    def __init__(self, ports: List[int], model_name: str = "JunHowie/Qwen3-4B-Thinking-2507-GPTQ-Int8"):
        self.ports = ports
        self.model_name = model_name
        self.lock = Lock()
        self.results = []
        self.progress = {"completed": 0, "failed": 0, "total": 0}

    def _call_api(self, port: int, domain: str) -> Optional[DomainFeatures]:
        """単一ドメインのAPI呼び出し"""
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

        try:
            response = requests.post(
                f"http://localhost:{port}/v1/completions",
                json={
                    "model": self.model_name,
                    "prompt": prompt,
                    "max_tokens": 1500,
                    "temperature": 0.0,
                },
                timeout=120
            )

            if response.status_code == 200:
                text = response.json()['choices'][0]['text'].strip()
                json_data = self._extract_json(text)
                if json_data:
                    return DomainFeatures(**json_data)
        except Exception as e:
            pass
        return None

    def _extract_json(self, text: str) -> Optional[dict]:
        """バランスドブレース法でJSON抽出"""
        if not text:
            return None

        if '</think>' in text:
            text = text.split('</think>')[-1].strip()

        start = text.find('{')
        if start == -1:
            return None

        depth = 0
        in_string = False
        escape = False

        for i, c in enumerate(text[start:], start):
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
                    try:
                        return json.loads(text[start:i+1])
                    except json.JSONDecodeError:
                        return None
        return None

    def _process_domain(self, domain: str, port: int, idx: int) -> Dict:
        """単一ドメイン処理"""
        features = self._call_api(port, domain)

        with self.lock:
            if features:
                self.progress["completed"] += 1
                result = {
                    "domain": domain,
                    "is_typosquatting": features.typo_analysis.is_typosquatting,
                    "target_brand": features.typo_analysis.target_brand,
                    "similarity_score": features.typo_analysis.similarity_score,
                    "typo_type": features.typo_analysis.typo_type,
                    "legitimacy_score": features.legitimacy_analysis.legitimacy_score,
                    "looks_legitimate": features.legitimacy_analysis.looks_legitimate,
                    "red_flags": "|".join(features.legitimacy_analysis.red_flags),
                    "is_dga": features.dga_analysis.is_likely_dga,
                    "dga_score": features.dga_analysis.dga_score,
                    "impersonation_target": features.impersonation_target,
                    "risk_score": features.risk_score,
                    "error": None,
                }
            else:
                self.progress["failed"] += 1
                result = {
                    "domain": domain,
                    "error": "extraction_failed",
                }

            # Progress update every 50 domains
            total_done = self.progress["completed"] + self.progress["failed"]
            if total_done % 50 == 0 or total_done == self.progress["total"]:
                print(f"Progress: {total_done}/{self.progress['total']} "
                      f"(OK: {self.progress['completed']}, Failed: {self.progress['failed']})")

        return result

    def process_batch(self, domains: List[str], output_file: str):
        """バッチ処理"""
        self.progress["total"] = len(domains)
        print(f"Processing {len(domains)} domains with {len(self.ports)} GPUs...")

        results = []

        # Use ThreadPoolExecutor for parallel processing
        with ThreadPoolExecutor(max_workers=len(self.ports) * 2) as executor:
            futures = {}
            for idx, domain in enumerate(domains):
                port = self.ports[idx % len(self.ports)]
                future = executor.submit(self._process_domain, domain, port, idx)
                futures[future] = domain

            for future in as_completed(futures):
                result = future.result()
                results.append(result)

        # Save results
        df = pd.DataFrame(results)
        df.to_csv(output_file, index=False)
        print(f"\nResults saved to: {output_file}")
        print(f"Total: {len(results)}, Success: {self.progress['completed']}, Failed: {self.progress['failed']}")

        # Summary statistics
        success_df = df[df['error'].isna()]
        if len(success_df) > 0:
            print(f"\n=== Summary ===")
            print(f"Typosquatting detected: {success_df['is_typosquatting'].sum()} ({100*success_df['is_typosquatting'].mean():.1f}%)")
            print(f"DGA detected: {success_df['is_dga'].sum()} ({100*success_df['is_dga'].mean():.1f}%)")
            print(f"Risk score >= 0.7: {(success_df['risk_score'] >= 0.7).sum()}")
            print(f"Risk score mean: {success_df['risk_score'].mean():.3f}")

            # Top brands detected
            brands = success_df[success_df['target_brand'].notna()]['target_brand'].value_counts().head(10)
            if len(brands) > 0:
                print(f"\nTop detected brands:")
                for brand, count in brands.items():
                    print(f"  {brand}: {count}")


def main():
    parser = argparse.ArgumentParser(description="Parallel LLM Feature Extraction")
    parser.add_argument("--input", "-i", required=True, help="Input CSV with domains")
    parser.add_argument("--output", "-o", required=True, help="Output CSV for results")
    parser.add_argument("--ports", default="8000,8001,8002", help="Comma-separated vLLM ports")
    parser.add_argument("--model", default="JunHowie/Qwen3-4B-Thinking-2507-GPTQ-Int8", help="Model name")

    args = parser.parse_args()

    # Parse ports
    ports = [int(p.strip()) for p in args.ports.split(",")]

    # Load domains
    df = pd.read_csv(args.input)
    domains = df['domain'].tolist()

    # Process
    extractor = ParallelExtractor(ports=ports, model_name=args.model)
    extractor.process_batch(domains, args.output)


if __name__ == "__main__":
    main()
