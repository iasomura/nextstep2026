#!/usr/bin/env python3
"""
ブランド除外パターンの効果分析スクリプト

評価結果からブランド除外パターンの効果を分析する。
特定のブランドキーワードによるFP/TPを確認し、除外の効果を検証する。

使用方法:
    python scripts/analyze_brand_exclusion.py [results_dir]

例:
    python scripts/analyze_brand_exclusion.py artifacts/2026-01-24_213326/results/stage2_validation
"""

import pandas as pd
import glob
import sys
import re
from typing import List, Dict, Tuple

# 除外対象のブランドキーワード（BOUNDARY_REQUIRED_BRANDS に追加したもの）
EXCLUDED_BRANDS = {
    # 2026-01-29 追加分 (v2評価)
    "steam": {
        "exclusion_words": ["stream", "upstream", "downstream", "mainstream", "livestream"],
        "fp_examples": ["sharp-stream.com"],
    },
    "roblox": {
        "exclusion_words": ["oblog", "noblog", "blog"],
        "fp_examples": ["noblog.net"],
    },
    "eshop": {
        "exclusion_words": ["noodleshop", "coffeeshop", "workshop", "bookshop"],
        "fp_examples": ["pennysnoodleshop.info"],
    },
    # 以前の追加分
    "costco": {
        "exclusion_words": ["costa", "costarica", "custo", "costumer", "costume"],
        "fp_examples": ["costa-rica-guide.com"],
    },
    "youtube": {
        "exclusion_words": ["yourule", "yourtube"],
        "fp_examples": ["yourule.top"],
    },
    "laposte": {
        "exclusion_words": ["lacoste"],
        "fp_examples": ["lacoste.com"],
    },
    "sbinet": {
        "exclusion_words": ["rinet", "biznet"],
        "fp_examples": ["biznet.id"],
    },
    # 2026-01-29 追加分 (#10 fuzzy2 FP対策)
    "bestbuy": {
        "exclusion_words": ["bitbuy", "buybuy", "buybit"],
        "fp_examples": ["bitbuy.ca"],
    },
    "binance": {
        "exclusion_words": ["balance", "finance", "refinance", "alliance", "vigilance"],
        "fp_examples": ["balance.media", "next-finance.net"],
    },
    "usbank": {
        "exclusion_words": ["unisbank", "unibank"],
        "fp_examples": ["unisbank.ac.id"],
    },
    "signal": {
        "exclusion_words": ["sigsac", "sigact", "sigmod", "sigchi", "sigplan", "sigops"],
        "fp_examples": ["sigsac.org"],
    },
    "nordea": {
        "exclusion_words": ["norge", "nordic", "nordia"],
        "fp_examples": ["curasept-norge.no"],
    },
    "shopify": {
        "exclusion_words": ["shoppy", "shoppie", "shopping"],
        "fp_examples": ["shoppy.gg"],
    },
    # 2026-01-29 追加分 (#11 compound/substring FP対策)
    "acom": {
        "exclusion_words": ["revistacomunicar", "pharmacomedicale", "comunicar", "comedicale", "pharmacom", "telecom", "dotcom", "intercom"],
        "fp_examples": ["revistacomunicar.com", "pharmacomedicale.org"],
    },
    "wise": {
        "exclusion_words": ["worldwise", "otherwise", "likewise", "clockwise", "pairwise", "stepwise"],
        "fp_examples": ["worldwisepeople.net"],
    },
    "stripe": {
        "exclusion_words": ["stripes", "starsandstripes", "pinstripe", "pinstripes"],
        "fp_examples": ["starsandstripesfc.com"],
    },
    "tmobile": {
        "exclusion_words": ["xtmobile"],
        "fp_examples": ["xtmobile.vn"],
    },
    "promise": {
        "exclusion_words": ["americaspromise", "compromise", "compromises"],
        "fp_examples": ["americaspromise.org"],
    },
    "disney": {
        "exclusion_words": ["disneydriven", "disneyfan", "disneylife"],
        "fp_examples": ["thedisneydrivenlife.com"],
    },
    "mastercard": {
        "exclusion_words": ["mastercardfdn", "mastercardfoundation"],
        "fp_examples": ["mastercardfdn.org"],
    },
}


def load_results(results_dir: str) -> pd.DataFrame:
    """評価結果を読み込む"""
    dfs = []
    for f in glob.glob(f"{results_dir}/worker_*_results.csv"):
        try:
            df = pd.read_csv(f)
            dfs.append(df)
        except Exception as e:
            print(f"Warning: Could not load {f}: {e}")

    if not dfs:
        raise ValueError(f"No results found in {results_dir}")

    combined = pd.concat(dfs, ignore_index=True)
    # 重複排除
    combined = combined.drop_duplicates(subset='domain', keep='first')
    return combined


def analyze_brand(df: pd.DataFrame, brand: str, info: Dict) -> Dict:
    """特定ブランドの検出状況を分析"""
    results = {
        "brand": brand,
        "exclusion_words": info["exclusion_words"],
        "fp_examples": info["fp_examples"],
        "detected_count": 0,
        "tp_count": 0,
        "fp_count": 0,
        "fp_domains": [],
        "tp_domains": [],
    }

    # ブランドが検出されたケースを抽出
    brand_pattern = re.compile(rf'\b{brand}\b', re.IGNORECASE)

    for _, row in df.iterrows():
        detected_brands = str(row.get('ai_detected_brands', ''))
        if brand_pattern.search(detected_brands):
            results["detected_count"] += 1

            is_phishing = row.get('ai_is_phishing', False)
            actual = row.get('y_true', 0)

            if is_phishing and actual == 1:  # TP
                results["tp_count"] += 1
                results["tp_domains"].append(row['domain'])
            elif is_phishing and actual == 0:  # FP
                results["fp_count"] += 1
                results["fp_domains"].append(row['domain'])

    return results


def check_exclusion_effect(df: pd.DataFrame, brand: str, info: Dict) -> Dict:
    """除外パターンの効果を確認"""
    effect = {
        "brand": brand,
        "exclusion_words_found": [],
        "would_be_fp": [],
    }

    # 除外ワードがドメインに含まれるケースをチェック
    for word in info["exclusion_words"]:
        for _, row in df.iterrows():
            domain = row['domain'].lower()
            if word in domain:
                detected_brands = str(row.get('ai_detected_brands', '')).lower()
                is_phishing = row.get('ai_is_phishing', False)
                actual = row.get('y_true', 0)

                # ブランドが検出されていない場合、除外が効いている
                if brand.lower() not in detected_brands:
                    effect["exclusion_words_found"].append({
                        "domain": row['domain'],
                        "word": word,
                        "status": "excluded",
                        "actual_label": "phishing" if actual == 1 else "benign",
                    })
                else:
                    # ブランドが検出されている場合
                    if is_phishing and actual == 0:
                        effect["would_be_fp"].append({
                            "domain": row['domain'],
                            "word": word,
                        })

    return effect


def main():
    if len(sys.argv) < 2:
        results_dir = "artifacts/2026-01-24_213326/results/stage2_validation"
    else:
        results_dir = sys.argv[1]

    print(f"Loading results from: {results_dir}")
    df = load_results(results_dir)
    print(f"Loaded {len(df)} unique samples\n")

    # FP/FN集計
    fp = df[(df['ai_is_phishing'] == True) & (df['y_true'] == 0)]
    fn = df[(df['ai_is_phishing'] == False) & (df['y_true'] == 1)]
    tp = df[(df['ai_is_phishing'] == True) & (df['y_true'] == 1)]
    tn = df[(df['ai_is_phishing'] == False) & (df['y_true'] == 0)]

    print("="*60)
    print("        全体サマリ")
    print("="*60)
    print(f"TP: {len(tp)}, FP: {len(fp)}, TN: {len(tn)}, FN: {len(fn)}")
    print()

    print("="*60)
    print("        ブランド別分析")
    print("="*60)

    for brand, info in EXCLUDED_BRANDS.items():
        print(f"\n【{brand}】")
        print(f"  除外ワード: {', '.join(info['exclusion_words'])}")

        # ブランド検出状況
        analysis = analyze_brand(df, brand, info)
        print(f"  検出数: {analysis['detected_count']} (TP: {analysis['tp_count']}, FP: {analysis['fp_count']})")

        if analysis['fp_domains']:
            print(f"  FPドメイン:")
            for d in analysis['fp_domains'][:5]:
                print(f"    - {d}")

        # 除外効果
        effect = check_exclusion_effect(df, brand, info)
        if effect['exclusion_words_found']:
            print(f"  除外が効いたケース: {len(effect['exclusion_words_found'])}件")
            for item in effect['exclusion_words_found'][:3]:
                print(f"    - {item['domain']} (word: {item['word']}, actual: {item['actual_label']})")

    print("\n" + "="*60)
    print("        除外パターン効果サマリ")
    print("="*60)

    total_excluded = 0
    total_remaining_fp = 0

    for brand, info in EXCLUDED_BRANDS.items():
        effect = check_exclusion_effect(df, brand, info)
        analysis = analyze_brand(df, brand, info)

        excluded = len(effect['exclusion_words_found'])
        remaining_fp = analysis['fp_count']

        total_excluded += excluded
        total_remaining_fp += remaining_fp

        print(f"  {brand}: 除外={excluded}, 残FP={remaining_fp}")

    print(f"\n  合計: 除外={total_excluded}, 残FP={total_remaining_fp}")


if __name__ == "__main__":
    main()
