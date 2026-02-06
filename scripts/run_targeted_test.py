#!/usr/bin/env python3
"""
ターゲットテスト: 閾値調整・ブランドキーワード・TLD変更の効果検証

修正対象のFP/FNケースのみで評価を実行し、効果を測定する。
"""
import asyncio
import json
import os
import sys
from datetime import datetime
from pathlib import Path
import pandas as pd

# プロジェクトルートをパスに追加
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from phishing_agent.agent import evaluate_domain
from phishing_agent.llm_final_decision import get_vllm_config


async def evaluate_single(domain: str, label: int, port: int, cert_map: dict) -> dict:
    """1ドメインを評価"""
    try:
        result = await evaluate_domain(
            domain=domain,
            ml_probability=None,  # 自動取得
            vllm_port=port,
            cert_map=cert_map,
        )
        return {
            "domain": domain,
            "y_true": label,
            "ai_is_phishing": result.get("is_phishing", False),
            "ai_confidence": result.get("confidence", 0.0),
            "trace_phase6_rules_fired": json.dumps(result.get("phase6_rules_fired", [])),
            "success": True,
        }
    except Exception as e:
        return {
            "domain": domain,
            "y_true": label,
            "ai_is_phishing": None,
            "ai_confidence": None,
            "trace_phase6_rules_fired": None,
            "success": False,
            "error": str(e),
        }


async def worker(worker_id: int, domains: list, port: int, cert_map: dict, results: list):
    """ワーカー: 担当ドメインを順次評価"""
    for i, (domain, label) in enumerate(domains):
        result = await evaluate_single(domain, label, port, cert_map)
        results.append(result)
        if (i + 1) % 10 == 0:
            print(f"[Worker {worker_id}] {i+1}/{len(domains)} completed")


async def main():
    # 設定
    ports = [8000, 8001, 8002]
    test_csv = project_root / "test_data" / "threshold_adjustment_test_domains.csv"

    # 証明書マップを読み込み
    import pickle
    cert_pkl = project_root / "artifacts" / "2026-02-02_224105" / "processed" / "cert_full_info_map.pkl"
    with open(cert_pkl, "rb") as f:
        cert_map = pickle.load(f)
    print(f"Loaded {len(cert_map)} certificate records")

    # テストデータ読み込み
    df = pd.read_csv(test_csv)
    domains = [(row["domain"], row["y_true"]) for _, row in df.iterrows()]
    print(f"Test domains: {len(domains)}")

    # ドメインをワーカーに分配
    num_workers = len(ports)
    chunks = [[] for _ in range(num_workers)]
    for i, d in enumerate(domains):
        chunks[i % num_workers].append(d)

    for i, c in enumerate(chunks):
        print(f"Worker {i} (port {ports[i]}): {len(c)} domains")

    # 並列評価
    results = []
    tasks = [
        worker(i, chunks[i], ports[i], cert_map, results)
        for i in range(num_workers)
    ]

    print("\nStarting evaluation...")
    start = datetime.now()
    await asyncio.gather(*tasks)
    elapsed = (datetime.now() - start).total_seconds()

    print(f"\nCompleted in {elapsed:.1f}s")

    # 結果を保存
    result_df = pd.DataFrame(results)
    output_file = project_root / "test_data" / f"targeted_test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    result_df.to_csv(output_file, index=False)
    print(f"Saved: {output_file}")

    # 効果測定
    print("\n" + "=" * 60)
    print("効果測定")
    print("=" * 60)

    success_df = result_df[result_df["success"] == True].copy()
    success_df["is_FP"] = (success_df["ai_is_phishing"] == True) & (success_df["y_true"] == 0)
    success_df["is_FN"] = (success_df["ai_is_phishing"] == False) & (success_df["y_true"] == 1)
    success_df["is_TP"] = (success_df["ai_is_phishing"] == True) & (success_df["y_true"] == 1)
    success_df["is_TN"] = (success_df["ai_is_phishing"] == False) & (success_df["y_true"] == 0)

    # 元データ
    orig_df = df.copy()
    orig_df["was_FP"] = (orig_df["ai_is_phishing"] == True) & (orig_df["y_true"] == 0)
    orig_df["was_FN"] = (orig_df["ai_is_phishing"] == False) & (orig_df["y_true"] == 1)

    # 比較
    print(f"\n成功件数: {len(success_df)}/{len(df)}")
    print(f"\n【FP変化】")
    print(f"  修正前: {orig_df['was_FP'].sum()}件")
    print(f"  修正後: {success_df['is_FP'].sum()}件")
    print(f"  削減: {orig_df['was_FP'].sum() - success_df['is_FP'].sum()}件")

    print(f"\n【FN変化】")
    print(f"  修正前: {orig_df['was_FN'].sum()}件")
    print(f"  修正後: {success_df['is_FN'].sum()}件")
    print(f"  削減: {orig_df['was_FN'].sum() - success_df['is_FN'].sum()}件")

    # 詳細: .shop TLD
    shop_domains = ['authenticationaua.shop', 'tepcopowerjpco.shop']
    print(f"\n【.shop TLD詳細】")
    for d in shop_domains:
        row = success_df[success_df["domain"] == d]
        if len(row) > 0:
            r = row.iloc[0]
            print(f"  {d}: is_phishing={r['ai_is_phishing']} (期待: True)")

    # 詳細: ブランドキーワード
    brand_domains = ['myjcb-open.com', 'jcbrocl.com', 'kecbank.com', 'saccount-members.com', 'ulys-support.com']
    print(f"\n【ブランドキーワード詳細】")
    for d in brand_domains:
        row = success_df[success_df["domain"] == d]
        if len(row) > 0:
            r = row.iloc[0]
            print(f"  {d}: is_phishing={r['ai_is_phishing']} (期待: True)")


if __name__ == "__main__":
    asyncio.run(main())
