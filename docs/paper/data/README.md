# docs/paper/data/ — 論文用データ再生成ガイド

本ディレクトリは論文の表・図・統計の **source of truth** である。
すべてのファイルは `scripts/generate_paper_data.py` から再生成できる。

---

## 再生成コマンド

```bash
# 全Phase実行（Phase 1 + Phase 2）+ 検証
python scripts/generate_paper_data.py

# Phase 1 のみ（表1-5, 図2/4データ, 統計JSON 5件）
python scripts/generate_paper_data.py --phase 1

# Phase 2 のみ（表6アブレーション, 図3閾値スイープ, 図5誤りカテゴリ）
python scripts/generate_paper_data.py --phase 2

# 検証のみ（既存ファイルと VERIFIED 定数の整合チェック）
python scripts/generate_paper_data.py --verify
```

`--verify` はファイルを上書きせず、`system_overall_metrics.json` / `stage3_metrics.json` / `stage2_metrics.json` の数値が `VERIFIED` 定数と一致するかを確認する。

---

## 入力ファイル一覧

すべて `artifacts/2026-02-02_224105/` 配下。

| ファイル | 変数名 | 役割 |
|---------|--------|------|
| `results/stage1_decisions_latest.csv` | `STAGE1_CSV` | Stage1 三値ルーティング結果（127,222行） |
| `results/stage2_decisions_latest.csv` | `STAGE2_CSV` | Stage2 判定結果（57,991行 = Stage1 handoff） |
| `results/stage2_decisions_candidates_latest.csv` | `STAGE2_CANDIDATES_CSV` | Stage2 候補詳細（p_error, ゲートフラグ等） |
| `results/stage2_budget_eval.json` | `STAGE2_BUDGET_JSON` | Stage2 投入制御パラメータ・自動判定誤り集計 |
| `results/stage2_validation/eval_20260205_230157/eval_df__nALL__ts_20260205_230158.csv` | `EVAL_CSV` | Stage3 全件評価結果（11,983行→重複除去→11,952行） |

---

## 出力ファイル一覧

### tables/ （CSV）

| ファイル | 生成Phase | 対応する表/図 | 内容 |
|---------|----------|-------------|------|
| `table1_dataset.csv` | 1 | 表1 | データセット構築内訳（ソース別件数, Train/Test分割） |
| `table2_cert_availability.csv` | 1 | 表2(A) | ソース別の証明書保有率 |
| `table2_cert_status.csv` | 1 | 表2(B) | ソース別の証明書ステータス分布 |
| `table3_system_performance.csv` | 1 | 表3 (§4.2 RQ1補助) | システム全体性能（Stage1+2 vs Full cascade） |
| `table4_stage2_effect.csv` | 1 | 表4 (§4.2 RQ1一次) | Stage2投入制御効果（call rate, auto-decision error） |
| `table5_stage3_performance.csv` | 1 | 表5 (§4.3 RQ2) | Stage3混同行列・ルール発火率（n=11,952） |
| `table6_stage3_ablation.csv` | 2 | 表6 (§4.3 RQ2) | Stage3アブレーション（LLMのみ vs LLM+Rules） |
| `fig2_stage_transitions.csv` | 1 | 図1, 図2, 図6 | Stage遷移件数・割合 |
| `fig3_threshold_sweep.csv` | 2 | 図3 (§4.2) | 閾値τスイープ（call rate vs auto-decision errors） |
| `fig4_processing_time.csv` | 1 | 図4 | Stage3処理時間分布（ヒストグラム, パーセンタイル, ワーカー別） |
| `fig5_error_categories.csv` | 2 | 図5 | FN/FP Stage別内訳、MLスコア統計、ソース/TLD分布 |

### statistics/ （JSON）

| ファイル | 対応する表/図/節 | 内容 |
|---------|----------------|------|
| `system_overall_metrics.json` | 表3, 図1, §4.2, §6 | システム全体の混同行列・F1/FPR/FNR・auto-decision率 |
| `stage1_metrics.json` | 図1, 図6, §3.2 | Stage1 ルーティング詳細（TP/FP/TN/FN）・閾値 |
| `stage2_metrics.json` | 図1, 図6, §3.3 | Stage2 判定分布・ゲート内訳・パラメータ |
| `stage3_metrics.json` | 表5, §4.3 | Stage3 混同行列・処理時間統計・ワーカー別件数 |
| `rule_firing_summary.json` | 表5, §4.3 | ルール別発火件数・TP/FP寄与 |

---

## 環境情報

| 項目 | バージョン |
|------|-----------|
| Python | 3.12 |
| numpy | >= 2.0 |
| pandas | >= 2.0 |

**前提条件**:
- `artifacts/2026-02-02_224105/` ディレクトリが存在すること（評価パイプラインの成果物）
- Stage3 評価が完了済みであること（`EVAL_CSV` が 11,983行以上）

---

## 検証済み数値リファレンス（VERIFIED定数）

`generate_paper_data.py` 内の `VERIFIED` 辞書に正解値を保持。生成時に自動で assert チェックされる。

| 項目 | 値 |
|------|-----|
| テスト件数 | 127,222 |
| Stage3 TP/FP/TN/FN | 1,685 / 529 / 8,978 / 760 |
| System TP/FP/TN/FN | 62,453 / 532 / 63,079 / 1,158 |
| System F1 | 98.67% |

---

## よくある失敗

1. **`FileNotFoundError: artifacts/2026-02-02_224105/...`**
   - 原因: artifacts ディレクトリが存在しない、またはパスが異なる
   - 対処: `ARTIFACTS_DIR` 定数を実際のパスに合わせる。評価パイプラインを先に実行する

2. **`AssertionError: Stage3 TP mismatch`**
   - 原因: `EVAL_CSV` の内容が更新された（再評価、SO failure修復等）のに `VERIFIED` 定数が未更新
   - 対処: 再評価後は `VERIFIED` 辞書の値を実際の集計結果に更新する

3. **eval行数の不一致（11,983 vs 11,952）**
   - 原因: `EVAL_CSV` にはリトライ分の重複行が含まれる（正常動作）
   - 対処: スクリプト内で `drop_duplicates(subset=["domain"], keep="last")` により自動で11,952行に正規化される。手動で重複除去する必要はない
