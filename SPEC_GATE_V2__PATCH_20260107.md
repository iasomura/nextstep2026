# Gate v2: Segment-first (dangerous中心) — 実装ノート

## 目的
現状のStage2 agentは **特定のセグメント**（特に「dangerous TLD かつ Stage1=benign」）では高い改善効果がある一方、
それ以外では **新規FP/FNを作るリスクがあり**、全体では優位性が薄く見えていました。

Gate v2では、まず **ROIが実証されたセグメントにだけ** Stage2を当てることで、
- 不要なStage2呼び出しを大幅に減らす
- agentが悪化させがちな領域を避ける
- 「少ないコストで確実に効く」領域から段階的に広げる
を実現します。

## 実装内容
次のNotebookを追加しました（元Notebookは変更せずに残しています）:
- `02_stage2_thresholdcap_...__gatev2_segment_priority.ipynb`

追加された `STAGE2_SELECT_MODE=segment_priority` は以下の条件でStage2へ送ります:

- `tld_category == "dangerous"`
- `stage1_pred == benign`
- `defer_score >= TAU_DANGER_BENIGN` （defer_score = max(p_error, uncertainty)）

また、分析用に以下を保存します:
- `results/gate_trace__{suffix}.csv`
  - p_error / uncertainty / defer_score / tld_category / stage2_selected などを全test分出力

## 使い方（例）
```bash
export STAGE2_SELECT_MODE=segment_priority
export STAGE2_TAU_DANGER_BENIGN=0.85   # 0.6,0.7,0.8,0.85 などで調整
# 以降 02* notebook を実行
```

## 推奨デフォルト
- `STAGE2_TAU_DANGER_BENIGN=0.85`
  - 選択件数が小さく（おおむね数百以下）、precisionが高い
  - まずはこの設定で「agentのROIを見える化」してから対象を広げる

## 次の拡張（未実装）
- `unknown` / `legitimate` セグメントを追加する場合は、**agent側のFP抑制（policyの保守化）が先**。
- 低ML FN（p<0.2）の救済は特徴量拡張なしでは難しいため、別途 feature roadmap が必要。


---

CHANGELOG 2026-01-07

- Emergency defaults: STAGE2_SEG_ONLY_BENIGN=0, STAGE2_SEG_OPTIONAL=1, STAGE2_TAU=0.40, STAGE2_MAX_BUDGET=5000.
- Design note: segment-first gating alone can starve Stage3 and leave thousands of phish inside Stage1 DEFER if not processed.
- Stage2 v2b (proposed): treat Stage2 as a second decision maker for Stage1 DEFER, outputting p2 and (AUTO_BENIGN_2 / AUTO_PHISH_2 / DEFER2).
  - Save results/stage2_thresholds.json, results/stage2_decisions_latest.csv, results/e2e_summary.json.
  - DEFER2 must not be treated as benign; it requires quarantine / warning / delayed agent or human review.
