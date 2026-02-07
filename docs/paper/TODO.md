# 論文TODO（未着手作業リスト / 優先度つき）

作成日: 2026-02-07
対象: CSS論文「3段カスケード型フィッシング検出における投入制御とルール統合の効果分析」

---

## 優先度0（即死回避：整合性・再現性の破綻を先に潰す）

### ~~TODO-0: 図（images）と data の数値整合を100%一致させる（最優先）~~ ✅完了

**完了日**: 2026-02-07
- `generate_paper_figures.py` に `load_figure_data()` を追加し、fig01/fig06 のハードコード数値（計30箇所）をすべて CSV/JSON 駆動に置換
- データソース: `fig2_stage_transitions.csv`, `table5_stage3_performance.csv`, `system_overall_metrics.json`, `stage1_metrics.json`, `stage2_metrics.json`
- `--verify` フラグ追加（データ整合性チェック・旧数値残存チェック・ソースファイル存在チェック）
- 旧図を `docs/paper/images/_legacy/` に隔離済み
- fig01/fig06 を正しい数値で再生成済み
- `docs/paper/images/FIGURE_MAP.md` 作成（図↔ファイル↔データソース対応表）
- `docs/paper/number_source_map.md` 作成（論文数値↔CSV/JSON出典の1:1対応表）
- `python scripts/generate_paper_data.py --verify` 全パス
- `python scripts/generate_paper_figures.py --verify` 全パス

**優先度**: 最高

---

## 優先度1（MTG合意の反映：論文の芯を固定する）

### ~~TODO-7: 「確信度（グレー）を定義して後段へ送る」設計思想を本文の主軸に固定~~ ✅完了

**完了日**: 2026-02-07
- §1.1 に「焦点は分類器比較ではなく確信度ベースの投入制御＋困難集合補正」を明記
- §1.2 を「確信度に基づく投入制御が未整理」にリフレーム（FN追跡の書き方を排除）
- RQ1 を call rate + auto-decision error の一次指標で定義、F1 を補助に格下げ
- RQ2 を difficult subset (n=11,952) 上の Recall 改善に限定
- §1.4 に防御線「任意の確率出力モデルに適用可能、貢献はモデル選択ではなく制御構造」を追加
- §3.1 に用語定義表（Auto-decision / Handoff / Gray zone / Difficult subset / Call rate / Auto-decision error）を追加
- §3.2 に Algorithm 1（三値ルーティング擬似コード、t_high=0.957, t_low=0.001）を追加
- §3.3 に cert gate 仕様境界を明文化（適用順序擬似コード、仕様性質表: cert gate優先 / override優先 / auto-decision error一意性）
- §4.1.5 に RQ ごとの一次指標・補助指標を構造化
- §4.2 見出しを「call rate と auto-decision error のトレードオフ」に変更
- §4.3 見出しに「difficult subset, n=11,952」を明記、重要注記ブロック追加
- §5.1-5.2 を確信度制御・投入制御の観点で一貫記述、一般化可能性の防御線を追加
- §6 まとめを一次指標ベースに更新
- 全変更箇所に `<!-- CHANGED: TODO-7 — 理由 -->` コメントを付与

**優先度**: 高

---

## 優先度2（査読耐性の最低ライン：殴られないための防御線）

### ~~TODO-8: Fig3（スイープ）の主張と図の対応を一致させる~~ ✅完了

**完了日**: 2026-02-07
**採用**: 案A（追加実験なし）

**案A/案B 判断根拠**:
- **案A を採用**: `fig3_threshold_sweep.csv` のデータ（τ=0.0〜1.0、51点）はStage1+2の自動判定誤りのみを含み、Stage3込みの最終性能ではない。Fig3の主張を「call rate vs auto-decision errors」に限定すればCSV全データを活用でき、追加実験ゼロで整合する
- **案B を不採用**: τを1点変えてStage3まで回すだけで3GPU×数時間の計算コスト。得られるcall rate変化幅は±0.4%程度（τ=0.3→0.4→0.5でcall rate 9.4→8.98%）で、コストに見合わない

**実施内容**:
- `generate_paper_figures.py` に `generate_fig08()` 追加（fig3_threshold_sweep.csv からCSV駆動で生成）
- 出力: `fig08_s4.2_threshold_sweep.png`（X: Stage3 call rate %, Y左: auto-decision errors件数, Y右: error rate %）
- 運用点 τ=0.4 を星印で明示、注記で「Stage1+2の自動判定誤りのみ」を明記
- `paper_outline.md` 図表計画の図3を修正: 「Stage3投入率と全体性能のトレードオフ」→「Stage3 call rate vs 自動判定誤り（Stage1+2のauto-decision errors、τスイープ）」
- `paper_outline.md` §4.2 に閾値感度分析（図3）の記述を追加
- `FIGURE_MAP.md` 更新: 論文図3 = fig08 の対応を明記
- `number_source_map.md` 更新: 閾値スイープ数値の出典を追加
- 禁止語の不使用を確認済み: "overall performance trade-off curve", "end-to-end trade-off curve" はゼロ

**優先度**: 高（案Aなら文章修正のみで軽い）

---

### ~~TODO-9: 母数のズレ（11,952 vs 11,936）~~ ✅完了

**完了日**: 2026-02-07
- SO (Structured Output) parse failure 16件全件を `scripts/retry_so_failures.py` で再評価・修復
- max_tokens 2048→8192, vLLM max-model-len 4096→16384（一時的）で再実行
- **Table5/Table6 ともに n=11,952 で完全一致**（TP=1685, FP=529, TN=8978, FN=760）
- 再評価により一部判定が変化: FP 535→529 (-6), FN 1157→1158 (+1), System F1 98.66%→98.67%

---

### ~~TODO-B: 再現性の最小セット（docs/paper/data/README.md）~~ ✅完了

**完了日**: 2026-02-07
- `docs/paper/data/README.md` を新規作成
- 再生成コマンド（`--phase 1/2`, `--verify`）の説明
- 入力ファイル一覧（5ファイル、artifacts配下のパスと役割）
- 出力ファイル一覧（tables/ 11件 + statistics/ 5件、対応する表/図/節を紐付け）
- 環境情報（Python 3.12, numpy >= 2.0, pandas >= 2.0）
- VERIFIED定数のサマリと、よくある失敗3件を付記

**優先度**: 中（作業量小・効果大）

---

## レビュー指摘からの保留事項（優先度を再定義）

### ~~TODO-1: 同一データセットでのベースライン比較（最小構成）（指摘4）~~ ✅完了

**完了日**: 2026-02-07

**実施内容**:
- 同一 42 特徴量・同一 Train/Test split (Train=508,888 / Test=127,222) で LightGBM 2設定 + RandomForest 2設定を評価
- StandardScaler（論文パイプラインと同一の scaler.pkl）を全モデルに適用
- seed=42 固定、ハイパラは各2設定（計4 + XGBoost参照 = 5行）
- 結果: **全モデル F1=98.58〜98.66%** の狭い範囲。分類器選択がシステム結論に影響しないことを確認

| Model | F1 | FPR | FNR |
|-------|-----|-----|-----|
| XGBoost (Stage1) | 98.60% | 0.51% | 2.27% |
| LightGBM-A | 98.65% | 0.47% | 2.20% |
| LightGBM-B | 98.66% | 0.47% | 2.19% |
| RandomForest-A | 98.58% | 0.68% | 2.15% |
| RandomForest-B | 98.63% | 0.43% | 2.29% |

**成果物**:
- `scripts/evaluate_baselines_minimal.py` — 再現コマンド: `python scripts/evaluate_baselines_minimal.py`
- `docs/paper/data/tables/appendix_baselines.csv` — Appendix用結果CSV
- `paper_outline.md` §5.3 に防御線を追記、図表計画に付録表Aを追加

**優先度**: 中（原則実施。Appendix表1枚＋本文1行で紙面コストほぼゼロ、査読耐性が上がる）

---

### TODO-2: 「なぜ証明書か」の動機付け（最小でよい）（指摘8）

**内容**: URLやコンテンツベースの既存手法と差別化するため、証明書ベース検出の利点（早期検出、ページ取得不要、CT監視との接続可能性）を論文内で明確にする。

**判断ポイント**:
- §1.1（背景）に1〜2文で書くか
- §2（関連研究）の末尾で差別化として書くか
- §5（議論）で優位性として議論するか
- 複数箇所に分散させるか

**優先度**: 中（1〜2文で済むが、無いと読者が迷う）

---

### ~~TODO-3: Threats to Validityの緩和策の具体化（MTG合意を反映）（指摘9）~~ ✅完了

**完了日**: 2026-02-07
- §5.3 を8脅威（T1〜T8）に構造化、各脅威に「緩和策（実施済み）」「残存する制限」「今後の課題」を明記
  - T1: 観測バイアス → Table2の証明書保有率で定量化
  - T2: 時間的外挿 → 未実施。Future workに明記
  - T3: データセット地理バイアス → 未実施。限界として明記
  - T4: ラベルノイズ → Fig5のFN分析（JPCERT=387, PhishTank=232, CT=141）で偏り把握
  - T5: 閾値感度 → Fig3（τ=0.3〜0.5で誤り396〜427、±7.5%）で安定域を確認
  - T6: ルール閾値の調整 → Table6（flip 811件、精度49.57%）で影響範囲を定量化
  - T7: 分類器選択 → Appendix Table A（5モデル、F1=98.58〜98.66%）で防御
  - T8: 処理遅延 → Fig4（p50=8.31s, p90=15.27s, p99=28.59s）で定量化
- スコープ宣言を§5.3末尾に配置:「三値学習・uncertainty calibration・別モデル最適化は自然な拡張だが、本稿のスコープは投入制御とルール統合の効果分析」
- 表7（脅威サマリ表）を追加: 脅威分類/緩和策/残存制限の対応表

**優先度**: 高（追加実験がなくても、既存データで書ける緩和策は書く）

---

## 追加実験・データ準備

### ~~TODO-4: Stage3アブレーション実験（LLMのみ vs LLM+ルール）~~ ✅完了

**完了日**: 2026-02-07（SO再評価後に全件修復・数値確定）
**成果物**: `docs/paper/data/tables/table6_stage3_ablation.csv`
- `graph_state_slim_json` → `decision_trace[0].policy_trace` の `llm_raw_output` から抽出（11,952/11,952件）
- LLM単体: P=87.69%, R=55.34%, F1=67.85%
- LLM+Rules: P=76.11%, R=68.92%, F1=72.33%
- 判定変更: 811件（6.79%）、flip精度49.57%

---

### ~~TODO-5: 誤り分析（残存FN/増加FPのカテゴリ分類）~~ ✅完了

**完了日**: 2026-02-07（SO再評価後に数値更新）
**成果物**: `docs/paper/data/tables/fig5_error_categories.csv`
- FN Stage別: Stage1=3, Stage2=395, Stage3=760, 合計=1,158
- FP Stage別: Stage1=2, Stage2=1, Stage3=529, 合計=532
- Stage3 FN/FPのMLスコア統計、ソース別・TLD別分布を含む

---

### ~~TODO-6: 論文データ生成スクリプト~~ ✅完了

**完了日**: 2026-02-07
**成果物**: `scripts/generate_paper_data.py`
- 表1〜6のCSV、図2〜5の元データCSV、統計JSON 5件を生成（計16ファイル）
- 出力先: `docs/paper/data/{tables,statistics}/`
- 検証済み数値リファレンスとの自動整合チェック付き

---

## 推奨実行順序

1. ~~**TODO-0** — 図の数値一致＋legacy隔離＋整合チェック~~ ✅完了
2. ~~**TODO-7** — MTG芯の言語化：グレー定義・用語固定・評価目的の固定~~ ✅完了
3. ~~**TODO-8** — Fig3主張の確定（案A採用）~~ ✅完了
4. ~~**TODO-9** — 母数ズレの脚注・引用ルール固定（原則n=11,952）~~ ✅完了
5. ~~**TODO-3** — Threats：実施済み範囲で具体化~~ ✅完了
6. ~~**TODO-1** — Appendix最小ベースライン（2モデル、原則実施）~~ ✅完了
7. **TODO-2** — なぜ証明書か（1〜2文）
8. ~~**TODO-B** — docs/paper/data/README.md（再現性の入口）~~ ✅完了

---

## 判断待ち事項（更新）

| 項目 | 判断内容 | 依存先 |
|------|---------|--------|
| ~~TODO-0~~ | ✅完了。CSV/JSON駆動に移行、旧図legacy隔離、verify追加、対応表作成 | — |
| ~~TODO-7~~ | ✅完了。用語定義・擬似コード・cert gate仕様境界・指標体系を paper_outline.md に反映済み | — |
| ~~TODO-8~~ | ✅完了。案A採用。fig08生成、paper_outline修正、FIGURE_MAP更新済み | — |
| ~~TODO-9~~ | ✅完了。Table5/Table6 ともに n=11,952 で完全一致 | — |
| ~~TODO-1~~ | ✅完了。5モデル比較（F1=98.58〜98.66%）。appendix_baselines.csv + §5.3防御線 | — |
| TODO-2 | どのセクションに書くか | 論文全体の流れを見て判断 |
| ~~TODO-3~~ | ✅完了。8脅威（T1〜T8）構造化、既存データで緩和策を定量記述、スコープ宣言を§5.3末尾に配置、表7追加 | — |
