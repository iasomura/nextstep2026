# 論文TODO 完了ログ

対象: CSS論文「3段カスケード型フィッシング検出における投入制御とルール統合の効果分析」
運用: TODO.md から完了したタスクをここに移動する。

---

## Phase 1: データ整合性・分析・アウトライン整備（全完了 2026-02-07）

### [2026-02-07] TODO-0: 図（images）と data の数値整合を100%一致させる ✅

- `generate_paper_figures.py` に `load_figure_data()` を追加し、fig01/fig06 のハードコード数値（計30箇所）をすべて CSV/JSON 駆動に置換
- データソース: `fig2_stage_transitions.csv`, `table5_stage3_performance.csv`, `system_overall_metrics.json`, `stage1_metrics.json`, `stage2_metrics.json`
- `--verify` フラグ追加（データ整合性チェック・旧数値残存チェック・ソースファイル存在チェック）
- 旧図を `docs/paper/images/_legacy/` に隔離済み
- fig01/fig06 を正しい数値で再生成済み
- `docs/paper/images/FIGURE_MAP.md` 作成（図↔ファイル↔データソース対応表）
- `docs/paper/number_source_map.md` 作成（論文数値↔CSV/JSON出典の1:1対応表）
- `python scripts/generate_paper_data.py --verify` 全パス
- `python scripts/generate_paper_figures.py --verify` 全パス

---

### [2026-02-07] TODO-7: 「確信度（グレー）を定義して後段へ送る」設計思想を本文の主軸に固定 ✅

- §1.1 に「焦点は分類器比較ではなく確信度ベースの投入制御＋困難集合補正」を明記
- §1.2 を「確信度に基づく投入制御が未整理」にリフレーム（FN追跡の書き方を排除）
- RQ1 を call rate + auto-decision error の一次指標で定義、F1 を補助に格下げ
- RQ2 を difficult subset (n=11,952) 上の Recall 改善に限定
- §1.4 に防御線「任意の確率出力モデルに適用可能、貢献はモデル選択ではなく制御構造」を追加
- §3.1 に用語定義表（Auto-decision / Handoff / Gray zone / Difficult subset / Call rate / Auto-decision error）を追加
- §3.2 に Algorithm 1（三値ルーティング擬似コード、t_high=0.957, t_low=0.001）を追加
- §3.3 に cert gate 仕様境界を明文化（適用順序擬似コード、仕様性質表）
- §4.1.5 に RQ ごとの一次指標・補助指標を構造化
- §4.2 見出しを「call rate と auto-decision error のトレードオフ」に変更
- §4.3 見出しに「difficult subset, n=11,952」を明記、重要注記ブロック追加
- §5.1-5.2 を確信度制御・投入制御の観点で一貫記述、一般化可能性の防御線を追加
- §6 まとめを一次指標ベースに更新
- 全変更箇所に `<!-- CHANGED: TODO-7 — 理由 -->` コメントを付与

---

### [2026-02-07] TODO-8: Fig3（スイープ）の主張と図の対応を一致させる ✅

**採用**: 案A（追加実験なし）

**案A/案B 判断根拠**:
- **案A を採用**: `fig3_threshold_sweep.csv` のデータ（τ=0.0〜1.0、51点）はStage1+2の自動判定誤りのみを含み、Stage3込みの最終性能ではない。Fig3の主張を「call rate vs auto-decision errors」に限定すればCSV全データを活用でき、追加実験ゼロで整合する
- **案B を不採用**: τを1点変えてStage3まで回すだけで3GPU×数時間の計算コスト。得られるcall rate変化幅は±0.4%程度で、コストに見合わない

**実施内容**:
- `generate_paper_figures.py` に `generate_fig08()` 追加（fig3_threshold_sweep.csv からCSV駆動で生成）
- 出力: `fig08_s4.2_threshold_sweep.png`（X: Stage3 call rate %, Y左: auto-decision errors件数, Y右: error rate %）
- 運用点 τ=0.4 を星印で明示、注記で「Stage1+2の自動判定誤りのみ」を明記
- `paper_outline.md` 図表計画の図3を修正
- `FIGURE_MAP.md` 更新: 論文図3 = fig08 の対応を明記
- `number_source_map.md` 更新: 閾値スイープ数値の出典を追加
- 禁止語の不使用を確認済み

---

### [2026-02-07] TODO-9: 母数のズレ（11,952 vs 11,936） ✅

- SO (Structured Output) parse failure 16件全件を `scripts/retry_so_failures.py` で再評価・修復
- max_tokens 2048→8192, vLLM max-model-len 4096→16384（一時的）で再実行
- **Table5/Table6 ともに n=11,952 で完全一致**（TP=1685, FP=529, TN=8978, FN=760）
- 再評価により一部判定が変化: FP 535→529 (-6), FN 1157→1158 (+1), System F1 98.66%→98.67%

---

### [2026-02-07] TODO-B: 再現性の最小セット（docs/paper/data/README.md） ✅

- `docs/paper/data/README.md` を新規作成
- 再生成コマンド（`--phase 1/2`, `--verify`）の説明
- 入力ファイル一覧（5ファイル、artifacts配下のパスと役割）
- 出力ファイル一覧（tables/ 11件 + statistics/ 5件、対応する表/図/節を紐付け）
- 環境情報（Python 3.12, numpy >= 2.0, pandas >= 2.0）
- VERIFIED定数のサマリと、よくある失敗3件を付記

---

### [2026-02-07] TODO-1: 同一データセットでのベースライン比較（最小構成） ✅

**実施内容**:
- 同一 42 特徴量・同一 Train/Test split (Train=508,888 / Test=127,222) で LightGBM 2設定 + RandomForest 2設定を評価
- StandardScaler（論文パイプラインと同一の scaler.pkl）を全モデルに適用
- seed=42 固定、ハイパラは各2設定（計4 + XGBoost参照 = 5行）
- 結果: **全モデル F1=98.58〜98.66%** の狭い範囲

| Model | F1 | FPR | FNR |
|-------|-----|-----|-----|
| XGBoost (Stage1) | 98.60% | 0.51% | 2.27% |
| LightGBM-A | 98.65% | 0.47% | 2.20% |
| LightGBM-B | 98.66% | 0.47% | 2.19% |
| RandomForest-A | 98.58% | 0.68% | 2.15% |
| RandomForest-B | 98.63% | 0.43% | 2.29% |

**成果物**:
- `scripts/evaluate_baselines_minimal.py`
- `docs/paper/data/tables/appendix_baselines.csv`
- `paper_outline.md` §5.3 に防御線を追記、図表計画に付録表Aを追加

---

### [2026-02-07] TODO-2: 「なぜ証明書か」の動機付け ✅

- §1.1（背景）のline 46直後に2文を挿入
- 内容: TLS証明書メタ情報のコンテンツ配備に先行する観測可能性、監視・対応準備の起点としての運用含意
- 制限（HTTP専用等の適用外）は§5.3 T1へ委譲
- 比較煽りを回避、断定表現なし
- `<!-- CHANGED: TODO-2 rationale for certificates -->` コメント付与

---

### [2026-02-07] TODO-3: Threats to Validityの緩和策の具体化 ✅

- §5.3 を8脅威（T1〜T8）に構造化、各脅威に「緩和策（実施済み）」「残存する制限」「今後の課題」を明記
  - T1: 観測バイアス → Table2の証明書保有率で定量化
  - T2: 時間的外挿 → 未実施。Future workに明記
  - T3: データセット地理バイアス → 未実施。限界として明記
  - T4: ラベルノイズ → Fig5のFN分析（JPCERT=387, PhishTank=232, CT=141）で偏り把握
  - T5: 閾値感度 → Fig3（τ=0.3〜0.5で誤り396〜427、±7.5%）で安定域を確認
  - T6: ルール閾値の調整 → Table6（flip 811件、精度49.57%）で影響範囲を定量化
  - T7: 分類器選択 → Appendix Table A（5モデル、F1=98.58〜98.66%）で防御
  - T8: 処理遅延 → Fig4（p50=8.31s, p90=15.27s, p99=28.59s）で定量化
- スコープ宣言を§5.3末尾に配置
- 表7（脅威サマリ表）を追加

---

### [2026-02-07] TODO-4: Stage3アブレーション実験（LLMのみ vs LLM+ルール） ✅

**成果物**: `docs/paper/data/tables/table6_stage3_ablation.csv`
- LLM単体: P=87.69%, R=55.34%, F1=67.85%
- LLM+Rules: P=76.11%, R=68.92%, F1=72.33%
- 判定変更: 811件（6.79%）、flip精度49.57%

---

### [2026-02-07] TODO-5: 誤り分析（残存FN/増加FPのカテゴリ分類） ✅

**成果物**: `docs/paper/data/tables/fig5_error_categories.csv`
- FN Stage別: Stage1=3, Stage2=395, Stage3=760, 合計=1,158
- FP Stage別: Stage1=2, Stage2=1, Stage3=529, 合計=532

---

### [2026-02-07] TODO-6: 論文データ生成スクリプト ✅

**成果物**: `scripts/generate_paper_data.py`
- 表1〜6のCSV、図2〜5の元データCSV、統計JSON 5件を生成（計16ファイル）
- 出力先: `docs/paper/data/{tables,statistics}/`
- 検証済み数値リファレンスとの自動整合チェック付き
