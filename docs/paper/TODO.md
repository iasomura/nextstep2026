# 論文TODO（未着手作業リスト / 優先度つき）

作成日: 2026-02-07
対象: CSS論文「3段カスケード型フィッシング検出における投入制御とルール統合の効果分析」

---

## 優先度0（即死回避：整合性・再現性の破綻を先に潰す）

### TODO-0: 図（images）と data の数値整合を100%一致させる（最優先）

**状況**: `docs/paper/images/` に旧実験の図が混入しており、本文・`docs/paper/data/`（検証済み）と数値不一致がある。これは査読で即死。

**不一致の実態**（確認済み）:
- `fig01`（アーキ図）: 入力127,754→正127,222、auto_benign 6,166→正8,464、handoff 60,974→正57,991、Stage3投入 15,670→正11,952 等14箇所
- `fig06`（処理フロー）: 同系統の旧数値16箇所
- fig02〜fig05, fig07 は問題なし

**必要な作業**:
- [ ] 論文に使う図を確定（最低限: Fig1=アーキ図, Fig2=遷移, Fig3=スイープ, Fig4=遅延, Fig5=誤り分解）
- [ ] `docs/paper/data/`（例: `tables/fig2_stage_transitions.csv` など）から **再生成**して `docs/paper/images/` を上書き
- [ ] 旧図（入力127,754 / Stage3 15,670 等の系統）を削除または `docs/paper/images/_legacy/` に隔離し、本文参照を完全に断つ
- [ ] 図キャプションに母数（n=127,222 / n=11,952 等）を明記し、本文中の引用値と一致させる
- [ ] 整合チェックの機械化：`generate_paper_data.py --verify` は tables/statistics 検証済み。図（`generate_paper_figures.py` のハードコード値）との照合スクリプトも追加する

**受入条件（Done定義）**:
- [ ] `paper_outline.md` の検証済み数値と、本文・表・図の全てが一致（不一致ゼロ）
- [ ] `python scripts/generate_paper_data.py --verify` が全パスすること（tables/statistics）
- [ ] `generate_paper_figures.py` 内のハードコード値（Fig1/Fig6）が `docs/paper/data/tables/fig2_stage_transitions.csv` と一致することを機械チェックで保証（PNGは目視不可のため、ソースコード側で検証）
- [ ] `paper_outline.md` から引用している数値の出典（table/figパス）を1対1で紐付け

**優先度**: 最高

---

## 優先度1（MTG合意の反映：論文の芯を固定する）

### TODO-7: 「確信度（グレー）を定義して後段へ送る」設計思想を本文の主軸に固定

**目的**: 2025/12のMTG合意（`docs/mtg/202512/`：FN追跡ではなく不確実性=グレーの定義と投入制御）を、RQ/説明/議論に一貫して反映する。

**必要な作業**:
- [ ] §1（導入）に「本研究の焦点は分類器の優劣ではなく、確信度に基づく投入制御と困難集合での補正」である旨を明記
- [ ] RQ1/RQ2の書き方を「投入率（budget）と自動判定の信頼性」「困難集合でのルール統合」に寄せ、FN削減"だけ"の書き方を避ける
- [ ] §4（評価）で Stage3 の評価対象が **difficult subset (n=11,952)** であることを表題・キャプションで明確化
- [ ] **用語・集合・指標の定義を明文化**（査読者が「FN追跡？budget最適化？」で迷わないため）:
  - Gray / Handoff / Auto decision の定義（式 or 擬似コード1個：Stage1は [t_low, t_high] の外のみ自動判定、内はhandoff）
  - **cert gate の仕様境界**（査読者が「確率モデルと規則が混ざってない？」と突く箇所）:
    - 位置付け: **hard gate**（cert gateはsafe_benign判定として先にdrop。p_errorによる選択はその後）
    - 適用順: cert gate（safe_benign_combined: 45,307件drop）→ p_error閾値（tau=0.4で残りから選択）→ high_ml_phish override（1,718件を強制追加）
    - 衝突時: cert gateが優先（gateでdropされた行はp_errorに関わらずStage3に送らない）
    - これにより "auto-decision error" の定義が一意に決まることを確認
  - 評価の主目的指標の固定：RQ1 = "Stage3 call rate" + "auto-decision error" が一次指標、最終F1は補助（Table3）。RQ2 = difficult subset での Recall改善（とFP増）を明示
- [ ] **貢献の定型文**（導入または議論に挿入）: 「本研究の貢献は分類器選択ではなく、**確信度に基づくhandoff制御**と、**困難集合での説明可能な補正（ルール統合）**である。提案は**任意の確率出力モデルに適用可能**。」→ 「XGBoostを変えたら？」への防御、Stage3 F1=72%が低く見える問題への文脈付与

**優先度**: 高

---

## 優先度2（査読耐性の最低ライン：殴られないための防御線）

### TODO-8: Fig3（スイープ）の主張と図の対応を一致させる

**状況**: `tables/fig3_threshold_sweep.csv` は「投入率 vs auto_errors（Stage1+2の自動誤り）」であり、最終性能（Stage3込み）の曲線ではない。

**必要な作業（どちらかを選ぶ）**:
- [ ] **案A（追加実験なし・推奨）**: Fig3の主張を「投入率と自動判定誤り（auto_errors）の関係」に限定し、最終性能は `table3_system_performance.csv` の点比較で述べる。**「最終性能曲線」とは言わない**こと。
- [ ] **案B（最小追加実験）**: τを**2点**選び、Stage3まで回して最終F1/FPR/FNRを算出。Table3と対応する形で「最終FNR/FPR」の2点比較を作る。（3点は贅沢）

**図タイトルの禁止語**（案A採用時、誤爆防止）:
- 禁止: "overall performance trade-off curve", "end-to-end trade-off curve"
- 推奨: "Stage3 call rate vs auto-decision errors under Stage1+2"

**優先度**: 高（案Aなら文章修正のみで軽い）

---

### TODO-9: 母数のズレ（11,952 vs 11,936）を明示し、引用の混在を禁止する

**状況**:
- Stage3全体の性能（困難集合）は `docs/paper/data/tables/table5_stage3_performance.csv`（n=11,952）
- アブレーションは `docs/paper/data/tables/table6_stage3_ablation.csv`（n=11,936。`llm_raw_output` 抽出不可16件を除外）

**必要な作業**:
- [ ] Table5とTable6のキャプションに、母数と除外理由を明記（脚注でよい）
- [ ] **引用元の固定**: 本文中のStage3性能は **原則 n=11,952（Table5）** で統一。アブレーション節のみ n=11,936 を明記（脚注）
- [ ] 可能なら Table5側も 11,936 に揃えた再集計版を作り、本文の引用は揃えた方に統一（任意）

**優先度**: 高（文章修正だけでリスクを大きく下げられる）

---

### TODO-B: 再現性の最小セット（docs/paper/data/README.md）

**状況**: `generate_paper_data.py` は存在するが、再生成手順のドキュメントがない。

**必要な作業**:
- [ ] `docs/paper/data/README.md` を作成（1ページで十分）:
  - 再生成コマンド（`python scripts/generate_paper_data.py`）
  - 入力ファイル一覧（どのCSV/JSON/DBスナップショットを読むか）
  - 出力ファイル一覧（tables/statistics の対応表）
  - 環境情報（Python版、主要ライブラリ）最小記載

**優先度**: 中（作業量小・効果大）

---

## レビュー指摘からの保留事項（優先度を再定義）

### TODO-1: 同一データセットでのベースライン比較（最小構成）（指摘4）

**内容**: 同一Test 127,222件で単体モデルを評価し、**論点を「分類器優劣」にずらされないための防御線**を作る（勝つためではない）。

**必要な作業（最小構成・上限固定）**:
- [ ] **実装追加はしない**（既存特徴量42個・既存split をそのまま使い、学習器差し替えの学習・推論のみ）
- [ ] モデルは **2本固定**（例: LightGBM + RF）。3本目は不可
- [ ] ハイパーパラメータ探索は最小（各モデル2〜3個、試行回数に上限を設定。沼らない）
- [ ] 指標は **F1/FPR/FNR（＋混同行列）** に絞る（紙面節約）
- [ ] 出力は **Appendix表** を原則とし、本文は1行で触れる（本文に表を増やさない）

**やらない場合の代償**: Threatsに "single-stage strong baseline may achieve comparable accuracy; our focus is budgeted handoff and explainable correction" を明記して論点ずらしを防ぐ（ただし殴られる確率は上がる）。なお本文で「技術的に意味がない」とは言わない。言うなら「本研究の貢献は分類器選択ではない」に留める。

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

### TODO-3: Threats to Validityの緩和策の具体化（MTG合意を反映）（指摘9）

**内容**: §5.3に列挙した脅威（観測バイアス、時間差、ラベルノイズ、ルール閾値調整）に対して、具体的な緩和策を記述する。

**判断ポイント**: 緩和策として記述できるのは実際に実施した分析のみ。以下の実験実施状況に依存する。
- 閾値感度分析 → Fig3データあり。「ルール閾値の調整」の緩和策になる
- 時系列評価 → 未実施
- 外部データ検証 → 未実施

未実施の場合は「今後の課題」として§5または§6で言及する。

- [ ] **スコープ宣言**（文章で封じる。追加実験ゼロ）: 三値学習（0/1/gray）、uncertainty calibration、別モデル最適化は自然な拡張だが、**本稿のスコープは分類器優劣ではなく投入制御とルール統合の効果**である、とThreats or Future workに明記。これにより「なぜ三値にしない？」「なぜcalibrationしない？」を"次の課題"として処理し、査読での追加実験要求を防ぐ

**優先度**: 高（追加実験がなくても、既存データで書ける緩和策は書く）

---

## 追加実験・データ準備

### ~~TODO-4: Stage3アブレーション実験（LLMのみ vs LLM+ルール）~~ ✅完了

**完了日**: 2026-02-07
**成果物**: `docs/paper/data/tables/table6_stage3_ablation.csv`
- `graph_state_slim_json` → `decision_trace[0].policy_trace` の `llm_raw_output` から抽出（11,936/11,952件）
- LLM単体: P=87.69%, R=55.47%, F1=67.96%
- LLM+Rules: P=76.14%, R=68.96%, F1=72.38%
- 判定変更: 806件（6.75%）、flip精度49.5%

---

### ~~TODO-5: 誤り分析（残存FN/増加FPのカテゴリ分類）~~ ✅完了

**完了日**: 2026-02-07
**成果物**: `docs/paper/data/tables/fig5_error_categories.csv`
- FN Stage別: Stage1=3, Stage2=395, Stage3=759, 合計=1,157
- FP Stage別: Stage1=2, Stage2=1, Stage3=532, 合計=535
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

1. **TODO-0** — 図の数値一致＋legacy隔離＋整合チェック
2. **TODO-7** — MTG芯の言語化：グレー定義・用語固定・評価目的の固定
3. **TODO-8** — Fig3主張の確定（案A推奨）
4. **TODO-9** — 母数ズレの脚注・引用ルール固定（原則n=11,952）
5. **TODO-3** — Threats：実施済み範囲で具体化
6. **TODO-1** — Appendix最小ベースライン（2モデル、原則実施）
7. **TODO-2** — なぜ証明書か（1〜2文）
8. **TODO-B** — docs/paper/data/README.md（再現性の入口）

---

## 判断待ち事項（更新）

| 項目 | 判断内容 | 依存先 |
|------|---------|--------|
| TODO-0 | 旧図の扱い（削除 or legacy隔離）と再生成の方法 | `generate_paper_data.py` / `generate_paper_figures.py` |
| TODO-7 | MTG合意（グレー定義・投入制御）をどこまで本文主張に寄せるか | `docs/mtg/202512/` / `paper_outline.md` |
| TODO-8 | Fig3を案A（追加なし）/案B（最小追加τ2点）どちらで成立させるか | 追加計算コストと主張の強さ |
| TODO-9 | 11,952/11,936 を統一するか（統一しない場合は脚注で明示） | table5/table6 |
| TODO-1 | 原則実施（Appendix 2モデル）。やらない場合はThreatsで代償 | 実装負荷と紙面 |
| TODO-2 | どのセクションに書くか | 論文全体の流れを見て判断 |
| TODO-3 | 緩和策として何を書けるか。三値/uncertainty/calibration/別モデル最適化のスコープ外宣言を **Threats に書くか Future work に書くか** | Fig3/処理時間/誤り分解を活用 |
