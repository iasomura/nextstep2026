# ToDo.md — 提出パッケージ作成用（OPENのみ）

作成日: 2026-02-07
対象: CSS論文「3段カスケード型フィッシング検出における投入制御とルール統合の効果分析」
前提: 既存のデータ生成・整合性検証（`--verify`）および主要分析は完了。完了ログは `DONE.md` に集約。

---

## このToDoの目的

**「論文が提出できる状態」**をゴールとして、未完タスクだけを管理する。

### Definition of Done（提出状態）
- 原稿（LaTeX/Word）が **ページ制約内** でビルドできる
- 図表が **最終採用品** で統一され、番号・キャプション・本文参照が一致
- 主要数値が `docs/paper/data/` と一致（旧数値の混入なし）
- `scripts/generate_paper_data.py --verify` と `scripts/generate_paper_figures.py --verify` がパス
- `docs/paper/number_source_map.md` が「本文に出す主要数値」をカバー

---

## 運用ルール
- このファイルは **OPENのみ**。完了したら `DONE.md` に移す（完了日・成果物・verify結果を残す）
- 迷ったら **「査読で即死するか？」**を基準に優先度を上げる

---

## 優先度 P0（提出に必須）

### P0-1: 文章・図表の言語/表記を統一する（日本語/英語どちらか）

**状態**: OPEN
**狙い**: 図の言語混在や用語ゆれによる読みづらさ・誤解を防ぐ。

- 決める（デフォルト案）: **日本語本文 + 図も日本語**
  - 例: call rate → 「投入率（Stage3投入率）」、auto-decision error → 「自動判定誤り」
- 用語の正規形（例）:
  - Stage1/Stage2/Stage3（表記固定）
  - Gray zone / Handoff / Difficult subset（訳語を固定し、初出で英併記）
- 数値表記ルール（例）:
  - 桁区切り: 127,222（カンマ）
  - ％: 9.4%（半角、%直前スペースなし）
  - 小数桁: 重要数値は小数点以下2桁まで

**成果物**
- `docs/paper/STYLE_GUIDE.md`（A4 1枚相当で良い：表記・用語・単位・図ラベル方針）

**受入条件**
- 採用図（最終版）の軸ラベル・凡例・注記が言語統一
- `paper_outline.md` の見出し・指標名の表記がSTYLE_GUIDEと一致

---

### P0-2: 最終採用する図セットを「論文図番号」と1:1対応にする

**状態**: OPEN
**狙い**: `images/` 内の候補図が複数ある状態から、提出に使う図だけを確定させる。

**タスク**
1) `docs/paper/paper_outline.md` の図表計画を基準に、最終採用する図（Fig1..）を確定
2) `docs/paper/images/` で「最終採用品」だけが一目で分かる命名に統一
   - 例: `fig01_architecture.png`, `fig02_transitions.png` …
3) `docs/paper/images/FIGURE_MAP.md` を「最終採用品のみ」に整理
4) 落選図は `docs/paper/images/_unused/` に移動（消さない）

**成果物**
- 整理後の `docs/paper/images/`（最終採用図のみがトップに残る）
- 更新済み `FIGURE_MAP.md`

**受入条件**
- `FIGURE_MAP.md` に Fig番号→ファイル→データ出典 が揃っている
- 論文本文で参照する図が `FIGURE_MAP.md` と一致

---

### P0-3: Fig4（処理遅延）を、outlineの意図どおりの図として確定する

**状態**: OPEN
**狙い**: Stage3運用のボトルネック（p50/p90/p99等）を査読者に一目で伝える。

**前提データ**
- `docs/paper/data/tables/fig4_processing_time.csv`

**タスク**
- `fig4_processing_time.csv` から、以下のどちらかを生成（紙面に合う方を採用）
  - (A) CDF（推奨）: 横軸=秒、縦軸=累積割合。p50/p90/p99の縦線注記
  - (B) 分位点バー: p50/p90/p99 を棒で表示（注記で分位点定義）

**成果物**
- `docs/paper/images/fig04_latency.png`（+ 可能なら `fig04_latency.pdf`）
- 図キャプション草案（日本語/英語はSTYLE_GUIDEに合わせる）

**受入条件**
- 図中に n（評価件数）と単位（秒）が明示されている
- `paper_outline.md` の該当箇所が「図の見せ方」と矛盾しない

---

### P0-4: Fig5（誤り分析）を、outlineの意図どおりの図として確定する

**状態**: OPEN
**狙い**: 「どこでどんな誤りが残る/増えるか」をカテゴリで示し、議論とThreatsの根拠にする。

**前提データ**
- `docs/paper/data/tables/fig5_error_categories.csv`

**タスク**
- 目的に合わせて図を1枚に圧縮（紙面都合）
  - 例: Stage3の FNカテゴリ分布 と FPカテゴリ分布 を左右（または上下）で並べる
  - もしくは「上位Kカテゴリのみ + Others」で可読性優先

**成果物**
- `docs/paper/images/fig05_error_breakdown.png`（+ 可能ならPDF）
- 図キャプション草案

**受入条件**
- 図のカテゴリ定義が本文（or Appendix）に明記され、循環参照になっていない
- `docs/paper/paper_outline.md` の誤り分析節と整合

---

### P0-5: Stage1/ベースラインのハイパラ表記を最終整合させる

**状態**: OPEN
**狙い**: Appendix/本文のパラメータ不一致（査読で刺される）をゼロにする。

**タスク**
1) Stage1の学習設定（XGBoost等）を「正」ソースに合わせて確定
2) `docs/paper/data/tables/appendix_baselines.csv` と本文/付録表の記述を一致させる
3) 必要なら `paper_outline.md` の該当箇所を修正（"n_estimators=100 vs 500" 等の矛盾を排除）

**成果物**
- 修正済み `paper_outline.md`（差分コメント付き推奨）
- パラメータの根拠（どの設定ファイル/スクリプト由来か）を `number_source_map.md` か注記に残す

**受入条件**
- Appendix表と本文の説明が同一
- ベースライン評価スクリプトの実行条件と矛盾しない

---

### P0-6: 原稿（LaTeX/Word）を作り、図表を流し込んでビルドできる状態にする

**状態**: OPEN
**狙い**: 「outlineがある」状態から「提出物がある」状態に移行する。

**タスク（LaTeX想定）**
1) `paper/`（または `docs/paper/manuscript/`）配下に原稿プロジェクト作成
   - `main.tex`, `references.bib`, `figures/`, `tables/`
2) `paper_outline.md` を章立てに落とし、図表の入れ込みまで行う
3) 図表番号・本文参照（Fig/Table）を整合させる

**成果物**
- ビルド手順 `paper/README.md`（1ページ）
- ビルドが通る原稿（PDF生成）

**受入条件**
- 1コマンドでビルドできる（例: `latexmk` など）
- ページ制約を超えない（超える場合は削減案がToDoに残る）

---

### P0-7: 提出前の整合性ゲート（自動/手動）を通す

**状態**: OPEN
**狙い**: 数値・図・本文の食い違いを提出前に潰す。

**タスク**
- 自動:
  - `python scripts/generate_paper_data.py --verify`
  - `python scripts/generate_paper_figures.py --verify`
  - 旧数値（例: 127,754 / 15,670 / 60,614…）が残っていないことをgrepで確認
- 手動:
  - 原稿中の主要数値（n、p50/p90/p99、F1等）が `number_source_map.md` に対応していることを確認

**成果物**
- `docs/paper/verification_log.md`（実行日・コマンド・結果要約）

**受入条件**
- verifyが全パス
- 主要数値の出典が追える（査読質問に即答できる）

---

## 優先度 P1（強く推奨：査読耐性・読みやすさ）

### P1-1: 要旨（Abstract）を、一次指標中心で書き切る

**状態**: OPEN
- 一次指標（call rate / auto-decision error / difficult subset recall）を必ず入れる
- 分類器比較に見える表現を避ける

---

### P1-2: 関連研究の「差分」を1段だけ強くする

**状態**: OPEN
- 既存研究との差分を「投入制御」「困難集合補正（ルール統合）」に寄せる

---

### P1-3: Ethics / Data availability / Reproducibility を最小で明文化

**状態**: OPEN
- 既にある `docs/paper/data/README.md` を参照導線として活用

---

## 優先度 P2（余裕があれば）

### P2-1: 付録に「落選図」を回す（必要なら）

**状態**: OPEN
- 0.5閾値の確率分布など、誤解を招きやすいものは本文に載せない
- 付録に載せるなら「参考」であることを明記する
