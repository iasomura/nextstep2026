# ToDo.md — 提出パッケージ作成用（OPENのみ）

作成日: 2026-02-07
対象: CSS論文「3段カスケード型フィッシング検出における投入制御とルール統合の効果分析」
前提: 既存のデータ生成・整合性検証（`--verify`）および主要分析は完了。完了ログは `20260207-DONE.md` に集約。

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
- このファイルは **OPENのみ**。完了したら日付付き DONE ファイル（例: `yyyymmdd-DONE.md`）に移す（完了日・成果物・verify結果を残す）
- 迷ったら **「査読で即死するか？」**を基準に優先度を上げる

---

## 完了済み（P0-1〜P0-5）→ `20260207-DONE.md` Phase 2 に移動済み

---

## 優先度 P0（提出に必須）

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
