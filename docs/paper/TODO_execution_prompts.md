# ToDo-Execution-Prompts.md — ToDo.md 実行プロンプト（AI非依存）

作成日: 2026-02-07

この文書は `ToDo.md` の各タスクを **ChatGPT / Claude / Gemini / ローカルLLM / エージェント**等で同じ品質で実行できるようにするための「コピペ用プロンプト集」です。
"AIがファイルを直接編集できる環境" と "編集できない環境" の両方に対応します。

---

## 0) 使い方（共通プロトコル）

### 0.1 入力（最初にAIへ渡すもの）
- リポジトリルート（例: `nextstep/`）が見えること
- **必読**:
  - `ToDo.md`
  - `docs/paper/paper_outline.md`
  - `docs/paper/images/FIGURE_MAP.md`
  - `docs/paper/number_source_map.md`
  - `docs/paper/data/README.md`

### 0.2 AIへの基本ルール（重要）
- **捏造禁止**: データ・数値・ファイルの存在を勝手に仮定しない
- **スコープ固定**: ToDo.md に書いてない「追加実験」「追加データ収集」「モデル再学習」を勝手に提案しない（必要なら *Optional* として分離）
- **出力は差分中心**:
  - AIが編集できる: 変更ファイル一覧 + コマンド + 実行ログ要約
  - AIが編集できない: 変更案を *パッチ形式*（unified diff）か、*新ファイル全文*で提示
- **受入条件が満たされるまで"完了"と宣言しない**（ToDo.mdの受入条件に従う）

---

## 1) ベースプロンプト（最初に貼る）

> どのAIでも最初にこのブロックを貼ってから、個別タスクプロンプトを続けてください。

```
あなたは「論文提出パッケージ作成の実務アシスタント」です。
目的は、ToDo.md に書かれた OPEN タスクを順に潰して、論文を提出できる状態にすることです。

【必須ルール】
- 捏造しない。ファイルや数値が見つからない場合は「見つからない」と言い、代替案を提示する。
- 追加実験・追加データ収集・モデル再学習はしない（ToDoに明記されたもの以外は Optional に分離）。
- 変更は最小にし、影響範囲を説明する。
- すべての主張に「根拠ファイルパス」を添える（例: docs/paper/data/tables/xxx.csv）。
- 出力は「(1) 実行計画 → (2) 具体作業 → (3) 変更差分/ファイル全文 → (4) verify手順 → (5) 受入条件チェック」の順にする。

【最初にやること】
1) ToDo.md を読み、OPENタスク一覧をそのまま転記して「実行順序」を提示する。
2) 各タスクの依存関係（先にやらないと困るもの）を明記する。
3) その後、私が指定したタスクから着手する。
```

---

## 2) タスク別プロンプト（ToDo.mdの番号に対応）

### Prompt: P0-1（言語/表記統一 → STYLE_GUIDE.md 作成）

```
ToDo.md の P0-1 を実行してください。

【必ず読む】
- ToDo.md（P0-1）
- docs/paper/paper_outline.md
- docs/paper/images/FIGURE_MAP.md
- docs/paper/images/ 配下の画像（ラベル言語の現状確認）
- docs/paper/number_source_map.md

【作業】
1) 本文と図の言語を「日本語」に統一する方針で、STYLE_GUIDE を設計する（英語論文にする場合の差分も末尾に1段だけ書く）
2) 用語の正規形（Stage1/2/3, call rate, auto-decision error, difficult subset 等）を「日本語＋初出で英併記」の形で定義
3) 数値・単位・桁区切り・%表記・小数点のルールを定義
4) 図ラベル方針（軸ラベル、凡例、注記、n表記）を定義

【出力】
- 新規ファイル docs/paper/STYLE_GUIDE.md の全文
- 既存ファイルとの衝突がある場合は「どこを直すべきか」を箇条書き
```

---

### Prompt: P0-2（最終図セット確定 → FIGURE_MAP整理）

```
ToDo.md の P0-2 を実行してください。

【必ず読む】
- ToDo.md（P0-2）
- docs/paper/paper_outline.md（図表計画）
- docs/paper/images/FIGURE_MAP.md
- docs/paper/images/ 配下の全ファイル名一覧

【作業】
1) paper_outline の図番号（Fig1..）ごとに「最終採用品候補」を1つずつ選ぶ
2) 最終採用品は命名規則に合わせてリネーム案を作る（例: fig01_*.png）
3) 落選図の退避先（_unused/）を提案
4) FIGURE_MAP.md を「最終採用品のみ」に更新した全文を提示

【出力】
- リネーム/移動のコマンド案（mvのリスト）
- 更新後の FIGURE_MAP.md 全文
- もし図が不足している場合は、不足図番号と、どのCSVから生成すべきかを明記
```

---

### Prompt: P0-3（Fig4 遅延図の生成/更新）

```
ToDo.md の P0-3 を実行してください。

【必ず読む】
- ToDo.md（P0-3）
- docs/paper/data/tables/fig4_processing_time.csv
- docs/paper/STYLE_GUIDE.md（あれば）
- docs/paper/paper_outline.md（Fig4の意図）

【作業】
1) CSVの列定義（秒/ミリ秒、対象母数n、集計方法）を確認し、図に適切な形へ変換する
2) CDF（推奨）または分位点バーで、論文掲載に耐える図を1枚作る
3) 画像の保存先と名前を提案（例: docs/paper/images/fig04_latency.png）
4) 図キャプション案（1段落）を作る。必ず以下を含める:
   - 対象（何の遅延か）
   - 単位（秒）
   - 分位点（p50/p90/p99）
   - n（評価件数）

【出力】
- 図を生成するコード（Python推奨。matplotlibでOK）
- 生成コマンド
- 図ファイル名と、FIGURE_MAP/outlineにどう反映するか
```

---

### Prompt: P0-4（Fig5 誤り分析図の生成/更新）

```
ToDo.md の P0-4 を実行してください。

【必ず読む】
- ToDo.md（P0-4）
- docs/paper/data/tables/fig5_error_categories.csv
- docs/paper/STYLE_GUIDE.md（あれば）
- docs/paper/paper_outline.md（誤り分析の使い方）

【作業】
1) CSVから、本文の議論に直結する「カテゴリ」を抽出する（上位K + Others で可）
2) Stage3の FN と FP を比較できる形の図を作る（左右/上下の2パネルでも良いが、1枚に収める）
3) 画像の保存先と名前を提案（例: docs/paper/images/fig05_error_breakdown.png）
4) 図キャプション案（カテゴリ定義の導線含む）を作る

【出力】
- 図を生成するコード（Python + matplotlib）
- 生成コマンド
- 図ファイル名と、FIGURE_MAP/outlineにどう反映するか
```

---

### Prompt: P0-5（ハイパラ表記の最終整合）

```
ToDo.md の P0-5 を実行してください。

【必ず読む】
- ToDo.md（P0-5）
- docs/paper/data/tables/appendix_baselines.csv
- scripts/evaluate_baselines_minimal.py（存在すれば）
- docs/paper/paper_outline.md（Stage1/Appendix記述）
- もし存在すれば Stage1 学習設定ファイル/ログ/コード

【作業】
1) Stage1/ベースラインの「正」ハイパラを確定（根拠ファイルを明示）
2) paper_outline と appendix_baselines の矛盾点を列挙し、最小修正案を提示
3) number_source_map への追記が必要なら提案

【出力】
- 修正が必要な箇所リスト（ファイルパス + 該当行/該当節）
- 修正文（コピペ可能。差分形式推奨）
- 最終的に"一貫した説明"になる文章案（1〜2文）
```

---

### Prompt: P0-6（原稿組版：LaTeXプロジェクト作成）

```
ToDo.md の P0-6 を実行してください。

【必ず読む】
- ToDo.md（P0-6）
- docs/paper/paper_outline.md（章立て・図表計画）
- docs/paper/images/FIGURE_MAP.md（採用図）
- docs/paper/data/tables/（採用表）

【作業】
1) 原稿プロジェクトのディレクトリ構成案を提示する（paper/ など）
2) main.tex の雛形（章立て、図表のinclude、引用の枠）を作る
3) 表はCSV→LaTeXへの変換方針を決める（手作業/自動、どちらでも可）
4) ビルド手順（latexmk等）を README にまとめる

【出力】
- 作成すべきファイル一覧
- main.tex の雛形全文（コピペ可能）
- paper/README.md の全文
- 図表の include 例（\includegraphics、\input 等）
```

---

### Prompt: P0-7（提出前ゲート：verify + grep + 主要数値トレース）

```
ToDo.md の P0-7 を実行してください。

【必ず読む】
- ToDo.md（P0-7）
- docs/paper/number_source_map.md
- docs/paper/data/README.md

【作業】
1) verifyコマンドを実行する前提で、必要な手順と期待結果を整理する
2) "旧数値残存チェック"のgrep対象とコマンドを列挙する
3) 主要数値（n、F1、p50/p90/p99 等）を、number_source_map でトレースするチェックリストを作る
4) verification_log.md のテンプレを作る

【出力】
- 実行コマンド一覧
- チェックリスト
- docs/paper/verification_log.md のテンプレ全文
```

---

## 3) 仕上げ用プロンプト（P1系）

必要なら、P1タスク（要旨、関連研究、Ethics）も同じ形式で追加できます。
