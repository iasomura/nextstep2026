# TODO 実行プロンプト集

各TODO項目を Claude Code に実行させる際に使用したプロンプト（原文）。
再利用・類似論文への応用を想定し、パターンごとに記録する。

作成日: 2026-02-07

---

## 共通パターン

全プロンプトに共通する設計原則：

1. **ロール宣言**（冒頭）: `あなたは「○○担当」です。` で役割を限定
2. **入力ファイル指定**（必須読み込み）: 判断材料を明示し、hallucination を防止
3. **タスク分割**: 番号付きで具体的な作業を列挙
4. **出力形式**: 期待するアウトプットの形式を指定
5. **制約・禁止事項**: やってはいけないことを明示（追加実験の抑止、断定の回避等）

---

## TODO-0: 図の数値整合性修正

**種別**: コード実装（図生成スクリプトの修正）
**前段**: Plan Mode で調査→計画策定→承認後に実行

```
Implement the following plan:

# TODO-0: 図の数値整合性修正計画

## 概要

`generate_paper_figures.py` の fig01/fig06 にハードコードされた旧数値（14箇所以上）を、検証済みCSV (`docs/paper/data/tables/`) から読み込む方式に修正し、図と本文・表の数値不一致をゼロにする。

---

## 前提（調査済み）

### 問題のある図
- **fig01** (lines 143-251): カスケードアーキテクチャ図 — 14箇所の旧数値
- **fig06** (lines 694-801): 処理フロー図 — 16箇所の旧数値

### 問題のない図
- fig02〜fig05, fig07: CSVから読み込み済み、問題なし

### 旧→正の対応（fig2_stage_transitions.csv + VERIFIED dict）

| 項目 | 旧値 | 正値 |
|------|------|------|
| Input | 127,754 | 127,222 |
| auto_phishing | 60,614 (47.4%) | 60,767 (47.8%) |
| auto_benign | 6,166 (4.8%) | 8,464 (6.7%) |
| handoff | 60,974 (47.7%) | 57,991 (45.6%) |
| safe_benign (drop) | 45,304 (35.5%) | 46,039 (36.2%) |
| Stage3投入 | 15,670 (12.3%) | 11,952 (9.4%) |
| Stage3 TP | 2,446 | 1,685 |
| Stage3 FP | 665 | 529 |
| Stage3 TN | 13,224 | 8,978 |
| Stage3 FN | 1,781 | 760 |
| System F1 | 98.66% | 98.67% |

### データソース（正解の出典）
- `docs/paper/data/tables/fig2_stage_transitions.csv` — Stage遷移件数
- `docs/paper/data/tables/table3_system_performance.csv` — システム性能
- `docs/paper/data/tables/table5_stage3_performance.csv` — Stage3混同行列
- `docs/paper/data/statistics/system_overall_metrics.json` — システム全体指標

---

## 実装ステップ

### Step 1: 旧図のlegacy隔離
- `docs/paper/images/_legacy/` ディレクトリ作成
- 現在の `fig01_s3.1_cascade_architecture.png` と `fig06_s4.5.1_processing_flow.png` を `_legacy/` にコピー

### Step 2: `generate_paper_figures.py` を修正
- 2a: CSV読み込み関数 `load_figure_data()` の追加
- 2b: fig01 の修正 (lines 143-251) — ハードコード数値を全て置換
- 2c: fig06 の修正 (lines 694-801) — 同上
- 2d: `--verify` フラグの追加

### Step 3: 図の再生成
### Step 4: `docs/paper/images/FIGURE_MAP.md` 作成
### Step 5: `docs/paper/number_source_map.md` 作成
### Step 6: 旧数値の残存チェック
### Step 7: 検証実行

## 受入条件
1. `generate_paper_figures.py` 内に旧数値がゼロ
2. fig01/fig06 の全数値が CSV と一致
3. `--verify` がパス
4. FIGURE_MAP.md と number_source_map.md が存在
5. 旧図が `_legacy/` に隔離済み
```

---

## TODO-7: MTG合意の反映（論文の芯を固定）

**種別**: 論文アウトライン編集（大規模リライト）

```
あなたは「論文本文（骨子）を、MTG合意に沿って論理一貫させる編集者」です。
本研究の主張は "分類器の優劣" ではなく、「確信度に基づく投入制御（handoff/budget）」と「困難集合でのルール統合による補正」です。
査読者が "FN追跡？" "budget最適化？" で迷わないように、用語・集合・指標・適用順を明文化してください。

# 入力として必ず読むもの
- `docs/paper/TODO.md` の TODO-7 節
- `docs/mtg/202512/20251228.txt`（MTG議論の核：gray/確信度設計）
- `docs/paper/paper_outline.md`
- `docs/paper/review_notes.md`
- `docs/paper/data/tables/table4_stage2_effect.csv`（cert gate / tau / override）
- `docs/paper/data/tables/fig2_stage_transitions.csv`（handoff母数の定義）
- `docs/paper/data/tables/table5_stage3_performance.csv`（difficult subset n=11,952）

# タスク
1) `docs/paper/paper_outline.md` を編集し、以下を"本文主軸"として固定する（文言を具体化）
   - §1（導入）に「焦点は分類器比較ではなく、確信度に基づく投入制御＋困難集合での補正」である旨を明記
   - RQ1/RQ2の書き方を、投入率（budget）と auto-decision error、困難集合でのルール統合（Recall改善とFP増）へ寄せる
   - §4（評価）で Stage3 の評価対象が difficult subset（n=11,952）であることを表題・キャプション級の強さで明示

2) 用語・集合・指標の定義を明文化（査読者が迷わないことが目的）
   - Gray / Handoff / Auto decision の定義
   - Stage1の三値ルーティングを、式 or 擬似コードで 1つ提示
   - cert gate の仕様境界を、順序と優先度で明確化：
     - 位置付け: hard gate（safe_benign判定として先にdrop）
     - 適用順: cert gate → p_error閾値 → high_ml_phish override
     - 衝突時: cert gate優先
     - これにより "auto-decision error" が一意に定義されることを断言できる形にする

3) 主目的指標を固定
   - RQ1: "Stage3 call rate" と "auto-decision error" を一次指標、最終F1は補助
   - RQ2: difficult subset での Recall改善（＋FP増）を主に書く

4) 貢献の定型文（導入 or 議論に挿入）
   - 「任意の確率出力モデルに適用可能」という防御線

# 出力形式
- `docs/paper/paper_outline.md` の更新版（変更箇所へ `<!-- CHANGED: 理由 -->` コメント付与）
- 定義（擬似コード/式）部分はコピペ可能な Markdown ブロック

# 制約
- 数値は検証済みリファレンスと一致させ、勝手に改変しない
- "FN追跡" を主語にした書き方に寄せない
```

---

## TODO-8: Fig3（スイープ）と本文の整合

**種別**: 図生成 + 論文アウトライン編集

```
あなたは「図（Fig3）と本文の主張整合性チェック担当」です。
現状の `docs/paper/data/tables/fig3_threshold_sweep.csv` は "投入率（Stage3 call rate） vs 自動判定誤り（auto_errors; Stage1+2の誤り）" のスイープであり、
"最終性能（Stage3込み）のトレードオフ曲線" ではありません。ここを誤ると査読で即死です。

# 入力として必ず読むもの
- `docs/paper/TODO.md` の TODO-8 節
- `docs/paper/data/tables/fig3_threshold_sweep.csv`
- `docs/paper/data/tables/table3_system_performance.csv`（最終性能は点比較）
- `docs/paper/paper_outline.md`

# タスク
1) 基本方針は「案A（追加実験なし）」で成立させる（推奨）
   - Fig3の主張を "投入率と自動判定誤り（auto_errors）の関係" に限定する
   - 最終性能については "曲線" と言わず、点比較で述べる導線に修正する

2) Fig3のタイトル/キャプション/本文参照を修正し、禁止語を排除する
   - 禁止: "overall performance trade-off curve", "end-to-end trade-off curve"
   - 推奨表現: "Stage3 call rate vs auto-decision errors under Stage1+2"

3) もし Fig3 の画像がまだ無い/不適切なら、CSV から図を新規生成する
   - 横軸=stage3_rate_pct、縦軸=auto_errors
   - "最終性能曲線に見える表現" を避ける

4) `docs/paper/paper_outline.md` の §4.2 / 図表計画 / Fig3説明を更新する

# 出力形式
- 変更後の `paper_outline.md`（該当セクション差分）
- 生成したFig3画像と生成コード
- "本文でどう言い換えるか" の具体文

# 追加条件（案Bの扱い）
- コストが小さく τ を2点だけ選んで Stage3 まで回せるなら案B提案可。
  ただし 3点以上に増やして沼らない。実施可否・コスト・メリットを比較し最終案を提示。
```

---

## TODO-9: 母数のズレ修正

**種別**: データ修復（SO failure 再評価）
**備考**: 専用のロールプロンプトではなく、対話的に進行

```
TODO-9 — 母数ズレの脚注・引用ルール固定（原則n=11,952）

[初期質問]
これはpaper_outline.mdを更新すれば終わるのか？

[追加指摘]
確認しました。現状、TODO-9は「ほぼ解消」ですが、査読者視点ではまだ"未完"扱いになります。
理由は母数が完全一致していないためです（1件ズレています）。

対象ファイル：
- tables/table5_stage3_performance.csv: total_evaluated = 11952
- statistics/stage3_metrics.json: total_evaluated = 11952
- tables/table6_stage3_ablation.csv: n_evaluated = 11951（1件ズレ）
```

**結果**: SO parse failure 16件を再評価し、Table5/Table6ともにn=11,952で完全一致を達成。

---

## TODO-B: 再現性ドキュメント

**種別**: ドキュメント新規作成

```
あなたは「再現性ドキュメント（最小の入口）担当」です。
`docs/paper/data/` は論文の表・図・統計の根拠データだが、再生成手順が未整備です。
`docs/paper/data/README.md` を "1ページで十分" の方針で新規作成してください。

# 入力として必ず読むもの
- `docs/paper/TODO.md` の TODO-B 節
- `scripts/generate_paper_data.py`（入力ファイル・出力ファイル・phase/verify）
- `docs/paper/data/tables/` と `docs/paper/data/statistics/` の実ファイル一覧

# タスク
`docs/paper/data/README.md` を新規作成し、以下を必ず含める：
1) 再生成コマンド（phase指定と verify の説明）
2) 入力ファイル一覧（artifacts配下、役割も一言）
3) 出力ファイル一覧（対応表：どの表/図/節で使うか）
4) 最小の環境情報（Pythonバージョン、主要ライブラリ、前提条件）

# 出力形式
- `docs/paper/data/README.md` の内容（そのままコミットできる品質）
- READMEの末尾に "よくある失敗" を3つ程度添える
```

---

## TODO-1: 最小ベースライン比較

**種別**: ML実験 + スクリプト作成

```
あなたは「同一データセットでの最小ベースライン比較」を実施するML実験担当です。
目的は"勝つ"ことではなく、査読で論点を「分類器優劣」にずらされないための防御線（Appendix用）を用意することです。

# 制約（絶対）
- 追加の特徴量実装はしない：既存の 42 特徴量・既存 split をそのまま使う
- モデルは 2本固定（LightGBM + RandomForest）。3本目は作らない
- ハイパラ探索は最小（各モデル 2〜3設定まで）
- 指標は F1 / FPR / FNR（＋混同行列）に絞る
- 出力は Appendix 表が原則。本文は 1行で触れる程度

# 入力として読むべきもの
- `docs/paper/TODO.md` の TODO-1 節
- `docs/paper/paper_outline.md` と `docs/paper/review_notes.md`
- Stage1の学習・データ生成の導線

# タスク
1) Stage1で使ったのと同じ Train/Test を再現できるデータ入手経路を特定する
2) 2モデル（LightGBM / RandomForest）で学習→Test推論→評価（seed固定）
3) 結果を Appendix 用テーブルとして出力（CSV: `appendix_baselines.csv`）
4) 論文側の書き方（"分類器比較が主ではない" 防御線）を用意

# 出力形式
- 実験手順（再現コマンド）、入力パス、結果CSV、要約
- 新規スクリプト `scripts/evaluate_baselines_minimal.py` を追加
```

---

## TODO-2: 「なぜ証明書か」の動機付け

**種別**: 論文アウトライン編集（最小限の追記）

```
あなたは「論文（CSS想定）の編集者」です。追加実験は一切行わず、既存のアウトラインに最小限（1〜2文）で「なぜ証明書（TLS certificate）に着目するのか」を動機付けとして追記してください。目的は、査読者の「証明書じゃだめなの？」「なぜURL/HTMLではないの？」を文章だけで止め、論点を本研究の主軸（確信度に基づく投入制御・ルール統合）へ戻すことです。

# 前提（重要）
- このTODOは「追加実験を生まないための論点コントロール」であり、性能比較や新規評価はしない。
- 断定を避ける（例：「必ず事前検知できる」はNG）。誠実に「〜できる場合がある」「〜に寄与し得る」の表現でまとめる。
- 「証明書がURL/HTMLより優れている」と読める比較煽りはしない（比較実験要求を誘発するため）。

# 調整済み材料（この核を必ず使う：学術的に刺されにくい言い回し）
材料_adjusted = """
フィッシングサイトの立ち上げでは、運用上しばしばインフラ準備（ドメイン設定等）に続いてTLS証明書の取得・設定が先行し、最終段でコンテンツ配備が行われる。
そのため証明書メタ情報は、Webページの取得やレンダリングを行う前段で観測できる場合があり、攻撃に使われる前の兆候検知や事前対処（監視・対応準備）に寄与し得る。
"""

# 参考（CSS2025.pdf から"使える"記述）
- CSS2025.pdf p.2: SSL/TLS普及に伴いフィッシングサイトのHTTPS化が進んでいる
- CSS2025.pdf p.3: TLS証明書に基づく特徴量（5個）を設計

# 読むべきリポジトリ内ドキュメント（必須）
- `docs/paper/TODO.md` の TODO-2 節
- `docs/paper/paper_outline.md`
- （可能なら）`docs/analysis/03_certificate_analysis.md`
- （可能なら）`docs/paper/data/tables/table2_cert_availability.csv`、`table2_cert_status.csv`

# タスク（文章のみ／追加実験なし）
1) 「なぜ証明書か」を 1〜2文で成立させる文章案を 3パターン作る（日本語）
   - 必須要素：早期性（コンテンツ取得より前段で観測できる"場合がある"）、運用含意（事前対処・監視準備の"可能性"）
   - 最小の誠実さ：適用範囲の限界を"一言だけ"添える

2) 文章を入れる最適位置を 1つ推奨し、理由を短く説明する
   - 候補：導入（§1.1）/ 関連研究末尾（§2）/ 議論（§5）

3) `docs/paper/paper_outline.md` への反映案を作る（差分が分かる形）
   - `<!-- CHANGED: TODO-2 rationale for certificates -->` コメント付与
   - 前後の主張を主軸に戻す接続にする

# セルフチェック
- 「証明書じゃだめなの？」への回答になっている
- 追加実験を誘発しない
- 断定していない
```

---

## TODO-3: Threats to Validity

**種別**: 論文アウトライン編集（§5.3 構造化リライト）

```
あなたは「Threats to Validity を"殴られにくい形"に仕上げる担当」です。
追加実験を要求されないように、既に実施済みの分析（Fig3の感度、処理時間、誤り分解）を使って、
"脅威の列挙" から "緩和策/限界/今後課題" まで落とし込んでください。

# 入力として必ず読むもの
- `docs/paper/TODO.md` の TODO-3 節
- `docs/paper/paper_outline.md` §5.3（Threats）
- `docs/paper/data/tables/fig3_threshold_sweep.csv`（閾値感度＝緩和策にできる）
- `docs/paper/data/tables/fig4_processing_time.csv`（遅延・運用面の含意）
- `docs/paper/data/tables/fig5_error_categories.csv`（誤り分解）
- `docs/paper/data/tables/table2_cert_availability.csv` & `table2_cert_status.csv`（観測バイアス説明材料）

# タスク
1) 各脅威に対し、以下を1セットにして文章として成立させる：
   - "本研究で実際にやった緩和策（書ける事実）"
   - "残る限界（正直に）"
   - "今後課題（追加実験が必要なもの）"

2) スコープ宣言（追加実験ゼロで封じる）
   - 三値学習、uncertainty calibration、別モデル最適化は自然な拡張だが、
     本稿のスコープは「投入制御とルール統合の効果」にある、と明記
   - Threats 置き / Future Work 置きの両案を作り、推奨を1つ示す

3) "Threats と緩和策の要約表（表7相当）" を提案（行数を絞る）

4) `docs/paper/paper_outline.md` の §5.3 を更新案として提示
   - 既存データ（Fig3/4/5, Table2等）への参照導線も追加する

# 出力形式
- 更新後の §5.3 案（日本語、コピペ可能）
- スコープ宣言の文（2案＋推奨1つ）
- 要約表案（Markdown表）
```

---

## プロンプト設計のポイント（振り返り）

### 効果的だったパターン
1. **ロール限定**: 「○○担当です」で AI のスコープを絞ると、余計な作業をしない
2. **入力ファイル明示**: 「必ず読むもの」を列挙すると、データに基づいた回答になる
3. **禁止事項**: 「追加実験をしない」「断定しない」「比較煽りをしない」を明記すると、暴走しない
4. **出力形式の指定**: 「コピペ可能」「差分が分かる形」で、手戻りが減る
5. **受入条件**: Done定義を事前に書くと、完了判定が明確

### TODO種別ごとの使い分け
| 種別 | 代表TODO | ポイント |
|------|---------|---------|
| コード実装 | TODO-0 | Plan Mode → 実装計画を先に承認 |
| 大規模リライト | TODO-7 | MTG議事録等の「根拠」を入力に含める |
| 図と本文の整合 | TODO-8 | 禁止語を明示、案A/案Bの選択肢を提示 |
| データ修復 | TODO-9 | 対話的に進行（専用プロンプト不要の場合あり） |
| ドキュメント作成 | TODO-B | 「1ページで十分」等のスコープ制約 |
| ML実験 | TODO-1 | 「勝つことが目的ではない」と目的を明示 |
| 最小追記 | TODO-2 | 材料を先に用意し、セルフチェック項目を付与 |
| 構造化リライト | TODO-3 | 既存データへの参照導線を要求 |
