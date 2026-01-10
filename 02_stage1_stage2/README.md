# 02_stage1_stage2: Stage1 & Stage2 Implementation

このディレクトリは、フィッシング検知システムの **Stage1 (XGBoost) と Stage2 (LR Gate)** の実装とその関連ファイルを管理します。

---

## ディレクトリ構成

```
02_stage1_stage2/
├── configs/              # 設定ファイル
│   ├── default.yaml      # デフォルト設定（Phase 1で作成）
│   └── ...               # 実験用設定（Phase 2以降で追加予定）
│
├── src/                  # Pythonソースコード（Phase 2で作成予定）
│   ├── features.py       # 特徴量抽出
│   ├── train_xgb.py      # Stage1 XGBoost訓練
│   ├── route1_threshold.py  # Route1自動閾値選択
│   ├── stage2_gate.py    # Stage2 LRゲート
│   ├── outputs.py        # 出力生成
│   ├── utils.py          # ユーティリティ
│   └── main.py           # パイプライン統合
│
├── scripts/              # 実験・自動化スクリプト（Phase 3で作成予定）
│   └── sweep_budget.py   # budget感度分析
│
└── README.md             # このファイル
```

---

## メインファイル（プロジェクトルート）

**Jupyter Notebook**: `../02_main.ipynb`（プロジェクトルートに配置）
- Stage1 XGBoost訓練 + Stage2 LR Gate + 出力生成
- 設定ファイル `02_stage1_stage2/configs/default.yaml` を読み込み

---

## 設定ファイル

### `configs/default.yaml`

全ての設定を一元管理するYAMLファイル。以下のセクションで構成：

- **experiment**: 可視化・評価設定
- **xgboost**: Stage1ハイパーパラメータ
- **route1**: 自動閾値選択（Wilson upper bound）
- **stage2**: Gate v2 segment_priority設定
- **brand_keywords**: ブランドキーワード抽出設定
- **io**: 入出力パス設定

### 設定変更方法

1. `configs/default.yaml` を編集
2. `02_main.ipynb` を実行
3. 結果が `artifacts/<RUN_ID>/` に保存される

### 複数設定の管理（Phase 2以降）

実験用に複数の設定ファイルを作成可能：

```bash
cp configs/default.yaml configs/budget_10k.yaml
# budget_10k.yaml を編集: max_budget: 10000
```

---

## 使い方

### 基本実行

```bash
cd /data/hdd/asomura/nextstep
jupyter notebook 02_main.ipynb
# 全セルを実行
```

### 設定変更して実験

1. `02_stage1_stage2/configs/default.yaml` を編集
   ```yaml
   stage2:
     max_budget: 10000  # 5000から変更
   ```

2. `02_main.ipynb` を実行

3. 結果確認
   ```bash
   ls artifacts/<RUN_ID>/results/
   # stage1_decisions_latest.csv
   # stage2_decisions_latest.csv
   # stage2_pending_latest.csv  ← Phase 1で追加
   # handoff_candidates_latest.csv
   # route1_thresholds.json
   # stage2_budget_eval.json
   ```

---

## Phase 1 で追加された機能

### 1. 設定外部化
- 全設定を `configs/default.yaml` に集約
- notebook内のハードコード設定を削除

### 2. Brand特徴の有効化
- `seg_include_brand: true` に修正（Phase 0で発見したバグ修正）
- `brand_hit` 列が正常に機能

### 3. PENDING出力の明示化
- `stage2_pending_latest.csv` を新規出力
- Stage2で選抜されなかった候補（drop_to_auto）を明示
- 統計情報と警告メッセージを表示

---

## Phase 2 以降の予定

### Phase 2: Pythonモジュール化
- `src/` 配下にコアロジックを抽出
- `main.py` でパイプライン統合
- コマンドライン実行可能に

### Phase 3: 自動化スクリプト
- `scripts/sweep_budget.py` でパラメータスイープ
- 複数設定の自動実行
- 結果集約・比較

---

## 関連ドキュメント

- **Phase 0 分析結果**: `../docs/sakusen/02_phase0.md`
- **Phase 1 変更履歴**: `../CHANGELOG_Phase1.md`
- **プロジェクト概要**: `../docs/00_overview.txt`
- **システム構成**: `../docs/02_XGBoost_LR.txt`

---

## 問い合わせ

設定変更や実験結果の解釈については、以下を参照：
- Phase 0で特定された3つの課題
- brand特徴の動作確認方法
- PENDING領域の扱い

---

**最終更新**: 2026-01-10 (Phase 1完了)
