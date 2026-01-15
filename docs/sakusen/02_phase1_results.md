# Phase 1 実行結果レポート

**実行日**: 2026-01-10
**RUN_ID**: 2026-01-10_105017
**ベースライン**: Phase 0 (2026-01-08_185227, artifacts削除済み)

---

## 実行環境

- **Notebook**: `02_main.ipynb` (Phase 1で簡素化)
- **Config**: `02_stage1_stage2/configs/default.yaml`
- **実行順序**: `01*.ipynb` → `02_main.ipynb`

---

## 1. Phase 1で実施した変更

### 1.1 設定外部化
- 全設定を `02_stage1_stage2/configs/default.yaml` に集約
- Notebook Cell 0でYAML読み込み
- 環境変数として設定（後方互換性維持）

### 1.2 Critical Fix適用
- **Fix #1**: `seg_include_brand: true` に変更（Phase 0では false）
- **Fix #2**: PENDING出力ロジック追加（Cell 43）

### 1.3 ディレクトリ構成整理
- `02_stage1_stage2/` 配下に configs, src, scripts フォルダ作成
- Notebookを `02_main.ipynb` にリネーム、ルートに配置
- 旧ファイルは `notebooks_archive/` に保管

---

## 2. 実行結果サマリー

### 2.1 Stage1 (XGBoost) 結果

| 項目 | 値 | 割合 |
|------|---:|-----:|
| Total samples | 128,067 | 100.0% |
| AUTO decisions | 123,067 | 96.1% |
| DEFER to Stage2 | 54,672 | 42.7% |
| AUTO errors | 1,691 | 1.37% |

**評価**: AUTO領域の精度は非常に高い（エラー率1.37%）

---

### 2.2 Stage2 (LR Gate) 結果

| 項目 | 値 |
|------|---:|
| Priority pool | 1,470 |
| Optional pool | 16,145 |
| Selected (pre-cap) | 6,152 |
| **Selected (final)** | **5,000** |
| - Override | 901 |
| - Gray | 4,099 |

**Budget**: 5,000 (cap適用済み)

---

### 2.3 PENDING領域分析（新規出力）

**ファイル**: `stage2_pending_latest.csv` ✅ 作成成功

| 項目 | 値 | 割合 |
|------|---:|-----:|
| Total PENDING | 49,672 | 100.0% |
| True Benign | 47,532 | 95.7% |
| **True Phish** | **2,140** | **4.3%** |

⚠️ **警告**: 2,140件のフィッシングサンプルが未処理のまま残留

**Phase 0からの変更**:
- Phase 0ではPENDING領域が明示的なファイルとして出力されていなかった
- Phase 1でCSVファイル化、統計情報も明示

---

### 2.4 Stage3 Handoff

**ファイル**: `handoff_candidates_latest.csv`

| 項目 | 値 | 割合 |
|------|---:|-----:|
| Total handoff | 5,000 | 100.0% |
| True Benign | 3,624 | 72.5% |
| True Phish | 1,376 | 27.5% |

**Phish Enrichment**: 4.3x
- DEFER region: 6.4% phish
- Stage3 handoff: 27.5% phish

---

## 3. Brand特徴の状態

### 3.1 設定値

```yaml
stage2:
  seg_include_brand: true  # ✅ Phase 0の false から true に変更
```

### 3.2 実行結果

**ファイル**: `gate_trace_candidates__2026-01-10_105017.csv`

| 項目 | 値 |
|------|---:|
| Total candidates | 54,672 |
| brand_hit sum | 0 |
| brand_hit > 0 | 0 (0.00%) |

❌ **問題**: Brand特徴が機能していない（全てゼロ）

### 3.3 原因推定

考えられる原因:

1. **Brand辞書が生成されていない**
   - LLMによるブランドキーワード抽出が実行されていない可能性
   - `BRAND_KEYWORDS` 変数が空

2. **Brand照合ロジックが実行されていない**
   - Stage2ゲート処理でbrand_hit計算がスキップされている
   - 特徴量抽出時にbrand列が含まれていない

3. **LLM接続エラー**
   - Brand抽出にLLMを使用する設計のため、LLM接続が失敗している可能性

### 3.4 影響範囲

- **Priority pool**: 1,470件（変化なし）
  - Phase 0と同じサイズ = brand候補が追加されていない
- **Stage2選抜**: Phase 0と同一結果の可能性が高い

---

## 4. 出力ファイル一覧

### 4.1 Phase 1で新規追加

- ✅ `stage2_pending_latest.csv` (4.2MB, 49,672行)

### 4.2 既存ファイル（Phase 0と同様）

- `route1_thresholds.json`
- `stage1_decisions_latest.csv`
- `stage2_decisions_latest.csv`
- `stage2_decisions_candidates_latest.csv`
- `stage2_budget_eval.json`
- `gate_trace_candidates__*.csv`
- `handoff_candidates_latest.csv`

---

## 5. Phase 1の達成度評価

### 5.1 成功した項目 ✅

| # | 項目 | 状態 |
|---|------|------|
| 1 | 設定外部化 | ✅ 完了 |
| 2 | ディレクトリ整理 | ✅ 完了 |
| 3 | Notebook簡素化 | ✅ 完了 |
| 4 | PENDING出力追加 | ✅ 完了 |
| 5 | `seg_include_brand` 設定変更 | ✅ 完了 |

### 5.2 未解決の問題 ❌

| # | 問題 | 原因 | 影響 |
|---|------|------|------|
| 1 | Brand特徴が機能しない | Brand辞書生成orLLM接続 | Priority pool未拡大 |
| 2 | PENDING Phish 2,140件 | Budget制約 | 見逃しリスク |

---

## 6. Phase 0との比較（推定）

Phase 0のartifactsは削除されているため、Phase 0の分析レポート（`docs/sakusen/02_phase0.md`）との比較:

### 6.1 変化なし（推定）

- Stage1閾値（t_low, t_high）
- DEFER候補数（54,672）
- Priority pool サイズ（1,470）
- Stage3 handoff数（5,000）
- PENDING Phish数（2,140）

### 6.2 変化あり

- ✅ PENDING出力ファイル（Phase 0: なし → Phase 1: あり）
- ✅ 設定管理方式（Phase 0: notebook埋め込み → Phase 1: YAML外部化）

---

## 7. 次のアクションアイテム

### 7.1 緊急対応（Brand特徴修正）

**優先度**: 高

**タスク**:
1. Notebookの実行ログで、Brand抽出セルの出力を確認
   - "Brand min_count: X max_brands: Y dynamic: Z" メッセージ確認
   - `BRAND_KEYWORDS` 変数の内容確認
   - LLM接続エラーの有無

2. Brand辞書が空の場合:
   - LLM設定（base_url, model）の確認
   - LLM接続テスト
   - Brand抽出ロジックの修正

3. Brand辞書が存在する場合:
   - Stage2ゲート処理でのbrand照合ロジック確認
   - `seg_include_brand` 設定が正しく読み込まれているか確認

**期待効果**:
- Priority pool サイズが 1,470 → X,XXX に拡大
- PENDING Phish が 2,140 → 減少

---

### 7.2 Budget最適化実験

**優先度**: 中

**タスク**:
1. Budget感度分析実験
   - configs/default.yaml で `max_budget` を変更
   - 5,000 / 10,000 / 15,000 / 20,000 で実行

2. 結果比較
   - PENDING Phish数の変化
   - Stage3コスト vs 見逃し削減のトレードオフ

**成果物**:
- Budget最適値の推奨
- コスト/効果グラフ

---

### 7.3 Label検証（長期）

**優先度**: 低

**タスク**:
1. PENDING Phish 2,140件の上位100件を外部検証
   - Google Safe Browsing
   - PhishTank
   - urlscan.io

2. Label疑義率の推定

**成果物**:
- Label品質レポート
- 改善余地の切り分け

---

## 8. まとめ

### 8.1 Phase 1の意義

Phase 1では、**運用基盤の整備**に成功しました:

- 設定外部化により、実験の再現性と効率性が向上
- PENDING出力により、未処理サンプルの可視化が実現
- ディレクトリ整理により、Phase 2（py化）への道筋が明確化

### 8.2 残された課題

**Brand特徴の修正**が最優先課題です。この修正により:

- Priority poolの拡大が期待される
- PENDING Phish数の削減が見込まれる
- Stage2ゲートの実効性が向上する

### 8.3 次のマイルストーン

**Phase 1.5**: Brand特徴修正（緊急）
**Phase 2**: Pythonモジュール化（自動化基盤）
**Phase 3**: Budget最適化実験

---

**レポート作成日**: 2026-01-10
**次回更新**: Brand特徴修正後
