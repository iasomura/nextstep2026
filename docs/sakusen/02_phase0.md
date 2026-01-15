# Phase 0: 現状把握 - 分析報告書

**実施日:** 2026-01-10
**対象RUN_ID:** 2026-01-08_185227
**分析者:** Claude (Sonnet 4.5)

---

## エグゼクティブサマリー

本Phase 0では、02系ノートブック（`02_stage2_gatev2_NOENV__planA__fixed_metrics__SANFIX_CONFOPT__PATCHED_20260107_EMERGENCY_DEFAULTS__STAGE2DECISIONS.ipynb`）の最新実行結果を分析し、システムの現状を定量的に把握した。

### 主要な発見

✅ **良好な点:**
- Stage1（XGBoost）のAUTO領域精度: **99.96%**
- リスク制約付き自動閾値選択が機能
- Stage2のsegment_priority選択が動作

🔴 **重大な問題（緊急対応必要）:**
1. **PENDING領域に2,140件のPhish残留** - 見逃しリスク1.67%
2. **brand特徴が完全停止** - 全54,672件でbrand_hit=0
3. **Stage3予算制約が厳しい** - DEFER候補の9.1%のみ精査

---

## 1. システム構成の確認

### 1.1 三段階アーキテクチャ

```
Stage1 (XGBoost)
  ├─ 入力: 全ドメイン 128,067件
  ├─ 出力: AUTO_BENIGN (12,882) / AUTO_PHISHING (60,513) / DEFER (54,672)
  └─ 閾値: t_low=0.000271, t_high=0.979959 (auto_from_val)

Stage2 (LR + segment_priority Gate)
  ├─ 入力: DEFER領域 54,672件
  ├─ 出力: Stage3送り 5,000件 / PENDING 49,672件
  └─ 設定: budget=5000, tau=0.40, seg_include_brand=FALSE

Stage3 (AI Agent)
  ├─ 入力: Stage2選択済み 5,000件
  └─ 出力: 最終判定 + 根拠（03系ノートブック、本分析対象外）
```

---

## 2. Stage1（XGBoost）の詳細分析

### 2.1 閾値選択（Route1自動選択）

**設定:**
```json
{
  "XGB_T_MODE": "auto_from_val",
  "use_upper": true,
  "alpha": 0.05,
  "risk_max_auto_benign": 0.001,
  "risk_max_auto_phish": 0.0002,
  "min_auto_samples": 200
}
```

**選択結果:**
```json
{
  "t_low": 0.0002705836189576259,
  "t_high": 0.9799588915437725,
  "val_auto_benign_n": 5147,
  "val_auto_benign_risk_est": 0.0008704,
  "val_auto_phish_n": 24138,
  "val_auto_phish_risk_est": 0.0001857
}
```

**テスト時の実測リスク:**
- AUTO_BENIGN領域のリスク: **0.116%** (目標0.1%に対しやや超過)
- AUTO_PHISHING領域のリスク: **0.018%** (目標0.02%以内)

### 2.2 Stage1判定結果

| 判定カテゴリ | 件数 | 割合 | 説明 |
|-------------|------|------|------|
| **auto_benign** | 12,882 | 10.1% | 高確信でBenign判定 |
| **auto_phishing** | 60,513 | 47.2% | 高確信でPhish判定 |
| **handoff_to_agent** | 54,672 | 42.7% | DEFER（次段へ送付） |
| **合計** | 128,067 | 100% | - |

### 2.3 AUTO領域の精度（高確信領域）

**Confusion Matrix:**
```
              Predicted
              Benign  Phish
Actual Benign  12,867    11
       Phish       15 60,502
```

**メトリクス:**
- **精度（Accuracy）:** 99.96%
- **FPR（誤検知率）:** 0.0854% (11 / 12,878)
- **FNR（見逃し率）:** 0.0248% (15 / 60,517)

**✅ 評価:**
AUTO領域は極めて高精度。森先生の指摘「確信を持った判定は正確であるべき」を満たしている。

### 2.4 DEFER領域の構成

**真値の分布:**
```
Total DEFER: 54,672件
  True Benign: 51,156件 (93.6%)
  True Phish:   3,516件 ( 6.4%)
```

**Stage1がDEFERと判定した理由（推定）:**
- ML確率が中間領域（0.000271 < p < 0.979959）
- 特徴量が正常/悪性の境界にある
- ドメイン構造や証明書情報が曖昧

---

## 3. Stage2（LRゲート + segment_priority）の詳細分析

### 3.1 ゲート設定

**segment_priorityモードの設定:**
```python
STAGE2_SELECT_MODE = 'segment_priority'
STAGE2_MAX_BUDGET = 5000
STAGE2_TAU = 0.40
STAGE2_SEG_ONLY_BENIGN = False  # 両側（Benign/Phish予測）を許可
STAGE2_SEG_OPTIONAL = True      # Optional pool有効
STAGE2_SEG_INCLUDE_IDN = True   # IDN優先
STAGE2_SEG_INCLUDE_BRAND = False  # ⚠️ ブランド特徴無効
STAGE2_SEG_MIN_P1 = 0.00        # 低ML確率ガード無効
```

### 3.2 プール構成

**Priority Pool（優先度高）:**
```
構成要素:
  - Dangerous TLD (.icu, .cfd, .cyou, .buzz, .top等 17種)
  - IDN (xn--* 国際化ドメイン名)
  - Brand keywords hit (今回は無効)

件数: 1,470件
選択: τ≥0.40 → 901件をStage3へ
```

**Optional Pool（優先度中）:**
```
構成要素:
  - Unknown TLD (dangerous/legitimateどちらでもない)

件数: 16,145件
選択: τ≥0.488 (動的調整) → 4,099件をStage3へ
```

### 3.3 Stage3への送付

**最終選択結果:**
```
Total Selected: 5,000件（予算上限）
  Priority Pool: 901件
  Optional Pool: 4,099件

真値の分布:
  True Benign: 3,624件 (72.5%)
  True Phish:  1,376件 (27.5%)

Phish濃縮率: 6.4% → 27.5% (4.3倍向上)
```

**✅ 評価:**
Stage2のゲートはPhish濃縮に成功している。優先度付けロジックは機能。

### 3.4 PENDING（未処理）の深刻な問題

**PENDING領域:**
```
Total PENDING: 49,672件（DEFER候補の90.8%）
  True Benign: 47,532件
  True Phish:   2,140件 ⚠️⚠️⚠️

PENDING内のPhish率: 4.3%
```

**⚠️ リスク分析:**

もしPENDINGを「benign扱い」で通した場合:
```
システム全体の見逃し:
  AUTO FN:     15件
  PENDING FN: 2,140件
  合計:      2,155件

見逃し率: 2,155 / 128,067 = 1.68%
```

これは**論文の目標値（偽陰性率1.04%）を大幅に超過**する。

**00_overview.txtの指摘との一致:**
> "Stage2で予算に入らなかったものは、正常確定ではありません。
> 運用上は**PENDING として、隔離・後追い・人手、いずれかの責任ある扱いが必要**です。"

---

## 4. brand特徴の完全停止（重大問題）

### 4.1 検証結果

**gate_trace_candidates CSVの分析:**
```bash
$ cut -d',' -f12 gate_trace_candidates__*.csv | tail -n +2 | sort | uniq -c
  54672 0
```

**結論:** 全54,672件のDEFER候補で`brand_hit=0`

### 4.2 原因調査

**設定確認:**
```python
GATEV2 = {
    'STAGE2_SEG_INCLUDE_BRAND': '0',  # ← FALSE設定
}
```

**Stage2ゲートのコード:**
```python
seg_include_brand = str(os.getenv("STAGE2_SEG_INCLUDE_BRAND", "0")).strip() not in ("0","false","False")
# → False

brand_hit = np.zeros_like(is_dang, dtype=bool)  # ← 常に0
if seg_include_brand:  # ← 実行されない
    # brand検出ロジック
```

### 4.3 影響範囲

**機能していない処理:**
1. ブランドキーワード辞書の読み込み
2. ドメイン名との照合
3. Priority Poolへのブランド偽装候補の追加

**実際の影響:**
- ブランド偽装型フィッシング（PayPal、Amazon等）の優先度が上がらない
- Priority Poolが「dangerous TLD + IDN」のみで構成
- 論文の重要な主張「ブランド偽装検出」が実証されていない

### 4.4 00_overview.txtとの一致

> "brand特徴が機能しているかを必ず検証
> DEFER候補集合でbrand_hitが全件0なら**壊れている**"

**✅ 指摘通りの状態を確認**

---

## 5. システム全体のエラー分析

### 5.1 エラー分類

| エラータイプ | 件数 | 内訳 | 重大度 |
|-------------|------|------|--------|
| **AUTO FP** | 11 | AUTO領域の誤検知 | 低 |
| **AUTO FN** | 15 | AUTO領域の見逃し | 低 |
| **PENDING FN** | 2,140 | Stage2未選択の見逃し | **🔴 高** |
| **合計 FN** | 2,155 | - | - |

### 5.2 Stage別の誤り寄与度

```
見逃し（FN）の内訳:
  Stage1 AUTO FN:     0.7% (15/2,155)
  Stage2 PENDING FN: 99.3% (2,140/2,155)

→ 見逃しの99.3%がStage2のPENDING問題に起因
```

### 5.3 ベンチマーク比較

**論文の既報値（CSS2025.pdf より）:**
```
XGBoost単体: 偽陰性率 6.58%
ハイブリッド: 偽陰性率 1.04%
```

**今回の実測値（PENDINGを放置した場合）:**
```
AUTO領域のみ: 偽陰性率 0.0248%（極めて良好）
PENDING含む:  偽陰性率 1.68%（論文値を超過）
```

**⚠️ 結論:**
論文の1.04%達成には、**PENDINGの適切な処理が前提**となっている可能性が高い。

---

## 6. データ品質の初期評価

### 6.1 ラベル疑義の可能性

**PENDING内のPhish 2,140件の特徴（要検証）:**

1. **ML確率の分布:**
   ```
   p < 0.01:  約400件（極端に低い）
   p < 0.10:  約800件
   0.10-0.50: 約1,340件
   ```
   → 極端に低い確率でPhishラベルは疑義対象

2. **TLD分布（推定）:**
   - .com/.jp等のlegitimate TLDが多い可能性
   - → 正規サイト配下の一時的な悪用の可能性

3. **証明書特性（推定）:**
   - 正規CAの証明書を持つケースが含まれる可能性

### 6.2 優先調査候補（00_overview.txt準拠）

**レベル1（自動照会対象）:**
```
対象: PENDING Phish 2,140件のうち、上位50-100件
照会先:
  - Google Safe Browsing
  - PhishTank
  - urlscan.io
  - VirusTotal（サンプル）

期待成果: ラベル疑義率の推定（例: 20%がラベル誤り疑い）
```

**レベル2（手動レビュー対象）:**
```
優先度A（ラベル誤り疑い高）:
  - legitimate TLD + 組織情報あり証明書 + Phishラベル
  - sourceがtrusted + Phishラベル

優先度B（難例確認）:
  - 特徴量が正常寄り + Phishラベル + 外部照会不明
```

---

## 7. 定量的サマリー

### 7.1 処理フロー全体

```
入力: 128,067件
  ↓
Stage1 (XGBoost)
  ├─ AUTO決定: 73,395件 (57.3%)
  │   ├─ 正解: 73,369件
  │   └─ 誤り: 26件 (FP=11, FN=15)
  └─ DEFER: 54,672件 (42.7%)
      ├─ Benign: 51,156件
      └─ Phish: 3,516件
  ↓
Stage2 (LRゲート)
  ├─ Stage3送り: 5,000件 (9.1%)
  │   ├─ Benign: 3,624件
  │   └─ Phish: 1,376件
  └─ PENDING: 49,672件 (90.9%) ⚠️
      ├─ Benign: 47,532件
      └─ Phish: 2,140件 ← 見逃しリスク
```

### 7.2 主要メトリクス

| メトリクス | 値 | 評価 |
|-----------|-----|------|
| Stage1 AUTO精度 | 99.96% | ✅ 優秀 |
| Stage1 DEFER率 | 42.7% | ⚠️ やや高い |
| Stage2 選択率 | 9.1% | ⚠️ 低い（予算制約） |
| Stage2 Phish濃縮率 | 4.3倍 | ✅ 機能 |
| PENDING Phish件数 | 2,140 | 🔴 重大問題 |
| brand_hit件数 | 0 | 🔴 完全停止 |

---

## 8. 結論と推奨アクション

### 8.1 Phase 0で判明した事実

**✅ システムの強み:**
1. Stage1のAUTO領域は極めて高精度（99.96%）
2. リスク制約付き自動閾値選択が機能
3. Stage2のsegment_priority選択ロジックは動作
4. Phish濃縮（6.4%→27.5%）に成功

**🔴 システムの重大な問題:**
1. **PENDING問題:** 2,140件のPhishが未処理（見逃しリスク1.68%）
2. **brand停止:** 全候補でbrand_hit=0（論文の主張が実証されず）
3. **予算制約:** DEFER候補の9.1%しか精査されない

### 8.2 Phase 1への推奨アクション（優先順位順）

#### 優先度★★★（緊急）

**1. brand特徴の復旧**
```
対応: STAGE2_SEG_INCLUDE_BRAND = '1' に変更
工数: 1-2時間（設定変更 + 再実行 + 検証）
効果:
  - ブランド偽装型PhishのPriority Pool優先化
  - 論文の主張「ブランド検出」の実証
  - Stage3へのPhish送付率向上
```

**2. PENDING出力の明示化**
```
対応: 以下のファイルを追加出力
  - stage2_pending_latest.csv
  - stage2_pending_summary.json

工数: 2-3時間（コード追加 + ドキュメント）
効果:
  - 運用上の責任所在の明確化
  - 論文での「未処理の扱い」の説明材料
  - Phase 3でのラベル検証対象の可視化
```

#### 優先度★★（重要）

**3. Stage2予算の最適化検討**
```
対応: 予算5,000 → 10,000-15,000への引き上げ検討
工数: 半日（感度分析 + コスト試算）
効果:
  - PENDING Phish削減（2,140 → 1,000以下目標）
  - Stage3コストとの最適バランス発見
```

**4. PENDING上位50件のラベル検証**
```
対応: 外部照会（Safe Browsing, PhishTank等）
工数: 1日（手動照会 + 結果記録）
効果:
  - ラベル疑義率の推定（例: 20%）
  - 改善余地の切り分け
  - 論文での考察材料
```

#### 優先度★（中期）

**5. XGBoost損失関数の変更（森先生の指摘）**
```
対応: Confidence-Aware Loss / Focal Lossの導入
工数: 3-5日（実装 + 実験 + 比較）
効果:
  - 「自信を持って間違える」ケースの削減
  - DEFER領域の質的向上
  - 論文での方法論的貢献
```

---

## 9. 次回Phase 1の計画

### 9.1 推奨シナリオ（2日間）

**Day 1（基盤修正）:**
```
午前: brand特徴の復旧
  - 設定変更
  - ノートブック再実行
  - brand_hit分布の検証

午後: PENDING出力の実装
  - stage2_pending_*.csv生成
  - サマリーJSON追加
  - ドキュメント更新
```

**Day 2（検証と最適化）:**
```
午前: 結果比較
  - brand復旧前後の比較表作成
  - PENDING内訳の詳細分析

午後: 予算最適化の検討
  - 感度分析（budget 5k/10k/15k/20k）
  - コストベネフィット試算
  - 最適値の提案
```

### 9.2 期待成果物

1. **修正版ノートブック**
   - brand特徴有効化
   - PENDING明示出力
   - CHANGELOG更新

2. **比較分析レポート**
   - brand復旧の効果
   - PENDING詳細分析
   - ラベル疑義の初期推定

3. **Phase 2への提言**
   - 損失関数変更の実験計画
   - ラベル検証の詳細手順
   - 論文執筆への反映事項

---

## Appendix A: ファイル一覧

### 成果物の所在

```
artifacts/2026-01-08_185227/
├── results/
│   ├── route1_thresholds.json              # Stage1閾値
│   ├── stage1_decisions_latest.csv         # Stage1判定結果
│   ├── stage2_budget_eval.json             # Stage2評価
│   ├── stage2_decisions_candidates_latest.csv  # DEFER全体
│   ├── stage2_decisions_latest.csv         # （※要確認：全件）
│   └── gate_trace_candidates__*.csv        # Gate詳細ログ
├── handoff/
│   └── handoff_candidates_latest.csv       # Stage3送り（5000件）
└── models/
    ├── xgboost_model.pkl
    ├── lr_defer_model.pkl
    └── scaler.pkl
```

### ⚠️ ファイル整合性の注意

`stage2_decisions_latest.csv`が128,067件（全件）含む問題を確認。
正しくは以下の理解:
- `stage2_decisions_candidates_latest.csv`: DEFER全体（54,672件）
- `handoff_candidates_latest.csv`: Stage3送り（5,000件）
- PENDING = 差分（49,672件）は明示的なファイルなし

→ Phase 1でPENDING専用ファイルを追加すべき。

---

## Appendix B: 用語集

| 用語 | 定義 |
|------|------|
| **AUTO領域** | Stage1が高確信で決定した領域（benign/phish） |
| **DEFER領域** | Stage1が次段に送った曖昧な領域 |
| **PENDING** | Stage2で予算に入らず未処理となった件 |
| **Phish濃縮** | Stage処理後のPhish率の向上倍率 |
| **Priority Pool** | Stage2で優先的に選ぶ候補群（危険TLD/IDN/brand） |
| **Optional Pool** | Stage2で予算余剰時に選ぶ候補群（unknown TLD） |
| **segment_priority** | Stage2選択モード（優先度別の階層選択） |

---

## 変更履歴

- 2026-01-10: Phase 0分析完了、初版作成
