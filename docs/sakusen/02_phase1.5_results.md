# Phase 1.5 実行結果レポート

**実行日**: 2026-01-10
**RUN_ID**: 2026-01-10_134155
**ベースライン**: Phase 1 (2026-01-10_105017)
**修正内容**: Cell 38のbrand_list読み込みロジック修正

---

## エグゼクティブサマリー

✅ **Brand feature修正成功**: brand_hit 0件 → 198件
✅ **Priority pool拡大**: 1,470 → 1,657（+12.7%）
✅ **PENDING Phish削減**: 2,140 → 2,119（-1.0%）

**結論**: 修正は成功したが、効果は期待値（5,000-7,000件）を下回る。Brand keyword設計の改善余地あり。

---

## 1. Phase 1 vs Phase 1.5 比較

### 1.1 定量的比較

| 指標 | Phase 1 | Phase 1.5 | 変化 | 評価 |
|------|---------|-----------|------|------|
| brand_hit > 0 | 0 (0.0%) | 198 (0.36%) | +198 | ✅ 修正成功 |
| Priority pool | 1,470 | 1,657 | +187 (+12.7%) | ✅ 改善 |
| Optional pool | 16,145 | 16,078 | -67 | - |
| Stage3 handoff | 5,000 | 5,000 | 0 | - |
| PENDING total | 49,672 | 49,672 | 0 | - |
| **PENDING Phish** | **2,140** | **2,119** | **-21 (-1.0%)** | ✅ 削減 |

### 1.2 修正の効果

**✅ 成功した点**:
1. Brand featureが正常に動作（0件 → 198件）
2. Priority poolが拡大（13%増加）
3. PENDING Phish数が削減（21件、1%減少）

**⚠️ 期待を下回った点**:
1. Brand match数: 期待5,000-7,000件 → 実際198件（期待の約3%）
2. PENDING Phish削減: 期待30%削減 → 実際1%削減

---

## 2. Brand Feature詳細分析

### 2.1 Brand Keyword別マッチ数

主要なbrand keywordのマッチ状況（全54,672候補中）:

| Brand | マッチ数 | Benign | Phish | Phish率 | 代表例 |
|-------|---------|--------|-------|---------|--------|
| visa | 41 | 40 | 1 | 2.4% | visa-to-travel.com, india-e-visas.com |
| google | 46 | 46 | 0 | 0.0% | google.hr, google.jp |
| apple | 22 | 19 | 3 | 13.6% | pineapplepaperco.com, seaappleshop.com |
| amazon | 15 | 6 | 9 | **60.0%** | amazon-co.me, rakuten-amazon.info |
| steam | 15 | 11 | 4 | 26.7% | steampunk-addiction.com |
| rakuten | 10 | 1 | 9 | **90.0%** | rakutenvdn.com, rakuten-japan.live |
| netflix | 3 | 1 | 2 | 66.7% | renouvellement-abonnements-netflix.com |
| paypal | 2 | 1 | 1 | 50.0% | paypal-home.com |

**観察**:
- **効果的なkeyword**: rakuten (90% phish), amazon (60% phish), netflix (67% phish)
- **ノイズが多いkeyword**: visa (98% benign), google (100% benign), apple (86% benign)

### 2.2 Brand Match全体の内訳

**198件のbrand match**:
- True Benign: 156件（78.8%）
- True Phish: 42件（21.2%）

**評価**:
- Phish enrichment: 6.4%（DEFER全体） → 21.2%（Brand match）
- **3.3倍の濃縮効果**あり

---

## 3. なぜBrand Match数が少ないのか？

### 3.1 原因分析

#### 原因1: Brand Keywordが長すぎる

生成されたBRAND_KEYWORDSの例（Cell 16出力より）:
- `internalrevenueservice` (23文字)
- `bankofamericacorporation` (24文字)
- `britishtelecom` (15文字)

**問題**: こんなに長い文字列を含むドメインは稀

#### 原因2: Exact Substring Matchの限界

**現在のロジック**:
```python
for b in brand_list:
    brand_hit |= np.char.find(dom_low.astype(str), b) >= 0
```

**問題**:
- `google` → マッチ: `google.hr` ✅
- `google` → 不一致: `g00gle.com` ❌（typo）
- `google` → 不一致: `googIe.com` ❌（homoglyph: I vs l）

フィッシングサイトは意図的にtypoやhomoglyphを使うため、exact matchでは検出できない。

#### 原因3: Brand Keyword選定の問題

**不適切なkeyword**:
- `visa`: ビザ関連の正規サイト（visa-to-travel.com）も大量にマッチ
- `apple`: 無関係な単語（pineapple）もマッチ
- `steam`: 無関係な単語（steampunk）もマッチ

**適切なkeyword**:
- `rakuten`: 9/10がPhish（効果的）
- `amazon`: 9/15がPhish（効果的）
- `netflix`: 2/3がPhish（効果的）

---

## 4. Priority Pool分析

### 4.1 Priority Pool構成

**Phase 1** (1,470件):
- Dangerous TLD: 推定1,200件
- IDN (xn--): 推定270件
- Brand match: 0件

**Phase 1.5** (1,657件):
- Dangerous TLD: 推定1,200件
- IDN (xn--): 推定270件
- **Brand match: 187件**（198件中、重複除く）

**増加率**: +12.7%

### 4.2 Priority Poolの実効性

Priority poolからの選抜状況は不明だが、Stage2 budget=5,000の制約により、Priority poolの大部分は選抜されていると推測される。

---

## 5. PENDING Phish削減効果

### 5.1 削減状況

| 指標 | Phase 1 | Phase 1.5 | 削減数 | 削減率 |
|------|---------|-----------|--------|--------|
| PENDING total | 49,672 | 49,672 | 0 | 0.0% |
| PENDING Benign | 47,532 | 47,553 | +21 | +0.04% |
| **PENDING Phish** | **2,140** | **2,119** | **-21** | **-1.0%** |

### 5.2 削減メカニズム

1. Brand match 42件のPhishがPriority poolに追加
2. Priority poolの拡大により、Stage2選抜の優先度が変化
3. 結果として21件のPhishがPENDING→Handoffに移動

**削減率が小さい理由**:
- Brand match自体が少ない（42 Phish）
- Budget=5,000の制約により、Priority pool全体からの選抜は限定的
- 42件中、約半分（21件）がHandoffに選ばれた

---

## 6. Stage3 Handoff分析

（詳細な分析は省略。Phase 1と大きく変わらないと推測）

**推測**:
- Total: 5,000件
- Benign: 約3,600件
- Phish: 約1,400件（Phase 1の1,376から微増）

---

## 7. 改善の余地

### 7.1 短期改善（Phase 1.6候補）

#### 改善1: Brand Keyword選定の改善

**現状**: LLMが長い正式名称を抽出
- `internalrevenueservice`, `bankofamericacorporation`

**提案**: 短い一般名称を優先
- `irs`, `bankofamerica` または `bofa`

**実装**: Cell 16のBrand抽出ロジックにフィルタ追加
```python
# Prefer shorter keywords (4-12 characters)
brand_list = [b for b in brand_list if 4 <= len(b) <= 12]
```

#### 改善2: Typo-tolerant matching

**現状**: Exact substring match

**提案**: Edit distance（Levenshtein distance）で近似マッチ
```python
# Allow 1-2 character difference
# 'google' matches 'g00gle', 'googIe', etc.
```

**課題**: 計算コスト増加（54,672 × 100 = 500万回の距離計算）

#### 改善3: 不適切なKeywordの除外

**除外候補**:
- `visa` → ビザ関連サイトとの誤マッチ多数
- `apple` → pineapple等との誤マッチ

**追加候補**:
- `paypal`, `ebay`, `whatsapp` など、フィッシング頻出だが今回マッチが少ないもの

---

### 7.2 中期改善（Phase 2以降）

#### 改善4: 特徴量としてのBrand

**現状**: Priority poolへの追加のみ

**提案**: XGBoost特徴量として利用
- `contains_brand` 特徴がすでに存在（Cell 19で実装）
- これをStage1訓練時に有効活用

#### 改善5: Dynamic Brand List更新

**現状**: 実行時にLLM抽出（毎回同じ100件）

**提案**:
- フィッシング頻出ブランドの統計分析
- 季節性・トレンドを反映した動的更新
- 手動キュレーションの追加

---

## 8. まとめ

### 8.1 Phase 1.5の成果

✅ **技術的成功**:
1. Brand feature修正により、機能が正常に動作
2. BRAND_KEYWORDS変数がStage2ゲートで正しく使用される
3. Priority poolが13%拡大

✅ **定量的効果**:
1. brand_hit: 0 → 198件
2. PENDING Phish: 2,140 → 2,119（-1%）

⚠️ **期待を下回った点**:
1. Brand match数が期待の3%程度
2. PENDING Phish削減が期待の3%程度（期待30% → 実際1%）

### 8.2 根本的な課題

**Brand Keyword設計の問題**:
1. Keywordが長すぎる（LLMが正式名称を抽出）
2. Exact matchの限界（typo/homoglyph検出不可）
3. 不適切なkeyword選定（visa, apple等のノイズ）

**システム設計の制約**:
1. Budget=5,000の制約により、Priority pool拡大の効果が限定的
2. Stage1特徴量として使用されていない（Priority poolのみ）

### 8.3 次のステップ

**Phase 1.6（短期改善）**:
1. Brand keyword長さフィルタ（4-12文字）
2. 不適切なkeyword除外（visa, apple等）
3. 頻出ブランドの手動追加

**Phase 2（中期改善）**:
1. Pythonモジュール化
2. Budget最適化実験
3. Brand特徴のStage1統合

**Phase 3（長期改善）**:
1. Typo-tolerant matching実装
2. Dynamic brand list更新
3. 外部脅威インテリジェンス統合

---

## 9. 付録: 実行ログ抜粋

### Cell 16出力（Brand抽出）

```
🔌 データベースに接続中...
✅ データベース接続成功

📊 phishtank_entries からターゲットを取得...
  ✅ 119 件

📊 jpcert_phishing_urls から説明文を取得...
  ✅ 200 件
🔧 MAX_BRANDS (effective): 100
🔧 BATCH_SIZE (effective): 5

Brand validation:  97%|███████| 115/119 [00:44<00:01]

⏱️  Done. processed=115/119, found=100/100, elapsed=44.6s

✅ 最終的なBRAND_KEYWORDS: 100件（batch=5, max=100）
📋 最初の20件: ['allegro', 'internalrevenueservice', 'facebook', ...]
```

### Stage2 budget_eval.json

```json
{
  "stage2_select": {
    "mode": "segment_priority",
    "max_budget": 5000,
    "seg_include_brand": true,
    "priority_pool": 1657,
    "optional_pool": 16078,
    "selected_final": 5000
  }
}
```

---

**レポート作成日**: 2026-01-10
**次回更新**: Phase 1.6実施後、またはPhase 2開始時
