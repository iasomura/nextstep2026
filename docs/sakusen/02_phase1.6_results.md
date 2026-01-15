# Phase 1.6 実行結果レポート

**実行日**: 2026-01-10
**RUN_ID**: 2026-01-10_140940
**ベースライン**: Phase 1.5 (2026-01-10_134155)
**修正内容**: Brand keyword filtering (length filter + blacklist + manual additions)

---

## エグゼクティブサマリー

❌ **Phase 1.6は失敗**: Brand match数、Priority pool、PENDING Phishの全てが悪化

**根本原因**: ブラックリストが aggressive すぎて、有効なkeyword（apple, steam）まで除外

**教訓**: データ駆動の分析なしに、直感的なブラックリストを作成すべきでない

---

## 1. Phase 1.5 vs Phase 1.6 比較

### 1.1 定量的比較

| 指標 | Phase 1.5 | Phase 1.6 | 変化 | 評価 |
|------|-----------|-----------|------|------|
| Total candidates | 54,672 | 55,258 | +586 (+1.1%) | ⚠️ Dataset differs |
| brand_hit > 0 | 198 (0.36%) | **147 (0.27%)** | **-51 (-26%)** | ❌ **悪化** |
| Priority pool | 1,657 | **1,649** | **-8 (-0.5%)** | ❌ **悪化** |
| PENDING total | 49,672 | 50,258 | +586 | - |
| **PENDING Phish** | 2,119 | **2,359** | **+240 (+11%)** | ❌ **悪化** |

**結論**: 全ての指標で悪化。Phase 1.6の修正は逆効果だった。

---

## 2. 失敗の原因分析

### 2.1 Aggressive Blacklisting

**除外したkeyword（4件）**:
- `visa`: 40マッチ（2.5% phish）
- `apple`: **20マッチ（15.0% phish）** ← 除外すべきでなかった
- `steam`: **14マッチ（28.6% phish）** ← 除外すべきでなかった
- `india`: 92マッチ（1.1% phish）

**合計**: 166マッチを除外

**問題点**:
1. apple: 15% phishは十分有効（Phase 1.5の分析で「86% benign」としたのは誤り）
2. steam: 28.6% phishは非常に有効（Phase 1.5の分析で「73% benign」としたのは誤り）
3. indiaの92件除外が大きな損失（1.1% phishでも、volumeが大きい）

---

### 2.2 Manual Additions の限定的効果

**追加したkeyword（9件）**:
- `paypal`: 2マッチ（50% phish）
- `ebay`: 14マッチ（**0% phish**） ← 誤マッチ（healthebay, treasurebay等）
- `whatsapp`: 2マッチ（50% phish）
- `linkedin`: 1マッチ（0% phish）
- `dropbox`: 0マッチ
- `chase`: 7マッチ（**0% phish**） ← 誤マッチ（人名等）
- `wellsfargo`: 0マッチ
- `citibank`: 0マッチ
- `usbank`: 2マッチ（0% phish）

**合計**: 28マッチを追加（うち、Phishは4件のみ）

**問題点**:
1. ebayとchaseは誤マッチばかり（部分文字列マッチの限界）
2. 金融機関系（wellsfargo, citibank）はDEFER候補に存在しない
3. 追加による phish 検出: わずか4件

---

### 2.3 Net Effect

```
除外: -166マッチ
追加: +28マッチ
-----------------
ネット: -138マッチ（理論値）

実際の変化: -51マッチ
```

**差異の理由**:
- データセットの違い（+586候補）
- 他の要因（例: 長さフィルタで除外された長いkeywordがPhase 1.5でマッチしていた可能性）

---

## 3. Phase 1.5の分析ミス

### 3.1 apple と steam の誤評価

**Phase 1.5での報告**:
- apple: 86% benign → ブラックリスト候補
- steam: 73% benign → ブラックリスト候補

**Phase 1.6での実測**:
- apple: **15.0% phish**（85% benign）
- steam: **28.6% phish**（71.4% benign）

**原因**:
- Phase 1.5では全マッチ数22件（apple）と15件（steam）から計算
- Phase 1.6ではマッチ数が異なる（20件、14件）
- データセットのばらつき、またはサンプリングの違い

**教訓**: 少数サンプルでの判断は危険。より大きなデータセットでの検証が必要。

---

## 4. Brand Keyword別詳細分析

### 4.1 効果的なKeyword（Phase 1.6）

| Keyword | マッチ数 | Phish数 | Phish率 | 評価 |
|---------|---------|---------|---------|------|
| rakuten | 10 | 9 | 90.0% | ✅ 非常に有効 |
| netflix | 3 | 2 | 66.7% | ✅ 有効 |
| amazon | 15 | 9 | 60.0% | ✅ 有効 |
| paypal | 2 | 1 | 50.0% | ✅ 有効（小サンプル） |
| yahoo | 2 | 1 | 50.0% | ✅ 有効（小サンプル） |
| whatsapp | 2 | 1 | 50.0% | ✅ 有効（小サンプル） |

---

### 4.2 ノイズが多いKeyword

| Keyword | マッチ数 | Phish数 | Phish率 | 評価 |
|---------|---------|---------|---------|------|
| google | 51 | 0 | 0.0% | ⚠️ 全て正規サイト |
| facebook | 4 | 0 | 0.0% | ⚠️ 全て正規サイト |
| microsoft | 2 | 0 | 0.0% | ⚠️ 全て正規サイト |
| instagram | 3 | 0 | 0.0% | ⚠️ 全て正規サイト |
| ebay | 14 | 0 | 0.0% | ⚠️ 誤マッチ（healthebay等） |
| linkedin | 1 | 0 | 0.0% | - |
| chase | 7 | 0 | 0.0% | ⚠️ 誤マッチ（人名等） |

---

### 4.3 除外したKeyword（実測）

| Keyword | マッチ数 | Phish数 | Phish率 | 判断 |
|---------|---------|---------|---------|------|
| visa | 40 | 1 | 2.5% | ✅ ブラックリスト正当 |
| apple | 20 | 3 | **15.0%** | ❌ 除外すべきでなかった |
| steam | 14 | 4 | **28.6%** | ❌ 除外すべきでなかった |
| india | 92 | 1 | 1.1% | ⚠️ 低phish%だが大volume |

---

## 5. Dataset Variance問題

### 5.1 候補数の違い

- Phase 1.5: 54,672候補
- Phase 1.6: 55,258候補
- 差: +586 (+1.1%)

### 5.2 原因推測

1. **01*.ipynb の実行条件が異なる**:
   - データベースの内容が変化
   - サンプリングロジックの違い
   - 時間帯による違い

2. **再現性の問題**:
   - 毎回異なるデータセットでは、Phase間の比較が困難
   - RUN_IDごとにデータが変わるのは研究として問題

### 5.3 今後の対策

- データセットを固定化（01*.ipynbの出力を保存し、再利用）
- または、01*.ipynbを含めた完全な再実行を毎回行い、ベースラインとの比較を慎重に行う

---

## 6. 根本的な課題

### 6.1 部分文字列マッチの限界

**問題1: 誤マッチ**
- `ebay` → `healthebay.org`, `treasurebay.com`
- `chase` → `jacksonschase.com` (人名), `skchase.com`
- `apple` → `pineapplepaperco.com`

**解決策（Phase 2以降）**:
- 単語境界マッチ（word boundary）
- ドメインの構造的解析（SLD/TLDの分離）

---

### 6.2 Brand Keyword生成の問題

**問題2: LLMが長い正式名称を抽出**
- `internalrevenueservice`, `bankofamericacorporation`

**問題3: 一般名称の不足**
- LLMは "Internal Revenue Service" から `irs` を抽出しない
- LLMは "Bank of America" から `bofa` を抽出しない

**解決策**:
- LLMに「短い一般名称も抽出せよ」と明示的に指示
- 手動での abbreviation追加（irs, bofa, amex等）

---

### 6.3 ブラックリスト設計の問題

**問題4: データ駆動でないブラックリスト**
- Phase 1.5の限定的データ（198件）から判断
- apple, steamの誤評価を招いた

**解決策**:
- より大きなデータセットでの検証
- Phish率の閾値を設定（例: 10%未満はブラックリスト）
- 手動判断を避け、統計的根拠に基づく

---

## 7. 次のステップ

### 7.1 Phase 1.6の修正（Phase 1.7候補）

**Option A: ブラックリスト最小化**
- visa のみブラックリスト
- apple, steam, indiaは保持

**Option B: Phish率閾値ベース**
- Phish率 < 5% のkeywordのみブラックリスト
- visa (2.5%), india (1.1%) が除外される
- apple (15%), steam (28.6%) は保持

**Option C: Phase 1.5に戻す**
- Phase 1.6の変更を全て revert
- Phase 1.5の状態でPhase 2（py化）に進む

---

### 7.2 推奨: Option C（Phase 1.5に戻す）

**理由**:
1. Phase 1.6の改善効果は証明されなかった
2. ブラックリストの設計は現時点で不十分なデータに基づく
3. Phase 2（py化）で、より柔軟なフィルタリングを実装可能

**Phase 2での改善案**:
1. Config駆動のブラックリスト
2. Phish率閾値の設定
3. 単語境界マッチの実装
4. Abbreviationの自動生成

---

## 8. まとめ

### 8.1 Phase 1.6の評価

❌ **失敗**: 全ての指標で悪化

**失敗の原因**:
1. 過度なブラックリスト（apple, steam, indiaを除外）
2. 手動追加の低効果（ebay, chaseが誤マッチ）
3. データ駆動でない設計（Phase 1.5の小サンプルから判断）

### 8.2 学んだこと

**教訓1**: 少数サンプルでの判断は危険
- Phase 1.5のapple（22件）、steam（15件）から「ノイズが多い」と判断
- 実際にはapple 15% phish、steam 28.6% phishで有効

**教訓2**: 部分文字列マッチの限界
- ebay → healthebay、chase → person namesなど誤マッチ多数

**教訓3**: データセットの再現性重要
- Phase間で候補数が異なると、公正な比較が困難

### 8.3 推奨事項

**即時対応**:
- Phase 1.5に戻す（Phase 1.6の変更をrevert）
- Phase 2（py化）に進む

**Phase 2での改善**:
- Config駆動のフィルタリング
- より洗練されたマッチングロジック
- データセットの固定化

---

## 9. 付録: データテーブル

### 9.1 All Brand Keyword Performance (Phase 1.6)

```
Keyword         | Matches | Benign | Phish | Phish%
----------------+---------+--------+-------+--------
rakuten         |      10 |      1 |     9 |  90.0%
netflix         |       3 |      1 |     2 |  66.7%
amazon          |      15 |      6 |     9 |  60.0%
paypal          |       2 |      1 |     1 |  50.0%
yahoo           |       2 |      1 |     1 |  50.0%
whatsapp        |       2 |      1 |     1 |  50.0%
google          |      51 |     51 |     0 |   0.0%
facebook        |       4 |      4 |     0 |   0.0%
microsoft       |       2 |      2 |     0 |   0.0%
instagram       |       3 |      3 |     0 |   0.0%
ebay            |      14 |     14 |     0 |   0.0%
linkedin        |       1 |      1 |     0 |   0.0%
chase           |       7 |      7 |     0 |   0.0%
usbank          |       2 |      2 |     0 |   0.0%
dropbox         |       0 |      0 |     0 |   N/A
wellsfargo      |       0 |      0 |     0 |   N/A
citibank        |       0 |      0 |     0 |   N/A
```

### 9.2 Blacklisted Keyword Performance

```
Keyword         | Matches | Benign | Phish | Phish%
----------------+---------+--------+-------+--------
india           |      92 |     91 |     1 |   1.1%
visa            |      40 |     39 |     1 |   2.5%
apple           |      20 |     17 |     3 |  15.0%
steam           |      14 |     10 |     4 |  28.6%
```

---

**レポート作成日**: 2026-01-10
**推奨**: Phase 1.5に戻し、Phase 2（py化）へ進む
