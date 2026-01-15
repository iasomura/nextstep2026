# CHANGELOG - Phase 1.6: Brand Keyword Filtering

**Date**: 2026-01-10
**Scope**: Brand keyword improvement
**Objective**: Improve brand keyword quality by filtering and manual additions

---

## Summary

Phase 1.5でBrand featureは動作したが、効果が限定的（198件マッチ、PENDING Phish削減1%）だった。
Phase 1.6では、Brand keywordの質を改善することで、より多くのマッチと効果的な検出を目指す。

---

## Phase 1.5 Analysis Results

### 問題点

1. **Brand keywordが長すぎる**:
   - `internalrevenueservice` (23文字)
   - `bankofamericacorporation` (24文字)
   - `britishtelecom` (15文字)
   - → このような長いkeywordを含むドメインは稀

2. **不適切なkeywordによる誤検知**:
   - `visa`: 98% benign（旅行ビザサイトと誤マッチ）
   - `apple`: 86% benign（pineapple等と誤マッチ）
   - `steam`: 73% benign（steampunk等と誤マッチ）

3. **効果的なkeywordが不足**:
   - `paypal`, `ebay`, `whatsapp`等の頻出フィッシング標的が含まれていない

---

## Changes Applied

### 1. Cell 16修正: Brand Keyword Filtering

**Modified File**: `02_main.ipynb` Cell 16

**Location**: 最後のprint文の後に追加（line 478以降）

**Added Code**:
```python
# Phase 1.6: Brand keyword filtering and improvement
print("\n🔧 Phase 1.6: Filtering brand keywords...")

# Save original count
original_count = len(BRAND_KEYWORDS)

# Filter 1: Length filter (4-12 characters)
BRAND_KEYWORDS_filtered = [b for b in BRAND_KEYWORDS if 4 <= len(b) <= 12]
print(f"  After length filter (4-12 chars): {len(BRAND_KEYWORDS_filtered)} keywords")

# Filter 2: Blacklist (high false positive rate)
BLACKLIST = ['visa', 'apple', 'steam', 'india']
BRAND_KEYWORDS_filtered = [b for b in BRAND_KEYWORDS_filtered if b not in BLACKLIST]
print(f"  After blacklist filter: {len(BRAND_KEYWORDS_filtered)} keywords")

# Filter 3: Add manual high-value keywords
MANUAL_KEYWORDS = ['paypal', 'ebay', 'whatsapp', 'linkedin', 'dropbox',
                   'chase', 'wellsfargo', 'citibank', 'usbank']
for kw in MANUAL_KEYWORDS:
    if kw not in BRAND_KEYWORDS_filtered:
        BRAND_KEYWORDS_filtered.append(kw)
        added_manual.append(kw)

# Replace original list
BRAND_KEYWORDS = BRAND_KEYWORDS_filtered
```

---

### 2. Config.yaml更新: Brand Settings Documentation

**Modified File**: `02_stage1_stage2/configs/default.yaml`

**Added Section**:
```yaml
brand_keywords:
  min_count: 2
  max_brands: 100
  dynamic: true

  # Phase 1.6: Filtering settings
  min_length: 4         # Minimum keyword length
  max_length: 12        # Maximum keyword length

  # Keywords with high false positive rate
  blacklist:
    - visa              # 98% benign (travel visa sites)
    - apple             # 86% benign (pineapple, etc.)
    - steam             # 73% benign (steampunk, etc.)
    - india             # Generic word

  # High-value keywords to add manually
  manual_additions:
    - paypal
    - ebay
    - whatsapp
    - linkedin
    - dropbox
    - chase
    - wellsfargo
    - citibank
    - usbank
```

**Note**: 現時点では、Cell 16はconfig.yamlから読み込まず、ハードコードされたBLACKLISTとMANUAL_KEYWORDSを使用。将来のPhase 2（py化）でconfig駆動に移行予定。

---

## Expected Impact

### Before (Phase 1.5)

| Metric | Value |
|--------|-------|
| BRAND_KEYWORDS count (raw) | 100 |
| BRAND_KEYWORDS count (filtered) | 100 |
| brand_hit > 0 | 198 (0.36%) |
| Priority pool | 1,657 |
| PENDING Phish | 2,119 |

### After (Phase 1.6 - Expected)

| Metric | Expected Value | Rationale |
|--------|---------------|-----------|
| BRAND_KEYWORDS count (raw) | 100 | Same (LLM extraction) |
| BRAND_KEYWORDS count (filtered) | 60-80 | Length filter + blacklist |
| brand_hit > 0 | 300-500 (0.5-0.9%) | Better keywords + manual additions |
| Priority pool | 1,800-2,000 | +200-400 from Phase 1.5 |
| PENDING Phish | 2,050-2,080 | -40-70 from Phase 1.5 (-2-3%) |

---

## Filtering Details

### Length Filter (4-12 characters)

**Removed keywords** (too long):
- `internalrevenueservice` (23 chars)
- `bankofamericacorporation` (24 chars)
- `britishtelecom` (15 chars)
- その他13文字以上のkeyword

**Removed keywords** (too short, if any):
- 3文字以下のkeyword（ほぼ存在しないと予想）

**Retained keywords**:
- `facebook` (8 chars) ✅
- `microsoft` (9 chars) ✅
- `amazon` (6 chars) ✅
- `google` (6 chars) ✅
- `netflix` (7 chars) ✅
- `rakuten` (7 chars) ✅

---

### Blacklist Filter

**Removed keywords** (high false positive):
- `visa` → 98% benign（旅行ビザサイト）
- `apple` → 86% benign（pineapple, seaapple等）
- `steam` → 73% benign（steampunk等）
- `india` → 一般的な単語、高誤検知

**Impact**: 約4-5キーワード削除、誤検知の削減

---

### Manual Additions

**Added keywords** (high-value phishing targets):
- `paypal` → Phase 1.5で2件マッチ（50% phish）、高価値
- `ebay` → Phase 1.5で0件マッチだが、頻出標的
- `whatsapp` → 頻出標的
- `linkedin` → ビジネス関連フィッシングで頻出
- `dropbox` → ファイル共有詐欺で頻出
- `chase`, `wellsfargo`, `citibank`, `usbank` → 金融機関

**Rationale**:
- LLMが長い正式名称を抽出する傾向があるため、短い一般名称を手動追加
- 実際のフィッシング攻撃で頻出するブランドを補完

---

## Verification Plan (実行後に確認)

### 1. Brand keyword count check

```python
# Expected: 60-80 keywords (from 100)
print(f"Filtered BRAND_KEYWORDS: {len(BRAND_KEYWORDS)} keywords")
```

**期待値**: 60-80件

---

### 2. Brand match count increase

```python
df_gate = pd.read_csv('artifacts/<RUN_ID>/results/gate_trace_candidates__<RUN_ID>.csv')
brand_hit_count = (df_gate['brand_hit'] > 0).sum()
brand_hit_rate = brand_hit_count / len(df_gate) * 100

print(f"brand_hit > 0: {brand_hit_count:,} ({brand_hit_rate:.2f}%)")
```

**期待値**: 300-500件（Phase 1.5の198件から1.5-2.5倍）

---

### 3. Priority pool expansion

```python
with open('artifacts/<RUN_ID>/results/stage2_budget_eval.json') as f:
    data = json.load(f)
print(f"Priority pool: {data['stage2_select']['priority_pool']:,}")
```

**期待値**: 1,800-2,000（Phase 1.5の1,657から10-20%増）

---

### 4. PENDING Phish reduction

```python
df_pending = pd.read_csv('artifacts/<RUN_ID>/results/stage2_pending_latest.csv')
pending_phish = (df_pending['y_true'] == 1).sum()
print(f"PENDING Phish: {pending_phish:,}")
```

**期待値**: 2,050-2,080（Phase 1.5の2,119から2-3%削減）

---

### 5. Manual keyword effectiveness

```python
# Check if manual keywords are matching
manual_keywords = ['paypal', 'ebay', 'whatsapp', 'linkedin', 'dropbox']
domains_lower = df_gate['domain'].str.lower()

for kw in manual_keywords:
    matches = domains_lower.str.contains(kw, regex=False).sum()
    if matches > 0:
        matched_df = df_gate[domains_lower.str.contains(kw, regex=False)]
        phish_count = (matched_df['y_true'] == 1).sum()
        print(f"{kw}: {matches} matches ({phish_count} phish)")
```

**期待**: 手動追加keywordが実際にマッチすることを確認

---

## Backward Compatibility

✅ **完全に後方互換性あり**:

- Cell 16の最後に追加コードを挿入（既存ロジックは変更なし）
- BRAND_KEYWORDSリストを上書きするだけ
- 後続のセルには影響なし

---

## Known Limitations

### 1. Typo/Homoglyphは依然として検出不可

**問題**:
- `google` → マッチ: `google.hr` ✅
- `google` → 不一致: `g00gle.com` ❌

**解決策（Phase 2以降）**:
- Edit distance利用
- 正規表現パターンマッチ

### 2. Config.yamlとCell 16のハードコードが二重管理

**問題**:
- Cell 16でBLACKLISTとMANUAL_KEYWORDSがハードコード
- config.yamlに同じ情報が記載されているが、読み込まれていない

**解決策（Phase 2）**:
- Pythonモジュール化時に、config.yamlから読み込むように修正

---

## Next Steps

### Immediate (Phase 1.6実行)

1. **02_main.ipynb を再実行**
   - Cell 16で新しいフィルタリングロジックが実行される
   - 実行時間: 約10-15分

2. **結果確認**
   - Filtered BRAND_KEYWORDS count: 60-80件を期待
   - brand_hit > 0: 300-500件を期待
   - PENDING Phish: 2,050-2,080を期待

3. **Phase 1.5 vs Phase 1.6 比較レポート作成**
   - 定量的改善効果を記録
   - `docs/sakusen/02_phase1.6_results.md` に保存

---

### Follow-up (Phase 2以降)

- Pythonモジュール化（config駆動の実装）
- Typo-tolerant matching実装
- Budget最適化実験

---

## Files Modified

- `02_main.ipynb` - Cell 16 modified (brand keyword filtering added)
- `02_stage1_stage2/configs/default.yaml` - brand_keywords section extended

## Files Created

- `CHANGELOG_Phase1.6.md` - This file

---

## Summary

Phase 1.6は、**Brand keywordの質を改善**することで、より効果的なフィッシング検出を目指します。

**Key Improvements**:
1. 長すぎるkeywordを除外（4-12文字に制限）
2. 誤検知が多いkeywordをブラックリスト化（visa, apple, steam, india）
3. 高価値なkeywordを手動追加（paypal, ebay, whatsapp等）

**Expected Outcome**:
- Brand match数: 198 → 300-500（1.5-2.5倍）
- Priority pool: 1,657 → 1,800-2,000（10-20%増）
- PENDING Phish: 2,119 → 2,050-2,080（2-3%削減）

---

**Change Date**: 2026-01-10
**Next Milestone**: Phase 1.6実行 → Phase 2（py化）
