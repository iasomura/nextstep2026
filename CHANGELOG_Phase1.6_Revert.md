# CHANGELOG - Phase 1.6 Revert

**Date**: 2026-01-10
**Action**: Revert Phase 1.6 changes, return to Phase 1.5 state
**Reason**: Phase 1.6 filtering caused all metrics to deteriorate

---

## Summary

Phase 1.6 attempted to improve brand keyword quality through filtering (length filter, blacklist, manual additions), but results showed **significant deterioration across all metrics**:

- brand_hit: 198 → 147 (-51, -26%)
- Priority pool: 1,657 → 1,649 (-8, -0.5%)
- PENDING Phish: 2,119 → 2,359 (+240, +11%)

This revert returns the codebase to **Phase 1.5 state**, which had demonstrated successful brand feature operation.

---

## What Was Reverted

### 1. Cell 16 Brand Filtering Code (47 lines removed)

**Removed Code** (lines 478-525):
```python
# Phase 1.6: Brand keyword filtering and improvement
print("\n🔧 Phase 1.6: Filtering brand keywords...")

# Filter 1: Length filter (4-12 characters)
BRAND_KEYWORDS_filtered = [b for b in BRAND_KEYWORDS if 4 <= len(b) <= 12]

# Filter 2: Blacklist (high false positive rate)
BLACKLIST = ['visa', 'apple', 'steam', 'india']
BRAND_KEYWORDS_filtered = [b for b in BRAND_KEYWORDS_filtered if b not in BLACKLIST]

# Filter 3: Add manual high-value keywords
MANUAL_KEYWORDS = ['paypal', 'ebay', 'whatsapp', 'linkedin', 'dropbox',
                   'chase', 'wellsfargo', 'citibank', 'usbank']
for kw in MANUAL_KEYWORDS:
    if kw not in BRAND_KEYWORDS_filtered:
        BRAND_KEYWORDS_filtered.append(kw)

# Replace original list
BRAND_KEYWORDS = BRAND_KEYWORDS_filtered
```

**Reason**: This filtering had net negative effect:
- Removed 166 matches (including valuable keywords: apple 15% phish, steam 28.6% phish)
- Added only 28 matches (many false positives: ebay 0% phish, chase 0% phish)
- Net effect: -138 matches

---

### 2. Config.yaml Brand Section

**Removed**:
```yaml
brand_keywords:
  min_count: 2
  max_brands: 100
  dynamic: true

  # Phase 1.6: Filtering settings
  min_length: 4
  max_length: 12

  blacklist:
    - visa
    - apple
    - steam
    - india

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

**Restored to**:
```yaml
brand_keywords:
  min_count: 2
  max_brands: 100
  dynamic: true
  # Note: Phase 1.6 filtering was reverted due to negative impact
```

---

## Why Phase 1.6 Failed

### 1. Aggressive Blacklisting Mistakes

**Blacklisted Keywords** (actual performance from Phase 1.6 data):

| Keyword | Matches | Phish | Phish% | Judgment |
|---------|---------|-------|--------|----------|
| visa | 40 | 1 | 2.5% | ✅ Blacklist justified |
| apple | 20 | 3 | **15.0%** | ❌ Should NOT have blacklisted |
| steam | 14 | 4 | **28.6%** | ❌ Should NOT have blacklisted |
| india | 92 | 1 | 1.1% | ⚠️ Low phish% but high volume |

**Mistake**: Phase 1.5 analysis incorrectly reported apple as "86% benign" and steam as "73% benign" based on small sample sizes, leading to wrong blacklisting decision.

**Impact**: Removed 166 matches, including 7 valuable phish detections (apple: 3, steam: 4).

---

### 2. Manual Additions Had Low Value

**Added Keywords** (actual performance from Phase 1.6 data):

| Keyword | Matches | Phish | Phish% | Issue |
|---------|---------|-------|--------|-------|
| paypal | 2 | 1 | 50.0% | ✅ Valuable (small sample) |
| whatsapp | 2 | 1 | 50.0% | ✅ Valuable (small sample) |
| ebay | 14 | 0 | **0.0%** | ❌ False positives (healthebay, treasurebay) |
| chase | 7 | 0 | **0.0%** | ❌ False positives (person names) |
| linkedin | 1 | 0 | 0.0% | - |
| usbank | 2 | 0 | 0.0% | - |
| dropbox | 0 | 0 | N/A | - |
| wellsfargo | 0 | 0 | N/A | - |
| citibank | 0 | 0 | N/A | - |

**Impact**: Added 28 matches, but only 4 were actual phish. Many were false positives due to substring matching limitations.

---

### 3. Dataset Variance Issue

**Phase 1.5 vs Phase 1.6 Candidate Counts**:
- Phase 1.5: 54,672 candidates
- Phase 1.6: 55,258 candidates
- Difference: +586 (+1.1%)

**Problem**: Different data from 01*.ipynb executions makes phase-to-phase comparison difficult.

**Future Fix**: Data fixation strategy in Phase 2.

---

## Lessons Learned

### 1. Don't Trust Small Sample Analysis

**Phase 1.5 Mistake**:
- Analyzed only 198 brand matches total
- Concluded apple (22 matches) and steam (15 matches) were "noisy"
- Small sample sizes led to wrong conclusions

**Reality** (Phase 1.6 data):
- apple: 15.0% phish (valuable)
- steam: 28.6% phish (very valuable)

**Lesson**: Require larger datasets or statistical validation before blacklisting.

---

### 2. Substring Matching Has Fundamental Limitations

**False Positive Examples**:
- `ebay` → `healthebay.org`, `treasurebay.com`
- `chase` → `jacksonschase.com` (person name), `skchase.com`
- `apple` → `pineapplepaperco.com`

**Solution** (Phase 2):
- Word boundary matching
- Domain structure analysis (SLD/TLD separation)
- Edit distance for typo tolerance

---

### 3. Data-Driven Design is Critical

**Phase 1.6 Mistake**: Created blacklist based on intuition and limited data analysis.

**Better Approach** (Phase 2):
- Config-driven filtering with phish rate thresholds
- Statistical validation on larger datasets
- A/B testing framework for systematic evaluation

---

## Files Modified (Revert)

1. **`02_main.ipynb`**:
   - Cell 16: Removed lines 478-525 (brand filtering code)
   - Cell count: 525 → 478 lines

2. **`02_stage1_stage2/configs/default.yaml`**:
   - brand_keywords section simplified
   - Removed: min_length, max_length, blacklist, manual_additions

---

## Current State After Revert

**Phase 1.5 State Restored**:
- ✅ Cell 16: BRAND_KEYWORDS generation (100 keywords, no filtering)
- ✅ Cell 38: Brand matching logic (using globals() variable)
- ✅ Cell 43: PENDING output logic
- ✅ Config: Simple brand_keywords settings (min_count, max_brands, dynamic)

**Expected Performance** (same as Phase 1.5):
- brand_hit > 0: ~198 matches (0.36%)
- Priority pool: ~1,657
- PENDING Phish: ~2,119

---

## Next Steps

### Immediate: Phase 2 Planning

**Objective**: Python modularization with config-driven design

**Key Components**:
1. Module structure (02_stage1_stage2/src/)
2. Config-driven filtering (YAML-based)
3. Automated experimentation framework
4. Budget optimization experiments

---

### Future Improvements (Phase 2+)

**Brand Feature Enhancements**:
1. **Better Keyword Generation**:
   - Include abbreviations (irs, bofa, amex)
   - Filter by length (4-12 chars) at generation time
   - Add common phishing targets manually

2. **Smarter Matching**:
   - Word boundary matching
   - Edit distance for typo tolerance
   - Domain structure analysis

3. **Data-Driven Filtering**:
   - Phish rate thresholds (e.g., keep keywords with >10% phish rate)
   - Statistical validation on large datasets
   - Config-driven blacklist/whitelist

4. **Dataset Fixation**:
   - Save 01*.ipynb output for reproducible experiments
   - Consistent baseline for phase comparison

---

## Summary

**Phase 1.6 was a valuable learning experience**, but the results demonstrated that:

1. **Small sample analysis is unreliable** for critical decisions
2. **Substring matching needs improvement** to reduce false positives
3. **Data-driven design is essential** for systematic improvements

**Reverting to Phase 1.5** allows us to:
- Maintain the successful brand feature implementation
- Proceed to Phase 2 (Python modularization) with clean baseline
- Implement more sophisticated filtering logic in config-driven framework

---

**Revert Date**: 2026-01-10
**Status**: Phase 1.5 restored, ready for Phase 2 planning
**Next Milestone**: Phase 2 - Python Modularization

